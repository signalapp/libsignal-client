//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::proto;
use crate::state::{PreKeyId, SignedPreKeyId};
use crate::{DeviceId, IdentityKey, PrivateKey, PublicKey, Result, SignalProtocolError};

use std::convert::{TryFrom, TryInto};

use hmac::{Hmac, Mac, NewMac};
use num_enum::TryFromPrimitiveError;
use prost::Message;
use rand::{CryptoRng, Rng};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub const CIPHERTEXT_MESSAGE_CURRENT_VERSION: MessageVersion = MessageVersion::V3;
pub const SENDERKEY_MESSAGE_CURRENT_VERSION: MessageVersion = MessageVersion::V3;

/// A [u8] describing the version of the message chain format to use when starting a chain.
#[derive(
    Copy,
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Debug,
    num_enum::TryFromPrimitive,
    num_enum::IntoPrimitive,
)]
#[repr(u8)]
pub enum MessageVersion {
    V2 = 2,
    /// **\[CURRENT\]**.
    V3 = 3,
}

impl TryFrom<u32> for MessageVersion {
    type Error = SignalProtocolError;
    fn try_from(value: u32) -> Result<Self> {
        let value_u8: u8 = value
            .try_into()
            .map_err(|_| SignalProtocolError::UnrecognizedMessageVersion(value))?;
        Ok(Self::try_from(value_u8)?)
    }
}

impl From<MessageVersion> for u32 {
    fn from(value: MessageVersion) -> u32 {
        let value_u8: u8 = value.into();
        value_u8 as u32
    }
}

impl From<TryFromPrimitiveError<MessageVersion>> for SignalProtocolError {
    fn from(value: TryFromPrimitiveError<MessageVersion>) -> SignalProtocolError {
        SignalProtocolError::UnrecognizedMessageVersion(value.number.into())
    }
}

pub enum CiphertextMessage {
    SignalMessage(SignalMessage),
    PreKeySignalMessage(PreKeySignalMessage),
    SenderKeyMessage(SenderKeyMessage),
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, num_enum::TryFromPrimitive)]
#[repr(u8)]
pub enum CiphertextMessageType {
    Whisper = 2,
    PreKey = 3,
    // Further cases should line up with Envelope.Type (proto), even though old cases don't.
    SenderKey = 7,
}

impl CiphertextMessage {
    pub fn message_type(&self) -> CiphertextMessageType {
        match self {
            CiphertextMessage::SignalMessage(_) => CiphertextMessageType::Whisper,
            CiphertextMessage::PreKeySignalMessage(_) => CiphertextMessageType::PreKey,
            CiphertextMessage::SenderKeyMessage(_) => CiphertextMessageType::SenderKey,
        }
    }

    pub fn serialize(&self) -> &[u8] {
        match self {
            CiphertextMessage::SignalMessage(x) => x.serialized(),
            CiphertextMessage::PreKeySignalMessage(x) => x.serialized(),
            CiphertextMessage::SenderKeyMessage(x) => x.serialized(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignalMessage {
    message_version: MessageVersion,
    sender_ratchet_key: PublicKey,
    counter: u32,
    #[allow(dead_code)]
    previous_counter: u32,
    ciphertext: Box<[u8]>,
    serialized: Box<[u8]>,
}

impl SignalMessage {
    const MAC_LENGTH: usize = 8;

    pub fn new(
        message_version: MessageVersion,
        mac_key: &[u8],
        sender_ratchet_key: PublicKey,
        counter: u32,
        previous_counter: u32,
        ciphertext: &[u8],
        sender_identity_key: &IdentityKey,
        receiver_identity_key: &IdentityKey,
    ) -> Result<Self> {
        let message = proto::wire::SignalMessage {
            ratchet_key: Some(sender_ratchet_key.serialize().into_vec()),
            counter: Some(counter),
            previous_counter: Some(previous_counter),
            ciphertext: Some(Vec::<u8>::from(&ciphertext[..])),
        };
        let mut serialized = vec![0u8; 1 + message.encoded_len() + Self::MAC_LENGTH];
        let message_version_u8: u8 = message_version.into();
        let current_version_u8: u8 = CIPHERTEXT_MESSAGE_CURRENT_VERSION.into();
        serialized[0] = ((message_version_u8 & 0xF) << 4) | current_version_u8;
        message.encode(&mut &mut serialized[1..message.encoded_len() + 1])?;
        let msg_len_for_mac = serialized.len() - Self::MAC_LENGTH;
        let mac = Self::compute_mac(
            sender_identity_key,
            receiver_identity_key,
            mac_key,
            &serialized[..msg_len_for_mac],
        )?;
        serialized[msg_len_for_mac..].copy_from_slice(&mac);
        let serialized = serialized.into_boxed_slice();
        Ok(Self {
            message_version,
            sender_ratchet_key,
            counter,
            previous_counter,
            ciphertext: ciphertext.into(),
            serialized,
        })
    }

    #[inline]
    pub fn message_version(&self) -> MessageVersion {
        self.message_version
    }

    #[inline]
    pub fn sender_ratchet_key(&self) -> &PublicKey {
        &self.sender_ratchet_key
    }

    #[inline]
    pub fn counter(&self) -> u32 {
        self.counter
    }

    #[inline]
    pub fn serialized(&self) -> &[u8] {
        &*self.serialized
    }

    #[inline]
    pub fn body(&self) -> &[u8] {
        &*self.ciphertext
    }

    pub fn verify_mac(
        &self,
        sender_identity_key: &IdentityKey,
        receiver_identity_key: &IdentityKey,
        mac_key: &[u8],
    ) -> Result<bool> {
        let our_mac = &Self::compute_mac(
            sender_identity_key,
            receiver_identity_key,
            mac_key,
            &self.serialized[..self.serialized.len() - Self::MAC_LENGTH],
        )?;
        let their_mac = &self.serialized[self.serialized.len() - Self::MAC_LENGTH..];
        let result: bool = our_mac.ct_eq(their_mac).into();
        if !result {
            log::error!(
                "Bad Mac! Their Mac: {} Our Mac: {}",
                hex::encode(their_mac),
                hex::encode(our_mac)
            );
        }
        Ok(result)
    }

    fn compute_mac(
        sender_identity_key: &IdentityKey,
        receiver_identity_key: &IdentityKey,
        mac_key: &[u8],
        message: &[u8],
    ) -> Result<[u8; Self::MAC_LENGTH]> {
        if mac_key.len() != 32 {
            return Err(SignalProtocolError::InvalidMacKeyLength(mac_key.len()));
        }
        let mut mac = Hmac::<Sha256>::new_varkey(mac_key).map_err(|_| {
            SignalProtocolError::InvalidArgument(format!(
                "Invalid HMAC key length <{}>",
                mac_key.len()
            ))
        })?;

        mac.update(sender_identity_key.public_key().serialize().as_ref());
        mac.update(receiver_identity_key.public_key().serialize().as_ref());
        mac.update(message);
        let mut result = [0u8; Self::MAC_LENGTH];
        result.copy_from_slice(&mac.finalize().into_bytes()[..Self::MAC_LENGTH]);
        Ok(result)
    }
}

impl AsRef<[u8]> for SignalMessage {
    fn as_ref(&self) -> &[u8] {
        &*self.serialized
    }
}

impl TryFrom<&[u8]> for SignalMessage {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() < SignalMessage::MAC_LENGTH + 1 {
            return Err(SignalProtocolError::CiphertextMessageTooShort(value.len()));
        }
        let message_version: MessageVersion = (value[0] >> 4).try_into()?;
        if message_version < CIPHERTEXT_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::LegacyCiphertextVersion(
                message_version.into(),
            ));
        }
        if message_version > CIPHERTEXT_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::UnrecognizedCiphertextVersion(
                message_version.into(),
            ));
        }

        let proto_structure =
            proto::wire::SignalMessage::decode(&value[1..value.len() - SignalMessage::MAC_LENGTH])?;

        let sender_ratchet_key = proto_structure
            .ratchet_key
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let sender_ratchet_key = PublicKey::deserialize(&sender_ratchet_key)?;
        let counter = proto_structure
            .counter
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let previous_counter = proto_structure.previous_counter.unwrap_or(0);
        let ciphertext = proto_structure
            .ciphertext
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?
            .into_boxed_slice();

        Ok(SignalMessage {
            message_version: message_version.try_into()?,
            sender_ratchet_key,
            counter,
            previous_counter,
            ciphertext,
            serialized: Box::from(value),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PreKeySignalMessage {
    message_version: MessageVersion,
    registration_id: DeviceId,
    pre_key_id: Option<PreKeyId>,
    signed_pre_key_id: SignedPreKeyId,
    base_key: PublicKey,
    identity_key: IdentityKey,
    message: SignalMessage,
    serialized: Box<[u8]>,
}

impl PreKeySignalMessage {
    pub fn new(
        message_version: MessageVersion,
        registration_id: DeviceId,
        pre_key_id: Option<PreKeyId>,
        signed_pre_key_id: SignedPreKeyId,
        base_key: PublicKey,
        identity_key: IdentityKey,
        message: SignalMessage,
    ) -> Result<Self> {
        let proto_message = proto::wire::PreKeySignalMessage {
            registration_id: Some(registration_id.into()),
            pre_key_id: pre_key_id.map(|id| id.into()),
            signed_pre_key_id: Some(signed_pre_key_id.into()),
            base_key: Some(base_key.serialize().into_vec()),
            identity_key: Some(identity_key.serialize().into_vec()),
            message: Some(Vec::from(message.as_ref())),
        };
        let mut serialized = vec![0u8; 1 + proto_message.encoded_len()];
        let message_version_u8: u8 = message_version.into();
        let current_version_u8: u8 = CIPHERTEXT_MESSAGE_CURRENT_VERSION.into();
        serialized[0] = ((message_version_u8 & 0xF) << 4) | current_version_u8;
        proto_message.encode(&mut &mut serialized[1..])?;
        Ok(Self {
            message_version,
            registration_id,
            pre_key_id,
            signed_pre_key_id,
            base_key,
            identity_key,
            message,
            serialized: serialized.into_boxed_slice(),
        })
    }

    #[inline]
    pub fn message_version(&self) -> MessageVersion {
        self.message_version
    }

    #[inline]
    pub fn registration_id(&self) -> DeviceId {
        self.registration_id
    }

    #[inline]
    pub fn pre_key_id(&self) -> Option<PreKeyId> {
        self.pre_key_id
    }

    #[inline]
    pub fn signed_pre_key_id(&self) -> SignedPreKeyId {
        self.signed_pre_key_id
    }

    #[inline]
    pub fn base_key(&self) -> &PublicKey {
        &self.base_key
    }

    #[inline]
    pub fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }

    #[inline]
    pub fn message(&self) -> &SignalMessage {
        &self.message
    }

    #[inline]
    pub fn serialized(&self) -> &[u8] {
        &*self.serialized
    }
}

impl AsRef<[u8]> for PreKeySignalMessage {
    fn as_ref(&self) -> &[u8] {
        &*self.serialized
    }
}

impl TryFrom<&[u8]> for PreKeySignalMessage {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(SignalProtocolError::CiphertextMessageTooShort(value.len()));
        }

        let message_version: MessageVersion = (value[0] >> 4).try_into()?;
        if message_version < CIPHERTEXT_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::LegacyCiphertextVersion(
                message_version.into(),
            ));
        }
        if message_version > CIPHERTEXT_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::UnrecognizedCiphertextVersion(
                message_version.into(),
            ));
        }

        let proto_structure = proto::wire::PreKeySignalMessage::decode(&value[1..])?;

        let base_key = proto_structure
            .base_key
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let identity_key = proto_structure
            .identity_key
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let message = proto_structure
            .message
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let signed_pre_key_id = proto_structure
            .signed_pre_key_id
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;

        let base_key = PublicKey::deserialize(base_key.as_ref())?;

        Ok(PreKeySignalMessage {
            message_version: message_version.into(),
            registration_id: (proto_structure.registration_id.unwrap_or(0)).into(),
            pre_key_id: proto_structure.pre_key_id.map(|id| id.into()),
            signed_pre_key_id: signed_pre_key_id.into(),
            base_key,
            identity_key: IdentityKey::try_from(identity_key.as_ref())?,
            message: SignalMessage::try_from(message.as_ref())?,
            serialized: Box::from(value),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SenderKeyMessage {
    message_version: MessageVersion,
    distribution_id: Uuid,
    chain_id: u32,
    iteration: u32,
    ciphertext: Box<[u8]>,
    serialized: Box<[u8]>,
}

impl SenderKeyMessage {
    const SIGNATURE_LEN: usize = 64;

    pub fn new<R: CryptoRng + Rng>(
        message_version: MessageVersion,
        distribution_id: Uuid,
        chain_id: u32,
        iteration: u32,
        ciphertext: Box<[u8]>,
        csprng: &mut R,
        signature_key: &PrivateKey,
    ) -> Result<Self> {
        let proto_message = proto::wire::SenderKeyMessage {
            distribution_uuid: Some(distribution_id.as_bytes().to_vec()),
            chain_id: Some(chain_id),
            iteration: Some(iteration),
            ciphertext: Some(ciphertext.to_vec()),
        };
        let proto_message_len = proto_message.encoded_len();
        let mut serialized = vec![0u8; 1 + proto_message_len + Self::SIGNATURE_LEN];
        let message_version_u8: u8 = message_version.into();
        let current_senderkey_version_u8: u8 = SENDERKEY_MESSAGE_CURRENT_VERSION.into();
        serialized[0] = ((message_version_u8 & 0xF) << 4) | current_senderkey_version_u8;
        proto_message.encode(&mut &mut serialized[1..1 + proto_message_len])?;
        let signature =
            signature_key.calculate_signature(&serialized[..1 + proto_message_len], csprng)?;
        serialized[1 + proto_message_len..].copy_from_slice(&signature[..]);
        Ok(Self {
            message_version: MessageVersion::V3,
            distribution_id,
            chain_id,
            iteration,
            ciphertext,
            serialized: serialized.into_boxed_slice(),
        })
    }

    pub fn verify_signature(&self, signature_key: &PublicKey) -> Result<bool> {
        let valid = signature_key.verify_signature(
            &self.serialized[..self.serialized.len() - Self::SIGNATURE_LEN],
            &self.serialized[self.serialized.len() - Self::SIGNATURE_LEN..],
        )?;

        Ok(valid)
    }

    #[inline]
    pub fn message_version(&self) -> MessageVersion {
        self.message_version
    }

    #[inline]
    pub fn distribution_id(&self) -> Uuid {
        self.distribution_id
    }

    #[inline]
    pub fn chain_id(&self) -> u32 {
        self.chain_id
    }

    #[inline]
    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    #[inline]
    pub fn ciphertext(&self) -> &[u8] {
        &*self.ciphertext
    }

    #[inline]
    pub fn serialized(&self) -> &[u8] {
        &*self.serialized
    }
}

impl AsRef<[u8]> for SenderKeyMessage {
    fn as_ref(&self) -> &[u8] {
        &*self.serialized
    }
}

impl TryFrom<&[u8]> for SenderKeyMessage {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() < 1 + Self::SIGNATURE_LEN {
            return Err(SignalProtocolError::CiphertextMessageTooShort(value.len()));
        }
        let message_version: MessageVersion = (value[0] >> 4).try_into()?;
        if message_version < SENDERKEY_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::LegacyCiphertextVersion(
                message_version.into(),
            ));
        }
        if message_version > SENDERKEY_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::UnrecognizedCiphertextVersion(
                message_version.into(),
            ));
        }
        let proto_structure =
            proto::wire::SenderKeyMessage::decode(&value[1..value.len() - Self::SIGNATURE_LEN])?;

        let distribution_id = proto_structure
            .distribution_uuid
            .and_then(|bytes| Uuid::from_slice(bytes.as_slice()).ok())
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let chain_id = proto_structure
            .chain_id
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let iteration = proto_structure
            .iteration
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let ciphertext = proto_structure
            .ciphertext
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?
            .into_boxed_slice();

        Ok(SenderKeyMessage {
            message_version: message_version.try_into()?,
            distribution_id,
            chain_id,
            iteration,
            ciphertext,
            serialized: Box::from(value),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SenderKeyDistributionMessage {
    message_version: MessageVersion,
    distribution_id: Uuid,
    chain_id: u32,
    iteration: u32,
    chain_key: Vec<u8>,
    signing_key: PublicKey,
    serialized: Box<[u8]>,
}

impl SenderKeyDistributionMessage {
    pub fn new(
        message_version: u8,
        distribution_id: Uuid,
        chain_id: u32,
        iteration: u32,
        chain_key: Vec<u8>,
        signing_key: PublicKey,
    ) -> Result<Self> {
        let proto_message = proto::wire::SenderKeyDistributionMessage {
            distribution_uuid: Some(distribution_id.as_bytes().to_vec()),
            chain_id: Some(chain_id),
            iteration: Some(iteration),
            chain_key: Some(chain_key.clone()),
            signing_key: Some(signing_key.serialize().to_vec()),
        };
        let mut serialized = vec![0u8; 1 + proto_message.encoded_len()];
        let current_senderkey_version_u8: u8 = SENDERKEY_MESSAGE_CURRENT_VERSION.into();
        serialized[0] = ((message_version & 0xF) << 4) | current_senderkey_version_u8;
        proto_message.encode(&mut &mut serialized[1..])?;

        Ok(Self {
            message_version: message_version.try_into()?,
            distribution_id,
            chain_id,
            iteration,
            chain_key,
            signing_key,
            serialized: serialized.into_boxed_slice(),
        })
    }

    #[inline]
    pub fn message_version(&self) -> MessageVersion {
        self.message_version
    }

    #[inline]
    pub fn distribution_id(&self) -> Result<Uuid> {
        Ok(self.distribution_id)
    }

    #[inline]
    pub fn chain_id(&self) -> Result<u32> {
        Ok(self.chain_id)
    }

    #[inline]
    pub fn iteration(&self) -> Result<u32> {
        Ok(self.iteration)
    }

    #[inline]
    pub fn chain_key(&self) -> Result<&[u8]> {
        Ok(&self.chain_key)
    }

    #[inline]
    pub fn signing_key(&self) -> Result<&PublicKey> {
        Ok(&self.signing_key)
    }

    #[inline]
    pub fn serialized(&self) -> &[u8] {
        &*self.serialized
    }
}

impl AsRef<[u8]> for SenderKeyDistributionMessage {
    fn as_ref(&self) -> &[u8] {
        &*self.serialized
    }
}

impl TryFrom<&[u8]> for SenderKeyDistributionMessage {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        // The message contains at least a X25519 key and a chain key
        if value.len() < 1 + 32 + 32 {
            return Err(SignalProtocolError::CiphertextMessageTooShort(value.len()));
        }

        let message_version: MessageVersion = (value[0] >> 4).try_into()?;

        if message_version < SENDERKEY_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::LegacyCiphertextVersion(
                message_version.into(),
            ));
        }
        if message_version > SENDERKEY_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::UnrecognizedCiphertextVersion(
                message_version.into(),
            ));
        }

        let proto_structure = proto::wire::SenderKeyDistributionMessage::decode(&value[1..])?;

        let distribution_id = proto_structure
            .distribution_uuid
            .and_then(|bytes| Uuid::from_slice(bytes.as_slice()).ok())
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let chain_id = proto_structure
            .chain_id
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let iteration = proto_structure
            .iteration
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let chain_key = proto_structure
            .chain_key
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let signing_key = proto_structure
            .signing_key
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;

        if chain_key.len() != 32 || signing_key.len() != 33 {
            return Err(SignalProtocolError::InvalidProtobufEncoding);
        }

        let signing_key = PublicKey::deserialize(&signing_key)?;

        Ok(SenderKeyDistributionMessage {
            message_version: message_version.try_into()?,
            distribution_id,
            chain_id,
            iteration,
            chain_key,
            signing_key,
            serialized: Box::from(value),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    use rand::rngs::OsRng;
    use rand::{CryptoRng, Rng};

    fn create_signal_message<T>(csprng: &mut T) -> Result<SignalMessage>
    where
        T: Rng + CryptoRng,
    {
        let mut mac_key = [0u8; 32];
        csprng.fill_bytes(&mut mac_key);
        let mac_key = mac_key;

        let mut ciphertext = [0u8; 20];
        csprng.fill_bytes(&mut ciphertext);
        let ciphertext = ciphertext;

        let sender_ratchet_key_pair = KeyPair::generate(csprng);
        let sender_identity_key_pair = KeyPair::generate(csprng);
        let receiver_identity_key_pair = KeyPair::generate(csprng);

        SignalMessage::new(
            MessageVersion::V3,
            &mac_key,
            sender_ratchet_key_pair.public_key,
            42,
            41,
            &ciphertext,
            &sender_identity_key_pair.public_key.into(),
            &receiver_identity_key_pair.public_key.into(),
        )
    }

    fn assert_signal_message_equals(m1: &SignalMessage, m2: &SignalMessage) {
        assert_eq!(m1.message_version, m2.message_version);
        assert_eq!(m1.sender_ratchet_key, m2.sender_ratchet_key);
        assert_eq!(m1.counter, m2.counter);
        assert_eq!(m1.previous_counter, m2.previous_counter);
        assert_eq!(m1.ciphertext, m2.ciphertext);
        assert_eq!(m1.serialized, m2.serialized);
    }

    #[test]
    fn test_signal_message_serialize_deserialize() -> Result<()> {
        let mut csprng = OsRng;
        let message = create_signal_message(&mut csprng)?;
        let deser_message =
            SignalMessage::try_from(message.as_ref()).expect("should deserialize without error");
        assert_signal_message_equals(&message, &deser_message);
        Ok(())
    }

    #[test]
    fn test_pre_key_signal_message_serialize_deserialize() -> Result<()> {
        let mut csprng = OsRng;
        let identity_key_pair = KeyPair::generate(&mut csprng);
        let base_key_pair = KeyPair::generate(&mut csprng);
        let message = create_signal_message(&mut csprng)?;
        let pre_key_signal_message = PreKeySignalMessage::new(
            MessageVersion::V3,
            365.into(),
            None,
            97.into(),
            base_key_pair.public_key,
            identity_key_pair.public_key.into(),
            message,
        )?;
        let deser_pre_key_signal_message =
            PreKeySignalMessage::try_from(pre_key_signal_message.as_ref())
                .expect("should deserialize without error");
        assert_eq!(
            pre_key_signal_message.message_version,
            deser_pre_key_signal_message.message_version
        );
        assert_eq!(
            pre_key_signal_message.registration_id,
            deser_pre_key_signal_message.registration_id
        );
        assert_eq!(
            pre_key_signal_message.pre_key_id,
            deser_pre_key_signal_message.pre_key_id
        );
        assert_eq!(
            pre_key_signal_message.signed_pre_key_id,
            deser_pre_key_signal_message.signed_pre_key_id
        );
        assert_eq!(
            pre_key_signal_message.base_key,
            deser_pre_key_signal_message.base_key
        );
        assert_eq!(
            pre_key_signal_message.identity_key.public_key(),
            deser_pre_key_signal_message.identity_key.public_key()
        );
        assert_signal_message_equals(
            &pre_key_signal_message.message,
            &deser_pre_key_signal_message.message,
        );
        assert_eq!(
            pre_key_signal_message.serialized,
            deser_pre_key_signal_message.serialized
        );
        Ok(())
    }

    #[test]
    fn test_sender_key_message_serialize_deserialize() -> Result<()> {
        let mut csprng = OsRng;
        let signature_key_pair = KeyPair::generate(&mut csprng);
        let sender_key_message = SenderKeyMessage::new(
            SENDERKEY_MESSAGE_CURRENT_VERSION,
            Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6),
            42,
            7,
            [1u8, 2, 3].into(),
            &mut csprng,
            &signature_key_pair.private_key,
        )?;
        let deser_sender_key_message = SenderKeyMessage::try_from(sender_key_message.as_ref())
            .expect("should deserialize without error");
        assert_eq!(
            sender_key_message.message_version,
            deser_sender_key_message.message_version
        );
        assert_eq!(
            sender_key_message.chain_id,
            deser_sender_key_message.chain_id
        );
        assert_eq!(
            sender_key_message.iteration,
            deser_sender_key_message.iteration
        );
        assert_eq!(
            sender_key_message.ciphertext,
            deser_sender_key_message.ciphertext
        );
        assert_eq!(
            sender_key_message.serialized,
            deser_sender_key_message.serialized
        );
        Ok(())
    }
}
