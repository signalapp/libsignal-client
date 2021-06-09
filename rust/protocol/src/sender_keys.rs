//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::consts::limits::{MAX_MESSAGE_KEYS, MAX_SENDER_KEY_STATES};
use crate::crypto::{hmac_sha256, AES_NONCE_SIZE, HMAC_OUTPUT_SIZE};
use crate::curve::curve25519::{PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH};
use crate::proto::storage as storage_proto;
use crate::protocol::SENDERKEY_MESSAGE_CURRENT_VERSION;
use crate::utils::no_encoding_error;
use crate::{AsymmetricRole, KeyType, PrivateKey, PublicKey, Result, SignalProtocolError, HKDF};

use arrayref::array_ref;
use prost::Message;
use uuid::Uuid;

use std::collections::VecDeque;
use std::convert::TryInto;

#[derive(Debug, Clone)]
pub struct SenderMessageKey {
    iteration: u32,
    iv: [u8; AES_NONCE_SIZE],
    cipher_key: [u8; PUBLIC_KEY_LENGTH],
    seed: [u8; HMAC_OUTPUT_SIZE],
}

impl SenderMessageKey {
    pub fn new(iteration: u32, seed: [u8; HMAC_OUTPUT_SIZE]) -> Result<Self> {
        let hkdf = HKDF::new(3)?;
        let derived_bytes =
            hkdf.derive_secrets(&seed, b"WhisperGroup", AES_NONCE_SIZE + PUBLIC_KEY_LENGTH)?;
        let derived: [u8; AES_NONCE_SIZE + PUBLIC_KEY_LENGTH] =
            *array_ref![&derived_bytes, 0, AES_NONCE_SIZE + PUBLIC_KEY_LENGTH];
        Ok(Self {
            iteration,
            seed,
            iv: *array_ref![&derived, 0, AES_NONCE_SIZE],
            cipher_key: *array_ref![&derived, AES_NONCE_SIZE, PUBLIC_KEY_LENGTH],
        })
    }

    pub fn from_protobuf(
        smk: storage_proto::sender_key_state_structure::SenderMessageKey,
    ) -> Result<Self> {
        let seed: &[u8; HMAC_OUTPUT_SIZE] = &smk.seed.try_into().map_err(|e: Vec<u8>| {
            SignalProtocolError::BadKeyLength(KeyType::Curve25519, AsymmetricRole::Hmac, e.len())
        })?;
        Self::new(smk.iteration, *seed)
    }

    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    pub fn iv(&self) -> [u8; AES_NONCE_SIZE] {
        self.iv
    }

    pub fn cipher_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.cipher_key
    }

    pub fn seed(&self) -> [u8; HMAC_OUTPUT_SIZE] {
        self.seed
    }

    pub fn as_protobuf(&self) -> storage_proto::sender_key_state_structure::SenderMessageKey {
        storage_proto::sender_key_state_structure::SenderMessageKey {
            iteration: self.iteration,
            seed: self.seed.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SenderChainKey {
    iteration: u32,
    chain_key: [u8; PUBLIC_KEY_LENGTH],
}

impl SenderChainKey {
    const MESSAGE_KEY_SEED: u8 = 0x01;
    const CHAIN_KEY_SEED: u8 = 0x02;

    pub fn new(iteration: u32, chain_key: [u8; PUBLIC_KEY_LENGTH]) -> Self {
        Self {
            iteration,
            chain_key,
        }
    }

    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    pub fn seed(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.chain_key
    }

    pub fn next(&self) -> SenderChainKey {
        SenderChainKey::new(
            self.iteration + 1,
            self.get_derivative(Self::CHAIN_KEY_SEED),
        )
    }

    pub fn sender_message_key(&self) -> Result<SenderMessageKey> {
        SenderMessageKey::new(self.iteration, self.get_derivative(Self::MESSAGE_KEY_SEED))
    }

    fn get_derivative(&self, label: u8) -> [u8; HMAC_OUTPUT_SIZE] {
        let label = [label];
        hmac_sha256(&self.chain_key, &label)
    }

    pub fn as_protobuf(&self) -> storage_proto::sender_key_state_structure::SenderChainKey {
        storage_proto::sender_key_state_structure::SenderChainKey {
            iteration: self.iteration,
            seed: self.chain_key.to_vec(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SenderKeyState {
    state: storage_proto::SenderKeyStateStructure,
}

impl SenderKeyState {
    pub fn new(
        message_version: u8,
        chain_id: u32,
        iteration: u32,
        chain_key: &[u8; PRIVATE_KEY_LENGTH],
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) -> Result<SenderKeyState> {
        let state = storage_proto::SenderKeyStateStructure {
            message_version: message_version as u32,
            chain_id,
            sender_chain_key: Some(SenderChainKey::new(iteration, *chain_key).as_protobuf()),
            sender_signing_key: Some(
                storage_proto::sender_key_state_structure::SenderSigningKey {
                    public: signature_key.serialize().to_vec(),
                    private: match signature_private_key {
                        None => vec![],
                        Some(k) => k.serialize().to_vec(),
                    },
                },
            ),
            sender_message_keys: vec![],
        };

        Self::from_protobuf(state)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        let state = storage_proto::SenderKeyStateStructure::decode(buf)?;
        Self::from_protobuf(state)
    }

    pub fn from_protobuf(state: storage_proto::SenderKeyStateStructure) -> Result<Self> {
        Ok(Self { state })
    }

    pub fn serialize(&self) -> Box<[u8]> {
        no_encoding_error(self.state.clone())
    }

    pub fn message_version(&self) -> u32 {
        match self.state.message_version {
            0 => SENDERKEY_MESSAGE_CURRENT_VERSION.into(),
            v => v,
        }
    }

    pub fn chain_id(&self) -> u32 {
        self.state.chain_id
    }

    pub fn sender_chain_key(&self) -> Result<SenderChainKey> {
        let sender_chain = self
            .state
            .sender_chain_key
            .as_ref()
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        Ok(SenderChainKey::new(
            sender_chain.iteration,
            sender_chain.seed.clone().try_into().map_err(|e: Vec<u8>| {
                SignalProtocolError::BadKeyLength(
                    KeyType::Curve25519,
                    AsymmetricRole::Hmac,
                    e.len(),
                )
            })?,
        ))
    }

    pub fn set_sender_chain_key(&mut self, chain_key: SenderChainKey) {
        self.state.sender_chain_key = Some(chain_key.as_protobuf());
    }

    pub fn signing_key_public(&self) -> Result<PublicKey> {
        if let Some(ref signing_key) = self.state.sender_signing_key {
            Ok(PublicKey::deserialize_result(&signing_key.public)?)
        } else {
            Err(SignalProtocolError::InvalidProtobufEncoding)
        }
    }

    pub fn signing_key_private(&self) -> Result<PrivateKey> {
        if let Some(ref signing_key) = self.state.sender_signing_key {
            Ok(PrivateKey::deserialize_result(&signing_key.private)?)
        } else {
            Err(SignalProtocolError::InvalidProtobufEncoding)
        }
    }

    pub fn has_sender_message_key(&self, iteration: u32) -> bool {
        for sender_message_key in &self.state.sender_message_keys {
            if sender_message_key.iteration == iteration {
                return true;
            }
        }
        false
    }

    pub fn as_protobuf(&self) -> storage_proto::SenderKeyStateStructure {
        self.state.clone()
    }

    pub fn add_sender_message_key(&mut self, sender_message_key: &SenderMessageKey) {
        self.state
            .sender_message_keys
            .push(sender_message_key.as_protobuf());
        while self.state.sender_message_keys.len() > MAX_MESSAGE_KEYS {
            self.state.sender_message_keys.remove(0);
        }
    }

    pub fn remove_sender_message_key(
        &mut self,
        iteration: u32,
    ) -> Result<Option<SenderMessageKey>> {
        if let Some(index) = self
            .state
            .sender_message_keys
            .iter()
            .position(|x| x.iteration == iteration)
        {
            let smk = self.state.sender_message_keys.remove(index);
            Ok(Some(SenderMessageKey::from_protobuf(smk)?))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Clone)]
pub struct SenderKeyRecord {
    states: VecDeque<SenderKeyState>,
}

impl SenderKeyRecord {
    pub fn new_empty() -> Self {
        Self {
            states: VecDeque::new(),
        }
    }

    pub fn deserialize(buf: &[u8]) -> Result<SenderKeyRecord> {
        let skr = storage_proto::SenderKeyRecordStructure::decode(buf)?;

        let mut states = VecDeque::with_capacity(skr.sender_key_states.len());
        for state in skr.sender_key_states {
            states.push_back(SenderKeyState::from_protobuf(state)?)
        }
        Ok(Self { states })
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.states.is_empty())
    }

    pub fn sender_key_state(&mut self) -> Result<&mut SenderKeyState> {
        if !self.states.is_empty() {
            return Ok(&mut self.states[0]);
        }
        Err(SignalProtocolError::NoSenderKeyState)
    }

    pub fn sender_key_state_for_chain_id(
        &mut self,
        chain_id: u32,
        distribution_id: Uuid,
    ) -> Result<&mut SenderKeyState> {
        for i in 0..self.states.len() {
            if self.states[i].chain_id() == chain_id {
                return Ok(&mut self.states[i]);
            }
        }
        log::error!(
            "SenderKey distribution {} could not find chain ID {} (known chain IDs: {:?})",
            distribution_id,
            chain_id,
            self.states
                .iter()
                .map(|state| state.chain_id())
                .collect::<Vec<_>>()
        );
        Err(SignalProtocolError::NoSenderKeyState)
    }

    pub fn add_sender_key_state(
        &mut self,
        message_version: u8,
        chain_id: u32,
        iteration: u32,
        chain_key: &[u8; PRIVATE_KEY_LENGTH],
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) -> Result<()> {
        self.states.push_front(SenderKeyState::new(
            message_version,
            chain_id,
            iteration,
            chain_key,
            signature_key,
            signature_private_key,
        )?);

        while self.states.len() > MAX_SENDER_KEY_STATES {
            self.states.pop_back();
        }
        Ok(())
    }

    pub fn set_sender_key_state(
        &mut self,
        message_version: u8,
        chain_id: u32,
        iteration: u32,
        chain_key: &[u8; PRIVATE_KEY_LENGTH],
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) -> Result<()> {
        self.states.clear();
        self.add_sender_key_state(
            message_version,
            chain_id,
            iteration,
            chain_key,
            signature_key,
            signature_private_key,
        )
    }

    pub fn as_protobuf(&self) -> Result<storage_proto::SenderKeyRecordStructure> {
        let mut states = Vec::with_capacity(self.states.len());
        for state in &self.states {
            states.push(state.as_protobuf());
        }

        Ok(storage_proto::SenderKeyRecordStructure {
            sender_key_states: states,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];
        self.as_protobuf()?.encode(&mut buf)?;
        Ok(buf)
    }
}
