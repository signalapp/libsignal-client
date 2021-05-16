//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::*;
use libsignal_protocol::error::Result;
use libsignal_protocol::*;
use static_assertions::const_assert_eq;
use std::convert::{TryFrom, TryInto};
use uuid::Uuid;

use crate::support::*;
use crate::*;

bridge_handle!(CiphertextMessage, clone = false, jni = false);
bridge_handle!(Fingerprint, jni = NumericFingerprintGenerator);
bridge_handle!(PreKeyBundle);
bridge_handle!(PreKeyRecord);
bridge_handle!(PreKeySignalMessage);
bridge_handle!(PrivateKey, ffi = privatekey, jni = ECPrivateKey);
bridge_handle!(ProtocolAddress, ffi = address);
bridge_handle!(PublicKey, ffi = publickey, jni = ECPublicKey);
bridge_handle!(SenderCertificate);
bridge_handle!(SenderKeyDistributionMessage);
bridge_handle!(SenderKeyMessage);
bridge_handle!(SenderKeyRecord);
bridge_handle!(ServerCertificate);
bridge_handle!(SessionRecord, mut = true);
bridge_handle!(SignalMessage, ffi = message);
bridge_handle!(SignedPreKeyRecord);
bridge_handle!(UnidentifiedSenderMessageContent, clone = false);
bridge_handle!(SealedSenderDecryptionResult, ffi = false, jni = false);

#[bridge_fn_buffer(ffi = false)]
fn HKDF_DeriveSecrets<E: Env>(
    env: E,
    output_length: u32,
    version: u32,
    ikm: &[u8],
    label: Option<&[u8]>,
    salt: Option<&[u8]>,
) -> Result<E::Buffer> {
    let label = label.unwrap_or(&[]);
    let kdf = HKDF::new_for_version(version.try_into()?)?;
    let buffer = match salt {
        Some(salt) => kdf.derive_salted_secrets(ikm, salt, label, output_length as usize)?,
        None => kdf.derive_secrets(ikm, label, output_length as usize)?,
    };
    Ok(env.buffer(buffer.into_vec()))
}

// Alternate implementation to fill an existing buffer.
#[bridge_fn_void(jni = false, node = false)]
fn HKDF_Derive(
    output: &mut [u8],
    version: u32,
    ikm: &[u8],
    label: &[u8],
    salt: &[u8],
) -> Result<()> {
    let kdf = HKDF::new_for_version(version.try_into()?)?;
    let kdf_output = kdf.derive_salted_secrets(ikm, salt, label, output.len())?;
    output.copy_from_slice(&kdf_output);
    Ok(())
}

#[bridge_fn(ffi = "address_new")]
fn ProtocolAddress_New(name: String, device_id: u32) -> ProtocolAddress {
    ProtocolAddress::new(name, device_id.into())
}

bridge_deserialize!(PublicKey::deserialize, ffi = publickey, jni = false);

// Alternate implementation to deserialize from an offset.
#[bridge_fn(ffi = false, node = false)]
fn ECPublicKey_Deserialize(data: &[u8], offset: u32) -> Result<PublicKey> {
    let offset = offset as usize;
    PublicKey::deserialize(&data[offset..])
}

bridge_get_bytearray!(
    PublicKey::serialize as Serialize,
    ffi = "publickey_serialize",
    jni = "ECPublicKey_1Serialize"
);
bridge_get_bytearray!(
    PublicKey::public_key_bytes,
    ffi = "publickey_get_public_key_bytes",
    jni = "ECPublicKey_1GetPublicKeyBytes"
);
bridge_get!(ProtocolAddress::device_id as DeviceId -> u32, ffi = "address_get_device_id");
bridge_get!(ProtocolAddress::name as Name -> &str, ffi = "address_get_name");

#[bridge_fn(ffi = "publickey_compare", node = "PublicKey_Compare")]
fn ECPublicKey_Compare(key1: &PublicKey, key2: &PublicKey) -> i32 {
    match key1.cmp(&key2) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

#[bridge_fn(ffi = "publickey_verify", node = "PublicKey_Verify")]
fn ECPublicKey_Verify(key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<bool> {
    key.verify_signature(&message, &signature)
}

bridge_deserialize!(
    PrivateKey::deserialize,
    ffi = privatekey,
    jni = ECPrivateKey
);
bridge_get_bytearray!(
    PrivateKey::serialize as Serialize,
    ffi = "privatekey_serialize",
    jni = "ECPrivateKey_1Serialize"
);

#[bridge_fn(ffi = "privatekey_generate", node = "PrivateKey_Generate")]
fn ECPrivateKey_Generate() -> PrivateKey {
    let mut rng = rand::rngs::OsRng;
    let keypair = KeyPair::generate(&mut rng);
    keypair.private_key
}

#[bridge_fn(ffi = "privatekey_get_public_key", node = "PrivateKey_GetPublicKey")]
fn ECPrivateKey_GetPublicKey(k: &PrivateKey) -> Result<PublicKey> {
    k.public_key()
}

#[bridge_fn_buffer(ffi = "privatekey_sign", node = "PrivateKey_Sign")]
fn ECPrivateKey_Sign<T: Env>(env: T, key: &PrivateKey, message: &[u8]) -> Result<T::Buffer> {
    let mut rng = rand::rngs::OsRng;
    let sig = key.calculate_signature(&message, &mut rng)?;
    Ok(env.buffer(sig.into_vec()))
}

#[bridge_fn_buffer(ffi = "privatekey_agree", node = "PrivateKey_Agree")]
fn ECPrivateKey_Agree<T: Env>(
    env: T,
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<T::Buffer> {
    let dh_secret = private_key.calculate_agreement(&public_key)?;
    Ok(env.buffer(dh_secret.into_vec()))
}

#[bridge_fn_buffer(ffi = "identitykeypair_serialize")]
fn IdentityKeyPair_Serialize<T: Env>(
    env: T,
    public_key: &PublicKey,
    private_key: &PrivateKey,
) -> Result<T::Buffer> {
    let identity_key_pair = IdentityKeyPair::new(IdentityKey::new(*public_key), *private_key);
    Ok(env.buffer(identity_key_pair.serialize().into_vec()))
}

#[bridge_fn(jni = false)]
fn Fingerprint_New(
    iterations: u32,
    version: u32,
    local_identifier: &[u8],
    local_key: &PublicKey,
    remote_identifier: &[u8],
    remote_key: &PublicKey,
) -> Result<Fingerprint> {
    Fingerprint::new(
        version,
        iterations,
        local_identifier,
        &IdentityKey::new(*local_key),
        remote_identifier,
        &IdentityKey::new(*remote_key),
    )
}

// Alternate implementation that takes untyped buffers.
#[bridge_fn(ffi = false, node = false)]
fn NumericFingerprintGenerator_New(
    iterations: u32,
    version: u32,
    local_identifier: &[u8],
    local_key: &[u8],
    remote_identifier: &[u8],
    remote_key: &[u8],
) -> Result<Fingerprint> {
    let local_key = IdentityKey::decode(local_key)?;
    let remote_key = IdentityKey::decode(remote_key)?;

    Fingerprint::new(
        version,
        iterations,
        local_identifier,
        &local_key,
        remote_identifier,
        &remote_key,
    )
}

#[bridge_fn_buffer(jni = "NumericFingerprintGenerator_1GetScannableEncoding")]
fn Fingerprint_ScannableEncoding<E: Env>(env: E, obj: &Fingerprint) -> Result<E::Buffer> {
    Ok(env.buffer(obj.scannable.serialize()?))
}

bridge_get!(
    Fingerprint::display_string as DisplayString -> String,
    jni = "NumericFingerprintGenerator_1GetDisplayString"
);

#[bridge_fn(ffi = "fingerprint_compare")]
fn ScannableFingerprint_Compare(fprint1: &[u8], fprint2: &[u8]) -> Result<bool> {
    ScannableFingerprint::deserialize(&fprint1)?.compare(fprint2)
}

bridge_deserialize!(SignalMessage::try_from, ffi = message);

#[bridge_fn_buffer(ffi = false, node = false)]
fn SignalMessage_GetSenderRatchetKey<E: Env>(env: E, m: &SignalMessage) -> E::Buffer {
    env.buffer(m.sender_ratchet_key().serialize().into_vec())
}

bridge_get_bytearray!(SignalMessage::body, ffi = "message_get_body");
bridge_get_bytearray!(SignalMessage::serialized, ffi = "message_get_serialized");
bridge_get!(SignalMessage::counter -> u32, ffi = "message_get_counter");
bridge_get!(SignalMessage::message_version -> u32, ffi = "message_get_message_version");

#[bridge_fn(ffi = "message_new")]
fn SignalMessage_New(
    message_version: u8,
    mac_key: &[u8],
    sender_ratchet_key: &PublicKey,
    counter: u32,
    previous_counter: u32,
    ciphertext: &[u8],
    sender_identity_key: &PublicKey,
    receiver_identity_key: &PublicKey,
) -> Result<SignalMessage> {
    SignalMessage::new(
        message_version.try_into()?,
        mac_key,
        *sender_ratchet_key,
        counter,
        previous_counter,
        ciphertext,
        &IdentityKey::new(*sender_identity_key),
        &IdentityKey::new(*receiver_identity_key),
    )
}

#[bridge_fn(ffi = "message_verify_mac")]
fn SignalMessage_VerifyMac(
    msg: &SignalMessage,
    sender_identity_key: &PublicKey,
    receiver_identity_key: &PublicKey,
    mac_key: &[u8],
) -> Result<bool> {
    msg.verify_mac(
        &IdentityKey::new(*sender_identity_key),
        &IdentityKey::new(*receiver_identity_key),
        &mac_key,
    )
}

#[bridge_fn(ffi = "message_get_sender_ratchet_key", jni = false, node = false)]
fn Message_GetSenderRatchetKey(m: &SignalMessage) -> PublicKey {
    *m.sender_ratchet_key()
}

#[bridge_fn]
fn PreKeySignalMessage_New(
    message_version: u8,
    registration_id: u32,
    pre_key_id: Option<u32>,
    signed_pre_key_id: u32,
    base_key: &PublicKey,
    identity_key: &PublicKey,
    signal_message: &SignalMessage,
) -> Result<PreKeySignalMessage> {
    PreKeySignalMessage::new(
        message_version.try_into()?,
        registration_id.into(),
        pre_key_id.map(|id| id.into()),
        signed_pre_key_id.into(),
        *base_key,
        IdentityKey::new(*identity_key),
        signal_message.clone(),
    )
}

#[bridge_fn(jni = false, node = false)]
fn PreKeySignalMessage_GetBaseKey(m: &PreKeySignalMessage) -> PublicKey {
    *m.base_key()
}

#[bridge_fn(jni = false, node = false)]
fn PreKeySignalMessage_GetIdentityKey(m: &PreKeySignalMessage) -> PublicKey {
    *m.identity_key().public_key()
}

#[bridge_fn(jni = false, node = false)]
fn PreKeySignalMessage_GetSignalMessage(m: &PreKeySignalMessage) -> SignalMessage {
    m.message().clone()
}

bridge_deserialize!(PreKeySignalMessage::try_from);
bridge_get_bytearray!(
    PreKeySignalMessage::serialized as Serialize,
    jni = "PreKeySignalMessage_1GetSerialized"
);

#[bridge_fn_buffer(ffi = false, jni = "PreKeySignalMessage_1GetBaseKey", node = false)]
fn PreKeySignalMessage_GetBaseKeySerialized<E: Env>(env: E, m: &PreKeySignalMessage) -> E::Buffer {
    env.buffer(m.base_key().serialize().into_vec())
}

#[bridge_fn_buffer(ffi = false, jni = "PreKeySignalMessage_1GetIdentityKey", node = false)]
fn PreKeySignalMessage_GetIdentityKeySerialized<E: Env>(
    env: E,
    m: &PreKeySignalMessage,
) -> E::Buffer {
    env.buffer(m.identity_key().serialize().into_vec())
}

#[bridge_fn_buffer(
    ffi = false,
    jni = "PreKeySignalMessage_1GetSignalMessage",
    node = false
)]
fn PreKeySignalMessage_GetSignalMessageSerialized<E: Env>(
    env: E,
    m: &PreKeySignalMessage,
) -> E::Buffer {
    env.buffer(m.message().serialized())
}

bridge_get!(PreKeySignalMessage::registration_id -> u32);
bridge_get!(PreKeySignalMessage::signed_pre_key_id -> u32);
bridge_get!(PreKeySignalMessage::pre_key_id -> Option<u32>);
bridge_get!(PreKeySignalMessage::message_version as GetVersion -> u32);

bridge_deserialize!(SenderKeyMessage::try_from);
bridge_get_bytearray!(SenderKeyMessage::ciphertext as GetCipherText);
bridge_get_bytearray!(
    SenderKeyMessage::serialized as Serialize,
    jni = "SenderKeyMessage_1GetSerialized"
);
bridge_get!(SenderKeyMessage::distribution_id -> Uuid, ffi = false);
bridge_get!(SenderKeyMessage::chain_id -> u32);
bridge_get!(SenderKeyMessage::iteration -> u32);

// Alternate form that copies into an existing buffer.
#[bridge_fn_void(jni = false, node = false)]
fn SenderKeyMessageGetDistributionId(out: &mut [u8; 16], obj: &SenderKeyMessage) -> Result<()> {
    *out = *obj.distribution_id().as_bytes();
    Ok(())
}

// For testing
#[bridge_fn]
fn SenderKeyMessage_New(
    message_version: u8,
    distribution_id: Uuid,
    chain_id: u32,
    iteration: u32,
    ciphertext: &[u8],
    pk: &PrivateKey,
) -> Result<SenderKeyMessage> {
    let mut csprng = rand::rngs::OsRng;
    SenderKeyMessage::new(
        message_version.try_into()?,
        distribution_id,
        chain_id,
        iteration,
        ciphertext.into(),
        &mut csprng,
        pk,
    )
}

#[bridge_fn]
fn SenderKeyMessage_VerifySignature(skm: &SenderKeyMessage, pubkey: &PublicKey) -> Result<bool> {
    skm.verify_signature(pubkey)
}

bridge_deserialize!(SenderKeyDistributionMessage::try_from);
bridge_get_bytearray!(SenderKeyDistributionMessage::chain_key);

#[bridge_fn_buffer(
    ffi = false,
    jni = "SenderKeyDistributionMessage_1GetSignatureKey",
    node = false
)]
fn SenderKeyDistributionMessage_GetSignatureKeySerialized<E: Env>(
    env: E,
    m: &SenderKeyDistributionMessage,
) -> Result<E::Buffer> {
    Ok(env.buffer(m.signing_key()?.serialize().into_vec()))
}

bridge_get_bytearray!(
    SenderKeyDistributionMessage::serialized as Serialize,
    jni = "SenderKeyDistributionMessage_1GetSerialized"
);
bridge_get!(SenderKeyDistributionMessage::distribution_id -> Uuid, ffi = false);
bridge_get!(SenderKeyDistributionMessage::chain_id -> u32);
bridge_get!(SenderKeyDistributionMessage::iteration -> u32);

// Alternate form that copies into an existing buffer.
#[bridge_fn_void(jni = false, node = false)]
fn SenderKeyDistributionMessageGetDistributionId(
    out: &mut [u8; 16],
    obj: &SenderKeyDistributionMessage,
) -> Result<()> {
    *out = *obj.distribution_id()?.as_bytes();
    Ok(())
}

// For testing
#[bridge_fn]
fn SenderKeyDistributionMessage_New(
    message_version: u8,
    distribution_id: Uuid,
    chain_id: u32,
    iteration: u32,
    chainkey: &[u8],
    pk: &PublicKey,
) -> Result<SenderKeyDistributionMessage> {
    SenderKeyDistributionMessage::new(
        message_version,
        distribution_id,
        chain_id,
        iteration,
        chainkey.into(),
        *pk,
    )
}

#[bridge_fn(jni = false, node = false)]
fn SenderKeyDistributionMessage_GetSignatureKey(
    m: &SenderKeyDistributionMessage,
) -> Result<PublicKey> {
    Ok(*m.signing_key()?)
}

#[bridge_fn]
fn PreKeyBundle_New(
    registration_id: u32,
    device_id: u32,
    prekey_id: Option<u32>,
    prekey: Option<&PublicKey>,
    signed_prekey_id: u32,
    signed_prekey: &PublicKey,
    signed_prekey_signature: &[u8],
    identity_key: &PublicKey,
) -> Result<PreKeyBundle> {
    let identity_key = IdentityKey::new(*identity_key);

    let prekey: Option<(PreKeyId, PublicKey)> = match (prekey, prekey_id) {
        (None, None) => None,
        (Some(k), Some(id)) => Some((id.into(), *k)),
        _ => {
            return Err(SignalProtocolError::InvalidArgument(
                "Must supply both or neither of prekey and prekey_id".to_owned(),
            ))
        }
    };

    PreKeyBundle::new(
        registration_id.into(),
        device_id.into(),
        prekey,
        signed_prekey_id.into(),
        *signed_prekey,
        signed_prekey_signature.to_vec(),
        identity_key,
    )
}

#[bridge_fn]
fn PreKeyBundle_GetIdentityKey(p: &PreKeyBundle) -> Result<PublicKey> {
    Ok(*p.identity_key()?.public_key())
}

bridge_get_bytearray!(PreKeyBundle::signed_pre_key_signature);
bridge_get!(PreKeyBundle::registration_id -> u32);
bridge_get!(PreKeyBundle::device_id -> u32);
bridge_get!(PreKeyBundle::signed_pre_key_id -> u32);
bridge_get!(PreKeyBundle::pre_key_id -> Option<u32>);
bridge_get!(PreKeyBundle::pre_key_public -> Option<PublicKey>);
bridge_get!(PreKeyBundle::signed_pre_key_public -> PublicKey);

bridge_deserialize!(SignedPreKeyRecord::deserialize);
bridge_get_bytearray!(SignedPreKeyRecord::signature);
bridge_get_bytearray!(
    SignedPreKeyRecord::serialize as Serialize,
    jni = "SignedPreKeyRecord_1GetSerialized"
);
bridge_get!(SignedPreKeyRecord::id -> u32);
bridge_get!(SignedPreKeyRecord::timestamp -> u64);
bridge_get!(SignedPreKeyRecord::public_key -> PublicKey);
bridge_get!(SignedPreKeyRecord::private_key -> PrivateKey);

#[bridge_fn]
fn SignedPreKeyRecord_New(
    id: u32,
    timestamp: u64,
    pub_key: &PublicKey,
    priv_key: &PrivateKey,
    signature: &[u8],
) -> SignedPreKeyRecord {
    let keypair = KeyPair::new(*pub_key, *priv_key);
    SignedPreKeyRecord::new(id.into(), timestamp.into(), &keypair, &signature)
}

bridge_deserialize!(PreKeyRecord::deserialize);
bridge_get_bytearray!(
    PreKeyRecord::serialize as Serialize,
    jni = "PreKeyRecord_1GetSerialized"
);
bridge_get!(PreKeyRecord::id -> u32);
bridge_get!(PreKeyRecord::public_key -> PublicKey);
bridge_get!(PreKeyRecord::private_key -> PrivateKey);

#[bridge_fn]
fn PreKeyRecord_New(id: u32, pub_key: &PublicKey, priv_key: &PrivateKey) -> PreKeyRecord {
    let keypair = KeyPair::new(*pub_key, *priv_key);
    PreKeyRecord::new(id.into(), &keypair)
}

bridge_deserialize!(SenderKeyRecord::deserialize);
bridge_get_bytearray!(
    SenderKeyRecord::serialize as Serialize,
    jni = "SenderKeyRecord_1GetSerialized"
);

#[bridge_fn(ffi = "sender_key_record_new_fresh")]
fn SenderKeyRecord_New() -> SenderKeyRecord {
    SenderKeyRecord::new_empty()
}

bridge_deserialize!(ServerCertificate::deserialize);
bridge_get_bytearray!(ServerCertificate::serialized);
bridge_get_bytearray!(ServerCertificate::certificate);
bridge_get_bytearray!(ServerCertificate::signature);
bridge_get!(ServerCertificate::key_id -> u32);
bridge_get!(ServerCertificate::public_key as GetKey -> PublicKey);

#[bridge_fn]
fn ServerCertificate_New(
    key_id: u32,
    server_key: &PublicKey,
    trust_root: &PrivateKey,
) -> Result<ServerCertificate> {
    let mut rng = rand::rngs::OsRng;
    ServerCertificate::new(key_id, *server_key, trust_root, &mut rng)
}

bridge_deserialize!(SenderCertificate::deserialize);
bridge_get_bytearray!(SenderCertificate::serialized);
bridge_get_bytearray!(SenderCertificate::certificate);
bridge_get_bytearray!(SenderCertificate::signature);
bridge_get!(SenderCertificate::sender_uuid -> &str);
bridge_get!(SenderCertificate::sender_e164 -> Option<&str>);
bridge_get!(SenderCertificate::expiration -> u64);
bridge_get!(SenderCertificate::sender_device_id as GetDeviceId -> u32);
bridge_get!(SenderCertificate::key -> PublicKey);

#[bridge_fn]
fn SenderCertificate_Validate(
    cert: &SenderCertificate,
    key: &PublicKey,
    time: u64,
) -> Result<bool> {
    cert.validate(key, time)
}

#[bridge_fn]
fn SenderCertificate_GetServerCertificate(cert: &SenderCertificate) -> Result<ServerCertificate> {
    Ok(cert.signer()?.clone())
}

#[bridge_fn]
fn SenderCertificate_New(
    sender_uuid: String,
    sender_e164: Option<String>,
    sender_device_id: u32,
    sender_key: &PublicKey,
    expiration: u64,
    signer_cert: &ServerCertificate,
    signer_key: &PrivateKey,
) -> Result<SenderCertificate> {
    let mut rng = rand::rngs::OsRng;

    SenderCertificate::new(
        sender_uuid,
        sender_e164,
        *sender_key,
        sender_device_id.into(),
        expiration,
        signer_cert.clone(),
        signer_key,
        &mut rng,
    )
}

bridge_deserialize!(UnidentifiedSenderMessageContent::deserialize);
bridge_get_bytearray!(
    UnidentifiedSenderMessageContent::serialized as Serialize,
    jni = "UnidentifiedSenderMessageContent_1GetSerialized"
);
bridge_get_bytearray!(UnidentifiedSenderMessageContent::contents);

#[bridge_fn]
fn UnidentifiedSenderMessageContent_GetSenderCert(
    m: &UnidentifiedSenderMessageContent,
) -> Result<SenderCertificate> {
    Ok(m.sender()?.clone())
}

#[bridge_fn_buffer]
fn UnidentifiedSenderMessageContent_GetGroupId<E: Env>(
    env: E,
    m: &UnidentifiedSenderMessageContent,
) -> Result<Option<E::Buffer>> {
    Ok(m.group_id()?.map(|buf| env.buffer(buf)))
}

#[bridge_fn]
fn UnidentifiedSenderMessageContent_GetMsgType(m: &UnidentifiedSenderMessageContent) -> Result<u8> {
    Ok(m.msg_type()? as u8)
}

#[derive(Debug)]
#[repr(C)]
pub enum FfiContentHint {
    Default = 0,
    Supplementary = 1,
    Retry = 2,
}

const_assert_eq!(
    FfiContentHint::Default as u32,
    ContentHint::Default.to_u32(),
);
const_assert_eq!(
    FfiContentHint::Supplementary as u32,
    ContentHint::Supplementary.to_u32(),
);
const_assert_eq!(FfiContentHint::Retry as u32, ContentHint::Retry.to_u32());

#[bridge_fn]
fn UnidentifiedSenderMessageContent_GetContentHint(
    m: &UnidentifiedSenderMessageContent,
) -> Result<u32> {
    Ok(m.content_hint()?.into())
}

#[bridge_fn(ffi = false, jni = false)]
fn UnidentifiedSenderMessageContent_New(
    message: &CiphertextMessage,
    sender: &SenderCertificate,
    content_hint: u32,
    group_id: Option<&[u8]>,
) -> Result<UnidentifiedSenderMessageContent> {
    UnidentifiedSenderMessageContent::new(
        message.message_type(),
        sender.clone(),
        message.serialize().to_owned(),
        ContentHint::from(content_hint),
        group_id.map(|g| g.to_owned()),
    )
}

// Alternate version for FFI because FFI can't support optional slices.
#[bridge_fn(jni = false, node = false)]
fn UnidentifiedSenderMessageContentNew(
    message: &CiphertextMessage,
    sender: &SenderCertificate,
    content_hint: u32,
    group_id: &[u8],
) -> Result<UnidentifiedSenderMessageContent> {
    UnidentifiedSenderMessageContent::new(
        message.message_type(),
        sender.clone(),
        message.serialize().to_owned(),
        ContentHint::from(content_hint),
        if group_id.is_empty() {
            None
        } else {
            Some(group_id.to_owned())
        },
    )
}

// Alternate version for Java since CiphertextMessage isn't opaque in Java.
#[bridge_fn(
    ffi = false,
    jni = "UnidentifiedSenderMessageContent_1New",
    node = false
)]
fn UnidentifiedSenderMessageContent_New_Java(
    message: jni::CiphertextMessageRef,
    sender: &SenderCertificate,
    content_hint: u32,
    group_id: Option<&[u8]>,
) -> Result<UnidentifiedSenderMessageContent> {
    UnidentifiedSenderMessageContent::new(
        message.message_type(),
        sender.clone(),
        message.serialize().to_owned(),
        ContentHint::from(content_hint),
        group_id.map(|g| g.to_owned()),
    )
}

#[derive(Debug)]
#[repr(C)]
pub enum FfiCiphertextMessageType {
    Whisper = 2,
    PreKey = 3,
    SenderKey = 7,
}

const_assert_eq!(
    FfiCiphertextMessageType::Whisper as u8,
    CiphertextMessageType::Whisper as u8
);
const_assert_eq!(
    FfiCiphertextMessageType::PreKey as u8,
    CiphertextMessageType::PreKey as u8
);
const_assert_eq!(
    FfiCiphertextMessageType::SenderKey as u8,
    CiphertextMessageType::SenderKey as u8
);

#[bridge_fn(jni = false)]
fn CiphertextMessage_Type(msg: &CiphertextMessage) -> u8 {
    msg.message_type() as u8
}

bridge_get_bytearray!(CiphertextMessage::serialize as Serialize, jni = false);

#[bridge_fn(ffi = false, node = false)]
fn SessionRecord_NewFresh() -> SessionRecord {
    SessionRecord::new_fresh()
}

#[bridge_fn(ffi = false, node = false)]
fn SessionRecord_FromSingleSessionState(session_state: &[u8]) -> Result<SessionRecord> {
    SessionRecord::from_single_session_state(session_state)
}

// For historical reasons Android assumes this function will return zero if there is no session state
#[bridge_fn(ffi = false, node = false)]
fn SessionRecord_GetSessionVersion(s: &SessionRecord) -> Result<u32> {
    match s.session_version() {
        Ok(v) => Ok(v),
        Err(SignalProtocolError::InvalidState(_, _)) => Ok(0),
        Err(e) => Err(e),
    }
}

#[bridge_fn_void]
fn SessionRecord_ArchiveCurrentState(session_record: &mut SessionRecord) -> Result<()> {
    session_record.archive_current_state()
}

bridge_get!(SessionRecord::has_current_session_state as HasCurrentState -> bool, jni = false);

bridge_deserialize!(SessionRecord::deserialize);
bridge_get_bytearray!(SessionRecord::serialize as Serialize);
bridge_get_bytearray!(SessionRecord::alice_base_key, ffi = false, node = false);
bridge_get_bytearray!(
    SessionRecord::local_identity_key_bytes as GetLocalIdentityKeyPublic,
    ffi = false,
    node = false
);
bridge_get_optional_bytearray!(
    SessionRecord::remote_identity_key_bytes as GetRemoteIdentityKeyPublic,
    ffi = false,
    node = false
);
bridge_get!(SessionRecord::local_registration_id -> u32);
bridge_get!(SessionRecord::remote_registration_id -> u32);
bridge_get!(SessionRecord::has_sender_chain as HasSenderChain -> bool, ffi = false, node = false);

bridge_get!(SealedSenderDecryptionResult::sender_uuid -> String, ffi = false, jni = false);
bridge_get!(SealedSenderDecryptionResult::sender_e164 -> Option<String>, ffi = false, jni = false);
bridge_get!(SealedSenderDecryptionResult::device_id -> u32, ffi = false, jni = false);
bridge_get_bytearray!(
    SealedSenderDecryptionResult::message as Message,
    ffi = false,
    jni = false
);

// The following SessionRecord APIs are just exposed to make it possible to retain some of the Java tests:

bridge_get_bytearray!(
    SessionRecord::get_sender_chain_key_bytes as GetSenderChainKeyValue,
    ffi = false,
    node = false
);
#[bridge_fn_buffer(ffi = false, node = false)]
fn SessionRecord_GetReceiverChainKeyValue<E: Env>(
    env: E,
    session_state: &SessionRecord,
    key: &PublicKey,
) -> Result<Option<E::Buffer>> {
    let chain_key = session_state.get_receiver_chain_key(key)?;
    Ok(chain_key.map(|ck| env.buffer(&ck.key()[..])))
}

#[bridge_fn(ffi = false, node = false)]
fn SessionRecord_InitializeAliceSession(
    identity_key_private: &PrivateKey,
    identity_key_public: &PublicKey,
    base_private: &PrivateKey,
    base_public: &PublicKey,
    their_identity_key: &PublicKey,
    their_signed_prekey: &PublicKey,
    their_ratchet_key: &PublicKey,
) -> Result<SessionRecord> {
    let our_identity_key_pair = IdentityKeyPair::new(
        IdentityKey::new(*identity_key_public),
        *identity_key_private,
    );

    let our_base_key_pair = KeyPair::new(*base_public, *base_private);

    let their_identity_key = IdentityKey::new(*their_identity_key);

    let mut csprng = rand::rngs::OsRng;

    let parameters = AliceSignalProtocolParameters::new(
        our_identity_key_pair,
        our_base_key_pair,
        their_identity_key,
        *their_signed_prekey,
        None,
        *their_ratchet_key,
    );

    initialize_alice_session_record(&parameters, &mut csprng)
}

#[bridge_fn(ffi = false, node = false)]
fn SessionRecord_InitializeBobSession(
    identity_key_private: &PrivateKey,
    identity_key_public: &PublicKey,
    signed_prekey_private: &PrivateKey,
    signed_prekey_public: &PublicKey,
    eph_private: &PrivateKey,
    eph_public: &PublicKey,
    their_identity_key: &PublicKey,
    their_base_key: &PublicKey,
) -> Result<SessionRecord> {
    let our_identity_key_pair = IdentityKeyPair::new(
        IdentityKey::new(*identity_key_public),
        *identity_key_private,
    );

    let our_signed_pre_key_pair = KeyPair::new(*signed_prekey_public, *signed_prekey_private);

    let our_ratchet_key_pair = KeyPair::new(*eph_public, *eph_private);

    let their_identity_key = IdentityKey::new(*their_identity_key);

    let parameters = BobSignalProtocolParameters::new(
        our_identity_key_pair,
        our_signed_pre_key_pair,
        None,
        our_ratchet_key_pair,
        their_identity_key,
        *their_base_key,
    );

    initialize_bob_session_record(&parameters)
}

// End SessionRecord testing functions

#[bridge_fn_void(ffi = "process_prekey_bundle")]
async fn SessionBuilder_ProcessPreKeyBundle(
    bundle: &PreKeyBundle,
    protocol_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_key_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<()> {
    let mut csprng = rand::rngs::OsRng;
    process_prekey_bundle(
        protocol_address,
        session_store,
        identity_key_store,
        bundle,
        &mut csprng,
        ctx,
    )
    .await
}

#[bridge_fn(ffi = "encrypt_message")]
async fn SessionCipher_EncryptMessage(
    ptext: &[u8],
    protocol_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_key_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<CiphertextMessage> {
    message_encrypt(
        ptext,
        protocol_address,
        session_store,
        identity_key_store,
        ctx,
    )
    .await
}

#[bridge_fn_buffer(ffi = "decrypt_message")]
async fn SessionCipher_DecryptSignalMessage<E: Env>(
    env: E,
    message: &SignalMessage,
    protocol_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_key_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<E::Buffer> {
    let mut csprng = rand::rngs::OsRng;
    let ptext = message_decrypt_signal(
        message,
        protocol_address,
        session_store,
        identity_key_store,
        &mut csprng,
        ctx,
    )
    .await?;
    Ok(env.buffer(ptext))
}

#[bridge_fn_buffer(ffi = "decrypt_pre_key_message")]
async fn SessionCipher_DecryptPreKeySignalMessage<E: Env>(
    env: E,
    message: &PreKeySignalMessage,
    protocol_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_key_store: &mut dyn IdentityKeyStore,
    prekey_store: &mut dyn PreKeyStore,
    signed_prekey_store: &mut dyn SignedPreKeyStore,
    ctx: Context,
) -> Result<E::Buffer> {
    let mut csprng = rand::rngs::OsRng;
    let ptext = message_decrypt_prekey(
        message,
        protocol_address,
        session_store,
        identity_key_store,
        prekey_store,
        signed_prekey_store,
        &mut csprng,
        ctx,
    )
    .await?;
    Ok(env.buffer(ptext))
}

#[bridge_fn_buffer(node = "SealedSender_Encrypt")]
async fn SealedSessionCipher_Encrypt<E: Env>(
    env: E,
    destination: &ProtocolAddress,
    content: &UnidentifiedSenderMessageContent,
    identity_key_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<E::Buffer> {
    let mut rng = rand::rngs::OsRng;
    let ctext =
        sealed_sender_encrypt_from_usmc(destination, content, identity_key_store, ctx, &mut rng)
            .await?;
    Ok(env.buffer(ctext))
}

#[bridge_fn_buffer(jni = "SealedSessionCipher_1MultiRecipientEncrypt")]
async fn SealedSender_MultiRecipientEncrypt<E: Env>(
    env: E,
    recipients: &[&ProtocolAddress],
    content: &UnidentifiedSenderMessageContent,
    identity_key_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<E::Buffer> {
    let mut rng = rand::rngs::OsRng;
    let ctext = sealed_sender_multi_recipient_encrypt(
        recipients,
        content,
        identity_key_store,
        ctx,
        &mut rng,
    )
    .await?;
    Ok(env.buffer(ctext))
}

#[bridge_fn_buffer(jni = "SealedSessionCipher_1MultiRecipientMessageForSingleRecipient")]
fn SealedSender_MultiRecipientMessageForSingleRecipient<E: Env>(
    env: E,
    encoded_multi_recipient_message: &[u8],
) -> Result<E::Buffer> {
    let messages = sealed_sender_multi_recipient_fan_out(encoded_multi_recipient_message)?;
    let [single_message] = <[_; 1]>::try_from(messages)
        .map_err(|_| SignalProtocolError::InvalidMessage("encoded for more than one recipient"))?;
    Ok(env.buffer(single_message))
}

#[bridge_fn(node = "SealedSender_DecryptToUsmc")]
async fn SealedSessionCipher_DecryptToUsmc(
    ctext: &[u8],
    identity_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<UnidentifiedSenderMessageContent> {
    sealed_sender_decrypt_to_usmc(ctext, identity_store, ctx).await
}

#[allow(clippy::too_many_arguments)]
#[bridge_fn(ffi = false, jni = false)]
async fn SealedSender_DecryptMessage(
    message: &[u8],
    trust_root: &PublicKey,
    timestamp: u64,
    local_e164: Option<String>,
    local_uuid: String,
    local_device_id: u32,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    prekey_store: &mut dyn PreKeyStore,
    signed_prekey_store: &mut dyn SignedPreKeyStore,
) -> Result<SealedSenderDecryptionResult> {
    sealed_sender_decrypt(
        message,
        trust_root,
        timestamp,
        local_e164,
        local_uuid,
        local_device_id.into(),
        identity_store,
        session_store,
        prekey_store,
        signed_prekey_store,
        None,
    )
    .await
}

#[bridge_fn(jni = "GroupSessionBuilder_1CreateSenderKeyDistributionMessage")]
async fn SenderKeyDistributionMessage_Create(
    sender: &ProtocolAddress,
    distribution_id: Uuid,
    store: &mut dyn SenderKeyStore,
    ctx: Context,
) -> Result<SenderKeyDistributionMessage> {
    let mut csprng = rand::rngs::OsRng;
    create_sender_key_distribution_message(sender, distribution_id, store, &mut csprng, ctx).await
}

#[bridge_fn_void(
    ffi = "process_sender_key_distribution_message",
    jni = "GroupSessionBuilder_1ProcessSenderKeyDistributionMessage"
)]
async fn SenderKeyDistributionMessage_Process(
    sender: &ProtocolAddress,
    sender_key_distribution_message: &SenderKeyDistributionMessage,
    store: &mut dyn SenderKeyStore,
    ctx: Context,
) -> Result<()> {
    process_sender_key_distribution_message(sender, sender_key_distribution_message, store, ctx)
        .await
}

#[bridge_fn(ffi = "group_encrypt_message")]
async fn GroupCipher_EncryptMessage(
    sender: &ProtocolAddress,
    distribution_id: Uuid,
    message: &[u8],
    store: &mut dyn SenderKeyStore,
    ctx: Context,
) -> Result<CiphertextMessage> {
    let mut rng = rand::rngs::OsRng;
    let ctext = group_encrypt(store, sender, distribution_id, message, &mut rng, ctx).await?;
    Ok(CiphertextMessage::SenderKeyMessage(ctext))
}

#[bridge_fn_buffer(ffi = "group_decrypt_message")]
async fn GroupCipher_DecryptMessage<E: Env>(
    env: E,
    sender: &ProtocolAddress,
    message: &[u8],
    store: &mut dyn SenderKeyStore,
    ctx: Context,
) -> Result<E::Buffer> {
    let ptext = group_decrypt(message, store, sender, ctx).await?;
    Ok(env.buffer(ptext))
}
