//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::curve::KeyType;

use displaydoc::Display;
use thiserror::Error;

use std::fmt;
use std::panic::UnwindSafe;

pub type Result<T> = std::result::Result<T, SignalProtocolError>;

/// Wraps a boxed error struct and delegates the [std::error::Error] trait to it.
///
/// A [Box] wrapping an error apparently does not implement [std::error::Error] itself, which breaks
/// the `#[source]` annotation from the [thiserror::Error] derive macro that requires its target to
/// quack like an error. So we have to create this wrapper struct to do that ourselves in order to
/// nicely write `#[derive(Debug, Error)]` in the declaration of [SignalProtocolError].
#[derive(Debug)]
pub struct CallbackErrorWrapper(
    pub Box<dyn std::error::Error + Send + Sync + UnwindSafe + 'static>,
);

impl fmt::Display for CallbackErrorWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for CallbackErrorWrapper {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

#[derive(Debug, Display, Error)]
pub enum SignalProtocolError {
    /// invalid argument: {0}
    InvalidArgument(String),
    /// invalid state for call to {0} to succeed: {1}
    InvalidState(&'static str, String),

    /// failed to decode protobuf: {0}
    ProtobufDecodingError(#[from] prost::DecodeError),
    /// failed to encode protobuf: {0}
    ProtobufEncodingError(#[from] prost::EncodeError),
    /// protobuf encoding was invalid
    InvalidProtobufEncoding,

    /// ciphertext serialized bytes were too short <{0}>
    CiphertextMessageTooShort(usize),
    /// ciphertext version was too old <{0}>
    LegacyCiphertextVersion(u8),
    /// ciphertext version was unrecognized <{0}>
    UnrecognizedCiphertextVersion(u8),
    /// unrecognized message version <{0}>
    UnrecognizedMessageVersion(u32),

    /// fingerprint identifiers do not match
    FingerprintIdentifierMismatch,
    /// fingerprint version number mismatch them {0} us {1}
    FingerprintVersionMismatch(u32, u32),
    /// fingerprint parsing error
    FingerprintParsingError,

    /// no key type identifier
    NoKeyTypeIdentifier,
    /// bad key type <{0:#04x}>
    BadKeyType(u8),
    /// bad key length <{0}> for key with type <{1}>
    BadKeyLength(KeyType, usize),

    /// invalid signature detected
    SignatureValidationFailed,

    /// untrusted identity for address {0}
    UntrustedIdentity(crate::ProtocolAddress),

    /// invalid prekey identifier
    InvalidPreKeyId,
    /// invalid signed prekey identifier
    InvalidSignedPreKeyId,

    /// invalid root key length <{0}>
    InvalidRootKeyLength(usize),
    /// invalid chain key length <{0}>
    InvalidChainKeyLength(usize),

    /// invalid MAC key length <{0}>
    InvalidMacKeyLength(usize),
    /// invalid cipher key length <{0}> or nonce length <{1}>
    InvalidCipherCryptographicParameters(usize, usize),
    /// invalid ciphertext message
    InvalidCiphertext,

    /// no sender key state
    NoSenderKeyState,

    /// session with '{0}' not found
    SessionNotFound(String),
    /// invalid session structure
    InvalidSessionStructure,

    /// message with old counter {0} / {1}
    DuplicatedMessage(u32, u32),
    /// invalid message {0}
    InvalidMessage(&'static str),
    /// internal error {0}
    InternalError(&'static str),
    /// error while invoking an ffi callback: {0}
    FfiBindingError(String),
    /// error in method call '{0}': {1}
    ApplicationCallbackError(&'static str, #[source] CallbackErrorWrapper),

    /// invalid sealed sender message {0}
    InvalidSealedSenderMessage(String),
    /// unknown sealed sender message version {0}
    UnknownSealedSenderVersion(u8),
    /// self send of a sealed sender message
    SealedSenderSelfSend,
}
