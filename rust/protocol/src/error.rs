//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::curve::KeyType;

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

#[derive(Debug, Error)]
pub enum SignalProtocolError {
    #[error("invalid argument: {}", .0)]
    InvalidArgument(String),
    #[error("invalid state for call to {} to succeed: {}", .0, .1)]
    InvalidState(&'static str, String),

    #[error("failed to decode protobuf: {}", .0)]
    ProtobufDecodingError(#[from] prost::DecodeError),
    #[error("failed to encode protobuf: {}", .0)]
    ProtobufEncodingError(#[from] prost::EncodeError),
    #[error("protobuf encoding was invalid")]
    InvalidProtobufEncoding,

    #[error("ciphertext serialized bytes were too short <{}>", .0)]
    CiphertextMessageTooShort(usize),
    #[error("ciphertext version was too old <{}>", .0)]
    LegacyCiphertextVersion(u8),
    #[error("ciphertext version was unrecognized <{}>", .0)]
    UnrecognizedCiphertextVersion(u8),
    #[error("unrecognized message version <{}>", .0)]
    UnrecognizedMessageVersion(u32),

    #[error("fingerprint identifiers do not match")]
    FingerprintIdentifierMismatch,
    #[error("fingerprint version number mismatch them {} us {}", .0, .1)]
    FingerprintVersionMismatch(u32, u32),
    #[error("fingerprint parsing error")]
    FingerprintParsingError,

    #[error("no key type identifier")]
    NoKeyTypeIdentifier,
    #[error("bad key type <{:#04x}>", .0)]
    BadKeyType(u8),
    #[error("bad key length <{}> for key with type <{}>", .1, .0)]
    BadKeyLength(KeyType, usize),

    #[error("invalid signature detected")]
    SignatureValidationFailed,

    #[error("untrusted identity for address {}", .0)]
    UntrustedIdentity(crate::ProtocolAddress),

    #[error("invalid prekey identifier")]
    InvalidPreKeyId,
    #[error("invalid signed prekey identifier")]
    InvalidSignedPreKeyId,

    #[error("invalid root key length <{}>", .0)]
    InvalidRootKeyLength(usize),
    #[error("invalid chain key length <{}>", .0)]
    InvalidChainKeyLength(usize),

    #[error("invalid MAC key length <{}>", .0)]
    InvalidMacKeyLength(usize),
    #[error("invalid cipher key length <{}> or nonce length <{}>", .0, .1)]
    InvalidCipherCryptographicParameters(usize, usize),
    #[error("invalid ciphertext message")]
    InvalidCiphertext,

    #[error("no sender key state")]
    NoSenderKeyState,

    #[error("session with '{}' not found", .0)]
    SessionNotFound(String),
    #[error("invalid session structure")]
    InvalidSessionStructure,

    #[error("message with old counter {} / {}", .0, .1)]
    DuplicatedMessage(u32, u32),
    #[error("invalid message {}", .0)]
    InvalidMessage(&'static str),
    #[error("internal error {}", .0)]
    InternalError(&'static str),
    #[error("error while invoking an ffi callback: {}", .0)]
    FfiBindingError(String),
    #[error("error in method call '{}': {}", .0, .1)]
    ApplicationCallbackError(&'static str, #[source] CallbackErrorWrapper),

    #[error("invalid sealed sender message {}", .0)]
    InvalidSealedSenderMessage(String),
    #[error("unknown sealed sender message version {}", .0)]
    UnknownSealedSenderVersion(u8),
    #[error("self send of a sealed sender message")]
    SealedSenderSelfSend,
}
