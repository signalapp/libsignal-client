//
// Copyright 2020, 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::curve::KeyType;

use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::panic::UnwindSafe;

pub type Result<T> = std::result::Result<T, SignalProtocolError>;

#[derive(Debug)]
pub enum SignalProtocolError {
    InvalidArgument(String),
    InvalidState(&'static str, String),

    ProtobufDecodingError(prost::DecodeError),
    ProtobufEncodingError(prost::EncodeError),
    InvalidProtobufEncoding,

    CiphertextMessageTooShort(usize),
    LegacyCiphertextVersion(u8),
    UnrecognizedCiphertextVersion(u8),
    UnrecognizedMessageVersion(u32),

    FingerprintIdentifierMismatch,
    FingerprintVersionMismatch(u32, u32),
    FingerprintParsingError,

    NoKeyTypeIdentifier,
    BadKeyType(u8),
    BadKeyLength(KeyType, usize),

    SignatureValidationFailed,

    UntrustedIdentity(crate::ProtocolAddress),

    InvalidPreKeyId,
    InvalidSignedPreKeyId,

    InvalidRootKeyLength(usize),
    InvalidChainKeyLength(usize),

    InvalidMacKeyLength(usize),
    InvalidCipherCryptographicParameters(usize, usize),
    InvalidCiphertext,

    NoSenderKeyState,

    SessionNotFound(String),
    InvalidSessionStructure,

    DuplicatedMessage(u32, u32),
    InvalidMessage(&'static str),
    InternalError(&'static str),
    FfiBindingError(String),
    ApplicationCallbackError(
        &'static str,
        Box<dyn Error + Send + Sync + UnwindSafe + 'static>,
    ),

    InvalidSealedSenderMessage(String),
    UnknownSealedSenderVersion(u8),
    SealedSenderSelfSend,
}

impl Error for SignalProtocolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SignalProtocolError::ProtobufEncodingError(e) => Some(e),
            SignalProtocolError::ProtobufDecodingError(e) => Some(e),
            SignalProtocolError::ApplicationCallbackError(_, e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<Infallible> for SignalProtocolError {
    fn from(_value: Infallible) -> SignalProtocolError {
        unreachable!()
    }
}

impl From<prost::DecodeError> for SignalProtocolError {
    fn from(value: prost::DecodeError) -> SignalProtocolError {
        SignalProtocolError::ProtobufDecodingError(value)
    }
}

impl From<prost::EncodeError> for SignalProtocolError {
    fn from(value: prost::EncodeError) -> SignalProtocolError {
        SignalProtocolError::ProtobufEncodingError(value)
    }
}

impl fmt::Display for SignalProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignalProtocolError::ProtobufDecodingError(e) => {
                write!(f, "failed to decode protobuf: {}", e)
            }
            SignalProtocolError::ProtobufEncodingError(e) => {
                write!(f, "failed to encode protobuf: {}", e)
            }
            SignalProtocolError::InvalidProtobufEncoding => {
                write!(f, "protobuf encoding was invalid")
            }
            SignalProtocolError::InvalidArgument(s) => write!(f, "invalid argument: {}", s),
            SignalProtocolError::InvalidState(func, s) => {
                write!(f, "invalid state for call to {} to succeed: {}", func, s)
            }
            SignalProtocolError::CiphertextMessageTooShort(size) => {
                write!(f, "ciphertext serialized bytes were too short <{}>", size)
            }
            SignalProtocolError::LegacyCiphertextVersion(version) => {
                write!(f, "ciphertext version was too old <{}>", version)
            }
            SignalProtocolError::UnrecognizedCiphertextVersion(version) => {
                write!(f, "ciphertext version was unrecognized <{}>", version)
            }
            SignalProtocolError::UnrecognizedMessageVersion(message_version) => {
                write!(f, "unrecognized message version <{}>", message_version)
            }
            SignalProtocolError::FingerprintIdentifierMismatch => {
                write!(f, "fingerprint identifiers do not match")
            }
            SignalProtocolError::FingerprintVersionMismatch(theirs, ours) => {
                write!(
                    f,
                    "fingerprint version number mismatch them {} us {}",
                    theirs, ours
                )
            }
            SignalProtocolError::FingerprintParsingError => {
                write!(f, "fingerprint parsing error")
            }
            SignalProtocolError::NoKeyTypeIdentifier => write!(f, "no key type identifier"),
            SignalProtocolError::BadKeyType(t) => write!(f, "bad key type <{:#04x}>", t),
            SignalProtocolError::BadKeyLength(t, l) => {
                write!(f, "bad key length <{}> for key with type <{}>", l, t)
            }
            SignalProtocolError::InvalidPreKeyId => write!(f, "invalid prekey identifier"),
            SignalProtocolError::InvalidSignedPreKeyId => {
                write!(f, "invalid signed prekey identifier")
            }
            SignalProtocolError::InvalidChainKeyLength(l) => {
                write!(f, "invalid chain key length <{}>", l)
            }
            SignalProtocolError::InvalidRootKeyLength(l) => {
                write!(f, "invalid root key length <{}>", l)
            }
            SignalProtocolError::InvalidCipherCryptographicParameters(kl, nl) => write!(
                f,
                "invalid cipher key length <{}> or nonce length <{}>",
                kl, nl
            ),
            SignalProtocolError::InvalidMacKeyLength(l) => {
                write!(f, "invalid MAC key length <{}>", l)
            }
            SignalProtocolError::UntrustedIdentity(addr) => {
                write!(f, "untrusted identity for address {}", addr)
            }
            SignalProtocolError::SignatureValidationFailed => {
                write!(f, "invalid signature detected")
            }
            SignalProtocolError::InvalidCiphertext => write!(f, "invalid ciphertext message"),
            SignalProtocolError::SessionNotFound(who) => {
                write!(f, "session with '{}' not found", who)
            }
            SignalProtocolError::InvalidSessionStructure => write!(f, "invalid session structure"),
            SignalProtocolError::DuplicatedMessage(i, c) => {
                write!(f, "message with old counter {} / {}", i, c)
            }
            SignalProtocolError::InvalidMessage(m) => write!(f, "invalid message {}", m),
            SignalProtocolError::InternalError(m) => write!(f, "internal error {}", m),
            SignalProtocolError::NoSenderKeyState => write!(f, "no sender key state"),
            SignalProtocolError::FfiBindingError(m) => {
                write!(f, "error while invoking an ffi callback: {}", m)
            }
            SignalProtocolError::ApplicationCallbackError(func, c) => {
                write!(f, "application callback {} failed with {}", func, c)
            }
            SignalProtocolError::InvalidSealedSenderMessage(m) => {
                write!(f, "invalid sealed sender message {}", m)
            }
            SignalProtocolError::UnknownSealedSenderVersion(v) => {
                write!(f, "unknown sealed sender message version {}", v)
            }
            SignalProtocolError::SealedSenderSelfSend => {
                write!(f, "self send of a sealed sender message")
            }
        }
    }
}
