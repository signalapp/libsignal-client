//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Errors that may occur during various stages of the Signal Protocol.

#![warn(missing_docs)]

use crate::curve::KeyType;

#[cfg(doc)]
pub use crate::{
    address::ProtocolAddress,
    curve::{PrivateKey, PublicKey},
    group_cipher::{group_decrypt, group_encrypt},
    protocol::{SenderKeyMessage, SignalMessage, CIPHERTEXT_MESSAGE_CURRENT_VERSION},
    ratchet::{ChainKey, RootKey},
    sealed_sender::{sealed_sender_decrypt, sealed_sender_multi_recipient_encrypt},
    sender_keys::SenderKeyRecord,
    session_cipher::{message_decrypt, message_encrypt},
    state::{PreKeyId, PreKeyRecord, SignedPreKeyId, SignedPreKeyRecord},
    storage::{IdentityKeyStore, PreKeyStore, SenderKeyStore, SessionStore, SignedPreKeyStore},
};
#[cfg(doc)]
use uuid::Uuid;

use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::panic::UnwindSafe;

/// Return type for all fallible operations in this crate.
pub type Result<T> = std::result::Result<T, SignalProtocolError>;

/// Error states recognized by the Signal Protocol.
#[derive(Debug)]
pub enum SignalProtocolError {
    /// Raised if an invalid argument is provided to any Signal API methods.
    ///
    /// Prefer to use lifetimes, static-sized slices, and dedicated wrapper structs in API
    /// signatures to minimize the need to raise this error to FFI boundaries.
    InvalidArgument(String),
    /// Raised if some optional value was missing before performing some operation which needed it.
    ///
    /// Prefer to avoid returning [std::result::Result] and [Option] from struct methods in cases
    /// where they're not necessary for trait polymorphism, as well as using dedicated wrapper
    /// structs in API signatures, to minimize the need to raise this error.
    InvalidState(&'static str, String),

    /// Raised if there was an error decoding a protobuf from bytes.
    ProtobufDecodingError(prost::DecodeError),
    /// Raised if there was an error encoding a protobuf into bytes.
    ProtobufEncodingError(prost::EncodeError),
    /// Raised if a field in a protobuf is invalid in some way.
    ///
    /// Prefer to raise [Self::InvalidState] except in methods which directly decode protobufs.
    InvalidProtobufEncoding,

    /// Raised if some ciphertext was deserialized from a too-small slice.
    ///
    /// Prefer to make API method signatures and wrapper structs consume and produce static-sized
    /// byte slices to minimize the need to raise this error.
    CiphertextMessageTooShort(usize),
    /// Raised if the ciphertext version decoded from a protobuf is older than this client.
    ///
    /// The current client's ciphertext version is at [CIPHERTEXT_MESSAGE_CURRENT_VERSION].
    LegacyCiphertextVersion(u8),
    /// Raised if the ciphertext version decoded from a protobuf is newer than this client.
    ///
    /// The current client's ciphertext version is at [CIPHERTEXT_MESSAGE_CURRENT_VERSION].
    UnrecognizedCiphertextVersion(u8),
    /// Raised if the ciphertext version decoded from a protobuf fails to match the cached version
    /// for the message chain that message originates from.
    ///
    /// *TODO: This case should wrap the same numeric type as [Self::LegacyCiphertextVersion] and
    /// [Self::UnrecognizedCiphertextVersion]. This dissonance is addressed in
    /// <https://github.com/signalapp/libsignal-client/pull/289>.*
    UnrecognizedMessageVersion(u32),

    #[deprecated(since = "0.1.0", note = "This is only raised by legacy clients.")]
    /// Raised if a fingerprint's identifier (from [ProtocolAddress::name]) fails to match
    /// another fingerprint.
    FingerprintIdentifierMismatch,
    /// Raised if a fingerprint version decoded from a protobuf has an unexpected value.
    FingerprintVersionMismatch(u32, u32),
    /// Raised if a field in a fingerprint protobuf is invalid in some way.
    ///
    /// Similar to [Self::InvalidProtobufEncoding].
    FingerprintParsingError,

    /// Raised if a [PublicKey] is deserialized from an empty slice.
    ///
    /// Prefer to use static-sized slices in API method signatures and struct fields to minimize the
    /// need to raise this error.
    NoKeyTypeIdentifier,
    /// Raised if a [KeyType] decoded from a [u8] has an unrecognized value.
    BadKeyType(u8),
    /// Raised if a [PublicKey] or [PrivateKey] is deserialized from a slice of incorrect length.
    ///
    /// Prefer to use static-sized slices in API method signatures and struct fields to minimize the
    /// need to raise this error.
    BadKeyLength(KeyType, usize),

    /// Raised if signature validation fails for a [SignedPreKeyRecord] or a [SenderKeyMessage].
    SignatureValidationFailed,

    /// Raised if an identity verification check fails in [message_encrypt] or [message_decrypt].
    UntrustedIdentity(crate::ProtocolAddress),

    /// Raised if a [PreKeyId] could not be resolved to a [PreKeyRecord] by a [PreKeyStore].
    InvalidPreKeyId,
    /// Raised if a [SignedPreKeyId] could not be resolved to a [SignedPreKeyRecord] by
    /// a [SignedPreKeyStore].
    InvalidSignedPreKeyId,

    /// Raised if a [RootKey] is deserialized from an incorrectly-sized slice.
    ///
    /// Prefer to use static-sized slices in API method signatures and struct fields to minimize the
    /// need to raise this error.
    InvalidRootKeyLength(usize),
    /// Raised if a [ChainKey] is deserialized from an incorrectly-sized slice.
    ///
    /// Prefer to use static-sized slices in API method signatures and struct fields to minimize the
    /// need to raise this error.
    InvalidChainKeyLength(usize),

    /// Raised if a MAC key is deserialized from an incorrectly-sized slice.
    ///
    /// Prefer to use static-sized slices in API method signatures and struct fields to minimize the
    /// need to raise this error.
    InvalidMacKeyLength(usize),
    /// Raised if the key or initialization vector is deserialized from an incorrectly-sized slice.
    ///
    /// Prefer to use static-sized slices in API method signatures and struct fields to minimize the
    /// need to raise this error.
    InvalidCipherCryptographicParameters(usize, usize),
    /// Raised if some ciphertext was the wrong size or could not be decrypted.
    InvalidCiphertext,

    /// Raised if a [SenderKeyStore] is unable to locate a [SenderKeyRecord] for a given
    /// *([ProtocolAddress], [Uuid])* pair in [group_encrypt] or [group_decrypt].
    NoSenderKeyState,

    /// Raised if an [IdentityKeyStore] does not contain an entry for a [ProtocolAddress], or
    /// alternately if a [SessionStore] does not contain a session for a given [ProtocolAddress].
    SessionNotFound(String),
    /// Raised if a [SessionStore] does not contain a remote identity key to validate.
    ///
    /// Similar to [Self::InvalidState].
    InvalidSessionStructure,

    /// Raised if the same message is decrypted twice so it can be discarded.
    DuplicatedMessage(u32, u32),
    /// Raised if a [SignalMessage] could not be decrypted or some field had an unexpected value.
    ///
    /// *TODO: what differentiates this from [Self::CiphertextMessageTooShort]?*
    InvalidMessage(&'static str),
    /// Raised if encryption fails in [sealed_sender_multi_recipient_encrypt].
    ///
    /// Prefer to use a more specialized error case like [Self::InvalidCiphertext].
    InternalError(&'static str),
    /// Raised to propagate an error from an FFI callback.
    FfiBindingError(String),
    /// Raised to propagate an error through to an FFI exception along with a boxed handle.
    ApplicationCallbackError(
        &'static str,
        Box<dyn Error + Send + Sync + UnwindSafe + 'static>,
    ),

    /// Raised if an [crate::sealed_sender::UnidentifiedSenderMessage] could not be
    /// deserialized successfully.
    ///
    /// *TODO: this sounds a lot like [Self::InvalidProtobufEncoding] or [Self::UntrustedIdentity]?*
    InvalidSealedSenderMessage(String),
    /// Raised if an version decoded from a [crate::sealed_sender::UnidentifiedSenderMessage]
    /// was unrecognized.
    UnknownSealedSenderVersion(u8),
    /// Raised if [sealed_sender_decrypt] finds that the message came from this exact client.
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

/// According to the docs for [Infallible], this error case should never be raised, so we just use
/// `unreachable!()`.
impl From<Infallible> for SignalProtocolError {
    fn from(_value: Infallible) -> SignalProtocolError {
        unreachable!("Infallible From impl reached")
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
            #[allow(deprecated)]
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
                write!(f, "bad key length <{:?}> for key with type <{:?}>", l, t)
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
