//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Rust implementation of the **[Signal Protocol]** for asynchronous
//! forward-secret public-key cryptography.
//!
//! In particular, this library implements operations conforming to the following specifications:
//! - the **[X3DH]** key agreement protocol,
//! - the **[Double Ratchet]** *(Axolotl)* messaging protocol,
//!
//! [Signal Protocol]: https://signal.org/
//! [X3DH]: https://signal.org/docs/specifications/x3dh/
//! [Double Ratchet]: https://signal.org/docs/specifications/doubleratchet/

#![warn(clippy::unwrap_used)]
#![deny(unsafe_code)]

// TODO(https://github.com/signalapp/libsignal-client/issues/285): it should be an aspiration to
// eventually warn and then error for public members without docstrings. Also see
// https://doc.rust-lang.org/rustdoc/what-to-include.html for background.
// #![warn(missing_docs)]

// Make all doctests fail if they produce any warnings.
#![doc(test(attr(deny(warnings))))]

mod address;
mod consts;
mod crypto;
mod curve;
pub mod error;
mod fingerprint;
mod group_cipher;
mod identity_key;
mod kdf;
mod proto;
mod protocol;
mod ratchet;
mod sealed_sender;
mod sender_keys;
mod session;
mod session_cipher;
mod state;
mod storage;
mod utils;

use error::Result;

pub use {
    address::{DeviceId, ProtocolAddress},
    curve::{KeyPair, PrivateKey, PublicKey},
    error::SignalProtocolError,
    fingerprint::{DisplayableFingerprint, Fingerprint, ScannableFingerprint},
    group_cipher::{
        create_sender_key_distribution_message, group_decrypt, group_encrypt,
        process_sender_key_distribution_message,
    },
    identity_key::{IdentityKey, IdentityKeyPair},
    kdf::HKDF,
    protocol::{
        extract_decryption_error_message_from_serialized_content, CiphertextMessage,
        CiphertextMessageType, DecryptionErrorMessage, PlaintextContent, PreKeySignalMessage,
        SenderKeyDistributionMessage, SenderKeyMessage, SignalMessage,
    },
    ratchet::{
        initialize_alice_session_record, initialize_bob_session_record,
        AliceSignalProtocolParameters, BobSignalProtocolParameters,
    },
    sealed_sender::{
        sealed_sender_decrypt, sealed_sender_decrypt_to_usmc, sealed_sender_encrypt,
        sealed_sender_encrypt_from_usmc, sealed_sender_multi_recipient_encrypt,
        sealed_sender_multi_recipient_fan_out, ContentHint, SealedSenderDecryptionResult,
        SenderCertificate, ServerCertificate, UnidentifiedSenderMessageContent,
    },
    sender_keys::SenderKeyRecord,
    session::{process_prekey, process_prekey_bundle},
    session_cipher::{
        message_decrypt, message_decrypt_prekey, message_decrypt_signal, message_encrypt,
    },
    state::{PreKeyBundle, PreKeyRecord, SessionRecord, SignedPreKeyRecord},
    storage::{
        Context, Direction, IdentityKeyStore, InMemIdentityKeyStore, InMemPreKeyStore,
        InMemSenderKeyStore, InMemSessionStore, InMemSignalProtocolStore, InMemSignedPreKeyStore,
        PreKeyStore, ProtocolStore, SenderKeyStore, SessionStore, SignedPreKeyStore,
    },
};
