//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod keys;
mod params;

pub use self::keys::{ChainKey, MessageKeys, RootKey};
pub use self::params::{AliceSignalProtocolParameters, BobSignalProtocolParameters};
use crate::proto::storage::SessionStructure;
use crate::protocol::{MessageVersion, CIPHERTEXT_MESSAGE_CURRENT_VERSION};
use crate::state::SessionState;
use crate::{KeyPair, Result, SessionRecord};
use rand::{CryptoRng, Rng};

fn derive_keys(secret_input: &[u8]) -> Result<(RootKey, ChainKey)> {
    let kdf = crate::kdf::HKDF::new_for_version(MessageVersion::V3)?;

    let secrets = kdf.derive_secrets(secret_input, b"WhisperText", 64)?;

    let root_key = RootKey::new(kdf, &secrets[0..32])?;
    let chain_key = ChainKey::new(kdf, &secrets[32..64], 0)?;

    Ok((root_key, chain_key))
}

pub(crate) fn initialize_alice_session<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    mut csprng: &mut R,
) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    let sending_ratchet_key = KeyPair::generate(&mut csprng);

    let mut secrets = Vec::with_capacity(32 * 5);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    let our_base_private_key = parameters.our_base_key_pair().private_key;

    secrets.extend_from_slice(
        &parameters
            .our_identity_key_pair()
            .private_key()
            .calculate_agreement(parameters.their_signed_pre_key())?,
    );

    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(parameters.their_identity_key().public_key())?,
    );

    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(parameters.their_signed_pre_key())?,
    );

    if let Some(their_one_time_prekey) = parameters.their_one_time_pre_key() {
        secrets
            .extend_from_slice(&our_base_private_key.calculate_agreement(their_one_time_prekey)?);
    }

    let (root_key, chain_key) = derive_keys(&secrets)?;

    let (sending_chain_root_key, sending_chain_chain_key) = root_key.create_chain(
        parameters.their_ratchet_key(),
        &sending_ratchet_key.private_key,
    )?;

    let session = SessionStructure {
        session_version: CIPHERTEXT_MESSAGE_CURRENT_VERSION as u32,
        local_identity_public: local_identity.public_key().serialize().to_vec(),
        remote_identity_public: parameters.their_identity_key().serialize().to_vec(),
        root_key: sending_chain_root_key.key().to_vec(),
        previous_counter: 0,
        sender_chain: None,
        receiver_chains: vec![],
        pending_pre_key: None,
        remote_registration_id: 0,
        local_registration_id: 0,
        needs_refresh: false,
        alice_base_key: vec![],
    };

    let mut session = SessionState::new(session);

    session.add_receiver_chain(parameters.their_ratchet_key(), &chain_key)?;
    session.set_sender_chain(&sending_ratchet_key, &sending_chain_chain_key)?;

    Ok(session)
}

pub(crate) fn initialize_bob_session(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    let mut secrets = Vec::with_capacity(32 * 5);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    secrets.extend_from_slice(
        &parameters
            .our_signed_pre_key_pair()
            .private_key
            .calculate_agreement(parameters.their_identity_key().public_key())?,
    );

    secrets.extend_from_slice(
        &parameters
            .our_identity_key_pair()
            .private_key()
            .calculate_agreement(parameters.their_base_key())?,
    );

    secrets.extend_from_slice(
        &parameters
            .our_signed_pre_key_pair()
            .private_key
            .calculate_agreement(parameters.their_base_key())?,
    );

    if let Some(our_one_time_pre_key_pair) = parameters.our_one_time_pre_key_pair() {
        secrets.extend_from_slice(
            &our_one_time_pre_key_pair
                .private_key
                .calculate_agreement(parameters.their_base_key())?,
        );
    }

    let (root_key, chain_key) = derive_keys(&secrets)?;

    let session = SessionStructure {
        session_version: CIPHERTEXT_MESSAGE_CURRENT_VERSION as u32,
        local_identity_public: local_identity.public_key().serialize().to_vec(),
        remote_identity_public: parameters.their_identity_key().serialize().to_vec(),
        root_key: root_key.key().to_vec(),
        previous_counter: 0,
        sender_chain: None,
        receiver_chains: vec![],
        pending_pre_key: None,
        remote_registration_id: 0,
        local_registration_id: 0,
        needs_refresh: false,
        alice_base_key: vec![],
    };

    let mut session = SessionState::new(session);

    session.set_sender_chain(&parameters.our_ratchet_key_pair(), &chain_key)?;

    Ok(session)
}

pub fn initialize_alice_session_record<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    csprng: &mut R,
) -> Result<SessionRecord> {
    Ok(SessionRecord::new(initialize_alice_session(
        parameters, csprng,
    )?))
}

pub fn initialize_bob_session_record(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionRecord> {
    Ok(SessionRecord::new(initialize_bob_session(parameters)?))
}
