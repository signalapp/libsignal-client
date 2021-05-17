//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::consts::MAX_FORWARD_JUMPS;
use crate::crypto;
use crate::ratchet::{ChainKey, MessageKeys};
use crate::session;
use crate::state::SessionState;
use crate::{
    CiphertextMessage, Context, Direction, IdentityKeyStore, KeyPair, PreKeySignalMessage,
    PreKeyStore, ProtocolAddress, PublicKey, Result, SessionRecord, SessionStore, SignalMessage,
    SignalProtocolError, SignedPreKeyStore,
};

use std::convert::TryInto;

use rand::{CryptoRng, Rng};

pub async fn message_encrypt(
    ptext: &[u8],
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<CiphertextMessage> {
    let mut session_record = session_store
        .load_session(&remote_address, ctx)
        .await?
        .ok_or_else(|| SignalProtocolError::SessionNotFound(format!("{}", remote_address)))?;
    let session_state = session_record.session_state_mut()?;

    let chain_key = session_state.get_sender_chain_key()?;

    let message_keys = chain_key.message_keys()?;

    let sender_ephemeral = session_state.sender_ratchet_key()?;
    let previous_counter = session_state.previous_counter()?;
    let session_version = session_state.session_version()? as u8;

    let local_identity_key = session_state.local_identity_key()?;
    let their_identity_key = session_state
        .remote_identity_key()?
        .ok_or(SignalProtocolError::InvalidSessionStructure)?;

    let ctext = crypto::aes_256_cbc_encrypt(ptext, message_keys.cipher_key(), message_keys.iv())?;

    let message = if let Some(items) = session_state.unacknowledged_pre_key_message_items()? {
        let local_registration_id = session_state.local_registration_id()?;

        log::info!(
            "Building PreKeyWhisperMessage for: {} with preKeyId: {}",
            remote_address,
            items
                .pre_key_id()?
                .map_or_else(|| "<none>".to_string(), |id| format!("{:?}", id))
        );

        let message = SignalMessage::new(
            session_version.try_into()?,
            message_keys.mac_key(),
            sender_ephemeral,
            chain_key.index(),
            previous_counter,
            &ctext,
            &local_identity_key,
            &their_identity_key,
        )?;

        CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::new(
            session_version.try_into()?,
            local_registration_id.into(),
            items.pre_key_id()?,
            items.signed_pre_key_id()?,
            *items.base_key()?,
            local_identity_key,
            message,
        )?)
    } else {
        CiphertextMessage::SignalMessage(SignalMessage::new(
            session_version.try_into()?,
            message_keys.mac_key(),
            sender_ephemeral,
            chain_key.index(),
            previous_counter,
            &ctext,
            &local_identity_key,
            &their_identity_key,
        )?)
    };

    session_state.set_sender_chain_key(&chain_key.next_chain_key()?)?;

    // XXX why is this check after everything else?!!
    if !identity_store
        .is_trusted_identity(
            &remote_address,
            &their_identity_key,
            Direction::Sending,
            ctx,
        )
        .await?
    {
        log::warn!(
            "Identity key {} is not trusted for remote address {}",
            their_identity_key
                .public_key()
                .public_key_bytes()
                .map_or_else(|e| format!("<error: {}>", e), hex::encode),
            remote_address,
        );
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    // XXX this could be combined with the above call to the identity store (in a new API)
    identity_store
        .save_identity(&remote_address, &their_identity_key, ctx)
        .await?;

    session_store
        .store_session(&remote_address, &session_record, ctx)
        .await?;
    Ok(message)
}

pub async fn message_decrypt<R: Rng + CryptoRng>(
    ciphertext: &CiphertextMessage,
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &mut dyn SignedPreKeyStore,
    csprng: &mut R,
    ctx: Context,
) -> Result<Vec<u8>> {
    match ciphertext {
        CiphertextMessage::SignalMessage(m) => {
            message_decrypt_signal(
                m,
                remote_address,
                session_store,
                identity_store,
                csprng,
                ctx,
            )
            .await
        }
        CiphertextMessage::PreKeySignalMessage(m) => {
            message_decrypt_prekey(
                m,
                remote_address,
                session_store,
                identity_store,
                pre_key_store,
                signed_pre_key_store,
                csprng,
                ctx,
            )
            .await
        }
        _ => Err(SignalProtocolError::InvalidArgument(
            "SessionCipher::decrypt cannot decrypt this message type".to_owned(),
        )),
    }
}

pub async fn message_decrypt_prekey<R: Rng + CryptoRng>(
    ciphertext: &PreKeySignalMessage,
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &mut dyn SignedPreKeyStore,
    csprng: &mut R,
    ctx: Context,
) -> Result<Vec<u8>> {
    let mut session_record = session_store
        .load_session(&remote_address, ctx)
        .await?
        .unwrap_or_else(SessionRecord::new_fresh);

    // Make sure we log the session state if we fail to process the pre-key.
    let pre_key_id_or_err = session::process_prekey(
        ciphertext,
        &remote_address,
        &mut session_record,
        identity_store,
        pre_key_store,
        signed_pre_key_store,
        ctx,
    )
    .await;

    let pre_key_id = match pre_key_id_or_err {
        Ok(id) => id,
        Err(e) => {
            let errs = [e];
            log::error!(
                "{}",
                create_decryption_failure_log(
                    remote_address,
                    &errs,
                    &session_record,
                    ciphertext.message()
                )?
            );
            let [e] = errs;
            return Err(e);
        }
    };

    let ptext = decrypt_message_with_record(
        &remote_address,
        &mut session_record,
        ciphertext.message(),
        csprng,
    )?;

    session_store
        .store_session(&remote_address, &session_record, ctx)
        .await?;

    if let Some(pre_key_id) = pre_key_id {
        pre_key_store.remove_pre_key(pre_key_id, ctx).await?;
    }

    Ok(ptext)
}

pub async fn message_decrypt_signal<R: Rng + CryptoRng>(
    ciphertext: &SignalMessage,
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    csprng: &mut R,
    ctx: Context,
) -> Result<Vec<u8>> {
    let mut session_record = session_store
        .load_session(&remote_address, ctx)
        .await?
        .ok_or_else(|| SignalProtocolError::SessionNotFound(format!("{}", remote_address)))?;

    let ptext =
        decrypt_message_with_record(&remote_address, &mut session_record, ciphertext, csprng)?;

    // Why are we performing this check after decryption instead of before?
    let their_identity_key = session_record
        .session_state()?
        .remote_identity_key()?
        .ok_or(SignalProtocolError::InvalidSessionStructure)?;

    if !identity_store
        .is_trusted_identity(
            &remote_address,
            &their_identity_key,
            Direction::Receiving,
            ctx,
        )
        .await?
    {
        log::warn!(
            "Identity key {} is not trusted for remote address {}",
            their_identity_key
                .public_key()
                .public_key_bytes()
                .map_or_else(|e| format!("<error: {}>", e), hex::encode),
            remote_address,
        );
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    identity_store
        .save_identity(&remote_address, &their_identity_key, ctx)
        .await?;

    session_store
        .store_session(&remote_address, &session_record, ctx)
        .await?;

    Ok(ptext)
}

fn create_decryption_failure_log(
    remote_address: &ProtocolAddress,
    errs: &[SignalProtocolError],
    record: &SessionRecord,
    ciphertext: &SignalMessage,
) -> Result<String> {
    let mut lines = vec![];

    lines.push(format!(
        "Message from {} failed to decrypt; sender ratchet public key {} message counter {}",
        remote_address,
        hex::encode(ciphertext.sender_ratchet_key().public_key_bytes()?),
        ciphertext.counter()
    ));

    let current_session = record.session_state().ok();
    for (idx, (state, err)) in current_session
        .into_iter()
        .chain(record.previous_session_states()?)
        .zip(errs.iter().map(Some).chain(std::iter::repeat(None)))
        .enumerate()
    {
        let chains = state.all_receiver_chain_logging_info()?;
        match err {
            Some(err) => {
                lines.push(format!(
                    "Candidate session {} failed with '{}', had {} receiver chains",
                    idx,
                    err,
                    chains.len()
                ));
            }
            None => {
                lines.push(format!(
                    "Candidate session {} had {} receiver chains",
                    idx,
                    chains.len()
                ));
            }
        }

        for chain in chains {
            let chain_idx = match chain.1 {
                Some(i) => format!("{}", i),
                None => "missing in protobuf".to_string(),
            };

            lines.push(format!(
                "Receiver chain with sender ratchet public key {} chain key index {}",
                hex::encode(chain.0),
                chain_idx
            ));
        }
    }

    Ok(lines.join("\n"))
}

fn decrypt_message_with_record<R: Rng + CryptoRng>(
    remote_address: &ProtocolAddress,
    record: &mut SessionRecord,
    ciphertext: &SignalMessage,
    csprng: &mut R,
) -> Result<Vec<u8>> {
    let log_decryption_failure = |state: &SessionState, error: &SignalProtocolError| {
        log::error!(
            "Failed to decrypt whisper message with ratchet key: {} and counter: {}. \
             Session loaded for {}. Local session has base key: {} and counter: {}. {}",
            ciphertext
                .sender_ratchet_key()
                .public_key_bytes()
                .map_or_else(|e| format!("<error: {}>", e), hex::encode),
            ciphertext.counter(),
            remote_address,
            state
                .sender_ratchet_key_for_logging()
                .unwrap_or_else(|e| format!("<error: {}>", e)),
            state.previous_counter().unwrap_or(u32::MAX),
            error
        );
    };

    let mut errs = vec![];

    if let Ok(current_state) = record.session_state() {
        let mut current_state = current_state.clone();
        let result =
            decrypt_message_with_state(&mut current_state, ciphertext, remote_address, csprng);

        match result {
            Ok(ptext) => {
                log::debug!(
                    "successfully decrypted with current session state (base key {})",
                    hex::encode(
                        current_state
                            .sender_ratchet_key_for_logging()
                            .expect("successful decrypt always has a valid base key")
                    ),
                );
                record.set_session_state(current_state)?; // update the state
                return Ok(ptext);
            }
            Err(SignalProtocolError::DuplicatedMessage(_, _)) => {
                return result;
            }
            Err(e) => {
                log_decryption_failure(&current_state, &e);
                errs.push(e);
            }
        }
    }

    // Try some old sessions:
    let mut updated_session = None;

    for (idx, previous) in record.previous_session_states()?.enumerate() {
        let mut updated = previous.clone();

        let result = decrypt_message_with_state(&mut updated, ciphertext, remote_address, csprng);

        match result {
            Ok(ptext) => {
                log::info!(
                    "successfully decrypted with PREVIOUS session state (base key {})",
                    hex::encode(
                        previous
                            .sender_ratchet_key_for_logging()
                            .expect("successful decrypt always has a valid base key")
                    ),
                );
                updated_session = Some((ptext, idx, updated));
                break;
            }
            Err(SignalProtocolError::DuplicatedMessage(_, _)) => {
                return result;
            }
            Err(e) => {
                log_decryption_failure(&previous, &e);
                errs.push(e);
            }
        }
    }

    if let Some((ptext, idx, updated_session)) = updated_session {
        record.promote_old_session(idx, updated_session)?;
        Ok(ptext)
    } else {
        let previous_state_count = || {
            record.previous_session_states().map_or_else(
                |e| format!("<error: {}>", e),
                |states| states.count().to_string(),
            )
        };

        if let Ok(current_state) = record.session_state() {
            log::error!(
                "No valid session for recipient: {}, current session base key {}, number of previous states: {}",
                remote_address,
                current_state.sender_ratchet_key_for_logging()
                .unwrap_or_else(|e| format!("<error: {}>", e)),
                previous_state_count(),
            );
        } else {
            log::error!(
                "No valid session for recipient: {}, (no current session state), number of previous states: {}",
                remote_address,
                previous_state_count(),
            );
        }
        log::error!(
            "{}",
            create_decryption_failure_log(remote_address, &errs, record, ciphertext)?
        );
        Err(SignalProtocolError::InvalidMessage(
            "Message decryption failed",
        ))
    }
}

fn decrypt_message_with_state<R: Rng + CryptoRng>(
    state: &mut SessionState,
    ciphertext: &SignalMessage,
    remote_address: &ProtocolAddress,
    csprng: &mut R,
) -> Result<Vec<u8>> {
    if !state.has_sender_chain()? {
        return Err(SignalProtocolError::InvalidMessage(
            "No session available to decrypt",
        ));
    }

    let ciphertext_version: u8 = ciphertext.message_version().into();
    if ciphertext_version as u32 != state.session_version()? {
        return Err(SignalProtocolError::UnrecognizedMessageVersion(
            ciphertext_version.into(),
        ));
    }

    let their_ephemeral = ciphertext.sender_ratchet_key();
    let counter = ciphertext.counter();
    let chain_key = get_or_create_chain_key(state, their_ephemeral, remote_address, csprng)?;
    let message_keys =
        get_or_create_message_key(state, their_ephemeral, remote_address, &chain_key, counter)?;

    let their_identity_key = state
        .remote_identity_key()?
        .ok_or(SignalProtocolError::InvalidSessionStructure)?;

    let mac_valid = ciphertext.verify_mac(
        &their_identity_key,
        &state.local_identity_key()?,
        message_keys.mac_key(),
    )?;

    if !mac_valid {
        return Err(SignalProtocolError::InvalidCiphertext);
    }

    let ptext = crypto::aes_256_cbc_decrypt(
        ciphertext.body(),
        message_keys.cipher_key(),
        message_keys.iv(),
    )?;

    state.clear_unacknowledged_pre_key_message()?;

    Ok(ptext)
}

fn get_or_create_chain_key<R: Rng + CryptoRng>(
    state: &mut SessionState,
    their_ephemeral: &PublicKey,
    remote_address: &ProtocolAddress,
    csprng: &mut R,
) -> Result<ChainKey> {
    if let Some(chain) = state.get_receiver_chain_key(their_ephemeral)? {
        log::debug!("{} has existing receiver chain.", remote_address);
        return Ok(chain);
    }

    log::info!("{} creating new chains.", remote_address);

    let root_key = state.root_key()?;
    let our_ephemeral = state.sender_ratchet_private_key()?;
    let receiver_chain = root_key.create_chain(their_ephemeral, &our_ephemeral)?;
    let our_new_ephemeral = KeyPair::generate(csprng);
    let sender_chain = receiver_chain
        .0
        .create_chain(their_ephemeral, &our_new_ephemeral.private_key)?;

    state.set_root_key(&sender_chain.0)?;
    state.add_receiver_chain(their_ephemeral, &receiver_chain.1)?;

    let current_index = state.get_sender_chain_key()?.index();
    let previous_index = if current_index > 0 {
        current_index - 1
    } else {
        0
    };
    state.set_previous_counter(previous_index)?;
    state.set_sender_chain(&our_new_ephemeral, &sender_chain.1)?;

    Ok(receiver_chain.1)
}

fn get_or_create_message_key(
    state: &mut SessionState,
    their_ephemeral: &PublicKey,
    remote_address: &ProtocolAddress,
    chain_key: &ChainKey,
    counter: u32,
) -> Result<MessageKeys> {
    let chain_index = chain_key.index();

    if chain_index > counter {
        return match state.get_message_keys(their_ephemeral, counter)? {
            Some(keys) => Ok(keys),
            None => {
                log::info!(
                    "{} Duplicate message for counter: {}",
                    remote_address,
                    counter
                );
                Err(SignalProtocolError::DuplicatedMessage(chain_index, counter))
            }
        };
    }

    assert!(chain_index <= counter);

    let jump = (counter - chain_index) as usize;

    if jump > MAX_FORWARD_JUMPS {
        if state.session_with_self()? {
            log::info!(
                "{} Jumping ahead {} messages (index: {}, counter: {})",
                remote_address,
                jump,
                chain_index,
                counter
            );
        } else {
            log::error!(
                "{} Exceeded future message limit: {}, index: {}, counter: {})",
                remote_address,
                MAX_FORWARD_JUMPS,
                chain_index,
                counter
            );
            return Err(SignalProtocolError::InvalidMessage(
                "message from too far into the future",
            ));
        }
    }

    let mut chain_key = chain_key.clone();

    while chain_key.index() < counter {
        let message_keys = chain_key.message_keys()?;
        state.set_message_keys(their_ephemeral, &message_keys)?;
        chain_key = chain_key.next_chain_key()?;
    }

    state.set_receiver_chain_key(their_ephemeral, &chain_key.next_chain_key()?)?;
    Ok(chain_key.message_keys()?)
}
