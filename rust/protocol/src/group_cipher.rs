//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::consts;
use crate::crypto;

use crate::{
    KeyPair, ProtocolAddress, Result, SenderKeyDistributionMessage, SenderKeyMessage,
    SenderKeyRecord, SenderKeyStore, SignalProtocolError,
};

use crate::protocol::SENDERKEY_MESSAGE_CURRENT_VERSION;
use crate::sender_keys::{SenderKeyState, SenderMessageKey};

use rand::{CryptoRng, Rng};
use std::convert::TryFrom;
use uuid::Uuid;

pub async fn group_encrypt<R: Rng + CryptoRng>(
    sender_key_store: &mut dyn SenderKeyStore,
    sender: &ProtocolAddress,
    distribution_id: Uuid,
    plaintext: &[u8],
    csprng: &mut R,
) -> Result<SenderKeyMessage> {
    let mut record = sender_key_store
        .load_sender_key(sender, distribution_id)
        .await?
        .ok_or(SignalProtocolError::NoSenderKeyState)?;

    let sender_key_state = record.sender_key_state()?;

    let sender_key = sender_key_state.sender_chain_key()?.sender_message_key()?;

    let ciphertext =
        crypto::aes_256_cbc_encrypt(plaintext, &sender_key.cipher_key()?, &sender_key.iv()?)?;

    let signing_key = sender_key_state.signing_key_private()?;

    let skm = SenderKeyMessage::new(
        sender_key_state.message_version()? as u8,
        distribution_id,
        sender_key_state.chain_id()?,
        sender_key.iteration()?,
        ciphertext.into_boxed_slice(),
        csprng,
        &signing_key,
    )?;

    sender_key_state.set_sender_chain_key(sender_key_state.sender_chain_key()?.next()?)?;

    sender_key_store
        .store_sender_key(sender, distribution_id, &record)
        .await?;

    Ok(skm)
}

fn get_sender_key(
    state: &mut SenderKeyState,
    iteration: u32,
    distribution_id: Uuid,
) -> Result<SenderMessageKey> {
    let sender_chain_key = state.sender_chain_key()?;
    let current_iteration = sender_chain_key.iteration()?;

    if current_iteration > iteration {
        if let Some(smk) = state.remove_sender_message_key(iteration)? {
            return Ok(smk);
        } else {
            log::info!(
                "SenderKey distribution {} Duplicate message for iteration: {}",
                distribution_id,
                iteration
            );
            return Err(SignalProtocolError::DuplicatedMessage(
                current_iteration,
                iteration,
            ));
        }
    }

    let jump = (iteration - current_iteration) as usize;
    if jump > consts::MAX_FORWARD_JUMPS {
        log::error!(
            "SenderKey distribution {} Exceeded future message limit: {}, current iteration: {})",
            distribution_id,
            consts::MAX_FORWARD_JUMPS,
            current_iteration
        );
        return Err(SignalProtocolError::InvalidMessage(
            "message from too far into the future",
        ));
    }

    let mut sender_chain_key = sender_chain_key;

    while sender_chain_key.iteration()? < iteration {
        state.add_sender_message_key(&sender_chain_key.sender_message_key()?)?;
        sender_chain_key = sender_chain_key.next()?;
    }

    state.set_sender_chain_key(sender_chain_key.next()?)?;
    Ok(sender_chain_key.sender_message_key()?)
}

pub async fn group_decrypt(
    skm_bytes: &[u8],
    sender_key_store: &mut dyn SenderKeyStore,
    sender: &ProtocolAddress,
) -> Result<Vec<u8>> {
    let skm = SenderKeyMessage::try_from(skm_bytes)?;
    let mut record = sender_key_store
        .load_sender_key(sender, skm.distribution_id())
        .await?
        .ok_or(SignalProtocolError::NoSenderKeyState)?;

    let mut sender_key_state =
        record.sender_key_state_for_chain_id(skm.chain_id(), skm.distribution_id())?;

    let message_version = skm.message_version() as u32;
    if message_version != sender_key_state.message_version()? {
        return Err(SignalProtocolError::UnrecognizedMessageVersion(
            message_version,
        ));
    }

    let signing_key = sender_key_state.signing_key_public()?;
    if !skm.verify_signature(&signing_key)? {
        return Err(SignalProtocolError::SignatureValidationFailed);
    }

    let sender_key = get_sender_key(
        &mut sender_key_state,
        skm.iteration(),
        skm.distribution_id(),
    )?;

    let plaintext = crypto::aes_256_cbc_decrypt(
        skm.ciphertext(),
        &sender_key.cipher_key()?,
        &sender_key.iv()?,
    )?;

    sender_key_store
        .store_sender_key(sender, skm.distribution_id(), &record)
        .await?;

    Ok(plaintext)
}

pub async fn process_sender_key_distribution_message(
    sender: &ProtocolAddress,
    skdm: &SenderKeyDistributionMessage,
    sender_key_store: &mut dyn SenderKeyStore,
) -> Result<()> {
    let distribution_id = skdm.distribution_id()?;
    log::info!(
        "{} Processing SenderKey distribution {} with chain ID {}",
        sender,
        distribution_id,
        skdm.chain_id()?
    );

    let mut sender_key_record = sender_key_store
        .load_sender_key(sender, distribution_id)
        .await?
        .unwrap_or_else(SenderKeyRecord::new_empty);

    sender_key_record.add_sender_key_state(
        skdm.message_version(),
        skdm.chain_id()?,
        skdm.iteration()?,
        skdm.chain_key()?,
        *skdm.signing_key()?,
        None,
    )?;
    sender_key_store
        .store_sender_key(sender, distribution_id, &sender_key_record)
        .await?;
    Ok(())
}

pub async fn create_sender_key_distribution_message<R: Rng + CryptoRng>(
    sender: &ProtocolAddress,
    distribution_id: Uuid,
    sender_key_store: &mut dyn SenderKeyStore,
    csprng: &mut R,
) -> Result<SenderKeyDistributionMessage> {
    let mut sender_key_record = sender_key_store
        .load_sender_key(sender, distribution_id)
        .await?
        .unwrap_or_else(SenderKeyRecord::new_empty);

    if sender_key_record.is_empty()? {
        // libsignal-protocol-java uses 31-bit integers for sender key chain IDs
        let chain_id = (csprng.gen::<u32>()) >> 1;
        log::info!(
            "Creating SenderKey for distribution {} with chain ID {}",
            distribution_id,
            chain_id
        );

        let iteration = 0;
        let sender_key: [u8; 32] = csprng.gen();
        let signing_key = KeyPair::generate(csprng);
        sender_key_record.set_sender_key_state(
            SENDERKEY_MESSAGE_CURRENT_VERSION,
            chain_id,
            iteration,
            &sender_key,
            signing_key.public_key,
            Some(signing_key.private_key),
        )?;
        sender_key_store
            .store_sender_key(sender, distribution_id, &sender_key_record)
            .await?;
    }

    let state = sender_key_record.sender_key_state()?;
    let sender_chain_key = state.sender_chain_key()?;

    SenderKeyDistributionMessage::new(
        state.message_version()? as u8,
        distribution_id,
        state.chain_id()?,
        sender_chain_key.iteration()?,
        sender_chain_key.seed()?,
        state.signing_key_public()?,
    )
}
