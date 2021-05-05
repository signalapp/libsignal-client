//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::ratchet::{ChainKey, MessageKeys, RootKey};
use crate::{IdentityKey, KeyPair, PrivateKey, PublicKey, Result, SignalProtocolError, HKDF};

use crate::consts;
use crate::proto::storage::session_structure;
use crate::proto::storage::{RecordStructure, SessionStructure};
use crate::state::{PreKeyId, SignedPreKeyId};

use prost::Message;

use std::collections::VecDeque;
use std::convert::TryInto;

#[derive(Debug, Clone)]
pub(crate) struct UnacknowledgedPreKeyMessageItems {
    pre_key_id: Option<PreKeyId>,
    signed_pre_key_id: SignedPreKeyId,
    base_key: PublicKey,
}

impl UnacknowledgedPreKeyMessageItems {
    fn new(
        pre_key_id: Option<PreKeyId>,
        signed_pre_key_id: SignedPreKeyId,
        base_key: PublicKey,
    ) -> Self {
        Self {
            pre_key_id,
            signed_pre_key_id,
            base_key,
        }
    }

    pub(crate) fn pre_key_id(&self) -> Result<Option<PreKeyId>> {
        Ok(self.pre_key_id)
    }

    pub(crate) fn signed_pre_key_id(&self) -> Result<SignedPreKeyId> {
        Ok(self.signed_pre_key_id)
    }

    pub(crate) fn base_key(&self) -> Result<&PublicKey> {
        Ok(&self.base_key)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SessionState {
    session: SessionStructure,
}

impl SessionState {
    pub(crate) fn new(session: SessionStructure) -> Self {
        Self { session }
    }

    pub(crate) fn alice_base_key(&self) -> Result<&[u8]> {
        // Check the length before returning?
        Ok(&self.session.alice_base_key)
    }

    pub(crate) fn set_alice_base_key(&mut self, key: &[u8]) -> Result<()> {
        // Should we check the length?
        self.session.alice_base_key = key.to_vec();
        Ok(())
    }

    pub fn session_version(&self) -> Result<u32> {
        match self.session.session_version {
            0 => Ok(2),
            v => Ok(v),
        }
    }

    pub(crate) fn remote_identity_key(&self) -> Result<Option<IdentityKey>> {
        match self.session.remote_identity_public.len() {
            0 => Ok(None),
            _ => Ok(Some(IdentityKey::decode(
                &self.session.remote_identity_public,
            )?)),
        }
    }

    pub(crate) fn remote_identity_key_bytes(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.remote_identity_key()?.map(|k| k.serialize().to_vec()))
    }

    pub(crate) fn local_identity_key(&self) -> Result<IdentityKey> {
        IdentityKey::decode(&self.session.local_identity_public)
    }

    pub(crate) fn local_identity_key_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.local_identity_key()?.serialize().to_vec())
    }

    pub(crate) fn session_with_self(&self) -> Result<bool> {
        if let Some(remote_id) = self.remote_identity_key_bytes()? {
            let local_id = self.local_identity_key_bytes()?;
            return Ok(remote_id == local_id);
        }

        // If remote ID is not set then we can't be sure but treat as non-self
        Ok(false)
    }

    pub(crate) fn previous_counter(&self) -> Result<u32> {
        Ok(self.session.previous_counter)
    }

    pub(crate) fn set_previous_counter(&mut self, ctr: u32) -> Result<()> {
        self.session.previous_counter = ctr;
        Ok(())
    }

    pub(crate) fn root_key(&self) -> Result<RootKey> {
        if self.session.root_key.len() != 32 {
            return Err(SignalProtocolError::InvalidProtobufEncoding);
        }
        let hkdf = HKDF::new_for_version(self.session_version()?.try_into()?)?;
        RootKey::new(hkdf, &self.session.root_key)
    }

    pub(crate) fn set_root_key(&mut self, root_key: &RootKey) -> Result<()> {
        self.session.root_key = root_key.key().to_vec();
        Ok(())
    }

    pub(crate) fn sender_ratchet_key(&self) -> Result<PublicKey> {
        match self.session.sender_chain {
            None => Err(SignalProtocolError::InvalidProtobufEncoding),
            Some(ref c) => PublicKey::deserialize(&c.sender_ratchet_key),
        }
    }

    pub(crate) fn sender_ratchet_key_for_logging(&self) -> Result<String> {
        self.sender_ratchet_key()?
            .public_key_bytes()
            .map(hex::encode)
    }

    pub(crate) fn sender_ratchet_private_key(&self) -> Result<PrivateKey> {
        match self.session.sender_chain {
            None => Err(SignalProtocolError::InvalidProtobufEncoding),
            Some(ref c) => PrivateKey::deserialize(&c.sender_ratchet_key_private),
        }
    }

    pub fn has_sender_chain(&self) -> Result<bool> {
        Ok(self.session.sender_chain.is_some())
    }

    pub(crate) fn all_receiver_chain_logging_info(&self) -> Result<Vec<(Vec<u8>, Option<u32>)>> {
        let mut results = vec![];
        for chain in self.session.receiver_chains.iter() {
            let sender_ratchet_public = chain.sender_ratchet_key.clone();

            let chain_key_idx = match &chain.chain_key {
                Some(chain_key) => Some(chain_key.index),
                None => None,
            };

            results.push((sender_ratchet_public, chain_key_idx))
        }
        Ok(results)
    }

    pub(crate) fn get_receiver_chain(
        &self,
        sender: &PublicKey,
    ) -> Result<Option<(session_structure::Chain, usize)>> {
        let sender_bytes = sender.serialize();

        for (idx, chain) in self.session.receiver_chains.iter().enumerate() {
            /*
            If we compared bytes directly without a deserialize + serialize pair it would
            be faster, but may miss non-canonical points. It's unclear if supporting such
            points is desirable.
            */
            let this_point = PublicKey::deserialize(&chain.sender_ratchet_key)?.serialize();

            if this_point == sender_bytes {
                return Ok(Some((chain.clone(), idx)));
            }
        }

        Ok(None)
    }

    pub(crate) fn get_receiver_chain_key(&self, sender: &PublicKey) -> Result<Option<ChainKey>> {
        match self.get_receiver_chain(sender)? {
            None => Ok(None),
            Some((chain, _)) => match chain.chain_key {
                None => Err(SignalProtocolError::InvalidProtobufEncoding),
                Some(c) => {
                    if c.key.len() != 32 {
                        return Err(SignalProtocolError::InvalidProtobufEncoding);
                    }
                    let hkdf = HKDF::new_for_version(self.session_version()?.try_into()?)?;
                    Ok(Some(ChainKey::new(hkdf, &c.key, c.index)?))
                }
            },
        }
    }

    pub(crate) fn add_receiver_chain(
        &mut self,
        sender: &PublicKey,
        chain_key: &ChainKey,
    ) -> Result<()> {
        let chain_key = session_structure::chain::ChainKey {
            index: chain_key.index(),
            key: chain_key.key().to_vec(),
        };

        let chain = session_structure::Chain {
            sender_ratchet_key: sender.serialize().to_vec(),
            sender_ratchet_key_private: vec![],
            chain_key: Some(chain_key),
            message_keys: vec![],
        };

        self.session.receiver_chains.push(chain);

        if self.session.receiver_chains.len() > consts::MAX_RECEIVER_CHAINS {
            log::info!(
                "Trimming excessive receiver_chain for session with base key {}, chain count: {}",
                self.sender_ratchet_key_for_logging()
                    .unwrap_or_else(|e| format!("<error: {}>", e)),
                self.session.receiver_chains.len()
            );
            self.session.receiver_chains.remove(0);
        }

        Ok(())
    }

    pub(crate) fn set_sender_chain(
        &mut self,
        sender: &KeyPair,
        next_chain_key: &ChainKey,
    ) -> Result<()> {
        let chain_key = session_structure::chain::ChainKey {
            index: next_chain_key.index(),
            key: next_chain_key.key().to_vec(),
        };

        let new_chain = session_structure::Chain {
            sender_ratchet_key: sender.public_key.serialize().to_vec(),
            sender_ratchet_key_private: sender.private_key.serialize().to_vec(),
            chain_key: Some(chain_key),
            message_keys: vec![],
        };

        self.session.sender_chain = Some(new_chain);

        Ok(())
    }

    pub(crate) fn get_sender_chain_key(&self) -> Result<ChainKey> {
        let sender_chain = self.session.sender_chain.as_ref().ok_or_else(|| {
            SignalProtocolError::InvalidState("get_sender_chain_key", "No chain".to_owned())
        })?;

        let chain_key = sender_chain.chain_key.as_ref().ok_or_else(|| {
            SignalProtocolError::InvalidState("get_sender_chain_key", "No chain key".to_owned())
        })?;

        let hkdf = HKDF::new_for_version(self.session_version()?.try_into()?)?;
        ChainKey::new(hkdf, &chain_key.key, chain_key.index)
    }

    pub(crate) fn get_sender_chain_key_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.get_sender_chain_key()?.key().to_vec())
    }

    pub(crate) fn set_sender_chain_key(&mut self, next_chain_key: &ChainKey) -> Result<()> {
        let chain_key = session_structure::chain::ChainKey {
            index: next_chain_key.index(),
            key: next_chain_key.key().to_vec(),
        };

        // Is it actually valid to call this function with sender_chain == None?

        let new_chain = match self.session.sender_chain.take() {
            None => session_structure::Chain {
                sender_ratchet_key: vec![],
                sender_ratchet_key_private: vec![],
                chain_key: Some(chain_key),
                message_keys: vec![],
            },
            Some(mut c) => {
                c.chain_key = Some(chain_key);
                c
            }
        };

        self.session.sender_chain = Some(new_chain);

        Ok(())
    }

    pub(crate) fn get_message_keys(
        &mut self,
        sender: &PublicKey,
        counter: u32,
    ) -> Result<Option<MessageKeys>> {
        if let Some(mut chain_and_index) = self.get_receiver_chain(sender)? {
            let message_key_idx = chain_and_index
                .0
                .message_keys
                .iter()
                .position(|m| m.index == counter);
            if let Some(position) = message_key_idx {
                let message_key = chain_and_index.0.message_keys.remove(position);

                let keys = MessageKeys::new(
                    &message_key.cipher_key,
                    &message_key.mac_key,
                    &message_key.iv,
                    counter,
                )?;

                // Update with message key removed
                self.session.receiver_chains[chain_and_index.1] = chain_and_index.0;
                return Ok(Some(keys));
            }
        }

        Ok(None)
    }

    pub(crate) fn set_message_keys(
        &mut self,
        sender: &PublicKey,
        message_keys: &MessageKeys,
    ) -> Result<()> {
        let new_keys = session_structure::chain::MessageKey {
            cipher_key: message_keys.cipher_key().to_vec(),
            mac_key: message_keys.mac_key().to_vec(),
            iv: message_keys.iv().to_vec(),
            index: message_keys.counter(),
        };

        if let Some(chain_and_index) = self.get_receiver_chain(sender)? {
            let mut updated_chain = chain_and_index.0;
            updated_chain.message_keys.insert(0, new_keys);

            if updated_chain.message_keys.len() > consts::MAX_MESSAGE_KEYS {
                updated_chain.message_keys.pop();
            }

            self.session.receiver_chains[chain_and_index.1] = updated_chain;
            Ok(())
        } else {
            Err(SignalProtocolError::InvalidState(
                "set_message_keys",
                "No receiver".to_string(),
            ))
        }
    }

    pub(crate) fn set_receiver_chain_key(
        &mut self,
        sender: &PublicKey,
        chain_key: &ChainKey,
    ) -> Result<()> {
        if let Some(chain_and_index) = self.get_receiver_chain(sender)? {
            let mut updated_chain = chain_and_index.0;
            updated_chain.chain_key = Some(session_structure::chain::ChainKey {
                index: chain_key.index(),
                key: chain_key.key().to_vec(),
            });

            self.session.receiver_chains[chain_and_index.1] = updated_chain;
            return Ok(());
        }

        Err(SignalProtocolError::InvalidState(
            "set_receiver_chain_key",
            "No receiver".to_string(),
        ))
    }

    pub(crate) fn set_unacknowledged_pre_key_message(
        &mut self,
        pre_key_id: Option<PreKeyId>,
        signed_pre_key_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<()> {
        let signed_pre_key_id: u32 = signed_pre_key_id.into();
        let pending = session_structure::PendingPreKey {
            pre_key_id: pre_key_id.unwrap_or(0.into()).into(),
            signed_pre_key_id: signed_pre_key_id as i32,
            base_key: base_key.serialize().to_vec(),
        };
        self.session.pending_pre_key = Some(pending);
        Ok(())
    }

    pub(crate) fn unacknowledged_pre_key_message_items(
        &self,
    ) -> Result<Option<UnacknowledgedPreKeyMessageItems>> {
        if let Some(ref pending_pre_key) = self.session.pending_pre_key {
            Ok(Some(UnacknowledgedPreKeyMessageItems::new(
                match pending_pre_key.pre_key_id {
                    0 => None,
                    v => Some(v.into()),
                },
                (pending_pre_key.signed_pre_key_id as u32).into(),
                PublicKey::deserialize(&pending_pre_key.base_key)?,
            )))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn clear_unacknowledged_pre_key_message(&mut self) -> Result<()> {
        self.session.pending_pre_key = None;
        Ok(())
    }

    pub(crate) fn set_remote_registration_id(&mut self, registration_id: u32) -> Result<()> {
        self.session.remote_registration_id = registration_id;
        Ok(())
    }

    pub(crate) fn remote_registration_id(&self) -> Result<u32> {
        Ok(self.session.remote_registration_id)
    }

    pub(crate) fn set_local_registration_id(&mut self, registration_id: u32) -> Result<()> {
        self.session.local_registration_id = registration_id;
        Ok(())
    }

    pub(crate) fn local_registration_id(&self) -> Result<u32> {
        Ok(self.session.local_registration_id)
    }
}

impl From<SessionStructure> for SessionState {
    fn from(value: SessionStructure) -> SessionState {
        SessionState::new(value)
    }
}

impl From<SessionState> for SessionStructure {
    fn from(value: SessionState) -> SessionStructure {
        value.session
    }
}

impl From<&SessionState> for SessionStructure {
    fn from(value: &SessionState) -> SessionStructure {
        value.session.clone()
    }
}

#[derive(Clone, Debug)]
pub struct SessionRecord {
    current_session: Option<SessionState>,
    previous_sessions: VecDeque<SessionState>,
}

impl SessionRecord {
    pub fn new_fresh() -> Self {
        Self {
            current_session: None,
            previous_sessions: VecDeque::new(),
        }
    }

    pub(crate) fn new(state: SessionState) -> Self {
        Self {
            current_session: Some(state),
            previous_sessions: VecDeque::new(),
        }
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let record = RecordStructure::decode(bytes)?;

        let mut previous = VecDeque::with_capacity(record.previous_sessions.len());
        for s in record.previous_sessions {
            previous.push_back(s.into());
        }

        Ok(Self {
            current_session: record.current_session.map(|s| s.into()),
            previous_sessions: previous,
        })
    }

    pub fn from_single_session_state(bytes: &[u8]) -> Result<Self> {
        let session = SessionState::new(SessionStructure::decode(bytes)?);
        Ok(Self {
            current_session: Some(session),
            previous_sessions: VecDeque::new(),
        })
    }

    pub(crate) fn has_session_state(&self, version: u32, alice_base_key: &[u8]) -> Result<bool> {
        if let Some(current_session) = &self.current_session {
            if current_session.session_version()? == version
                && alice_base_key == current_session.alice_base_key()?
            {
                return Ok(true);
            }
        }

        for previous in &self.previous_sessions {
            if previous.session_version()? == version
                && alice_base_key == previous.alice_base_key()?
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn has_current_session_state(&self) -> bool {
        self.current_session.is_some()
    }

    pub(crate) fn session_state(&self) -> Result<&SessionState> {
        if let Some(ref session) = self.current_session {
            Ok(session)
        } else {
            Err(SignalProtocolError::InvalidState(
                "session_state",
                "No session".into(),
            ))
        }
    }

    pub(crate) fn session_state_mut(&mut self) -> Result<&mut SessionState> {
        if let Some(ref mut session) = self.current_session {
            Ok(session)
        } else {
            Err(SignalProtocolError::InvalidState(
                "session_state",
                "No session".into(),
            ))
        }
    }

    pub(crate) fn set_session_state(&mut self, session: SessionState) -> Result<()> {
        self.current_session = Some(session);
        Ok(())
    }

    pub(crate) fn previous_session_states(&self) -> Result<impl Iterator<Item = &SessionState>> {
        Ok(self.previous_sessions.iter())
    }

    pub(crate) fn promote_old_session(
        &mut self,
        old_session: usize,
        updated_session: SessionState,
    ) -> Result<()> {
        self.previous_sessions.remove(old_session).ok_or_else(|| {
            SignalProtocolError::InvalidState("promote_old_session", "out of range".into())
        })?;
        self.promote_state(updated_session)
    }

    pub(crate) fn promote_state(&mut self, new_state: SessionState) -> Result<()> {
        self.archive_current_state()?;
        self.current_session = Some(new_state);
        Ok(())
    }

    pub fn archive_current_state(&mut self) -> Result<()> {
        if self.current_session.is_some() {
            self.previous_sessions
                .push_front(self.current_session.take().expect("Checked is_some"));
            if self.previous_sessions.len() > consts::ARCHIVED_STATES_MAX_LENGTH {
                self.previous_sessions.pop_back();
            }
        } else {
            log::info!("Skipping archive, current session state is fresh",);
        }

        Ok(())
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];

        let record = RecordStructure {
            current_session: self.current_session.as_ref().map(|s| s.into()),
            previous_sessions: self.previous_sessions.iter().map(|s| s.into()).collect(),
        };
        record.encode(&mut buf)?;
        Ok(buf)
    }

    pub fn remote_registration_id(&self) -> Result<u32> {
        self.session_state()?.remote_registration_id()
    }

    pub fn local_registration_id(&self) -> Result<u32> {
        self.session_state()?.local_registration_id()
    }

    pub fn session_version(&self) -> Result<u32> {
        self.session_state()?.session_version()
    }

    pub fn local_identity_key_bytes(&self) -> Result<Vec<u8>> {
        self.session_state()?.local_identity_key_bytes()
    }

    pub fn remote_identity_key_bytes(&self) -> Result<Option<Vec<u8>>> {
        self.session_state()?.remote_identity_key_bytes()
    }

    pub fn has_sender_chain(&self) -> Result<bool> {
        match &self.current_session {
            Some(session) => session.has_sender_chain(),
            None => Ok(false),
        }
    }

    pub fn alice_base_key(&self) -> Result<&[u8]> {
        self.session_state()?.alice_base_key()
    }

    pub fn get_receiver_chain_key(&self, sender: &PublicKey) -> Result<Option<ChainKey>> {
        self.session_state()?.get_receiver_chain_key(sender)
    }

    pub fn get_sender_chain_key_bytes(&self) -> Result<Vec<u8>> {
        self.session_state()?.get_sender_chain_key_bytes()
    }
}
