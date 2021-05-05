//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::consts;
use crate::crypto::hmac_sha256;
use crate::proto::storage as storage_proto;
use crate::{PrivateKey, PublicKey, Result, SignalProtocolError, HKDF};

use prost::Message;
use std::collections::VecDeque;
use std::convert::TryFrom;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SenderMessageKey {
    iteration: u32,
    iv: Vec<u8>,
    cipher_key: Vec<u8>,
    seed: Vec<u8>,
}

impl SenderMessageKey {
    pub fn new(iteration: u32, seed: Vec<u8>) -> Result<Self> {
        let hkdf = HKDF::new()?;
        let derived = hkdf.derive_secrets(&seed, b"WhisperGroup", 48)?;
        Ok(Self {
            iteration,
            seed,
            iv: derived[0..16].to_vec(),
            cipher_key: derived[16..48].to_vec(),
        })
    }

    pub fn from_protobuf(
        smk: storage_proto::sender_key_state_structure::SenderMessageKey,
    ) -> Result<Self> {
        Self::new(smk.iteration, smk.seed)
    }

    pub fn iteration(&self) -> Result<u32> {
        Ok(self.iteration)
    }

    pub fn iv(&self) -> Result<Vec<u8>> {
        Ok(self.iv.clone())
    }

    pub fn cipher_key(&self) -> Result<Vec<u8>> {
        Ok(self.cipher_key.clone())
    }

    pub fn seed(&self) -> Result<Vec<u8>> {
        Ok(self.seed.clone())
    }

    pub fn as_protobuf(
        &self,
    ) -> Result<storage_proto::sender_key_state_structure::SenderMessageKey> {
        Ok(
            storage_proto::sender_key_state_structure::SenderMessageKey {
                iteration: self.iteration,
                seed: self.seed.clone(),
            },
        )
    }
}

#[derive(Debug, Clone)]
pub struct SenderChainKey {
    iteration: u32,
    chain_key: Vec<u8>,
}

impl SenderChainKey {
    const MESSAGE_KEY_SEED: u8 = 0x01;
    const CHAIN_KEY_SEED: u8 = 0x02;

    pub fn new(iteration: u32, chain_key: Vec<u8>) -> Result<Self> {
        Ok(Self {
            iteration,
            chain_key,
        })
    }

    pub fn iteration(&self) -> Result<u32> {
        Ok(self.iteration)
    }

    pub fn seed(&self) -> Result<Vec<u8>> {
        Ok(self.chain_key.clone())
    }

    pub fn next(&self) -> Result<SenderChainKey> {
        Ok(SenderChainKey::new(
            self.iteration + 1,
            self.get_derivative(Self::CHAIN_KEY_SEED)?,
        )?)
    }

    pub fn sender_message_key(&self) -> Result<SenderMessageKey> {
        Ok(SenderMessageKey::new(
            self.iteration,
            self.get_derivative(Self::MESSAGE_KEY_SEED)?,
        )?)
    }

    fn get_derivative(&self, label: u8) -> Result<Vec<u8>> {
        let label = [label];
        Ok(hmac_sha256(&self.chain_key, &label)?.to_vec())
    }

    pub fn as_protobuf(&self) -> Result<storage_proto::sender_key_state_structure::SenderChainKey> {
        Ok(storage_proto::sender_key_state_structure::SenderChainKey {
            iteration: self.iteration,
            seed: self.chain_key.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SenderKeyState {
    state: storage_proto::SenderKeyStateStructure,
}

impl SenderKeyState {
    pub fn new(
        message_version: u8,
        chain_id: u32,
        iteration: u32,
        chain_key: &[u8],
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) -> Result<SenderKeyState> {
        let state = storage_proto::SenderKeyStateStructure {
            message_version: message_version as u32,
            chain_id,
            sender_chain_key: Some(
                SenderChainKey::new(iteration, chain_key.to_vec())?.as_protobuf()?,
            ),
            sender_signing_key: Some(
                storage_proto::sender_key_state_structure::SenderSigningKey {
                    public: signature_key.serialize().to_vec(),
                    private: match signature_private_key {
                        None => vec![],
                        Some(k) => k.serialize().to_vec(),
                    },
                },
            ),
            sender_message_keys: vec![],
        };

        Ok(Self { state })
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        let state = storage_proto::SenderKeyStateStructure::decode(buf)?;
        Ok(Self { state })
    }

    pub fn from_protobuf(state: storage_proto::SenderKeyStateStructure) -> Self {
        Self { state }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];
        self.state.encode(&mut buf)?;
        Ok(buf)
    }

    pub fn message_version(&self) -> Result<u32> {
        match self.state.message_version {
            0 => Ok(3), // the first SenderKey version
            v => Ok(v),
        }
    }

    pub fn chain_id(&self) -> Result<u32> {
        Ok(self.state.chain_id)
    }

    pub fn sender_chain_key(&self) -> Result<SenderChainKey> {
        let sender_chain = self
            .state
            .sender_chain_key
            .as_ref()
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        SenderChainKey::new(sender_chain.iteration, sender_chain.seed.clone())
    }

    pub fn set_sender_chain_key(&mut self, chain_key: SenderChainKey) -> Result<()> {
        self.state.sender_chain_key = Some(chain_key.as_protobuf()?);
        Ok(())
    }

    pub fn signing_key_public(&self) -> Result<PublicKey> {
        if let Some(ref signing_key) = self.state.sender_signing_key {
            Ok(PublicKey::try_from(&signing_key.public[..])?)
        } else {
            Err(SignalProtocolError::InvalidProtobufEncoding)
        }
    }

    pub fn signing_key_private(&self) -> Result<PrivateKey> {
        if let Some(ref signing_key) = self.state.sender_signing_key {
            Ok(PrivateKey::deserialize(&signing_key.private)?)
        } else {
            Err(SignalProtocolError::InvalidProtobufEncoding)
        }
    }

    pub fn has_sender_message_key(&self, iteration: u32) -> Result<bool> {
        for sender_message_key in &self.state.sender_message_keys {
            if sender_message_key.iteration == iteration {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn as_protobuf(&self) -> Result<storage_proto::SenderKeyStateStructure> {
        Ok(self.state.clone())
    }

    pub fn add_sender_message_key(&mut self, sender_message_key: &SenderMessageKey) -> Result<()> {
        self.state
            .sender_message_keys
            .push(sender_message_key.as_protobuf()?);
        while self.state.sender_message_keys.len() > consts::MAX_MESSAGE_KEYS {
            self.state.sender_message_keys.remove(0);
        }
        Ok(())
    }

    pub fn remove_sender_message_key(
        &mut self,
        iteration: u32,
    ) -> Result<Option<SenderMessageKey>> {
        if let Some(index) = self
            .state
            .sender_message_keys
            .iter()
            .position(|x| x.iteration == iteration)
        {
            let smk = self.state.sender_message_keys.remove(index);
            Ok(Some(SenderMessageKey::from_protobuf(smk)?))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Clone)]
pub struct SenderKeyRecord {
    states: VecDeque<SenderKeyState>,
}

impl SenderKeyRecord {
    pub fn new_empty() -> Self {
        Self {
            states: VecDeque::new(),
        }
    }

    pub fn deserialize(buf: &[u8]) -> Result<SenderKeyRecord> {
        let skr = storage_proto::SenderKeyRecordStructure::decode(buf)?;

        let mut states = VecDeque::with_capacity(skr.sender_key_states.len());
        for state in skr.sender_key_states {
            states.push_back(SenderKeyState::from_protobuf(state))
        }
        Ok(Self { states })
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.states.is_empty())
    }

    pub fn sender_key_state(&mut self) -> Result<&mut SenderKeyState> {
        if !self.states.is_empty() {
            return Ok(&mut self.states[0]);
        }
        Err(SignalProtocolError::NoSenderKeyState)
    }

    pub fn sender_key_state_for_chain_id(
        &mut self,
        chain_id: u32,
        distribution_id: Uuid,
    ) -> Result<&mut SenderKeyState> {
        for i in 0..self.states.len() {
            if self.states[i].chain_id()? == chain_id {
                return Ok(&mut self.states[i]);
            }
        }
        log::error!(
            "SenderKey distribution {} could not find chain ID {} (known chain IDs: {:?})",
            distribution_id,
            chain_id,
            self.states
                .iter()
                .map(|state| state.chain_id().expect("accessed successfully above"))
                .collect::<Vec<_>>()
        );
        Err(SignalProtocolError::NoSenderKeyState)
    }

    pub fn add_sender_key_state(
        &mut self,
        message_version: u8,
        chain_id: u32,
        iteration: u32,
        chain_key: &[u8],
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) -> Result<()> {
        self.states.push_front(SenderKeyState::new(
            message_version,
            chain_id,
            iteration,
            chain_key,
            signature_key,
            signature_private_key,
        )?);

        while self.states.len() > consts::MAX_SENDER_KEY_STATES {
            self.states.pop_back();
        }
        Ok(())
    }

    pub fn set_sender_key_state(
        &mut self,
        message_version: u8,
        chain_id: u32,
        iteration: u32,
        chain_key: &[u8],
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) -> Result<()> {
        self.states.clear();
        self.add_sender_key_state(
            message_version,
            chain_id,
            iteration,
            chain_key,
            signature_key,
            signature_private_key,
        )
    }

    pub fn as_protobuf(&self) -> Result<storage_proto::SenderKeyRecordStructure> {
        let mut states = Vec::with_capacity(self.states.len());
        for state in &self.states {
            states.push(state.as_protobuf()?);
        }

        Ok(storage_proto::SenderKeyRecordStructure {
            sender_key_states: states,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];
        self.as_protobuf()?.encode(&mut buf)?;
        Ok(buf)
    }
}
