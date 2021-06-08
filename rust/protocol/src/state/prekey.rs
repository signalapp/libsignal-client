//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::curve::curve25519::PRIVATE_KEY_LENGTH;
use crate::proto::storage::PreKeyRecordStructure;
use crate::{KeyPair, KeyType, PrivateKey, PublicKey, Result, SignalProtocolError};

use prost::Message;

use std::convert::TryInto;

pub type PreKeyId = u32;

#[derive(Debug, Clone)]
pub struct PreKeyRecord {
    pre_key: PreKeyRecordStructure,
    key_pair: KeyPair,
}

impl PreKeyRecord {
    pub fn new(id: PreKeyId, key: &KeyPair) -> Self {
        Self {
            pre_key: PreKeyRecordStructure {
                id,
                public_key: key.public_key.serialize().to_vec(),
                private_key: key.private_key.serialize().to_vec(),
            },
            key_pair: *key,
        }
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let record = PreKeyRecordStructure::decode(data)?;
        let PreKeyRecordStructure {
            public_key,
            private_key,
            ..
        } = record.clone();
        let public_key: &[u8; PublicKey::ENCODED_PUBLIC_KEY_LENGTH] =
            &public_key.try_into().map_err(|e: Vec<u8>| {
                SignalProtocolError::BadKeyLength(KeyType::Curve25519, e.len())
            })?;
        let public_key = PublicKey::deserialize(&public_key)?;
        let private_key: &[u8; PRIVATE_KEY_LENGTH] =
            &private_key.try_into().map_err(|e: Vec<u8>| {
                SignalProtocolError::BadKeyLength(KeyType::Curve25519, e.len())
            })?;
        let private_key = PrivateKey::deserialize(&private_key);
        Ok(Self {
            pre_key: record,
            key_pair: KeyPair::new(public_key, private_key),
        })
    }

    pub fn id(&self) -> PreKeyId {
        self.pre_key.id
    }

    pub fn key_pair(&self) -> KeyPair {
        self.key_pair
    }

    pub fn public_key(&self) -> PublicKey {
        self.key_pair.public_key
    }

    pub fn private_key(&self) -> PrivateKey {
        self.key_pair.private_key
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];
        self.pre_key.encode(&mut buf)?;
        Ok(buf)
    }
}
