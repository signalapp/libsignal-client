//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::curve::curve25519::SIGNATURE_LENGTH;
use crate::proto::storage::SignedPreKeyRecordStructure;
use crate::{KeyPair, KeyType, PrivateKey, PublicKey, Result, SignalProtocolError};
use prost::Message;
use std::convert::TryInto;

pub type SignedPreKeyId = u32;

#[derive(Debug, Clone)]
pub struct SignedPreKeyRecord {
    signed_pre_key: SignedPreKeyRecordStructure,
    id: SignedPreKeyId,
    timestamp: u64,
    key_pair: KeyPair,
    signature: [u8; SIGNATURE_LENGTH],
}

impl SignedPreKeyRecord {
    pub fn new(
        id: SignedPreKeyId,
        timestamp: u64,
        key: &KeyPair,
        signature: &[u8],
    ) -> Result<Self> {
        let signature: &[u8; SIGNATURE_LENGTH] =
            &signature.to_vec().try_into().map_err(|e: Vec<u8>| {
                SignalProtocolError::BadKeyLength(
                    KeyType::Curve25519,
                    e.len(),
                )
            })?;
        Ok(Self {
            signed_pre_key: SignedPreKeyRecordStructure {
                id,
                timestamp,
                public_key: key.public_key.serialize().to_vec(),
                private_key: key.private_key.serialize().to_vec(),
                signature: signature.to_vec(),
            },
            id,
            timestamp,
            key_pair: *key,
            signature: *signature,
        })
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let record = SignedPreKeyRecordStructure::decode(data)?;
        let SignedPreKeyRecordStructure {
            id,
            timestamp,
            public_key,
            private_key,
            signature,
        } = record.clone();
        let public_key = PublicKey::deserialize_result(&public_key)?;
        let private_key = PrivateKey::deserialize_result(&private_key)?;
        let signature: &[u8; SIGNATURE_LENGTH] = &signature.try_into().map_err(|e: Vec<u8>| {
            SignalProtocolError::BadKeyLength(
                KeyType::Curve25519,
                e.len(),
            )
        })?;
        Ok(Self {
            signed_pre_key: record,
            id,
            timestamp,
            key_pair: KeyPair::new(public_key, private_key),
            signature: *signature,
        })
    }

    pub fn id(&self) -> SignedPreKeyId {
        self.id
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn signature(&self) -> [u8; SIGNATURE_LENGTH] {
        self.signature
    }

    pub fn public_key(&self) -> PublicKey {
        self.key_pair.public_key
    }

    pub fn private_key(&self) -> PrivateKey {
        self.key_pair.private_key
    }

    pub fn key_pair(&self) -> KeyPair {
        self.key_pair
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];
        self.signed_pre_key.encode(&mut buf)?;
        Ok(buf)
    }
}
