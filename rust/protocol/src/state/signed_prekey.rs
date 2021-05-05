//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::proto::storage::SignedPreKeyRecordStructure;
use crate::{KeyPair, PrivateKey, PublicKey, Result};
use prost::Message;

/// A unique identifier selecting among this client's known signed pre-keys.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct SignedPreKeyId(u32);

impl From<u32> for SignedPreKeyId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<SignedPreKeyId> for u32 {
    fn from(value: SignedPreKeyId) -> Self {
        value.0
    }
}

#[derive(Debug, Clone)]
pub struct SignedPreKeyRecord {
    signed_pre_key: SignedPreKeyRecordStructure,
}

impl SignedPreKeyRecord {
    pub fn new(id: SignedPreKeyId, timestamp: u64, key: &KeyPair, signature: &[u8]) -> Self {
        let public_key = key.public_key.serialize().to_vec();
        let private_key = key.private_key.serialize().to_vec();
        let signature = signature.to_vec();
        Self {
            signed_pre_key: SignedPreKeyRecordStructure {
                id: id.into(),
                timestamp,
                public_key,
                private_key,
                signature,
            },
        }
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        Ok(Self {
            signed_pre_key: SignedPreKeyRecordStructure::decode(data)?,
        })
    }

    pub fn id(&self) -> Result<SignedPreKeyId> {
        Ok(self.signed_pre_key.id.into())
    }

    pub fn timestamp(&self) -> Result<u64> {
        Ok(self.signed_pre_key.timestamp)
    }

    pub fn signature(&self) -> Result<Vec<u8>> {
        Ok(self.signed_pre_key.signature.clone())
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::deserialize(&self.signed_pre_key.public_key)
    }

    pub fn private_key(&self) -> Result<PrivateKey> {
        PrivateKey::deserialize(&self.signed_pre_key.private_key)
    }

    pub fn key_pair(&self) -> Result<KeyPair> {
        KeyPair::from_public_and_private(
            &self.signed_pre_key.public_key,
            &self.signed_pre_key.private_key,
        )
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];
        self.signed_pre_key.encode(&mut buf)?;
        Ok(buf)
    }
}
