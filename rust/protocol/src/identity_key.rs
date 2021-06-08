//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::proto;
use crate::{KeyPair, PrivateKey, PublicKey, Result, SignalProtocolError};

use rand::{CryptoRng, Rng};
use std::convert::TryFrom;

use prost::Message;

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
pub struct IdentityKey {
    public_key: PublicKey,
}

impl IdentityKey {
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }

    #[inline]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    #[inline]
    pub fn serialize(&self) -> Box<[u8]> {
        self.public_key.serialize()
    }

    pub fn decode(value: &[u8]) -> Result<Self> {
        let pk = PublicKey::try_from(value)?;
        Ok(Self { public_key: pk })
    }
}

impl TryFrom<&[u8]> for IdentityKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        IdentityKey::decode(value)
    }
}

impl From<PublicKey> for IdentityKey {
    fn from(value: PublicKey) -> Self {
        Self { public_key: value }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct IdentityKeyPair {
    identity_key: IdentityKey,
    private_key: PrivateKey,
}

impl IdentityKeyPair {
    pub fn new(identity_key: IdentityKey, private_key: PrivateKey) -> Self {
        Self {
            identity_key,
            private_key,
        }
    }

    pub fn generate<R: CryptoRng + Rng>(csprng: &mut R) -> Self {
        let keypair = KeyPair::generate(csprng);

        Self {
            identity_key: keypair.public_key.into(),
            private_key: keypair.private_key,
        }
    }

    #[inline]
    pub fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }

    #[inline]
    pub fn public_key(&self) -> &PublicKey {
        &self.identity_key.public_key()
    }

    #[inline]
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    pub fn serialize(&self) -> Box<[u8]> {
        let structure = proto::storage::IdentityKeyPairStructure {
            public_key: self.identity_key.serialize().to_vec(),
            private_key: self.private_key.serialize().to_vec(),
        };
        let mut result = Vec::new();

        // prost documents the only possible encoding error is if there is insufficient
        // space, which is not a problem when it is allowed to encode into a Vec
        structure.encode(&mut result).expect("No encoding error");
        result.into_boxed_slice()
    }
}

impl TryFrom<&[u8]> for IdentityKeyPair {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        let structure = proto::storage::IdentityKeyPairStructure::decode(value)?;
        Ok(Self {
            identity_key: IdentityKey::try_from(&structure.public_key[..])?,
            private_key: PrivateKey::deserialize(&structure.private_key)?,
        })
    }
}

impl TryFrom<PrivateKey> for IdentityKeyPair {
    type Error = SignalProtocolError;

    fn try_from(private_key: PrivateKey) -> Result<Self> {
        let identity_key = IdentityKey::new(private_key.public_key()?);
        Ok(Self::new(identity_key, private_key))
    }
}

impl From<KeyPair> for IdentityKeyPair {
    fn from(value: KeyPair) -> Self {
        Self {
            identity_key: value.public_key.into(),
            private_key: value.private_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::rngs::OsRng;

    #[test]
    fn test_identity_key_from() {
        let key_pair = KeyPair::generate(&mut OsRng);
        let key_pair_public_serialized = key_pair.public_key.serialize();
        let identity_key = IdentityKey::from(key_pair.public_key);
        assert_eq!(key_pair_public_serialized, identity_key.serialize());
    }

    #[test]
    fn test_serialize_identity_key_pair() -> Result<()> {
        let identity_key_pair = IdentityKeyPair::generate(&mut OsRng);
        let serialized = identity_key_pair.serialize();
        let deserialized_identity_key_pair = IdentityKeyPair::try_from(&serialized[..])?;
        assert_eq!(
            identity_key_pair.identity_key(),
            deserialized_identity_key_pair.identity_key()
        );
        assert_eq!(
            identity_key_pair.private_key().key_type(),
            deserialized_identity_key_pair.private_key().key_type()
        );
        assert_eq!(
            identity_key_pair.private_key().serialize(),
            deserialized_identity_key_pair.private_key().serialize()
        );

        Ok(())
    }
}
