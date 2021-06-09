//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Wrappers over cryptographic primitives from [crate::curve] to represent [identity].
//!
//! [identity]: https://en.wikipedia.org/wiki/Online_identity

#![warn(missing_docs)]

use crate::proto;
use crate::utils::no_encoding_error;
use crate::{KeyPair, PrivateKey, PublicKey, Result, SignalProtocolError};

#[cfg(doc)]
use crate::{protocol::PreKeySignalMessage, state::SessionRecord, storage::IdentityKeyStore};

use rand::{CryptoRng, Rng};
use std::convert::TryFrom;

use prost::Message;

/// The public identity of a user, used in [IdentityKeyStore].
///
/// Wrapper for [PublicKey].
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
pub struct IdentityKey {
    public_key: PublicKey,
}

impl IdentityKey {
    /// Initialize a public-facing identity from a public key.
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }

    /// Return a public key representing the public identity.
    #[inline]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Return an owned byte slice which can be deserialized with [Self::decode].
    #[inline]
    pub fn serialize(&self) -> [u8; PublicKey::ENCODED_PUBLIC_KEY_LENGTH] {
        self.public_key.serialize()
    }

    /// Deserialize a public identity from a byte slice.
    pub fn decode(value: &[u8]) -> Result<Self> {
        let pk = PublicKey::deserialize_result(value)?;
        Ok(Self { public_key: pk })
    }
}

impl TryFrom<&[u8; PublicKey::ENCODED_PUBLIC_KEY_LENGTH]> for IdentityKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8; PublicKey::ENCODED_PUBLIC_KEY_LENGTH]) -> Result<Self> {
        IdentityKey::decode(value)
    }
}

impl From<PublicKey> for IdentityKey {
    fn from(value: PublicKey) -> Self {
        Self { public_key: value }
    }
}

/// The private identity of a user.
///
/// This cryptographic identity is used to sign pre-keys in [PreKeySignalMessage], to conceal
/// sealed-sender [crate::sealed_sender::UnidentifiedSenderMessage]s, or to initiate the key
/// derivation function for a [SessionRecord].
///
/// Also see [KeyPair].
#[derive(Copy, Clone, Debug)]
pub struct IdentityKeyPair {
    identity_key: IdentityKey,
    private_key: PrivateKey,
}

impl IdentityKeyPair {
    /// Create a key pair from a public `identity_key` and a private `private_key`.
    pub fn new(identity_key: IdentityKey, private_key: PrivateKey) -> Self {
        Self {
            identity_key,
            private_key,
        }
    }

    /// Generate a random new identity from randomness in `csprng`.
    pub fn generate<R: CryptoRng + Rng>(csprng: &mut R) -> Self {
        let keypair = KeyPair::generate(csprng);

        Self {
            identity_key: keypair.public_key.into(),
            private_key: keypair.private_key,
        }
    }

    /// Return the public identity of this user.
    #[inline]
    pub fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }

    /// Return the public key that defines this identity.
    #[inline]
    pub fn public_key(&self) -> &PublicKey {
        &self.identity_key.public_key()
    }

    /// Return the private key that defines this identity.
    #[inline]
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Return a byte slice which can later be deserialized with [Self::try_from].
    pub fn serialize(&self) -> Box<[u8]> {
        no_encoding_error(proto::storage::IdentityKeyPairStructure {
            public_key: self.identity_key.serialize().to_vec(),
            private_key: self.private_key.serialize().to_vec(),
        })
    }
}

impl TryFrom<&[u8]> for IdentityKeyPair {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        let structure = proto::storage::IdentityKeyPairStructure::decode(value)?;
        Ok(Self {
            identity_key: IdentityKey::new(PublicKey::deserialize_result(
                &structure.public_key[..],
            )?),
            private_key: PrivateKey::deserialize_result(&structure.private_key)?,
        })
    }
}

impl From<PrivateKey> for IdentityKeyPair {
    fn from(private_key: PrivateKey) -> Self {
        let identity_key = IdentityKey::new(private_key.public_key());
        Self::new(identity_key, private_key)
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
    use crate::curve::Keyed;

    use rand::rngs::OsRng;

    #[test]
    fn test_identity_key_from() {
        let key_pair = KeyPair::generate(&mut OsRng);
        let key_pair_public_serialized = key_pair.public_key.serialize();
        let identity_key = IdentityKey::from(key_pair.public_key);
        assert_eq!(
            key_pair_public_serialized.as_ref(),
            identity_key.serialize().as_ref()
        );
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
