//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Cryptographic primitives for asymmetric keys.
//!
//! Some example operations:
//!```
//! use libsignal_protocol::KeyPair;
//! use std::collections::HashSet;
//!
//! let alice = KeyPair::generate(&mut rand::thread_rng());
//! assert!(alice == alice.clone());
//! let bob = KeyPair::generate(&mut rand::thread_rng());
//! assert!(alice != bob);
//!
//! // Keys can be hashed and put in sets.
//! let key_set: HashSet<KeyPair> = [alice, bob].iter().cloned().collect();
//! assert!(key_set.contains(&alice));
//! assert!(key_set.contains(&bob));
//!```

#![warn(missing_docs)]

pub mod curve25519;

use crate::utils::constant_time_cmp;
use crate::{Result, SignalProtocolError};

use std::cmp::Ordering;
use std::convert::{TryFrom, TryInto};
use std::fmt;

use arrayref::array_ref;
use num_enum::{IntoPrimitive, TryFromPrimitive, TryFromPrimitiveError};
use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;

/// Map the variant of key being used to and from a [u8].
///
/// Implements [SignalProtocolError::from] on top of [num_enum::TryFromPrimitive] to convert into
/// raising a [SignalProtocolError] if the encoded key variant is invalid.
///
///```
/// # fn main() -> libsignal_protocol::error::Result<()> {
/// use libsignal_protocol::KeyType;
/// use std::convert::{TryFrom, TryInto};
///
/// let encoded_key_type: u8 = KeyType::Curve25519.into();
/// assert!(encoded_key_type == 0x05);
///
/// let original_key_type: KeyType = encoded_key_type.try_into()?;
/// assert!(original_key_type == KeyType::Curve25519);
///
/// let bad_encoded_key: u8 = 0x27;
/// assert!(KeyType::try_from(bad_encoded_key).is_err());
/// # Ok(())
/// # }
///```
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum KeyType {
    /// See [Curve25519].
    ///
    /// [Curve25519]: https://en.wikipedia.org/wiki/Curve25519.
    Curve25519 = 0x05,
}

impl From<TryFromPrimitiveError<KeyType>> for SignalProtocolError {
    fn from(err: TryFromPrimitiveError<KeyType>) -> Self {
        SignalProtocolError::BadKeyType(err.number)
    }
}

/// Interface for structs that perform operations parameterized by values of [KeyType].
pub trait Keyed {
    /// Return the variant of key this object employs.
    fn key_type(&self) -> KeyType;
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
enum PublicKeyData {
    Curve25519([u8; 32]),
}

/// Public key half of a [KeyPair].
///
/// Uses [Self::ct_eq] and [constant_time_cmp] to implement equality and ordering without leaking
/// too much information about the contents of the data being compared.
#[derive(Clone, Copy, Eq, Hash)]
pub struct PublicKey {
    key: PublicKeyData,
}

impl PublicKey {
    fn new(key: PublicKeyData) -> Self {
        Self { key }
    }

    /// Deserialize a public key from a byte slice.
    pub fn deserialize(value: &[u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(SignalProtocolError::NoKeyTypeIdentifier);
        }
        let key_type = KeyType::try_from(value[0])?;
        match key_type {
            KeyType::Curve25519 => {
                // We allow trailing data after the public key (why?)
                if value.len() < 32 + 1 {
                    return Err(SignalProtocolError::BadKeyLength(
                        KeyType::Curve25519,
                        value.len(),
                    ));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&value[1..33]);
                Ok(PublicKey {
                    key: PublicKeyData::Curve25519(key),
                })
            }
        }
    }

    /// Return the bytes that make up this public key.
    pub fn public_key_bytes(&self) -> Result<&[u8]> {
        match self.key {
            PublicKeyData::Curve25519(ref v) => Ok(v),
        }
    }

    /// Create an instance by attempting to interpret `bytes` as a [KeyType::Curve25519] public key.
    pub fn from_curve25519_public_key_bytes(bytes: &[u8]) -> Result<Self> {
        match <[u8; 32]>::try_from(bytes) {
            Err(_) => Err(SignalProtocolError::BadKeyLength(
                KeyType::Curve25519,
                bytes.len(),
            )),
            Ok(key) => Ok(PublicKey {
                key: PublicKeyData::Curve25519(key),
            }),
        }
    }

    /// Return a byte slice which can be deserialized with [Self::deserialize].
    pub fn serialize(&self) -> Box<[u8]> {
        let value_len = match self.key {
            PublicKeyData::Curve25519(v) => v.len(),
        };
        let mut result = Vec::with_capacity(1 + value_len);
        result.push(self.key_type().into());
        match self.key {
            PublicKeyData::Curve25519(v) => result.extend_from_slice(&v),
        }
        result.into_boxed_slice()
    }

    /// Validate whether `signature` successfully matches `message` for this public key.
    ///
    /// Return `Ok(false)` if the signature fails to match or could not be read.
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        match self.key {
            PublicKeyData::Curve25519(pub_key) => {
                if signature.len() != 64 {
                    return Ok(false);
                }
                Ok(curve25519::KeyPair::verify_signature(
                    &pub_key,
                    message,
                    array_ref![signature, 0, 64],
                ))
            }
        }
    }

    pub(crate) fn key_data(&self) -> &[u8] {
        match self.key {
            PublicKeyData::Curve25519(ref x) => x,
        }
    }
}

impl Keyed for PublicKey {
    fn key_type(&self) -> KeyType {
        match self.key {
            PublicKeyData::Curve25519(_) => KeyType::Curve25519,
        }
    }
}

impl From<PublicKeyData> for PublicKey {
    fn from(key: PublicKeyData) -> PublicKey {
        Self { key }
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::deserialize(value)
    }
}

impl subtle::ConstantTimeEq for PublicKey {
    /// A constant-time comparison as long as the two keys have a matching type.
    ///
    /// If the two keys have different types, the comparison short-circuits,
    /// much like comparing two slices of different lengths.
    fn ct_eq(&self, other: &PublicKey) -> subtle::Choice {
        if self.key_type() != other.key_type() {
            return 0.ct_eq(&1);
        }
        self.key_data().ct_eq(other.key_data())
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.key_type() != other.key_type() {
            return self.key_type().cmp(&other.key_type());
        }

        crate::utils::constant_time_cmp(self.key_data(), other.key_data())
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PublicKey {{ key_type={:?}, serialize={:?} }}",
            self.key_type(),
            self.serialize()
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
enum PrivateKeyData {
    Curve25519([u8; curve25519::PRIVATE_KEY_LENGTH]),
}

/// Private key half of a [KeyPair].
///
/// Analogously to [PublicKey], uses [Self::ct_eq] and [constant_time_cmp] to implement equality and
/// ordering without leaking too much information about the contents of the data being compared.
#[derive(Clone, Copy, Eq, Hash)]
pub struct PrivateKey {
    key: PrivateKeyData,
}

impl PrivateKey {
    /// Try to parse a private key from the byte slice `value`.
    pub fn deserialize(value: &[u8]) -> Result<Self> {
        if value.len() != 32 {
            Err(SignalProtocolError::BadKeyLength(
                KeyType::Curve25519,
                value.len(),
            ))
        } else {
            let mut key = [0u8; 32];
            key.copy_from_slice(&value[..32]);
            // Clamp:
            key[0] &= 0xF8;
            key[31] &= 0x7F;
            key[31] |= 0x40;
            Ok(Self {
                key: PrivateKeyData::Curve25519(key),
            })
        }
    }

    /// Return a byte slice which can be deserialized with [Self::deserialize].
    pub fn serialize(&self) -> Vec<u8> {
        match self.key {
            PrivateKeyData::Curve25519(v) => v.to_vec(),
        }
    }

    /// Derive a public key from the current private key's contents.
    pub fn public_key(&self) -> Result<PublicKey> {
        match self.key {
            PrivateKeyData::Curve25519(private_key) => {
                let public_key = curve25519::derive_public_key(&private_key);
                Ok(PublicKey::new(PublicKeyData::Curve25519(public_key)))
            }
        }
    }

    /// Calculate a signature for `message` given this private key.
    pub fn calculate_signature<R: CryptoRng + Rng>(
        &self,
        message: &[u8],
        csprng: &mut R,
    ) -> Result<Box<[u8]>> {
        match self.key {
            PrivateKeyData::Curve25519(k) => {
                let kp = curve25519::KeyPair::from(k);
                Ok(Box::from(kp.calculate_signature(csprng, message).as_ref()))
            }
        }
    }

    /// Calculate a shared secret between this private key and the public key `their_key`.
    pub fn calculate_agreement(
        &self,
        their_key: &PublicKey,
    ) -> Result<[u8; curve25519::AGREEMENT_LENGTH]> {
        match (self.key, their_key.key) {
            (PrivateKeyData::Curve25519(priv_key), PublicKeyData::Curve25519(pub_key)) => {
                let kp = curve25519::KeyPair::from(priv_key);
                Ok(kp.calculate_agreement(&pub_key))
            }
        }
    }

    pub(crate) fn key_data(&self) -> Box<[u8]> {
        Box::from(
            self.public_key()
                .expect("should always have a public key translation")
                .key_data(),
        )
    }
}

impl Keyed for PrivateKey {
    fn key_type(&self) -> KeyType {
        match self.key {
            PrivateKeyData::Curve25519(_) => KeyType::Curve25519,
        }
    }
}

impl From<PrivateKeyData> for PrivateKey {
    fn from(key: PrivateKeyData) -> PrivateKey {
        Self { key }
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::deserialize(value)
    }
}

impl subtle::ConstantTimeEq for PrivateKey {
    fn ct_eq(&self, other: &PrivateKey) -> subtle::Choice {
        if self.key_type() != other.key_type() {
            return 0.ct_eq(&1);
        }
        self.key_data().as_ref().ct_eq(other.key_data().as_ref())
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &PrivateKey) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Ord for PrivateKey {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.key_type() != other.key_type() {
            return self.key_type().cmp(&other.key_type());
        }
        constant_time_cmp(self.key_data().as_ref(), other.key_data().as_ref())
    }
}

impl PartialOrd for PrivateKey {
    fn partial_cmp(&self, other: &PrivateKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            // Do not print out private keys in debug logs.
            "PrivateKey {{ key_type={:?}, serialize=<...> }}",
            self.key_type(),
        )
    }
}

/// A matching public and private key pair which can be used to encrypt and sign messages.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct KeyPair {
    /// The public half of this identity.
    pub public_key: PublicKey,
    /// The private half of this identity.
    pub private_key: PrivateKey,
}

impl KeyPair {
    /// Create a new identity from randomness in `csprng`.
    ///
    ///```
    /// use libsignal_protocol::KeyPair;
    ///
    /// // Create a new unique key pair from random state.
    /// let alice = KeyPair::generate(&mut rand::thread_rng());
    /// assert!(alice == alice.clone());
    ///
    /// // Any subsequently generated random key pair will be different.
    /// let bob = KeyPair::generate(&mut rand::thread_rng());
    /// assert!(alice != bob);
    ///```
    pub fn generate<R: Rng + CryptoRng>(csprng: &mut R) -> Self {
        let keypair = curve25519::KeyPair::new(csprng);

        let public_key = PublicKey::from(PublicKeyData::Curve25519(*keypair.public_key()));
        let private_key = PrivateKey::from(PrivateKeyData::Curve25519(*keypair.private_key()));

        Self::new(public_key, private_key)
    }

    /// Instantiate an identity from a known public/private key pair.
    ///
    ///```
    /// use libsignal_protocol::KeyPair;
    ///
    /// // Generate a random key pair.
    /// let kp = KeyPair::generate(&mut rand::thread_rng());
    ///
    /// // Reconstruct the key pair from its fields.
    /// let KeyPair { public_key, private_key } = kp;
    /// assert!(kp == KeyPair::new(public_key, private_key));
    ///```
    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Self {
        assert_eq!(public_key.key_type(), private_key.key_type());
        Self {
            public_key,
            private_key,
        }
    }

    /// Instantiate an identity from serialized public and private keys.
    ///```
    /// # fn main() -> Result<(), libsignal_protocol::error::SignalProtocolError> {
    /// use libsignal_protocol::KeyPair;
    ///
    /// // Generate a random key pair.
    /// let kp = KeyPair::generate(&mut rand::thread_rng());
    ///
    /// // Reconstruct the key pair from its fields.
    /// let KeyPair { public_key, private_key } = kp;
    /// assert!(kp == KeyPair::from_public_and_private(
    ///                   &public_key.serialize(),
    ///                   &private_key.serialize(),
    ///               )?);
    /// # Ok(())
    /// # }
    ///```
    pub fn from_public_and_private(public_key: &[u8], private_key: &[u8]) -> Result<Self> {
        let public_key = PublicKey::try_from(public_key)?;
        let private_key = PrivateKey::try_from(private_key)?;
        Ok(Self::new(public_key, private_key))
    }

    /// Calculate a signature for `message` given the current identity's private key.
    ///
    ///```
    /// # fn main() -> Result<(), libsignal_protocol::error::SignalProtocolError> {
    /// # use libsignal_protocol::KeyPair;
    /// let kp = KeyPair::generate(&mut rand::thread_rng());
    /// # #[allow(unused_variables)]
    /// let signature: Box<[u8]> = kp.calculate_signature(b"hello", &mut rand::thread_rng())?;
    /// # Ok(())
    /// # }
    ///```
    pub fn calculate_signature<R: CryptoRng + Rng>(
        &self,
        message: &[u8],
        csprng: &mut R,
    ) -> Result<Box<[u8]>> {
        self.private_key.calculate_signature(message, csprng)
    }

    /// Calculate a shared secret between our private key and the public key `their_key`.
    ///
    ///```
    /// # fn main() -> Result<(), libsignal_protocol::SignalProtocolError> {
    /// # use libsignal_protocol::KeyPair;
    /// let kp = KeyPair::generate(&mut rand::thread_rng());
    /// let kp2 = KeyPair::generate(&mut rand::thread_rng());
    /// assert!(
    ///   kp.calculate_agreement(&kp2.public_key)? == kp2.calculate_agreement(&kp.public_key)?
    /// );
    /// # Ok(())
    /// # }
    ///```
    pub fn calculate_agreement(&self, their_key: &PublicKey) -> Result<Box<[u8]>> {
        Ok(Box::from(
            self.private_key.calculate_agreement(their_key)?.as_ref(),
        ))
    }

    /// Verify a signature for `message` produced by [Self::calculate_signature].
    ///```
    /// # fn main() -> Result<(), libsignal_protocol::error::SignalProtocolError> {
    /// # use libsignal_protocol::KeyPair;
    /// let kp = KeyPair::generate(&mut rand::thread_rng());
    /// let signature = kp.calculate_signature(b"hello", &mut rand::thread_rng())?;
    /// assert!(KeyPair::verify_signature(&kp.public_key.serialize(), b"hello", &signature)?);
    /// # Ok(())
    /// # }
    ///```
    pub fn verify_signature(
        their_public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let their_public_key: PublicKey = their_public_key.try_into()?;
        their_public_key.verify_signature(message, signature)
    }
}

impl Keyed for KeyPair {
    fn key_type(&self) -> KeyType {
        assert_eq!(self.public_key.key_type(), self.private_key.key_type());
        self.public_key.key_type()
    }
}

impl subtle::ConstantTimeEq for KeyPair {
    fn ct_eq(&self, other: &KeyPair) -> subtle::Choice {
        if self.key_type() != other.key_type() {
            return 0.ct_eq(&1);
        }
        self.public_key.ct_eq(&other.public_key) & self.private_key.ct_eq(&other.private_key)
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn test_large_signatures() -> Result<()> {
        let mut csprng = OsRng;
        let key_pair = KeyPair::generate(&mut csprng);
        let mut message = [0u8; 1024 * 1024];
        let signature = key_pair
            .private_key
            .calculate_signature(&message, &mut csprng)?;

        assert!(key_pair.public_key.verify_signature(&message, &signature)?);
        message[0] ^= 0x01u8;
        assert!(!key_pair.public_key.verify_signature(&message, &signature)?);
        message[0] ^= 0x01u8;
        let public_key = key_pair.private_key.public_key()?;
        assert!(public_key.verify_signature(&message, &signature)?);

        Ok(())
    }

    #[test]
    fn test_decode_size() -> Result<()> {
        let mut csprng = OsRng;
        let key_pair = KeyPair::generate(&mut csprng);
        let serialized_public = key_pair.public_key.serialize();

        assert_eq!(
            serialized_public,
            key_pair.private_key.public_key()?.serialize()
        );
        let empty: [u8; 0] = [];

        let just_right = PublicKey::try_from(&serialized_public[..]);

        assert!(just_right.is_ok());
        assert!(PublicKey::try_from(&serialized_public[1..]).is_err());
        assert!(PublicKey::try_from(&empty[..]).is_err());

        let mut bad_key_type = [0u8; 33];
        bad_key_type[..].copy_from_slice(&serialized_public[..]);
        bad_key_type[0] = 0x01u8;
        assert!(PublicKey::try_from(&bad_key_type[..]).is_err());

        let mut extra_space = [0u8; 34];
        extra_space[..33].copy_from_slice(&serialized_public[..]);
        let extra_space_decode = PublicKey::try_from(&extra_space[..]);
        assert!(extra_space_decode.is_ok());

        assert_eq!(&serialized_public[..], &just_right?.serialize()[..]);
        assert_eq!(&serialized_public[..], &extra_space_decode?.serialize()[..]);
        Ok(())
    }
}
