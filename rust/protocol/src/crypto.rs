//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Application of cryptographic primitives, including [HMAC] and [AES].
//!
//! [HMAC]: https://en.wikipedia.org/wiki/HMAC
//! [AES]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

#![warn(missing_docs)]

use crate::{error::Result, SignalProtocolError};

use aes::cipher::stream::{NewStreamCipher, SyncStreamCipher};
use aes::Aes256;
use arrayref::array_ref;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use ctr::Ctr128;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// To avoid mysterious 8s everywhere.
///
/// *TODO: Could be nice to have a type-safe library for manipulating units of bytes safely.*
const BITS_PER_BYTE: usize = std::mem::size_of::<u8>() * 8;

/// The length of the key we use for [AES] encryption in this crate.
///
/// Used in [aes_256_ctr_encrypt] and [aes_256_ctr_decrypt].
///
/// [AES]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
pub const AES_256_KEY_SIZE: usize = 256 / BITS_PER_BYTE;

/// The size of the generated nonce we use for [AES] encryption in this crate.
///
/// Used in [aes_256_ctr_encrypt] and [aes_256_ctr_decrypt].
///
/// [AES]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
pub const AES_NONCE_SIZE: usize = 128 / BITS_PER_BYTE;

/// Encrypt plaintext `ptext` using key `key` with [AES]-256 in [CTR] mode.
///
/// [AES]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
/// [CTR]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CTR
///```
/// # fn main() -> Result<(), libsignal_protocol::error::SignalProtocolError> {
/// # use libsignal_protocol::crypto_unstable::*;
/// use rand::Rng;
/// // Generate a random AES key.
/// let key: [u8; AES_256_KEY_SIZE] = (&mut rand::thread_rng()).gen();
///
/// # #[allow(unused_variables)]
/// // Encrypt a message with the generated key.
/// let encrypted = aes_256_ctr_encrypt(b"hello", &key)?;
/// # Ok(())
/// # }
///```
pub fn aes_256_ctr_encrypt(ptext: &[u8], key: &[u8; AES_256_KEY_SIZE]) -> Result<Vec<u8>> {
    let zero_nonce = [0u8; 16];
    let mut cipher = Ctr128::<Aes256>::new(key.into(), (&zero_nonce).into());

    let mut ctext = ptext.to_vec();
    cipher.apply_keystream(&mut ctext);
    Ok(ctext)
}

/// Decrypt ciphertext `ctext` using key `key` with [AES]-256 in [CTR] mode.
///
/// [AES]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
/// [CTR]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CTR
///```
/// # fn main() -> Result<(), libsignal_protocol::error::SignalProtocolError> {
/// # use libsignal_protocol::crypto_unstable::*;
/// use rand::Rng;
/// // Generate a random AES key.
/// let key: [u8; AES_256_KEY_SIZE] = (&mut rand::thread_rng()).gen();
///
/// // Encrypt and decrypt a message with the symmetric key we just generated.
/// let encrypted = aes_256_ctr_encrypt(b"hello", &key)?;
/// assert!(b"hello".as_ref() == &aes_256_ctr_decrypt(&encrypted, &key)?);
/// # Ok(())
/// # }
///```
pub fn aes_256_ctr_decrypt(ctext: &[u8], key: &[u8; AES_256_KEY_SIZE]) -> Result<Vec<u8>> {
    aes_256_ctr_encrypt(ctext, key)
}

/// Encrypt plaintext `ptext` using key `key` and initialization vector `iv` with [AES]-256 in
/// [CBC] mode.
///
/// [AES]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
/// [CBC]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC
///```
/// # fn main() -> Result<(), libsignal_protocol::error::SignalProtocolError> {
/// # use libsignal_protocol::crypto_unstable::*;
/// use rand::Rng;
/// // Generate a random AES key.
/// let key: [u8; AES_256_KEY_SIZE] = (&mut rand::thread_rng()).gen();
/// // Generate an AES initialization vector (IV).
/// let iv: [u8; AES_NONCE_SIZE] = (&mut rand::thread_rng()).gen();
///
/// # #[allow(unused_variables)]
/// // Encrypt a message with the generated key material.
/// let encrypted = aes_256_cbc_encrypt(b"hello", &key, &iv)?;
/// # Ok(())
/// # }
///```
pub fn aes_256_cbc_encrypt(
    ptext: &[u8],
    key: &[u8; AES_256_KEY_SIZE],
    iv: &[u8; AES_NONCE_SIZE],
) -> Result<Vec<u8>> {
    match Cbc::<Aes256, Pkcs7>::new_var(key, iv) {
        Ok(mode) => Ok(mode.encrypt_vec(&ptext)),
        Err(block_modes::InvalidKeyIvLength) => Err(
            SignalProtocolError::InvalidCipherCryptographicParameters(key.len(), iv.len()),
        ),
    }
}

/// Decrypt ciphertext `ctext` using key `key` and initialization vector `iv` with [AES]-256 in
/// [CBC] mode.
///
/// [AES]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
/// [CBC]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC
///```
/// # fn main() -> Result<(), libsignal_protocol::error::SignalProtocolError> {
/// # use libsignal_protocol::crypto_unstable::*;
/// use rand::Rng;
/// // Generate a random AES key.
/// let key: [u8; AES_256_KEY_SIZE] = (&mut rand::thread_rng()).gen();
/// // Generate an AES initialization vector (IV).
/// let iv: [u8; AES_NONCE_SIZE] = (&mut rand::thread_rng()).gen();
///
/// // Encrypt and decrypt a message with the generated symmetric key material.
/// let encrypted = aes_256_cbc_encrypt(b"hello", &key, &iv)?;
/// assert!(b"hello".as_ref() == &aes_256_cbc_decrypt(&encrypted, &key, &iv)?);
/// # Ok(())
/// # }
///```
pub fn aes_256_cbc_decrypt(
    ctext: &[u8],
    key: &[u8; AES_256_KEY_SIZE],
    iv: &[u8; AES_NONCE_SIZE],
) -> Result<Vec<u8>> {
    if ctext.is_empty() || ctext.len() % 16 != 0 {
        return Err(SignalProtocolError::InvalidCiphertext);
    }

    let mode = match Cbc::<Aes256, Pkcs7>::new_var(key, iv) {
        Ok(mode) => mode,
        Err(block_modes::InvalidKeyIvLength) => {
            return Err(SignalProtocolError::InvalidCipherCryptographicParameters(
                key.len(),
                iv.len(),
            ))
        }
    };

    Ok(mode
        .decrypt_vec(ctext)
        .map_err(|_| SignalProtocolError::InvalidCiphertext)?)
}

/// The statically-known size of the output of [hmac_sha256].
pub const HMAC_OUTPUT_SIZE: usize = 256 / BITS_PER_BYTE;

/// Calculate the [HMAC]-SHA256 code over `input` using `key`.
///
/// [HMAC]: https://en.wikipedia.org/wiki/HMAC
///```
/// # fn main() -> Result<(), libsignal_protocol::error::SignalProtocolError> {
/// # use libsignal_protocol::crypto_unstable::*;
/// use rand::distributions::*;
/// // We can accept any size key for the HMAC operation, so generate a random size from 35-300.
/// let key_len: usize = Uniform::new_inclusive(35, 300).sample(&mut rand::thread_rng());
/// // Generate a random byte vector of the desired length.
/// let key: Vec<u8> = Standard.sample_iter(&mut rand::thread_rng()).take(key_len).collect();
///
/// # #[allow(unused_variables)]
/// // Generate the HMAC.
/// let hmac: [u8; 32] = hmac_sha256(key.as_ref(), b"hello");
/// # Ok(())
/// # }
///```
pub fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; HMAC_OUTPUT_SIZE] {
    let mut hmac = Hmac::<Sha256>::new_varkey(key).expect("HMAC-SHA256 should accept any size key");
    hmac.update(input);
    let result = hmac.finalize().into_bytes();
    assert_eq!(HMAC_OUTPUT_SIZE, result.len());
    *array_ref![&result, 0, HMAC_OUTPUT_SIZE]
}

/// Length in bytes of the [HMAC] key used for [aes256_ctr_hmacsha256_encrypt] and
/// [aes256_ctr_hmacsha256_decrypt].
///
/// [HMAC]: https://en.wikipedia.org/wiki/HMAC
pub const MAC_KEY_LENGTH: usize = 10;

/// Encrypt plaintext `msg` with [AES]-256 and embed a computed [HMAC] into the returned bytes.
///
/// *Implementation note: within the body of this method, only the first [MAC_KEY_LENGTH] bytes of
/// the computed MAC are used.*
///
/// [AES]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
/// [HMAC]: https://en.wikipedia.org/wiki/HMAC
///```
/// # fn main() -> Result<(), libsignal_protocol::error::SignalProtocolError> {
/// # use libsignal_protocol::crypto_unstable::*;
/// use rand::{Rng, distributions::*};
/// // We can accept any size key for the HMAC operation, so generate a random size from 35-300.
/// let mac_key_len: usize = Uniform::new_inclusive(35, 300).sample(&mut rand::thread_rng());
/// // Generate a random byte vector of the desired length.
/// let mac_key: Vec<u8> =
///     Standard.sample_iter(&mut rand::thread_rng()).take(mac_key_len).collect();
/// // Generate a random AES cipher key.
/// let cipher_key: [u8; AES_256_KEY_SIZE] = (&mut rand::thread_rng()).gen();
///
/// # #[allow(unused_variables)]
/// // Encrypt a message with the generated key material, embedding a MAC into the ciphertext.
/// let encrypted = aes256_ctr_hmacsha256_encrypt(b"hello", &cipher_key, &mac_key)?;
/// # Ok(())
/// # }
///```
pub fn aes256_ctr_hmacsha256_encrypt(
    msg: &[u8],
    cipher_key: &[u8; AES_256_KEY_SIZE],
    mac_key: &[u8],
) -> Result<Vec<u8>> {
    let ctext = aes_256_ctr_encrypt(msg, cipher_key)?;
    let mac = hmac_sha256(mac_key, &ctext);
    let mut result = Vec::with_capacity(ctext.len() + MAC_KEY_LENGTH);
    result.extend_from_slice(&ctext);
    result.extend_from_slice(&mac[..MAC_KEY_LENGTH]);
    Ok(result)
}

/// Validate the [HMAC] `mac_key` against the ciphertext `ctext`, then decrypt `ctext` using
/// [AES]-256 with `cipher_key` and [aes_256_ctr_decrypt].
///
/// *Implementation note: the last [MAC_KEY_LENGTH] bytes of the `ctext` slice represent the
/// truncated [HMAC] of the rest of the message, as generated by [aes256_ctr_hmacsha256_encrypt].*
///
/// [AES]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
/// [HMAC]: https://en.wikipedia.org/wiki/HMAC
///```
/// # fn main() -> Result<(), libsignal_protocol::error::SignalProtocolError> {
/// # use libsignal_protocol::{*, crypto_unstable::*};
/// use rand::{Rng, distributions::*};
/// // We can accept any size key for the HMAC operation, so generate a random size from 35-300.
/// let mac_key_len: usize = Uniform::new_inclusive(35, 300).sample(&mut rand::thread_rng());
/// // Generate a random byte vector of the desired length.
/// let mut mac_key: Vec<u8> =
///     Standard.sample_iter(&mut rand::thread_rng()).take(mac_key_len).collect();
/// // Generate a random AES cipher key.
/// let cipher_key: [u8; AES_256_KEY_SIZE] = (&mut rand::thread_rng()).gen();
///
/// // Encrypt and decrypt a message with the symmetric keys we generated.
/// let encrypted = aes256_ctr_hmacsha256_encrypt(b"hello", &cipher_key, &mac_key)?;
/// // This decryption method verifies that the input ciphertext has a correct MAC at the end.
/// assert!(&aes256_ctr_hmacsha256_decrypt(&encrypted, &cipher_key, &mac_key)? ==
///         b"hello".as_ref());
/// // Modify the MAC key to demonstrate how it would fail.
/// mac_key[0] += 1;
/// assert!(aes256_ctr_hmacsha256_decrypt(&encrypted, &cipher_key, &mac_key) ==
///         Err(SignalProtocolError::InvalidCiphertext));
/// # Ok(())
/// # }
///```
pub fn aes256_ctr_hmacsha256_decrypt(
    ctext: &[u8],
    cipher_key: &[u8; AES_256_KEY_SIZE],
    mac_key: &[u8],
) -> Result<Vec<u8>> {
    if ctext.len() < MAC_KEY_LENGTH {
        return Err(SignalProtocolError::InvalidCiphertext);
    }
    let ptext_len = ctext.len() - MAC_KEY_LENGTH;
    let our_mac = hmac_sha256(mac_key, &ctext[..ptext_len]);
    let same: bool = our_mac[..MAC_KEY_LENGTH].ct_eq(&ctext[ptext_len..]).into();
    if !same {
        return Err(SignalProtocolError::InvalidCiphertext);
    }
    aes_256_ctr_decrypt(&ctext[..ptext_len], cipher_key)
}

#[cfg(test)]
mod test {
    use super::Result;
    use std::convert::TryInto;

    #[test]
    fn aes_cbc_test() -> Result<()> {
        let key: [u8; 32] =
            hex::decode("4e22eb16d964779994222e82192ce9f747da72dc4abe49dfdeeb71d0ffe3796e")
                .expect("valid hex")
                .try_into()
                .expect("valid AES key");
        let iv: [u8; 16] = hex::decode("6f8a557ddc0a140c878063a6d5f31d3d")
            .expect("valid hex")
            .try_into()
            .expect("valid AES IV");

        let ptext = hex::decode("30736294a124482a4159").expect("valid hex");

        let ctext = super::aes_256_cbc_encrypt(&ptext, &key, &iv)?;
        assert_eq!(
            hex::encode(ctext.clone()),
            "dd3f573ab4508b9ed0e45e0baf5608f3"
        );

        let recovered = super::aes_256_cbc_decrypt(&ctext, &key, &iv)?;
        assert_eq!(hex::encode(ptext), hex::encode(recovered.clone()));

        // padding is invalid:
        assert!(super::aes_256_cbc_decrypt(&recovered, &key, &iv).is_err());

        // bitflip the IV to cause a change in the recovered text
        let bad_iv: [u8; 16] = hex::decode("ef8a557ddc0a140c878063a6d5f31d3d")
            .expect("valid hex")
            .try_into()
            .expect("valid AES IV");
        let recovered = super::aes_256_cbc_decrypt(&ctext, &key, &bad_iv)?;
        assert_eq!(hex::encode(recovered), "b0736294a124482a4159");

        Ok(())
    }

    #[test]
    fn aes_ctr_test() -> Result<()> {
        let key = hex::decode("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4")
            .expect("valid hex");
        let ptext = [0u8; 35];

        let ctext = super::aes_256_ctr_encrypt(
            &ptext,
            &key.try_into()
                .expect("failed to encrypt with valid hex string"),
        )?;
        assert_eq!(
            hex::encode(ctext),
            "e568f68194cf76d6174d4cc04310a85491151e5d0b7a1f1bc0d7acd0ae3e51e4170e23"
        );

        Ok(())
    }
}
