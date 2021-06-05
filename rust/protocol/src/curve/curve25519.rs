//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

pub const AGREEMENT_LENGTH: usize = 32;
pub const PRIVATE_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SIGNATURE_LENGTH: usize = 64;

#[derive(Debug, Clone)]
pub struct KeyPair {
    public_key: [u8; PUBLIC_KEY_LENGTH],
    private_key: [u8; PRIVATE_KEY_LENGTH],
}

impl KeyPair {
    pub fn new<R>(csprng: &mut R) -> Self
    where
        R: CryptoRng + Rng,
    {
        let secret = StaticSecret::new(csprng);
        let public = PublicKey::from(&secret);
        KeyPair {
            public_key: *public.as_bytes(),
            private_key: secret.to_bytes(),
        }
    }

    pub fn calculate_agreement(
        &self,
        their_public_key: &[u8; PUBLIC_KEY_LENGTH],
    ) -> [u8; AGREEMENT_LENGTH] {
        *StaticSecret::from(self.private_key)
            .diffie_hellman(&PublicKey::from(*their_public_key))
            .as_bytes()
    }

    /// Calculates an XEdDSA signature using the X25519 private key directly.
    ///
    /// Refer to https://signal.org/docs/specifications/xeddsa/#curve25519 for more details.
    ///
    /// Note that this implementation varies slightly from that paper in that the sign bit is not
    /// fixed to 0, but rather passed back in the most significant bit of the signature which would
    /// otherwise always be 0. This is for compatibility with the implementation found in
    /// libsignal-protocol-java.
    pub fn calculate_signature<R>(&self, csprng: &mut R, message: &[u8]) -> [u8; SIGNATURE_LENGTH]
    where
        R: CryptoRng + Rng,
    {
        let mut random_bytes = [0u8; 64];
        csprng.fill_bytes(&mut random_bytes);

        let a = Scalar::from_bits(self.private_key);
        let ed_public_key_point = &a * &ED25519_BASEPOINT_TABLE;
        let ed_public_key = ed_public_key_point.compress();
        let sign_bit = ed_public_key.as_bytes()[31] & 0b1000_0000_u8;

        let mut hash1 = Sha512::new();
        let hash_prefix = [
            0xFEu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
            0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
            0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
        ];
        hash1.update(&hash_prefix);
        hash1.update(&self.private_key);
        hash1.update(&message);
        hash1.update(&random_bytes[..]);

        let r = Scalar::from_hash(hash1);
        let cap_r = (&r * &ED25519_BASEPOINT_TABLE).compress();

        let mut hash = Sha512::new();
        hash.update(cap_r.as_bytes());
        hash.update(ed_public_key.as_bytes());
        hash.update(&message);

        let h = Scalar::from_hash(hash);
        let s = (h * a) + r;

        let mut result = [0u8; SIGNATURE_LENGTH];
        result[..32].copy_from_slice(cap_r.as_bytes());
        result[32..].copy_from_slice(s.as_bytes());
        result[SIGNATURE_LENGTH - 1] &= 0b0111_1111_u8;
        result[SIGNATURE_LENGTH - 1] |= sign_bit;
        result
    }

    pub fn verify_signature(
        their_public_key: &[u8; PUBLIC_KEY_LENGTH],
        message: &[u8],
        signature: &[u8; SIGNATURE_LENGTH],
    ) -> bool {
        let mont_point = MontgomeryPoint(*their_public_key);
        let ed_pub_key_point =
            match mont_point.to_edwards((signature[SIGNATURE_LENGTH - 1] & 0b1000_0000_u8) >> 7) {
                Some(x) => x,
                None => return false,
            };
        let cap_a = ed_pub_key_point.compress();
        let mut cap_r = [0u8; 32];
        cap_r.copy_from_slice(&signature[..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&signature[32..]);
        s[31] &= 0b0111_1111_u8;
        if (s[31] & 0b1110_0000_u8) != 0 {
            return false;
        }
        let minus_cap_a = -ed_pub_key_point;

        let mut hash = Sha512::new();
        hash.update(&cap_r);
        hash.update(cap_a.as_bytes());
        hash.update(&message);
        let h = Scalar::from_hash(hash);

        let cap_r_check_point = EdwardsPoint::vartime_double_scalar_mul_basepoint(
            &h,
            &minus_cap_a,
            &Scalar::from_bits(s),
        );
        let cap_r_check = cap_r_check_point.compress();

        bool::from(cap_r_check.as_bytes().ct_eq(&cap_r))
    }

    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.public_key
    }

    pub fn private_key(&self) -> &[u8; PRIVATE_KEY_LENGTH] {
        &self.private_key
    }
}

pub fn derive_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from(*private_key)).as_bytes()
}

impl From<[u8; PRIVATE_KEY_LENGTH]> for KeyPair {
    fn from(private_key: [u8; 32]) -> Self {
        let private_key = StaticSecret::from(private_key);
        let public_key = PublicKey::from(&private_key);

        KeyPair {
            private_key: private_key.to_bytes(),
            public_key: *public_key.as_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use rand::RngCore;

    use super::*;

    #[test]
    fn test_agreement() {
        let alice_public: [u8; 32] = [
            0x1b, 0xb7, 0x59, 0x66, 0xf2, 0xe9, 0x3a, 0x36, 0x91, 0xdf, 0xff, 0x94, 0x2b, 0xb2,
            0xa4, 0x66, 0xa1, 0xc0, 0x8b, 0x8d, 0x78, 0xca, 0x3f, 0x4d, 0x6d, 0xf8, 0xb8, 0xbf,
            0xa2, 0xe4, 0xee, 0x28,
        ];
        let alice_private: [u8; 32] = [
            0xc8, 0x06, 0x43, 0x9d, 0xc9, 0xd2, 0xc4, 0x76, 0xff, 0xed, 0x8f, 0x25, 0x80, 0xc0,
            0x88, 0x8d, 0x58, 0xab, 0x40, 0x6b, 0xf7, 0xae, 0x36, 0x98, 0x87, 0x90, 0x21, 0xb9,
            0x6b, 0xb4, 0xbf, 0x59,
        ];
        let bob_public: [u8; 32] = [
            0x65, 0x36, 0x14, 0x99, 0x3d, 0x2b, 0x15, 0xee, 0x9e, 0x5f, 0xd3, 0xd8, 0x6c, 0xe7,
            0x19, 0xef, 0x4e, 0xc1, 0xda, 0xae, 0x18, 0x86, 0xa8, 0x7b, 0x3f, 0x5f, 0xa9, 0x56,
            0x5a, 0x27, 0xa2, 0x2f,
        ];
        let bob_private: [u8; 32] = [
            0xb0, 0x3b, 0x34, 0xc3, 0x3a, 0x1c, 0x44, 0xf2, 0x25, 0xb6, 0x62, 0xd2, 0xbf, 0x48,
            0x59, 0xb8, 0x13, 0x54, 0x11, 0xfa, 0x7b, 0x03, 0x86, 0xd4, 0x5f, 0xb7, 0x5d, 0xc5,
            0xb9, 0x1b, 0x44, 0x66,
        ];
        let shared: [u8; 32] = [
            0x32, 0x5f, 0x23, 0x93, 0x28, 0x94, 0x1c, 0xed, 0x6e, 0x67, 0x3b, 0x86, 0xba, 0x41,
            0x01, 0x74, 0x48, 0xe9, 0x9b, 0x64, 0x9a, 0x9c, 0x38, 0x06, 0xc1, 0xdd, 0x7c, 0xa4,
            0xc4, 0x77, 0xe6, 0x29,
        ];

        let alice_key_pair = KeyPair::from(alice_private);
        let bob_key_pair = KeyPair::from(bob_private);

        assert_eq!(alice_public, *alice_key_pair.public_key());
        assert_eq!(bob_public, *bob_key_pair.public_key());

        let alice_computed_secret = alice_key_pair.calculate_agreement(&bob_public);
        let bob_computed_secret = bob_key_pair.calculate_agreement(&alice_public);

        assert_eq!(shared, alice_computed_secret);
        assert_eq!(shared, bob_computed_secret);
    }

    #[test]
    fn test_random_agreements() {
        let mut csprng = OsRng;
        for _ in 0..50 {
            let alice_key_pair = KeyPair::new(&mut csprng);
            let bob_key_pair = KeyPair::new(&mut csprng);

            let alice_computed_secret =
                alice_key_pair.calculate_agreement(bob_key_pair.public_key());
            let bob_computed_secret = bob_key_pair.calculate_agreement(alice_key_pair.public_key());

            assert_eq!(alice_computed_secret, bob_computed_secret);
        }
    }

    #[test]
    fn test_signature() {
        let alice_identity_private: [u8; PRIVATE_KEY_LENGTH] = [
            0xc0, 0x97, 0x24, 0x84, 0x12, 0xe5, 0x8b, 0xf0, 0x5d, 0xf4, 0x87, 0x96, 0x82, 0x05,
            0x13, 0x27, 0x94, 0x17, 0x8e, 0x36, 0x76, 0x37, 0xf5, 0x81, 0x8f, 0x81, 0xe0, 0xe6,
            0xce, 0x73, 0xe8, 0x65,
        ];
        let alice_identity_public: [u8; PUBLIC_KEY_LENGTH] = [
            0xab, 0x7e, 0x71, 0x7d, 0x4a, 0x16, 0x3b, 0x7d, 0x9a, 0x1d, 0x80, 0x71, 0xdf, 0xe9,
            0xdc, 0xf8, 0xcd, 0xcd, 0x1c, 0xea, 0x33, 0x39, 0xb6, 0x35, 0x6b, 0xe8, 0x4d, 0x88,
            0x7e, 0x32, 0x2c, 0x64,
        ];
        let alice_ephemeral_public: [u8; PUBLIC_KEY_LENGTH + 1] = [
            0x05, 0xed, 0xce, 0x9d, 0x9c, 0x41, 0x5c, 0xa7, 0x8c, 0xb7, 0x25, 0x2e, 0x72, 0xc2,
            0xc4, 0xa5, 0x54, 0xd3, 0xeb, 0x29, 0x48, 0x5a, 0x0e, 0x1d, 0x50, 0x31, 0x18, 0xd1,
            0xa8, 0x2d, 0x99, 0xfb, 0x4a,
        ];
        let alice_signature: [u8; SIGNATURE_LENGTH] = [
            0x5d, 0xe8, 0x8c, 0xa9, 0xa8, 0x9b, 0x4a, 0x11, 0x5d, 0xa7, 0x91, 0x09, 0xc6, 0x7c,
            0x9c, 0x74, 0x64, 0xa3, 0xe4, 0x18, 0x02, 0x74, 0xf1, 0xcb, 0x8c, 0x63, 0xc2, 0x98,
            0x4e, 0x28, 0x6d, 0xfb, 0xed, 0xe8, 0x2d, 0xeb, 0x9d, 0xcd, 0x9f, 0xae, 0x0b, 0xfb,
            0xb8, 0x21, 0x56, 0x9b, 0x3d, 0x90, 0x01, 0xbd, 0x81, 0x30, 0xcd, 0x11, 0xd4, 0x86,
            0xce, 0xf0, 0x47, 0xbd, 0x60, 0xb8, 0x6e, 0x88,
        ];

        let alice_identity_key_pair = KeyPair::from(alice_identity_private);

        assert_eq!(alice_identity_public, *alice_identity_key_pair.public_key());

        assert!(
            KeyPair::verify_signature(
                &alice_identity_public,
                &alice_ephemeral_public,
                &alice_signature
            ),
            "signature check failed"
        );

        for i in 0..alice_signature.len() {
            let mut alice_signature_copy: [u8; SIGNATURE_LENGTH] = [0; SIGNATURE_LENGTH];
            alice_signature_copy.copy_from_slice(&alice_signature);
            alice_signature_copy[i] ^= 0x01u8;

            assert!(
                !KeyPair::verify_signature(
                    &alice_identity_public,
                    &alice_ephemeral_public,
                    &alice_signature_copy
                ),
                "signature check passed when it should not have"
            );
        }
    }

    #[test]
    fn test_random_signatures() {
        let mut csprng = OsRng;
        for _ in 0..50 {
            let mut message = [0u8; 64];
            csprng.fill_bytes(&mut message);
            let key_pair = KeyPair::new(&mut csprng);
            let signature = key_pair.calculate_signature(&mut csprng, &message);
            assert!(
                KeyPair::verify_signature(key_pair.public_key(), &message, &signature),
                "signature check failed"
            );
        }
    }
}
