//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::aes::Aes256;
use crate::error::{Error, Result};
use crate::polyval::Polyval;
use std::convert::TryInto;

use subtle::ConstantTimeEq;

pub const AAD_MAX: u64 = 1 << 36;
pub const PTEXT_MAX: u64 = 1 << 36;
pub const AES_BLOCK_SIZE: usize = 16;
pub const AES_KEY_SIZE: usize = 32;
pub const POLYVAL_KEY_SIZE: usize = 16;

pub struct Aes256GcmSiv {
    key_generator: Aes256,
}

impl Aes256GcmSiv {
    pub const GCM_SIV_TAG_SIZE: usize = 16;
    pub const GCM_SIV_NONCE_SIZE: usize = 12;

    const TAG_SIZE: usize = Self::GCM_SIV_TAG_SIZE;
    const NONCE_SIZE: usize = Self::GCM_SIV_NONCE_SIZE;

    pub fn new(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key_generator: Aes256::new(key)?,
        })
    }

    fn derive_keys(&self, nonce: &[u8]) -> Result<([u8; AES_KEY_SIZE], [u8; POLYVAL_KEY_SIZE])> {
        if nonce.len() != Self::NONCE_SIZE {
            return Err(Error::InvalidNonceSize);
        }

        /*
        Actually only 6 blocks are needed here, but use a pad of 8 blocks.

        The RustCrypto block cipher crates can only take advantage of parallelism in
        multiples of 8 blocks due to a deficiency in the API. So go ahead and use 8
        blocks, just throwing 2 away. This improves overall performance by almost 30% for
        small messages when using the bitsliced AES (software only fallback).
        */
        const BLOCKS_NEEDED: usize = 6;
        const BLOCKS_USED: usize = 8;

        let mut pad = [0u8; AES_BLOCK_SIZE * BLOCKS_USED];

        // prepare the input blocks
        for i in 0..BLOCKS_NEEDED {
            pad[(i * 16)..(i * 16 + 4)].copy_from_slice(&(i as u32).to_le_bytes());
            pad[(i * 16 + 4)..(i * 16 + 16)].copy_from_slice(nonce);
        }

        self.key_generator.encrypt(&mut pad)?;

        let mut polyval_key = [0u8; POLYVAL_KEY_SIZE];
        let mut aes_key = [0u8; AES_KEY_SIZE];

        for i in 0..2 {
            polyval_key[(8 * i)..(8 * i + 8)].copy_from_slice(&pad[16 * i..16 * i + 8]);
        }
        for i in 0..4 {
            aes_key[(8 * i)..(8 * i + 8)].copy_from_slice(&pad[32 + 16 * i..32 + 16 * i + 8]);
        }

        Ok((aes_key, polyval_key))
    }

    fn compute_tag(
        buffer: &[u8],
        associated_data: &[u8],
        nonce: &[u8],
        polyval_key: &[u8],
        aes256: &Aes256,
    ) -> Result<[u8; 16]> {
        let associated_data_bits = (associated_data.len() as u64) * 8;
        let buffer_bits = (buffer.len() as u64) * 8;

        let mut length_block = [0u8; 16];
        length_block[..8].copy_from_slice(&associated_data_bits.to_le_bytes());
        length_block[8..].copy_from_slice(&buffer_bits.to_le_bytes());

        let mut polyval = Polyval::new(polyval_key)?;

        polyval.update_padded(associated_data)?;
        polyval.update_padded(buffer)?;
        polyval.update(&length_block)?;

        let mut tag = polyval.finalize()?;

        for i in 0..12 {
            tag[i] ^= nonce[i];
        }

        tag[15] &= 0x7f;

        aes256.encrypt(&mut tag)?;
        Ok(tag)
    }

    fn ctr32(buffer: &mut [u8], nonce: &[u8], aes256: &Aes256) -> Result<()> {
        /*
        aes-soft uses 8x bitslicing
        aesni uses 8x pipelining
        aarch64 uses 4x pipelining
        */
        const PAR_BLOCKS: usize = 8;
        const PAD_SIZE: usize = PAR_BLOCKS * AES_BLOCK_SIZE;

        let mut ctr = [0u8; PAD_SIZE];
        let mut pad = [0u8; PAD_SIZE];
        let mut counter = u32::from_le_bytes(nonce[..4].try_into().expect("Correct size"));

        let pads_required = (buffer.len() + PAD_SIZE) / PAD_SIZE;

        for i in 0..pads_required {
            for b in 0..PAR_BLOCKS {
                ctr[AES_BLOCK_SIZE * b..AES_BLOCK_SIZE * b + 4]
                    .copy_from_slice(&counter.to_le_bytes());
                ctr[AES_BLOCK_SIZE * b + 4..AES_BLOCK_SIZE * (b + 1)].copy_from_slice(&nonce[4..]);
                ctr[AES_BLOCK_SIZE * b + 15] |= 0x80;
                counter = counter.wrapping_add(1);
            }

            pad.copy_from_slice(&ctr);
            aes256.encrypt(&mut pad[..])?;

            let to_xor = std::cmp::min(PAD_SIZE, buffer.len() - i * PAD_SIZE);
            for j in 0..to_xor {
                buffer[i * PAD_SIZE + j] ^= pad[j];
            }
        }

        Ok(())
    }

    pub fn encrypt(
        &self,
        buffer: &mut [u8],
        nonce: &[u8],
        associated_data: &[u8],
    ) -> Result<[u8; Self::TAG_SIZE]> {
        if buffer.len() as u64 > PTEXT_MAX || associated_data.len() as u64 > AAD_MAX {
            return Err(Error::InvalidInputSize);
        }

        let keys = self.derive_keys(nonce)?;
        let aes256 = Aes256::new(&keys.0)?;
        let tag = Self::compute_tag(buffer, associated_data, nonce, &keys.1, &aes256)?;
        Self::ctr32(buffer, &tag, &aes256)?;
        Ok(tag)
    }

    pub fn decrypt(
        &self,
        buffer: &mut [u8],
        nonce: &[u8],
        associated_data: &[u8],
        tag: &[u8],
    ) -> Result<()> {
        if nonce.len() != Self::NONCE_SIZE {
            return Err(Error::InvalidNonceSize);
        }
        if tag.len() != Self::TAG_SIZE {
            return Err(Error::InvalidTag);
        }
        if buffer.len() as u64 > PTEXT_MAX || associated_data.len() as u64 > AAD_MAX {
            return Err(Error::InvalidInputSize);
        }
        let keys = self.derive_keys(nonce)?;
        let aes256 = Aes256::new(&keys.0)?;
        Self::ctr32(buffer, &tag, &aes256)?;
        let gtag = Self::compute_tag(buffer, associated_data, nonce, &keys.1, &aes256)?;

        let tag_ok = tag.ct_eq(&gtag);

        if tag_ok.unwrap_u8() == 0 {
            // Zero out the buffer before returning
            for i in buffer.iter_mut() {
                *i = 0;
            }
            return Err(Error::InvalidTag);
        }
        Ok(())
    }

    pub fn decrypt_with_appended_tag(
        &self,
        buffer: &mut Vec<u8>,
        nonce: &[u8],
        associated_data: &[u8],
    ) -> Result<()> {
        if buffer.len() < Self::TAG_SIZE {
            return Err(Error::InvalidInputSize);
        }

        let tag = buffer.split_off(buffer.len() - Self::TAG_SIZE);
        self.decrypt(buffer, nonce, associated_data, &tag)
    }
}
