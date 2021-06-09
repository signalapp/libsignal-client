//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::aes::Aes256;
use crate::error::{Error, Result};
use std::convert::TryInto;

const AES_BLOCK_SIZE: usize = 16;
const PAR_BLOCKS: usize = 8;
const PAD_SIZE: usize = PAR_BLOCKS * AES_BLOCK_SIZE;

#[derive(Clone)]
pub struct Aes256Ctr32 {
    aes256: Aes256,
    ctr: [u8; PAD_SIZE],
    pad: [u8; PAD_SIZE],
    pad_offset: usize,
}

fn update_ctr(ctr: &mut [u8; PAD_SIZE], init_ctr: u32) {
    let mut counter = init_ctr;
    for b in 0..PAR_BLOCKS {
        ctr[AES_BLOCK_SIZE * b + 12..AES_BLOCK_SIZE * (b + 1)]
            .copy_from_slice(&counter.to_be_bytes());
        counter = counter.wrapping_add(1);
    }
}

impl Aes256Ctr32 {
    pub const CTR_NONCE_SIZE: usize = AES_BLOCK_SIZE - 4;

    const NONCE_SIZE: usize = Self::CTR_NONCE_SIZE;

    pub fn new(aes256: Aes256, nonce: &[u8], init_ctr: u32) -> Result<Self> {
        if nonce.len() != Self::NONCE_SIZE {
            return Err(Error::InvalidNonceSize);
        }

        let mut ctr = [0u8; PAD_SIZE];
        for b in 0..PAR_BLOCKS {
            ctr[AES_BLOCK_SIZE * b..AES_BLOCK_SIZE * b + 12].copy_from_slice(nonce);
        }

        update_ctr(&mut ctr, init_ctr);

        let mut pad = ctr;
        aes256.encrypt(&mut pad[..])?;

        Ok(Self {
            aes256,
            ctr,
            pad,
            pad_offset: 0,
        })
    }

    pub fn from_key(key: &[u8], nonce: &[u8], init_ctr: u32) -> Result<Self> {
        Self::new(Aes256::new(key)?, nonce, init_ctr)
    }

    pub fn process(&mut self, buf: &mut [u8]) -> Result<()> {
        for b in buf.iter_mut() {
            if self.pad_offset == PAD_SIZE {
                let mut counter =
                    u32::from_be_bytes(self.ctr[PAD_SIZE - 4..].try_into().expect("Correct size"));
                counter = counter.wrapping_add(1); // increment from last counter

                update_ctr(&mut self.ctr, counter);

                self.pad.copy_from_slice(&self.ctr);
                self.aes256.encrypt(&mut self.pad[..])?;
                self.pad_offset = 0;
            }

            *b ^= self.pad[self.pad_offset];
            self.pad_offset += 1;
        }

        Ok(())
    }
}
