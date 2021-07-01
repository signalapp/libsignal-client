//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(all(target_arch = "aarch64", feature = "nightly"))]
mod aarch64;

use crate::error::{Error, Result};

use cipher::block::{BlockCipher, NewBlockCipher};
use generic_array::typenum::Unsigned;
use generic_array::GenericArray;

#[derive(Clone)]
pub enum Aes256 {
    Soft(aes_soft::Aes256),
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    AesNi(aesni::Aes256),
    #[cfg(all(target_arch = "aarch64", feature = "nightly"))]
    Aarch64(aarch64::Aes256Aarch64),
}

impl Aes256 {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(Error::InvalidKeySize);
        }

        #[cfg(all(target_arch = "aarch64", feature = "nightly"))]
        {
            if crate::cpuid::has_armv8_crypto() {
                unsafe {
                    return Ok(Aes256::Aarch64(aarch64::Aes256Aarch64::new(key)?));
                }
            }
        }

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if crate::cpuid::has_intel_aesni() {
                return Ok(Aes256::AesNi(aesni::Aes256::new(key.into())));
            }
        }

        Ok(Aes256::Soft(aes_soft::Aes256::new(key.into())))
    }

    pub fn encrypt(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() % 16 != 0 {
            return Err(Error::InvalidInputSize);
        }

        fn trait_encrypt<C: BlockCipher>(aes: &C, buf: &mut [u8]) -> Result<()> {
            type BlockSize<C> = <C as BlockCipher>::BlockSize;
            type ParBlocks<C> = <C as BlockCipher>::ParBlocks;
            let pb = ParBlocks::<C>::to_usize();

            let unroll_to = pb * 16;

            for blocks in buf.chunks_mut(unroll_to) {
                if blocks.len() == unroll_to {
                    let mut pbuf: GenericArray<GenericArray<u8, BlockSize<C>>, ParBlocks<C>> =
                        Default::default();
                    for j in 0..pb {
                        pbuf[j]
                            .as_mut_slice()
                            .copy_from_slice(&blocks[16 * j..16 * (j + 1)]);
                    }
                    aes.encrypt_blocks(&mut pbuf);
                    for j in 0..pb {
                        blocks[16 * j..16 * (j + 1)].copy_from_slice(pbuf[j].as_slice());
                    }
                } else {
                    for block in blocks.chunks_mut(16) {
                        aes.encrypt_block(GenericArray::from_mut_slice(block));
                    }
                }
            }

            Ok(())
        }

        match self {
            Aes256::Soft(aes) => trait_encrypt(aes, buf),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Aes256::AesNi(aes) => trait_encrypt(aes, buf),
            #[cfg(all(target_arch = "aarch64", feature = "nightly"))]
            Aes256::Aarch64(aes) => unsafe { aes.encrypt(buf) },
        }
    }
}

#[test]
fn aes_kat() -> Result<()> {
    let key = hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
        .expect("valid hex");
    let pt = hex::decode("00000000000000000000000000000010000000000000000000000000000000080000000000000000000000000000000400000000000000000000000000000002000000000000000000000000000000010000000000000000000000000000001000000000000000000000000000000008000000000000000000000000000000040000000000000000000000000000000200000000000000000000000000000001").expect("valid hex");
    let ct = hex::decode("1490A05A7CEE43BDE98B56E309DC0126ABFA77CD6E85DA245FB0BDC5E52CFC29DD4AB1284D4AE17B41E85924470C36F7CEA7403D4D606B6E074EC5D3BAF39D18530F8AFBC74536B9A963B4F1C4CB738B1490A05A7CEE43BDE98B56E309DC0126ABFA77CD6E85DA245FB0BDC5E52CFC29DD4AB1284D4AE17B41E85924470C36F7CEA7403D4D606B6E074EC5D3BAF39D18530F8AFBC74536B9A963B4F1C4CB738B").expect("valid hex");

    let aes = Aes256::new(&key)?;

    let mut buf = pt;
    aes.encrypt(&mut buf)?;
    assert_eq!(hex::encode(buf), hex::encode(ct));

    Ok(())
}
