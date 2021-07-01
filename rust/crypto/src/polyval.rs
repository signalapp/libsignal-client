//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::{Error, Result};

mod polyval_soft;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod polyval_clmul;

#[cfg(all(target_arch = "aarch64", feature = "nightly"))]
mod polyval_pmul;

#[derive(Clone)]
pub enum Polyval {
    Soft(polyval_soft::PolyvalSoft),
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Clmul(polyval_clmul::PolyvalClmul),
    #[cfg(all(target_arch = "aarch64", feature = "nightly"))]
    Pmul(polyval_pmul::PolyvalPmul),
}

impl Polyval {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 {
            return Err(Error::InvalidKeySize);
        }

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if crate::cpuid::has_intel_aesni() {
                return Ok(Polyval::Clmul(polyval_clmul::PolyvalClmul::new(key)?));
            }
        }

        #[cfg(all(target_arch = "aarch64", feature = "nightly"))]
        {
            if crate::cpuid::has_armv8_crypto() {
                return Ok(Polyval::Pmul(polyval_pmul::PolyvalPmul::new(key)?));
            }
        }

        Ok(Polyval::Soft(polyval_soft::PolyvalSoft::new(key)?))
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        if data.len() % 16 != 0 {
            return Err(Error::InvalidInputSize);
        }

        match self {
            Polyval::Soft(polyval) => polyval.update(data),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Polyval::Clmul(polyval) => polyval.update(data),
            #[cfg(all(target_arch = "aarch64", feature = "nightly"))]
            Polyval::Pmul(polyval) => polyval.update(data),
        }
    }

    pub fn update_padded(&mut self, data: &[u8]) -> Result<()> {
        match self {
            Polyval::Soft(polyval) => polyval.update_padded(data),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Polyval::Clmul(polyval) => polyval.update_padded(data),
            #[cfg(all(target_arch = "aarch64", feature = "nightly"))]
            Polyval::Pmul(polyval) => polyval.update_padded(data),
        }
    }

    pub fn finalize(self) -> Result<[u8; 16]> {
        match self {
            Polyval::Soft(polyval) => polyval.finalize(),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Polyval::Clmul(polyval) => polyval.finalize(),
            #[cfg(all(target_arch = "aarch64", feature = "nightly"))]
            Polyval::Pmul(polyval) => polyval.finalize(),
        }
    }

    // See RFC 8452 Appendix A
    pub fn mulx(block: &[u8; 16]) -> [u8; 16] {
        let mut v = u128::from_le_bytes(*block);
        let carry = v >> 127;

        v <<= 1;
        v ^= carry ^ (carry << 127) ^ (carry << 126) ^ (carry << 121);
        v.to_le_bytes()
    }
}

#[test]
fn polyval_kat() -> Result<()> {
    let h = hex::decode("25629347589242761d31f826ba4b757b").expect("valid hex");
    let input1 = hex::decode("4f4f95668c83dfb6401762bb2d01a262").expect("valid hex");
    let input2 = hex::decode("d1a24ddd2721d006bbe45f20d3c9f362").expect("valid hex");
    let mut poly = Polyval::new(&h)?;
    poly.update(&input1)?;
    poly.update(&input2)?;

    let result = poly.finalize()?;

    assert_eq!(hex::encode(&result), "f7a3b47b846119fae5b7866cf5e5b77e");

    Ok(())
}
