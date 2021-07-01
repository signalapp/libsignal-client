//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![cfg_attr(all(target_arch = "aarch64", feature = "nightly"), feature(stdsimd))]
#![cfg_attr(
    all(target_arch = "aarch64", feature = "nightly"),
    feature(aarch64_target_feature)
)]
#![deny(clippy::unwrap_used)]

mod error;
mod hash;

mod aes;
mod aes_ctr;
mod aes_gcm;
mod aes_gcm_siv;
mod cpuid;
mod ghash;
mod polyval;

pub use {
    aes_ctr::Aes256Ctr32,
    aes_gcm::{Aes256GcmDecryption, Aes256GcmEncryption},
    aes_gcm_siv::Aes256GcmSiv,
    error::{Error, Result},
    hash::{CryptographicHash, CryptographicMac},
};
