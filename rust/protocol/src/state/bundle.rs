//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::curve::curve25519::SIGNATURE_LENGTH;
use crate::state::{PreKeyId, SignedPreKeyId};
use crate::{IdentityKey, PublicKey, Result};

#[derive(Debug, Clone)]
pub struct PreKeyBundle {
    registration_id: u32,
    device_id: u32,
    pre_key_id: Option<PreKeyId>,
    pre_key_public: Option<PublicKey>,
    signed_pre_key_id: SignedPreKeyId,
    signed_pre_key_public: PublicKey,
    signed_pre_key_signature: [u8; SIGNATURE_LENGTH],
    identity_key: IdentityKey,
}

impl PreKeyBundle {
    pub fn new(
        registration_id: u32,
        device_id: u32,
        pre_key: Option<(PreKeyId, PublicKey)>,
        signed_pre_key_id: SignedPreKeyId,
        signed_pre_key_public: PublicKey,
        signed_pre_key_signature: [u8; SIGNATURE_LENGTH],
        identity_key: IdentityKey,
    ) -> Result<Self> {
        let (pre_key_id, pre_key_public) = match pre_key {
            None => (None, None),
            Some((id, key)) => (Some(id), Some(key)),
        };

        Ok(Self {
            registration_id,
            device_id,
            pre_key_id,
            pre_key_public,
            signed_pre_key_id,
            signed_pre_key_public,
            signed_pre_key_signature,
            identity_key,
        })
    }

    pub fn registration_id(&self) -> Result<u32> {
        Ok(self.registration_id)
    }

    pub fn device_id(&self) -> Result<u32> {
        Ok(self.device_id)
    }

    pub fn pre_key_id(&self) -> Result<Option<PreKeyId>> {
        Ok(self.pre_key_id)
    }

    pub fn pre_key_public(&self) -> Result<Option<PublicKey>> {
        Ok(self.pre_key_public)
    }

    pub fn signed_pre_key_id(&self) -> Result<SignedPreKeyId> {
        Ok(self.signed_pre_key_id)
    }

    pub fn signed_pre_key_public(&self) -> Result<PublicKey> {
        Ok(self.signed_pre_key_public)
    }

    pub fn signed_pre_key_signature(&self) -> Result<&[u8; SIGNATURE_LENGTH]> {
        Ok(&self.signed_pre_key_signature)
    }

    pub fn identity_key(&self) -> Result<&IdentityKey> {
        Ok(&self.identity_key)
    }
}
