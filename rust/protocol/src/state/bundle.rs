//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::state::{PreKeyId, SignedPreKeyId};
use crate::{DeviceId, IdentityKey, PublicKey, RegistrationId, Result};

#[derive(Debug, Clone)]
pub struct PreKeyBundle {
    registration_id: RegistrationId,
    device_id: DeviceId,
    pre_key_id: Option<PreKeyId>,
    pre_key_public: Option<PublicKey>,
    signed_pre_key_id: SignedPreKeyId,
    signed_pre_key_public: PublicKey,
    // TODO: make wrappers for byte strings!
    signed_pre_key_signature: Vec<u8>,
    identity_key: IdentityKey,
}

impl PreKeyBundle {
    pub fn new(
        registration_id: RegistrationId,
        device_id: DeviceId,
        pre_key: Option<(PreKeyId, PublicKey)>,
        signed_pre_key_id: SignedPreKeyId,
        signed_pre_key_public: PublicKey,
        signed_pre_key_signature: Vec<u8>,
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

    pub fn registration_id(&self) -> Result<RegistrationId> {
        Ok(self.registration_id)
    }

    pub fn device_id(&self) -> Result<DeviceId> {
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

    pub fn signed_pre_key_signature(&self) -> Result<&[u8]> {
        Ok(self.signed_pre_key_signature.as_ref())
    }

    pub fn identity_key(&self) -> Result<&IdentityKey> {
        Ok(&self.identity_key)
    }
}
