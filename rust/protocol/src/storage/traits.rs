//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use uuid::Uuid;

use crate::state::{PreKeyId, SignedPreKeyId};
use crate::{
    IdentityKey, IdentityKeyPair, PreKeyRecord, ProtocolAddress, Result, SenderKeyRecord,
    SessionRecord, SignedPreKeyRecord,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Direction {
    Sending,
    Receiving,
}

#[cfg_attr(feature = "ffi", async_trait(?Send))]
#[cfg_attr(not(feature = "ffi"), async_trait)]
pub trait IdentityKeyStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair>;

    async fn get_local_registration_id(&self) -> Result<u32>;

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool>;

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool>;

    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>>;
}

#[cfg_attr(feature = "ffi", async_trait(?Send))]
#[cfg_attr(not(feature = "ffi"), async_trait)]
pub trait PreKeyStore {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord>;

    async fn save_pre_key(&mut self, prekey_id: PreKeyId, record: &PreKeyRecord) -> Result<()>;

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<()>;
}

#[cfg_attr(feature = "ffi", async_trait(?Send))]
#[cfg_attr(not(feature = "ffi"), async_trait)]
pub trait SignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord>;

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()>;
}

#[cfg_attr(feature = "ffi", async_trait(?Send))]
#[cfg_attr(not(feature = "ffi"), async_trait)]
pub trait SessionStore {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>>;

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<()>;
}

#[cfg_attr(feature = "ffi", async_trait(?Send))]
#[cfg_attr(not(feature = "ffi"), async_trait)]
pub trait SenderKeyStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<()>;

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>>;
}

pub trait ProtocolStore: SessionStore + PreKeyStore + SignedPreKeyStore + IdentityKeyStore {}
