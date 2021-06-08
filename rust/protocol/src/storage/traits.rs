//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Traits defining several stores used throughout the Signal Protocol.

use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    address::ProtocolAddress,
    error::Result,
    sender_keys::SenderKeyRecord,
    state::{PreKeyId, PreKeyRecord, SessionRecord, SignedPreKeyId, SignedPreKeyRecord},
    IdentityKey, IdentityKeyPair,
};

/// Handle to FFI-provided context object.
///
/// This object is not manipulated in Rust, but is instead passed back to each FFI
/// method invocation. This argument should just be [None] for all clients of the Rust-only API.
pub type Context = Option<*mut std::ffi::c_void>;

/// Each Signal message can be considered to have exactly two participants, a sender and receiver.
///
/// [IdentityKeyStore::is_trusted_identity] uses this to ensure the identity provided is configured
/// for the appropriate role.
///
/// *TODO: consider moving this enum into [crate::protocol]?*
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Direction {
    /// We are in the context of sending a message.
    Sending,
    /// We are in the context of receiving a message.
    Receiving,
}

/// Interface defining the identity store, which may be in-memory, on-disk, etc.
///
/// Signal clients usually use the identity store in a [TOFU] manner, but this is not required.
///
/// [TOFU]: https://en.wikipedia.org/wiki/Trust_on_first_use
#[async_trait(?Send)]
pub trait IdentityKeyStore {
    /// Return the single specific identity the store is assumed to represent, with private key.
    async fn get_identity_key_pair(&self, ctx: Context) -> Result<IdentityKeyPair>;

    /// Return a [u32] specific to this store instance.
    ///
    /// This local registration id is separate from the per-device identifier used in
    /// [ProtocolAddress] and should not change run over run.
    ///
    /// If the same *device* is unregistered, then registers again, the [ProtocolAddress::device_id]
    /// will be the same, but the store registration id returned by this method will be regenerated.
    async fn get_local_registration_id(&self, ctx: Context) -> Result<u32>;

    /// Record an identity into the store. The identity is then considered "trusted".
    ///
    /// The return value represents whether an existing identity was replaced (`Ok(true)`). If it is
    /// new or hasn't changed, the return value is `Ok(false)`.
    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        ctx: Context,
    ) -> Result<bool>;

    /// Return whether an identity is trusted for the role specified by `direction`.
    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
        ctx: Context,
    ) -> Result<bool>;

    /// Return the public identity for the given `address`, if known.
    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        ctx: Context,
    ) -> Result<Option<IdentityKey>>;
}

/// Interface for storing pre-keys downloaded from a server.
#[async_trait(?Send)]
pub trait PreKeyStore {
    /// Look up the pre-key corresponding to `prekey_id`.
    async fn get_pre_key(&self, prekey_id: PreKeyId, ctx: Context) -> Result<PreKeyRecord>;

    /// Set the entry for `prekey_id` to the value of `record`.
    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
        ctx: Context,
    ) -> Result<()>;

    /// Remove the entry for `prekey_id`.
    async fn remove_pre_key(&mut self, prekey_id: PreKeyId, ctx: Context) -> Result<()>;
}

/// Interface for storing signed pre-keys downloaded from a server.
#[async_trait(?Send)]
pub trait SignedPreKeyStore {
    /// Look up the signed pre-key corresponding to `signed_prekey_id`.
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
        ctx: Context,
    ) -> Result<SignedPreKeyRecord>;

    /// Set the entry for `signed_prekey_id` to the value of `record`.
    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
        ctx: Context,
    ) -> Result<()>;
}

/// Interface for a Signal client instance to store a session associated with another particular
/// separate Signal client instance.
///
/// This [SessionRecord] object between a pair of Signal clients is used to drive the state for the
/// forward-secret message chain in the [Double Ratchet] protocol.
///
/// [Double Ratchet]: https://signal.org/docs/specifications/doubleratchet/
#[async_trait(?Send)]
pub trait SessionStore {
    /// Look up the session corresponding to `address`.
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        ctx: Context,
    ) -> Result<Option<SessionRecord>>;

    /// Set the entry for `address` to the value of `record`.
    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        ctx: Context,
    ) -> Result<()>;
}

/// Interface for storing sender key records for other users, allowing multiple keys per user.
#[async_trait(?Send)]
pub trait SenderKeyStore {
    /// Set the entry for `(sender, distribution_id)` to the value of `record`.
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
        ctx: Context,
    ) -> Result<()>;

    /// Look up the entry corresponding to `(sender, distribution_id)`.
    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        ctx: Context,
    ) -> Result<Option<SenderKeyRecord>>;
}

/// Mixes in all the store interfaces defined in this module.
pub trait ProtocolStore: SessionStore + PreKeyStore + SignedPreKeyStore + IdentityKeyStore {}
