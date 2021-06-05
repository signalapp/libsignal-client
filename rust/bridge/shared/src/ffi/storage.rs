//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use super::*;
use async_trait::async_trait;
use libc::{c_int, c_uint, c_void};
use uuid::Uuid;

type GetIdentityKeyPair =
    extern "C" fn(store_ctx: *mut c_void, keyp: *mut *mut PrivateKey, ctx: *mut c_void) -> c_int;
type GetLocalRegistrationId =
    extern "C" fn(store_ctx: *mut c_void, idp: *mut u32, ctx: *mut c_void) -> c_int;
type GetIdentityKey = extern "C" fn(
    store_ctx: *mut c_void,
    public_keyp: *mut *mut PublicKey,
    address: *const ProtocolAddress,
    ctx: *mut c_void,
) -> c_int;
type SaveIdentityKey = extern "C" fn(
    store_ctx: *mut c_void,
    address: *const ProtocolAddress,
    public_key: *const PublicKey,
    ctx: *mut c_void,
) -> c_int;
type IsTrustedIdentity = extern "C" fn(
    store_ctx: *mut c_void,
    address: *const ProtocolAddress,
    public_key: *const PublicKey,
    direction: c_uint,
    ctx: *mut c_void,
) -> c_int;

#[derive(Debug)]
#[repr(C)]
pub enum FfiDirection {
    Sending = 0,
    Receiving = 1,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiIdentityKeyStoreStruct {
    ctx: *mut c_void,
    get_identity_key_pair: GetIdentityKeyPair,
    get_local_registration_id: GetLocalRegistrationId,
    save_identity: SaveIdentityKey,
    get_identity: GetIdentityKey,
    is_trusted_identity: IsTrustedIdentity,
}

#[async_trait(?Send)]
impl IdentityKeyStore for &FfiIdentityKeyStoreStruct {
    async fn get_identity_key_pair(
        &self,
        ctx: Context,
    ) -> Result<IdentityKeyPair, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let mut key = std::ptr::null_mut();
        let result = (self.get_identity_key_pair)(self.ctx, &mut key, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "get_identity_key_pair",
                Box::new(error),
            ));
        }

        if key.is_null() {
            return Err(SignalProtocolError::InternalError("No identity key pair"));
        }

        let priv_key = unsafe { Box::from_raw(key) };
        let pub_key = priv_key.public_key();

        Ok(IdentityKeyPair::new(IdentityKey::new(pub_key), *priv_key))
    }

    async fn get_local_registration_id(&self, ctx: Context) -> Result<u32, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let mut id = 0;
        let result = (self.get_local_registration_id)(self.ctx, &mut id, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "get_local_registration_id",
                Box::new(error),
            ));
        }

        Ok(id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let result = (self.save_identity)(self.ctx, &*address, &*identity.public_key(), ctx);

        match result {
            0 => Ok(false),
            1 => Ok(true),
            r => Err(SignalProtocolError::ApplicationCallbackError(
                "save_identity",
                Box::new(CallbackError::check(r).expect("verified non-zero")),
            )),
        }
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
        ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let direction = match direction {
            Direction::Sending => FfiDirection::Sending,
            Direction::Receiving => FfiDirection::Receiving,
        };
        let result = (self.is_trusted_identity)(
            self.ctx,
            &*address,
            &*identity.public_key(),
            direction as u32,
            ctx,
        );

        match result {
            0 => Ok(false),
            1 => Ok(true),
            r => Err(SignalProtocolError::ApplicationCallbackError(
                "is_trusted_identity",
                Box::new(CallbackError::check(r).expect("verified non-zero")),
            )),
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        ctx: Context,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let mut key = std::ptr::null_mut();
        let result = (self.get_identity)(self.ctx, &mut key, &*address, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "get_identity",
                Box::new(error),
            ));
        }

        if key.is_null() {
            return Ok(None);
        }

        let pk = unsafe { Box::from_raw(key) };

        Ok(Some(IdentityKey::new(*pk)))
    }
}

type LoadPreKey = extern "C" fn(
    store_ctx: *mut c_void,
    recordp: *mut *mut PreKeyRecord,
    id: u32,
    ctx: *mut c_void,
) -> c_int;
type StorePreKey = extern "C" fn(
    store_ctx: *mut c_void,
    id: u32,
    record: *const PreKeyRecord,
    ctx: *mut c_void,
) -> c_int;
type RemovePreKey = extern "C" fn(store_ctx: *mut c_void, id: u32, ctx: *mut c_void) -> c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiPreKeyStoreStruct {
    ctx: *mut c_void,
    load_pre_key: LoadPreKey,
    store_pre_key: StorePreKey,
    remove_pre_key: RemovePreKey,
}

#[async_trait(?Send)]
impl PreKeyStore for &FfiPreKeyStoreStruct {
    async fn get_pre_key(
        &self,
        prekey_id: u32,
        ctx: Context,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let mut record = std::ptr::null_mut();
        let result = (self.load_pre_key)(self.ctx, &mut record, prekey_id, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "load_pre_key",
                Box::new(error),
            ));
        }

        if record.is_null() {
            return Err(SignalProtocolError::InvalidPreKeyId);
        }

        let record = unsafe { Box::from_raw(record) };
        Ok(*record)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: u32,
        record: &PreKeyRecord,
        ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let result = (self.store_pre_key)(self.ctx, prekey_id, &*record, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "store_pre_key",
                Box::new(error),
            ));
        }

        Ok(())
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: u32,
        ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let result = (self.remove_pre_key)(self.ctx, prekey_id, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "remove_pre_key",
                Box::new(error),
            ));
        }

        Ok(())
    }
}

type LoadSignedPreKey = extern "C" fn(
    store_ctx: *mut c_void,
    recordp: *mut *mut SignedPreKeyRecord,
    id: u32,
    ctx: *mut c_void,
) -> c_int;
type StoreSignedPreKey = extern "C" fn(
    store_ctx: *mut c_void,
    id: u32,
    record: *const SignedPreKeyRecord,
    ctx: *mut c_void,
) -> c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiSignedPreKeyStoreStruct {
    ctx: *mut c_void,
    load_signed_pre_key: LoadSignedPreKey,
    store_signed_pre_key: StoreSignedPreKey,
}

#[async_trait(?Send)]
impl SignedPreKeyStore for &FfiSignedPreKeyStoreStruct {
    async fn get_signed_pre_key(
        &self,
        prekey_id: u32,
        ctx: Context,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let mut record = std::ptr::null_mut();
        let result = (self.load_signed_pre_key)(self.ctx, &mut record, prekey_id, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "load_signed_pre_key",
                Box::new(error),
            ));
        }

        if record.is_null() {
            return Err(SignalProtocolError::InvalidSignedPreKeyId);
        }

        let record = unsafe { Box::from_raw(record) };

        Ok(*record)
    }

    async fn save_signed_pre_key(
        &mut self,
        prekey_id: u32,
        record: &SignedPreKeyRecord,
        ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let result = (self.store_signed_pre_key)(self.ctx, prekey_id, &*record, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "store_signed_pre_key",
                Box::new(error),
            ));
        }

        Ok(())
    }
}

type LoadSession = extern "C" fn(
    store_ctx: *mut c_void,
    recordp: *mut *mut SessionRecord,
    address: *const ProtocolAddress,
    ctx: *mut c_void,
) -> c_int;
type StoreSession = extern "C" fn(
    store_ctx: *mut c_void,
    address: *const ProtocolAddress,
    record: *const SessionRecord,
    ctx: *mut c_void,
) -> c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiSessionStoreStruct {
    ctx: *mut c_void,
    load_session: LoadSession,
    store_session: StoreSession,
}

#[async_trait(?Send)]
impl SessionStore for &FfiSessionStoreStruct {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        ctx: Context,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let mut record = std::ptr::null_mut();
        let result = (self.load_session)(self.ctx, &mut record, &*address, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "load_session",
                Box::new(error),
            ));
        }

        if record.is_null() {
            return Ok(None);
        }

        let record = unsafe { Box::from_raw(record) };

        Ok(Some(*record))
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let result = (self.store_session)(self.ctx, &*address, &*record, ctx);

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "store_session",
                Box::new(error),
            ));
        }

        Ok(())
    }
}

type LoadSenderKey = extern "C" fn(
    store_ctx: *mut c_void,
    *mut *mut SenderKeyRecord,
    *const ProtocolAddress,
    distribution_id: *const [u8; 16],
    ctx: *mut c_void,
) -> c_int;
type StoreSenderKey = extern "C" fn(
    store_ctx: *mut c_void,
    *const ProtocolAddress,
    distribution_id: *const [u8; 16],
    *const SenderKeyRecord,
    ctx: *mut c_void,
) -> c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiSenderKeyStoreStruct {
    ctx: *mut c_void,
    load_sender_key: LoadSenderKey,
    store_sender_key: StoreSenderKey,
}

#[async_trait(?Send)]
impl SenderKeyStore for &FfiSenderKeyStoreStruct {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
        ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let result = (self.store_sender_key)(
            self.ctx,
            &*sender,
            distribution_id.as_bytes(),
            &*record,
            ctx,
        );

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "store_sender_key",
                Box::new(error),
            ));
        }

        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        ctx: Context,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        let ctx = ctx.unwrap_or(std::ptr::null_mut());
        let mut record = std::ptr::null_mut();
        let result = (self.load_sender_key)(
            self.ctx,
            &mut record,
            &*sender,
            distribution_id.as_bytes(),
            ctx,
        );

        if let Some(error) = CallbackError::check(result) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "load_sender_key",
                Box::new(error),
            ));
        }

        if record.is_null() {
            return Ok(None);
        }

        let record = unsafe { Box::from_raw(record) };

        Ok(Some(*record))
    }
}
