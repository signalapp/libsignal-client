//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use super::*;

use async_trait::async_trait;
use signal_neon_futures::*;
use std::cell::RefCell;
use std::sync::Arc;
use uuid::Uuid;

pub struct NodePreKeyStore {
    js_queue: EventQueue,
    store_object: Arc<Root<JsObject>>,
}

impl NodePreKeyStore {
    pub(crate) fn new(cx: &mut FunctionContext, store: Handle<JsObject>) -> Self {
        Self {
            js_queue: cx.queue(),
            store_object: Arc::new(store.root(cx)),
        }
    }

    async fn do_get_pre_key(&self, id: u32) -> Result<PreKeyRecord, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let id = id.convert_into(cx)?;
            let result = call_method(cx, store_object, "_getPreKey", vec![id.upcast()])?;
            let result = result.downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<DefaultJsBox<PreKeyRecord>, _>(cx) {
                Ok(obj) => Ok((***obj).clone()),
                Err(_) => Err("result must be an object".to_owned()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }

    async fn do_save_pre_key(&self, id: u32, record: PreKeyRecord) -> Result<(), String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let id: Handle<JsNumber> = id.convert_into(cx)?;
            let record: Handle<JsValue> = record.convert_into(cx)?;
            let result = call_method(cx, store_object, "_savePreKey", vec![id.upcast(), record])?
                .downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsUndefined, _>(cx) {
                Ok(_) => Ok(()),
                Err(_) => Err("unexpected result from _savePreKey".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }

    async fn do_remove_pre_key(&self, id: u32) -> Result<(), String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let id: Handle<JsNumber> = id.convert_into(cx)?;
            let result = call_method(cx, store_object, "_removePreKey", vec![id.upcast()])?
                .downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsUndefined, _>(cx) {
                Ok(_) => Ok(()),
                Err(_) => Err("unexpected result from _removePreKey".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }
}

impl Finalize for NodePreKeyStore {
    fn finalize<'b, C: neon::prelude::Context<'b>>(self, cx: &mut C) {
        self.store_object.finalize(cx)
    }
}

#[async_trait(?Send)]
impl PreKeyStore for NodePreKeyStore {
    async fn get_pre_key(
        &self,
        pre_key_id: PreKeyId,
        _ctx: libsignal_protocol::Context,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        self.do_get_pre_key(pre_key_id.into())
            .await
            .map_err(|s| js_error_to_rust("getPreKey", s))
    }

    async fn save_pre_key(
        &mut self,
        pre_key_id: PreKeyId,
        record: &PreKeyRecord,
        _ctx: libsignal_protocol::Context,
    ) -> Result<(), SignalProtocolError> {
        self.do_save_pre_key(pre_key_id.into(), record.clone())
            .await
            .map_err(|s| js_error_to_rust("savePreKey", s))
    }

    async fn remove_pre_key(
        &mut self,
        pre_key_id: PreKeyId,
        _ctx: libsignal_protocol::Context,
    ) -> Result<(), SignalProtocolError> {
        self.do_remove_pre_key(pre_key_id.into())
            .await
            .map_err(|s| js_error_to_rust("removePreKey", s))
    }
}

pub struct NodeSignedPreKeyStore {
    js_queue: EventQueue,
    store_object: Arc<Root<JsObject>>,
}

impl NodeSignedPreKeyStore {
    pub(crate) fn new(cx: &mut FunctionContext, store: Handle<JsObject>) -> Self {
        Self {
            js_queue: cx.queue(),
            store_object: Arc::new(store.root(cx)),
        }
    }

    async fn do_get_signed_pre_key(&self, id: u32) -> Result<SignedPreKeyRecord, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let id = id.convert_into(cx)?;
            let result = call_method(cx, store_object, "_getSignedPreKey", vec![id.upcast()])?;
            let result = result.downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<DefaultJsBox<SignedPreKeyRecord>, _>(cx) {
                Ok(obj) => Ok((***obj).clone()),
                Err(_) => Err("result must be an object".to_owned()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }

    async fn do_save_signed_pre_key(
        &self,
        id: u32,
        record: SignedPreKeyRecord,
    ) -> Result<(), String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let id: Handle<JsNumber> = id.convert_into(cx)?;
            let record: Handle<JsValue> = record.convert_into(cx)?;
            let result = call_method(
                cx,
                store_object,
                "_saveSignedPreKey",
                vec![id.upcast(), record],
            )?
            .downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsUndefined, _>(cx) {
                Ok(_) => Ok(()),
                Err(_) => Err("unexpected result from _saveSignedPreKey".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }
}

impl Finalize for NodeSignedPreKeyStore {
    fn finalize<'b, C: neon::prelude::Context<'b>>(self, cx: &mut C) {
        self.store_object.finalize(cx)
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for NodeSignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        signed_pre_key_id: SignedPreKeyId,
        _ctx: libsignal_protocol::Context,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        self.do_get_signed_pre_key(signed_pre_key_id.into())
            .await
            .map_err(|s| js_error_to_rust("getSignedPreKey", s))
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_pre_key_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
        _ctx: libsignal_protocol::Context,
    ) -> Result<(), SignalProtocolError> {
        self.do_save_signed_pre_key(signed_pre_key_id.into(), record.clone())
            .await
            .map_err(|s| js_error_to_rust("saveSignedPreKey", s))
    }
}

pub struct NodeSessionStore {
    js_queue: EventQueue,
    store_object: Arc<Root<JsObject>>,
}

impl NodeSessionStore {
    pub(crate) fn new(cx: &mut FunctionContext, store: Handle<JsObject>) -> Self {
        Self {
            js_queue: cx.queue(),
            store_object: Arc::new(store.root(cx)),
        }
    }

    async fn do_get_session(&self, name: ProtocolAddress) -> Result<Option<SessionRecord>, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let name: Handle<JsValue> = name.convert_into(cx)?;
            let result = call_method(cx, store_object, "_getSession", vec![name])?;
            let result = result.downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<DefaultJsBox<RefCell<SessionRecord>>, _>(cx) {
                Ok(obj) => Ok(Some((***obj).borrow().clone())),
                Err(_) => {
                    if value.is_a::<JsNull, _>(cx) || value.is_a::<JsUndefined, _>(cx) {
                        Ok(None)
                    } else {
                        Err("_getSession returned unexpected type".into())
                    }
                }
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }

    async fn do_save_session(
        &self,
        name: ProtocolAddress,
        record: SessionRecord,
    ) -> Result<(), String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let name = name.convert_into(cx)?;
            let record = record.convert_into(cx)?;
            let result = call_method(
                cx,
                store_object,
                "_saveSession",
                vec![name, record.upcast()],
            )?
            .downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsUndefined, _>(cx) {
                Ok(_) => Ok(()),
                Err(_) => Err("unexpected result from _saveSession".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }
}

impl Finalize for NodeSessionStore {
    fn finalize<'b, C: neon::prelude::Context<'b>>(self, cx: &mut C) {
        self.store_object.finalize(cx)
    }
}

#[async_trait(?Send)]
impl SessionStore for NodeSessionStore {
    async fn load_session(
        &self,
        name: &ProtocolAddress,
        _ctx: libsignal_protocol::Context,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        self.do_get_session(name.clone())
            .await
            .map_err(|s| js_error_to_rust("getSession", s))
    }

    async fn store_session(
        &mut self,
        name: &ProtocolAddress,
        record: &SessionRecord,
        _ctx: libsignal_protocol::Context,
    ) -> Result<(), SignalProtocolError> {
        self.do_save_session(name.clone(), record.clone())
            .await
            .map_err(|s| js_error_to_rust("saveSession", s))
    }
}

pub struct NodeIdentityKeyStore {
    js_queue: EventQueue,
    store_object: Arc<Root<JsObject>>,
}

impl NodeIdentityKeyStore {
    pub(crate) fn new(cx: &mut FunctionContext, store: Handle<JsObject>) -> Self {
        Self {
            js_queue: cx.queue(),
            store_object: Arc::new(store.root(cx)),
        }
    }

    async fn do_get_identity_key(&self) -> Result<PrivateKey, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let result = call_method(cx, store_object, "_getIdentityKey", vec![])?;
            let result = result.downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<DefaultJsBox<PrivateKey>, _>(cx) {
                Ok(obj) => Ok(***obj),
                Err(_) => Err("result must be an object".to_owned()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }

    async fn do_get_local_registration_id(&self) -> Result<u32, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let result = call_method(cx, store_object, "_getLocalRegistrationId", vec![])?
                .downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsNumber, _>(cx) {
                Ok(b) => Ok(b.value(cx) as u32),
                Err(_) => Err("unexpected result from _getLocalRegistrationId".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }

    async fn do_get_identity(&self, name: ProtocolAddress) -> Result<Option<PublicKey>, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let name: Handle<JsValue> = name.convert_into(cx)?;
            let result = call_method(cx, store_object, "_getIdentity", vec![name])?;
            let result = result.downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<DefaultJsBox<PublicKey>, _>(cx) {
                Ok(obj) => Ok(Some(***obj)),
                Err(_) => {
                    if value.is_a::<JsNull, _>(cx) {
                        Ok(None)
                    } else {
                        Err("result must be an object".to_owned())
                    }
                }
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }

    async fn do_save_identity(
        &self,
        name: ProtocolAddress,
        key: PublicKey,
    ) -> Result<bool, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let name: Handle<JsValue> = name.convert_into(cx)?;
            let key: Handle<JsValue> = key.convert_into(cx)?;
            let result = call_method(cx, store_object, "_saveIdentity", vec![name, key])?
                .downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsBoolean, _>(cx) {
                Ok(b) => Ok(b.value(cx)),
                Err(_) => Err("unexpected result from _saveIdentity".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }

    async fn do_is_trusted(
        &self,
        name: ProtocolAddress,
        key: PublicKey,
        direction: Direction,
    ) -> Result<bool, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let name: Handle<JsValue> = name.convert_into(cx)?;
            let key: Handle<JsValue> = key.convert_into(cx)?;
            let sending = direction == Direction::Sending;

            let sending = sending.convert_into(cx)?;
            let result = call_method(
                cx,
                store_object,
                "_isTrustedIdentity",
                vec![name, key, sending.upcast()],
            )?
            .downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsBoolean, _>(cx) {
                Ok(b) => Ok(b.value(cx)),
                Err(_) => Err("unexpected result from _isTrustedIdentity".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }
}

impl Finalize for NodeIdentityKeyStore {
    fn finalize<'b, C: neon::prelude::Context<'b>>(self, cx: &mut C) {
        self.store_object.finalize(cx)
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for NodeIdentityKeyStore {
    async fn get_identity_key_pair(
        &self,
        _ctx: libsignal_protocol::Context,
    ) -> Result<IdentityKeyPair, SignalProtocolError> {
        let pk = self
            .do_get_identity_key()
            .await
            .map_err(|s| js_error_to_rust("getIdentityPrivateKey", s))?;

        IdentityKeyPair::try_from(pk)
    }

    async fn get_local_registration_id(
        &self,
        _ctx: libsignal_protocol::Context,
    ) -> Result<SessionSeed, SignalProtocolError> {
        Ok(self
            .do_get_local_registration_id()
            .await
            .map_err(|s| js_error_to_rust("getLocalRegistrationId", s))?
            .into())
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        _ctx: libsignal_protocol::Context,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        Ok(self
            .do_get_identity(address.clone())
            .await
            .map_err(|s| js_error_to_rust("getIdentity", s))?
            .map(IdentityKey::new))
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _ctx: libsignal_protocol::Context,
    ) -> Result<bool, SignalProtocolError> {
        self.do_save_identity(address.clone(), *identity.public_key())
            .await
            .map_err(|s| js_error_to_rust("saveIdentity", s))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: libsignal_protocol::Direction,
        _ctx: libsignal_protocol::Context,
    ) -> Result<bool, SignalProtocolError> {
        self.do_is_trusted(address.clone(), *identity.public_key(), direction)
            .await
            .map_err(|s| js_error_to_rust("isTrustedIdentity", s))
    }
}

pub struct NodeSenderKeyStore {
    js_queue: EventQueue,
    store_object: Arc<Root<JsObject>>,
}

impl NodeSenderKeyStore {
    pub(crate) fn new(cx: &mut FunctionContext, store: Handle<JsObject>) -> Self {
        Self {
            js_queue: cx.queue(),
            store_object: Arc::new(store.root(cx)),
        }
    }

    async fn do_get_sender_key(
        &self,
        sender: ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let sender: Handle<JsValue> = sender.convert_into(cx)?;
            let distribution_id: Handle<JsValue> = distribution_id.convert_into(cx)?.upcast();
            let result = call_method(
                cx,
                store_object,
                "_getSenderKey",
                vec![sender, distribution_id],
            )?;
            let result = result.downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<DefaultJsBox<SenderKeyRecord>, _>(cx) {
                Ok(obj) => Ok(Some((***obj).clone())),
                Err(_) => {
                    if value.is_a::<JsNull, _>(cx) {
                        Ok(None)
                    } else {
                        Err("result must be an object".to_owned())
                    }
                }
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }

    async fn do_save_sender_key(
        &self,
        sender: ProtocolAddress,
        distribution_id: Uuid,
        record: SenderKeyRecord,
    ) -> Result<(), String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let sender: Handle<JsValue> = sender.convert_into(cx)?;
            let distribution_id: Handle<JsValue> = distribution_id.convert_into(cx)?.upcast();
            let record: Handle<JsValue> = record.convert_into(cx)?;
            let result = call_method(
                cx,
                store_object,
                "_saveSenderKey",
                vec![sender, distribution_id, record],
            )?
            .downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsUndefined, _>(cx) {
                Ok(_) => Ok(()),
                Err(_) => Err("unexpected result from _saveSenderKey".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }
}

impl Finalize for NodeSenderKeyStore {
    fn finalize<'a, C: Context<'a>>(self, cx: &mut C) {
        self.store_object.finalize(cx)
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for NodeSenderKeyStore {
    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        _ctx: libsignal_protocol::Context,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        self.do_get_sender_key(sender.clone(), distribution_id)
            .await
            .map_err(|s| js_error_to_rust("getSenderKey", s))
    }

    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
        _ctx: libsignal_protocol::Context,
    ) -> Result<(), SignalProtocolError> {
        self.do_save_sender_key(sender.clone(), distribution_id, record.clone())
            .await
            .map_err(|s| js_error_to_rust("saveSenderKey", s))
    }
}
