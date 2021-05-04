//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use super::*;
use async_trait::async_trait;
use uuid::Uuid;

pub type JavaIdentityKeyStore<'a> = JObject<'a>;
pub type JavaPreKeyStore<'a> = JObject<'a>;
pub type JavaSignedPreKeyStore<'a> = JObject<'a>;
pub type JavaSessionStore<'a> = JObject<'a>;
pub type JavaSenderKeyStore<'a> = JObject<'a>;

fn protocol_address_to_jobject<'a>(
    env: &'a JNIEnv,
    address: &ProtocolAddress,
) -> Result<JObject<'a>, SignalJniError> {
    let address_class = env.find_class("org/whispersystems/libsignal/SignalProtocolAddress")?;
    let device_id: u32 = address.device_id().into();
    let address_ctor_args = [
        JObject::from(env.new_string(address.name())?).into(),
        JValue::from(device_id.convert_into(env)?),
    ];

    let address_ctor_sig = jni_signature!((java.lang.String, int) -> void);
    let address_jobject = env.new_object(address_class, address_ctor_sig, &address_ctor_args)?;
    Ok(address_jobject)
}

pub struct JniIdentityKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    store: JObject<'a>,
}

impl<'a> JniIdentityKeyStore<'a> {
    pub fn new(env: &'a JNIEnv, store: JObject<'a>) -> Result<Self, SignalJniError> {
        check_jobject_type(
            &env,
            store,
            "org/whispersystems/libsignal/state/IdentityKeyStore",
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniIdentityKeyStore<'a> {
    fn do_get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalJniError> {
        let callback_sig = jni_signature!(() -> org.whispersystems.libsignal.IdentityKeyPair);
        let bits = get_object_with_serialization(
            self.env,
            self.store,
            &[],
            callback_sig,
            "getIdentityKeyPair",
        )?;

        match bits {
            None => Err(SignalJniError::Signal(SignalProtocolError::InternalError(
                "getIdentityKeyPair returned null",
            ))),
            Some(k) => Ok(IdentityKeyPair::try_from(k.as_ref())?),
        }
    }

    fn do_get_local_registration_id(&self) -> Result<u32, SignalJniError> {
        let callback_sig = jni_signature!(() -> int);
        let i: jint = call_method_checked(
            self.env,
            self.store,
            "getLocalRegistrationId",
            callback_sig,
            &[],
        )?;
        jint_to_u32(i)
    }

    fn do_save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;
        let key_jobject = jobject_from_serialized(
            self.env,
            "org/whispersystems/libsignal/IdentityKey",
            identity.serialize().as_ref(),
        )?;
        let callback_sig = jni_signature!((
            org.whispersystems.libsignal.SignalProtocolAddress,
            org.whispersystems.libsignal.IdentityKey
        ) -> boolean);
        let callback_args = [address_jobject.into(), key_jobject.into()];
        let result: jboolean = call_method_checked(
            self.env,
            self.store,
            "saveIdentity",
            callback_sig,
            &callback_args,
        )?;
        Ok(result != 0)
    }

    fn do_is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;
        let key_jobject = jobject_from_serialized(
            self.env,
            "org/whispersystems/libsignal/IdentityKey",
            identity.serialize().as_ref(),
        )?;

        let direction_class = self
            .env
            .find_class("org/whispersystems/libsignal/state/IdentityKeyStore$Direction")?;
        let field_name = match direction {
            Direction::Sending => "SENDING",
            Direction::Receiving => "RECEIVING",
        };

        let field_value = self.env.get_static_field(
            direction_class,
            field_name,
            "Lorg/whispersystems/libsignal/state/IdentityKeyStore$Direction;",
        )?;

        let callback_sig = jni_signature!((
            org.whispersystems.libsignal.SignalProtocolAddress,
            org.whispersystems.libsignal.IdentityKey,
            "Lorg/whispersystems/libsignal/state/IdentityKeyStore$Direction;",
        ) -> boolean);
        let callback_args = [address_jobject.into(), key_jobject.into(), field_value];
        let result: jboolean = call_method_checked(
            self.env,
            self.store,
            "isTrustedIdentity",
            callback_sig,
            &callback_args,
        )?;

        Ok(result != 0)
    }

    fn do_get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;
        let callback_sig = jni_signature!((
            org.whispersystems.libsignal.SignalProtocolAddress
        ) -> org.whispersystems.libsignal.IdentityKey);
        let callback_args = [address_jobject.into()];

        let bits = get_object_with_serialization(
            self.env,
            self.store,
            &callback_args,
            callback_sig,
            "getIdentity",
        )?;

        match bits {
            None => Ok(None),
            Some(k) => Ok(Some(IdentityKey::decode(&k)?)),
        }
    }
}

#[async_trait(?Send)]
impl<'a> IdentityKeyStore for JniIdentityKeyStore<'a> {
    async fn get_identity_key_pair(
        &self,
        _ctx: Context,
    ) -> Result<IdentityKeyPair, SignalProtocolError> {
        Ok(self.do_get_identity_key_pair()?)
    }

    async fn get_local_registration_id(&self, _ctx: Context) -> Result<u32, SignalProtocolError> {
        Ok(self.do_get_local_registration_id()?)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        Ok(self.do_save_identity(address, identity)?)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
        _ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        Ok(self.do_is_trusted_identity(address, identity, direction)?)
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        Ok(self.do_get_identity(address)?)
    }
}

pub struct JniPreKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    store: JObject<'a>,
}

impl<'a> JniPreKeyStore<'a> {
    pub fn new(env: &'a JNIEnv, store: JObject<'a>) -> Result<Self, SignalJniError> {
        check_jobject_type(
            &env,
            store,
            "org/whispersystems/libsignal/state/PreKeyStore",
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniPreKeyStore<'a> {
    fn do_get_pre_key(&self, prekey_id: u32) -> Result<PreKeyRecord, SignalJniError> {
        let callback_sig = jni_signature!((int) -> org.whispersystems.libsignal.state.PreKeyRecord);
        let callback_args = [JValue::from(prekey_id.convert_into(self.env)?)];
        let pk = get_object_with_native_handle::<PreKeyRecord>(
            self.env,
            self.store,
            &callback_args,
            callback_sig,
            "loadPreKey",
        )?;
        match pk {
            Some(pk) => Ok(pk),
            None => Err(SignalJniError::Signal(SignalProtocolError::InvalidPreKeyId)),
        }
    }

    fn do_save_pre_key(
        &mut self,
        prekey_id: u32,
        record: &PreKeyRecord,
    ) -> Result<(), SignalJniError> {
        let jobject_record = jobject_from_serialized(
            self.env,
            "org/whispersystems/libsignal/state/PreKeyRecord",
            &record.serialize()?,
        )?;
        let callback_sig = jni_signature!((
            int,
            org.whispersystems.libsignal.state.PreKeyRecord
        ) -> void);
        let callback_args = [
            JValue::from(prekey_id.convert_into(self.env)?),
            jobject_record.into(),
        ];
        let _: () = call_method_checked(
            self.env,
            self.store,
            "storePreKey",
            callback_sig,
            &callback_args,
        )?;
        Ok(())
    }

    fn do_remove_pre_key(&mut self, prekey_id: u32) -> Result<(), SignalJniError> {
        let callback_sig = jni_signature!((int) -> void);
        let callback_args = [JValue::from(prekey_id.convert_into(self.env)?)];
        let _: () = call_method_checked(
            self.env,
            self.store,
            "removePreKey",
            callback_sig,
            &callback_args,
        )?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl<'a> PreKeyStore for JniPreKeyStore<'a> {
    async fn get_pre_key(
        &self,
        prekey_id: u32,
        _ctx: Context,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        Ok(self.do_get_pre_key(prekey_id)?)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: u32,
        record: &PreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_save_pre_key(prekey_id, record)?)
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: u32,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_remove_pre_key(prekey_id)?)
    }
}

pub struct JniSignedPreKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    store: JObject<'a>,
}

impl<'a> JniSignedPreKeyStore<'a> {
    pub fn new(env: &'a JNIEnv, store: JObject<'a>) -> Result<Self, SignalJniError> {
        check_jobject_type(
            &env,
            store,
            "org/whispersystems/libsignal/state/SignedPreKeyStore",
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniSignedPreKeyStore<'a> {
    fn do_get_signed_pre_key(&self, prekey_id: u32) -> Result<SignedPreKeyRecord, SignalJniError> {
        let callback_sig = jni_signature!((
            int
        ) -> org.whispersystems.libsignal.state.SignedPreKeyRecord);
        let callback_args = [JValue::from(prekey_id.convert_into(self.env)?)];
        let spk = get_object_with_native_handle::<SignedPreKeyRecord>(
            self.env,
            self.store,
            &callback_args,
            callback_sig,
            "loadSignedPreKey",
        )?;
        match spk {
            Some(spk) => Ok(spk),
            None => Err(SignalJniError::Signal(
                SignalProtocolError::InvalidSignedPreKeyId,
            )),
        }
    }

    fn do_save_signed_pre_key(
        &mut self,
        prekey_id: u32,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalJniError> {
        let jobject_record = jobject_from_serialized(
            self.env,
            "org/whispersystems/libsignal/state/SignedPreKeyRecord",
            &record.serialize()?,
        )?;
        let callback_sig = jni_signature!((
            int,
            org.whispersystems.libsignal.state.SignedPreKeyRecord
        ) -> void);
        let callback_args = [
            JValue::from(prekey_id.convert_into(self.env)?),
            jobject_record.into(),
        ];
        let _: () = call_method_checked(
            self.env,
            self.store,
            "storeSignedPreKey",
            callback_sig,
            &callback_args,
        )?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl<'a> SignedPreKeyStore for JniSignedPreKeyStore<'a> {
    async fn get_signed_pre_key(
        &self,
        prekey_id: u32,
        _ctx: Context,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        Ok(self.do_get_signed_pre_key(prekey_id)?)
    }

    async fn save_signed_pre_key(
        &mut self,
        prekey_id: u32,
        record: &SignedPreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_save_signed_pre_key(prekey_id, record)?)
    }
}

pub struct JniSessionStore<'a> {
    env: &'a JNIEnv<'a>,
    store: JObject<'a>,
}

impl<'a> JniSessionStore<'a> {
    pub fn new(env: &'a JNIEnv, store: JObject<'a>) -> Result<Self, SignalJniError> {
        check_jobject_type(
            &env,
            store,
            "org/whispersystems/libsignal/state/SessionStore",
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniSessionStore<'a> {
    fn do_load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;

        let callback_sig = jni_signature!((
            org.whispersystems.libsignal.SignalProtocolAddress
        ) -> org.whispersystems.libsignal.state.SessionRecord);
        let callback_args = [address_jobject.into()];
        get_object_with_native_handle::<SessionRecord>(
            self.env,
            self.store,
            &callback_args,
            callback_sig,
            "loadSession",
        )
    }

    fn do_store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalJniError> {
        let address_jobject = protocol_address_to_jobject(self.env, address)?;
        let session_jobject = jobject_from_serialized(
            self.env,
            "org/whispersystems/libsignal/state/SessionRecord",
            &record.serialize()?,
        )?;

        let callback_sig = jni_signature!((
            org.whispersystems.libsignal.SignalProtocolAddress,
            org.whispersystems.libsignal.state.SessionRecord,
        ) -> void);
        let callback_args = [address_jobject.into(), session_jobject.into()];
        let _: () = call_method_checked(
            self.env,
            self.store,
            "storeSession",
            callback_sig,
            &callback_args,
        )?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl<'a> SessionStore for JniSessionStore<'a> {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        Ok(self.do_load_session(address)?)
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_store_session(address, record)?)
    }
}

pub struct JniSenderKeyStore<'a> {
    env: &'a JNIEnv<'a>,
    store: JObject<'a>,
}

impl<'a> JniSenderKeyStore<'a> {
    pub fn new(env: &'a JNIEnv, store: JObject<'a>) -> Result<Self, SignalJniError> {
        check_jobject_type(
            &env,
            store,
            "org/whispersystems/libsignal/groups/state/SenderKeyStore",
        )?;
        Ok(Self { env, store })
    }
}

impl<'a> JniSenderKeyStore<'a> {
    fn do_store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalJniError> {
        let sender_jobject = protocol_address_to_jobject(self.env, sender)?;
        let distribution_id_jobject = distribution_id.convert_into(self.env)?;
        let sender_key_record_jobject = jobject_from_native_handle(
            self.env,
            "org/whispersystems/libsignal/groups/state/SenderKeyRecord",
            box_object::<SenderKeyRecord>(Ok(record.clone()))?,
        )?;

        let callback_args = [
            sender_jobject.into(),
            distribution_id_jobject.into(),
            sender_key_record_jobject.into(),
        ];
        let callback_sig = jni_signature!((
            org.whispersystems.libsignal.SignalProtocolAddress,
            java.util.UUID,
            org.whispersystems.libsignal.groups.state.SenderKeyRecord,
        ) -> void);
        let _: () = call_method_checked(
            self.env,
            self.store,
            "storeSenderKey",
            callback_sig,
            &callback_args[..],
        )?;

        Ok(())
    }

    fn do_load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalJniError> {
        let sender_jobject = protocol_address_to_jobject(self.env, sender)?;
        let distribution_id_jobject = distribution_id.convert_into(self.env)?;
        let callback_args = [sender_jobject.into(), distribution_id_jobject.into()];
        let callback_sig = jni_signature!((
            org.whispersystems.libsignal.SignalProtocolAddress,
            java.util.UUID,
        ) -> org.whispersystems.libsignal.groups.state.SenderKeyRecord);

        let skr = get_object_with_native_handle::<SenderKeyRecord>(
            self.env,
            self.store,
            &callback_args,
            callback_sig,
            "loadSenderKey",
        )?;

        Ok(skr)
    }
}

#[async_trait(?Send)]
impl<'a> SenderKeyStore for JniSenderKeyStore<'a> {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.do_store_sender_key(sender, distribution_id, record)?)
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        _ctx: Context,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        Ok(self.do_load_sender_key(sender, distribution_id)?)
    }
}
