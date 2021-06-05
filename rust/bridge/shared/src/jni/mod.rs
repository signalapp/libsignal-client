//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

extern crate jni_crate as jni;

use jni::objects::{JThrowable, JValue};
use jni::sys::jobject;

use device_transfer::Error as DeviceTransferError;
use libsignal_protocol::*;
use signal_crypto::Error as SignalCryptoError;
use std::convert::{TryFrom, TryInto};
use std::error::Error;

pub(crate) use jni::objects::{AutoArray, JClass, JObject, JString, ReleaseMode};
pub(crate) use jni::sys::{jboolean, jbyteArray, jint, jlong, jlongArray, jstring};
pub(crate) use jni::JNIEnv;

/// Converts a function signature to a JNI signature string.
///
/// This macro uses Rust function syntax `(Foo, Bar) -> Baz`, and uses Rust syntax for Java arrays
/// `[Foo]`, but otherwise uses Java names for types: `boolean`, `byte`, `void`.
// Placed here so that it can be used in submodules.
// (Unlike regular Rust declarations, macros rely on lexical ordering.)
#[macro_export]
macro_rules! jni_signature {
    ( boolean ) => ("Z");
    ( bool ) => (compile_error!("use Java type 'boolean'"));
    ( byte ) => ("B");
    ( char ) => ("C");
    ( short ) => ("S");
    ( int ) => ("I");
    ( long ) => ("J");
    ( float ) => ("F");
    ( double ) => ("D");
    ( void ) => ("V");
    ( $x:literal ) => ($x);

    // Functions
    ( ( $($arg_base:tt $(. $arg_rest:ident)*),* $(,)? ) -> $ret_base:tt $(. $ret_rest:ident)* ) => {
        concat!("(" $(, jni_signature!($arg_base $(. $arg_rest)*))*, ")", jni_signature!($ret_base $(. $ret_rest)*))
    };

    // Arrays
    ( [$arg_base:tt $(. $arg_rest:ident)*] ) => {
        concat!("[", jni_signature!($arg_base $(. $arg_rest)*))
    };

    // Objects
    ( $arg_base:tt $(. $arg_rest:ident)* ) => {
        concat!("L", stringify!($arg_base) $(, "/", stringify!($arg_rest))*, ";")
    };
}

#[macro_use]
mod convert;
pub use convert::*;

mod error;
pub use error::*;

mod storage;
pub use storage::*;

pub use crate::support::expect_ready;

/// The type of boxed Rust values, as surfaced in JavaScript.
pub type ObjectHandle = jlong;

pub type JavaUUID<'a> = JObject<'a>;
pub type JavaReturnUUID = jobject;
pub type JavaCiphertextMessage<'a> = JObject<'a>;
pub type JavaReturnCiphertextMessage = jobject;

/// Translates errors into Java exceptions.
///
/// Exceptions thrown in callbacks will be rethrown; all other errors will be mapped to an
/// appropriate Java exception class and thrown.
fn throw_error(env: &JNIEnv, error: SignalJniError) {
    // Handle special cases first.
    let error = match error {
        SignalJniError::Signal(SignalProtocolError::ApplicationCallbackError(
            callback,
            exception,
        )) => {
            // The usual way to write this code would be to match on the result of Error::downcast.
            // However, the "failure" result, which is intended to return the original type back,
            // only supports Send and Sync as additional traits. For anything else, we have to test first.
            if Error::is::<ThrownException>(&*exception) {
                let exception =
                    Error::downcast::<ThrownException>(exception).expect("just checked");
                if let Err(e) = env.throw(exception.as_obj()) {
                    log::error!("failed to rethrow exception from {}: {}", callback, e);
                }
                return;
            }

            // Fall through to generic handling below.
            SignalJniError::Signal(SignalProtocolError::ApplicationCallbackError(
                callback, exception,
            ))
        }

        SignalJniError::Signal(SignalProtocolError::UntrustedIdentity(ref addr)) => {
            let result = env.throw_new(
                "org/whispersystems/libsignal/UntrustedIdentityException",
                addr.name(),
            );
            if let Err(e) = result {
                log::error!("failed to throw exception for {}: {}", error, e);
            }
            return;
        }

        SignalJniError::Signal(SignalProtocolError::FingerprintVersionMismatch(theirs, ours)) => {
            let throwable = env.new_object(
                "org/whispersystems/libsignal/fingerprint/FingerprintVersionMismatchException",
                jni_signature!((int, int) -> void),
                &[JValue::from(theirs as jint), JValue::from(ours as jint)],
            );

            match throwable {
                Err(e) => log::error!("failed to create exception for {}: {}", error, e),
                Ok(throwable) => {
                    let result = env.throw(JThrowable::from(throwable));
                    if let Err(e) = result {
                        log::error!("failed to throw exception for {}: {}", error, e);
                    }
                }
            }
            return;
        }

        SignalJniError::Signal(SignalProtocolError::SealedSenderSelfSend) => {
            let throwable = env.new_object(
                "org/signal/libsignal/metadata/SelfSendException",
                jni_signature!(() -> void),
                &[],
            );

            match throwable {
                Err(e) => log::error!("failed to create exception for {}: {}", error, e),
                Ok(throwable) => {
                    let result = env.throw(JThrowable::from(throwable));
                    if let Err(e) = result {
                        log::error!("failed to throw exception for {}: {}", error, e);
                    }
                }
            }
            return;
        }

        SignalJniError::UnexpectedPanic(_)
        | SignalJniError::BadJniParameter(_)
        | SignalJniError::UnexpectedJniResultType(_, _) => {
            // java.lang.AssertionError has a slightly different signature.
            let throwable = env.new_string(error.to_string()).and_then(|message| {
                env.new_object(
                    "java/lang/AssertionError",
                    jni_signature!((java.lang.Object) -> void),
                    &[JValue::from(message)],
                )
            });

            match throwable {
                Err(e) => log::error!("failed to create exception for {}: {}", error, e),
                Ok(throwable) => {
                    let result = env.throw(JThrowable::from(throwable));
                    if let Err(e) = result {
                        log::error!("failed to throw exception for {}: {}", error, e);
                    }
                }
            }
            return;
        }

        e => e,
    };

    let exception_type = match error {
        SignalJniError::NullHandle => "java/lang/NullPointerException",

        SignalJniError::Signal(SignalProtocolError::InvalidState(_, _))
        | SignalJniError::Signal(SignalProtocolError::NoSenderKeyState)
        | SignalJniError::SignalCrypto(SignalCryptoError::InvalidState)
        | SignalJniError::Signal(SignalProtocolError::InvalidSessionStructure) => {
            "java/lang/IllegalStateException"
        }

        SignalJniError::Signal(SignalProtocolError::InvalidArgument(_))
        | SignalJniError::SignalCrypto(SignalCryptoError::UnknownAlgorithm(_, _))
        | SignalJniError::SignalCrypto(SignalCryptoError::InvalidInputSize)
        | SignalJniError::SignalCrypto(SignalCryptoError::InvalidNonceSize) => {
            "java/lang/IllegalArgumentException"
        }

        SignalJniError::IntegerOverflow(_)
        | SignalJniError::Jni(_)
        | SignalJniError::Signal(SignalProtocolError::ApplicationCallbackError(_, _))
        | SignalJniError::Signal(SignalProtocolError::FfiBindingError(_))
        | SignalJniError::Signal(SignalProtocolError::InternalError(_))
        | SignalJniError::DeviceTransfer(DeviceTransferError::InternalError(_))
        | SignalJniError::DeviceTransfer(DeviceTransferError::KeyDecodingFailed)
        | SignalJniError::Signal(SignalProtocolError::InvalidChainKeyLength(_))
        | SignalJniError::Signal(SignalProtocolError::InvalidCipherCryptographicParameters(_, _))
        | SignalJniError::Signal(SignalProtocolError::InvalidMacKeyLength(_))
        | SignalJniError::Signal(SignalProtocolError::InvalidRootKeyLength(_))
        | SignalJniError::Signal(SignalProtocolError::ProtobufEncodingError(_)) => {
            "java/lang/RuntimeException"
        }

        SignalJniError::Signal(SignalProtocolError::DuplicatedMessage(_, _)) => {
            "org/whispersystems/libsignal/DuplicateMessageException"
        }

        SignalJniError::Signal(SignalProtocolError::InvalidPreKeyId)
        | SignalJniError::Signal(SignalProtocolError::InvalidSignedPreKeyId) => {
            "org/whispersystems/libsignal/InvalidKeyIdException"
        }

        SignalJniError::Signal(SignalProtocolError::NoKeyTypeIdentifier)
        | SignalJniError::Signal(SignalProtocolError::SignatureValidationFailed)
        | SignalJniError::Signal(SignalProtocolError::BadKeyType(_))
        | SignalJniError::Signal(SignalProtocolError::BadKeyLength(_, _, _))
        | SignalJniError::SignalCrypto(SignalCryptoError::InvalidKeySize) => {
            "org/whispersystems/libsignal/InvalidKeyException"
        }

        SignalJniError::Signal(SignalProtocolError::SessionNotFound(_)) => {
            "org/whispersystems/libsignal/NoSessionException"
        }

        SignalJniError::Signal(SignalProtocolError::InvalidMessage(_))
        | SignalJniError::Signal(SignalProtocolError::CiphertextMessageTooShort(_))
        | SignalJniError::Signal(SignalProtocolError::InvalidCiphertext)
        | SignalJniError::Signal(SignalProtocolError::InvalidProtobufEncoding)
        | SignalJniError::Signal(SignalProtocolError::ProtobufDecodingError(_))
        | SignalJniError::Signal(SignalProtocolError::InvalidSealedSenderMessage(_))
        | SignalJniError::SignalCrypto(SignalCryptoError::InvalidTag) => {
            "org/whispersystems/libsignal/InvalidMessageException"
        }

        SignalJniError::Signal(SignalProtocolError::UnrecognizedCiphertextVersion(_))
        | SignalJniError::Signal(SignalProtocolError::UnrecognizedMessageVersion(_))
        | SignalJniError::Signal(SignalProtocolError::UnknownSealedSenderVersion(_)) => {
            "org/whispersystems/libsignal/InvalidVersionException"
        }

        SignalJniError::Signal(SignalProtocolError::LegacyCiphertextVersion(_)) => {
            "org/whispersystems/libsignal/LegacyMessageException"
        }

        #[allow(deprecated)]
        SignalJniError::Signal(SignalProtocolError::FingerprintIdentifierMismatch)
        | SignalJniError::Signal(SignalProtocolError::FingerprintParsingError) => {
            "org/whispersystems/libsignal/fingerprint/FingerprintParsingException"
        }

        SignalJniError::Signal(SignalProtocolError::SealedSenderSelfSend)
        | SignalJniError::Signal(SignalProtocolError::UntrustedIdentity(_))
        | SignalJniError::Signal(SignalProtocolError::FingerprintVersionMismatch(_, _))
        | SignalJniError::UnexpectedPanic(_)
        | SignalJniError::BadJniParameter(_)
        | SignalJniError::UnexpectedJniResultType(_, _) => {
            unreachable!("already handled in prior match")
        }
    };

    if let Err(e) = env.throw_new(exception_type, error.to_string()) {
        log::error!("failed to throw exception for {}: {}", error, e);
    }
}

/// Provides a dummy value to return when an exception is thrown.
pub trait JniDummyValue {
    fn dummy_value() -> Self;
}

impl JniDummyValue for ObjectHandle {
    fn dummy_value() -> Self {
        0
    }
}

impl JniDummyValue for jint {
    fn dummy_value() -> Self {
        0
    }
}

impl JniDummyValue for jobject {
    fn dummy_value() -> Self {
        std::ptr::null_mut()
    }
}

impl JniDummyValue for jboolean {
    fn dummy_value() -> Self {
        0
    }
}

impl JniDummyValue for () {
    fn dummy_value() -> Self {}
}

pub fn run_ffi_safe<F: FnOnce() -> Result<R, SignalJniError> + std::panic::UnwindSafe, R>(
    env: &JNIEnv,
    f: F,
) -> R
where
    R: JniDummyValue,
{
    match std::panic::catch_unwind(f) {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            throw_error(env, e);
            R::dummy_value()
        }
        Err(r) => {
            throw_error(env, SignalJniError::UnexpectedPanic(r));
            R::dummy_value()
        }
    }
}

pub fn box_object<T>(t: Result<T, SignalProtocolError>) -> Result<ObjectHandle, SignalJniError> {
    match t {
        Ok(t) => Ok(Box::into_raw(Box::new(t)) as ObjectHandle),
        Err(e) => Err(SignalJniError::Signal(e)),
    }
}

pub unsafe fn native_handle_cast<T>(
    handle: ObjectHandle,
) -> Result<&'static mut T, SignalJniError> {
    /*
    Should we try testing the encoded pointer for sanity here, beyond
    being null? For example verifying that lowest bits are zero,
    highest bits are zero, greater than 64K, etc?
    */
    if handle == 0 {
        return Err(SignalJniError::NullHandle);
    }

    Ok(&mut *(handle as *mut T))
}

pub fn jint_to_u32(v: jint) -> Result<u32, SignalJniError> {
    if v < 0 {
        return Err(SignalJniError::IntegerOverflow(format!("{} to u32", v)));
    }
    Ok(v as u32)
}

pub fn jint_to_u8(v: jint) -> Result<u8, SignalJniError> {
    match u8::try_from(v) {
        Err(_) => Err(SignalJniError::IntegerOverflow(format!("{} to u8", v))),
        Ok(v) => Ok(v),
    }
}

pub fn jlong_to_u64(v: jlong) -> Result<u64, SignalJniError> {
    if v < 0 {
        return Err(SignalJniError::IntegerOverflow(format!("{} to u64", v)));
    }
    Ok(v as u64)
}

pub fn to_jbytearray<T: AsRef<[u8]>>(
    env: &JNIEnv,
    data: Result<T, SignalProtocolError>,
) -> Result<jbyteArray, SignalJniError> {
    let data = data?;
    let data: &[u8] = data.as_ref();
    Ok(env.byte_array_from_slice(data)?)
}

/// Calls a method and translates any thrown exceptions to
/// [`SignalProtocolError::ApplicationCallbackError`].
///
/// Wraps [`JNIEnv::call_method`]; all arguments are the same.
/// The result must have the correct type, or [`SignalJniError::UnexpectedJniResultType`] will be
/// returned instead.
pub fn call_method_checked<'a, O: Into<JObject<'a>>, R: TryFrom<JValue<'a>>>(
    env: &JNIEnv<'a>,
    obj: O,
    fn_name: &'static str,
    sig: &'static str,
    args: &[JValue<'_>],
) -> Result<R, SignalJniError> {
    // Note that we are *not* unwrapping the result yet!
    // We need to check for exceptions *first*.
    let result = env.call_method(obj, fn_name, sig, args);

    let throwable = env.exception_occurred()?;
    if **throwable == *JObject::null() {
        let result = result?;
        result
            .try_into()
            .map_err(|_| SignalJniError::UnexpectedJniResultType(fn_name, result.type_name()))
    } else {
        env.exception_clear()?;

        Err(SignalProtocolError::ApplicationCallbackError(
            fn_name,
            Box::new(ThrownException::new(env, throwable)?),
        )
        .into())
    }
}

/// Constructs a Java object from the given boxed Rust value.
///
/// Assumes there's a corresponding constructor that takes a single `long` to represent the address.
pub fn jobject_from_native_handle<'a>(
    env: &'a JNIEnv,
    class_name: &str,
    boxed_handle: ObjectHandle,
) -> Result<JObject<'a>, SignalJniError> {
    let class_type = env.find_class(class_name)?;
    let ctor_sig = jni_signature!((long) -> void);
    let ctor_args = [JValue::from(boxed_handle)];
    Ok(env.new_object(class_type, ctor_sig, &ctor_args)?)
}

/// Constructs a Java object from its serialized form.
///
/// Assumes there's a corresponding constructor that takes a single `byte[]`.
pub fn jobject_from_serialized<'a>(
    env: &'a JNIEnv,
    class_name: &str,
    serialized: &[u8],
) -> Result<JObject<'a>, SignalJniError> {
    let class_type = env.find_class(class_name)?;
    let ctor_sig = jni_signature!(([byte]) -> void);
    let ctor_args = [JValue::from(to_jbytearray(env, Ok(serialized))?)];
    Ok(env.new_object(class_type, ctor_sig, &ctor_args)?)
}

/// Verifies that a Java object is a non-`null` instance of the given class.
pub fn check_jobject_type(
    env: &JNIEnv,
    obj: JObject,
    class_name: &'static str,
) -> Result<(), SignalJniError> {
    if obj.is_null() {
        return Err(SignalJniError::NullHandle);
    }

    let class = env.find_class(class_name)?;

    if !env.is_instance_of(obj, class)? {
        return Err(SignalJniError::BadJniParameter(class_name));
    }

    Ok(())
}

/// Calls a method, then clones the Rust value from the result.
///
/// The method is assumed to return a type with a `long nativeHandle()` method, which in turn must
/// produce a boxed Rust value.
pub fn get_object_with_native_handle<T: 'static + Clone>(
    env: &JNIEnv,
    store_obj: JObject,
    callback_args: &[JValue],
    callback_sig: &'static str,
    callback_fn: &'static str,
) -> Result<Option<T>, SignalJniError> {
    let obj: JObject =
        call_method_checked(env, store_obj, callback_fn, callback_sig, &callback_args)?;
    if obj.is_null() {
        return Ok(None);
    }

    let handle: jlong =
        call_method_checked(env, obj, "nativeHandle", jni_signature!(() -> long), &[])?;
    if handle == 0 {
        return Ok(None);
    }

    let object = unsafe { native_handle_cast::<T>(handle)? };
    Ok(Some(object.clone()))
}

/// Calls a method, then serializes the result.
///
/// The method is assumed to return a type with a `byte[] serialize()` method.
pub fn get_object_with_serialization(
    env: &JNIEnv,
    store_obj: JObject,
    callback_args: &[JValue],
    callback_sig: &'static str,
    callback_fn: &'static str,
) -> Result<Option<Vec<u8>>, SignalJniError> {
    let obj: JObject =
        call_method_checked(env, store_obj, callback_fn, callback_sig, &callback_args)?;

    if obj.is_null() {
        return Ok(None);
    }

    let bytes: JObject =
        call_method_checked(env, obj, "serialize", jni_signature!(() -> [byte]), &[])?;

    Ok(Some(env.convert_byte_array(*bytes)?))
}

/// Like [CiphertextMessage], but non-owning.
///
/// Java has an interface for CiphertextMessage instead of an opaque handle, so we need to do extra
/// work to bridge it back to Rust.
#[derive(Clone, Copy)]
pub enum CiphertextMessageRef<'a> {
    SignalMessage(&'a SignalMessage),
    PreKeySignalMessage(&'a PreKeySignalMessage),
    SenderKeyMessage(&'a SenderKeyMessage),
    PlaintextContent(&'a PlaintextContent),
}

impl<'a> CiphertextMessageRef<'a> {
    pub fn message_type(self) -> CiphertextMessageType {
        match self {
            CiphertextMessageRef::SignalMessage(_) => CiphertextMessageType::Whisper,
            CiphertextMessageRef::PreKeySignalMessage(_) => CiphertextMessageType::PreKey,
            CiphertextMessageRef::SenderKeyMessage(_) => CiphertextMessageType::SenderKey,
            CiphertextMessageRef::PlaintextContent(_) => CiphertextMessageType::Plaintext,
        }
    }

    pub fn serialize(self) -> &'a [u8] {
        match self {
            CiphertextMessageRef::SignalMessage(x) => x.serialized(),
            CiphertextMessageRef::PreKeySignalMessage(x) => x.serialized(),
            CiphertextMessageRef::SenderKeyMessage(x) => x.serialized(),
            CiphertextMessageRef::PlaintextContent(x) => x.serialized(),
        }
    }
}

/// Used by [`bridge_handle`](crate::support::bridge_handle).
///
/// Not intended to be invoked directly.
macro_rules! jni_bridge_destroy {
    ( $typ:ty as $jni_name:ident ) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<Java_org_signal_client_internal_Native_ $jni_name _1Destroy>](
                _env: jni::JNIEnv,
                _class: jni::JClass,
                handle: jni::ObjectHandle,
            ) {
                if handle != 0 {
                    let _boxed_value = Box::from_raw(handle as *mut $typ);
                }
            }
        }
    };
}

/// Implementation of [`bridge_deserialize`](crate::support::bridge_deserialize) for JNI.
macro_rules! jni_bridge_deserialize {
    ( $typ:ident::$fn:path as false ) => {};
    ( $typ:ident::$fn:path as $jni_name:ident ) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<Java_org_signal_client_internal_Native_ $jni_name _1Deserialize>](
                env: jni::JNIEnv,
                _class: jni::JClass,
                data: jni::jbyteArray,
            ) -> jni::ObjectHandle {
                jni::run_ffi_safe(&env, || {
                    let data = env.convert_byte_array(data)?;
                    jni::ResultTypeInfo::convert_into($typ::$fn(data.as_ref()), &env)
                })
            }
        }
    };
    ( $typ:ident::$fn:path ) => {
        jni_bridge_deserialize!($typ::$fn as $typ);
    };
}
