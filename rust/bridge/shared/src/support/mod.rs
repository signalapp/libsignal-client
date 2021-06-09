//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use futures::pin_mut;
use futures::task::noop_waker_ref;
use std::borrow::Cow;
use std::future::Future;
use std::task::{self, Poll};

pub(crate) use paste::paste;

mod transform_helper;
pub(crate) use transform_helper::*;

/// Polls a future once; panics if it is not Ready.
#[allow(dead_code)] // not used in Node-only builds
#[track_caller]
pub fn expect_ready<F: Future>(future: F) -> F::Output {
    pin_mut!(future);
    match future.poll(&mut task::Context::from_waker(noop_waker_ref())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("future was not ready"),
    }
}

/// Used for returning newly-allocated buffers as efficiently as possible.
///
/// Functions marked `#[bridge_fn_buffer]` must have an `Env` as their first parameter.
pub(crate) trait Env {
    type Buffer;
    fn buffer<'a, T: Into<Cow<'a, [u8]>>>(self, input: T) -> Self::Buffer;
}

/// Exposes a Rust type to each of the bridges as a boxed value.
///
/// Full form:
///
/// ```no_run
/// # #[macro_use] extern crate libsignal_bridge;
/// # struct Foo;
/// bridge_handle!(Foo, clone = true, mut = true, ffi = "foo", jni = "Foo", node = "Foo");
/// ```
///
/// This has several effects for a type `Foo`:
///
/// - `Foo` and `Option<Foo>` become valid result types for `bridge_fn`s (conforming to the
///   `ResultTypeInfo` traits for all three bridges).
///
/// - `&Foo` and `Option<&Foo>` become valid argument types (conforming to the `ArgTypeInfo` traits
///   for all three bridges).
///
/// - If `mut = true` is passed to `bridge_handle`, `&mut Foo` becomes a valid argument type for all
///   three bridges as well. This may include extra overhead to check Rust's exclusive borrow rules,
///   even for immutable accesses.
///
/// - If `mut = true` is *not* passed to `bridge_handle`, `&Foo` and `Option<&Foo>` become valid
///   argument types for async functions as well (conforming to [`node::AsyncArgTypeInfo`]).
///   (Note that you can't write `mut = false` because I was lazy with the macros.)
///
/// - "Destroy" functions are generated for FFI and JNI based on the name of the type:
///   `signal_foo_destroy` and `Native.Foo_Destroy`.
///
/// - If `clone = true` is passed to `bridge_handle`, a `signal_foo_clone` function will be
///   generated for the FFI bridge as well. `Foo` must adopt `Clone`.
///
/// # Representation
///
/// Each bridge represents a boxed Rust value differently:
///
/// - FFI: boxed values are opaque structs with manual memory management (`SignalFoo *`).
///   Note that the pointer may not refer directly to a `Foo` on the Rust side; that's an
///   implementation detail. (For example, it could point to a type tag.)
///
/// - JNI: boxed values are bare `long` values with manual memory management. (The Java code on the
///   other side of the bridge is expected to wrap these in strong class types.)
///
/// - Node: boxed values use Neon's [`JsBox`][] type, but this is only used for return values.
///   Arguments are always in the form of a JavaScript object with a `_nativeHandle` property that
///   refers to the box. The type inside the box may not directy be a `Foo` on the Rust side;
///   that's an implementation detail.
///
///   For TypeScript's benefit, each boxed type gets its own unique `interface Foo`, and the
///   arguments are of the form `Wrapper<Foo>`.
///
/// [`JsBox`]: https://docs.rs/neon/0.7.1-napi/neon/types/struct.JsBox.html
macro_rules! bridge_handle {
    ($typ:ty $(, clone = $_clone:tt)? $(, mut = $_mut:tt)? $(, ffi = $ffi_name:ident)? $(, jni = $jni_name:ident)? $(, node = $node_name:ident)?) => {
        #[cfg(feature = "ffi")]
        ffi_bridge_handle!($typ $(as $ffi_name)? $(, clone = $_clone)?);
        #[cfg(feature = "jni")]
        jni_bridge_handle!($typ $(as $jni_name)?);
        #[cfg(feature = "node")]
        node_bridge_handle!($typ $(as $node_name)? $(, mut = $_mut)?);
    };
}

/// Exposes a deserialization method to the bridges.
///
/// Example:
///
/// ```no_run
/// # #[macro_use] extern crate libsignal_bridge_macros;
/// # struct Foo;
/// # impl Foo {
/// #     fn try_from(buf: &[u8]) -> Result<Self, ()> {
/// #         Err(())
/// #     }
/// # }
///
/// bridge_deserialize!(Foo::try_from); // generates Foo_Deserialize
/// ```
///
/// The underlying method is expected to take a single `&[u8]` parameter and return
/// `Result<Self, _>`.
///
/// The `ffi`, `jni`, and `node` parameters control the name of the **type**; the resulting function
/// will always be suffixed with `_Deserialize` or `_deserialize` as appropriate. Unlike
/// `bridge_fn`, these parameters are identifiers, not string literals, and there is no way to
/// disable a particular bridge.
macro_rules! bridge_deserialize {
    ($typ:ident::$fn:path $(, ffi = $ffi_name:ident)? $(, jni = $jni_name:ident)? $(, node = $node_name:ident)? ) => {
        #[cfg(feature = "ffi")]
        ffi_bridge_deserialize!($typ::$fn $(as $ffi_name)?);
        #[cfg(feature = "jni")]
        jni_bridge_deserialize!($typ::$fn $(as $jni_name)?);
        #[cfg(feature = "node")]
        node_bridge_deserialize!($typ::$fn $(as $node_name)?);
    }
}

/// Exposes a buffer-returning getter to the bridges.
///
/// Example:
///
/// ```no_run
/// # #[macro_use] extern crate libsignal_bridge_macros;
/// # struct Foo;
/// # impl Foo {
/// #     fn payload(&self) -> Result<Vec<u8>, ()> {
/// #         Err(())
/// #     }
/// # }
///
/// bridge_get_bytearray!(Foo::payload); // generates Foo_GetPayload
/// ```
///
/// The underlying implementation is expected to return `Result<T, _>`, where `T` is a type that
/// adopts `Into<Cow<[u8]>>`. As a special case, `T` can also be `Box<[u8]>`.
///
/// Like `bridge_fn`, the `ffi`, `jni`, and `node` parameters allow customizing the name of the
/// resulting entry points; they can also be `false` to disable a particular entry point.
macro_rules! bridge_get_bytearray {
    ($typ:ident :: $method:ident as $name:ident $(, $param:ident = $val:tt)*) => {
        paste! {
            #[bridge_fn_buffer($($param = $val),*)]
            fn [<$typ _ $name>]<E: Env>(env: E, obj: &$typ) -> Result<E::Buffer> {
                let result = TransformHelper($typ::$method(obj));
                let result = result.ok_if_needed()?;
                let result = result.into_vec_if_needed().0;
                let r: &[u8] = result.as_ref();
                Ok(env.buffer(r))
            }
        }
    };
    ($typ:ident :: $method:ident $(, $param:ident = $val:tt)*) => {
        paste! {
            bridge_get_bytearray!($typ::$method as [<Get $method:camel>] $(, $param = $val)*);
        }
    };
}

/// Exposes an optional-buffer-returning getter to the bridges.
///
/// Example:
///
/// ```no_run
/// # #[macro_use] extern crate libsignal_bridge_macros;
/// # struct Foo;
/// # impl Foo {
/// #     fn payload(&self) -> Result<Option<Vec<u8>>, ()> {
/// #         Err(())
/// #     }
/// # }
///
/// bridge_get_optional_bytearray!(Foo::payload); // generates Foo_GetPayload
/// ```
///
/// The underlying implementation is expected to return `Result<Option<T>, _>`, where `T` is a type
/// that adopts `Into<Cow<[u8]>>`. As a special case, `T` can also be `Box<[u8]>`.
///
/// Like `bridge_fn`, the `ffi`, `jni`, and `node` parameters allow customizing the name of the
/// resulting entry points; they can also be `false` to disable a particular entry point.
macro_rules! bridge_get_optional_bytearray {
    ($typ:ident :: $method:ident as $name:ident $(, $param:ident = $val:tt)*) => {
        paste! {
            #[bridge_fn_buffer($($param = $val),*)]
            fn [<$typ _ $name>]<E: Env>(env: E, obj: &$typ) -> Result<Option<E::Buffer>> {
                let result = $typ::$method(obj);
                let result_without_errors = TransformHelper(result).ok_if_needed()?.0;
                let result_buffer = result_without_errors.map(|b| {
                    let b = TransformHelper(b).into_vec_if_needed().0;
                    env.buffer(b.as_ref())
                });
                Ok(result_buffer)
            }
        }
    };
    ($typ:ident :: $method:ident $(, $param:ident = $val:tt)*) => {
        paste! {
            bridge_get_optional_bytearray!(
                $typ::$method as [<Get $method:camel>] $(, $param = $val)*);
        }
    };
}

/// Exposes a getter method as a `bridge_fn`.
///
/// Full form:
///
/// ```no_run
/// # #[macro_use] extern crate libsignal_bridge;
/// # struct Foo;
/// impl Foo {
///     fn bar(&self) -> &str {
///         // ...
/// #       "baz"
///     }
/// }
///
/// bridge_get!(Foo::bar as GetBar -> &str, ffi = "foo_get_bar", jni = "Foo_GetBar", node = "Foo_GetBar");
/// ```
///
/// The `as GetBar` can be omitted if the default name is acceptable (camel-case and prefix with
/// "Get"). All additional arguments are forwarded to `bridge_fn`.
///
/// Roughly equivalent to
///
/// ```no_run
/// # #[macro_use] extern crate libsignal_bridge_macros;
/// # struct Foo;
/// # impl Foo {
/// #     fn bar(&self) -> &str {
/// #         "baz"
/// #     }
/// # }
///
/// #[bridge_fn]
/// fn Foo_GetBar(obj: &Foo) -> Result<&str> {
///   Foo::bar(obj)
/// }
/// ```
///
/// Automatically handles converting from the underlying type (using `into()`) and wrapping in
/// `Ok` if the underlying result is non-failable.
macro_rules! bridge_get {
    ($typ:ident :: $method:ident as $name:ident -> $result:ty $(, $param:ident = $val:tt)* ) => {
        paste! {
            #[bridge_fn($($param = $val),*)]
            fn [<$typ _ $name>](obj: &$typ) -> Result<$result> {
                let result = TransformHelper($typ::$method(obj));
                Ok(result.ok_if_needed()?.option_map_into().into())
            }
        }
    };
    ($typ:ident :: $method:ident -> $result:ty $(, $param:ident = $val:tt)* ) => {
        paste! {
            bridge_get!($typ::$method as [<Get $method:camel>] -> $result $(, $param = $val)*);
        }
    };
}
