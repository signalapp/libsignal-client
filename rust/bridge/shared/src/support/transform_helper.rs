//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/// A type that can perform operations inside Result and Option through Rust overloading trickery.
///
/// Rust normally doesn't support overloading, but it does have exactly one form we can use:
/// methods on a concrete type (struct or enum) are "better" than methods from a trait,
/// but not if the methods on the concrete type are constrained to certain generic parameters.
///
/// Based on the technique used by the [`impls`][impls] crate.
///
/// [impls]: https://github.com/nvzqz/impls#how-it-works
pub(crate) struct TransformHelper<T>(pub(crate) T);

impl<T> TransformHelper<T> {
    /// Extracts the value from the TransformHelper and transforms it as requested.
    ///
    /// This isn't an actual implementation of Into (or From)
    /// because `U` could be anything, including types outside this crate.
    pub(crate) fn into<U: From<T>>(self) -> U {
        self.0.into()
    }
}

impl<T, E> TransformHelper<Result<T, E>> {
    /// Transforms `TransformHelper<T>` into a `Result<TransformHelper<U>, _>`.
    ///
    /// If `T` is statically `Result` already, this pushes the TransformHelper
    /// type inside the success case; if it is not, the existing value will be
    /// wrapped in `Ok`.
    pub(crate) fn ok_if_needed(self) -> Result<TransformHelper<T>, E> {
        self.0.map(TransformHelper)
    }
}

impl<T> TransformHelper<Option<T>> {
    /// Transforms `TransformHelper<T>` into a `Option<TransformHelper<U>>`.
    ///
    /// If `T` is statically `Option` already, this pushes the TransformHelper
    /// type inside the present case; if it is not, the existing value will be
    /// wrapped in `Some`.
    #[allow(dead_code)] // when added, only used by the FFI bridge
    pub(crate) fn some_if_needed(self) -> Option<TransformHelper<T>> {
        self.0.map(TransformHelper)
    }

    /// Transforms `TransformHelper<Option<T>>` into a `TransformHelper<Option<U>>`
    /// and leaves other TransformHelper values unchanged.
    ///
    /// Combine this with [TransformHelper::into] to perform a transformation on
    /// optional and non-optional values alike.
    pub(crate) fn option_map_into<U: From<T>>(self) -> TransformHelper<Option<U>> {
        TransformHelper(self.0.map(U::from))
    }
}

impl<T> TransformHelper<Box<[T]>> {
    /// Transforms `TransformHelper<Box<[T]>>` into a `TransformHelper<Vec<T>>`
    /// and leaves other TransformHelper values unchanged.
    #[allow(dead_code)]
    pub(crate) fn into_vec_if_needed(self) -> TransformHelper<Vec<T>> {
        TransformHelper(self.0.into_vec())
    }
}

pub(crate) trait TransformHelperImpl: Sized {
    fn ok_if_needed(self) -> Result<Self, libsignal_protocol::SignalProtocolError> {
        Ok(self)
    }
    fn some_if_needed(self) -> Option<Self> {
        Some(self)
    }
    fn option_map_into(self) -> Self {
        self
    }
    fn into_vec_if_needed(self) -> Self {
        self
    }
}
impl<T> TransformHelperImpl for TransformHelper<T> {}

#[test]
fn test_ok_if_needed() {
    assert!(matches!(
        TransformHelper(0).ok_if_needed(),
        Ok(TransformHelper(0))
    ));
    assert!(matches!(
        TransformHelper(Result::<i32, bool>::Ok(0)).ok_if_needed(),
        Ok(TransformHelper(0))
    ));
    assert!(matches!(
        TransformHelper(Result::<i32, bool>::Err(false)).ok_if_needed(),
        Err(false)
    ));
}

#[test]
fn test_option_map_into() {
    assert!(matches!(
        TransformHelper(0u32).option_map_into(),
        TransformHelper(0u32)
    ));
    assert!(matches!(
        TransformHelper(Option::<u32>::Some(0u32)).option_map_into(),
        TransformHelper(Option::<u64>::Some(0u64))
    ));
    assert!(matches!(
        TransformHelper(Option::<u32>::None).option_map_into(),
        TransformHelper(Option::<u64>::None)
    ));

    assert!(matches!(
        TransformHelper(0u32).option_map_into().into(),
        0u64
    ));
    assert!(matches!(
        TransformHelper(Option::<u32>::Some(0u32))
            .option_map_into()
            .into(),
        Option::<u64>::Some(0u64)
    ));
    assert!(matches!(
        TransformHelper(Option::<u32>::None)
            .option_map_into()
            .into(),
        Option::<u64>::None
    ));
}
