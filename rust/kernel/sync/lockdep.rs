// SPDX-License-Identifier: GPL-2.0

//! Utilities related to lockdep.
//!
//! C headers: [`include/linux/lockdep.h`](srctree/include/linux/lockdep.h)

use crate::types::Opaque;

/// Represents a lockdep class. It's a wrapper around C's `lock_class_key`.
#[repr(transparent)]
pub struct LockClassKey(Opaque<bindings::lock_class_key>);

// SAFETY: `bindings::lock_class_key` is designed to be used concurrently from multiple threads and
// provides its own synchronization.
unsafe impl Sync for LockClassKey {}

impl LockClassKey {
    /// Returns a raw pointer to the lock class key.
    pub fn as_ptr(&self) -> *mut bindings::lock_class_key {
        self.0.get()
    }
}

/// Defines a new static lock class and returns a pointer to it.
#[doc(hidden)]
#[macro_export]
macro_rules! static_lock_class {
    () => {{
        static CLASS: $crate::sync::LockClassKey =
            // SAFETY: lockdep expects uninitialized memory when it's handed a statically allocated
            // lock_class_key
            unsafe { ::core::mem::MaybeUninit::uninit().assume_init() };
        &CLASS
    }};
}
pub use static_lock_class;

/// Returns the given string, if one is provided, otherwise generates one based on the source code
/// location.
#[doc(hidden)]
#[macro_export]
macro_rules! optional_name {
    () => {
        $crate::c_str!(::core::concat!(::core::file!(), ":", ::core::line!()))
    };
    ($name:literal) => {
        $crate::c_str!($name)
    };
}

/// Not checked, catch all.
pub const LD_WAIT_INV: u8 = bindings::lockdep_wait_type_LD_WAIT_INV as u8;
/// Spin loops, `raw_spinlock_t` etc
pub const LD_WAIT_SPIN: u8 = bindings::lockdep_wait_type_LD_WAIT_SPIN as u8;

/// Helper for declaring a raw `struct lockdep_map` for locks in statics.
///
/// It's up to the caller to use the returned `struct lockdep_map` correctly.
#[cfg(CONFIG_DEBUG_LOCK_ALLOC)]
pub(crate) const fn raw_lockdep_map(
    name: &'static crate::str::CStr,
    wait_type_inner: u8,
    wait_type_outer: u8,
) -> bindings::lockdep_map {
    // SAFETY: All zeros is valid for this type.
    let mut map: bindings::lockdep_map = unsafe { core::mem::zeroed() };
    map.name = name.as_char_ptr();
    map.wait_type_inner = wait_type_inner;
    map.wait_type_outer = wait_type_outer;
    map
}
