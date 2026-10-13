// SPDX-License-Identifier: GPL-2.0

//! A kernel spinlock to be used in irq contexts.
//!
//! This module allows Rust code to use the kernel's `spinlock_t`.

use super::LockClassKey;
use crate::{
    str::CStr,
    types::{NotThreadSafe, Opaque},
};
use core::{cell::UnsafeCell, marker::PhantomPinned, pin::Pin};
use pin_init::{pin_data, pin_init, PinInit};

/// Creates a [`SpinLock`] initialiser with the given name and a newly-created lock class.
///
/// It uses the name if one is given, otherwise it generates one based on the file name and line
/// number.
#[macro_export]
macro_rules! new_spinlock_irq {
    ($inner:expr $(, $name:literal)? $(,)?) => {
        $crate::sync::SpinLockIrq::new(
            $inner, $crate::optional_name!($($name)?), $crate::static_lock_class!())
    };
}
pub use new_spinlock_irq;

/// A spinlock to be used in an IRQ context.
///
/// Exposes the kernel's [`spinlock_t`]. When multiple CPUs attempt to lock the same spinlock, only
/// one at a time is allowed to progress, the others will block (spinning) until the spinlock is
/// unlocked, at which point another CPU will be allowed to make progress.
///
/// Instances of [`SpinLockIrq`] need a lock class and to be pinned. The recommended way to create
/// such instances is with the [`pin_init`](pin_init::pin_init) and [`new_spinlock_irq`] macros.
///
/// # Examples
///
/// The following example shows how to declare, allocate and initialise a struct (`Example`) that
/// contains an inner struct (`Inner`) that is protected by a spinlock.
///
/// ```
/// use kernel::sync::{new_spinlock_irq, SpinLockIrq};
///
/// struct Inner {
///     a: u32,
///     b: u32,
/// }
///
/// #[pin_data]
/// struct Example {
///     c: u32,
///     #[pin]
///     d: SpinLock<Inner>,
/// }
///
/// impl Example {
///     fn new() -> impl PinInit<Self> {
///         pin_init!(Self {
///             c: 10,
///             d <- new_spinlock_irq!(Inner { a: 20, b: 30 }),
///         })
///     }
/// }
///
/// // Allocate a boxed `Example`.
/// let e = KBox::pin_init(Example::new(), GFP_KERNEL)?;
/// assert_eq!(e.c, 10);
/// assert_eq!(e.d.lock().a, 20);
/// assert_eq!(e.d.lock().b, 30);
/// # Ok::<(), Error>(())
/// ```
///
/// The following example shows how to use interior mutability to modify the contents of a struct
/// protected by a spinlock despite only having a shared reference:
///
/// ```
/// use kernel::sync::SpinLockIrq;
///
/// struct Example {
///     a: u32,
///     b: u32,
/// }
///
/// fn example(m: &SpinLockIrq<Example>) {
///     m.lock_irq(|guard| {
///         guard.a += 10;
///         guard.b += 20;
///     }
/// }
/// ```
///
/// [`spinlock_t`]: srctree/include/linux/spinlock.h
#[repr(C)]
#[pin_data]
pub struct SpinLockIrq<T> {
    #[pin]
    state: Opaque<bindings::spinlock_t>,
    #[pin]
    _pin: PhantomPinned,

    /// The data protected by the lock.
    pub(crate) data: UnsafeCell<T>,
}

// SAFETY: `SpinLockIrq` can be transferred across thread boundaries iff the data it protects can.
unsafe impl<T: Send> Send for SpinLockIrq<T> {}

// SAFETY: `SpinLockIrq` serialises the interior mutability it provides, so it is `Sync` as long as
// the data it protects is `Send`.
unsafe impl<T: Send> Sync for SpinLockIrq<T> {}

impl<T> SpinLockIrq<T> {
    /// Constructs a new SpinLockIrq initialiser.
    pub fn new(t: T, name: &'static CStr, key: Pin<&'static LockClassKey>) -> impl PinInit<Self> {
        pin_init!(Self {
            data: UnsafeCell::new(t),
            _pin: PhantomPinned,
            // SAFETY: `slot` is valid while the closure is called and both `name` and `key` have
            // static lifetimes so they live indefinitely.
            state <- Opaque::ffi_init(|slot| unsafe {
                bindings::__spin_lock_init(slot, name.as_char_ptr(), key.as_ptr())
            }),
        })
    }

    #[inline]
    unsafe fn assert_is_held(ptr: *mut bindings::spinlock_t) {
        // SAFETY: The `ptr` pointer is guaranteed to be valid and initialized before use.
        unsafe { bindings::spin_assert_is_held(ptr) }
    }
}

/// A lock guard for a SpinLockIrq held through `lock_irq` inside an IRQ handler.
///
/// Unlike the generic lock guard `Guard`, this does _not_ automatically unlock the spinlock
/// when it's dropped, but simply allows access to the wrapped data through Deref and DerefMut
/// traits.
pub struct SpinLockIrqGuard<'a, T> {
    lock: &'a SpinLockIrq<T>,
    _not_send: NotThreadSafe,
}

// SAFETY: `SpinLockIrqGuard` is sync when the data protected by the lock is also sync.
unsafe impl<T: Sync> Sync for SpinLockIrqGuard<'_, T> {}

impl<'a, T> core::ops::Deref for SpinLockIrqGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: The caller owns the lock, so it is safe to deref the protected data.
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> core::ops::DerefMut for SpinLockIrqGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: The caller owns the lock, so it is safe to deref the protected data.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> SpinLockIrqGuard<'a, T> {
    #[inline]
    unsafe fn new(lock: &'a SpinLockIrq<T>) -> Self {
        // SAFETY: The caller can only hold the lock if `SpinLockBackend::init` has already been
        // called.
        unsafe { SpinLockIrq::<T>::assert_is_held(lock.state.get()) };

        Self {
            lock,
            _not_send: NotThreadSafe,
        }
    }
}

impl<T> SpinLockIrq<T> {
    /// Holds the spinlock inside an irq handler for the duration of the function `f`.
    /// `f` is passed a guard that allows access to the data wrapped by the SpinLock.
    pub fn lock_irq<F, R>(&self, f: F) -> R
    where
        F: FnOnce(SpinLockIrqGuard<'_, T>) -> R,
    {
        let flags = unsafe { bindings::spin_lock_irqsave(self.state.get()) };

        // SAFETY: We have just acquired the spinlock, so it's safe to create the guard.
        let res = unsafe { f(SpinLockIrqGuard::new(self)) };

        unsafe {
            bindings::spin_unlock_irqrestore(self.state.get(), flags);
        }

        res
    }
}
