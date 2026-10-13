// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Google LLC.

//! Support for anon-inode devices.
//!
//! C headers: [`include/linux/anon_inodes.h`](srctree/include/linux/anon_inodes.h).

use crate::{
    bindings, build_error,
    error::{from_err_ptr, VTABLE_DEFAULT_ERROR},
    fs::{file::Offset, File},
    mm::virt::VmaNew,
    prelude::*,
    seq_file::SeqFile,
    types::{ARef, ForeignOwnable},
};
use core::{marker::PhantomData, mem::MaybeUninit};

/// Trait implemented by the private data of an anon-inode device.
#[vtable]
pub trait AnonInodeFileInterface: Sized {
    /// What kind of pointer should `Self` be wrapped in.
    type Ptr: ForeignOwnable + Send + Sync;

    /// Called when the device is released.
    fn release(device: Self::Ptr, _file: &File) {
        drop(device);
    }

    /// Handler for llseek.
    ///
    fn llseek(
        _device: <Self::Ptr as ForeignOwnable>::Borrowed<'_>,
        _offs: Offset,
        _whence: ffi::c_int,
    ) -> Result<Offset> {
        build_error!(VTABLE_DEFAULT_ERROR)
    }

    /// Handler for mmap.
    ///
    /// This function is invoked when a user space process invokes the `mmap` system call on
    /// `file`. The function is a callback that is part of the VMA initializer. The kernel will do
    /// initial setup of the VMA before calling this function. The function can then interact with
    /// the VMA initialization by calling methods of `vma`. If the function does not return an
    /// error, the kernel will complete initialization of the VMA according to the properties of
    /// `vma`.
    fn mmap(
        _device: <Self::Ptr as ForeignOwnable>::Borrowed<'_>,
        _file: &File,
        _vma: &VmaNew,
    ) -> Result {
        build_error!(VTABLE_DEFAULT_ERROR)
    }

    /// Handler for ioctls.
    ///
    /// The `cmd` argument is usually manipulated using the utilities in [`kernel::ioctl`].
    ///
    /// [`kernel::ioctl`]: mod@crate::ioctl
    fn ioctl(
        _device: <Self::Ptr as ForeignOwnable>::Borrowed<'_>,
        _file: &File,
        _cmd: u32,
        _arg: usize,
    ) -> Result<isize> {
        build_error!(VTABLE_DEFAULT_ERROR)
    }

    /// Handler for ioctls.
    ///
    /// Used for 32-bit userspace on 64-bit platforms.
    ///
    /// This method is optional and only needs to be provided if the ioctl relies on structures
    /// that have different layout on 32-bit and 64-bit userspace. If no implementation is
    /// provided, then `compat_ptr_ioctl` will be used instead.
    #[cfg(CONFIG_COMPAT)]
    fn compat_ioctl(
        _device: <Self::Ptr as ForeignOwnable>::Borrowed<'_>,
        _file: &File,
        _cmd: u32,
        _arg: usize,
    ) -> Result<isize> {
        build_error!(VTABLE_DEFAULT_ERROR)
    }

    #[cfg(CONFIG_PROC_FS)]
    /// Show info for this fd.
    fn show_fdinfo(
        _device: <Self::Ptr as ForeignOwnable>::Borrowed<'_>,
        _m: &SeqFile,
        _file: &File,
    ) {
        build_error!(VTABLE_DEFAULT_ERROR)
    }
}

/// A vtable for the file operations of a Rust AnonInodeDevice.
pub struct AnonInodeFileVTable<T: AnonInodeFileInterface> {
    fops: bindings::file_operations,
    _marker: PhantomData<T>,
}

// SAFETY: `file_operations` contains only function pointers and module metadata.
unsafe impl<T: AnonInodeFileInterface> Sync for AnonInodeFileVTable<T> {}

impl<T: AnonInodeFileInterface> AnonInodeFileVTable<T> {
    /// Creates an `AnonInodeFileVTable`.
    pub const fn new(owner: &'static ThisModule) -> Self {
        Self {
            fops: bindings::file_operations {
                owner: owner.as_ptr(),
                release: Some(Self::release),
                llseek: if T::HAS_LLSEEK {
                    Some(Self::llseek)
                } else {
                    None
                },
                mmap: if T::HAS_MMAP { Some(Self::mmap) } else { None },
                unlocked_ioctl: if T::HAS_IOCTL {
                    Some(Self::ioctl)
                } else {
                    None
                },
                #[cfg(CONFIG_COMPAT)]
                compat_ioctl: if T::HAS_COMPAT_IOCTL {
                    Some(Self::compat_ioctl)
                } else if T::HAS_IOCTL {
                    Some(bindings::compat_ptr_ioctl)
                } else {
                    None
                },
                #[cfg(CONFIG_PROC_FS)]
                show_fdinfo: if T::HAS_SHOW_FDINFO {
                    Some(Self::show_fdinfo)
                } else {
                    None
                },
                // SAFETY: All zeros is a valid value for `bindings::file_operations`.
                ..unsafe { MaybeUninit::zeroed().assume_init() }
            },
            _marker: PhantomData,
        }
    }

    /// If `file` was created using this `AnonInodeFileVTable`, returns a borrow of its
    /// private data `T::Ptr`.
    pub fn borrow_private<'a>(
        &'static self,
        file: &'a File,
    ) -> Option<<T::Ptr as ForeignOwnable>::Borrowed<'a>> {
        // SAFETY: `file.as_ptr()` is a valid pointer to `struct file`.
        let f_op = unsafe { (*file.as_ptr()).f_op };
        if !core::ptr::eq(f_op, &self.fops) {
            return None;
        }

        // SAFETY: Because `f_op` points to `self.fops` (which is private and only attached to
        // files in `anon_inode_create_getfile`), `private_data` is guaranteed to be a valid
        // pointer produced by `T::Ptr::into_foreign()` that remains alive while `file` is live.
        let private = unsafe { (*file.as_ptr()).private_data };
        Some(unsafe { <T::Ptr as ForeignOwnable>::borrow(private.cast()) })
    }

    /// # Safety
    ///
    /// `file` and `inode` must be the file and inode for a file that is being released. The file
    /// must have been created via "anon_inode_create_getfile".
    unsafe extern "C" fn release(
        _inode: *mut bindings::inode,
        file: *mut bindings::file,
    ) -> ffi::c_int {
        // SAFETY: By the safety contract of this function, `file` is valid. The release call of a
        // file owns the private data.
        let private = unsafe { (*file).private_data };

        // SAFETY: This file was created via `anon_inode_create_getfile`, which set `private_data`
        // to a pointer from `T::Ptr::into_foreign`. The release call of a file owns the private
        // data and is called only once, so we can safely reclaim ownership.
        let ptr = unsafe { <T::Ptr as ForeignOwnable>::from_foreign(private) };

        // SAFETY:
        // * The file is valid for the duration of this call.
        // * There is no active fdget_pos region on the file on this thread.
        T::release(ptr, unsafe { File::from_raw_file(file) });

        0
    }

    /// # Safety
    ///
    /// `file` must be a valid file created via "anon_inode_create_getfile".
    unsafe extern "C" fn llseek(
        file: *mut bindings::file,
        offs: Offset,
        whence: ffi::c_int,
    ) -> Offset {
        // SAFETY: By the safety contract of this function, `file` is valid. The llseek call of a
        // file can access the private data.
        let private = unsafe { (*file).private_data };
        // SAFETY: This file was created via `anon_inode_create_getfile`, so `into_foreign` was
        // called in `anon_inode_create_getfile` and `from_foreign` will be called in `release`,
        // and `llseek` is guaranteed to be called between those two operations.
        let device = unsafe { <T::Ptr as ForeignOwnable>::borrow(private.cast()) };
        match T::llseek(device, offs, whence) {
            Ok(pos) => pos,
            Err(err) => err.to_errno().into(),
        }
    }

    /// # Safety
    ///
    /// `file` must be a valid file created via "anon_inode_create_getfile".
    /// `vma` must be a vma that is currently being mmap'ed with this file.
    unsafe extern "C" fn mmap(
        file: *mut bindings::file,
        vma: *mut bindings::vm_area_struct,
    ) -> ffi::c_int {
        // SAFETY: By the safety contract of this function, `file` is valid. The mmap call of a
        // file can access the private data.
        let private = unsafe { (*file).private_data };
        // SAFETY: This file was created via `anon_inode_create_getfile`, so `into_foreign` was
        // called in `anon_inode_create_getfile` and `from_foreign` will be called in `release`,
        // and `mmap` is guaranteed to be called between those two operations.
        let device = unsafe { <T::Ptr as ForeignOwnable>::borrow(private.cast()) };
        // SAFETY: By the safety contract, the caller provides a valid `vma` that is undergoing
        // initial VMA setup.
        let area = unsafe { VmaNew::from_raw(vma) };
        // SAFETY:
        // * The file is valid for the duration of this call.
        // * There is no active fdget_pos region on the file on this thread.
        let file = unsafe { File::from_raw_file(file) };

        match T::mmap(device, file, area) {
            Ok(()) => 0,
            Err(err) => err.to_errno(),
        }
    }

    /// # Safety
    ///
    /// `file` must be a valid file created via "anon_inode_create_getfile".
    unsafe extern "C" fn ioctl(
        file: *mut bindings::file,
        cmd: ffi::c_uint,
        arg: ffi::c_ulong,
    ) -> ffi::c_long {
        // SAFETY: By the safety contract of this function, `file` is valid. The ioctl call of a
        // file can access the private data.
        let private = unsafe { (*file).private_data };
        // SAFETY: This file was created via `anon_inode_create_getfile`, so `into_foreign` was
        // called in `anon_inode_create_getfile` and `from_foreign` will be called in `release`,
        // and `ioctl` is guaranteed to be called between those two operations.
        let device = unsafe { <T::Ptr as ForeignOwnable>::borrow(private.cast()) };

        // SAFETY:
        // * The file is valid for the duration of this call.
        // * There is no active fdget_pos region on the file on this thread.
        let file = unsafe { File::from_raw_file(file) };

        match T::ioctl(device, file, cmd, arg) {
            Ok(ret) => ret as ffi::c_long,
            Err(err) => err.to_errno() as ffi::c_long,
        }
    }

    /// # Safety
    ///
    /// `file` must be a valid file created via "anon_inode_create_getfile".
    #[cfg(CONFIG_COMPAT)]
    unsafe extern "C" fn compat_ioctl(
        file: *mut bindings::file,
        cmd: ffi::c_uint,
        arg: ffi::c_ulong,
    ) -> ffi::c_long {
        // SAFETY: By the safety contract of this function, `file` is valid. The compat_ioctl call
        // of a file can access the private data.
        let private = unsafe { (*file).private_data };
        // SAFETY: This file was created via `anon_inode_create_getfile`, so `into_foreign` was
        // called in `anon_inode_create_getfile` and `from_foreign` will be called in `release`,
        // and `compat_ioctl` is guaranteed to be called between those two operations.
        let device = unsafe { <T::Ptr as ForeignOwnable>::borrow(private.cast()) };

        // SAFETY:
        // * The file is valid for the duration of this call.
        // * There is no active fdget_pos region on the file on this thread.
        let file = unsafe { File::from_raw_file(file) };

        match T::compat_ioctl(device, file, cmd, arg) {
            Ok(ret) => ret as ffi::c_long,
            Err(err) => err.to_errno() as ffi::c_long,
        }
    }

    /// # Safety
    ///
    /// `file` must be a valid file created via "anon_inode_create_getfile".
    /// - `seq_file` must be a valid `struct seq_file` that we can write to.
    #[cfg(CONFIG_PROC_FS)]
    unsafe extern "C" fn show_fdinfo(seq_file: *mut bindings::seq_file, file: *mut bindings::file) {
        // SAFETY: By the safety contract of this function, `file` is valid. The show_fdinfo call
        // of a file can access the private data.
        let private = unsafe { (*file).private_data };
        // SAFETY: This file was created via `anon_inode_create_getfile`, so `into_foreign` was
        // called in `anon_inode_create_getfile` and `from_foreign` will be called in `release`,
        // and `show_fdinfo` is guaranteed to be called between those two operations.
        let device = unsafe { <T::Ptr as ForeignOwnable>::borrow(private.cast()) };

        // SAFETY:
        // * The file is valid for the duration of this call.
        // * There is no active fdget_pos region on the file on this thread.
        let file = unsafe { File::from_raw_file(file) };
        // SAFETY: The caller ensures that the pointer is valid and exclusive for the duration in
        // which this method is called.
        let m = unsafe { SeqFile::from_raw(seq_file) };

        T::show_fdinfo(device, m, file);
    }
}

/// Creates a new file hooking it on a new !S_PRIVATE anon inode.
pub fn anon_inode_create_getfile<T: AnonInodeFileInterface>(
    name: &CStr,
    ptr: T::Ptr,
    flags: u32,
    vtable: &'static AnonInodeFileVTable<T>,
) -> Result<ARef<File>, (Error, T::Ptr)> {
    let priv_data = ptr.into_foreign();

    // SAFETY:
    // * `name` is a valid NUL-terminated C string.
    // * `AnonInodeFileVTable::<T>::build()` returns a valid static `file_operations` table.
    // * `priv_data` is a foreign pointer from `T::Ptr::into_foreign` whose ownership is
    //   transferred to the file on success (and freed in `release`) or reclaimed on error.
    // * `context_inode` is optional and may be NULL.
    let raw_file_or_err = from_err_ptr(unsafe {
        bindings::anon_inode_create_getfile(
            name.as_ptr().cast(),
            &vtable.fops,
            priv_data,
            flags as i32,
            core::ptr::null(), // context_inode
        )
    });

    match raw_file_or_err {
        Err(err) => {
            // Convert foreign-owned pointer back to a rust-owned one.
            // SAFETY: `priv_data` was created by `ptr.into_foreign()` above, and since
            // `anon_inode_create_getfile` failed, the kernel did not take ownership of it and
            // `release` will not be called.
            let ptr = unsafe { <T::Ptr as ForeignOwnable>::from_foreign(priv_data) };
            Err((err, ptr))
        }

        Ok(raw_file) => {
            // SAFETY:
            // * `raw_file` is a valid pointer to a newly created file with a positive refcount.
            // * The file is newly created and not in any fd table, so there is no active
            //   `fdget_pos` region on this file.
            let file: &File = unsafe { File::from_raw_file(raw_file) };

            // SAFETY: `anon_inode_create_getfile` returns a file with an initial reference count
            // of 1 owned by the caller, and `ARef::from_raw` takes ownership of this reference.
            let file_ref = unsafe { ARef::from_raw(file.into()) };

            Ok(file_ref)
        }
    }
}
