// SPDX-License-Identifier: GPL-2.0

//! DMA-BUF abstractions.
//!
//! C header: [`include/linux/dma-buf.h`](srctree/include/linux/dma-buf.h)

use crate::{
    bindings,
    device::Device,
    dma::DataDirection,
    error::{from_err_ptr, to_result},
    fs::File,
    prelude::*,
    types::{ARef, AlwaysRefCounted, Opaque},
};
use core::{
    marker::PhantomData,
    ptr::{self, NonNull},
};

/// A wrapper for the kernel's `struct dma_buf`.
///
/// # Invariants
///
/// The dma-buf is always refcounted.
#[repr(transparent)]
pub struct DmaBuf(Opaque<bindings::dma_buf>);

// SAFETY: `DmaBuf` is reference counted and internally synchronized.
unsafe impl Send for DmaBuf {}
// SAFETY: `DmaBuf` is reference counted and internally synchronized.
unsafe impl Sync for DmaBuf {}

// SAFETY: The reference count is managed by `get_dma_buf` and `dma_buf_put`.
unsafe impl AlwaysRefCounted for DmaBuf {
    fn inc_ref(&self) {
        // SAFETY: By the type invariants, the dma-buf is refcounted.
        unsafe { bindings::get_dma_buf(self.as_ptr()) };
    }

    unsafe fn dec_ref(obj: NonNull<Self>) {
        // SAFETY: The type invariant guarantees that `obj` is valid, and the safety requirement
        // of `dec_ref` guarantees that we own a reference.
        unsafe { bindings::dma_buf_put(obj.as_ptr().cast()) };
    }
}

impl PartialEq for DmaBuf {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.as_ptr(), other.as_ptr())
    }
}
impl Eq for DmaBuf {}

impl DmaBuf {
    /// Get a `DmaBuf` from a file descriptor.
    pub fn get(fd: i32) -> Result<ARef<DmaBuf>> {
        // SAFETY: `dma_buf_get` is safe to call with any integer.
        let ptr = unsafe { bindings::dma_buf_get(fd) };
        let ptr = from_err_ptr(ptr)?;

        let non_null = NonNull::new(ptr).ok_or(EBADF)?;

        // SAFETY: `from_err_ptr` guarantees that `ptr` is not an error pointer.
        // We own the reference count returned by `dma_buf_get` and transfer it to `ARef`.
        Ok(unsafe { ARef::from_raw(non_null.cast()) })
    }

    /// Create a file descriptor for this `DmaBuf`.
    ///
    /// This consumes the `ARef<DmaBuf>` because the file descriptor takes ownership of the
    /// reference.
    pub fn into_fd(this: ARef<Self>, flags: i32) -> Result<i32> {
        let ptr = ARef::into_raw(this);
        // SAFETY: `ptr` is valid as it comes from `ARef`.
        let fd = unsafe { bindings::dma_buf_fd(ptr.as_ptr().cast(), flags) };
        if fd < 0 {
            // SAFETY: `ptr` was returned by `into_raw` and we haven't dropped it yet.
            drop(unsafe { ARef::from_raw(ptr) });
            Err(Error::from_errno(fd))
        } else {
            Ok(fd)
        }
    }

    /// Returns a raw pointer to the dma-buf.
    #[inline]
    pub fn as_ptr(&self) -> *mut bindings::dma_buf {
        self.0.get()
    }

    /// Attach a device to this `DmaBuf`.
    pub fn attach(&self, dev: &Device) -> Result<DmaBufAttachment> {
        // SAFETY: It's safe to attach any dma-buf with any device.
        let ptr = unsafe { bindings::dma_buf_attach(self.as_ptr(), dev.as_raw()) };
        let ptr = from_err_ptr(ptr)?;

        // INVARIANT: We created an attachment above, and it's associated with the right dma-buf.
        Ok(DmaBufAttachment {
            ptr: NonNull::new(ptr).ok_or(EINVAL)?,
            dmabuf: ARef::from(self),
        })
    }

    /// Map the DMA-BUF into kernel virtual address space.
    pub fn vmap(&self) -> Result<DmaBufVmap> {
        let mut map = bindings::iosys_map::default();
        // SAFETY: It's safe to create a vmap for any dma-buf. `&mut map` is valid for writing.
        let ret = unsafe { bindings::dma_buf_vmap_unlocked(self.as_ptr(), &raw mut map) };
        to_result(ret)?;

        let dmabuf = ARef::from(self);

        // INVARIANT: We created the vmap above, and it's associated with the right dma-buf.
        Ok(DmaBufVmap { dmabuf, map })
    }

    /// Returns the size of the DMA-BUF in bytes.
    #[inline]
    pub fn size(&self) -> usize {
        // SAFETY: A dma-buf's size cannot change.
        unsafe { (*self.as_ptr()).size }
    }

    /// Returns the underlying file.
    pub fn file(&self) -> &File {
        // SAFETY: `self.opaque.get()` is valid.
        unsafe { File::from_raw_file((*self.as_ptr()).file) }
    }
}

/// A wrapper for the kernel's `struct dma_buf_attachment`.
///
/// # Invariants
///
/// Owns a valid dma-buf attachment associated with the inner dma-buf.
pub struct DmaBufAttachment {
    ptr: NonNull<bindings::dma_buf_attachment>,
    dmabuf: ARef<DmaBuf>,
}

// SAFETY: `DmaBufAttachment` is safe to send to other threads.
unsafe impl Send for DmaBufAttachment {}
// SAFETY: `DmaBufAttachment` is safe to share between threads.
unsafe impl Sync for DmaBufAttachment {}

impl DmaBufAttachment {
    /// Map the attachment.
    pub fn map(self, dir: DataDirection) -> Result<DmaBufMapping> {
        // SAFETY: A DmaBufAttachment contains a valid attachment.
        let sgt =
            unsafe { bindings::dma_buf_map_attachment_unlocked(self.ptr.as_ptr(), dir.into()) };
        let sgt = from_err_ptr(sgt)?;
        let non_null = NonNull::new(sgt).ok_or(EINVAL)?;

        // INVARIANT: Mapping an attachment produces a valid sg-table.
        Ok(DmaBufMapping {
            attachment: self,
            sgt: non_null,
            dir,
        })
    }
}

impl Drop for DmaBufAttachment {
    fn drop(&mut self) {
        // SAFETY: We own the attachment, and this is the right dma-buf, so we can detach it.
        unsafe { bindings::dma_buf_detach(self.dmabuf.as_ptr(), self.ptr.as_ptr()) };
    }
}

/// A wrapper for an active DMA-BUF mapping.
///
/// # Invariants
///
/// - `sgt` is a valid sg-table.
/// - `sgt` was obtained by mapping `attachment` with direction `dir`.
pub struct DmaBufMapping {
    attachment: DmaBufAttachment,
    sgt: NonNull<bindings::sg_table>,
    dir: DataDirection,
}

// SAFETY: `DmaBufMapping` is safe to send to other threads.
unsafe impl Send for DmaBufMapping {}
// SAFETY: `DmaBufMapping` is safe to share between threads.
unsafe impl Sync for DmaBufMapping {}

impl Drop for DmaBufMapping {
    fn drop(&mut self) {
        // SAFETY: This is a valid sg-table and attachment that are associated with each other, and
        // we own the sg-table so we can give it up.
        unsafe {
            bindings::dma_buf_unmap_attachment_unlocked(
                self.attachment.ptr.as_ptr(),
                self.sgt.as_ptr(),
                self.dir.into(),
            )
        };
    }
}

/// A wrapper for an active DMA-BUF virtual mapping.
///
/// # Invariants
///
/// `map` is a valid `struct iosys_map` populated by `dma_buf_vmap_unlocked`.
pub struct DmaBufVmap {
    dmabuf: ARef<DmaBuf>,
    map: bindings::iosys_map,
}

// SAFETY: `DmaBufVmap` is safe to send to other threads.
unsafe impl Send for DmaBufVmap {}
// SAFETY: `DmaBufVmap` is safe to share between threads.
unsafe impl Sync for DmaBufVmap {}

impl DmaBufVmap {
    /// Returns the underlying [`DmaBuf`] that this mapping belongs to.
    #[inline]
    pub fn dmabuf(&self) -> &DmaBuf {
        &self.dmabuf
    }

    /// Returns the virtual address of the mapping if it is not in I/O memory.
    #[inline]
    pub fn vaddr(&self) -> Option<NonNull<crate::ffi::c_void>> {
        if self.map.is_iomem {
            None
        } else {
            // SAFETY: `self.map.__bindgen_anon_1.vaddr` is valid if `is_iomem` is false.
            let vaddr = unsafe { self.map.__bindgen_anon_1.vaddr };
            NonNull::new(vaddr)
        }
    }

    /// Internal helper for cpu access.
    fn begin_cpu_access<const READ: bool, const WRITE: bool, F>(&self, f: F) -> Result
    where
        F: FnOnce(CpuAccess<'_, READ, WRITE>),
    {
        let dir = const {
            match (READ, WRITE) {
                (false, false) => DataDirection::None,
                (false, true) => DataDirection::ToDevice,
                (true, false) => DataDirection::FromDevice,
                (true, true) => DataDirection::Bidirectional,
            }
        };
        let mut map = self.map;
        // SAFETY: It's always safe to begin cpu access.
        to_result(unsafe { bindings::dma_buf_begin_cpu_access(self.dmabuf.as_ptr(), dir.into()) })?;
        // INVARIANT: Cpu access has begin with the given direction.
        f(CpuAccess {
            map: &raw mut map,
            size: self.dmabuf.size(),
            _lifetime: PhantomData,
        });
        // SAFETY: We started cpu access, so we can end it.
        to_result(unsafe { bindings::dma_buf_end_cpu_access(self.dmabuf.as_ptr(), dir.into()) })?;
        Ok(())
    }

    /// Perform cpu-access that only writes to the device.
    pub fn begin_cpu_access_to<F>(&self, f: F) -> Result
    where
        F: FnOnce(CpuAccess<'_, false, true>),
    {
        self.begin_cpu_access(f)
    }

    /// Perform cpu-access that only reads from the device.
    pub fn begin_cpu_access_from<F>(&self, f: F) -> Result
    where
        F: FnOnce(CpuAccess<'_, true, false>),
    {
        self.begin_cpu_access(f)
    }

    /// Perform bidirectional cpu-access.
    pub fn begin_cpu_access_bidirectional<F>(&self, f: F) -> Result
    where
        F: FnOnce(CpuAccess<'_, true, true>),
    {
        self.begin_cpu_access(f)
    }
}

impl Drop for DmaBufVmap {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: This is a valid vmap that are associated with the dma-buf. We own the vmap so we
        // can unmap it.
        unsafe { bindings::dma_buf_vunmap_unlocked(self.dmabuf.as_ptr(), &mut self.map) };
    }
}

/// A reference for CPU access to a `DmaBuf`.
///
/// # Invariants
///
/// The iosys map references a vmap with cpu access enabled in the listed directions.
pub struct CpuAccess<'access, const READ: bool, const WRITE: bool> {
    map: *mut bindings::iosys_map,
    size: usize,
    _lifetime: PhantomData<&'access DmaBufVmap>,
}

impl<'a, const READ: bool> CpuAccess<'a, READ, true> {
    /// Copies data from `src` into the buffer at `offset`.
    #[inline]
    #[track_caller]
    pub fn memcpy_to(&mut self, offset: usize, src: &[u8]) {
        let (end, end_overflow) = offset.overflowing_add(src.len());
        if end_overflow || end > self.size {
            panic!(
                "memcpy_to of {} bytes at {offset} in dma-buf of {} bytes out of bounds",
                src.len(),
                self.size
            );
        }
        // SAFETY: The bounds check ensures we don't write out of bounds. The guard has WRITE
        // enabled.
        unsafe { bindings::iosys_map_memcpy_to(self.map, offset, src.as_ptr().cast(), src.len()) };
    }
}

impl<'a, const WRITE: bool> CpuAccess<'a, true, WRITE> {
    /// Copies data from the buffer at `offset` into `dst`.
    #[inline]
    #[track_caller]
    pub fn memcpy_from(&mut self, dst: &mut [u8], offset: usize) {
        let (end, end_overflow) = offset.overflowing_add(dst.len());
        if end_overflow || end > self.size {
            panic!(
                "memcpy_from of {} bytes at {offset} in dma-buf of {} bytes out of bounds",
                dst.len(),
                self.size
            );
        }
        // SAFETY: The bounds check ensures we don't write out of bounds. The guard has READ
        // enabled.
        unsafe {
            bindings::iosys_map_memcpy_from(dst.as_mut_ptr().cast(), self.map, offset, dst.len())
        };
    }
}
