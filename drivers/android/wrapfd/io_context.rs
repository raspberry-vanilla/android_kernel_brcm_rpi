// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Google LLC.

use core::{marker::PhantomPinned, ops::Deref, ops::DerefMut, ptr::NonNull};

use crate::module_parameters;

use kernel::{
    alloc::{AllocError, Flags},
    bindings,
    dma_buf::{CpuAccess, DmaBufVmap},
    ffi,
    fs::LocalFile,
    new_spinlock_irq,
    page::{
        is_page_aligned, offset_in_page, page_align, page_align_down, Page, PAGE_MASK, PAGE_SIZE,
    },
    prelude::*,
    sync::{Arc, SpinLockIrq},
    types::{ARef, Opaque},
};

/// A low-memory page, zero-initialized on allocation.
struct InitializedPage(Page);

impl InitializedPage {
    fn alloc_page(flags: Flags) -> Result<Self, AllocError> {
        // Passing `__GFP_ZERO` causes the allocator to zero-initialize the page's contents,
        // having the page's contents initialized is crucial in being able to access it through
        // refs/slices.
        // We also want a lowmem-page so that it's permanently mapped for its lifetime.
        let page = Page::alloc_page((flags | __GFP_ZERO) & !__GFP_HIGHMEM)?;
        Ok(Self(page))
    }
}

impl Deref for InitializedPage {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let base_address = unsafe { bindings::lowmem_page_address(self.0.as_ptr()) };
        // SAFETY: base_address is the address of an initialized low-memory page.
        unsafe { core::slice::from_raw_parts(base_address.cast(), PAGE_SIZE) }
    }
}

impl DerefMut for InitializedPage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let base_address = unsafe { bindings::lowmem_page_address(self.0.as_ptr()) };
        // SAFETY: base_address is the address of an initialized low-memory page.
        unsafe { core::slice::from_raw_parts_mut(base_address.cast(), PAGE_SIZE) }
    }
}

fn get_free_page() -> Result<InitializedPage> {
    Ok(InitializedPage::alloc_page(GFP_KERNEL)?)
}

// 1 buffer for the start, and at most 2 at the end.
const MAX_NR_BOUNCE_BUFS: usize = 3;

// 1 per bounce page (3), and 1 for content read directly into the buffer.
const MAX_NR_KVECS: usize = MAX_NR_BOUNCE_BUFS + 1;

struct DataSegment {
    offs: usize,
    len: usize,
}

impl DataSegment {
    fn new(offs: usize, len: usize) -> Self {
        Self { offs, len }
    }
}

struct IoResults {
    io_ret: ffi::c_long,
    bytes_read: usize,
    nr_reqs: usize,
}

#[pin_data]
struct SharedContext {
    #[pin]
    io_done: Opaque<bindings::completion>,

    #[pin]
    inner: SpinLockIrq<IoResults>,

    #[pin]
    _pin: PhantomPinned,
}

impl SharedContext {
    fn new(nr_reqs: usize) -> impl PinInit<Self> {
        pin_init!(Self {
            io_done <- Opaque::ffi_init(|slot| {
                // SAFETY: `slot` points to valid, properly aligned, uninitialized memory for a
                // `struct completion` provided by `Opaque::ffi_init`. `init_completion` safely
                // initializes it in place.
                unsafe { bindings::init_completion(slot) }
            }),
            inner <- new_spinlock_irq!(IoResults {
                io_ret: 0,
                bytes_read: 0,
                nr_reqs
            }),
            _pin: PhantomPinned,
        })
    }
}

#[pin_data]
struct IoRequest {
    shared_context: Arc<SharedContext>,

    #[pin]
    kiocb: Opaque<bindings::kiocb>,

    iter: bindings::iov_iter,
    iov: [bindings::kvec; MAX_NR_KVECS],
    file_seg: DataSegment,

    #[pin]
    _pin: PhantomPinned,
}

impl IoRequest {
    fn new<'a>(
        shared_context: Arc<SharedContext>,
        file: &'a LocalFile,
        req_file_offs: usize,
        req_len: usize,
        nr_segs: usize,
        iov: [bindings::kvec; MAX_NR_KVECS],
    ) -> impl PinInit<Self> + use<'a> {
        pin_init!(Self {
            shared_context,
            kiocb <- Opaque::ffi_init(|slot| {
                // SAFETY: `slot` points to valid, properly aligned, uninitialized memory for a
                // `struct kiocb` provided by `Opaque::ffi_init`, and `file.as_ptr()` is a valid
                // pointer to a live `struct file` kept alive across I/O via `ARef<LocalFile>`.
                unsafe { bindings::init_sync_kiocb(slot, file.as_ptr()) };

                // SAFETY: `slot` was just initialized above via `init_sync_kiocb`, so it points
                // to a valid `struct kiocb` to which we have exclusive access during init.
                unsafe {
                    (*slot).ki_pos = req_file_offs as i64;
                }

                // SAFETY: `slot` points to a valid, initialized `struct kiocb` with exclusive
                // access. `Self::async_io_complete` has the signature expected by `ki_complete`.
                unsafe {
                    (*slot).ki_flags |= bindings::IOCB_DIRECT as i32;
                    (*slot).ki_complete = Some(Self::async_io_complete);
                }
            }),
            iter: bindings::iov_iter::default(),
            iov,
            file_seg: DataSegment::new(req_file_offs, req_len),
            _pin: PhantomPinned,
        })
        .pin_chain(move |mut request: Pin<&mut Self>| {
            // SAFETY: We only project a mutable reference to the unpinned `iter` field and do
            // not move or invalidate the pinned fields (`kiocb`, `_pin`) or `Self`.
            let iter = &mut unsafe { request.as_mut().get_unchecked_mut() }.iter;

            // SAFETY: `iter` is a valid, exclusively borrowed `struct iov_iter`. `request.iov`
            // contains `nr_segs` initialized `kvec` elements whose total length is
            // `request.file_seg.len`. Because `request` is pinned (`!Unpin`), `request.iov`
            // will remain at a stable memory address for the lifetime of `request.iter`.
            unsafe {
                bindings::iov_iter_kvec(
                    iter,
                    bindings::ITER_DEST,
                    &request.iov.as_slice()[0],
                    nr_segs,
                    request.file_seg.len,
                )
            };

            Ok(())
        })
    }

    /// # Safety
    ///
    /// - If `iocb` is non-null, it must point to a valid `struct kiocb` embedded as the `kiocb`
    ///   field of a live, pinned `IoRequest` instance.
    /// - The enclosing `IoRequest` instance must remain valid and pinned in memory at least until
    ///   `Arc::clone` completes below.
    /// - Must only be invoked once per submitted `IoRequest` while `nr_reqs > 0`.
    unsafe extern "C" fn async_io_complete(iocb: *mut bindings::kiocb, ret: ffi::c_long) {
        if iocb.is_null() {
            return;
        }

        // Opaque<T> is #[repr(transparent)], so *mut T and *mut Opaque<T> have the same
        // memory representation.
        let opaque_ptr = iocb.cast::<Opaque<bindings::kiocb>>();
        let io_params_ptr = kernel::container_of!(opaque_ptr, Self, kiocb);

        // SAFETY: Per function safety contract, `iocb` is embedded within a live `IoRequest`
        // instance (`Self`), so `io_params_ptr` points to a valid, initialized `IoRequest`.
        // Because `nr_reqs > 0` prior to locking below, `IoContext::read` is still blocked in
        // `wait_for_completion` and cannot have dropped `IoRequest`.
        let shared_context = unsafe { &(*io_params_ptr).shared_context };

        // We're cloning `shared_context` here so we can be sure it'll be valid for the entire
        // duration of this function, unlike holding a reference whose underlying memory could
        // disappear in the process of executing `complete()` below.
        let shared_context = Arc::clone(shared_context);

        shared_context.inner.lock_irq(|mut guard| {
            if ret < 0 && guard.io_ret == 0 {
                guard.io_ret = ret;
            } else if ret > 0 {
                guard.bytes_read += ret as usize;
            }

            guard.nr_reqs -= 1;

            if guard.nr_reqs == 0 {
                // SAFETY: `SharedContext::io_done` is a properly initialized
                // `Opaque<bindings::completion>`, and remains valid because `shared_context`
                // holds a strong `Arc` reference across this call.
                unsafe { bindings::complete(shared_context.io_done.get()) };
            }
        });
    }
}

enum State {
    Idle,
    Prepared {
        file: ARef<LocalFile>,
        requests: KVVec<Pin<KBox<IoRequest>>>,
        shared_context: Arc<SharedContext>,
    },
    ReadDone(usize),
}

pub(crate) struct IoContext {
    bounce_bufs: KVec<InitializedPage>,
    dst_buf: NonNull<ffi::c_void>,
    start_bounce_len: usize,
    end_bounce_len: usize,
    buf_offs: usize,
    file_seg: DataSegment,
    dio_buf_seg: DataSegment,
    // The number of requests could be large, so use KVVec just in case.
    state: State,
}

fn dio_aligned_len(file_offs: usize, len: usize) -> usize {
    page_align(file_offs + len) - page_align_down(file_offs)
}

impl IoContext {
    /// # Safety
    ///
    /// The caller must guarantee that `vaddr` points to a valid, writable buffer of at least
    /// `buf_offs + len` bytes that remains allocated and valid across the call to `read()`, and
    /// matches `map.vaddr()` passed to `complete()`.
    pub(crate) unsafe fn new(
        file_offs: usize,
        vaddr: NonNull<ffi::c_void>,
        buf_offs: usize,
        len: usize,
    ) -> Result<Self> {
        /*
         * If either the file or buffer offset are unaligned, then using direct I/O into the first
         * page of the buffer will overwrite some of the data that is already there. Allocate a
         * bounce page for that scenario, and later only copy the amount of data that belongs in the
         * first page.
         */
        let (dio_buf_offs, start_bounce_len) = if !is_page_aligned(file_offs | buf_offs) {
            /*
             * The contents of interest in this bounce page will be copied to the buffer
             * starting at buf_offs after the direct I/O request completes. The amount of data
             * copied will be everything in the bounce page after file_offset bytes.
             *
             * Therefore, the next address where data needs to be read into is buf_offs +
             * (PAGE_SIZE - offset_in_page(file_offs)). However, this address may not be
             * page aligned, and therefore not suitable for direct I/O, so page align it.
             *
             * This means that the data will need to be shifted backwards if it is read into
             * the buffer directly.
             */
            (
                page_align(buf_offs + PAGE_SIZE - offset_in_page(file_offs)),
                PAGE_SIZE,
            )
        } else {
            (buf_offs, 0)
        };

        /*
         * Read as much as possible directly into the buffer without causing any overwrites beyond
         * the range we're reading into, and since direct I/O is done in units of pages,
         * ensure that there is at least a page to read.
         */
        let buf_end = buf_offs + len;

        let dio_buf_len = if buf_end >= PAGE_SIZE && dio_buf_offs <= (buf_end - PAGE_SIZE) {
            page_align_down(buf_end) - dio_buf_offs
        } else {
            0
        };

        let file_read_len = dio_aligned_len(file_offs, len);

        /*
         * Bounce the remainder, which is capped at 2 pages, since we may have shifted the data
         * earlier, because of the buffer offset by at most one page, and then any other data
         * at the tail which may cross into another page.
         */
        let end_bounce_len = file_read_len - start_bounce_len - dio_buf_len;
        if end_bounce_len > PAGE_SIZE * 2 {
            pr_warn!("end_bounce_len > PAGE_SIZE * 2\n");
        }

        let mut bounce_bufs = KVec::new();
        let nr_bounce_pages = (start_bounce_len + end_bounce_len) / PAGE_SIZE;
        for _ in 0..nr_bounce_pages {
            bounce_bufs.push(get_free_page()?, GFP_KERNEL)?;
        }

        Ok(Self {
            bounce_bufs,
            dst_buf: vaddr,
            start_bounce_len,
            end_bounce_len,
            buf_offs,
            file_seg: DataSegment::new(file_offs, len),
            dio_buf_seg: DataSegment::new(dio_buf_offs, dio_buf_len),
            state: State::Idle,
        })
    }

    fn init_io_request(
        &mut self,
        shared_context: Arc<SharedContext>,
        file: &LocalFile,
        req_file_offs: usize,
        req_len: usize,
    ) -> Result<Pin<KBox<IoRequest>>> {
        let global_file_offset = page_align_down(self.file_seg.offs);
        let global_dio_file_offset = global_file_offset + self.start_bounce_len;

        let mut nr_segs = 0;

        let mut iov = [bindings::kvec {
            iov_base: core::ptr::null_mut(),
            iov_len: 0,
        }; MAX_NR_KVECS];

        let mut remaining_req_len = req_len;
        let mut cur_file_offs = req_file_offs;

        /*
         * If there's a start bounce buffer, it's always for the first page in the overall read
         * request.
         */
        if self.start_bounce_len != 0 && cur_file_offs == global_file_offset {
            iov[nr_segs].iov_base = self.bounce_bufs[0].as_mut_ptr().cast();
            iov[nr_segs].iov_len = self.start_bounce_len;
            remaining_req_len -= self.start_bounce_len;
            cur_file_offs += self.start_bounce_len;
            nr_segs += 1;
        }

        /*
         * Handle the case where the sub-request pertains to data copied directly from the file to
         * the destination buffer.
         */
        if remaining_req_len != 0
            && self.dio_buf_seg.len != 0
            && global_dio_file_offset <= cur_file_offs
        {
            /*
             * The offset into the buffer for this request should be the base of where we start
             * reading directly into it, plus how much we've already read into the region in
             * previous requests.
             */
            // SAFETY: By the safety contract of `IoContext::new`, `self.dst_buf` points to a
            // valid allocation of at least `self.buf_offs + self.file_seg.len` bytes. Since
            // `self.dio_buf_seg` is a sub-range within that allocation and `cur_file_offs` is
            // within `[global_dio_file_offset, global_dio_file_offset + self.dio_buf_seg.len]`,
            // the computed byte offset is in bounds and does not overflow `isize::MAX`.
            iov[nr_segs].iov_base = unsafe {
                self.dst_buf
                    .as_ptr()
                    .byte_add(self.dio_buf_seg.offs + (cur_file_offs - global_dio_file_offset))
            };

            /*
             * The amount of data to read is the smaller of the two terms:
             *
             * 1. How much data is left for this request.
             * 2. How much data there is left in the file region that gets loaded directly
             * into the buffer, which is taken as the difference between the current position
             * in the file and the end of that region.
             */
            let dio_len = remaining_req_len
                .min(global_dio_file_offset + self.dio_buf_seg.len - cur_file_offs);

            iov[nr_segs].iov_len = dio_len;
            remaining_req_len -= dio_len;
            cur_file_offs += dio_len;
            nr_segs += 1;
        }

        if remaining_req_len != 0 && self.end_bounce_len != 0 {
            /*
             * The offset into the file that is copied into the end bounce buffer(s) for the
             * overall request.
             */

            let global_end_bounce_file_offs = global_file_offset
                + dio_aligned_len(self.file_seg.offs, self.file_seg.len)
                - self.end_bounce_len;

            /*
             * The last two pages in the overall read request can be bounce pages, so we
             * calculate which pages to use here. If there's a bounce page at the beginning,
             * then start at index 1.
             *
             * Since we know the file offset that corresponds to the start of the file data
             * that will be copied into the end pages and the length, we use that and our
             * current position to track which one of the end pages to use.
             */
            let mut start_bounce_idx = (if self.start_bounce_len != 0 { 1 } else { 0 })
                + (cur_file_offs - global_end_bounce_file_offs) / PAGE_SIZE;

            if remaining_req_len > PAGE_SIZE * 2 {
                pr_warn!("remaining_req_len > PAGE_SIZE * 2\n");
            }

            while remaining_req_len != 0 {
                iov[nr_segs].iov_base = self.bounce_bufs[start_bounce_idx].as_mut_ptr().cast();

                iov[nr_segs].iov_len = PAGE_SIZE;
                remaining_req_len -= PAGE_SIZE;
                nr_segs += 1;
                start_bounce_idx += 1;
            }
        }

        if remaining_req_len != 0 {
            pr_warn!("remaining_req_len != 0\n");
        }

        let request = KBox::pin_init(
            IoRequest::new(shared_context, file, req_file_offs, req_len, nr_segs, iov),
            GFP_KERNEL,
        )?;

        Ok(request)
    }

    pub(crate) fn prepare(&mut self, file: &LocalFile) -> Result<()> {
        if !matches!(self.state, State::Idle) {
            return Err(EINVAL);
        }

        /*
         * Try to split the I/O request evenly into MAX_NR_LOAD_REQS pieces, as long as each piece
         * is at least MIN_BYTES_PER_REQ in size, but no larger than MAX_RW_COUNT, since the VFS
         * layer cannot handle anything larger than that in one invocation.
         *
         * PAGE_ALIGN the length to ensure direct I/O requirements are upheld.
         */
        let mut remaining_len = dio_aligned_len(self.file_seg.offs, self.file_seg.len);

        const MAX_RW_COUNT: usize = (isize::MAX as usize) & PAGE_MASK;

        let len_per_req = page_align(
            (remaining_len / (*module_parameters::max_nr_load_reqs.value()).max(1))
                .max(*module_parameters::min_bytes_per_req.value())
                .min(MAX_RW_COUNT),
        );

        let nr_reqs = remaining_len.div_ceil(len_per_req);

        let mut cur_file_offs = page_align_down(self.file_seg.offs);

        let shared_context = Arc::pin_init(SharedContext::new(nr_reqs), GFP_KERNEL)?;

        let mut requests = KVVec::new();
        requests.reserve(nr_reqs, GFP_KERNEL)?;

        for _ in 0..nr_reqs {
            let req_len = len_per_req.min(remaining_len);
            requests.push(
                self.init_io_request(Arc::clone(&shared_context), file, cur_file_offs, req_len)?,
                GFP_KERNEL,
            )?;

            cur_file_offs += req_len;
            remaining_len -= req_len;
        }

        self.state = State::Prepared {
            file: file.into(),
            shared_context,
            requests,
        };

        Ok(())
    }

    pub(crate) fn read(&mut self) -> Result<()> {
        if !matches!(self.state, State::Prepared { .. }) {
            return Err(EINVAL);
        }

        // This contraption lets us extract relevant data from the `Prepared` state we're in
        // and switch to `Idle` state at the same time without unnecessary cloning or reference
        // bumping. We're keeping a reference on the underlying `file` alive here, the `IORequest`s
        // we've created implicitly reference that file through raw pointers.
        // Just in case an error happens during read, clients must re-prepare the context
        // to meaningfully proceed which is why we change the state to `Idle` here, if we fully
        // complete the `read` process we'll instead transition to the `ReadDone` state.
        let State::Prepared {
            file,
            shared_context,
            mut requests,
        } = core::mem::replace(&mut self.state, State::Idle)
        else {
            // We've already verified that we're in `Prepared` state above.
            unreachable!();
        };

        for request in &mut requests {
            // SAFETY: `file.as_ptr()` points to the valid, open `struct file` held by `ARef`
            // in `file` (matching `request.kiocb.ki_filp`). `request.kiocb` points to a live,
            // initialized `struct kiocb` pinned inside `request`. We only project a mutable
            // reference to the unpinned `iter` field via `get_unchecked_mut()` without moving
            // `request`. All `kvec` buffers referenced by `iter` (`bounce_bufs` and `dst_buf`)
            // remain valid and allocated until `wait_for_completion` returns below.
            let ret = unsafe {
                bindings::vfs_iocb_iter_read(
                    file.as_ptr(),
                    request.kiocb.get(),
                    &mut request.as_mut().get_unchecked_mut().iter,
                )
            };
            /*
             * ret == -EIOCBQUEUED => I/O request was queued successfully.
             * ret >= 0 => I/O request was satisfied synchronously.
             * ret < 0 => error.
             *
             * If an error is encountered, record the first one. We have to call
             * async_io_complete() if the request is not being processed asynchronously to
             * ensure that the nr_reqs context field is decremented properly so that we don't
             * block indefinitely in the wait_for_completion() call later.
             */
            if ret != -(bindings::EIOCBQUEUED as isize) {
                // SAFETY: `request.kiocb.get()` is a non-null pointer to the `kiocb` field
                // embedded within the live, pinned `request` (`IoRequest`). Because `ret` is not
                // `-EIOCBQUEUED`, the kernel will not invoke `ki_complete` asynchronously for
                // this request, so calling `async_io_complete` once here upholds its contract.
                unsafe {
                    IoRequest::async_io_complete(request.kiocb.get(), ret);
                }
            }
        }

        // SAFETY: `shared_context.io_done` points to a valid `struct completion` initialized in
        // `SharedContext::new`, and `shared_context` remains live via `Arc` for this call.
        unsafe { bindings::wait_for_completion(shared_context.io_done.get()) };

        // It is unfortunate that the kernel SpinLock cannot be unwrapped using something like
        // `into_inner()` now that we no longer need to protect that content. An alternative
        // approach would be to get rid of the SpinLock altogether and use atomic operations
        // to manage the shared state, which would be possible in the current implementation but
        // not necessarily generalize to future additions.
        let bytes_read = shared_context.inner.lock_irq(|guard| {
            let ret = guard.io_ret;
            if ret != 0 {
                return Err(Error::from_errno(ret as i32));
            }

            if guard.bytes_read < offset_in_page(self.file_seg.offs) + self.file_seg.len {
                return Err(EINVAL);
            }

            Ok(guard.bytes_read)
        })?;

        self.state = State::ReadDone(bytes_read);

        Ok(())
    }

    pub(crate) fn complete<'access, const READ: bool>(
        &mut self,
        map: &DmaBufVmap,
        mut access: CpuAccess<'access, READ, true>,
    ) -> Result<()> {
        let State::ReadDone(bytes_read) = self.state else {
            return Err(EINVAL);
        };

        self.state = State::Idle;

        let file_offs = self.file_seg.offs;

        if bytes_read < (offset_in_page(file_offs) + self.file_seg.len) {
            return Ok(());
        }

        let mut tot_len = self.file_seg.len;
        let mut dst_offset = self.buf_offs;

        let mut cur_bounce_page = 0;

        if self.start_bounce_len != 0 {
            let src_base = &self.bounce_bufs[cur_bounce_page];
            let src = &src_base[offset_in_page(file_offs)..];
            /* Handle the case where all of the requested data is in the first bounce page. */
            let len = tot_len.min(PAGE_SIZE - offset_in_page(file_offs));
            let src = &src[..len];
            access.memcpy_to(dst_offset, src);

            dst_offset += len;
            tot_len -= len;
            cur_bounce_page += 1;
        }

        if self.dio_buf_seg.len != 0 {
            let dio_start = self.dio_buf_seg.offs;
            let len = tot_len.min(self.dio_buf_seg.len);

            /*
             * If there's anything that was copied directly into the dmabuf, check to make sure
             * it's in the right place. Shift it back if it's not.
             */
            if dio_start != dst_offset {
                // This should never fail as we verified that the map is valid and gives us
                // a valid vaddr earlier in "load_prepare".
                let vaddr = map.vaddr().ok_or(EINVAL)?.as_ptr();

                // SAFETY: By the safety contract of `IoContext::new`, `vaddr` backs the buffer
                // region `[0, self.buf_offs + self.file_seg.len)`. Both `dst_offset + len` and
                // `dio_start + len` lie within this mapped allocation, so `byte_add` is in bounds
                // and `memmove` safely copies potentially overlapping regions within the buffer.
                unsafe {
                    bindings::memmove(vaddr.byte_add(dst_offset), vaddr.byte_add(dio_start), len)
                };
            }

            dst_offset += len;
            tot_len -= len;
        }

        for _ in 0..(self.end_bounce_len / PAGE_SIZE) {
            let len = tot_len.min(PAGE_SIZE);
            let src = &self.bounce_bufs[cur_bounce_page][..len];

            access.memcpy_to(dst_offset, src);

            dst_offset += len;
            tot_len -= len;
            cur_bounce_page += 1;
        }

        if tot_len != 0 {
            pr_warn!("tot_len != 0\n");
        }

        Ok(())
    }
}
