// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Google LLC.

use core::{mem::MaybeUninit, ptr::NonNull};

use crate::{content::DmaBufContent, THIS_MODULE};

use kernel::{
    alloc::{AllocError, Flags},
    anon_inodes::{anon_inode_create_getfile, AnonInodeFileInterface, AnonInodeFileVTable},
    bindings, device,
    dma_buf::DmaBuf,
    error::to_result,
    ffi,
    fs::{file::mode, file::Offset, File, LocalFile},
    mm::virt::VmaNew,
    new_mutex,
    prelude::*,
    seq_file::SeqFile,
    seq_print,
    sync::{Arc, Mutex},
    task::Task,
    types::{ARef, AlwaysRefCounted, ForeignOwnable},
    uaccess::UserSlice,
    uapi,
};

static WRAP_FOPS: AnonInodeFileVTable<Wrap> = AnonInodeFileVTable::new(&THIS_MODULE);

pub(crate) fn create_wrap_file(
    name: &CStr,
    ptr: <Wrap as AnonInodeFileInterface>::Ptr,
    flags: u32,
) -> Result<ARef<File>, (Error, <Wrap as AnonInodeFileInterface>::Ptr)> {
    anon_inode_create_getfile::<Wrap>(name, ptr, flags, &WRAP_FOPS)
}

enum WrapOwner {
    Task(ARef<Task>),
    Device(ARef<device::Device>),
    None,
}

impl WrapOwner {
    fn get_valid_owner(&mut self) -> Option<&Task> {
        if let Self::Task(task) = self {
            // SAFETY: `task.as_ptr()` returns a raw pointer to an initialized `task_struct`.
            if unsafe { (*task.as_ptr()).mm }.is_null() {
                *self = WrapOwner::None;
            }
        };

        match self {
            Self::Task(task) => Some(task),
            _ => None,
        }
    }

    fn has_owner(&mut self) -> bool {
        match self {
            Self::None => false,
            Self::Task(_task) => self.get_valid_owner().is_some(),
            Self::Device(_dev) => true,
        }
    }

    fn owned_by_current_task(&mut self) -> bool {
        match self {
            Self::Task(_task) => {
                let Some(task) = self.get_valid_owner() else {
                    return false;
                };
                task == current!().group_leader()
            }
            _ => false,
        }
    }

    fn owned_by_device(&self, dev: &device::Device) -> bool {
        matches!(self, Self::Device(owning_dev) if *dev == **owning_dev)
    }
}

enum VmaFile {
    /// This is the case where the `vma_file` matches the file our driver is bound to, in this
    /// case we can be sure that the raw pointer stays valid as long as our driver is. We don't
    /// want to acquire an additional reference on the `file` as that would create a circular
    /// reference on file and prevent it from ever being freed.
    /// Since `VmaFile` and its containing structure `WrapInfo` are decoupled from the driver's
    /// lifetime via `Arc` - this enum could survive the driver - we make sure to reset the
    /// enum value when the `Wrap` is dropped. Doing this does not impact operation because
    /// the enum is not actually accessed from outside the driver (i.e. as part of the task_work
    /// code that holds the other reference to the `Arc`.)
    Internal(*const bindings::file),

    /// We are mapping a file different from the file our driver is bound to (the common case).
    External(ARef<File>),

    /// No file is mapped.
    None,
}

// SAFETY: It is safe to send the enum `VmaFile` across thread boundaries.
unsafe impl Send for VmaFile {}

pub(crate) struct WrapInfo {
    pub(crate) content: Option<DmaBufContent>,
    owner: WrapOwner,
    allow_guests: bool,
    vma_file: VmaFile,
    num_pending_mmaps: usize,
}

impl WrapInfo {
    fn new() -> Self {
        Self {
            content: None,
            owner: WrapOwner::None,
            allow_guests: false,
            vma_file: VmaFile::None,
            num_pending_mmaps: 0,
        }
    }

    fn is_mapped(&mut self) -> bool {
        let vma_file_ptr = match self.vma_file {
            VmaFile::None => return false,
            VmaFile::Internal(file_ptr) => file_ptr,
            VmaFile::External(ref file) => file.as_ptr(),
        };

        if self.num_pending_mmaps > 0 {
            // One or more mmaps are currently pending completion, let's conservatively assume
            // they'll succeed.
            return true;
        }

        // SAFETY: `vma_file` is a valid `ARef<File>`, so `vma_file.as_ptr()` is non-null and
        // valid for reads.
        let mapping = unsafe { (*vma_file_ptr).f_mapping };

        // SAFETY: `mapping` points to the `struct address_space` of `vma_file`, which is kept
        // alive by our `ARef<File>` reference.
        unsafe { bindings::i_mmap_lock_read(mapping) };

        // SAFETY: Reading `i_mmap.rb_root` is synchronized under the `i_mmap_lock_read` lock.
        let rb_root_ref = unsafe { &(*mapping).i_mmap.rb_root };

        // SAFETY: `rb_root_ref` is a valid reference to `rb_root` within `struct address_space`.
        let is_mapped = !unsafe { bindings::RB_EMPTY_ROOT(rb_root_ref) };

        // SAFETY: `mapping` is valid and matches the lock acquired above.
        unsafe { bindings::i_mmap_unlock_read(mapping) };

        if !is_mapped {
            self.vma_file = VmaFile::None;
        }

        is_mapped
    }

    fn check_modifiable(&mut self) -> Result<()> {
        if !self.owner.owned_by_current_task() {
            return Err(EBUSY);
        }

        if self.is_mapped() {
            return Err(EINVAL);
        }

        Ok(())
    }

    fn check_modifiable_and_has_content(&mut self) -> Result<()> {
        self.check_modifiable()?;

        if self.content.is_none() {
            return Err(ENOENT);
        }

        Ok(())
    }
}

enum AllowState {
    AllowGuests,
    ProhibitGuests,
}

enum WrapState {
    InUse(usize),
    UsageBlocked,
    Available,
}

#[pin_data(PinnedDrop)]
pub(crate) struct Wrap {
    #[pin]
    state: Mutex<WrapState>,
    pub(crate) inner: Arc<Mutex<WrapInfo>>,

    // Set once on construction, never modified afterwards, does not need to be guarded by
    // the lock.
    pub(crate) close_on_exec: bool,
}

#[pinned_drop]
impl PinnedDrop for Wrap {
    fn drop(self: Pin<&mut Self>) {
        // The driver instance and the associated file are about to go away, let's make sure
        // we don't leave a dangling raw pointer to the file inside the VmaFile enum.
        self.inner.lock().vma_file = VmaFile::None;
    }
}

struct UseGuard<'a>(&'a Wrap);

impl<'a> Drop for UseGuard<'a> {
    fn drop(&mut self) {
        let mut guard = self.0.state.lock();
        *guard = match *guard {
            WrapState::Available => panic!(),
            WrapState::InUse(1) => WrapState::Available,
            WrapState::InUse(n) => WrapState::InUse(n - 1),
            WrapState::UsageBlocked => WrapState::Available,
        };
    }
}

impl Wrap {
    pub(crate) fn new(close_on_exec: bool) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            state <- new_mutex!(WrapState::Available),
            inner: Arc::pin_init(new_mutex!(WrapInfo::new()), GFP_KERNEL)?,
            close_on_exec,
        })
    }

    fn begin_block_usage(&self) -> Option<UseGuard<'_>> {
        let mut guard = self.state.lock();
        *guard = match *guard {
            WrapState::Available => WrapState::UsageBlocked,
            _ => {
                return None;
            }
        };
        Some(UseGuard(self))
    }

    fn begin_use(&self) -> Option<UseGuard<'_>> {
        let mut guard = self.state.lock();
        *guard = match *guard {
            WrapState::Available => WrapState::InUse(1),
            WrapState::InUse(n) => WrapState::InUse(n + 1),
            WrapState::UsageBlocked => {
                return None;
            }
        };
        Some(UseGuard(self))
    }

    fn file_ioctl(&self, cmd: u32, arg: usize) -> Result<isize> {
        let Some(_use_guard) = self.begin_use() else {
            return Err(ENOENT);
        };

        let mut guard = self.inner.lock();

        if !(guard.allow_guests || !guard.owner.has_owner() || guard.owner.owned_by_current_task())
        {
            return Err(EBUSY);
        }

        let Some(ref content) = guard.content else {
            return Err(ENOENT);
        };

        content.ioctl(cmd, arg)
    }

    fn get_wrap_state(&self, user_slice: UserSlice) -> Result<isize> {
        let (mut reader, mut writer) = user_slice.reader_writer();
        let mut get_state_args = reader.read::<uapi::wrapfd_get_state>()?;

        if get_state_args.reserved != 0 || get_state_args.pad != 0 {
            return Err(EINVAL);
        }

        if let Some(_use_guard) = self.begin_use() {
            let guard = self.inner.lock();

            get_state_args.state = if let Some(ref content) = guard.content {
                if content.is_writable() {
                    uapi::WRAPFD_CONTENT_RDWR
                } else {
                    uapi::WRAPFD_CONTENT_RDONLY
                }
            } else {
                uapi::WRAPFD_CONTENT_EMPTY
            };
        } else {
            get_state_args.state = uapi::WRAPFD_CONTENT_EMPTY;
        }

        writer.write(&get_state_args)?;

        Ok(0)
    }

    fn acquire_ownership(&self) -> Result<isize> {
        let state_guard = self.state.lock();
        match *state_guard {
            WrapState::Available => {}
            WrapState::UsageBlocked => return Err(ENOENT),
            WrapState::InUse(_) => return Err(EINVAL),
        }

        let mut guard = self.inner.lock();

        if guard.owner.owned_by_current_task() {
            return Ok(0);
        }

        if guard.owner.has_owner() {
            return Err(EBUSY);
        }

        if guard.is_mapped() {
            return Err(EINVAL);
        }

        if guard.content.is_none() {
            return Err(ENOENT);
        }

        guard.owner = WrapOwner::Task(ARef::from(current!().group_leader()));

        Ok(0)
    }

    fn release_ownership(&self) -> Result<isize> {
        let mut guard = self.inner.lock();

        guard.check_modifiable()?;

        guard.owner = WrapOwner::None;
        guard.allow_guests = false;

        Ok(0)
    }

    fn load(&self, user_slice: UserSlice) -> Result<isize> {
        let mut reader = user_slice.reader();
        let load_args = reader.read::<uapi::wrapfd_load>()?;

        let file_offset: Offset = load_args.file_offs.try_into()?;
        let buf_offset: Offset = load_args.buf_offs.try_into()?;
        let len: Offset = load_args.len.try_into()?;

        if file_offset < 0 || buf_offset < 0 || len < 0 {
            return Err(EINVAL);
        }

        if load_args.reserved != 0 || load_args.pad != 0 {
            return Err(EINVAL);
        }

        let localfile = LocalFile::fget(load_args.fd)?;

        let f_mode = localfile.mode();

        if (f_mode & mode::FMODE_READ) == 0 {
            return Err(EBADF);
        }

        // SAFETY: `f_op` is a valid pointer to `struct file_operations` for an open file.
        if unsafe { (*(*localfile.as_ptr()).f_op).read_iter }.is_none() {
            return Err(EINVAL);
        }

        if (f_mode & mode::FMODE_CAN_READ) == 0 {
            return Err(EINVAL);
        }

        if (f_mode & mode::FMODE_CAN_ODIRECT) == 0 {
            return Err(EINVAL);
        }

        let Some(end) = file_offset.checked_add(len) else {
            return Err(EINVAL);
        };

        // SAFETY: `file_inode` returns a valid `struct inode` for a live `struct file`, and
        // `i_size_read` safely reads its size under kernel RCU / lock rules.
        if end > unsafe { bindings::i_size_read(bindings::file_inode(localfile.as_ptr())) } {
            return Err(EINVAL);
        }

        let Some(_use_guard) = self.begin_use() else {
            return Err(ENOENT);
        };

        let dmabuf = {
            let guard = self.inner.lock();

            let Some(ref content) = guard.content else {
                return Err(ENOENT);
            };

            if !content.is_writable() {
                return Err(EACCES);
            }

            content.dmabuf.clone()
        };

        DmaBufContent::load(&dmabuf, localfile, file_offset, buf_offset, len)
    }

    fn rewrap(&self, user_slice: UserSlice) -> Result<u32> {
        let mut reader = user_slice.reader();
        let rewrap_args = reader.read::<uapi::wrapfd_rewrap>()?;

        if (rewrap_args.prot & !(bindings::PROT_WRITE | bindings::PROT_READ)) != 0 {
            return Err(EINVAL);
        }

        if rewrap_args.reserved != 0 || rewrap_args.pad != 0 {
            return Err(EINVAL);
        }

        let Some(_use_guard) = self.begin_block_usage() else {
            return Err(EINVAL);
        };

        let mut guard = self.inner.lock();
        guard.check_modifiable()?;

        let Some(mut content) = guard.content.take() else {
            return Err(ENOENT);
        };

        match content.make_writable((rewrap_args.prot & bindings::PROT_WRITE) != 0) {
            Ok(()) => {}
            Err(err) => {
                guard.content = Some(content);
                return Err(err);
            }
        }

        let close_on_exec = self.close_on_exec;

        let result = match KBox::pin_init(Wrap::new(close_on_exec), GFP_KERNEL) {
            Ok(new_wrap) => crate::WrapFdDevice::publish_wrap(new_wrap, content, close_on_exec),
            Err(err) => Err((err, content)),
        };

        match result {
            Err((err, content)) => {
                // Restore original wrap. XXX hasn't writeability potentially changed?
                guard.content = Some(content);

                Err(err)
            }
            Ok(fd) => Ok(fd),
        }
    }

    fn empty(&self) -> Result<isize> {
        let Some(_use_guard) = self.begin_block_usage() else {
            return Err(EINVAL);
        };

        let mut guard = self.inner.lock();
        guard.check_modifiable()?;

        if let Some(_content) = guard.content.take() {
            Ok(0)
        } else {
            Err(ENOENT)
        }
    }

    fn allow_guests(&self, allow: AllowState) -> Result<isize> {
        let mut guard = self.inner.lock();

        guard.check_modifiable_and_has_content()?;
        guard.allow_guests = matches!(allow, AllowState::AllowGuests);

        Ok(0)
    }
}

#[vtable]
impl AnonInodeFileInterface for Wrap {
    type Ptr = Pin<KBox<Self>>;

    fn llseek(
        wrap: <Self::Ptr as ForeignOwnable>::Borrowed<'_>,
        offs: Offset,
        whence: ffi::c_int,
    ) -> Result<Offset> {
        let Some(_use_guard) = wrap.begin_use() else {
            return Err(ENOENT);
        };

        let mut guard = wrap.inner.lock();

        let Some(ref mut content) = guard.content else {
            return Err(ENOENT);
        };

        content.llseek(offs, whence)
    }

    fn mmap(
        wrap: <Self::Ptr as ForeignOwnable>::Borrowed<'_>,
        file: &File,
        vma: &VmaNew,
    ) -> Result {
        let Some(_use_guard) = wrap.begin_use() else {
            return Err(ENOENT);
        };

        let mut guard = wrap.inner.lock();

        if !guard.allow_guests && guard.owner.has_owner() && !guard.owner.owned_by_current_task() {
            return Err(EBUSY);
        }

        // We're going to assume that this `mmap` call will succeed,  we'll increment the "pending"
        // counter now and `DeferredMmapCounter` will decrement it again upon return to user-space.
        DeferredMmapCounter::new(&wrap.inner, GFP_KERNEL)?.defer()?;
        guard.num_pending_mmaps += 1;

        let Some(ref content) = guard.content else {
            return Err(ENOENT);
        };

        let mut make_rdonly = false;

        if !content.is_writable() {
            if vma.writable() {
                return Err(EACCES);
            }

            make_rdonly = (vma.flags() & kernel::mm::virt::flags::MAYWRITE) != 0;
        }

        // SAFETY: `content.dmabuf` and `vma` are valid references, and `vm_pgoff` is safely
        // read from `vma`.
        to_result(unsafe {
            let pgoff = (*vma.as_ptr()).vm_pgoff;
            bindings::dma_buf_mmap(content.dmabuf.as_ptr(), vma.as_ptr(), pgoff)
        })?;

        if make_rdonly {
            if vma.writable() {
                pr_warn!("wrapfd read-only content was mapped as writable\n");
                return Err(EACCES);
            }

            vma.try_clear_maywrite()?;
        }

        /*
         * If remap_file_pages() succeeds on a VMA that maps a wrapped file, it will unconditionally
         * set VM_MAYWRITE by invoking do_mmap(), which will refer to the wrapped file's mmap()
         * f_op. This allows a read-only wrap to be made writable via mprotect() later.
         *
         * Setting VM_NO_REMAP_FILE_PAGES prevents remap_file_pages() from working on VMAs
         * associated with wrapped files.
         */
        vma.set_no_remap_file_pages();

        // SAFETY: `vma` is a valid reference to `struct vm_area_struct`.
        let vma_file_raw = unsafe { (*vma.as_ptr()).vm_file };

        if guard.is_mapped() {
            // Let's double check that the vma_file has not changed if we're already mapped.
            match guard.vma_file {
                VmaFile::None => {}
                VmaFile::Internal(file_ptr) => {
                    if file_ptr != vma_file_raw {
                        return Err(EINVAL);
                    }
                }
                VmaFile::External(ref file) => {
                    if file.as_ptr() != vma_file_raw {
                        return Err(EINVAL);
                    }
                }
            }
        } else if vma_file_raw == file.as_ptr() {
            guard.vma_file = VmaFile::Internal(vma_file_raw);
        } else {
            // SAFETY: In the `mmap` callback, `vm_file` points to a valid open `struct file` with
            // an existing reference count. `File::from_raw_file` safely takes ownership of a
            // reference to it.
            let vma_file: ARef<File> = unsafe { File::from_raw_file(vma_file_raw) }.into();

            guard.vma_file = VmaFile::External(vma_file);
        }

        Ok(())
    }

    fn ioctl(
        wrap: <Self::Ptr as ForeignOwnable>::Borrowed<'_>,
        _file: &File,
        cmd: u32,
        arg: usize,
    ) -> Result<isize> {
        use kernel::ioctl::_IOC_SIZE;

        match cmd {
            uapi::WRAPFD_DEV_IOC_GET_STATE => {
                let user_slice = UserSlice::new(UserPtr::from_addr(arg), _IOC_SIZE(cmd));
                wrap.get_wrap_state(user_slice)
            }
            uapi::WRAPFD_DEV_IOC_ACQUIRE_OWNERSHIP => wrap.acquire_ownership(),
            uapi::WRAPFD_DEV_IOC_RELEASE_OWNERSHIP => wrap.release_ownership(),
            uapi::WRAPFD_DEV_IOC_LOAD => {
                let user_slice = UserSlice::new(UserPtr::from_addr(arg), _IOC_SIZE(cmd));
                wrap.load(user_slice)
            }
            uapi::WRAPFD_DEV_IOC_REWRAP => {
                let user_slice = UserSlice::new(UserPtr::from_addr(arg), _IOC_SIZE(cmd));
                wrap.rewrap(user_slice).map(|fd| fd as isize)
            }
            uapi::WRAPFD_DEV_IOC_EMPTY => wrap.empty(),
            uapi::WRAPFD_DEV_IOC_ALLOW_GUESTS => wrap.allow_guests(AllowState::AllowGuests),
            uapi::WRAPFD_DEV_IOC_PROHIBIT_GUESTS => wrap.allow_guests(AllowState::ProhibitGuests),
            _ => wrap.file_ioctl(cmd, arg),
        }
    }

    #[cfg(CONFIG_COMPAT)]
    fn compat_ioctl(
        wrap: <Self::Ptr as ForeignOwnable>::Borrowed<'_>,
        file: &File,
        cmd: u32,
        mut arg: usize,
    ) -> Result<isize> {
        match cmd {
            uapi::WRAPFD_DEV_IOC_GET_STATE
            | uapi::WRAPFD_DEV_IOC_LOAD
            | uapi::WRAPFD_DEV_IOC_REWRAP => {
                // These commands are associated with pointers as arguments, so use compat_ptr()
                // on them.

                // SAFETY: `compat_ptr` is safe to call on 32bit user mode pointer.
                arg = unsafe { bindings::compat_ptr(arg as u32) } as usize;
            }

            _ => {}
        }

        Self::ioctl(wrap, file, cmd, arg)
    }

    #[cfg(CONFIG_PROC_FS)]
    fn show_fdinfo(wrap: <Self::Ptr as ForeignOwnable>::Borrowed<'_>, m: &SeqFile, _file: &File) {
        let mut guard = wrap.inner.lock();
        if matches!(&guard.owner, WrapOwner::Device(_dev)) {
            seq_print!(m, "owner:\t<device>\n");
        } else if let Some(task) = guard.owner.get_valid_owner() {
            seq_print!(m, "owner:\t{}\n", task.pid());
        } else {
            seq_print!(m, "owner:\t<none>\n");
        }

        seq_print!(
            m,
            "guests:\t{}\n",
            if guard.allow_guests { "yes" } else { "no" }
        );
        seq_print!(
            m,
            "maps:\t{}\n",
            if guard.is_mapped() { "yes" } else { "no" }
        );

        if let Some(ref content) = guard.content {
            seq_print!(
                m,
                "rdonly:\t{}\n",
                if content.is_writable() { "no" } else { "yes" }
            );
            seq_print!(m, "type:\tdmabuf\n");

            seq_print!(m, "size:\t{}\n", content.dmabuf.size());

            // SAFETY: `content.dmabuf.file()` returns a valid `struct file`, so reading `f_count`
            // is safe.
            let file_count = unsafe { bindings::file_count(content.dmabuf.file().as_ptr()) };
            seq_print!(m, "count:\t{}\n", file_count - 1);

            seq_print!(m, "exp_name:\t{}\n", content.dmabuf.exporter_name());

            content.dmabuf.with_name(|opt_name| {
                if let Some(name) = opt_name {
                    seq_print!(m, "name:\t{name}\n");
                }
            });
        }
    }
}

/// Helper for keeping track of mmap operations: Will decrement the "num_pending_mmaps" counter
/// upon return to user space.
struct DeferredMmapCounter {
    inner: KBox<DeferredMmapCounterInner>,
}

#[repr(C)]
struct DeferredMmapCounterInner {
    twork: MaybeUninit<bindings::callback_head>,
    wrap_info: Arc<Mutex<WrapInfo>>,
}

impl DeferredMmapCounter {
    /// Create a new [`DeferredMmapCounter`].
    fn new(wrap_info: &Arc<Mutex<WrapInfo>>, flags: Flags) -> Result<Self, AllocError> {
        Ok(Self {
            inner: KBox::new(
                DeferredMmapCounterInner {
                    twork: MaybeUninit::uninit(),
                    wrap_info: Arc::clone(wrap_info),
                },
                flags,
            )?,
        })
    }

    /// Defer decrementing the counter until we return to user space.
    /// Fails if this is called from a context where we cannot run work when returning to userspace.
    /// (E.g., from a kthread.)
    fn defer(self) -> Result<()> {
        use bindings::task_work_notify_mode_TWA_RESUME as TWA_RESUME;

        // Task works are not available on kthreads.
        let current = kernel::current!();

        // Check if this is a kthread.
        // SAFETY: Reading `flags` from a task is always okay.
        if unsafe { ((*current.as_ptr()).flags & bindings::PF_KTHREAD) != 0 } {
            return Err(ENOTSUPP);
        }

        // Transfer ownership of the box's allocation to a raw pointer. This disables the
        // destructor, so we must manually convert it back to a KBox to drop it.
        //
        // Until we convert it back to a `KBox`, there are no aliasing requirements on this
        // pointer.
        let inner = KBox::into_raw(self.inner);

        // The `callback_head` field is first in the struct, so this cast correctly gives us a
        // pointer to the field.
        let callback_head = inner.cast::<bindings::callback_head>();

        let current = current.as_ptr();
        // SAFETY: This function currently has exclusive access to the `DeferredMmapCounterInner`,
        // so it is okay for us to perform unsynchronized writes to its `callback_head` field.
        unsafe { bindings::init_task_work(callback_head, Some(Self::do_defer)) };

        // SAFETY: This inserts the `DeferredMmapCounterInner` into the task workqueue for the
        // current task. If this operation is successful, then this transfers exclusive ownership of
        // the `callback_head` field to the C side until it calls `do_defer`, and we don't touch or
        // invalidate the field during that time.
        //
        // When the C side calls `do_defer`, the safety requirements of that method are
        // satisfied because when a task work is executed, the callback is given ownership of the
        // pointer.
        let res = unsafe { bindings::task_work_add(current, callback_head, TWA_RESUME) };

        if res != 0 {
            // SAFETY: Scheduling the task work failed, so we still have ownership of the box, so
            // we may destroy it.
            unsafe { drop(KBox::from_raw(inner)) };

            return Err(ENOTSUPP);
        }

        Ok(())
    }

    /// # Safety
    ///
    /// The provided pointer must point at the `twork` field of a `DeferredMmapCounterInner` stored
    /// in a `KBox`, and the caller must pass exclusive ownership of that `KBox`.
    unsafe extern "C" fn do_defer(inner: *mut bindings::callback_head) {
        // SAFETY: The caller just passed us ownership of this box.
        let inner = unsafe { KBox::from_raw(inner.cast::<DeferredMmapCounterInner>()) };
        inner.wrap_info.lock().num_pending_mmaps -= 1;

        // The allocation is freed when `inner` goes out of scope.
    }
}

/// Performs argument validation and extracts a reference to a Wrap from the supplied `file`,
/// iff that file is one we created earlier in `create_wrap_file`.
fn with_wrap_helper(
    file: *mut bindings::file,
    label: &'static str,
    f: impl FnOnce(&Wrap) -> Result,
) -> Result {
    if file.is_null() {
        pr_warn!("{label}: file is NULL!\n");
        return Err(EBADF);
    }

    // SAFETY: `file` is guaranteed to be a valid pointer to a `struct file` by the C API contract.
    let file = unsafe { File::from_raw_file(file) };

    let Some(wrap) = WRAP_FOPS.borrow_private(file) else {
        return Err(EBADF);
    };

    f(&wrap)
}

#[export]
/// # Safety
///
/// - `file` must be a valid, non-null pointer to a live C `struct file` created by this driver.
/// - `dev` must be a valid pointer to a live C `struct device` or null (handled gracefully).
/// - `mappable` must be a valid pointer to a live C `struct wrapfd_mappable`.
/// - The caller must ensure `file`, `dev` and `mappable` remain allocated for the duration of
///   this call.
unsafe extern "C" fn wrapfd_get_mappable(
    file: *mut bindings::file,
    dev: *mut bindings::device,
    mappable: *mut bindings::wrapfd_mappable,
) -> ffi::c_int {
    let result = with_wrap_helper(file, "wrapfd_get_mappable", |wrap| {
        if dev.is_null() {
            pr_warn!("wrapfd_get_mappable: dev is NULL!\n");
            return Err(ENODEV);
        }

        if mappable.is_null() {
            return Err(EINVAL);
        }

        let state_guard = wrap.state.lock();
        match *state_guard {
            WrapState::Available => {}
            WrapState::UsageBlocked => return Err(ENOENT),
            WrapState::InUse(_) => return Err(EINVAL),
        }

        let mut guard = wrap.inner.lock();

        // SAFETY: `dev` is verified non-null and points to a valid C `struct device`. `get_device`
        // safely increments its reference count.
        let device = unsafe { device::Device::get_device(dev) };

        if guard.owner.has_owner() && !guard.owner.owned_by_device(&device) {
            return Err(EBUSY);
        }

        if guard.is_mapped() {
            return Err(EINVAL);
        }

        let Some(ref content) = guard.content else {
            return Err(ENOENT);
        };

        // We acquire an additional reference on `dmabuf` here that will be released in a matching
        // call to `wrapfd_put_mappable`.
        content.dmabuf.inc_ref();

        // SAFETY: `mappable` is a valid, writable pointer to `struct wrapfd_mappable` per caller
        // contract.
        unsafe {
            (*mappable).dmabuf = content.dmabuf.as_ptr();
        }

        guard.owner = WrapOwner::Device(device);

        Ok(())
    });

    match result {
        Ok(()) => 0,
        Err(err) => err.to_errno(),
    }
}

#[export]
/// # Safety
///
/// - `file` must be a valid, non-null pointer to a live C `struct file` created by this driver.
/// - `dev` must be a valid pointer to a live C `struct device` or null (handled gracefully).
/// - `mappable` must be a valid pointer to a live C `struct wrapfd_mappable`.
/// - The caller must ensure `file`, `dev` and `mappable` remain allocated for the duration of
///   this call.
unsafe extern "C" fn wrapfd_put_mappable(
    file: *mut bindings::file,
    dev: *mut bindings::device,
    mappable: *mut bindings::wrapfd_mappable,
) -> ffi::c_int {
    let result = with_wrap_helper(file, "wrapfd_put_mappable", |wrap| {
        if dev.is_null() {
            pr_warn!("wrapfd_put_mappable: dev is NULL!\n");
            return Err(ENODEV);
        }

        if mappable.is_null() {
            return Err(EINVAL);
        }

        let mut guard = wrap.inner.lock();

        // SAFETY: `dev` is verified non-null and points to a valid C `struct device`.
        // It's valid for the duration of this call.
        let device = unsafe { device::Device::from_raw(dev) };

        if !guard.owner.owned_by_device(&device) {
            return Err(EBUSY);
        }

        let Some(ref content) = guard.content else {
            // This really should not happen as `wrapfd_get_mappable` would've failed.
            return Err(EINVAL);
        };

        // SAFETY: `mappable` is a valid pointer to `struct wrapfd_mappable` per caller contract.
        if content.dmabuf.as_ptr() != unsafe { (*mappable).dmabuf } {
            return Err(EINVAL);
        }

        // SAFETY: We've acquired an extra reference in `wrapfd_get_mappable` that we now no
        // longer need. We retain our own reference to `content.dmabuf` through ARef<>.
        unsafe {
            <DmaBuf as AlwaysRefCounted>::dec_ref(NonNull::from_ref(&content.dmabuf));
        }

        guard.owner = WrapOwner::None;
        Ok(())
    });

    match result {
        Ok(()) => 0,
        Err(err) => err.to_errno(),
    }
}
