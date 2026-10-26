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

enum WrapState {
    InUse(usize),
    Available,
}

pub(crate) struct WrapInfo {
    pub(crate) content: Option<DmaBufContent>,
    owner: WrapOwner,
    allow_guests: bool,
    vma_file: VmaFile,
    num_pending_mmaps: usize,
    state: WrapState,
}

impl WrapInfo {
    fn new() -> Self {
        Self {
            content: None,
            owner: WrapOwner::None,
            allow_guests: false,
            vma_file: VmaFile::None,
            num_pending_mmaps: 0,
            state: WrapState::Available,
        }
    }

    fn get_valid_owner(&mut self) -> Option<&Task> {
        if let WrapOwner::Task(task) = &self.owner {
            if !task.has_mm() {
                self.owner = WrapOwner::None;
                self.allow_guests = false;
            }
        };

        match &self.owner {
            WrapOwner::Task(task) => Some(task),
            _ => None,
        }
    }

    fn has_owner(&mut self) -> bool {
        match &self.owner {
            WrapOwner::None => false,
            WrapOwner::Task(_task) => self.get_valid_owner().is_some(),
            WrapOwner::Device(_dev) => true,
        }
    }

    fn owned_by_current_task(&mut self) -> bool {
        let Some(task) = self.get_valid_owner() else {
            return false;
        };
        task == current!().group_leader()
    }

    fn owned_by_device(&self, dev: &device::Device) -> bool {
        matches!(&self.owner, WrapOwner::Device(owning_dev) if *dev == **owning_dev)
    }

    fn with_mmap_rbtree_read_locked<T>(
        mapping: *mut bindings::address_space,
        f: impl FnOnce(*const bindings::rb_root) -> T,
    ) -> T {
        // SAFETY: `mapping` points to the `struct address_space` of `vma_file`, which is kept
        // alive by our `ARef<File>` reference.
        unsafe { bindings::i_mmap_lock_read(mapping) };

        // SAFETY: Reading `i_mmap.rb_root` is synchronized under the `i_mmap_lock_read` lock.
        let rb_root_ref = unsafe { &(*mapping).i_mmap.rb_root };

        let result = f(rb_root_ref);

        // SAFETY: `mapping` is valid and matches the lock acquired above.
        unsafe { bindings::i_mmap_unlock_read(mapping) };

        result
    }

    fn map_count(&mut self) -> usize {
        let vma_file_ptr = match self.vma_file {
            VmaFile::None => return 0,
            VmaFile::Internal(file_ptr) => file_ptr,
            VmaFile::External(ref file) => file.as_ptr(),
        };

        // SAFETY: `vma_file` is either a valid `ARef<File>` or is a non-NULL valid raw pointer. The
        // raw pointer is valid, as it refers to the file structure associated with the wrap object,
        // and therefore valid throughout the wrap's lifetime. In either case, accessing it is safe.
        let mapping = unsafe { (*vma_file_ptr).f_mapping };

        let map_count = Self::with_mmap_rbtree_read_locked(mapping, |rb_root_ref| {
            // SAFETY: `rb_root_ref` is a valid reference to `rb_root` wihin `struct address_space`.
            let mut node = unsafe { bindings::rb_first(rb_root_ref) };
            let mut map_count = 0;

            while !node.is_null() {
                map_count += 1;
                // SAFETY: the rbtree lock is held throughout this function, so the entire tree is
                // valid.
                node = unsafe { bindings::rb_next(node) };
            }

            map_count
        });

        if map_count == 0 && self.num_pending_mmaps == 0 {
            self.vma_file = VmaFile::None;
        }

        map_count
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

        // SAFETY: `vma_file` is either a valid `ARef<File>` or is a non-NULL valid raw pointer. The
        // raw pointer is valid, as it refers to the file structure associated with the wrap object,
        // and therefore valid throughout the wrap's lifetime. In either case, accessing it is safe.
        let mapping = unsafe { (*vma_file_ptr).f_mapping };

        // SAFETY: `rb_root_ref` is a valid reference to `rb_root` within `struct address_space`.
        let is_mapped = Self::with_mmap_rbtree_read_locked(mapping, |rb_root| !unsafe {
            bindings::RB_EMPTY_ROOT(rb_root)
        });

        if !is_mapped {
            self.vma_file = VmaFile::None;
        }

        is_mapped
    }

    fn check_accessible(&mut self) -> Result<&DmaBufContent> {
        if !(self.allow_guests || !self.has_owner() || self.owned_by_current_task()) {
            return Err(EBUSY);
        }

        self.content.as_ref().ok_or(ENOENT)
    }

    fn check_modifiable(&mut self) -> Result<()> {
        if !self.owned_by_current_task() {
            return Err(EBUSY);
        }

        if matches!(self.state, WrapState::InUse(_)) || self.is_mapped() {
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

#[pin_data]
pub(crate) struct Wrap {
    pub(crate) inner: Arc<Mutex<WrapInfo>>,

    // Set once on construction, never modified afterwards, does not need to be guarded by
    // the lock.
    pub(crate) close_on_exec: bool,
}

struct UseGuard<'a>(&'a Wrap);

impl<'a> Drop for UseGuard<'a> {
    fn drop(&mut self) {
        let mut guard = self.0.inner.lock();
        guard.state = match guard.state {
            WrapState::Available => panic!(),
            WrapState::InUse(1) => WrapState::Available,
            WrapState::InUse(n) => WrapState::InUse(n - 1),
        };
    }
}

impl Wrap {
    pub(crate) fn new(close_on_exec: bool) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            inner: Arc::pin_init(new_mutex!(WrapInfo::new()), GFP_KERNEL)?,
            close_on_exec,
        })
    }

    fn begin_use(&self, info: &mut WrapInfo) -> UseGuard<'_> {
        info.state = match info.state {
            WrapState::Available => WrapState::InUse(1),
            WrapState::InUse(n) => WrapState::InUse(n + 1),
        };
        UseGuard(self)
    }

    fn file_ioctl(&self, cmd: u32, arg: usize) -> Result<isize> {
        let (_use_guard, dmabuf) = {
            let mut guard = self.inner.lock();
            let content = guard.check_accessible()?;

            let dmabuf = content.dmabuf.clone();
            (self.begin_use(&mut guard), dmabuf)
        };

        DmaBufContent::ioctl(&dmabuf, cmd, arg)
    }

    fn get_wrap_state(&self, user_slice: UserSlice) -> Result<isize> {
        let (mut reader, mut writer) = user_slice.reader_writer();
        let mut get_state_args = reader.read::<uapi::wrapfd_get_state>()?;

        if get_state_args.reserved != 0 || get_state_args.pad != 0 {
            return Err(EINVAL);
        }

        get_state_args.state = {
            let guard = self.inner.lock();

            if let Some(ref content) = guard.content {
                if content.is_writable() {
                    uapi::WRAPFD_CONTENT_RDWR
                } else {
                    uapi::WRAPFD_CONTENT_RDONLY
                }
            } else {
                uapi::WRAPFD_CONTENT_EMPTY
            }
        };

        writer.write(&get_state_args)?;

        Ok(0)
    }

    fn acquire_ownership(&self) -> Result<isize> {
        let mut guard = self.inner.lock();

        if guard.owned_by_current_task() {
            return Ok(0);
        }

        if guard.has_owner() {
            return Err(EBUSY);
        }

        if guard.content.is_none() {
            return Err(ENOENT);
        }

        if matches!(guard.state, WrapState::InUse(_)) || guard.is_mapped() {
            return Err(EINVAL);
        }

        guard.owner = WrapOwner::Task(ARef::from(current!().group_leader()));

        Ok(0)
    }

    fn release_ownership(&self) -> Result<isize> {
        let mut guard = self.inner.lock();

        if !guard.owned_by_current_task() {
            return Err(EBUSY);
        }

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

        if end > localfile.i_size_read() {
            return Err(EINVAL);
        }

        let (_use_guard, dmabuf) = {
            let mut guard = self.inner.lock();
            let content = guard.check_accessible()?;

            if !content.is_writable() {
                return Err(EACCES);
            }

            let dmabuf = content.dmabuf.clone();
            (self.begin_use(&mut guard), dmabuf)
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

        let mut guard = self.inner.lock();
        guard.check_modifiable()?;

        let Some(mut content) = guard.content.take() else {
            return Err(ENOENT);
        };

        let was_writable = content.is_writable();
        match content.make_writable((rewrap_args.prot & bindings::PROT_WRITE) != 0) {
            Ok(()) => {}
            Err(err) => {
                guard.content = Some(content);
                return Err(err);
            }
        }

        let close_on_exec = self.close_on_exec;

        let result = match KBox::pin_init(Wrap::new(close_on_exec), GFP_KERNEL) {
            Ok(new_wrap) => DmaBufContent::publish_wrap(new_wrap, content, close_on_exec, true),
            Err(err) => Err((err, content)),
        };

        match result {
            Err((err, mut content)) => {
                // Restore original wrap.
                _ = content.make_writable(was_writable);
                guard.content = Some(content);

                Err(err)
            }
            Ok(fd) => Ok(fd),
        }
    }

    fn empty(&self) -> Result<isize> {
        let _content = {
            let mut guard = self.inner.lock();
            guard.check_modifiable_and_has_content()?;
            guard.content.take()
        };
        Ok(0)
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

    fn release(wrap: Self::Ptr, _file: &File) {
        // The driver instance and the associated file are about to go away, let's make sure
        // we don't leave a dangling raw pointer to the file inside the VmaFile enum.
        wrap.inner.lock().vma_file = VmaFile::None;

        drop(wrap);
    }

    fn llseek(
        wrap: <Self::Ptr as ForeignOwnable>::Borrowed<'_>,
        offs: Offset,
        whence: ffi::c_int,
    ) -> Result<Offset> {
        let (_use_guard, dmabuf) = {
            let mut guard = wrap.inner.lock();
            let content = guard.check_accessible()?;

            let dmabuf = content.dmabuf.clone();
            (wrap.begin_use(&mut guard), dmabuf)
        };

        DmaBufContent::llseek(&dmabuf, offs, whence)
    }

    fn mmap(
        wrap: <Self::Ptr as ForeignOwnable>::Borrowed<'_>,
        file: &File,
        vma: &VmaNew,
    ) -> Result {
        let mut guard = wrap.inner.lock();
        let content = guard.check_accessible()?;

        let mut make_rdonly = false;

        if !content.is_writable() {
            if vma.writable() {
                return Err(EACCES);
            }

            make_rdonly = (vma.flags() & kernel::mm::virt::flags::MAYWRITE) != 0;
        }

        let dmabuf_ptr = content.dmabuf.as_ptr();

        // We're going to assume that this `mmap` call will succeed,  we'll increment the "pending"
        // counter now and `DeferredMmapCounter` will decrement it again upon return to user-space.
        DeferredMmapCounter::new(&wrap.inner, GFP_KERNEL)?.defer()?;
        guard.num_pending_mmaps += 1;

        // SAFETY: `dmabuf_ptr` and `vma` are valid pointers (`guard` keeps `content.dmabuf`
        // alive), and `vm_pgoff` is safely read from `vma`.
        to_result(unsafe {
            let pgoff = (*vma.as_ptr()).vm_pgoff;
            bindings::dma_buf_mmap(dmabuf_ptr, vma.as_ptr(), pgoff)
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

        // We want clients to create these mappings explicitly, rather than implicitly via fork().
        vma.set_dontcopy();

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
        } else if let Some(task) = guard.get_valid_owner() {
            seq_print!(m, "owner:\t{}\n", task.pid());
        } else {
            seq_print!(m, "owner:\t<none>\n");
        }

        seq_print!(
            m,
            "guests:\t{}\n",
            if guard.allow_guests { "yes" } else { "no" }
        );
        seq_print!(m, "maps:\t{}\n", guard.map_count());

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

        let mut guard = wrap.inner.lock();

        // SAFETY: `dev` is verified non-null and points to a valid C `struct device`. `get_device`
        // safely increments its reference count.
        let device = unsafe { device::Device::get_device(dev) };

        if guard.has_owner() && !guard.owned_by_device(&device) {
            return Err(EBUSY);
        }

        if guard.content.is_none() {
            return Err(ENOENT);
        }

        if matches!(guard.state, WrapState::InUse(_)) || guard.is_mapped() {
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

        if !guard.owned_by_device(&device) {
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
        guard.allow_guests = false;
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
/// - `ops` must be a valid pointer to a live C `struct wrapfd_listener_operations`.
/// - The caller must ensure `file` and `dev` remain allocated for the duration of this call.
/// - `ops` must remain allocated and `param` valid until a matching call to `wrapfd_del_listener`.
unsafe extern "C" fn wrapfd_add_listener(
    file: *mut bindings::file,
    dev: *mut bindings::device,
    ops: *const bindings::wrapfd_listener_operations,
    param: *mut ffi::c_void,
    handlep: *mut *mut ffi::c_void,
) -> ffi::c_int {
    let result = with_wrap_helper(file, "wrapfd_add_listener", |wrap| {
        if dev.is_null() {
            pr_warn!("wrapfd_add_listener: dev is NULL!\n");
            return Err(ENODEV);
        }

        if ops.is_null() || handlep.is_null() {
            return Err(EINVAL);
        }

        // SAFETY: We've previously verified that `ops` is a non-null pointer, the contract for
        // `wrapfd_add_listener` requires `ops` to point to a valid `struct
        // wrapfd_listener_operation` and remain valid for as long as the listener is
        // registered.
        if unsafe { (*ops).on_content_release }.is_none() {
            return Err(EINVAL);
        }

        let mut guard = wrap.inner.lock();

        let WrapOwner::Device(ref owning_dev) = guard.owner else {
            return Err(EBUSY);
        };

        // SAFETY: `dev` has been verified to be a non-null pointer and points to a live C `struct
        // device` per function contract.
        if owning_dev != &unsafe { kernel::device::Device::get_device(dev) } {
            return Err(EBUSY);
        }

        let Some(ref mut content) = guard.content else {
            return Err(ENOENT);
        };

        let handle = content.add_listener(ops, param)?;

        // SAFETY: We've verified that `handlep` is a non-null pointer, per function contract it
        // points to writable memory and can store a `*mut c_void`.
        unsafe {
            *handlep = handle as _;
        }

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
unsafe extern "C" fn wrapfd_del_listener(
    file: *mut bindings::file,
    handle: *mut ffi::c_void,
) -> ffi::c_int {
    let result = with_wrap_helper(file, "wrapfd_del_listener", |wrap| {
        let mut guard = wrap.inner.lock();

        if handle.is_null() {
            return Err(EINVAL);
        }

        let Some(ref mut content) = guard.content else {
            return Err(EINVAL);
        };

        content.remove_listener(handle)
    });

    match result {
        Ok(()) => 0,
        Err(err) => err.to_errno(),
    }
}

#[export]
unsafe extern "C" fn wrapfd_acquire_ownership(
    file: *mut bindings::file,
    dev: *mut bindings::device,
) -> ffi::c_int {
    let result = with_wrap_helper(file, "wrapfd_get_ownership", |wrap| {
        if dev.is_null() {
            return Err(ENODEV);
        }

        let mut guard = wrap.inner.lock();

        // SAFETY: `dev` is verified non-null and points to a valid C `struct device`. `get_device`
        // safely increments its reference count.
        let device = unsafe { device::Device::get_device(dev) };

        if guard.has_owner() {
            if guard.owned_by_device(&device) {
                return Ok(());
            } else {
                return Err(EBUSY);
            }
        }

        if guard.content.is_none() {
            return Err(ENOENT);
        }

        if matches!(guard.state, WrapState::InUse(_)) || guard.is_mapped() {
            return Err(EINVAL);
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
unsafe extern "C" fn wrapfd_release_ownership(
    file: *mut bindings::file,
    dev: *mut bindings::device,
) -> ffi::c_int {
    let result = with_wrap_helper(file, "wrapfd_put_ownership", |wrap| {
        if dev.is_null() {
            return Err(ENODEV);
        }

        let mut guard = wrap.inner.lock();

        // SAFETY: `dev` is verified non-null and points to a valid C `struct device`. `get_device`
        // safely increments its reference count.
        let device = unsafe { device::Device::get_device(dev) };

        if !guard.owned_by_device(&device) {
            return Err(EBUSY);
        }

        guard.owner = WrapOwner::None;

        Ok(())
    });

    match result {
        Ok(()) => 0,
        Err(err) => err.to_errno(),
    }
}
