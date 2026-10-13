// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Google LLC.

use crate::io_context::IoContext;
use crate::wrap::{create_wrap_file, Wrap};

use kernel::{
    bindings, c_str,
    dma_buf::{DmaBuf, DmaBufVmap},
    ffi,
    fs::{file::mode, file::FileDescriptorReservation, file::Offset, LocalFile},
    prelude::*,
    sync::Arc,
    types::ARef,
};

pub(crate) struct DmaBufContent {
    pub(crate) dmabuf: ARef<DmaBuf>,
    writable: bool,
}

impl DmaBufContent {
    fn is_dmabuf_writable(dmabuf: &DmaBuf) -> bool {
        (dmabuf.file().mode() & mode::FMODE_WRITE) != 0
    }

    pub(crate) fn make_writable(&mut self, writable: bool) -> Result<()> {
        if writable && !Self::is_dmabuf_writable(&self.dmabuf) {
            return Err(EACCES);
        }

        self.writable = writable;

        Ok(())
    }

    pub(crate) fn is_writable(&self) -> bool {
        self.writable && Self::is_dmabuf_writable(&self.dmabuf)
    }

    pub(crate) fn new(fd: u32, prot: u32) -> Result<Self> {
        // Userspace relies on this error to be EBADF if the u32 were to overflow an i32.
        // `i32::try_from()` results in `TryFromIntError` in that case, which `Error` converts
        // to EINVAL by default.
        let fd = i32::try_from(fd).map_err(|_| EBADF)?;
        let dmabuf = DmaBuf::get(fd)?;
        let writable = (prot & bindings::PROT_WRITE) != 0;

        if writable && !Self::is_dmabuf_writable(&dmabuf) {
            return Err(EACCES);
        }

        Ok(Self { dmabuf, writable })
    }

    pub(crate) fn create_wrap(
        context: Pin<KBox<Wrap>>,
        content: DmaBufContent,
        close_on_exec: bool,
    ) -> Result<u32, (Error, DmaBufContent)> {
        let size = content.dmabuf.size();
        let size = match Offset::try_from(size) {
            Err(_err) => {
                return Err((EINVAL, content));
            }
            Ok(size) => size,
        };

        let writable = content.is_writable();

        let mut flags = 0;
        if close_on_exec {
            flags |= bindings::O_CLOEXEC
        };
        if writable {
            flags |= bindings::O_RDWR
        } else {
            flags |= bindings::O_RDONLY
        };

        let reservation = match FileDescriptorReservation::get_unused_fd_flags(flags) {
            Err(err) => {
                return Err((err, content));
            }
            Ok(reservation) => reservation,
        };

        let inner_clone = Arc::clone(&context.inner);
        let mut guard = inner_clone.lock();
        guard.content = Some(content);

        let file =
            create_wrap_file(c_str!("[wrapfd]"), context, flags).map_err(|(err, _context)| {
                let content = guard
                    .content
                    .take()
                    .expect("We put a Some() in, we expect it still to be there");
                (err, content)
            })?;

        drop(guard);

        // SAFETY: `file` is a valid `kernel::fs::File` reference, ensuring `file.as_ptr()` is
        // non-null and points to an active `struct file`.
        let inode = unsafe { bindings::file_inode(file.as_ptr()) };

        // SAFETY: `file_inode` on a valid `struct file` returns a non-null, valid pointer to its
        // `struct inode`.
        unsafe { bindings::i_size_write(inode, size) };

        let fd = reservation.reserved_fd();
        reservation.fd_install(file);

        Ok(fd)
    }

    pub(crate) fn ioctl(&self, cmd: u32, arg: usize) -> Result<isize> {
        // pr_info!("DmaBufContent::ioctl\n");

        let file = self.dmabuf.file();
        let file_ptr = file.as_ptr();

        // SAFETY: "file" is valid as "dmabuf" holds a reference to it.
        let f_op = unsafe { (*file_ptr).f_op };

        // SAFETY: `in_compat_syscall` is safe to call.
        let opt_ioctl_cb = if unsafe { bindings::in_compat_syscall() } {
            // SAFETY: `f_op` is a valid pointer to the file's `struct file_operations`.
            unsafe { (*f_op).compat_ioctl }
        } else {
            // SAFETY: `f_op` is a valid pointer to the file's `struct file_operations`.
            unsafe { (*f_op).unlocked_ioctl }
        };

        // SAFETY: `f_op` is a valid pointer to the file's `struct file_operations`.
        let Some(ioctl_cb) = opt_ioctl_cb else {
            return Err(ENOIOCTLCMD);
        };

        // SAFETY: `file_ptr` is valid, `unlocked_ioctl` is a verified non-null function pointer,
        // and `cmd`/`arg` are primitive values passed directly per C ABI.
        let res = unsafe { ioctl_cb(file_ptr, cmd, arg) };

        if res < 0 {
            Err(Error::from_errno(res as i32))
        } else {
            Ok(res)
        }
    }

    pub(crate) fn llseek(&mut self, offs: Offset, whence: ffi::c_int) -> Result<Offset> {
        let file = self.dmabuf.file();
        let file_ptr = file.as_ptr();

        // SAFETY: "file" is valid as "dmabuf" holds a reference to it.
        let f_op = unsafe { (*file_ptr).f_op };

        // SAFETY: `f_op` is a valid pointer to the file's `struct file_operations`.
        let Some(llseek) = (unsafe { (*f_op).llseek }) else {
            return Err(ESPIPE);
        };

        // SAFETY: `file_ptr` is valid, `llseek` is a verified non-null function pointer,
        // and `cmd`/`arg` are primitive values passed directly per C ABI.
        let res = unsafe { llseek(file_ptr, offs, whence) };

        if res < 0 {
            Err(Error::from_errno(res as i32)) // XXX fishy
        } else {
            Ok(res)
        }
    }

    fn load_prepare(
        dmabuf: &DmaBuf,
        file: &LocalFile,
        file_offs: usize,
        buf_offs: usize,
        len: usize,
    ) -> Result<(DmaBufVmap, IoContext)> {
        /* We will only write into buf_offs + len, so no need to page-align the length here. */
        let Some(buf_end) = buf_offs.checked_add(len) else {
            return Err(EINVAL);
        };

        if buf_end > dmabuf.size() {
            return Err(EINVAL);
        }

        let map = dmabuf.vmap()?;

        let Some(vaddr) = map.vaddr() else {
            return Err(EINVAL);
        };

        // SAFETY: We've verified that the `dmabuf` has the required dimensions and we're making
        // sure to pass that same map to `complete` later.
        let mut io_context = unsafe { IoContext::new(file_offs, vaddr, buf_offs, len)? };
        io_context.prepare(file)?;

        Ok((map, io_context))
    }

    pub(crate) fn load(
        dmabuf: &DmaBuf,
        file: ARef<LocalFile>,
        file_offs: Offset,
        buf_offs: Offset,
        len: Offset,
    ) -> Result<isize> {
        // pr_info!("DmaBufContent::load\n");

        let file_offs: usize = file_offs.try_into()?;
        let buf_offs: usize = buf_offs.try_into()?;
        let len: usize = len.try_into()?;

        let (map, mut io_context) = Self::load_prepare(dmabuf, &file, file_offs, buf_offs, len)?;

        map.begin_cpu_access_bidirectional_fallible(|access| -> Result<()> {
            io_context.read()?;
            io_context.complete(&map, access)?;

            Ok(())
        })?;

        Ok(0)
    }
}
