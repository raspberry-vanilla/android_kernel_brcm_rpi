// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2025 Google LLC.

use core::sync::atomic::{AtomicBool, Ordering};
use kernel::{
    net::netlink::GENLMSG_DEFAULT_SIZE,
    prelude::*,
    seq_file::SeqFile,
    seq_print,
    str::BStr,
    sync::atomic::{ordering::Relaxed, Atomic},
    sync::{Arc, SetOnce, SpinLock},
    task::{Kuid, Pid},
    time::{Instant, Monotonic},
    types::ScopeGuard,
};

use crate::{
    allocation::{Allocation, TranslatedFds},
    defs::*,
    error::{BinderError, BinderResult, ErrorLocation},
    netlink::Report,
    node::{Node, NodeRef},
    prio::{self, BinderPriority, PriorityState},
    process::{Process, ProcessInner},
    ptr_align,
    thread::{PushWorkRes, Thread},
    BinderReturnWriter, DArc, DLArc, DTRWrap, DeliverToRead,
};

const LOG_SIZE: usize = 32;

pub(crate) static TRANSACTION_LOG: TransactionLog = TransactionLog::new();
pub(crate) static FAILED_TRANSACTION_LOG: TransactionLog = TransactionLog::new();

#[derive(Copy, Clone)]
enum CallType {
    Call,
    Async,
    Reply,
}

#[derive(Copy, Clone)]
pub(crate) struct TransactionLogEntry {
    debug_id: usize,
    call_type: CallType,
    from_proc: Pid,
    from_thread: Pid,
    // The kernel ignores `target.handle` on replies (where `libbinder` passes `-1` / `0xffffffff`),
    // and C Binder stores and prints this field as a signed `int` (`%d`).
    target_handle: i32,
    to_proc: Pid,
    to_thread: Pid,
    to_node: usize,
    data_size: usize,
    offsets_size: usize,
    return_error_line: Option<ErrorLocation>,
    return_error: u32,
    return_error_param: i32,
    context_name: [u8; 16],
}

impl TransactionLogEntry {
    const fn empty() -> Self {
        Self {
            debug_id: 0,
            call_type: CallType::Call,
            from_proc: 0,
            from_thread: 0,
            target_handle: 0,
            to_proc: 0,
            to_thread: 0,
            to_node: 0,
            data_size: 0,
            offsets_size: 0,
            return_error_line: None,
            return_error: 0,
            return_error_param: 0,
            context_name: [0; 16],
        }
    }

    fn new(info: &TransactionInfo, ctx: &crate::Context) -> Self {
        let call_type = if info.is_reply {
            CallType::Reply
        } else if info.is_oneway() {
            CallType::Async
        } else {
            CallType::Call
        };
        let name_bytes = ctx.name.to_bytes();
        let mut context_name = [0u8; 16];
        let len = usize::min(name_bytes.len(), context_name.len());
        context_name[..len].copy_from_slice(&name_bytes[..len]);

        let failed = info.reply != 0 && info.reply != BR_TRANSACTION_PENDING_FROZEN;
        Self {
            debug_id: info.debug_id,
            call_type,
            from_proc: info.from_pid,
            from_thread: info.from_tid,
            target_handle: info.target_handle as i32,
            to_proc: info.to_pid,
            to_thread: info.to_tid,
            to_node: info.to_node_debug_id,
            data_size: info.data_size,
            offsets_size: info.offsets_size,
            return_error_line: if failed { info.error_line } else { None },
            return_error: if failed { info.reply } else { 0 },
            return_error_param: if failed { info.errno } else { 0 },
            context_name,
        }
    }
}

#[pin_data]
#[repr(align(64))]
struct TransactionLogSlot {
    #[pin]
    entry: SpinLock<TransactionLogEntry>,
}

pub(crate) struct TransactionLog {
    cur: Atomic<usize>,
    entries: SetOnce<Pin<KBox<[TransactionLogSlot; LOG_SIZE]>>>,
}

impl TransactionLog {
    const fn new() -> Self {
        Self {
            cur: Atomic::new(0),
            entries: SetOnce::new(),
        }
    }

    pub(crate) fn init(&self) -> Result {
        let entries = KBox::pin_init(
            pin_init::pin_init_array_from_fn(|_| {
                pin_init!(TransactionLogSlot {
                    entry <- kernel::new_spinlock!(
                        TransactionLogEntry::empty(),
                        "TransactionLog::entries"
                    ),
                })
            }),
            GFP_KERNEL,
        )?;
        self.entries.populate(entries);
        Ok(())
    }

    fn add(&self, entry: &TransactionLogEntry) {
        let Some(entries) = self.entries.as_ref() else {
            return;
        };
        let idx = self.cur.fetch_add(1, Relaxed) % LOG_SIZE;
        let mut slot = entries[idx].entry.lock();
        // Avoid overwriting a newer entry if the ring buffer wraps around between `fetch_add` and
        // acquiring the lock.
        // CAST: Overflowing behavior of this cast is intentional to handle `debug_id` wrap-around.
        let diff = slot.debug_id.wrapping_sub(entry.debug_id) as isize;
        if slot.debug_id == 0 || diff < 0 {
            *slot = *entry;
        }
    }

    pub(crate) fn debug_print(&self, m: &SeqFile) {
        let Some(entries) = self.entries.as_ref() else {
            return;
        };
        let cur = self.cur.load(Relaxed);
        for i in 0..LOG_SIZE {
            let idx = cur.wrapping_add(i) % LOG_SIZE;
            let entry = *entries[idx].entry.lock();
            if entry.debug_id == 0 {
                continue;
            }
            let call_type = match entry.call_type {
                CallType::Call => "call ",
                CallType::Async => "async",
                CallType::Reply => "reply",
            };
            let ctx_name = match core::ffi::CStr::from_bytes_until_nul(&entry.context_name) {
                Ok(cstr) => BStr::from_bytes(cstr.to_bytes()),
                Err(_) => BStr::from_bytes(&entry.context_name),
            };
            let return_error_line: &dyn kernel::fmt::Display = match &entry.return_error_line {
                Some(line) => line,
                None => &0,
            };
            seq_print!(
                m,
                "{}: {} from {}:{} to {}:{} context {} node {} handle {} size {}:{} ret {}/{} l={}\n",
                entry.debug_id,
                call_type,
                entry.from_proc,
                entry.from_thread,
                entry.to_proc,
                entry.to_thread,
                ctx_name,
                entry.to_node,
                entry.target_handle,
                entry.data_size,
                entry.offsets_size,
                entry.return_error,
                entry.return_error_param,
                return_error_line,
            );
        }
    }
}

pub(crate) struct TransactionInfo {
    pub(crate) from_pid: Pid,
    pub(crate) from_tid: Pid,
    pub(crate) to_pid: Pid,
    pub(crate) to_tid: Pid,
    pub(crate) to_node_debug_id: usize,
    pub(crate) code: u32,
    pub(crate) flags: u32,
    pub(crate) data_ptr: UserPtr,
    pub(crate) data_size: usize,
    pub(crate) offsets_ptr: UserPtr,
    pub(crate) offsets_size: usize,
    pub(crate) buffers_size: usize,
    pub(crate) target_handle: u32,
    pub(crate) errno: i32,
    pub(crate) reply: u32,
    pub(crate) error_line: Option<ErrorLocation>,
    pub(crate) oneway_spam_suspect: bool,
    pub(crate) is_reply: bool,
    pub(crate) debug_id: usize,
}

// SAFETY: All fields of `TransactionInfo` can be safely zero-initialized.
unsafe impl Zeroable for TransactionInfo {}

impl TransactionInfo {
    #[inline]
    pub(crate) fn is_oneway(&self) -> bool {
        self.flags & TF_ONE_WAY != 0
    }

    pub(crate) fn write_log(&self, ctx: &crate::Context) {
        let entry = TransactionLogEntry::new(self, ctx);
        TRANSACTION_LOG.add(&entry);
        if self.reply != 0 && self.reply != BR_TRANSACTION_PENDING_FROZEN {
            FAILED_TRANSACTION_LOG.add(&entry);
        }
    }

    pub(crate) fn report_netlink(&self, reply: u32, ctx: &crate::Context) {
        if let Err(err) = self.report_netlink_inner(reply, ctx) {
            pr_warn!(
                "{}:{} netlink report failed: {err:?}\n",
                self.from_pid,
                self.from_tid
            );
        }
    }

    fn report_netlink_inner(&self, reply: u32, ctx: &crate::Context) -> kernel::error::Result {
        if !Report::has_listeners() {
            return Ok(());
        }
        let mut report = Report::new(GENLMSG_DEFAULT_SIZE, 0, 0, GFP_KERNEL)?;

        report.error(reply)?;
        report.context(&ctx.name)?;
        report.from_pid(self.from_pid as u32)?;
        report.from_tid(self.from_tid as u32)?;
        if self.to_pid != 0 {
            report.to_pid(self.to_pid as u32)?;
        }
        if self.to_tid != 0 {
            report.to_tid(self.to_tid as u32)?;
        }

        if self.is_reply {
            report.is_reply()?;
        }
        report.flags(self.flags)?;
        report.code(self.code)?;
        report.data_size(self.data_size as u32)?;

        report.multicast(0, GFP_KERNEL)?;
        Ok(())
    }
}

use core::mem::offset_of;
use kernel::bindings::rb_transaction_layout;
pub(crate) const TRANSACTION_LAYOUT: rb_transaction_layout = rb_transaction_layout {
    debug_id: offset_of!(Transaction, debug_id),
    code: offset_of!(Transaction, code),
    flags: offset_of!(Transaction, flags),
    from_thread: offset_of!(Transaction, from),
    to_proc: offset_of!(Transaction, to),
    target_node: offset_of!(Transaction, target_node),
    __kabi_reserved_backport0: 0,
    __kabi_reserved_backport1: 0,
    __kabi_reserved_backport2: 0,
    __kabi_reserved_backport3: 0,
};

#[pin_data(PinnedDrop)]
pub(crate) struct Transaction {
    pub(crate) debug_id: usize,
    target_node: Option<DArc<Node>>,
    pub(crate) from_parent: Option<DArc<Transaction>>,
    pub(crate) from: Arc<Thread>,
    pub(crate) to: Arc<Process>,
    #[pin]
    allocation: SpinLock<Option<Allocation>>,
    is_outstanding: AtomicBool,
    code: u32,
    pub(crate) flags: u32,
    data_size: usize,
    offsets_size: usize,
    data_address: usize,
    sender_euid: Kuid,
    txn_security_ctx_off: Option<usize>,
    start_time: Instant<Monotonic>,
    set_priority_called: AtomicBool,
    priority: BinderPriority,
    #[pin]
    saved_priority: SpinLock<BinderPriority>,
}

kernel::list::impl_list_arc_safe! {
    impl ListArcSafe<0> for Transaction { untracked; }
}

impl Transaction {
    pub(crate) fn new(
        node_ref: NodeRef,
        from_parent: Option<DArc<Transaction>>,
        from: &Arc<Thread>,
        info: &mut TransactionInfo,
    ) -> BinderResult<DLArc<Self>> {
        let allow_fds = node_ref.node.flags & FLAT_BINDER_FLAG_ACCEPTS_FDS != 0;
        let txn_security_ctx = node_ref.node.flags & FLAT_BINDER_FLAG_TXN_SECURITY_CTX != 0;
        let mut txn_security_ctx_off = if txn_security_ctx { Some(0) } else { None };
        let to = node_ref.node.owner.clone();
        let mut alloc = match from.copy_transaction_data(
            to.clone(),
            info,
            info.debug_id,
            allow_fds,
            txn_security_ctx_off.as_mut(),
        ) {
            Ok(alloc) => alloc,
            Err(err) => {
                if !err.is_dead() {
                    pr_warn!("Failure in copy_transaction_data: {:?}", err);
                }
                return Err(err);
            }
        };
        if info.is_oneway() {
            if from_parent.is_some() {
                pr_warn!("Oneway transaction should not be in a transaction stack.");
                return Err(EINVAL.into());
            }
            alloc.set_info_oneway_node(node_ref.node.clone());
        }
        if info.flags & TF_CLEAR_BUF != 0 {
            alloc.set_info_clear_on_drop();
        }
        let target_node = node_ref.node.clone();
        alloc.set_info_target_node(node_ref);
        let data_address = alloc.ptr;

        let priority = if !info.is_oneway() && prio::is_supported_policy(from.task.policy()) {
            BinderPriority {
                sched_policy: from.task.policy(),
                prio: from.task.normal_prio(),
            }
        } else {
            to.default_priority
        };

        Ok(DTRWrap::arc_pin_init(pin_init!(Transaction {
            debug_id: info.debug_id,
            target_node: Some(target_node),
            from_parent,
            sender_euid: Kuid::current_euid(),
            from: from.clone(),
            to,
            code: info.code,
            flags: info.flags,
            data_size: info.data_size,
            offsets_size: info.offsets_size,
            data_address,
            allocation <- kernel::new_spinlock!(Some(alloc.success()), "Transaction::new"),
            is_outstanding: AtomicBool::new(false),
            txn_security_ctx_off,
            start_time: Instant::now(),
            priority,
            saved_priority <- kernel::new_spinlock!(
                BinderPriority::default(),
                "Transaction::saved_priority"
            ),
            set_priority_called: AtomicBool::new(false),
        }))?)
    }

    pub(crate) fn new_reply(
        from: &Arc<Thread>,
        to: Arc<Process>,
        info: &mut TransactionInfo,
        allow_fds: bool,
    ) -> BinderResult<DLArc<Self>> {
        let mut alloc =
            match from.copy_transaction_data(to.clone(), info, info.debug_id, allow_fds, None) {
                Ok(alloc) => alloc,
                Err(err) => {
                    pr_warn!("Failure in copy_transaction_data: {:?}", err);
                    return Err(err);
                }
            };
        if info.flags & TF_CLEAR_BUF != 0 {
            alloc.set_info_clear_on_drop();
        }
        Ok(DTRWrap::arc_pin_init(pin_init!(Transaction {
            debug_id: info.debug_id,
            target_node: None,
            from_parent: None,
            sender_euid: Kuid::current_euid(),
            from: from.clone(),
            to,
            code: info.code,
            flags: info.flags,
            data_size: info.data_size,
            offsets_size: info.offsets_size,
            data_address: alloc.ptr,
            allocation <- kernel::new_spinlock!(Some(alloc.success()), "Transaction::new"),
            is_outstanding: AtomicBool::new(false),
            txn_security_ctx_off: None,
            start_time: Instant::now(),
            priority: BinderPriority::default(),
            saved_priority <- kernel::new_spinlock!(
                BinderPriority::default(),
                "Transaction::saved_priority"
            ),
            set_priority_called: AtomicBool::new(false),
        }))?)
    }

    #[inline(never)]
    pub(crate) fn debug_print_inner(&self, m: &SeqFile, prefix: &str) {
        seq_print!(
            m,
            "{}{}: from {}:{} to {} code {:x} flags {:x} elapsed {}ms",
            prefix,
            self.debug_id,
            self.from.process.task.pid(),
            self.from.id,
            self.to.task.pid(),
            self.code,
            self.flags,
            self.start_time.elapsed().as_millis(),
        );
        if let Some(target_node) = &self.target_node {
            seq_print!(m, " node {}", target_node.debug_id);
        }
        seq_print!(m, " size {}:{}\n", self.data_size, self.offsets_size);
    }

    pub(crate) fn saved_priority(&self) -> BinderPriority {
        *self.saved_priority.lock()
    }

    /// Determines if the transaction is stacked on top of the given transaction.
    pub(crate) fn is_stacked_on(&self, onext: &Option<DArc<Self>>) -> bool {
        match (&self.from_parent, onext) {
            (None, None) => true,
            (Some(from_parent), Some(next)) => Arc::ptr_eq(from_parent, next),
            _ => false,
        }
    }

    /// Returns a pointer to the next transaction on the transaction stack, if there is one.
    pub(crate) fn clone_next(&self) -> Option<DArc<Self>> {
        Some(self.from_parent.as_ref()?.clone())
    }

    /// Searches in the transaction stack for a thread that belongs to the target process. This is
    /// useful when finding a target for a new transaction: if the node belongs to a process that
    /// is already part of the transaction stack, we reuse the thread.
    fn find_target_thread(&self) -> Option<Arc<Thread>> {
        let mut it = &self.from_parent;
        while let Some(transaction) = it {
            if Arc::ptr_eq(&transaction.from.process, &self.to) {
                return Some(transaction.from.clone());
            }
            it = &transaction.from_parent;
        }
        None
    }

    /// Searches in the transaction stack for a transaction originating at the given thread.
    pub(crate) fn find_from(&self, thread: &Thread) -> Option<&DArc<Transaction>> {
        let mut it = &self.from_parent;
        while let Some(transaction) = it {
            if core::ptr::eq(thread, transaction.from.as_ref()) {
                return Some(transaction);
            }

            it = &transaction.from_parent;
        }
        None
    }

    pub(crate) fn set_outstanding(&self, to_process: &mut ProcessInner) {
        // No race because this method is only called once.
        if !self.is_outstanding.load(Ordering::Relaxed) {
            self.is_outstanding.store(true, Ordering::Relaxed);
            to_process.add_outstanding_txn();
        }
    }

    /// Decrement `outstanding_txns` in `to` if it hasn't already been decremented.
    fn drop_outstanding_txn(&self) {
        // No race because this is called at most twice, and one of the calls are in the
        // destructor, which is guaranteed to not race with any other operations on the
        // transaction. It also cannot race with `set_outstanding`, since submission happens
        // before delivery.
        if self.is_outstanding.load(Ordering::Relaxed) {
            self.is_outstanding.store(false, Ordering::Relaxed);
            self.to.drop_outstanding_txn();
        }
    }

    /// Submits the transaction to a work queue. Uses a thread if there is one in the transaction
    /// stack, otherwise uses the destination process.
    ///
    /// Not used for replies.
    pub(crate) fn submit(self: DLArc<Self>, info: &mut TransactionInfo) -> BinderResult {
        // Defined before `process_inner` so that the destructor runs after releasing the lock.
        let _t_outdated;
        let _oneway_node;

        let oneway = self.flags & TF_ONE_WAY != 0;
        let process = self.to.clone();
        let mut process_inner = process.inner.lock();

        self.set_outstanding(&mut process_inner);

        if oneway {
            if let Some(target_node) = self.target_node.clone() {
                crate::trace::trace_transaction(false, &self, None);
                if process_inner.is_frozen.is_frozen() {
                    process_inner.async_recv = true;
                    if self.flags & TF_UPDATE_TXN != 0 {
                        if let Some(t_outdated) =
                            target_node.take_outdated_transaction(&self, &mut process_inner)
                        {
                            crate::trace::trace_transaction_update_buffer_release(
                                t_outdated.debug_id,
                            );
                            let mut alloc_guard = t_outdated.allocation.lock();
                            if let Some(alloc) = (*alloc_guard).as_mut() {
                                // Take the oneway node to prevent `Allocation::drop` from calling
                                // `pending_oneway_finished()`, which would be incorrect as this
                                // transaction is not being submitted.
                                _oneway_node = alloc.take_oneway_node();
                            }
                            drop(alloc_guard);
                            // Save the transaction to be dropped after locks are released.
                            _t_outdated = t_outdated;
                        }
                    }
                }
                match target_node.submit_oneway(self, &mut process_inner) {
                    Ok(()) => {}
                    Err((err, work)) => {
                        drop(process_inner);
                        // Drop work after releasing process lock.
                        drop(work);
                        return Err(err);
                    }
                }

                if process_inner.is_frozen.is_frozen() {
                    return Err(BinderError::new_frozen_oneway());
                } else {
                    return Ok(());
                }
            } else {
                pr_err!("Failed to submit oneway transaction to node.");
            }
        }

        if process_inner.is_frozen.is_frozen() {
            process_inner.sync_recv = true;
            return Err(BinderError::new_frozen());
        }

        let res = if let Some(thread) = self.find_target_thread() {
            info.to_tid = thread.id;
            crate::trace::trace_transaction(false, &self, Some(&thread.task));
            match thread.push_work(self) {
                PushWorkRes::Ok => Ok(()),
                PushWorkRes::OkNotifyPoll => {
                    process.notify_poll(true);
                    Ok(())
                }
                PushWorkRes::FailedDead(me) => Err((BinderError::new_dead(), me)),
            }
        } else {
            crate::trace::trace_transaction(false, &self, None);
            process_inner.push_work(&process, self)
        };
        drop(process_inner);

        match res {
            Ok(()) => Ok(()),
            Err((err, work)) => {
                // Drop work after releasing process lock.
                drop(work);
                Err(err)
            }
        }
    }

    /// Check whether one oneway transaction can supersede another.
    pub(crate) fn can_replace(&self, old: &Transaction) -> bool {
        if self.from.process.task.pid() != old.from.process.task.pid() {
            return false;
        }

        if self.flags & old.flags & (TF_ONE_WAY | TF_UPDATE_TXN) != (TF_ONE_WAY | TF_UPDATE_TXN) {
            return false;
        }

        let target_node_match = match (self.target_node.as_ref(), old.target_node.as_ref()) {
            (None, None) => true,
            (Some(tn1), Some(tn2)) => Arc::ptr_eq(tn1, tn2),
            _ => false,
        };

        self.code == old.code && self.flags == old.flags && target_node_match
    }

    fn prepare_file_list(&self) -> Result<TranslatedFds> {
        let mut alloc = self.allocation.lock().take().ok_or(ESRCH)?;

        match alloc.translate_fds() {
            Ok(translated) => {
                *self.allocation.lock() = Some(alloc);
                Ok(translated)
            }
            Err(err) => {
                // Free the allocation eagerly.
                drop(alloc);
                Err(err)
            }
        }
    }
}

impl DeliverToRead for Transaction {
    fn do_work(
        self: DArc<Self>,
        thread: &Thread,
        writer: &mut BinderReturnWriter<'_>,
    ) -> Result<bool> {
        let send_failed_reply = ScopeGuard::new(|| {
            if self.target_node.is_some() && self.flags & TF_ONE_WAY == 0 {
                let reply = Err(BR_FAILED_REPLY);
                self.from.deliver_reply(reply, &self, None);
            }
            self.drop_outstanding_txn();
        });

        // Update thread priority. This only has an effect if the transaction is delivered via the
        // process work list, since the priority has otherwise already been updated.
        self.on_thread_selected(thread);

        let files = if let Ok(list) = self.prepare_file_list() {
            list
        } else {
            // On failure to process the list, we send a reply back to the sender and ignore the
            // transaction on the recipient.
            binder_debug!(
                FailedTransaction,
                "transaction {} to {} failed, fd fixups failed, size {}-{}",
                self.debug_id,
                self.to.task.pid(),
                self.data_size,
                self.offsets_size
            );
            return Ok(true);
        };

        let mut tr_sec = BinderTransactionDataSecctx::default();
        let tr = tr_sec.tr_data();
        if let Some(target_node) = &self.target_node {
            let (ptr, cookie) = target_node.get_id();
            tr.target.ptr = ptr as _;
            tr.cookie = cookie as _;
        };
        tr.code = self.code;
        tr.flags = self.flags;
        tr.data_size = self.data_size as _;
        tr.data.ptr.buffer = self.data_address as _;
        tr.offsets_size = self.offsets_size as _;
        if tr.offsets_size > 0 {
            tr.data.ptr.offsets = (self.data_address + ptr_align(self.data_size).unwrap()) as _;
        }
        tr.sender_euid = self.sender_euid.into_uid_in_current_ns();
        tr.sender_pid = 0;
        if self.target_node.is_some() && self.flags & TF_ONE_WAY == 0 {
            // Not a reply and not one-way.
            tr.sender_pid = self.from.process.pid_in_current_ns();
        }
        let code = if self.target_node.is_none() {
            BR_REPLY
        } else if self.txn_security_ctx_off.is_some() {
            BR_TRANSACTION_SEC_CTX
        } else {
            BR_TRANSACTION
        };

        // Write the transaction code and data to the user buffer.
        writer.write_code(code)?;
        if let Some(off) = self.txn_security_ctx_off {
            tr_sec.secctx = (self.data_address + off) as u64;
            writer.write_payload(&tr_sec)?;
        } else {
            writer.write_payload(&*tr)?;
        }

        let mut alloc = self.allocation.lock().take().ok_or(ESRCH)?;

        // Dismiss the completion of transaction with a failure. No failure paths are allowed from
        // here on out.
        send_failed_reply.dismiss();

        // Commit files, and set FDs in FDA to be closed on buffer free.
        let close_on_free = files.commit();
        alloc.set_info_close_on_free(close_on_free);

        // It is now the user's responsibility to clear the allocation.
        alloc.keep_alive();

        self.drop_outstanding_txn();

        crate::trace::trace_transaction_received(&self);

        // When this is not a reply and not a oneway transaction, update `current_transaction`. If
        // it's a reply, `current_transaction` has already been updated appropriately.
        if self.target_node.is_some() && tr_sec.transaction_data.flags & TF_ONE_WAY == 0 {
            thread.set_current_transaction(self);
        }

        Ok(false)
    }

    fn cancel(self: DArc<Self>) {
        let allocation = self.allocation.lock().take();
        drop(allocation);

        // If this is not a reply or oneway transaction, then send a dead reply.
        if self.target_node.is_some() && self.flags & TF_ONE_WAY == 0 {
            let reply = Err(BR_DEAD_REPLY);
            self.from.deliver_reply(reply, &self, None);
        } else {
            binder_debug!(
                pid = self.to.task.pid(),
                DeadTransaction,
                "undelivered transaction {}, process died",
                self.debug_id
            );
        }

        self.drop_outstanding_txn();
    }

    fn on_thread_selected(&self, to_thread: &Thread) {
        // Return immediately if reply.
        let target_node = match self.target_node.as_ref() {
            Some(target_node) => target_node,
            None => return,
        };

        // We only need to do this once.
        if self.set_priority_called.swap(true, Ordering::Relaxed) {
            return;
        }

        crate::trace::trace_transaction_thread_selected(self, to_thread);

        let node_prio = target_node.node_prio();
        let mut desired = self.priority;

        if !target_node.inherit_rt() && prio::is_rt_policy(desired.sched_policy) {
            desired.prio = prio::DEFAULT_PRIO;
            desired.sched_policy = prio::SCHED_NORMAL;
        }

        if node_prio.prio < desired.prio
            || (node_prio.prio == desired.prio && node_prio.sched_policy == prio::SCHED_FIFO)
        {
            // In case the minimum priority on the node is
            // higher (lower value), use that priority. If
            // the priority is the same, but the node uses
            // SCHED_FIFO, prefer SCHED_FIFO, since it can
            // run unbounded, unlike SCHED_RR.
            desired = node_prio;
        }

        let mut prio_state = to_thread.prio_lock.lock();
        if prio_state.state == PriorityState::Pending {
            // Task is in the process of changing priorities
            // saving its current values would be incorrect.
            // Instead, save the pending priority and signal
            // the task to abort the priority restore.
            prio_state.state = PriorityState::Abort;
            *self.saved_priority.lock() = prio_state.next;
        } else {
            let task = &*to_thread.task;
            let mut saved_priority = self.saved_priority.lock();
            saved_priority.sched_policy = task.policy();
            saved_priority.prio = task.normal_prio();
        }
        drop(prio_state);

        to_thread.set_priority(&desired, self);
    }

    fn should_sync_wakeup(&self) -> bool {
        self.flags & TF_ONE_WAY == 0
    }

    fn debug_print(&self, m: &SeqFile, _prefix: &str, tprefix: &str) -> Result<()> {
        self.debug_print_inner(m, tprefix);
        Ok(())
    }
}

#[pinned_drop]
impl PinnedDrop for Transaction {
    fn drop(self: Pin<&mut Self>) {
        self.drop_outstanding_txn();
    }
}
