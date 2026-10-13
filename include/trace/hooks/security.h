/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM security

#ifdef CREATE_TRACE_POINTS
#define TRACE_INCLUDE_PATH trace/hooks
#define UNDEF_TRACE_INCLUDE_PATH
#endif

#if !defined(_TRACE_HOOK_SECURITY_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOK_SECURITY_H
#include <trace/hooks/vendor_hooks.h>

/*
 * Following tracepoints are not exported in tracefs and provide a
 * mechanism for vendor modules to hook and extend functionality
 */

struct task_struct;
struct file;
struct dentry;
struct linux_binprm;
struct inode;

DECLARE_RESTRICTED_HOOK(android_rvh_security_inode_free,
	TP_PROTO(struct inode *inode),
	TP_ARGS(inode), 1);
DECLARE_RESTRICTED_HOOK(android_rvh_security_file_open,
	TP_PROTO(struct file *file, int *rc),
	TP_ARGS(file, rc), 1);
DECLARE_RESTRICTED_HOOK(android_rvh_security_file_free,
	TP_PROTO(struct file *file),
	TP_ARGS(file), 1);
DECLARE_RESTRICTED_HOOK(android_rvh_security_mmap_file,
	TP_PROTO(struct file *file, unsigned long prot, unsigned long flags, int *rc),
	TP_ARGS(file, prot, flags, rc), 1);
DECLARE_RESTRICTED_HOOK(android_rvh_security_task_alloc,
	TP_PROTO(struct task_struct *task, unsigned long clone_flags, int *rc),
	TP_ARGS(task, clone_flags, rc), 1);
DECLARE_RESTRICTED_HOOK(android_rvh_security_task_free,
	TP_PROTO(struct task_struct *task),
	TP_ARGS(task), 1);
DECLARE_RESTRICTED_HOOK(android_rvh_copy_process_integrity,
	TP_PROTO(unsigned long clone_flags, struct task_struct *p, int *retval),
	TP_ARGS(clone_flags, p, retval), 1);

#endif /* _TRACE_HOOK_SECURITY_H */
/* This part must be outside protection */
#include <trace/define_trace.h>
