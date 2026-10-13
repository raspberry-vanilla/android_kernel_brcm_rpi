/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM ptrace

#ifdef CREATE_TRACE_POINTS
#define TRACE_INCLUDE_PATH trace/hooks
#define UNDEF_TRACE_INCLUDE_PATH
#endif

#if !defined(_TRACE_HOOK_PTRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOK_PTRACE_H

#include <trace/hooks/vendor_hooks.h>

struct task_struct;
struct file;
DECLARE_RESTRICTED_HOOK(android_rvh_ptrace,
	TP_PROTO(struct task_struct *task, long request),
	TP_ARGS(task, request), 1);
#endif /* _TRACE_HOOK_PTRACE_H */
/* This part must be outside protection */
#include <trace/define_trace.h>
