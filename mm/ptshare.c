// SPDX-License-Identifier: GPL-2.0
/*
 * Shared Page Table Support
 *
 * The ptshare infrastructure lets processes share PTE-level page
 * tables for file-backed mappings that are mapped without write
 * permission. Paths that can still write through them, such as
 * mprotect() or FOLL_FORCE writes, unshare the tables first.
 * This is achieved by using a headless shadow MM (ptshare_mm) to
 * host the shared page tables.
 *
 * Copyright (c) 2026, Google LLC.
 * Author: Kalesh Singh <kaleshsingh@google.com>
 */
#include <linux/ptshare.h>

int __ptshare_unshare_vma(struct vm_area_struct *vma)
{
	return -EINVAL;
}
