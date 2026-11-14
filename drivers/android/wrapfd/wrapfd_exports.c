// SPDX-License-Identifier: GPL-2.0

/*
 * Symbols exported from the Wrapfd Rust driver for loadable kernel modules to use.
 *
 * Copyright (c) 2026, Google LLC.
 */

#include <linux/device.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/wrapfd.h>

/*
 * List symbols that need to be exported to loadable kernel modules below. This is needed because
 * the logic that exports symbols from Rust crates only considers the crates under the rust/
 * directory at the root of the kernel repo. It currently does not support exporting symbols from
 * other crates.
 */
EXPORT_SYMBOL_GPL(wrapfd_get_mappable);
EXPORT_SYMBOL_GPL(wrapfd_put_mappable);
EXPORT_SYMBOL_GPL(wrapfd_add_listener);
EXPORT_SYMBOL_GPL(wrapfd_del_listener);
EXPORT_SYMBOL_GPL(wrapfd_acquire_ownership);
EXPORT_SYMBOL_GPL(wrapfd_release_ownership);
