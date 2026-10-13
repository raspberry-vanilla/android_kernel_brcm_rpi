// SPDX-License-Identifier: GPL-2.0

#include <linux/uio.h>

__rust_helper void rust_helper_iov_iter_truncate(struct iov_iter *i, u64 count)
{
	iov_iter_truncate(i, count);
}
