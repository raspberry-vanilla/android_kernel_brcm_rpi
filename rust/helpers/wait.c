// SPDX-License-Identifier: GPL-2.0

#include <linux/wait.h>

__rust_helper void rust_helper_init_wait(struct wait_queue_entry *wq_entry)
{
	init_wait(wq_entry);
}

__rust_helper void rust_helper_init_waitqueue_head(struct wait_queue_head *wq)
{
	init_waitqueue_head(wq);
}

__rust_helper int rust_helper_wake_up_interruptible(struct wait_queue_head *wq)
{
	return wake_up_interruptible(wq);
}
