// SPDX-License-Identifier: GPL-2.0

#include <linux/container_of.h>
#include <linux/kfifo.h>

__rust_helper unsigned int rust_helper_kfifo_size(struct __kfifo *fifo)
{
	return kfifo_size(container_of(fifo, struct kfifo, kfifo));
}

__rust_helper unsigned int rust_helper_kfifo_esize(struct __kfifo *fifo)
{
	return kfifo_esize(container_of(fifo, struct kfifo, kfifo));
}

__rust_helper unsigned int rust_helper_kfifo_len(struct __kfifo *fifo)
{
	return kfifo_len(container_of(fifo, struct kfifo, kfifo));
}

__rust_helper unsigned int rust_helper_kfifo_avail(struct __kfifo *fifo)
{
	return kfifo_avail(container_of(fifo, struct kfifo, kfifo));
}

__rust_helper bool rust_helper_kfifo_is_empty(struct __kfifo *fifo)
{
	return kfifo_is_empty(container_of(fifo, struct kfifo, kfifo));
}

__rust_helper bool rust_helper_kfifo_is_full(struct __kfifo *fifo)
{
	return kfifo_is_full(container_of(fifo, struct kfifo, kfifo));
}

__rust_helper void rust_helper_kfifo_reset(struct __kfifo *fifo)
{
	kfifo_reset(container_of(fifo, struct kfifo, kfifo));
}

__rust_helper void rust_helper_kfifo_skip_count(struct __kfifo *fifo, unsigned int count)
{
	kfifo_skip_count(container_of(fifo, struct kfifo, kfifo), count);
}
