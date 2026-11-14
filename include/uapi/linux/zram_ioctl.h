/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef _UAPI_LINUX_ZRAM_IOCTL_H
#define _UAPI_LINUX_ZRAM_IOCTL_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define ZRAM_ANDROID_IOC_VERSION 1

/* Legacy for process writeback */
struct zram_android_ioc_data_process_writeback {
	__aligned_u64	pidfd;
	__u64		written_bytes;
};

/*
 * Legacy for process writeback.
 * Modify the members or the size of the 'data' union can break the ABI
 * compatibility.
 *
 * Deprecated: Use struct zram_android_ioc_process_range_writeback for new
 * implementations.
 */
struct zram_android_ioc_data {
	union {
		struct zram_android_ioc_data_process_writeback process_writeback;
	} data;
};

struct zram_android_ioc_process_range_writeback {
	/* The pidfd of the process to scan for writeback candidates */
	__aligned_u64	pidfd;
	/* The starting virtual address for the scan */
	__u64		start_addr;
	/**
	 * Maximum number of candidate bytes to scan for writeback. The scan
	 * process will iterate the process address space from the @start_addr,
	 * and stop when the number of writeback candidates is larger than
	 * @size. If the @size is zero, the scan range is unlimited.
	 */
	__u64		size;
	/**
	 * The address where the scan stopped exclusively. Can be used as the
	 * @start_addr for the next call. If the scan reaches the end of the
	 * address space, it will be set to zero.
	 */
	__u64		next_addr;
	/* Total number of bytes successfully written back */
	__u64		written_bytes;
};

/*
 * Extensible argument of ZRAM_ANDROID_IOC_PROCESS_PREFETCH.
 *
 * The struct is append-only. The kernel takes the size of the user struct
 * from _IOC_SIZE(cmd), so userspace built against an older (smaller) or
 * newer (larger) version of this struct keeps working:
 *  - Fields unknown to userspace are treated as zero by the kernel.
 *  - Fields unknown to the kernel must be zero, otherwise -E2BIG is
 *    returned.
 *  - Output fields are copied back only if the cmd has _IOC_READ, and at
 *    most min(user size, kernel size) bytes are copied.
 */
struct zram_android_ioc_process_prefetch {
	/* in: the pidfd of the process to scan for prefetch candidates */
	__aligned_u64	pidfd;
	/* in: must be zero */
	__u32		flags;
	/* out: size of this struct known by the kernel */
	__u32		size;
	/* out: total number of bytes successfully prefetched */
	__u64		read_bytes;
};

/* sizeof first published struct, used by the legacy _IOW cmd */
#define ZRAM_ANDROID_IOC_PROCESS_PREFETCH_SIZE_VER0	8
/* adds flags, size and read_bytes */
#define ZRAM_ANDROID_IOC_PROCESS_PREFETCH_SIZE_VER1	24

#define ZRAM_ANDROID_IOC_MAGIC 0xBB

/* Legacy API: keep it for compatibility */
#define ZRAM_ANDROID_IOC_PROCESS_WRITEBACK \
	_IOWR(ZRAM_ANDROID_IOC_MAGIC, 1, struct zram_android_ioc_data)

#define ZRAM_ANDROID_IOC_PROCESS_RANGE_WRITEBACK \
	_IOWR(ZRAM_ANDROID_IOC_MAGIC, 2, struct zram_android_ioc_process_range_writeback)

/*
 * Matched by _IOC_TYPE/_IOC_NR only. Binaries built with the previous
 * _IOW definition (SIZE_VER0) are still accepted, but get no output.
 */
#define ZRAM_ANDROID_IOC_PROCESS_PREFETCH \
	_IOWR(ZRAM_ANDROID_IOC_MAGIC, 3, struct zram_android_ioc_process_prefetch)

#define ZRAM_ANDROID_IOC_GET_VERSION _IO(ZRAM_ANDROID_IOC_MAGIC, 4)

#endif /* _UAPI_LINUX_ZRAM_IOCTL_H */

