/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Wrapfd UAPI
 *
 * Copyright (C) 2025 Google, Inc.
 */

#ifndef _UAPI_WRAPFD_H
#define _UAPI_WRAPFD_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct wrapfd_wrap {
	__u32 fd;		/* [in] file to wrap */
	__u32 prot;		/* [in] protection bits */
	__u64 reserved;
};

#define WRAPFD_CONTENT_EMPTY	0
#define WRAPFD_CONTENT_RDONLY	1
#define WRAPFD_CONTENT_RDWR	2

/* wrapfd_monitor.events bit values */
#define WRAPFD_EVENT_MAP	(1 << 0)
#define WRAPFD_EVENT_UNMAP	(1 << 1)
#define WRAPFD_EVENT_OWN	(1 << 2)
#define WRAPFD_EVENT_UNOWN	(1 << 3)
#define WRAPFD_EVENT_LOAD	(1 << 4)
#define WRAPFD_EVENT_LOAD_DONE	(1 << 5)

#define WRAPFD_EVENTS_MASK	(WRAPFD_EVENT_MAP | WRAPFD_EVENT_UNMAP | \
			WRAPFD_EVENT_OWN | WRAPFD_EVENT_UNOWN | \
			WRAPFD_EVENT_LOAD | WRAPFD_EVENT_LOAD_DONE)

struct wrapfd_get_state {
	__u32 state;		/* [out] wrapfd content state */
	__u32 pad;
	__u64 reserved;
};

struct wrapfd_load {
	__u32 fd;		/* [in] file to load */
	__u32 pad;
	__u64 file_offs;	/* [in] file offset */
	__u64 buf_offs;		/* [in] buffer offset */
	__u64 len;		/* [in] number of bytes to load */
	__u64 reserved;
};

struct wrapfd_rewrap {
	__u32 prot;		/* [in] protection bits */
	__u32 pad;
	__u64 reserved;
};

struct wrapfd_monitor {
	__u32 fd;
	__u32 events;
};

struct wrapfd_monitors {
	__u64 len;		/* [in] number of elements in arr and results */
	__u64 arr;		/* [in] array of struct wrapfd_monitor */
	__u64 results;		/* [in] array of integers */
};

struct wrapfd_add_monitors {
	struct wrapfd_monitors monitors;
	__u64 reserved;
};

struct wrapfd_del_monitors {
	struct wrapfd_monitors monitors;
	__u64 reserved;
};

struct wrapfd_event {
	__u32 fd;
	__u32 events;
	__u64 timestamp;
};

struct wrapfd_events {
	__u64 len;		/* [in] number of elements in arr */
	__u64 arr;		/* [in] array of struct wrapfd_event */
	__u64 count;
};

struct wrapfd_repopulate {
	__u32 wrapfd;		/* [in] wrapfd file to populate */
	__u32 fd;		/* [in] file to populate with */
	__u64 reserved;
};

#define WRAPFD_MAX_NR_MONITORS	(PAGE_SIZE / sizeof(struct wrapfd_monitor))
#define WRAPFD_MAX_NR_EVENTS	(PAGE_SIZE / sizeof(struct wrapfd_event))

/* ioctls for /dev/wrapfd */
#define WRAPFD_DEV_IOC 0xBC

/* ioctl for wrapfd */
enum {
	WRAPFD_DEV_IOC_WRAP	= _IOW(WRAPFD_DEV_IOC, 0, struct wrapfd_wrap),
	WRAPFD_DEV_IOC_GET_STATE	= _IOWR(WRAPFD_DEV_IOC, 1, struct wrapfd_get_state),
	WRAPFD_DEV_IOC_ACQUIRE_OWNERSHIP	= _IO(WRAPFD_DEV_IOC, 2),
	WRAPFD_DEV_IOC_RELEASE_OWNERSHIP	= _IO(WRAPFD_DEV_IOC, 3),
	WRAPFD_DEV_IOC_LOAD	= _IOW(WRAPFD_DEV_IOC, 4, struct wrapfd_load),
	WRAPFD_DEV_IOC_REWRAP	= _IOW(WRAPFD_DEV_IOC, 5, struct wrapfd_rewrap),
	WRAPFD_DEV_IOC_EMPTY	= _IO(WRAPFD_DEV_IOC, 6),
	WRAPFD_DEV_IOC_ALLOW_GUESTS	= _IO(WRAPFD_DEV_IOC, 7),
	WRAPFD_DEV_IOC_PROHIBIT_GUESTS	= _IO(WRAPFD_DEV_IOC, 8),
	WRAPFD_DEV_IOC_ADD_MONITOR	= _IOWR(WRAPFD_DEV_IOC, 9, struct wrapfd_add_monitors),
	WRAPFD_DEV_IOC_DEL_MONITOR	= _IOWR(WRAPFD_DEV_IOC, 10, struct wrapfd_del_monitors),
	WRAPFD_DEV_IOC_QUERY_EVENTS	= _IOWR(WRAPFD_DEV_IOC, 11, struct wrapfd_events),
	WRAPFD_DEV_IOC_REPOPULATE	= _IOW(WRAPFD_DEV_IOC, 12, struct wrapfd_repopulate),
};

#endif /* _UAPI_WRAPFD_H */
