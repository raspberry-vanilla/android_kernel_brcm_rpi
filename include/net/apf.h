/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Advanced Packet Filter (APF) kernel interface
 *
 * Copyright 2026 Google LLC
 */

#ifndef _NET_APF_H
#define _NET_APF_H

#include <linux/android_kabi.h>
#include <linux/if_ether.h>
#include <linux/types.h>

struct net_device;
struct netlink_ext_ack;

/**
 * struct apf_info - APF properties of the chip backing a network device
 * @chip_id: Opaque identifier owned by userspace. Neither the kernel, the
 *	driver nor the APF interpreter interpret it. Zero means unset.
 * @apf_version: APF interpreter version (e.g. 6100 represents APFv6.1).
 * @total_ram: Total APF RAM of the chip in bytes.
 * @overhead: Per-interface state overhead in bytes.
 * @granularity: Memory allocation granularity in bytes.
 * @used_ram: APF RAM of the chip currently allocated, in bytes, summed over
 *	all of its network devices.
 *
 * Every field describes the APF instance embedded in the chip, not the network
 * device it was queried through. A single chip may back several network
 * devices, in which case they all share one APF RAM pool. Userspace assigns
 * @chip_id to discover that grouping, see NET_APF_CMD_SET_ID.
 */
struct apf_info {
	/* Identity. */
	u32 chip_id;

	/* Static capabilities, constant while the chip is powered. */
	u32 apf_version;
	u32 total_ram;
	u32 overhead;
	u32 granularity;

	/* Dynamic state. */
	u32 used_ram;
};

/**
 * struct apf_ops - Advanced Packet Filter driver callbacks
 * @get_info: Query APF information and capabilities for the network device.
 * @set_id: Set chip-level APF instance identifier.
 * @enable: Allocate and enable per-interface APF state.
 * @get_ram_size: Query allocated RAM size for this interface. In APFv8 this
 *	only changes upon enable/disable; in APFv6.1 it always equals total_ram.
 *	Drivers should cache this value.
 * @read: Read buffer at a non-negative byte offset from APF RAM (APFv6.1 only
 *	supports offset == 0 and len == total_ram).
 * @write: Write buffer at a byte offset into APF RAM (offset -1 installs a
 *	program; APFv6.1 only supports offset == -1).
 * @disable: Disable and free per-interface APF state.
 * @fast_path: Configure hardware/driver APF fast path filtering parameters.
 *
 * Callbacks return 0 (or a non-negative value for @get_ram_size) on success,
 * or a negative errno on failure. Extended error messages may be reported via
 * @extack.
 *
 * Invoked with the netdev instance lock held (may sleep); drivers must still
 * synchronize state shared with the RX fast path.
 */
struct apf_ops {
	int (*get_info)(struct net_device *dev, struct netlink_ext_ack *extack,
			struct apf_info *info);
	int (*set_id)(struct net_device *dev, struct netlink_ext_ack *extack,
		      u32 chip_id);
	int (*enable)(struct net_device *dev, struct netlink_ext_ack *extack,
		      u32 ram_size);
	int (*get_ram_size)(struct net_device *dev,
			    struct netlink_ext_ack *extack);
	int (*read)(struct net_device *dev, struct netlink_ext_ack *extack,
		    u32 offset, u8 *buf, u32 len);
	int (*write)(struct net_device *dev, struct netlink_ext_ack *extack,
		     s32 offset, const u8 *buf, u32 len);
	int (*disable)(struct net_device *dev, struct netlink_ext_ack *extack);
	int (*fast_path)(struct net_device *dev, struct netlink_ext_ack *extack,
			 const u8 ucast_mac[ETH_ALEN], s16 vlan_tag,
			 __be32 ucast_addr4, bool enable_ipv6_fastpath);

	/* private: */
	ANDROID_KABI_RESERVE(1);
	ANDROID_KABI_RESERVE(2);
	ANDROID_KABI_RESERVE(3);
	ANDROID_KABI_RESERVE(4);
	ANDROID_KABI_RESERVE(5);
	ANDROID_KABI_RESERVE(6);
	ANDROID_KABI_RESERVE(7);
	ANDROID_KABI_RESERVE(8);
};

#endif /* _NET_APF_H */
