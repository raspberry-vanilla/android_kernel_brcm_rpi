// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/net_apf.yaml */
/* YNL-GEN kernel source */

#include <net/netlink.h>
#include <net/genetlink.h>

#include "apf_nl_gen.h"

#include <uapi/linux/net_apf.h>
#include <linux/if_ether.h>

/* NET_APF_CMD_GET_INFO - do */
static const struct nla_policy net_apf_get_info_nl_policy[NET_APF_A_IFINDEX + 1] = {
	[NET_APF_A_IFINDEX] = NLA_POLICY_MIN(NLA_U32, 1),
};

/* NET_APF_CMD_SET_ID - do */
static const struct nla_policy net_apf_set_id_nl_policy[NET_APF_A_INFO_CHIP_ID + 1] = {
	[NET_APF_A_IFINDEX] = NLA_POLICY_MIN(NLA_U32, 1),
	[NET_APF_A_INFO_CHIP_ID] = { .type = NLA_U32, },
};

/* NET_APF_CMD_ENABLE - do */
static const struct nla_policy net_apf_enable_nl_policy[NET_APF_A_RAM_SIZE + 1] = {
	[NET_APF_A_IFINDEX] = NLA_POLICY_MIN(NLA_U32, 1),
	[NET_APF_A_RAM_SIZE] = NLA_POLICY_RANGE(NLA_U32, 1, S16_MAX),
};

/* NET_APF_CMD_GET_RAM_SIZE - do */
static const struct nla_policy net_apf_get_ram_size_nl_policy[NET_APF_A_IFINDEX + 1] = {
	[NET_APF_A_IFINDEX] = NLA_POLICY_MIN(NLA_U32, 1),
};

/* NET_APF_CMD_READ - do */
static const struct nla_policy net_apf_read_nl_policy[NET_APF_A_DATA_LEN + 1] = {
	[NET_APF_A_IFINDEX] = NLA_POLICY_MIN(NLA_U32, 1),
	[NET_APF_A_OFFSET] = NLA_POLICY_MAX(NLA_U32, S16_MAX),
	[NET_APF_A_DATA_LEN] = NLA_POLICY_RANGE(NLA_U32, 1, S16_MAX),
};

/* NET_APF_CMD_WRITE - do */
static const struct nla_policy net_apf_write_nl_policy[NET_APF_A_DATA + 1] = {
	[NET_APF_A_IFINDEX] = NLA_POLICY_MIN(NLA_U32, 1),
	[NET_APF_A_OFFSET] = NLA_POLICY_MAX(NLA_U32, S16_MAX),
	[NET_APF_A_DATA] = NLA_POLICY_MIN_LEN(1),
};

/* NET_APF_CMD_DISABLE - do */
static const struct nla_policy net_apf_disable_nl_policy[NET_APF_A_IFINDEX + 1] = {
	[NET_APF_A_IFINDEX] = NLA_POLICY_MIN(NLA_U32, 1),
};

/* NET_APF_CMD_SET_FAST_PATH - do */
static const struct nla_policy net_apf_set_fast_path_nl_policy[NET_APF_A_FP_ENABLE_IPV6 + 1] = {
	[NET_APF_A_IFINDEX] = NLA_POLICY_MIN(NLA_U32, 1),
	[NET_APF_A_FP_UCAST_MAC] = NLA_POLICY_EXACT_LEN(ETH_ALEN),
	[NET_APF_A_FP_VLAN_TAG] = NLA_POLICY_MAX(NLA_U16, 4095),
	[NET_APF_A_FP_UCAST_ADDR4] = { .type = NLA_BE32, },
	[NET_APF_A_FP_ENABLE_IPV6] = { .type = NLA_FLAG, },
};

/* Ops table for net_apf */
static const struct genl_split_ops net_apf_nl_ops[] = {
	{
		.cmd		= NET_APF_CMD_GET_INFO,
		.pre_doit	= net_apf_nl_pre_doit,
		.doit		= net_apf_nl_get_info_doit,
		.post_doit	= net_apf_nl_post_doit,
		.policy		= net_apf_get_info_nl_policy,
		.maxattr	= NET_APF_A_IFINDEX,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd		= NET_APF_CMD_SET_ID,
		.pre_doit	= net_apf_nl_pre_doit,
		.doit		= net_apf_nl_set_id_doit,
		.post_doit	= net_apf_nl_post_doit,
		.policy		= net_apf_set_id_nl_policy,
		.maxattr	= NET_APF_A_INFO_CHIP_ID,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd		= NET_APF_CMD_ENABLE,
		.pre_doit	= net_apf_nl_pre_doit,
		.doit		= net_apf_nl_enable_doit,
		.post_doit	= net_apf_nl_post_doit,
		.policy		= net_apf_enable_nl_policy,
		.maxattr	= NET_APF_A_RAM_SIZE,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd		= NET_APF_CMD_GET_RAM_SIZE,
		.pre_doit	= net_apf_nl_pre_doit,
		.doit		= net_apf_nl_get_ram_size_doit,
		.post_doit	= net_apf_nl_post_doit,
		.policy		= net_apf_get_ram_size_nl_policy,
		.maxattr	= NET_APF_A_IFINDEX,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd		= NET_APF_CMD_READ,
		.pre_doit	= net_apf_nl_pre_doit,
		.doit		= net_apf_nl_read_doit,
		.post_doit	= net_apf_nl_post_doit,
		.policy		= net_apf_read_nl_policy,
		.maxattr	= NET_APF_A_DATA_LEN,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd		= NET_APF_CMD_WRITE,
		.pre_doit	= net_apf_nl_pre_doit,
		.doit		= net_apf_nl_write_doit,
		.post_doit	= net_apf_nl_post_doit,
		.policy		= net_apf_write_nl_policy,
		.maxattr	= NET_APF_A_DATA,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd		= NET_APF_CMD_DISABLE,
		.pre_doit	= net_apf_nl_pre_doit,
		.doit		= net_apf_nl_disable_doit,
		.post_doit	= net_apf_nl_post_doit,
		.policy		= net_apf_disable_nl_policy,
		.maxattr	= NET_APF_A_IFINDEX,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd		= NET_APF_CMD_SET_FAST_PATH,
		.pre_doit	= net_apf_nl_pre_doit,
		.doit		= net_apf_nl_set_fast_path_doit,
		.post_doit	= net_apf_nl_post_doit,
		.policy		= net_apf_set_fast_path_nl_policy,
		.maxattr	= NET_APF_A_FP_ENABLE_IPV6,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
};

struct genl_family net_apf_nl_family __ro_after_init = {
	.name		= NET_APF_FAMILY_NAME,
	.version	= NET_APF_FAMILY_VERSION,
	.netnsok	= true,
	.parallel_ops	= true,
	.module		= THIS_MODULE,
	.split_ops	= net_apf_nl_ops,
	.n_split_ops	= ARRAY_SIZE(net_apf_nl_ops),
};
