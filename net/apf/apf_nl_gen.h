/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/net_apf.yaml */
/* YNL-GEN kernel header */

#ifndef _LINUX_NET_APF_GEN_H
#define _LINUX_NET_APF_GEN_H

#include <net/netlink.h>
#include <net/genetlink.h>

#include <uapi/linux/net_apf.h>
#include <linux/if_ether.h>

int net_apf_nl_pre_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
			struct genl_info *info);
void
net_apf_nl_post_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
		     struct genl_info *info);

int net_apf_nl_get_info_doit(struct sk_buff *skb, struct genl_info *info);
int net_apf_nl_set_id_doit(struct sk_buff *skb, struct genl_info *info);
int net_apf_nl_enable_doit(struct sk_buff *skb, struct genl_info *info);
int net_apf_nl_get_ram_size_doit(struct sk_buff *skb, struct genl_info *info);
int net_apf_nl_read_doit(struct sk_buff *skb, struct genl_info *info);
int net_apf_nl_write_doit(struct sk_buff *skb, struct genl_info *info);
int net_apf_nl_disable_doit(struct sk_buff *skb, struct genl_info *info);
int net_apf_nl_set_fast_path_doit(struct sk_buff *skb, struct genl_info *info);

extern struct genl_family net_apf_nl_family;

#endif /* _LINUX_NET_APF_GEN_H */
