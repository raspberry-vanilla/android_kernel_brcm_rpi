// SPDX-License-Identifier: GPL-2.0-only
/*
 * Core implementation of the 'net-apf' genetlink family
 *
 * Copyright 2026 Google LLC
 */

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <net/genetlink.h>
#include <net/netlink.h>
#include <net/apf.h>

#include "apf_nl_gen.h"

/* Acquire the netdev instance lock to serialise commands per interface;
 * released in net_apf_nl_post_doit().
 */
int net_apf_nl_pre_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
			struct genl_info *info)
{
	struct net_device *dev;

	if (GENL_REQ_ATTR_CHECK(info, NET_APF_A_IFINDEX))
		return -EINVAL;

	dev = netdev_get_by_index_lock(genl_info_net(info),
				       nla_get_u32(info->attrs[NET_APF_A_IFINDEX]));
	if (!dev) {
		NL_SET_BAD_ATTR(info->extack, info->attrs[NET_APF_A_IFINDEX]);
		return -ENODEV;
	}

	if (!dev->netdev_ops->apf_ops) {
		NL_SET_ERR_MSG_ATTR(info->extack,
				    info->attrs[NET_APF_A_IFINDEX],
				    "APF not supported on device");
		netdev_unlock(dev);
		return -EOPNOTSUPP;
	}

	info->user_ptr[0] = dev;
	return 0;
}

void net_apf_nl_post_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
			  struct genl_info *info)
{
	netdev_unlock(info->user_ptr[0]);
}

static struct sk_buff *apf_genlmsg_new(struct genl_info *info, size_t payload,
				       void **hdr)
{
	struct sk_buff *rsp = genlmsg_new(GENLMSG_DEFAULT_SIZE + payload,
					  GFP_KERNEL);

	if (!rsp)
		return NULL;

	*hdr = genlmsg_iput(rsp, info);
	if (!*hdr) {
		nlmsg_free(rsp);
		return NULL;
	}

	return rsp;
}

int net_apf_nl_get_info_doit(struct sk_buff *req, struct genl_info *info)
{
	struct net_device *dev = info->user_ptr[0];
	struct apf_info apf_info = {};
	const struct apf_ops *ops;
	struct sk_buff *rsp;
	void *hdr;
	int ret;

	ops = dev->netdev_ops->apf_ops;
	if (!ops->get_info)
		return -EOPNOTSUPP;

	ret = ops->get_info(dev, info->extack, &apf_info);
	if (ret)
		return ret;

	rsp = apf_genlmsg_new(info, 0, &hdr);
	if (!rsp)
		return -ENOMEM;

	if (nla_put_u32(rsp, NET_APF_A_INFO_VERSION, apf_info.apf_version) ||
	    nla_put_u32(rsp, NET_APF_A_INFO_CHIP_ID, apf_info.chip_id) ||
	    nla_put_u32(rsp, NET_APF_A_INFO_TOTAL_RAM, apf_info.total_ram) ||
	    nla_put_u32(rsp, NET_APF_A_INFO_USED_RAM, apf_info.used_ram) ||
	    nla_put_u32(rsp, NET_APF_A_INFO_OVERHEAD, apf_info.overhead) ||
	    nla_put_u32(rsp, NET_APF_A_INFO_GRANULARITY, apf_info.granularity)) {
		nlmsg_free(rsp);
		return -EMSGSIZE;
	}

	genlmsg_end(rsp, hdr);
	return genlmsg_reply(rsp, info);
}

int net_apf_nl_set_id_doit(struct sk_buff *req, struct genl_info *info)
{
	struct net_device *dev = info->user_ptr[0];
	const struct apf_ops *ops;

	if (GENL_REQ_ATTR_CHECK(info, NET_APF_A_INFO_CHIP_ID))
		return -EINVAL;

	ops = dev->netdev_ops->apf_ops;
	if (!ops->set_id)
		return -EOPNOTSUPP;

	return ops->set_id(dev, info->extack,
			   nla_get_u32(info->attrs[NET_APF_A_INFO_CHIP_ID]));
}

int net_apf_nl_enable_doit(struct sk_buff *req, struct genl_info *info)
{
	struct net_device *dev = info->user_ptr[0];
	const struct apf_ops *ops;

	if (GENL_REQ_ATTR_CHECK(info, NET_APF_A_RAM_SIZE))
		return -EINVAL;

	ops = dev->netdev_ops->apf_ops;
	if (!ops->enable)
		return -EOPNOTSUPP;

	return ops->enable(dev, info->extack,
			   nla_get_u32(info->attrs[NET_APF_A_RAM_SIZE]));
}

int net_apf_nl_get_ram_size_doit(struct sk_buff *req, struct genl_info *info)
{
	struct net_device *dev = info->user_ptr[0];
	const struct apf_ops *ops;
	struct sk_buff *rsp;
	void *hdr;
	int ret;

	ops = dev->netdev_ops->apf_ops;
	if (!ops->get_ram_size)
		return -EOPNOTSUPP;

	ret = ops->get_ram_size(dev, info->extack);
	if (ret < 0)
		return ret;

	rsp = apf_genlmsg_new(info, 0, &hdr);
	if (!rsp)
		return -ENOMEM;

	if (nla_put_u32(rsp, NET_APF_A_RAM_SIZE, ret)) {
		nlmsg_free(rsp);
		return -EMSGSIZE;
	}

	genlmsg_end(rsp, hdr);
	return genlmsg_reply(rsp, info);
}

int net_apf_nl_read_doit(struct sk_buff *req, struct genl_info *info)
{
	struct net_device *dev = info->user_ptr[0];
	const struct apf_ops *ops;
	struct sk_buff *rsp;
	u32 offset = 0;
	void *hdr;
	u32 len;
	u8 *buf;
	int ret;

	ops = dev->netdev_ops->apf_ops;
	if (!ops->read)
		return -EOPNOTSUPP;

	/* Without an offset the read starts at 0; without a length the whole
	 * allocated RAM is read.
	 */
	if (info->attrs[NET_APF_A_OFFSET])
		offset = nla_get_u32(info->attrs[NET_APF_A_OFFSET]);

	if (info->attrs[NET_APF_A_DATA_LEN]) {
		len = nla_get_u32(info->attrs[NET_APF_A_DATA_LEN]);
	} else {
		if (offset) {
			NL_SET_ERR_MSG_ATTR(info->extack,
					    info->attrs[NET_APF_A_OFFSET],
					    "Reading the whole RAM requires offset 0");
			return -EINVAL;
		}

		if (!ops->get_ram_size)
			return -EOPNOTSUPP;

		ret = ops->get_ram_size(dev, info->extack);
		if (ret < 0)
			return ret;
		if (!ret) {
			NL_SET_ERR_MSG(info->extack,
				       "No APF RAM allocated on device");
			return -ENODATA;
		}

		len = ret;
	}

	buf = kmalloc(len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = ops->read(dev, info->extack, offset, buf, len);
	if (ret)
		goto out_free_buf;

	rsp = apf_genlmsg_new(info, nla_total_size(len), &hdr);
	if (!rsp) {
		ret = -ENOMEM;
		goto out_free_buf;
	}

	if (nla_put(rsp, NET_APF_A_DATA, len, buf)) {
		nlmsg_free(rsp);
		ret = -EMSGSIZE;
		goto out_free_buf;
	}

	genlmsg_end(rsp, hdr);
	ret = genlmsg_reply(rsp, info);

out_free_buf:
	kfree(buf);
	return ret;
}

int net_apf_nl_write_doit(struct sk_buff *req, struct genl_info *info)
{
	struct net_device *dev = info->user_ptr[0];
	const struct apf_ops *ops;
	s32 offset = -1;

	if (GENL_REQ_ATTR_CHECK(info, NET_APF_A_DATA))
		return -EINVAL;

	ops = dev->netdev_ops->apf_ops;
	if (!ops->write)
		return -EOPNOTSUPP;

	/* Without an offset the payload is installed as a new program, which
	 * the driver op selects with a negative offset.
	 */
	if (info->attrs[NET_APF_A_OFFSET])
		offset = nla_get_u32(info->attrs[NET_APF_A_OFFSET]);

	return ops->write(dev, info->extack, offset,
			  nla_data(info->attrs[NET_APF_A_DATA]),
			  nla_len(info->attrs[NET_APF_A_DATA]));
}

int net_apf_nl_disable_doit(struct sk_buff *req, struct genl_info *info)
{
	struct net_device *dev = info->user_ptr[0];
	const struct apf_ops *ops;

	ops = dev->netdev_ops->apf_ops;
	if (!ops->disable)
		return -EOPNOTSUPP;

	return ops->disable(dev, info->extack);
}

int net_apf_nl_set_fast_path_doit(struct sk_buff *req, struct genl_info *info)
{
	struct net_device *dev = info->user_ptr[0];
	const struct apf_ops *ops;
	__be32 ucast_addr4 = 0;
	s16 vlan_tag = -1;

	if (GENL_REQ_ATTR_CHECK(info, NET_APF_A_FP_UCAST_MAC))
		return -EINVAL;

	ops = dev->netdev_ops->apf_ops;
	if (!ops->fast_path)
		return -EOPNOTSUPP;

	/* Without a tag the fast path does no VLAN filtering, which the driver
	 * op selects with a negative tag.
	 */
	if (info->attrs[NET_APF_A_FP_VLAN_TAG])
		vlan_tag = nla_get_u16(info->attrs[NET_APF_A_FP_VLAN_TAG]);

	if (info->attrs[NET_APF_A_FP_UCAST_ADDR4])
		ucast_addr4 = nla_get_be32(info->attrs[NET_APF_A_FP_UCAST_ADDR4]);

	return ops->fast_path(dev, info->extack,
			      nla_data(info->attrs[NET_APF_A_FP_UCAST_MAC]),
			      vlan_tag, ucast_addr4,
			      nla_get_flag(info->attrs[NET_APF_A_FP_ENABLE_IPV6]));
}

static int __init apf_init(void)
{
	return genl_register_family(&net_apf_nl_family);
}

subsys_initcall(apf_init);
