// SPDX-License-Identifier: GPL-2.0

#include <linux/of.h>
#include <linux/of_reserved_mem.h>

__rust_helper bool rust_helper_is_of_node(const struct fwnode_handle *fwnode)
{
	return is_of_node(fwnode);
}

#ifndef CONFIG_OF_RESERVED_MEM
__rust_helper int
rust_helper_of_reserved_mem_region_to_resource(const struct device_node *np,
					       unsigned int idx,
					       struct resource *res)
{
	return of_reserved_mem_region_to_resource(np, idx, res);
}
#endif
