/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LINUX_VFIO_PLATFORM_H
#define LINUX_VFIO_PLATFORM_H

#include <linux/compiler_types.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>

struct device;

typedef int (*vfio_platform_reset_fn_t)(struct device *dev);

int __vfio_platform_register_reset(const char *compat,
				   vfio_platform_reset_fn_t fn,
				   struct module *owner);
void vfio_platform_unregister_reset(const char *compat,
				    vfio_platform_reset_fn_t fn);
void __iomem *vfio_platform_region_ioaddr(struct device *dev,
					  unsigned int index,
					  resource_size_t *size);

#define vfio_platform_register_reset(__compat, __reset)		\
	__vfio_platform_register_reset(__compat, __reset, THIS_MODULE)

#define module_vfio_reset_handler(compat, reset)		\
MODULE_ALIAS("vfio-reset:" compat);				\
static int __init reset ## _module_init(void)			\
{								\
	return vfio_platform_register_reset(compat, reset);	\
}								\
static void __exit reset ## _module_exit(void)			\
{								\
	vfio_platform_unregister_reset(compat, reset);		\
}								\
module_init(reset ## _module_init);				\
module_exit(reset ## _module_exit)

#endif /* LINUX_VFIO_PLATFORM_H */
