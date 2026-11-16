/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _WRAPFD_INTERNAL_H
#define _WRAPFD_INTERNAL_H

#if IS_ENABLED(CONFIG_ANDROID_WRAPFD_KUNIT_TEST)

#include <linux/fs.h>
#include <linux/device.h>

int create_wrapfd(int fd, int prot);
int empty_wrapfd(struct file *file, struct device *dev);

#endif

#endif /* _WRAPFD_INTERNAL_H */
