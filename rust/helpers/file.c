// SPDX-License-Identifier: GPL-2.0

#include <linux/file.h>

__rust_helper bool rust_helper_get_close_on_exec(unsigned int fd)
{
	return get_close_on_exec(fd);
}
