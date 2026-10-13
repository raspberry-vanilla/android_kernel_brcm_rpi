// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2024 Google LLC.
 */

#include <linux/fs.h>

__rust_helper struct file *rust_helper_get_file(struct file *f)
{
	return get_file(f);
}

loff_t rust_helper_i_size_read(const struct inode *inode)
{
	return i_size_read(inode);
}

__rust_helper struct inode *rust_helper_file_inode(const struct file *f)
{
	return file_inode(f);
}

__rust_helper void rust_helper_i_size_write(struct inode *inode, loff_t i_size)
{
	i_size_write(inode, i_size);
}

__rust_helper void rust_helper_i_mmap_lock_read(struct address_space *mapping)
{
	i_mmap_lock_read(mapping);
}

__rust_helper void rust_helper_i_mmap_unlock_read(struct address_space *mapping)
{
	i_mmap_unlock_read(mapping);
}

__rust_helper unsigned long rust_helper_file_count(struct file *f)
{
	return file_count(f);
}

__rust_helper void rust_helper_init_sync_kiocb(struct kiocb *kiocb, struct file *filp)
{
	init_sync_kiocb(kiocb, filp);
}
