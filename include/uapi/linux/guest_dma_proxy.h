/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_GUEST_DMA_PROXY_H
#define _UAPI_LINUX_GUEST_DMA_PROXY_H

#include <linux/types.h>
#include <linux/ioctl.h>

struct guest_dma_proxy_import_args {
	__u64 paddr;       /* Guest Physical Address (GPA) */
	__u64 size;        /* Size of the memory region */
	__u8  token[16];   /* 128-bit security token / UUID */
	__u32 flags;       /* e.g., O_RDONLY */
	__u32 fd;          /* Returned dma-buf FD */
	__u64 reserved[2]; /* Future expansion, must be 0 */
};

#define GUEST_DMA_PROXY_IOC_MAGIC 'G'
#define GUEST_DMA_PROXY_IOC_IMPORT \
	_IOWR(GUEST_DMA_PROXY_IOC_MAGIC, 1, struct guest_dma_proxy_import_args)

#endif /* _UAPI_LINUX_GUEST_DMA_PROXY_H */
