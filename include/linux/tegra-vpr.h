/* SPDX-License-Identifier: GPL-2.0 */
/*
 * NVIDIA Tegra Video Protection Region reserved-memory interface
 *
 * Copyright (C) 2024-2026 NVIDIA Corporation
 */

#ifndef _LINUX_TEGRA_VPR_H
#define _LINUX_TEGRA_VPR_H

struct cma;
struct device;
struct reserved_mem;

/**
 * struct tegra_vpr_ops - callbacks supplied by a Tegra VPR provider
 * @device_init: attach a device that references the VPR
 * @device_release: detach a device that references the VPR
 *
 * Once enabled, the provider must remain registered for the lifetime of the
 * system.
 */
struct tegra_vpr_ops {
	int (*device_init)(void *data, struct device *dev);
	void (*device_release)(void *data, struct device *dev);
};

struct cma *tegra_vpr_get_cma(struct reserved_mem *rmem);
int tegra_vpr_register(struct reserved_mem *rmem,
		       const struct tegra_vpr_ops *ops, void *data);
void tegra_vpr_unregister(struct reserved_mem *rmem, void *data);
void tegra_vpr_enable(struct reserved_mem *rmem, void *data);

#endif
