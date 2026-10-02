// SPDX-License-Identifier: GPL-2.0
/*
 * NVIDIA Tegra Video Protection Region reserved-memory initialization
 *
 * Copyright (C) 2024-2026 NVIDIA Corporation
 */

#define pr_fmt(fmt) "tegra-vpr: " fmt

#include <linux/cma.h>
#include <linux/of_reserved_mem.h>
#include <linux/tegra-vpr.h>

struct tegra_vpr_region {
	struct cma *cma;
	const struct tegra_vpr_ops *ops;
	void *data;
	bool enabled;
};

static DEFINE_MUTEX(tegra_vpr_lock);
static struct tegra_vpr_region tegra_vpr_region;
static const struct reserved_mem_ops tegra_vpr_rmem_ops;

static struct tegra_vpr_region *
tegra_vpr_region_from_rmem(struct reserved_mem *rmem)
{
	if (!rmem || rmem->ops != &tegra_vpr_rmem_ops)
		return NULL;

	return rmem->priv;
}

static int tegra_vpr_device_init(struct reserved_mem *rmem,
				 struct device *dev)
{
	struct tegra_vpr_region *region;
	int err = -EPROBE_DEFER;

	region = tegra_vpr_region_from_rmem(rmem);
	if (!region)
		return -ENODEV;

	mutex_lock(&tegra_vpr_lock);

	if (region->enabled)
		err = region->ops->device_init(region->data, dev);

	mutex_unlock(&tegra_vpr_lock);

	return err;
}

static void tegra_vpr_device_release(struct reserved_mem *rmem,
				     struct device *dev)
{
	struct tegra_vpr_region *region;

	region = tegra_vpr_region_from_rmem(rmem);
	if (!region)
		return;

	mutex_lock(&tegra_vpr_lock);

	if (region->enabled)
		region->ops->device_release(region->data, dev);

	mutex_unlock(&tegra_vpr_lock);
}

static const struct reserved_mem_ops tegra_vpr_rmem_ops = {
	.device_init = tegra_vpr_device_init,
	.device_release = tegra_vpr_device_release,
};

static int __init tegra_vpr_rmem_init(struct reserved_mem *rmem)
{
	struct cma *cma;
	int err;

	if (!IS_ALIGNED(rmem->base, SZ_1M)) {
		pr_err("%s: base is not aligned to 1 MiB\n", rmem->name);
		return -EINVAL;
	}

	if (!IS_ALIGNED(rmem->size, SZ_1M)) {
		pr_err("%s: size is not aligned to 1 MiB\n", rmem->name);
		return -EINVAL;
	}

	if (tegra_vpr_region.cma)
		return -EBUSY;

	err = cma_init_reserved_mem(rmem->base, rmem->size, 0, rmem->name,
				    &cma, false);
	if (err < 0) {
		pr_err("%s: failed to initialize CMA: %d\n", rmem->name, err);
		return err;
	}

	tegra_vpr_region.cma = cma;
	rmem->priv = &tegra_vpr_region;
	rmem->ops = &tegra_vpr_rmem_ops;

	return 0;
}

RESERVEDMEM_OF_DECLARE(tegra_vpr, "nvidia,tegra-video-protection-region",
		       tegra_vpr_rmem_init);

/**
 * tegra_vpr_get_cma() - retrieve the CMA area backing a Tegra VPR
 * @rmem: reserved-memory region initialized for Tegra VPR
 *
 * Return: the CMA area on success, or %NULL if @rmem is not a Tegra VPR.
 */
struct cma *tegra_vpr_get_cma(struct reserved_mem *rmem)
{
	struct tegra_vpr_region *region;

	region = tegra_vpr_region_from_rmem(rmem);

	return region ? region->cma : NULL;
}
EXPORT_SYMBOL_GPL(tegra_vpr_get_cma);

/**
 * tegra_vpr_register() - register a provider for a Tegra VPR
 * @rmem: reserved-memory region initialized for Tegra VPR
 * @ops: provider callbacks
 * @data: private provider data passed to the callbacks
 *
 * The provider must remain registered for the lifetime of the system.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int tegra_vpr_register(struct reserved_mem *rmem,
		       const struct tegra_vpr_ops *ops, void *data)
{
	struct tegra_vpr_region *region;
	int err = 0;

	if (!ops || !ops->device_init || !ops->device_release)
		return -EINVAL;

	region = tegra_vpr_region_from_rmem(rmem);
	if (!region)
		return -ENODEV;

	mutex_lock(&tegra_vpr_lock);

	if (region->ops) {
		err = -EBUSY;
		goto unlock;
	}

	region->data = data;
	region->ops = ops;
	region->enabled = false;

unlock:
	mutex_unlock(&tegra_vpr_lock);

	return err;
}
EXPORT_SYMBOL_GPL(tegra_vpr_register);

/**
 * tegra_vpr_unregister() - cancel a provider registration
 * @rmem: reserved-memory region initialized for Tegra VPR
 * @data: private provider data used during registration
 *
 * A provider may only be unregistered before it has been enabled.
 */
void tegra_vpr_unregister(struct reserved_mem *rmem, void *data)
{
	struct tegra_vpr_region *region;

	region = tegra_vpr_region_from_rmem(rmem);
	if (!region)
		return;

	mutex_lock(&tegra_vpr_lock);

	if (WARN_ON(region->enabled || region->data != data))
		goto unlock;

	region->ops = NULL;
	region->data = NULL;

unlock:
	mutex_unlock(&tegra_vpr_lock);
}
EXPORT_SYMBOL_GPL(tegra_vpr_unregister);

/**
 * tegra_vpr_enable() - enable a registered Tegra VPR provider
 * @rmem: reserved-memory region initialized for Tegra VPR
 * @data: private provider data used during registration
 *
 * Enabling cannot fail. The provider must remain registered afterward.
 */
void tegra_vpr_enable(struct reserved_mem *rmem, void *data)
{
	struct tegra_vpr_region *region;

	region = tegra_vpr_region_from_rmem(rmem);
	if (!region)
		return;

	mutex_lock(&tegra_vpr_lock);

	if (!WARN_ON(!region->ops || region->data != data))
		region->enabled = true;

	mutex_unlock(&tegra_vpr_lock);
}
EXPORT_SYMBOL_GPL(tegra_vpr_enable);
