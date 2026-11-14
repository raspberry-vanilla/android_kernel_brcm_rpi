// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 - Google Inc
 * Author: Mostafa Saleh <smostafa@google.com>
 * Template module for pKVM IOMMU drivers
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/kvm_pkvm_module.h>

#include "pkvm/pkvm-iommu-temp.h"

#define ksym_ref_addr_nvhe(x, token) \
	((typeof(kvm_nvhe_sym(x)) *)(pkvm_el2_mod_va(&kvm_nvhe_sym(x), token)))

static pkvm_handle_t kvm_iommu_temp_id_by_of(struct device_node *np)
{
	return 0;
}

static void kvm_iommu_temp_remove_drv(void)
{
}

static int kvm_iommu_temp_init_drv(void)
{
	struct kvm_hyp_memcache atomic_mc = {};
	unsigned long token;
	int ret;

	ret = pkvm_load_el2_module(kvm_nvhe_sym(pkvm_iommu_temp_hyp_init), &token);
	if (ret) {
		pr_err("Failed to register pKVM IOMMU template: %d\n", ret);
		return ret;
	}

	return kvm_iommu_init_hyp(ksym_ref_addr_nvhe(iommu_temp_ops, token), &atomic_mc);
}

static struct kvm_iommu_driver kvm_iommu_temp_ops = {
	.init_driver = kvm_iommu_temp_init_drv,
	.remove_driver = kvm_iommu_temp_remove_drv,
	.get_iommu_id_by_of = kvm_iommu_temp_id_by_of,
};

static int __init pkvm_iommu_temp_init(void)
{
	if (!is_protected_kvm_enabled()) {
		pr_warn("pKVM not enabled, iommu-temp module is not registering\n");
		return 0;
	}

	return kvm_iommu_register_driver(&kvm_iommu_temp_ops);
}

module_init(pkvm_iommu_temp_init);

MODULE_AUTHOR("Mostafa Saleh <smostafa@google.com>");
MODULE_DESCRIPTION("pKVM IOMMU template");
MODULE_LICENSE("GPL v2");
