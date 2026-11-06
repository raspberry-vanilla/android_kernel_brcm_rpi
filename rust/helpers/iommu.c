// SPDX-License-Identifier: GPL-2.0

#include <linux/iommu.h>

__rust_helper ssize_t rust_helper_iommu_map_sgtable(struct iommu_domain *domain,
						    unsigned long iova,
						    struct sg_table *sgt,
						    int prot)
{
	return iommu_map_sgtable(domain, iova, sgt, prot);
}

#ifndef CONFIG_IOMMU_API
__rust_helper struct iommu_domain *
rust_helper_iommu_get_domain_for_dev(struct device *dev)
{
	return iommu_get_domain_for_dev(dev);
}

__rust_helper size_t rust_helper_iommu_unmap(struct iommu_domain *domain,
					     unsigned long iova, size_t size)
{
	return iommu_unmap(domain, iova, size);
}
#endif
