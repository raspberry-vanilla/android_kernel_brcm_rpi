/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __NVHE_ITS_EMULATE_H
#define __NVHE_ITS_EMULATE_H


#include <asm/kvm_pkvm.h>


struct its_shadow_tables;

int pkvm_init_gic_its_emulation(phys_addr_t dev_addr, void *priv_state, size_t priv_num_pages,
				struct its_shadow_tables *shadow);

int pkvm_init_redist_emulation(phys_addr_t redist_base, void *host_priv_states);

void pkvm_handle_gic_emulation(struct pkvm_moveable_reg *region, u64 offset, bool write,
			       u64 *reg, u8 reg_size);
#endif /* __NVHE_ITS_EMULATE_H */
