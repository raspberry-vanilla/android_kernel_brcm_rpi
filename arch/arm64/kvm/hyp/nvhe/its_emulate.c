// SPDX-License-Identifier: GPL-2.0-only

#include <asm/kvm_pkvm.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <nvhe/its_emulate.h>
#include <nvhe/mem_protect.h>

struct emu_handler {
	u64 offset;
	u8 access_size;
	u8 num_registers;
	void (*write)(struct pkvm_moveable_reg *region, u64 offset, u64 value);
	void (*read)(struct pkvm_moveable_reg *region, u64 offset, u64 *read);
};

#define EMU_HANDLER(off, sz, num, write_cb, read_cb)	\
{							\
	.offset = (off),				\
	.access_size = (sz),				\
	.num_registers = (num),				\
	.write = (write_cb),				\
	.read = (read_cb),				\
}

#define EMU_REG(off, sz, write_cb, read_cb)	\
	EMU_HANDLER(off, sz, 1, write_cb, read_cb)

#define EMU_REG_RAZ_WI(off, sz) EMU_REG(off, sz, write_ignore, read_as_zero)

static void write_ignore(struct pkvm_moveable_reg *region, u64 offset,
			 u64 value)
{
	/* Do nothing */
}

static void read_as_zero(struct pkvm_moveable_reg *region, u64 offset,
			 u64 *read)
{
	*read = 0;
}

static void handle_emulation(struct pkvm_moveable_reg *region, u64 offset,
			     bool write, u64 *reg, u8 reg_size,
			     struct emu_handler *handlers, hyp_spinlock_t *lock)
{
	struct emu_handler *reg_handler;
	u64 end;

	for (reg_handler = handlers; reg_handler->access_size; reg_handler++) {
		end = reg_handler->offset +
		      reg_handler->access_size * reg_handler->num_registers;

		if (reg_handler->offset > offset || end <= offset)
			continue;

		if (reg_handler->access_size < reg_size)
			return;

		if (write && reg_handler->write) {
			if (lock)
				hyp_spin_lock(lock);
			reg_handler->write(region, offset, *reg);
			if (lock)
				hyp_spin_unlock(lock);
			return;
		}

		if (!write && reg_handler->read) {
			if (lock)
				hyp_spin_lock(lock);
			reg_handler->read(region, offset, reg);
			if (lock)
				hyp_spin_unlock(lock);
			return;
		}

		return;
	}

	pkvm_handle_forward_req(region, offset, write, reg, reg_size);
}

static int donate_and_clear_host_page(void *addr, size_t num_pages)
{
	int ret;

	if (!PAGE_ALIGNED(addr))
		return -EINVAL;

	ret = __pkvm_host_donate_hyp(hyp_virt_to_pfn(addr), num_pages);
	if (ret)
		return ret;

	memset(addr, 0, num_pages << PAGE_SHIFT);
	return 0;
}

struct dte_entry {
	u32 device_id;
	u64 itt_pfn;
};

struct its_priv_state {
	void *base;
	void *cmd_hyp_base;
	void *cmd_host_base;
	u64 cmd_offset;
	struct its_shadow_tables *shadow;
	hyp_spinlock_t its_lock;
	bool needs_flush;
	u16 empty_idx;
	u16 num_tracked_pfns;
	struct dte_entry tracked_pfns[];
};

DEFINE_HYP_SPINLOCK(its_setup_lock);
DECLARE_STATIC_KEY_FALSE(kvm_its_hardening);

#define GITS_CWRITER_RETRY	BIT_ULL(0)
#define GITS_CWRITER_OFFSET	GENMASK_ULL(19, 5)

#define GITS_CREADR_STALLED	BIT_ULL(0)
#define GITS_CREADR_OFFSET	GENMASK_ULL(19, 5)

static int track_pfn_add(struct its_priv_state *its, u32 device_id, u64 pfn)
{
	int ret, i;
	void *virt = hyp_phys_to_virt(hyp_pfn_to_phys(pfn));
	bool pfn_shared = false;

	/*
	 * If we already track this pfn pin it again to increase page refcount.
	 * We can have a different deviceId that wants to map to the same ITT table.
	 */
	for (i = 0; i < its->num_tracked_pfns; i++) {
		if (its->tracked_pfns[i].itt_pfn != pfn)
			continue;

		if (its->tracked_pfns[i].device_id != device_id) {
			pfn_shared = true;
			break;
		} else {
			return hyp_pin_shared_mem(virt, virt + PAGE_SIZE);
		}
	}

	if (its->empty_idx >= its->num_tracked_pfns)
		return -ENOSPC;

	if (!pfn_shared) {
		ret = __pkvm_host_share_hyp(pfn);
		if (ret)
			return ret;
	}

	/*
	 * Pin the memory to increase page refcount and make
	 * sure host cannot reclaim it.
	 */
	ret = hyp_pin_shared_mem(virt, virt + PAGE_SIZE);
	if (ret) {
		__pkvm_host_unshare_hyp(pfn);
		return ret;
	}

	its->tracked_pfns[its->empty_idx].itt_pfn = pfn;
	its->tracked_pfns[its->empty_idx].device_id = device_id;

	for (i = 0; i < its->num_tracked_pfns; i++) {
		if (!its->tracked_pfns[i].itt_pfn && !its->tracked_pfns[i].device_id)
			break;
	}

	its->empty_idx = i;
	return 0;
}

static int track_pfn_remove(struct its_priv_state *its, u32 device_id, u64 pfn)
{
	int i, ret;
	void *virt = hyp_phys_to_virt(hyp_pfn_to_phys(pfn));

	for (i = 0; i < its->num_tracked_pfns; i++) {
		if (its->tracked_pfns[i].itt_pfn != pfn ||
		    its->tracked_pfns[i].device_id != device_id)
			continue;

		/*
		 * First try to unshare to see if we have an elevated refcount.
		 * If it returns -EBUSY we have an elevated refcount and we need
		 * to decrement it.
		 * Then see if this was the last reference of the
		 * page if unshare succeeds.
		 */
		ret = __pkvm_host_unshare_hyp(pfn);
		if (ret == -EBUSY) {
			hyp_unpin_shared_mem(virt, virt + PAGE_SIZE);
			ret = __pkvm_host_unshare_hyp(pfn);
			if (ret == -EBUSY)
				return 0;

			WARN_ON(ret != 0);
		}

		memset(&its->tracked_pfns[i], 0, sizeof(struct dte_entry));
		its->empty_idx = i;
		return 0;
	}

	return -EINVAL;
}

static int get_num_itt_pages(struct its_priv_state *its, u8 num_bits)
{
	u64 size, gits_typer = readq_relaxed(its->base + GITS_TYPER);
	u64 nr_ites;

	if (num_bits > FIELD_GET(GITS_TYPER_IDBITS, gits_typer))
		return -EINVAL;

	nr_ites = BIT_ULL(num_bits + 1);
	size = nr_ites * (FIELD_GET(GITS_TYPER_ITT_ENTRY_SIZE, gits_typer) + 1);
	size = max(size, ITS_ITT_ALIGN) + ITS_ITT_ALIGN - 1;

	return PAGE_ALIGN(size) >> PAGE_SHIFT;
}

static int track_pfn(struct its_priv_state *its, u32 device_id, u64 start_pfn, int num_pages,
		     bool remove)
{
	int i, ret;

	for (i = 0; i < num_pages; i++) {
		if (remove)
			ret = track_pfn_remove(its, device_id, start_pfn + i);
		else
			ret = track_pfn_add(its, device_id, start_pfn + i);

		if (ret)
			goto err_track;
	}

	return 0;
err_track:
	for (i = i - 1; i >= 0; i--) {
		if (remove)
			track_pfn_add(its, device_id, start_pfn + i);
		else
			track_pfn_remove(its, device_id, start_pfn + i);
	}

	return ret;
}

static struct its_baser *get_table(struct its_priv_state *its, u64 type)
{
	int i;
	struct its_shadow_tables *shadow = its->shadow;

	for (i = 0; i < GITS_BASER_NR_REGS; i++) {
		if (GITS_BASER_TYPE(shadow->tables[i].val) == type)
			return &shadow->tables[i];
	}

	return NULL;
}

static int check_table_update(struct its_priv_state *its, u32 id, u64 type,
			      bool rollback)
{
	u32 lvl1_idx;
	u64 esz, *host_table, *hyp_table, new_entry, update, lvl1_sz;
	struct its_baser *table = get_table(its, type);
	int ret;
	phys_addr_t new_lvl2_table, lvl2_table;

	if (!table)
		return -EINVAL;

	if (!(table->val & GITS_BASER_INDIRECT))
		return 0;

	esz = GITS_BASER_ENTRY_SIZE(table->val);
	lvl1_sz = (1 << table->order) << PAGE_SHIFT;
	lvl1_idx = id / (table->psz / esz);
	if (lvl1_idx >= lvl1_sz / sizeof(u64))
		return -ENOSPC;

	host_table = kern_hyp_va(table->shadow);
	hyp_table = kern_hyp_va(table->base);

	new_entry = host_table[lvl1_idx];

	update = new_entry ^ hyp_table[lvl1_idx];
	if (!(update & GITS_BASER_VALID))
		return 0;

	/* If roll backing, flip to restore previous state */
	if (rollback)
		new_entry = new_entry ^ GITS_BASER_VALID;

	new_lvl2_table = hyp_phys_to_pfn(new_entry & PHYS_MASK);
	lvl2_table = hyp_phys_to_pfn(hyp_table[lvl1_idx] & PHYS_MASK);
	if (new_entry & GITS_BASER_VALID)
		ret = __pkvm_host_donate_hyp(new_lvl2_table, table->psz >> PAGE_SHIFT);
	else
		ret = __pkvm_hyp_donate_host(lvl2_table, table->psz >> PAGE_SHIFT);
	if (ret)
		return ret;

	hyp_table[lvl1_idx] = new_entry;
	return 0;
}

static int process_its_mapd(struct its_priv_state *its,
			    struct its_cmd_block *cmd, bool rollback)
{
	phys_addr_t itt_addr = cmd->raw_cmd[2] & GENMASK(51, 8);
	u8 size = cmd->raw_cmd[1] & GENMASK(4, 0);
	bool remove = !(cmd->raw_cmd[2] & BIT(63));
	u32 device_id = cmd->raw_cmd[0] >> 32;
	int num_pages, ret;
	u64 base_pfn;

	if (rollback)
		remove = !remove;

	if (!PAGE_ALIGNED(itt_addr))
		return -EINVAL;

	base_pfn = hyp_phys_to_pfn(itt_addr);
	num_pages = get_num_itt_pages(its, size);
	if (num_pages < 0)
		return num_pages;

	ret = check_table_update(its, device_id, GITS_BASER_TYPE_DEVICE,
				 rollback);
	if (ret)
		return ret;

	return track_pfn(its, device_id, base_pfn, num_pages, remove);
}

static int process_its_mapc(struct its_priv_state *its,
			    struct its_cmd_block *cmd, bool rollback)
{
	u32 icid = cmd->raw_cmd[2] & GENMASK(15, 0);

	return check_table_update(its, icid, GITS_BASER_TYPE_COLLECTION,
				  rollback);
}

static int submit_single_cmd(struct its_priv_state *its, bool retry)
{
	size_t cmdq_sz = its->shadow->cmdq_len;
	u64 timeout = 1000;
	u64 offset, cwriter, creadr;

	offset = (its->cmd_offset + sizeof(struct its_cmd_block)) % cmdq_sz;

	cwriter = offset & GITS_CWRITER_OFFSET;
	cwriter |= FIELD_PREP(GITS_CWRITER_RETRY, retry);
	writeq_relaxed(cwriter, its->base + GITS_CWRITER);

	while (its->cmd_offset != offset) {
		creadr = readq_relaxed(its->base + GITS_CREADR);

		/* Command failed. */
		if (FIELD_GET(GITS_CREADR_STALLED, creadr))
			return -EIO;

		its->cmd_offset = creadr & GITS_CREADR_OFFSET;
		if (its->cmd_offset == offset)
			return 0;

		/*
		 * We can't spin here forever and we can't roll back
		 * the cmd queue pointer. Let's revert the cmd effects in the
		 * emulation layer and then go back to the driver to let it
		 * decide what to do next.
		 */
		if (!timeout--)
			return -EBUSY;

		pkvm_udelay(100);
	}

	return 0;
}

static int process_cmd(struct its_priv_state *its, struct its_cmd_block *cmd,
		       bool rollback)
{
	u8 req_type = cmd->raw_cmd[0] & GENMASK_ULL(7, 0);
	int ret;

	/*
	 * Block all VLPI related commands until proper sanitization
	 * is shipped.
	 */
	if (req_type & 0x20)
		return -EFAULT;

	switch (req_type) {
	case GITS_CMD_MAPD:
		ret = process_its_mapd(its, cmd, rollback);
		break;

	case GITS_CMD_MAPC:
		ret = process_its_mapc(its, cmd, rollback);
		break;

	case GITS_CMD_CLEAR:
	case GITS_CMD_DISCARD:
	case GITS_CMD_INT:
	case GITS_CMD_INV:
	case GITS_CMD_INVALL:
	case GITS_CMD_MAPTI:
	case GITS_CMD_MOVALL:
	case GITS_CMD_MOVI:
	case GITS_CMD_SYNC:
		ret = 0;
		break;

	default:
		ret = 0;
		break;
	}

	return ret;
}

static void cwriter_write(struct pkvm_moveable_reg *region, u64 offset, u64 value)
{
	struct its_priv_state *its = region->priv;
	struct its_cmd_block cmd, raw;
	u64 new_offset;
	bool retry;
	int i;

	new_offset = value & GITS_CWRITER_OFFSET;
	if (new_offset >= its->shadow->cmdq_len)
		return;

	retry = FIELD_GET(GITS_CWRITER_RETRY, value);
	while (its->cmd_offset != new_offset) {
		memcpy(&raw, its->cmd_host_base + its->cmd_offset, sizeof(raw));

		for (i = 0; i < ARRAY_SIZE(cmd.raw_cmd); i++)
			cmd.raw_cmd[i] = le64_to_cpu(raw.raw_cmd_le[i]);

		if (process_cmd(its, &cmd, /* rollback */ false))
			return;

		memcpy(its->cmd_hyp_base + its->cmd_offset, &raw, sizeof(struct its_cmd_block));

		if (its->needs_flush)
			gic_flush_dcache_to_poc(its->cmd_hyp_base + its->cmd_offset, sizeof(cmd));
		else
			dsb(ishst);

		if (submit_single_cmd(its, retry)) {
			WARN_ON(process_cmd(its, &cmd, /* rollback */ true));
			return;
		}
	}
}

static void cwriter_read(struct pkvm_moveable_reg *region, u64 offset, u64 *read)
{
	struct its_priv_state *its = region->priv;
	*read = readq_relaxed(its->base + GITS_CWRITER);
}

static void ctlr_read(struct pkvm_moveable_reg *region, u64 offset, u64 *read)
{
	struct its_priv_state *its = region->priv;
	*read = readl_relaxed(its->base + GITS_CTLR);
}

static void ctlr_write(struct pkvm_moveable_reg *region, u64 offset, u64 value)
{
	struct its_priv_state *its = region->priv;
	u32 ctlr = readl_relaxed(its->base + GITS_CTLR);
	bool is_quiescent = !!(ctlr & GITS_CTLR_QUIESCENT);
	bool is_enabled = !!(ctlr & GITS_CTLR_ENABLE);

	if (!is_enabled && (value & GITS_CTLR_ENABLE) && !is_quiescent)
		return;

	writel_relaxed(value, its->base + GITS_CTLR);
}

static void cbaser_write(struct pkvm_moveable_reg *region, u64 offset, u64 value)
{
	struct its_priv_state *its = region->priv;
	u64 ctlr = readl_relaxed(its->base + GITS_CTLR);
	int num_pages;

	if ((ctlr & GITS_CTLR_ENABLE) ||
	    !(ctlr & GITS_CTLR_QUIESCENT))
		return;

	num_pages = its->shadow->cmdq_len / SZ_4K;
	value &= ~(GENMASK(7, 0) | GENMASK_ULL(51, 12));

	value |= (num_pages - 1) & GENMASK(7, 0);
	value |= __hyp_pa(its->cmd_hyp_base) & GENMASK_ULL(51, 12);
	its->needs_flush = (value & GITS_CBASER_SHAREABILITY_MASK) != GITS_CBASER_InnerShareable;

	writeq_relaxed(value, its->base + GITS_CBASER);

	/* Restart the CMDQ to read from 0 */
	its->cmd_offset = 0;
	writeq_relaxed(0, its->base + GITS_CWRITER);
}

static void cbaser_read(struct pkvm_moveable_reg *region, u64 offset, u64 *read)
{
	struct its_priv_state *its = region->priv;
	*read = readq_relaxed(its->base + GITS_CBASER);
}

static void baser_write(struct pkvm_moveable_reg *region, u64 offset, u64 value)
{
	struct its_priv_state *its = region->priv;
	u32 ctlr = readl_relaxed(its->base + GITS_CTLR);
	int baser_idx;
	u64 baser;

	if ((ctlr & GITS_CTLR_ENABLE) ||
	    !(ctlr & GITS_CTLR_QUIESCENT))
		return;

	baser_idx = (offset - GITS_BASER) >> 3;
	baser = its->shadow->tables[baser_idx].val;
	if ((value & GITS_BASER_INDIRECT) != (baser & GITS_BASER_INDIRECT))
		return;

	value &= ~(GENMASK_ULL(47, 12) | GENMASK_ULL(9, 0));
	value |= (baser & GENMASK_ULL(47, 12)) | (baser & GENMASK_ULL(9, 0));

	writeq_relaxed(value, its->base + offset);
}

static void baser_read(struct pkvm_moveable_reg *region, u64 offset, u64 *read)
{
	struct its_priv_state *its = region->priv;
	*read = readq_relaxed(its->base + offset);
}

static struct emu_handler its_handlers[] = {
	EMU_REG(GITS_CWRITER, sizeof(u64), cwriter_write, cwriter_read),
	EMU_REG(GITS_CTLR, sizeof(u32), ctlr_write, ctlr_read),
	EMU_REG(GITS_CBASER, sizeof(u64), cbaser_write, cbaser_read),
	EMU_HANDLER(GITS_BASER, sizeof(u64), 8, baser_write, baser_read),
	{},
};

void pkvm_handle_forward_req(struct pkvm_moveable_reg *region, u64 offset, bool write,
			     u64 *reg, u8 reg_size)
{
	void __iomem *addr = __hyp_va(region->start + offset);

	if (reg_size == sizeof(u32)) {
		if (!write)
			*reg = readl_relaxed(addr);
		else
			writel_relaxed(*reg, addr);
	} else if (reg_size == sizeof(u64)) {
		if (!write)
			*reg = readq_relaxed(addr);
		else
			writeq_relaxed(*reg, addr);
	}
}

void pkvm_handle_gic_emulation(struct pkvm_moveable_reg *region, u64 offset, bool write,
			       u64 *reg, u8 reg_size)
{
	struct its_priv_state *its_priv = region->priv;

	if (!its_priv)
		return;

	if (!IS_ALIGNED(offset, reg_size))
		return;

	handle_emulation(region, offset, write, reg, reg_size, its_handlers,
			 &its_priv->its_lock);
}

static struct pkvm_moveable_reg *get_region(phys_addr_t dev_addr)
{
	int i;

	for (i = 0; i < pkvm_moveable_regs_nr; i++) {
		if (pkvm_moveable_regs[i].start == dev_addr)
			return &pkvm_moveable_regs[i];
	}

	return NULL;
}

static int pkvm_host_unmap_last_level(void *shadow, size_t num_pages, u32 psz)
{
	u64 *table = shadow;
	int ret, i, end = (num_pages << PAGE_SHIFT) / sizeof(*table);
	phys_addr_t table_addr;

	for (i = 0; i < end; i++) {
		if (!(table[i] & GITS_BASER_VALID))
			continue;

		table_addr = table[i] & PHYS_MASK;
		ret = __pkvm_host_donate_hyp(hyp_phys_to_pfn(table_addr), psz >> PAGE_SHIFT);
		if (ret)
			goto err_donate;
	}

	return 0;
err_donate:
	for (i = i - 1; i >= 0; i--) {
		if (!(table[i] & GITS_BASER_VALID))
			continue;

		table_addr = table[i] & PHYS_MASK;
		__pkvm_hyp_donate_host(hyp_phys_to_pfn(table_addr), psz >> PAGE_SHIFT);
	}
	return ret;
}

static int pkvm_share_shadow_table(void *shadow, u64 nr_pages)
{
	u64 i, ret, start_pfn = hyp_virt_to_pfn(shadow);

	for (i = 0; i < nr_pages; i++) {
		ret = __pkvm_host_share_hyp(start_pfn + i);
		if (ret)
			goto unshare;
	}

	ret = hyp_pin_shared_mem(shadow, shadow + (nr_pages << PAGE_SHIFT));
	if (ret)
		goto unshare;

	return ret;
unshare:
	while (i--)
		__pkvm_host_unshare_hyp(start_pfn + i);
	return ret;
}

static void pkvm_unshare_shadow_table(void *shadow, u64 nr_pages)
{
	u64 i, start_pfn = hyp_virt_to_pfn(shadow);

	hyp_unpin_shared_mem(shadow, shadow + (nr_pages << PAGE_SHIFT));

	for (i = 0; i < nr_pages; i++)
		WARN_ON(__pkvm_host_unshare_hyp(start_pfn + i));
}

static void pkvm_host_map_last_level(void *shadow, size_t num_pages, u32 psz)
{
	u64 *table = shadow;
	int i, end = (num_pages << PAGE_SHIFT) / sizeof(*table);
	phys_addr_t table_addr;

	for (i = 0; i < end; i++) {
		if (!(table[i] & GITS_BASER_VALID))
			continue;

		table_addr = table[i] & PHYS_MASK;
		WARN_ON(__pkvm_hyp_donate_host(hyp_phys_to_pfn(table_addr), psz >> PAGE_SHIFT));
	}
}

static int pkvm_setup_its_shadow_baser(struct its_shadow_tables *shadow)
{
	int i, ret;
	u64 baser_val, num_pages, type;
	void *base, *host_base;

	for (i = 0; i < GITS_BASER_NR_REGS; i++) {
		baser_val = shadow->tables[i].val;
		if (!(baser_val & GITS_BASER_VALID))
			continue;

		base = kern_hyp_va(shadow->tables[i].base);
		num_pages = (1 << shadow->tables[i].order);

		ret = __pkvm_host_donate_hyp(hyp_virt_to_pfn(base), num_pages);
		if (ret)
			goto err_donate;

		if (baser_val & GITS_BASER_INDIRECT) {
			host_base = kern_hyp_va(shadow->tables[i].shadow);
			ret = pkvm_share_shadow_table(host_base, num_pages);
			if (ret)
				goto err_with_donation;

			type = GITS_BASER_TYPE(baser_val);
			if (type == GITS_BASER_TYPE_COLLECTION)
				continue;

			ret = pkvm_host_unmap_last_level(base, num_pages,
							 shadow->tables[i].psz);
			if (ret)
				goto err_with_share;
		}
	}

	return 0;
err_with_share:
	pkvm_unshare_shadow_table(host_base, num_pages);
err_with_donation:
	__pkvm_hyp_donate_host(hyp_virt_to_pfn(base), num_pages);
err_donate:
	for (i = i - 1; i >= 0; i--) {
		baser_val = shadow->tables[i].val;
		if (!(baser_val & GITS_BASER_VALID))
			continue;

		base = kern_hyp_va(shadow->tables[i].base);
		num_pages = (1 << shadow->tables[i].order);

		if (baser_val & GITS_BASER_INDIRECT) {
			host_base = kern_hyp_va(shadow->tables[i].shadow);
			pkvm_unshare_shadow_table(host_base, num_pages);

			type = GITS_BASER_TYPE(baser_val);
			if (type == GITS_BASER_TYPE_COLLECTION) {
				WARN_ON(__pkvm_hyp_donate_host(hyp_virt_to_pfn(base), num_pages));
				continue;
			}

			pkvm_host_map_last_level(base, num_pages, shadow->tables[i].psz);
		}

		WARN_ON(__pkvm_hyp_donate_host(hyp_virt_to_pfn(base), num_pages));
	}

	return ret;
}

static int pkvm_setup_its_shadow_cmdq(struct its_shadow_tables *shadow)
{
	int ret, i, num_pages;
	u64 shadow_start_pfn, original_start_pfn;
	void *cmd_shadow_va = kern_hyp_va(shadow->cmd_shadow);

	shadow_start_pfn = hyp_virt_to_pfn(cmd_shadow_va);
	original_start_pfn = hyp_virt_to_pfn(kern_hyp_va(shadow->cmd_original));
	num_pages = shadow->cmdq_len >> PAGE_SHIFT;

	for (i = 0; i < num_pages; i++) {
		ret = __pkvm_host_share_hyp(shadow_start_pfn + i);
		if (ret)
			goto unshare_shadow;
	}

	ret = hyp_pin_shared_mem(cmd_shadow_va, cmd_shadow_va + shadow->cmdq_len);
	if (ret)
		goto unshare_shadow;

	ret = __pkvm_host_donate_hyp(original_start_pfn, num_pages);
	if (ret)
		goto unpin_shadow;

	return ret;

unpin_shadow:
	hyp_unpin_shared_mem(cmd_shadow_va, cmd_shadow_va + shadow->cmdq_len);

unshare_shadow:
	for (i = i - 1; i >= 0; i--)
		__pkvm_host_unshare_hyp(shadow_start_pfn + i);

	return ret;
}

static void pkvm_teardown_its_shadow_cmdq(struct its_shadow_tables *shadow)
{
	u64 i, start_pfn, num_pages = shadow->cmdq_len >> PAGE_SHIFT;
	void *cmd_shadow_va = kern_hyp_va(shadow->cmd_shadow);
	void *cmd_original = kern_hyp_va(shadow->cmd_original);

	start_pfn = hyp_virt_to_pfn(cmd_shadow_va);
	hyp_unpin_shared_mem(cmd_shadow_va,
			     cmd_shadow_va + shadow->cmdq_len);

	for (i = 0; i < num_pages; i++)
		WARN_ON(__pkvm_host_unshare_hyp(start_pfn + i));

	WARN_ON(__pkvm_hyp_donate_host(hyp_virt_to_pfn(cmd_original), num_pages));
}

int pkvm_init_gic_its_emulation(phys_addr_t dev_addr, void *host_priv_state, size_t priv_num_pages,
				struct its_shadow_tables *host_shadow)
{
	int ret;
	struct its_priv_state *priv_state = kern_hyp_va(host_priv_state);
	struct its_shadow_tables *shadow = kern_hyp_va(host_shadow);
	struct pkvm_moveable_reg *its_reg;

	if (!static_branch_unlikely(&kvm_its_hardening))
		return -EOPNOTSUPP;

	if (!PAGE_ALIGNED(shadow) || !priv_num_pages)
		return -EINVAL;

	hyp_spin_lock(&its_setup_lock);
	its_reg = get_region(dev_addr);
	if (!its_reg) {
		ret = -ENODEV;
		goto err_unlock;
	}

	if (its_reg->priv || its_reg->type != PKVM_MREG_EMULATE_MMIO) {
		ret = -EOPNOTSUPP;
		goto err_unlock;
	}

	ret = donate_and_clear_host_page(priv_state, priv_num_pages);
	if (ret)
		goto err_unlock;

	ret = __pkvm_host_donate_hyp(hyp_virt_to_pfn(shadow), 1);
	if (ret)
		goto err_with_state;

	ret = pkvm_setup_its_shadow_cmdq(shadow);
	if (ret)
		goto err_with_shadow;

	ret = pkvm_setup_its_shadow_baser(shadow);
	if (ret)
		goto err_with_cmdq;

	hyp_spin_lock_init(&priv_state->its_lock);
	priv_state->shadow = shadow;
	priv_state->base = __hyp_va(dev_addr);

	priv_state->cmd_hyp_base = kern_hyp_va(shadow->cmd_original);
	priv_state->cmd_host_base = kern_hyp_va(shadow->cmd_shadow);
	priv_state->cmd_offset = readq_relaxed(priv_state->base + GITS_CREADR) &
		GITS_CREADR_OFFSET;
	priv_state->needs_flush =
		(readq_relaxed(priv_state->base + GITS_CBASER) & GITS_CBASER_SHAREABILITY_MASK) !=
		GITS_CBASER_InnerShareable;
	priv_state->empty_idx = 0;
	priv_state->num_tracked_pfns = ((priv_num_pages << PAGE_SHIFT) -
		offsetof(struct its_priv_state, tracked_pfns)) / sizeof(struct dte_entry);

	its_reg->priv = priv_state;

	hyp_spin_unlock(&its_setup_lock);

	return 0;
err_with_cmdq:
	pkvm_teardown_its_shadow_cmdq(shadow);
err_with_shadow:
	WARN_ON(__pkvm_hyp_donate_host(hyp_virt_to_pfn(shadow), 1));
err_with_state:
	memset(priv_state, 0, priv_num_pages * PAGE_SIZE);
	WARN_ON(__pkvm_hyp_donate_host(hyp_virt_to_pfn(priv_state), priv_num_pages));
err_unlock:
	hyp_spin_unlock(&its_setup_lock);
	return ret;
}

static DEFINE_HYP_SPINLOCK(redist_lock);
static LIST_HEAD(redist_states);

#define for_each_redist(__redist) \
	list_for_each_entry(__redist, &redist_states, entry)

struct redist_priv_state {
	void *base;
	struct list_head entry;

	u64 typer;
	u64 lpi_aff;
	bool lpi_enabled;
	u64 propbaser;
	u64 pendbaser;
};

static inline u64 redist_lpi_aff(u64 typer)
{
	u64 aff;
	u64 lpi_aff;

	aff = FIELD_GET(GICR_TYPER_AFFINITY, typer);
	lpi_aff = FIELD_GET(GICR_TYPER_COMMON_LPI_AFF, typer);

	return aff & ~GENMASK_ULL(31 - (lpi_aff << 3), 0);
}

static int hyp_share_pin_mem(u64 phys, u64 size, bool share)
{
	u64 start_pfn = phys >> PAGE_SHIFT;
	u64 num_pages = size >> PAGE_SHIFT;
	void *virt;
	int ret, i;

	virt = hyp_phys_to_virt(phys);
	if (!share)
		return hyp_pin_shared_mem(virt, virt + size);

	for (i = 0; i < num_pages; i++) {
		ret = __pkvm_host_share_hyp(start_pfn + i);
		if (ret)
			goto unshare;
	}

	ret = hyp_pin_shared_mem(virt, virt + size);
	if (ret)
		goto unshare;

	return 0;
unshare:
	for (i = i - 1; i >= 0; i--)
		__pkvm_host_unshare_hyp(start_pfn + i);

	return ret;
}

static void hyp_unshare_unpin_mem(u64 phys, u64 size, bool unshare)
{
	u64 start_pfn = phys >> PAGE_SHIFT;
	u64 num_pages = size >> PAGE_SHIFT;
	void *virt;
	int i;

	virt = hyp_phys_to_virt(phys);
	hyp_unpin_shared_mem(virt, virt + size);

	if (!unshare)
		return;

	for (i = 0; i < num_pages; i++)
		WARN_ON(__pkvm_host_unshare_hyp(start_pfn + i));
}

/* Minimum and maximum possible values of GICD_TYPER.IDbits */
#define MIN_LPI_ID_BITS	13
#define MAX_LPI_ID_BITS	31

static int handle_lpi_enable(struct redist_priv_state *redist)
{
	struct redist_priv_state *other;
	bool share_prop = true;
	u64 id_bits, prop_sz, pend_sz;
	int ret;

	id_bits = FIELD_GET(GICR_PROPBASER_IDBITS_MASK, redist->propbaser);
	id_bits = clamp_t(u64, id_bits, MIN_LPI_ID_BITS, MAX_LPI_ID_BITS);

	/*
	 * Require all GICRs in the affinity or sharing property table to
	 * share the same propbaser value.
	 */
	for_each_redist(other) {
		/* Ignore self and GICR with disabled LPI */
		if (redist == other || !other->lpi_enabled)
			continue;

		/*
		 * Process only the GICRs in the same affinity group or
		 * sharing the same property table.
		 */
		if (GICR_PROPBASER_ADDRESS(other->propbaser) !=
			    GICR_PROPBASER_ADDRESS(redist->propbaser) &&
		    redist->lpi_aff != other->lpi_aff)
			continue;

		if (redist->propbaser != other->propbaser)
			return -EFAULT;

		/*
		 * This is not the first GICR with this property table
		 * and LPI enabled. The table has been already shared.
		 */
		share_prop = false;
	}

	/* Increase refcount for the property table */
	prop_sz = ALIGN(BIT_ULL(id_bits + 1), SZ_64K);
	ret = hyp_share_pin_mem(GICR_PROPBASER_ADDRESS(redist->propbaser),
				prop_sz, share_prop);
	if (ret)
		return ret;

	/* Share and pin the pending table */
	pend_sz = ALIGN(BIT_ULL(id_bits + 1) / 8, SZ_64K);
	ret = hyp_share_pin_mem(GICR_PENDBASER_ADDRESS(redist->pendbaser),
				pend_sz, /* share */ true);
	if (ret)
		goto unshare_prop_tab;

	redist->lpi_enabled = true;
	return 0;
unshare_prop_tab:
	hyp_unshare_unpin_mem(GICR_PROPBASER_ADDRESS(redist->propbaser),
			      prop_sz, share_prop);
	return ret;
}

static int handle_lpi_disable(struct redist_priv_state *redist)
{
	struct redist_priv_state *other;
	bool unshare_prop = true;
	u64 id_bits, prop_sz, pend_sz;

	id_bits = FIELD_GET(GICR_PROPBASER_IDBITS_MASK, redist->propbaser);
	id_bits = clamp_t(u64, id_bits, MIN_LPI_ID_BITS, MAX_LPI_ID_BITS);

	/* Check if this is a last GICR that uses the property table */
	for_each_redist(other) {
		/* Ignore self and GICR with disabled LPI */
		if (redist == other || !other->lpi_enabled)
			continue;

		/* Ignore GICR that do not use the same property table */
		if (GICR_PROPBASER_ADDRESS(other->propbaser) !=
		    GICR_PROPBASER_ADDRESS(redist->propbaser))
			continue;

		/*
		 * Another GICR still uses this property table with LPIs
		 * enabled. Do not unshare the property table.
		 */
		unshare_prop = false;
	}

	/* Decrease refcount for property table */
	prop_sz = ALIGN(BIT_ULL(id_bits + 1), SZ_64K);
	hyp_unshare_unpin_mem(GICR_PROPBASER_ADDRESS(redist->propbaser),
			      prop_sz, unshare_prop);

	/* Unshare and unpin the pending table */
	pend_sz = ALIGN(BIT_ULL(id_bits + 1) / 8, SZ_64K);
	hyp_unshare_unpin_mem(GICR_PENDBASER_ADDRESS(redist->pendbaser),
			      pend_sz, /* unshare */ true);

	redist->lpi_enabled = false;
	return 0;
}

static int init_redist_priv_state(struct pkvm_moveable_reg *reg,
				  struct redist_priv_state *redist,
				  u64 typer)
{
	int ret = 0;
	u32 ctrl;

	redist->base = __hyp_va(reg->start);
	redist->typer = typer;
	redist->lpi_aff = redist_lpi_aff(typer);
	redist->propbaser = readq_relaxed(redist->base + GICR_PROPBASER);
	redist->pendbaser = readq_relaxed(redist->base + GICR_PENDBASER);

	/* If LPI are enabled, there's work to do */
	ctrl = readl_relaxed(redist->base + GICR_CTLR);
	if (FIELD_GET(GICR_CTLR_ENABLE_LPIS, ctrl))
		ret = handle_lpi_enable(redist);

	if (!ret)
		reg->priv = redist;

	return ret;
}

int pkvm_init_redist_emulation(phys_addr_t redist_base, void *host_priv_states)
{
	int ret = 0;
	struct redist_priv_state *redist = kern_hyp_va(host_priv_states);
	struct pkvm_moveable_reg *rd_reg, *vlpi_reg = NULL;
	u64 typer;

	if (!static_branch_unlikely(&kvm_its_hardening))
		return -EOPNOTSUPP;

	hyp_spin_lock(&redist_lock);
	/* Find the region with redistributor */
	rd_reg = get_region(redist_base);
	if (!rd_reg) {
		ret = -ENODEV;
		goto unlock;
	}

	/* Check if it supports VLPI and if so find its separate region */
	typer = readq_relaxed(__hyp_va(rd_reg->start) + GICR_TYPER);
	if (FIELD_GET(GICR_TYPER_VLPIS, typer)) {
		vlpi_reg = get_region(redist_base + SZ_128K);
		if (!vlpi_reg) {
			ret = -ENODEV;
			goto unlock;
		}
	}

	/* If either of these were initialized, something is seriously wrong */
	if (rd_reg->priv || (vlpi_reg && vlpi_reg->priv)) {
		ret = -EINVAL;
		goto unlock;
	}

	/* Use one page donated by host for RG_Base state */
	BUILD_BUG_ON(sizeof(struct redist_priv_state) > PAGE_SIZE);
	ret = donate_and_clear_host_page(redist, 1);
	if (ret)
		goto unlock;

	/* Initialize RD_Base state */
	ret = init_redist_priv_state(rd_reg, &redist[0], typer);
	if (ret)
		goto err;

	list_add_tail(&redist[0].entry, &redist_states);
err:
	if (ret) {
		memset(redist, 0, PAGE_SIZE);
		__pkvm_hyp_donate_host(hyp_virt_to_pfn(redist), 1);
	}
unlock:
	hyp_spin_unlock(&redist_lock);
	return ret;
}

static u32 update_ctlr(struct redist_priv_state *redist, u32 ctlr)
{
	u64 timeout = 1000;

	writel_relaxed(ctlr, redist->base + GICR_CTLR);

	ctlr = readl_relaxed(redist->base + GICR_CTLR);
	while (FIELD_GET(GICR_CTLR_RWP, ctlr)) {
		if (!timeout--)
			break;

		pkvm_udelay(100);
		ctlr = readl_relaxed(redist->base + GICR_CTLR);
	}

	return ctlr;
}

static void enable_lpi(struct redist_priv_state *redist, u32 ctlr)
{
	int ret;

	/* Try to verify if the LPI is safe to enable first */
	ret = handle_lpi_enable(redist);
	if (ret)
		return;

	writeq_relaxed(redist->propbaser, redist->base + GICR_PROPBASER);
	writeq_relaxed(redist->pendbaser, redist->base + GICR_PENDBASER);

	/*
	 * Try to update the GICR_CTLR to EnableLPI=1. If RWP=0 but
	 * EnableLPI stays disabled then revert to disabled.
	 */
	ctlr = update_ctlr(redist, ctlr);
	if (!FIELD_GET(GICR_CTLR_ENABLE_LPIS, ctlr) &&
	    !FIELD_GET(GICR_CTLR_RWP, ctlr))
		handle_lpi_disable(redist);
}

static void disable_lpi(struct redist_priv_state *redist, u32 ctlr)
{
	/*
	 * Try to update the GICR_CTLR to EnableLPI=0. If RWP=0 but
	 * EnableLPI stays enabled then drop write.
	 */
	ctlr = update_ctlr(redist, ctlr);
	if (FIELD_GET(GICR_CTLR_ENABLE_LPIS, ctlr) ||
	    FIELD_GET(GICR_CTLR_RWP, ctlr))
		return;

	/* Disabling was successful we can safely unshare memory */
	handle_lpi_disable(redist);
}

static void redist_ctlr_write(struct pkvm_moveable_reg *region, u64 offset,
			      u64 value)
{
	struct redist_priv_state *redist = region->priv;
	bool lpi;
	u32 ctlr;

	/*
	 * Check if previous write to GICR_CTLR is still pending
	 * indicated by GICR_CTLR.RWP. If so deny update.
	 */
	ctlr = readl_relaxed(redist->base + GICR_CTLR);
	if (FIELD_GET(GICR_CTLR_RWP, ctlr))
		return;

	lpi = FIELD_GET(GICR_CTLR_ENABLE_LPIS, value);

	/*
	 * Handle toggling EnableLPI in special manner.
	 * Forward oher writes.
	 */
	if (lpi && !redist->lpi_enabled)
		enable_lpi(redist, value);
	else if (!lpi && redist->lpi_enabled)
		disable_lpi(redist, value);
	else
		writel_relaxed(value, redist->base + GICR_CTLR);
}

static void redist_ctlr_read(struct pkvm_moveable_reg *region, u64 offset,
			     u64 *read)
{
	struct redist_priv_state *redist = region->priv;
	*read = readl_relaxed(redist->base + GICR_CTLR);
}

static void redist_ctlr_pre_init(struct pkvm_moveable_reg *region,
				      u64 offset, u64 *read)
{
	/*
	 * Pretend that there is a register write pending until
	 * redistributor is initialized using pkvm_init_redist_emulation.
	 * This should keep the driver busy for some time...
	 */
	*read = GICR_CTLR_RWP;
}

static void propbaser_write(struct pkvm_moveable_reg *region, u64 offset,
			    u64 value)
{
	struct redist_priv_state *redist = region->priv;

	/* Modifications to GICR_PROPBASER are not allowed when LPIs are enabled */
	if (redist->lpi_enabled)
		return;

	value &= GICR_PROPBASER_OUTER_CACHEABILITY_MASK |
		 /* Address */ GENMASK_ULL(51, 12) |
		 GICR_PROPBASER_SHAREABILITY_MASK |
		 GICR_PROPBASER_INNER_CACHEABILITY_MASK |
		 GICR_PROPBASER_IDBITS_MASK;

	writeq_relaxed(value, redist->base + GICR_PROPBASER);
	redist->propbaser = readq_relaxed(redist->base + GICR_PROPBASER);
}

static void propbaser_read(struct pkvm_moveable_reg *region, u64 offset,
			   u64 *read)
{
	struct redist_priv_state *redist = region->priv;
	*read = redist->propbaser;
}

static void pendbaser_write(struct pkvm_moveable_reg *region, u64 offset,
			    u64 value)
{
	struct redist_priv_state *redist = region->priv;

	/* Modifications to GICR_PENDBASER are not allowed when LPIs are enabled */
	if (redist->lpi_enabled)
		return;

	value &= GICR_PENDBASER_PTZ | GICR_PENDBASER_OUTER_CACHEABILITY_MASK |
		 /* Address */ GENMASK_ULL(51, 16) |
		 GICR_PENDBASER_SHAREABILITY_MASK |
		 GICR_PENDBASER_INNER_CACHEABILITY_MASK;

	writeq_relaxed(value, redist->base + GICR_PENDBASER);
	redist->pendbaser = readq_relaxed(redist->base + GICR_PENDBASER);
}

static void pendbaser_read(struct pkvm_moveable_reg *region, u64 offset,
			   u64 *read)
{
	struct redist_priv_state *redist = region->priv;
	*read = redist->pendbaser;
}

static void invlpir_write(struct pkvm_moveable_reg *region, u64 offset,
			  u64 value)
{
	void __iomem *addr = __hyp_va(region->start + GICR_INVLPIR);

	/* VLPIs are currently not allowed */
	if (FIELD_GET(GICR_INVLPIR_V, value))
		return;
	/*
	 * Don't use the region->priv (redist_priv_state) for priv->base
	 * so this callback can be used for both redist_handlers and
	 * redist_handlers_pre_init when priv is not initialized.
	 */
	writeq_relaxed(value, addr);
}

static void invallr_write(struct pkvm_moveable_reg *region, u64 offset,
			  u64 value)
{
	void __iomem *addr = __hyp_va(region->start + GICR_INVALLR);

	/* VLPIs are currently not allowed */
	if (FIELD_GET(GICR_INVALLR_V, value))
		return;

	/*
	 * Don't use the region->priv (redist_priv_state) for priv->base
	 * so this callback can be used for both redist_handlers and
	 * redist_handlers_pre_init when priv is not initialized.
	 */
	writeq_relaxed(value, addr);
}

static struct emu_handler redist_handlers[] = {
	EMU_REG(GICR_CTLR, sizeof(u32), redist_ctlr_write, redist_ctlr_read),
	EMU_REG_RAZ_WI(GICR_SETLPIR, sizeof(u64)),
	EMU_REG_RAZ_WI(GICR_CLRLPIR, sizeof(u64)),
	EMU_REG(GICR_PROPBASER, sizeof(u64), propbaser_write, propbaser_read),
	EMU_REG(GICR_PENDBASER, sizeof(u64), pendbaser_write, pendbaser_read),
	EMU_REG(GICR_INVLPIR, sizeof(u64), invlpir_write, read_as_zero),
	EMU_REG(GICR_INVALLR, sizeof(u64), invallr_write, read_as_zero),
	{},
};

/*
 * Emulation handlers for redistributors not yet initialized
 * by pkvm_init_redist_emulation in pkvm_drop_host_privileges
 * window.
 */
static struct emu_handler redist_handlers_pre_init[] = {
	EMU_REG(GICR_CTLR, sizeof(u32), write_ignore, redist_ctlr_pre_init),
	EMU_REG_RAZ_WI(GICR_SETLPIR, sizeof(u64)),
	EMU_REG_RAZ_WI(GICR_CLRLPIR, sizeof(u64)),
	EMU_REG_RAZ_WI(GICR_PROPBASER, sizeof(u64)),
	EMU_REG_RAZ_WI(GICR_PENDBASER, sizeof(u64)),
	EMU_REG(GICR_INVLPIR, sizeof(u64), invlpir_write, read_as_zero),
	EMU_REG(GICR_INVALLR, sizeof(u64), invallr_write, read_as_zero),
	{},
};

void pkvm_handle_rdist_emulation(struct pkvm_moveable_reg *region, u64 offset,
				 bool write, u64 *reg, u8 reg_size)
{
	struct redist_priv_state *redist;

	hyp_spin_lock(&redist_lock);
	redist = region->priv;
	hyp_spin_unlock(&redist_lock);

	if (redist)
		handle_emulation(region, offset, write, reg, reg_size,
				 redist_handlers, &redist_lock);
	else
		handle_emulation(region, offset, write, reg, reg_size,
				 redist_handlers_pre_init, NULL);
}

void pkvm_handle_vlpi_emulation(struct pkvm_moveable_reg *region, u64 offset,
				 bool write, u64 *reg, u8 reg_size)
{
	/* Do nothing. We block VLPIs for now until we can ship proper sanitization */
}
