/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_INTERRUPT_RC_H
#define __LINUX_INTERRUPT_RC_H

/*
 * Refcounted local processor interrupt management.
 *
 * local_interrupt_disable() disables interrupts on the local CPU and may be
 * nested; interrupts are only restored once the outermost
 * local_interrupt_enable() runs.
 *
 * Unlike local_irq_save()/local_irq_restore(), the saved interrupt state is
 * held in per-CPU state rather than by the caller, so the regions do not have
 * to be released in acquisition order. That property is what allows Rust's
 * SpinLockIrq guards - which are ordinary values and may be dropped in any
 * order - to be built on top of this.
 *
 * Since the implementation depends on local_irq_save()/local_irq_restore(),
 * this lives in its own header to make it easier to include without hitting
 * circular header dependencies.
 */

void local_interrupt_disable(void);
void local_interrupt_enable(void);

#endif /* !__LINUX_INTERRUPT_RC_H */
