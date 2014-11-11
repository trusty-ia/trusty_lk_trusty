/*
 * Copyright (c) 2013-2014, Google Inc. All rights reserved
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <uthread.h>
#include <stdlib.h>
#include <assert.h>
#include <debug.h>
#include <arch.h>
#include <arch/arm64.h>
#include <arch/arm64/mmu.h>
#include <arch/uthread_mmu.h>
#include <uthread.h>
#include <string.h>
#include <trace.h>

#define LOCAL_TRACE 0

#define USER_PAGE_MASK	(USER_PAGE_SIZE - 1)

void arch_uthread_init(void)
{
}

void arch_uthread_startup(void)
{
	struct uthread *ut = (struct uthread *) tls_get(TLS_ENTRY_UTHREAD);
	register uint64_t sp_usr asm("x2") = ROUNDDOWN(ut->start_stack, 8);
	register uint64_t entry asm("x3") = ut->entry;

	__asm__ volatile(
		"mov	x0, #0\n"
		"mov	x1, #0\n"
		"mov	x13, %[stack]\n" /* AArch32 SP_usr */
		"mov	x14, %[entry]\n" /* AArch32 LR_usr */
		"mov	x9, #0x10\n" /* Mode = AArch32 User */
		"msr	spsr_el1, x9\n"
		"msr	elr_el1, %[entry]\n"
		"eret\n"
		:
		: [stack]"r" (sp_usr), [entry]"r" (entry)
		: "x0", "x1", "memory"
	);
}

void arch_uthread_context_switch(struct uthread *old_ut, struct uthread *new_ut)
{
	paddr_t pgd;

	if (old_ut && !new_ut) {
		ARM64_WRITE_SYSREG(tcr_el1, MMU_TCR_FLAGS_KERNEL);
	}

	if (new_ut) {
		pgd = kvaddr_to_paddr(new_ut->page_table);
		ARM64_WRITE_SYSREG(ttbr0_el1, (paddr_t)new_ut->arch.asid << 48 | pgd);
		if (!old_ut)
			ARM64_WRITE_SYSREG(tcr_el1, MMU_TCR_FLAGS_USER);
	}
}

status_t arch_uthread_create(struct uthread *ut)
{
	status_t err = NO_ERROR;

	ut->arch.asid = ut->id;
	ut->arch.uthread = ut;

	return err;
}

void arch_uthread_free(struct uthread *ut)
{
	arm64_mmu_unmap(0, 1UL << MMU_USER_SIZE_SHIFT,
	                0, MMU_USER_SIZE_SHIFT,
	                MMU_USER_TOP_SHIFT, MMU_USER_PAGE_SIZE_SHIFT,
	                ut->page_table, ut->arch.asid);

	free(ut->page_table);
}

status_t arm64_uthread_allocate_page_table(struct uthread *ut)
{
	size_t page_table_size;

	page_table_size = MMU_USER_PAGE_TABLE_ENTRIES_TOP * sizeof(pte_t);

	ut->page_table = memalign(page_table_size, page_table_size);
	if (!ut->page_table)
		return ERR_NO_MEMORY;

	memset(ut->page_table, 0, page_table_size);

	LTRACEF("id %d, user page table %p, size %ld\n",
	        ut->id, ut->page_table, page_table_size);

	return NO_ERROR;
}

status_t arch_uthread_map(struct uthread *ut, struct uthread_map *mp)
{
	paddr_t pg, pte_attr;
	size_t entry_size;
	status_t err = NO_ERROR;

	if (!ut->page_table) {
		err = arm64_uthread_allocate_page_table(ut);
		if (err)
			return err;
	}

	ASSERT(!(mp->size & USER_PAGE_MASK));

	pte_attr = MMU_PTE_ATTR_NON_GLOBAL | MMU_PTE_ATTR_AF;

	pte_attr |= (mp->flags & UTM_NS_MEM) ? MMU_PTE_ATTR_NON_SECURE : 0;

	pte_attr |= (mp->flags & UTM_W) ? MMU_PTE_ATTR_AP_P_RW_U_RW :
	                                  MMU_PTE_ATTR_AP_P_RO_U_RO;
	if (mp->flags & UTM_IO) {
		pte_attr |= MMU_PTE_ATTR_STRONGLY_ORDERED;
	} else {
		/* shareable */
		pte_attr |= MMU_PTE_ATTR_SH_INNER_SHAREABLE;

		/* use same cache attributes as kernel */
		pte_attr |= MMU_PTE_ATTR_NORMAL_MEMORY;
	}

	entry_size = (mp->flags & UTM_PHYS_CONTIG) ? mp->size : USER_PAGE_SIZE;
	for (pg = 0; pg < (mp->size / entry_size); pg++) {
		err = arm64_mmu_map(mp->vaddr + pg * entry_size,
		                    mp->pfn_list[pg], entry_size, pte_attr,
		                    0, MMU_USER_SIZE_SHIFT, MMU_USER_TOP_SHIFT,
		                    MMU_USER_PAGE_SIZE_SHIFT,
		                    ut->page_table, ut->arch.asid);
		if (err)
			goto err_undo_maps;
	}

	return NO_ERROR;

err_undo_maps:
	for(u_int p = 0; p < pg; p++) {
		arm64_mmu_unmap(mp->vaddr + p * entry_size, entry_size,
		                0, MMU_USER_SIZE_SHIFT,
		                MMU_USER_TOP_SHIFT, MMU_USER_PAGE_SIZE_SHIFT,
		                ut->page_table, ut->arch.asid);
	}

	return err;
}

status_t arch_uthread_unmap(struct uthread *ut, struct uthread_map *mp)
{
	return arm64_mmu_unmap(mp->vaddr, mp->size, 0, MMU_USER_SIZE_SHIFT,
	                       MMU_USER_TOP_SHIFT, MMU_USER_PAGE_SIZE_SHIFT,
	                       ut->page_table, ut->arch.asid);
}
