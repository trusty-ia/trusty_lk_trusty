/*
 * Copyright (c) 2013, Google Inc. All rights reserved
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

#include <arch/arm.h>
#include <arch/arm/mmu.h>
#include <lib/kmap.h>

extern uint32_t tt[];

void arm_mmu_unmap_section(addr_t vaddr)
{
	int index;

	index = vaddr / PAGE_SIZE_1M;

	tt[index] = 0;
	arm_invalidate_tlb();
}

status_t arch_kmap(kmap_t *mp)
{
	addr_t vaddr, paddr;
	u_int flags, pg;

	/* Security */
	flags = (mp->flags & KM_NS_MEM) ? MMU_MEMORY_L1_SECTION_NON_SECURE : 0;

	/* Permissions */
	if (mp->flags & KM_NONE)
		flags |= MMU_MEMORY_L1_AP_P_NA_U_NA;
	else
		/* TODO: we don't have flags defined for kernel read-only perms */
		flags |= MMU_MEMORY_L1_AP_P_RW_U_NA;

	/* Caching policy */
	if (mp->flags & KM_IO)
		flags |= MMU_MEMORY_L1_TYPE_DEVICE_SHARED;
	else if (mp->flags & KM_UC)
		flags |= MMU_MEMORY_L1_TYPE_NORMAL;
	else
		flags |= MMU_MEMORY_L1_TYPE_NORMAL_WRITE_BACK_NO_ALLOCATE;

	for (pg = 0; pg < (mp->size / PAGE_SIZE_1M); pg++) {
		if (mp->flags & KM_PHYS_CONTIG)
			paddr = mp->pfn_list[0] + (pg * PAGE_SIZE_1M);
		else
			paddr = mp->pfn_list[pg];

		if (!paddr)
			goto err_undo_maps;

		vaddr = mp->vaddr + (pg * PAGE_SIZE_1M);
		arm_mmu_map_section(paddr, vaddr, flags);
	}

	return NO_ERROR;

err_undo_maps:
	for(u_int p = 0; p < pg; p++)
		arm_mmu_unmap_section(mp->vaddr + (p * PAGE_SIZE_1M));

	return ERR_INVALID_ARGS;
}

status_t arch_kunmap(kmap_t *mp)
{
	addr_t vaddr;
	u_int pg;

	for (pg = 0; pg < (mp->size / PAGE_SIZE_1M); pg++) {
		vaddr = mp->vaddr + (pg * PAGE_SIZE_1M);
		arm_mmu_unmap_section(vaddr);
	}

	return NO_ERROR;
}
