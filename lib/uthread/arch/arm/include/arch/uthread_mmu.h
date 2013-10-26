/*
 * Copyright (c) 2013, Google Inc. All rights reserved
 * Copyright (c) 2012-2013, NVIDIA CORPORATION. All rights reserved
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
#ifndef __LIB_UTHREAD_ARCH_ARM_MMU_H
#define __LIB_UTHREAD_ARCH_ARM_MMU_H

#include <arch.h>
#include <uthread.h>

#define MMU_MEMORY_TTBCR_N		7

#define MMU_MEMORY_TTBR0_L1_INDEX_BITS	(((31 - MMU_MEMORY_TTBCR_N) - 20) + 1)
#define MMU_MEMORY_TTBR0_L1_INDEX_MASK	((1 << MMU_MEMORY_TTBR0_L1_INDEX_BITS) - 1)
#define MMU_MEMORY_TTBR0_L1_SIZE	(1 << (MMU_MEMORY_TTBR0_L1_INDEX_BITS + 2))

#define MMU_MEMORY_TTBR1_L1_INDEX_BITS	((31 - 20) + 1)
#define MMU_MEMORY_TTBR1_L1_INDEX_MASK	((1 << MMU_MEMORY_TTBR1_L1_INDEX_BITS) - 1)
#define MMU_MEMORY_TTBR1_L1_SIZE	(1 << (MMU_MEMORY_TTBR1_L1_INDEX_BITS + 2))

#define MMU_MEMORY_TTBR_L2_INDEX_BITS	((19 - 12) + 1)
#define MMU_MEMORY_TTBR_L2_INDEX_MASK	((1 << MMU_MEMORY_TTBR_L2_INDEX_BITS) - 1)
#define MMU_MEMORY_TTBR_L2_SIZE		(1 << (MMU_MEMORY_TTBR_L2_INDEX_BITS + 2))

#define MAX_USR_VA		((MMU_MEMORY_TTBR0_L1_SIZE / 4) * \
				((MMU_MEMORY_TTBR_L2_SIZE / 4) * PAGE_SIZE))

#ifdef WITH_LIB_OTE
/* Decode of ARM PAR register */
#define PAR_ATTR_MASK			0xFFF
#define PAR_ATTR_NOS			(0x1 << 10)
#define PAR_ATTR_NON_SECURE		(0x1 << 9)
#define PAR_ATTR_SHAREABLE(par)		(((par) >> 7) & 0x1)
/* bits 6:4 are inner cacheable attrs */
#define PAR_ATTR_INNER(par)		(((par) >> 4) & 0x7)
#define PAR_ATTR_INNER_NON_CACHEABLE			0
#define PAR_ATTR_INNER_STRONGLY_ORDERED			1
#define PAR_ATTR_INNER_DEVICE				3
#define PAR_ATTR_INNER_WRITE_BACK_ALLOCATE		5
#define PAR_ATTR_INNER_WRITE_THROUGH_NO_ALLOCATE	6
#define PAR_ATTR_INNER_WRITE_BACK_NO_ALLOCATE		7
/* bits 3:2 are outer cacheable attrs */
#define PAR_ATTR_OUTER(par)		(((par) >> 2) & 0x3)
#define PAR_ATTR_OUTER_NON_CACHEABLE			0
#define PAR_ATTR_OUTER_WRITE_BACK_ALLOCATE		1
#define PAR_ATTR_OUTER_WRITE_THROUGH_NO_ALLOCATE	2
#define PAR_ATTR_OUTER_WRITE_BACK_NO_ALLOCATE		3
#define PAR_ATTR_SSECTION		(0x1 << 1)
#define PAR_ATTR_FAULTED		(0x1 << 0)

#define PAR_ADDR_MASK(par)	\
	(((par) & PAR_ATTR_SSECTION) ? 0x00FFFFFF : PAGE_MASK)

#define PAR_ALIGNED_PA(par)	\
	(((par) & PAR_ATTR_SSECTION) ? 	/* super-section */			\
		(((par) & 0xFF000000ULL) | (((par) & 0x00FF0000ULL) << 32)) : 	\
		((par) & ~PAGE_MASK))	/* section or large/small page */

/* virt -> phys address translation args */
typedef enum {
	ATS1CUR,
	ATS12NSOUR,
} v2p_t;

#endif /* WITH_LIB_OTE */

typedef enum {
	PGTBL_NONE = 0,
	PGTBL_LEVEL_1_USER,
	PGTBL_LEVEL_1_PRIV,
	PGTBL_LEVEL_2,
} pgtbl_lvl_t;

status_t arm_uthread_mmu_map(uthread_t *ut, paddr_t paddr,
		vaddr_t vaddr, uint l1_flags, uint l2_flags);
status_t arm_uthread_mmu_unmap(uthread_t *ut, vaddr_t vaddr);

#endif
