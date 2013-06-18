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

typedef enum {
	PGTBL_NONE = 0,
	PGTBL_LEVEL_1_USER,
	PGTBL_LEVEL_1_PRIV,
	PGTBL_LEVEL_2,
} pgtbl_lvl_t;

void arm_uthread_mmu_init(void);
status_t arm_uthread_mmu_map(uthread_t *ut, paddr_t paddr,
		vaddr_t vaddr, uint l1_flags, uint l2_flags);
status_t arm_uthread_mmu_unmap(uthread_t *ut, vaddr_t vaddr);

#endif
