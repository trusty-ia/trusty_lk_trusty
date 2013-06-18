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

#include <asm.h>
#include <arch/uthread_asm.h>

/* arm_usr_switch(sp_usr, lr_usr, pc_usr) */
FUNCTION(arm_uthread_usr_switch)
	stmdb	sp, {r0, r1}
	ldmdb	sp, {r13, r14}^
	msr	spsr_fxsc, #MODE_USR
	movs	pc, r2

FUNCTION(arm_uthread_write_ttbr0)
	mcr	p15, 0, r0, c2, c0, 0
	isb
	bx	lr

FUNCTION(arm_uthread_write_context_idr)
	mcr	p15, 0, r0, c13, c0, 1
	isb
	bx	lr

/* void arm_write_ttbr1(uint32_t val) */
FUNCTION(arm_uthread_write_ttbr1)
	mcr 	p15, 0, r0, c2, c0, 1
	bx	lr

/* void arm_write_ttbcr(uint32_t val) */
FUNCTION(arm_uthread_write_ttbcr)
	mcr 	p15, 0, r0, c2, c0, 2
	bx	lr

FUNCTION(arm_uthread_read_ttbr0)
	mrc	p15, 0, r0, c2, c0, 0
	bx	lr

/* void arm_uthread_invalidate_tlb_vaddr(vaddr, asid) */
FUNCTION(arm_uthread_invalidate_tlb_vaddr)
	lsr	r0, r0, #12
	lsl	r0, r0, #12		@ page align addr
	and	r1, r1, #0xFF		@ asid is 8bits
	orr	r0, r0, r1
	dsb				@ sync pgtbl writes
	mcr	p15, 0, r0, c8, c7, 1
	bx	lr

#ifdef ARM_WITH_NEON

/* void arm_uthread_write_fpexc(uint32_t val) */
FUNCTION(arm_uthread_write_fpexc)
	mcr	p10, 7, r2, c8, c0, 0
	bx	lr
#endif
