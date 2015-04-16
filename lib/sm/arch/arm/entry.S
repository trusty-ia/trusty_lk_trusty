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

#include <asm.h>
#include <lib/sm/monitor.h>
#include <lib/sm/smcall.h>
#include <lib/sm/sm_err.h>

#include <kernel/vm.h>

.macro SAVE_CONTEXT
	push	{r4-r11, lr}
	mov	r4, sp

	cps	#MODE_IRQ
	mrs	r5, spsr
	stmfd	r4!, {r5, sp, lr}

	cps	#MODE_SVC
	mrs	r5, spsr
	stmfd	r4!, {r5, sp, lr}

	cps	#MODE_ABT
	mrs	r5, spsr
	stmfd	r4!, {r5, sp, lr}

	cps	#MODE_UND
	mrs	r5, spsr
	stmfd	r4!, {r5, sp, lr}

	cps	#MODE_SYS
	stmfd	r4!, {sp, lr}

#if WITH_LIB_SM_MONITOR
	cps	#MODE_MON
#else
	cps	#MODE_SVC
#endif
	mov	sp, r4
.endm

.macro RESTORE_CONTEXT
	mov	r4, sp

	cps	#MODE_SYS
	ldmfd	r4!, {sp, lr}

	cps	#MODE_UND
	ldmfd	r4!, {r5, sp, lr}
	msr	spsr, r5

	cps	#MODE_ABT
	ldmfd	r4!, {r5, sp, lr}
	msr	spsr, r5

	cps	#MODE_SVC
	ldmfd	r4!, {r5, sp, lr}
	msr	spsr, r5

	cps	#MODE_IRQ
	ldmfd	r4!, {r5, sp, lr}
	msr	spsr, r5

#if WITH_LIB_SM_MONITOR
	cps	#MODE_MON
#else
	cps	#MODE_SVC
#endif
	mov	sp, r4
	pop	{r4-r11, lr}
.endm

#if WITH_LIB_SM_MONITOR

.p2align 5
.globl monitor_vector_table
monitor_vector_table:
	nop				/* RESET	*/
	b	.			/* UNDEF	*/
	b	arm_smcall		/* SWI		*/
	b	.			/* IABORT	*/
	b	.			/* DABORT	*/
	nop				/* reserved	*/
	b	.			/* IRQ		*/
	b	mon_fiq_entry		/* FIQ		*/

#endif
/* Secure monitor call
 * r0    = SMC call number
 * r1-r3 = args
 * r0    = return value
 */
FUNCTION(arm_smcall)
#if WITH_LIB_SM_MONITOR
	srsdb	sp!, #MODE_MON	/* srsfd alias not recognized by current assembler */
#endif

	tst	r0, #(1 << 30)		/* Check calling convention */
	movne	r0, #SM_ERR_NOT_SUPPORTED
	bne	1f

	push	{r0-r3}
	tst	r0, #(1 << 31)		/* Check if fastcall */
	ldreq	r14, =sm_sched_secure	/* handle stdcall */

	ubfxne	r0, r0, #24, #6		/* r0 = entity */
	ldrne	r14, =sm_fastcall_table
	ldrne	r14, [r14, r0, lsl #2]

	mov	r0, sp			/* r0 = smc_args_t* args */
	blx	r14
	add	sp, #(4 * SMC_NUM_ARGS)
1:
#if WITH_LIB_SM_MONITOR
	rfefd	sp!
#else
	mov	r1, r0
	ldr	r0, =SMC_SC_NS_RETURN
	smc	#0
	b	arm_smcall
#endif

FUNCTION(sm_boot_ns_locked)
#if WITH_SMP
	push	{r0-r3}
	ldr	r0, =secondary_boot_lock
	blx	spin_unlock
	pop	{r0-r3}
#endif
	/* fall through */
FUNCTION(sm_boot_ns)
#if WITH_LIB_SM_MONITOR
	SWITCH_SCR_TO_NONSECURE ip
#endif
#if WITH_LIB_SM_MONITOR
	rfefd	sp!
#else
	cpsid	f
	mov	r1, r0
	ldr	r0, =SMC_SC_NS_RETURN
	smc	#0
	b	arm_smcall
#endif

#if WITH_LIB_SM_MONITOR

mon_fiq_from_secure:
	pop	{r0-r3}
	sub	lr, lr, #4
	srsdb	sp!, #MODE_MON	/* srsfd alias not recognized by current assembler */
	push	{r0-r4, ip}
	sub	sp, sp, #(SMC_NUM_ARGS * 4)
	mov	r0, #SM_ERR_INTERRUPTED
1:
	mov	r1, sp
	bl	go_nonsecure
	ldr	r0, [sp]	/* r0 = args->smc_nr */
	ldr	r1, =SMC_SC_RESTART_LAST
	cmp	r0, r1
	movne	r0, #SM_ERR_INTERLEAVED_SMC
	bne	1b
	add	sp, sp, #(SMC_NUM_ARGS * 4)
	pop	{r0-r4, ip}
	rfefd	sp!

mon_fiq_entry:
	push	{r0-r3}

	mrc	p15, 0, r0, c1, c1, 0	/* r0 = SCR */
	tst	r0, #0x1
	beq	mon_fiq_from_secure

	push	{ip, lr}
	ldr	ip, =sm_intc_fiq_enter
	blx	ip
	pop	{ip, lr}

	cmp	r0, #0
	subne	lr, lr, #4
	bne	mon_fiq_return

	mrc	p15, 0, r3, c1, c0, 0	/* r3 = Non-secure SCTLR */

	SWITCH_SCR_TO_SECURE r2

	mrs	r0, spsr
	mov	r1, lr

	mov	r2, #0x91 /* fiq mode with IRQ disabled */
	msr	spsr_cfsx, r2

	tst	r3, #(1 << 13) /* Non-secure SCTLR.V */
	ldrne	lr, =0xffff0000
	mrceq	p15, 0, lr, c12, c0, 0 /* lr = VBAR (if not using Hivecs) */
	add	lr, lr, #0x1c /* fiq vector offset */

	/* Set fiq mode lr and spsr */
	cps	#MODE_FIQ
	msr	spsr_cfsx, r0
	mov	lr, r1
	cps	#MODE_MON

	SWITCH_SCR_TO_NONSECURE r2

mon_fiq_return:
	pop	{r0-r3}
	movs	pc, lr

FUNCTION(smc_fiq_exit)
	/* If called from secure, return */
	mrc	p15, 0, r0, c1, c1, 0	/* r0 = SCR */
	tst	r0, #0x1
	bxeq	lr

	/* Remove stack frame created by arm_smcall since we will not return there */
	pop	{r0-r3}
	add	sp, sp, #8

	stmfd	sp!, {r1-r3, ip}

	SWITCH_SCR_TO_SECURE r3

	ldr	ip, =sm_intc_fiq_exit
	blx	ip

	/* Retrieve FIQ mode spsr, lr and restore r0 from FIQ mode r12 */
	cps	#MODE_FIQ

	mov	r0, r12 /* restore r0 used for smc number */
	mrs	r1, spsr
	mov	r2, lr

	cps	#MODE_MON

	mov	lr, r2
	msr	spsr_cfsx, r1

	SWITCH_SCR_TO_NONSECURE r3

	ldmfd	sp!, {r1-r3, ip}
	movs	pc, lr
#endif

FUNCTION(platform_reset)
#if WITH_LIB_SM_MONITOR
	cps	#MODE_MON
#endif
	adr	sp, platform_reset	/* sp = paddr */
	ldr	ip, =platform_reset	/* ip = vaddr */
	sub	ip, sp, ip		/* ip = phys_offset */
	ldr	sp, =mon_ns_stack_top	/* sp = ns_stack vaddr */
	add	sp, sp, ip		/* sp = ns_stack paddr */

#if WITH_LIB_SM_MONITOR
	cps	#MODE_SVC
	msr	spsr_cfsx, #MODE_SVC_IRQ_DISABLED
	srsdb	sp!, #MODE_MON	/* srsfd alias not recognized by current assembler */
	cps	#MODE_MON
#endif

	ldr	lr, =sm_boot_ns_locked
	SAVE_CONTEXT

	ldr	lr, =mon_ns_sp	/* lr = mon_ns_sp vaddr */
	add	lr, lr, ip	/* lr = mon_ns_sp paddr */
	sub	sp, sp, ip	/* sp = sp vaddr */
	str	sp, [lr]

	/* Switch to S thread in monitor, stack will be allocated later */
	ldr	sp, =0

#if WITH_LIB_SM_MONITOR
	/* Initialize NS mode CPU context registers */
	mrc	p15, 0, r4, c12, c0, 0	/* r4 = VBAR */
	mrc	p15, 0, r5, c2, c0, 0	/* r5 = TTBR0 */
	mrc	p15, 0, r6, c2, c0, 1	/* r6 = TTBR1 */
	mrc	p15, 0, r7, c3, c0, 0	/* r7 = DACR */
	mrc	p15, 0, r8, c1, c0, 0	/* r8 = SCTLR */

	SWITCH_SCR_TO_NONSECURE r9

	mcr	p15, 0, r4, c12, c0, 0	/* VBAR = r4 */
	mcr	p15, 0, r5, c2, c0, 0	/* TTBR0 = r5 */
	mcr	p15, 0, r6, c2, c0, 1	/* TTBR1 = r6 */
	mcr	p15, 0, r7, c3, c0, 0	/* DACR = r7 */
	mcr	p15, 0, r8, c1, c0, 0	/* SCTLR = r8 */

	SWITCH_SCR_TO_SECURE r9

#endif

	/* patch mmu_initial_mappings table */
	ldr	r5, =mmu_initial_mappings
	add	r5, r5, ip	/* r5 = _mmu_initial_mappings paddr */

.Lnext_entry:
	/* if size == 0, end of list */
	ldr	r4, [r5, #__MMU_INITIAL_MAPPING_SIZE_OFFSET]
	cmp	r4, #0
	beq	.Lall_done

	ldr	r4, [r5, #__MMU_INITIAL_MAPPING_FLAGS_OFFSET]
	tst	r4, #MMU_INITIAL_MAPPING_FLAG_DYNAMIC
	addeq	r5, #__MMU_INITIAL_MAPPING_SIZE
	beq	.Lnext_entry

	/* patching dynamic entry: r5 - points to entry to patch */
	/* r0 is memsize passed in by the bootloader */

	/* update size field of mmu_initial_mappings struct */
	str	r0, [r5, #__MMU_INITIAL_MAPPING_SIZE_OFFSET]

	/* calculate phys mem base */
	ldr	r4, =_start	/* r4 = _start vaddr */
	add     r4, r4, ip      /* r4 = _start paddr */

	/* update phys field of mmu_initial_mappings struct */
	str	r4, [r5, #__MMU_INITIAL_MAPPING_PHYS_OFFSET]

.Lall_done:

	cps	#MODE_SVC
	b	arm_reset

/* Context switch preserving r0-r1 */
FUNCTION(sm_context_switch)
	SAVE_CONTEXT
	str	sp, [r2]
	clrex
	mov	sp, r3
	RESTORE_CONTEXT
	bx	lr

/* long sm_sched_secure(smc32_args_t *args) */
FUNCTION(sm_sched_secure)
#if WITH_SMP
	push	{r0-r1, ip, lr}
	ldr	r0, =secondary_boot_lock
	blx	spin_trylock
	cmp	r0, #0
	pop	{r0-r1, ip, lr}
	movne	r0, #SM_ERR_BUSY
	bne	sm_sched_secure_busy
#endif
#if WITH_LIB_SM_MONITOR
	SWITCH_SCR_TO_SECURE r1
#endif
	/* Context switch to secure */
	ldr	r2, =mon_ns_sp
	ldr	r3, =mon_s_sp
	ldr	r3, [r3]
	push	{ip, lr}
	bl	sm_context_switch
	pop	{ip, lr}
#if WITH_LIB_SM_MONITOR
	SWITCH_SCR_TO_NONSECURE ip
#endif

#if WITH_SMP
	push	{r0, lr}
	ldr	r0, =secondary_boot_lock
	blx	spin_unlock
	pop	{r0, lr}
#endif

sm_sched_secure_busy:
	/* clear scratch registers for security */
	mov	r1, #0
	mov	r2, #0
	mov	r3, #0
	mov	ip, #0
	bx	lr

#if WITH_LIB_SM_MONITOR

FUNCTION(smc_go_nonsecure)

	/* If NS called this, go back */
	mrc	p15, 0, r1, c1, c1, 0	/* r1 = SCR */
	tst	r1, #0x1
	movne	r0, #SM_ERR_NOT_ALLOWED
	bxne	lr

	/* Save return value from args->params[0] */
	ldr	r1, [r0, #8]
	ldr	r0, [r0, #4]

go_nonsecure:

#else /* !WITH_LIB_SM_MONITOR */

FUNCTION(sm_sched_nonsecure)

#endif
	/* Save secure only state, in case we return on a different cpu */
#if WITH_LIB_UTHREAD
	mrc	p15, 0, r2, c13, c0, 1	/* r2 = CONTEXTIDR */
	mrrc	p15, 0, r3, ip, c2	/* r3,ip = TTBR0 */
	push	{r2, r3, ip, lr}
#endif
	mrc	p15, 0, r2, c14, c2, 1	/* r2 = CNTP_CTL */
	mrrc	p15, 2, r3, ip, c14	/* r3,ip = CNTP_CVAL */
	push	{r2, r3, ip, lr}

#if !ARM_ISA_ARMV7M
	/* save current thread */
	mrc	 p15, 0, r2, c13, c0, 4  /* r2 = TPIDRPRW */
	push	{r2}
#endif
	push	{r1}

	/* Context switch to nonsecure */
	ldr	r2, =mon_s_sp
	ldr	r3, =mon_ns_sp
	ldr	r3, [r3]
	bl	sm_context_switch

	pop	{r1}

	/* copy smc32_args_t */
	ldmia	r0!, {r2, r3}
	stmia	r1!, {r2, r3}
	ldmia	r0!, {r2, r3}
	stmia	r1!, {r2, r3}

#if !ARM_ISA_ARMV7M
	/* restore current thread */
	pop	{r1}
	mcr	p15, 0, r1, c13, c0, 4  /* TPIDRPRW = r1 */
#endif

	pop	{r1, r2, r3, lr}
	mcrr	p15, 2, r2, r3, c14	/* CNTP_CVAL = r2,r3 (saved CNTP_CVAL) */
	mcr	p15, 0, r1, c14, c2, 1	/* CNTP_CTL = r1 (saved CNTP_CTL) */

#if WITH_LIB_UTHREAD
	mrrc	p15, 1, r2, r3, c2	/* r2,r3 = TTBR1 (global page tables) */
	mcrr	p15, 0, r2, r3, c2	/* TTBR0 = r2,r3 (TTBR1) */
	pop	{r1, r2, r3, lr}
	isb
	mcr	p15, 0, r1, c13, c0, 1	/* CONTEXTIDR = r1 (saved CONTEXTIDR) */
	isb
	mcrr	p15, 0, r2, r3, c2	/* TTBR0 = r2,r3 (saved TTBR0) */
#endif

	bx	lr

#if WITH_LIB_SM_MONITOR

/* sm_sched_nonsecure(uint32_t retval, smc32_args_t *args) */
FUNCTION(sm_sched_nonsecure)
	mov	r2, r1
	mov	r1, r0
	ldr	r0, =SMC_FC_GO_NONSECURE
	smc	#0
	bx	lr

FUNCTION(sm_set_mon_stack)
	cps	#MODE_MON
	mov	sp, r0
	cps	MODE_SVC
	bx	lr

#endif

FUNCTION(smc_fastcall_secure_monitor)
	ldrh	r1, [r0]	/* r1 = function# */
	ldr	r2, =sm_nr_fastcall_functions
	ldr	r2, [r2]
	cmp	r1, r2
	ldrlo	r2, =sm_fastcall_function_table
	ldrlo	r2, [r2, r1, lsl#2]
	rsblos	r1, r2, #1	/* This will set the same flags as the cmp above */
	ldrhs	r2, =smc_undefined
	bx	r2
.data
.align 3

LOCAL_DATA(mon_ns_stack)
	.skip	4096
DATA(mon_ns_stack_top)
LOCAL_DATA(mon_ns_sp)
	.long	0
LOCAL_DATA(mon_s_sp)
	.long 0
