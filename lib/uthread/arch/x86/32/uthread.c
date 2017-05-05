/*
 * Copyright (c) 2015 Intel Corporation
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
#include <arch/x86.h>
#include <arch/x86/descriptor.h>
#include <arch/x86/mmu.h>
#include <arch/uthread_mmu.h>
#include <uthread.h>

#define PAGE_MASK	(PAGE_SIZE - 1)

extern uint32_t __tss_start;
extern void x86_syscall();
static uint32_t syscall_stack;
uint32_t _current_stack;

/*********************************************************************************
   This is a part where all x86 specific user space initalization sequence is done.
   1. Set up user TSS
   2. Set up system call.
   3. Call VM specific APIs if required
 *********************************************************************************/

inline void set_tss_segment()
{
	/* Get system tss segment */
	tss_t *system_tss = get_system_selector(TSS_SELECTOR);
	syscall_stack = __tss_start;
	system_tss->esp0 = syscall_stack;
	system_tss->ss0 = DATA_SELECTOR;
}

inline void setup_syscall()
{
	/* msr_id,low,hi */
	write_msr_ver(SYSENTER_CS_MSR,KERNEL_CODE_SELECTOR,0);//cs_addr
	write_msr_ver(SYSENTER_ESP_MSR,syscall_stack,0);//esp_addr
	write_msr_ver(SYSENTER_EIP_MSR,(uint32_t)(x86_syscall),0);//eip_addr

}

/*
 * Called in the context of init hook. Called from uthread_init().
 * Common for lk-trusty.
 */
void arch_uthread_init()
{
	syscall_stack = 0;
	_current_stack = 0;
	//Add x86 uthread init
	set_tss_segment();
	//Add MSR set routine for syscalls
	setup_syscall();
}

void arch_uthread_startup(void)
{
	/**** This is x86 ring jump ****/
	struct uthread *ut = (struct uthread *) tls_get(TLS_ENTRY_UTHREAD);
	/* User space is passed params using user stack(*args).
         On x86, params on stack. So, 4 bytes of user stack should be
         zeroed out. Not able to write to user stack. And stack
          mapping is done in arch independent code.So, keeping 8 byte hole*/
	uint32_t STACK_BOUNDRY = 0x08;
	register uint32_t sp_usr =  ut->start_stack - STACK_BOUNDRY;
	register uint32_t entry = ut->entry;
	register uint32_t codeSeg = USER_CODE_SELECTOR | USER_DPL;
	register uint32_t dataSeg = USER_DATA_SELECTOR | USER_DPL;
	register uint32_t usrFlags = USER_EFLAGS;

	__asm__ __volatile__ (
		"mov %1,%%ebp	\n\t"
		"push %0	\n\t"
		"push %1	\n\t"
		"push %2	\n\t"
		"push %3	\n\t"
		"push %4	\n\t"
		"iret"
		:
		:"r"(dataSeg),"r"(sp_usr),"r"(usrFlags),"r"(codeSeg),"r"(entry)
	);
}

void arch_uthread_context_switch(struct uthread *old_ut, struct uthread *new_ut)
{
	/*
         * In the given scheme, eip and esp changes happen on external/lk.
         * User space specific changes happen here. Which includes tss
         * and gs
         */
	if(old_ut){
	}
	if (new_ut){
                /* userspace thread */
		tss_t *system_tss = get_system_selector(TSS_SELECTOR);
		_current_stack = new_ut->arch.kstack;
		system_tss->esp0 = _current_stack;
		/* setting gs for system call stacki */
		x86_set_cr3(new_ut->page_table);
	}
	else{
		tss_t *system_tss = get_system_selector(TSS_SELECTOR);
		_current_stack = syscall_stack;
		system_tss->esp0 = _current_stack;
                /* kernel tasks */
		x86_set_cr3(x86_get_kernel_table());
	}
}

status_t arch_uthread_create(struct uthread *ut)
{
	status_t err = NO_ERROR;

	ut->arch.asid = ut->id;
	ut->arch.uthread = ut;

        /*
         * To move all user specific code to uthread.
         * Only kernel task don't need tss switch.
         * To avoid continuous dereference, copied pointer here.
         * Instead of creating new stack, use stack created in LK kernel.
         * vaddr_t stack_top = (vaddr_t)ut->thread->stack + ut->thread->stack_size;
         * make sure the top of the stack is 8 byte aligned for EABI compliance
         */
	stack_top = ROUNDDOWN(stack_top, 8);
	ut->arch.kstack = stack_top;
	return err;
}

void arch_uthread_free(struct uthread *ut)
{
        /*Need to free stuff if anything is allocated somewhere.*/
}

status_t arch_uthread_map(struct uthread *ut, struct uthread_map *mp)
{
	addr_t vaddr, paddr;
	u_int pg, l1_flags, l2_flags;
	status_t err = NO_ERROR;

	if (mp->size > MAX_USR_VA || mp->vaddr > (MAX_USR_VA - mp->size)) {
		err = ERR_INVALID_ARGS;
		goto done;
	}

	ASSERT(!(mp->size & PAGE_MASK));
	l1_flags = mp->flags | ARCH_MMU_FLAG_PERM_USER;

	for (pg = 0; pg < (mp->size / PAGE_SIZE); pg++) {
		if (mp->flags & UTM_PHYS_CONTIG)
			paddr = mp->pfn_list[0] + (pg * PAGE_SIZE);
		else
			paddr = mp->pfn_list[pg];

		if (paddr & PAGE_MASK) {
			err = ERR_INVALID_ARGS;
			goto err_undo_maps;
		}

		vaddr = mp->vaddr + (pg * PAGE_SIZE);
		err = x86_uthread_mmu_map(ut, paddr, vaddr,l1_flags);
		if (err)
			goto err_undo_maps;
	}

	return NO_ERROR;
err_undo_maps:
	for(u_int p = 0; p < pg; p++) {
		x86_uthread_mmu_unmap(ut,
			mp->vaddr + (p * PAGE_SIZE));
	}
done:
	return err;

}

status_t arch_uthread_unmap(struct uthread *ut, struct uthread_map *mp)
{
	addr_t vaddr;
	u_int pg;
	status_t err = NO_ERROR;

	for (pg = 0; pg < (mp->size / PAGE_SIZE); pg++) {
		vaddr = mp->vaddr + (pg * PAGE_SIZE);
		err = x86_uthread_mmu_unmap(ut, vaddr);

		if (err)
			goto done;
	}

done:
	return err;
}

