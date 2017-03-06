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

#define PAGE_MASK   (PAGE_SIZE - 1)

extern uint32_t __tss_start;
extern void x86_syscall();
static uint64_t syscall_stack;
volatile uint64_t *current_stack;

/******************************************************************************
  This is a part where all x86 specific user space initalization is done.
  1. Set up user TSS
  2. Set up system call.
  3. Call VM specific APIs if required
 *********************************************************************************/
static void set_tss_segment()
{
    /* Get system tss segment */
    tss_t *system_tss = get_system_selector(TSS_SELECTOR);
    syscall_stack = __tss_start;
    system_tss->rsp0 = syscall_stack;
}

static void setup_syscall()
{
    /* msr_id,low,hi */
    write_msr(SYSENTER_CS_MSR, CODE_64_SELECTOR); /* cs_addr */
    write_msr(SYSENTER_ESP_MSR, syscall_stack); /* esp_addr */
    write_msr(SYSENTER_EIP_MSR, (uint64_t)(x86_syscall)); /* eip_addr */
}

/*******************************************************************************/
void arch_uthread_init()
{
    syscall_stack = 0;
    current_stack = 0;
    set_tss_segment();
    setup_syscall();
}

void arch_uthread_startup(void)
{
    /**** This is x86 ring jump ****/
    struct uthread *ut = (struct uthread *) tls_get(TLS_ENTRY_UTHREAD);

    uint64_t paddr = 0, flags = 0;
    register uint64_t sp_usr  = ROUNDDOWN(ut->start_stack, 8);
    register uint64_t entry = ut->entry;
    register uint64_t code_seg = USER_CODE_64_SELECTOR | USER_DPL;
    register uint64_t data_seg = USER_DATA_64_SELECTOR | USER_DPL;
    register uint64_t usr_flags = USER_EFLAGS;

    arch_mmu_query(sp_usr, &paddr, &flags);
    if(paddr)
        *(uint32_t *)paddr = 0x0;
    __asm__ __volatile__ (
            "pushq %0   \n\t"
            "pushq %1   \n\t"
            "pushq %2   \n\t"
            "pushq %3   \n\t"
            "pushq %4   \n\t"
            "pushq %0   \n\t"
            "popq %%rax \n\t"
            "movw %%ax, %%ds    \n\t"
            "movw %%ax, %%es    \n\t"
            "movw %%ax, %%fs    \n\t"
            "movw %%ax, %%gs    \n\t"
            "iretq"
            :
            :"r"(data_seg),"r"(sp_usr),"r"(usr_flags),"r"(code_seg),"r"(entry)
            );
}

void arch_uthread_context_switch(struct uthread *old_ut, struct uthread *new_ut)
{
    /*
     * In the given scheme, eip and esp changes happen on external/lk.
     * User space specific changes happen here. Which includes tss and gs
     */
    if (old_ut) {
    }
    if (new_ut) {
        /* userspace thread */
        tss_t *system_tss = get_system_selector(TSS_SELECTOR);
        current_stack = new_ut->arch.kstack;
        system_tss->rsp0 = current_stack;
        /* setting gs for system call stack */
        x86_set_cr3(new_ut->page_table);
    }
    else {
        tss_t *system_tss = get_system_selector(TSS_SELECTOR);
        current_stack = syscall_stack;
        system_tss->rsp0 = current_stack;
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
     */
    vaddr_t stack_top = (vaddr_t)ut->thread->stack + ut->thread->stack_size;
    /* make sure the top of the stack is 8 byte aligned for EABI compliance */
    stack_top = ROUNDDOWN(stack_top, 8);
    ut->arch.kstack = stack_top;
    return err;
}

void arch_uthread_free(struct uthread *ut)
{
}

status_t arch_uthread_map(struct uthread *ut, struct uthread_map *mp)
{
    addr_t vaddr, paddr;
    u_int pg, l1_flags, l2_flags;
    status_t err = NO_ERROR;
    static addr_t app_page_table =0;

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

        /* MMIO memory mapping requests should not be cached */
        if (mp->flags & UTM_IO) {
            l1_flags |= ARCH_MMU_FLAG_UNCACHED;
        }

        if (paddr & PAGE_MASK) {
            err = ERR_INVALID_ARGS;
            goto err_undo_maps;
        }

        vaddr = mp->vaddr + (pg * PAGE_SIZE);
        err = x86_uthread_mmu_map(ut, paddr, vaddr, l1_flags);
        if (err)
            goto err_undo_maps;
    }
    if(!app_page_table){
        app_page_table = ut->page_table;
    }
    return NO_ERROR;
err_undo_maps:
    for (u_int p = 0; p < pg; p++) {
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

/*****************************************************************************/
/* TODO: Need to implement asm optimized implementation.*/

extern void *memcpy(void *dest, const void *src, size_t count);
static inline void x86_mmap_lock(uthread_t *ut)
{
    DEBUG_ASSERT(ut);
    mutex_acquire(&ut->mmap_lock);
}

static inline void x86_mmap_unlock(uthread_t *ut)
{
    DEBUG_ASSERT(ut);
    mutex_release(&ut->mmap_lock);
}
static uthread_map_t *arch_uthread_map_find(uthread_t *ut, vaddr_t vaddr, size_t size)
{
    uthread_map_t *mp = NULL;
    if (vaddr + size < vaddr)
        return NULL;

    /* TODO: Fuzzy comparisions for now */
    list_for_every_entry(&ut->map_list, mp, uthread_map_t, node) {
        if ((mp->vaddr <= vaddr) &&
                (vaddr < mp->vaddr + mp->size) &&
                ((mp->vaddr + mp->size) >= (vaddr + size))) {
            return mp;
        }
    }
    return NULL;
}

bool arch_uthread_is_valid_range(uthread_t *ut, vaddr_t vaddr, size_t size)
{
    bool ret;
    x86_mmap_lock(ut);
    ret = arch_uthread_map_find(ut, vaddr, size) != NULL ? true : false;
    x86_mmap_unlock(ut);
    return ret;
}

status_t arch_copy_from_user(void *kdest, user_addr_t usrc, size_t len)
{
    if (len == 0)
        return NO_ERROR;

    if (kdest == NULL || usrc == NULL)
        return ERR_FAULT;

    /* TODO: be smarter about handling invalid addresses... */
    if (!arch_uthread_is_valid_range(uthread_get_current(), (vaddr_t)usrc, len))
        return ERR_FAULT;
    memcpy(kdest, (void *)usrc, len);
    return NO_ERROR;

}

status_t arch_copy_to_user(user_addr_t udest, const void *ksrc, size_t len)
{
    if (len == 0)
        return NO_ERROR;

    if (ksrc == NULL || udest == NULL)
        return ERR_FAULT;

    /* TODO: be smarter about handling invalid addresses... */
    if (!arch_uthread_is_valid_range(uthread_get_current(), (vaddr_t)udest, len))
        return ERR_FAULT;
    memcpy((void *)udest, ksrc, len);
    return NO_ERROR;
}

ssize_t arch_strlcpy_from_user(char *kdst, user_addr_t usrc, size_t len)
{
    uthread_map_t *mp;
    uthread_t *ut = uthread_get_current();
    x86_mmap_lock(ut);
    mp = arch_uthread_map_find (ut, usrc, 0);
    x86_mmap_unlock(ut);
    if (!mp) {
        return (ssize_t) ERR_FAULT;
    }
    /* TOOO: check mapping attributes */
    size_t usrc_len = mp->size - (usrc - mp->vaddr);
    char  *ksrc = (char*) usrc;
    while (len--) {
        if (usrc_len-- == 0) {
            /* end of segment reached */
            return (ssize_t) ERR_FAULT;
        }
        if (*ksrc == '\0') {
            *kdst = '\0';
            break;
        }
        *kdst++ = *ksrc++;
    }
    return (ssize_t) (ksrc - (char *)usrc);
}
