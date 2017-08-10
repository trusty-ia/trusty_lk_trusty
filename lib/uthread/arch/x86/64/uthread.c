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

extern uint64_t __tss_start;
extern uint64_t __tss_end;
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
    syscall_stack = &__tss_end;
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

#ifdef ASLR_OF_TA
static bool elf64_update_rela_section(uint16_t e_type, uint64_t relocation_offset,
    Elf64_Dyn *dyn_section, uint64_t dyn_section_sz)
{
    Elf64_Rela *rela = NULL;
    uint64_t rela_sz = 0;
    uint64_t rela_entsz = 0;
    Elf64_Sym *symtab = NULL;
    uint64_t symtab_entsz = 0;
    uint64_t i;
    uint64_t d_tag = 0;

    if (!dyn_section){
        dprintf(0, "failed to read dynamic section from file\n");
        return false;
    }

    /* locate rela address, size, entry size */
    for (i = 0; i < dyn_section_sz / sizeof(Elf64_Dyn); ++i) {
        d_tag = dyn_section[i].d_tag;

        if (DT_RELA == d_tag) {
            rela = (Elf64_Rela *)(uint64_t)(dyn_section[i].d_un.d_ptr +
                    relocation_offset);
        } else if ((DT_RELASZ == d_tag) || (DT_RELSZ == d_tag)) {
            rela_sz = dyn_section[i].d_un.d_val;
        } else if (DT_RELAENT == d_tag) {
            rela_entsz = dyn_section[i].d_un.d_val;
        } else if (DT_SYMTAB == d_tag) {
            symtab = (Elf64_Sym *)(uint64_t)(dyn_section[i].d_un.d_ptr +
                    relocation_offset);
        } else if(DT_SYMENT == d_tag) {
            symtab_entsz = dyn_section[i].d_un.d_val;
        } else {
            continue;
        }
    }

    if (NULL == rela
        || 0 == rela_sz
        || NULL == symtab
        || sizeof(Elf64_Rela) != rela_entsz
        || sizeof(Elf64_Sym) != symtab_entsz) {

        if (ET_DYN == e_type ) {
            dprintf(SPEW, "for DYN type relocation section is optional\n");
            return true;
        } else {
            dprintf(SPEW, "for EXEC type missed mandatory dynamic information\n");
            return false;
        }
    }

    __asm__ volatile("stac");

    for (i = 0; i < rela_sz / rela_entsz; ++i) {
        uint64_t *target_addr =
            (uint64_t *)(uint64_t)(rela[i].r_offset + relocation_offset);
        uint32_t symtab_idx;

        switch (rela[i].r_info & 0xFF) {
        /* Formula for R_x86_64_32 and R_X86_64_64 are same: S + A  */
        case R_X86_64_32:
        case R_X86_64_64:
            *target_addr = rela[i].r_addend + relocation_offset;
            symtab_idx = (uint32_t)(rela[i].r_info >> 32);
            *target_addr += symtab[symtab_idx].st_value;
            break;
        case R_X86_64_RELATIVE:
            *target_addr = rela[i].r_addend + relocation_offset;
            break;
        case 0:        /* do nothing */
            break;
        default:
            dprintf(0, "Unsupported Relocation %#llx\n", rela[i].r_info & 0xFF);
            __asm__ volatile("clac");
            return false;
        }
    }

    __asm__ volatile("clac");

    return true;
}
#endif

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

    vmm_aspace_t *aspace = vaddr_to_aspace(sp_usr);
    if (!aspace)
        return;

#ifdef ASLR_OF_TA
    if (NULL != ut->dyn_section)
        elf64_update_rela_section(ET_DYN, ut->aslr_offset, ut->dyn_section, ut->dyn_size);
#endif

    arch_mmu_query(&aspace->arch_aspace, sp_usr, &paddr, &flags);
    if(paddr)
        *(uint32_t *)sp_usr = 0x0;

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
    if (new_ut) {
        /* userspace thread */
        tss_t *system_tss = get_system_selector(TSS_SELECTOR);
        current_stack = new_ut->arch.kstack;
        system_tss->rsp0 = current_stack;
        /* setting gs for system call stack */
        x86_set_cr3(vaddr_to_paddr(new_ut->page_table));
    } else {
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
    u_int pg, flags;
    status_t err = NO_ERROR;

    if (mp->size > MAX_USR_VA || mp->vaddr > (MAX_USR_VA - mp->size)) {
        err = ERR_INVALID_ARGS;
        goto done;
    }

    ASSERT(!(mp->size & PAGE_MASK));
    /*we need to convert UTM flags to generic mmu falgs
     *default memory type is WB cache.
     */
    flags = ARCH_MMU_FLAG_PERM_USER;
    if ( (mp->flags & UTM_R) && !(mp->flags & UTM_W))
        flags |= ARCH_MMU_FLAG_PERM_RO;

    if (!(mp->flags & UTM_X))
        flags |= ARCH_MMU_FLAG_PERM_NO_EXECUTE;

    for (pg = 0; pg < (mp->size / PAGE_SIZE); pg++) {
        if (mp->flags & UTM_PHYS_CONTIG)
            paddr = mp->pfn_list[0] + (pg * PAGE_SIZE);
        else
            paddr = mp->pfn_list[pg];

        /* MMIO memory mapping requests should not be cached */
        if (mp->flags & UTM_IO) {
            flags |= ARCH_MMU_FLAG_UNCACHED;
        }

        if (paddr & PAGE_MASK) {
            err = ERR_INVALID_ARGS;
            goto err_undo_maps;
        }

        vaddr = mp->vaddr + (pg * PAGE_SIZE);
        err = x86_uthread_mmu_map(ut, paddr, vaddr, flags);
        if (err)
            goto err_undo_maps;
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

    __asm__ volatile("stac");
    memcpy(kdest, (void *)usrc, len);
    __asm__ volatile("clac");

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

    __asm__ volatile("stac");
    memcpy((void *)udest, ksrc, len);
    __asm__ volatile("clac");

    return NO_ERROR;
}

ssize_t arch_strlcpy_from_user(char *kdst, user_addr_t usrc, size_t len)
{
    size_t usrc_len;
    char  *ksrc;
    uthread_map_t *mp;
    uthread_t *ut = uthread_get_current();


    x86_mmap_lock(ut);
    mp = arch_uthread_map_find (ut, usrc, 0);
    x86_mmap_unlock(ut);
    if (!mp) {
        return (ssize_t) ERR_FAULT;
    }

    /* TOOO: check mapping attributes */
    usrc_len = mp->size - (usrc - mp->vaddr);
    ksrc = (char*) usrc;

    __asm__ volatile("stac");
    while (len--) {
        if (usrc_len-- == 0) {
            /* end of segment reached */
            __asm__ volatile("clac");
            return (ssize_t) ERR_FAULT;
        }
        if (*ksrc == '\0') {
            *kdst = '\0';
            break;
        }
        *kdst++ = *ksrc++;
    }

    __asm__ volatile("clac");

    return (ssize_t) (ksrc - (char *)usrc);
}
