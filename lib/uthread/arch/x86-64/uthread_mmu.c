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

#include <err.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arch.h>
#include <arch/x86.h>
#include <arch/x86/mmu.h>
#include <arch/uthread_mmu.h>
#include <lk/init.h>
#include <uthread.h>

static void x86_uthread_mmu_init(uint level)
{
}

uint64_t x86_get_kernel_table()
{
    uint64_t cr3 = get_kernel_cr3();
    cr3 = cr3?cr3:x86_get_cr3();
    return cr3;
}

LK_INIT_HOOK_FLAGS(libuthreadx86mmu, x86_uthread_mmu_init,
        LK_INIT_LEVEL_ARCH_EARLY, LK_INIT_FLAG_ALL_CPUS);

static uint64_t *x86_uthread_mmu_alloc_pgtbl()
{
    return((u_int *)x86_create_new_cr3());
}

status_t x86_uthread_mmu_map(uthread_t *ut, paddr_t paddr,
        vaddr_t vaddr, uint flags)
{
    uint64_t *page_table;
    status_t err = NO_ERROR;

    if (ut->page_table == NULL) {
        ut->page_table = x86_uthread_mmu_alloc_pgtbl();
        if (ut->page_table == NULL) {
            dprintf(CRITICAL,
                    "unable to allocate initial page table\n");
            return(ERR_NO_MEMORY);
        }
    }

    page_table = (uint64_t *)(ut->page_table);
    ASSERT(page_table);
    err = x86_mmu_add_mapping(page_table, paddr, vaddr, flags);
    return err;
}

status_t x86_uthread_mmu_unmap(uthread_t *ut, vaddr_t vaddr)
{
    return (x86_mmu_unmap(ut->page_table, vaddr, 1));
}
