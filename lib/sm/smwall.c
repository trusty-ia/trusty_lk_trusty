/*
 * Copyright (c) 2016, Google, Inc. All rights reserved
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
#include <assert.h>
#include <arch/spinlock.h>
#include <err.h>
#include <kernel/mutex.h>
#include <kernel/vm.h>
#include <list.h>
#include <lib/sm.h>
#include <lib/sm/sm_err.h>
#include <lib/sm/sm_wall.h>
#include <lk/init.h>
#include <malloc.h>
#include <pow2.h>
#include <stdlib.h>
#include <trace.h>

#define LOCAL_TRACE  0

#define ITEM_ALIGNMENT  8

static vaddr_t wall_va;
static size_t  wall_sz;
static bool    wall_registration_closed;

static uint32_t per_cpu_sz;
static uint32_t per_cpu_offset;
static uint32_t per_cpu_item_cnt;
static struct list_node per_cpu_items = LIST_INITIAL_VALUE(per_cpu_items);

static spin_lock_t wall_locks[SMP_MAX_CPUS] = {
    [0 ... SMP_MAX_CPUS-1] = SPIN_LOCK_INITIAL_VALUE,
};

static void lock_wall(void)
{
    for (int i = 0; i < SMP_MAX_CPUS; i++)
        spin_lock(&wall_locks[i]);
}

static void unlock_wall(void)
{
    for (int i = SMP_MAX_CPUS-1; i >= 0; i--)
        spin_unlock(&wall_locks[i]);
}

/*
 *  Called by sm module before returning to non-secure world
 */
void sm_wall_update(void)
{
    struct sm_wall_item *wi;
    uint cpu = arch_curr_cpu_num();

    ASSERT(wall_registration_closed);
    ASSERT(arch_ints_disabled());

    /* update per cpu items */
    spin_lock(&wall_locks[cpu]);
    if (wall_va) {
        list_for_every_entry(&per_cpu_items, wi, struct sm_wall_item, node) {
            if (wi->update_cb) {
                vaddr_t item_va = wall_va + per_cpu_offset +
                                  cpu * per_cpu_sz + wi->offset;
                wi->update_cb(wi, (void *)item_va);
            }
        }
    }
    spin_unlock(&wall_locks[cpu]);
}

/*
 * called by non-secure side to get required buffer size
 */
long smc_get_wall_size(smc32_args_t *args)
{
    ASSERT(wall_registration_closed);
    return wall_sz;
}

/*
 * Write The Wall Table of Content to provided buffer
 */
static void sm_wall_format(void *va)
{
    uint32_t offset = 0;
    struct sm_wall_item *wi;
    struct sm_wall_toc_item *item;
    struct sm_wall_toc *toc = (struct sm_wall_toc *)va;

    toc->version = SM_WALL_TOC_VER;
    toc->cpu_num = SMP_MAX_CPUS;

    /* per cpu items */
    toc->per_cpu_region_size = per_cpu_sz;
    toc->per_cpu_num_items = per_cpu_item_cnt;

    /* global items are not supported yet */
    toc->global_num_items = 0;

    /* setup per_cpu toc offset and itemst */
    offset = ALIGN(sizeof(struct sm_wall_toc), ITEM_ALIGNMENT);
    toc->per_cpu_toc_offset = offset;

    item = va + toc->per_cpu_toc_offset;
    list_for_every_entry(&per_cpu_items, wi, struct sm_wall_item, node) {
        item->id = wi->item_id;
        item->size = wi->size;
        item->offset = wi->offset;
        item->reserved  = 0;
        offset += sizeof(struct sm_wall_toc_item);
    }

    /* setup global toc offset and items */
    toc->global_toc_offset = offset;

    /* setup per_cpu data region base offset */
    offset = ALIGN(offset, ITEM_ALIGNMENT);
    toc->per_cpu_base_offset = per_cpu_offset = offset;

    /* TODO: implement global items if needed */
}

/*
 *  Called by non-secure side to setup shared buffer
 */
long smc_setup_wall_stdcall(smc32_args_t *args)
{
    status_t rc;
    void *ns_va;
    ns_addr_t ns_pa;
    ns_size_t ns_sz;
    uint  mmu_flags;

    ASSERT(wall_registration_closed);

    rc = smc32_decode_mem_buf_info(args, &ns_pa, &ns_sz, &mmu_flags);
    if (rc) {
        LTRACEF("smc32_decode_mem_buf_info returned %d\n", rc);
        if (rc == ERR_NOT_SUPPORTED)
            return SM_ERR_NOT_SUPPORTED;
        else
            return SM_ERR_INTERNAL_FAILURE;
    }

    /* check provided buffer size */
    if (ns_sz < wall_sz) {
        LTRACEF("buffer is too small (%zd bytes required)\n", wall_sz);
        return SM_ERR_INVALID_PARAMETERS;
    }

    if (ns_pa & (PAGE_SIZE-1)) {
        LTRACEF("unexpected alignment 0x%llx\n", ns_pa);
        return SM_ERR_INVALID_PARAMETERS;
    }

    if (!ns_pa) {
        LTRACEF("invalid descr addr 0x%llx\n", ns_pa);
        return SM_ERR_INVALID_PARAMETERS;
    }

    if (ns_pa != (paddr_t)ns_pa) {
        LTRACEF("unsuported addr range 0x%llx\n", ns_pa);
        return SM_ERR_INVALID_PARAMETERS;
    }

    /* check other attributes */
    if (mmu_flags & ARCH_MMU_FLAG_PERM_RO) {
        LTRACEF("read-write accessible buffer is expected\n");
        return SM_ERR_INVALID_PARAMETERS;
    }

#if !ARCH_X86_64
    if ((mmu_flags & ARCH_MMU_FLAG_CACHE_MASK) != ARCH_MMU_FLAG_CACHED) {
        LTRACEF("cached memory buffer is expected\n");
        return SM_ERR_INVALID_PARAMETERS;
    }
#endif

    /* map non-secure wall buffer */
    rc = vmm_alloc_physical(vmm_get_kernel_aspace(), "the wall",
                            ROUNDUP(ns_sz, PAGE_SIZE),
                            &ns_va, PAGE_SIZE_SHIFT,
                            (paddr_t)ns_pa, 0, mmu_flags);
    if (rc) {
        LTRACEF("vmm alloc failed (%d)\n", rc);
        return SM_ERR_INTERNAL_FAILURE;
    }

    LTRACEF("Mapped: pa=%lld sz=%u @ %p\n", ns_pa, ns_sz, ns_va);

    lock_wall();
    if (wall_va) {
        LTRACEF("Already initialized\n");
        unlock_wall();
        rc = vmm_free_region(vmm_get_kernel_aspace(), (vaddr_t)ns_va);
        ASSERT(rc == NO_ERROR);
        return SM_ERR_NOT_ALLOWED;
    }
    sm_wall_format(ns_va);
    wall_va = (vaddr_t)ns_va;
    unlock_wall();

    return 0;
}

/*
 *  Called by non-secure side to release shared buffer
 */
long smc_destroy_wall_stdcall(smc32_args_t *args)
{
    status_t rc;
    vaddr_t va = 0;

    ASSERT(wall_registration_closed);

    lock_wall();
    if (wall_va) {
        /* detach wall pointer */
        va = wall_va;
        wall_va = 0;
    }
    unlock_wall();

    if (va) {
        LTRACEF("Releasing the wall buffer: %p\n", (void*) va);
        rc = vmm_free_region(vmm_get_kernel_aspace(), va);
        ASSERT(rc == NO_ERROR);
    } else {
        LTRACEF("Sm_wall is not initialized\n");
        rc = SM_ERR_NOT_ALLOWED;
    }
    return rc;
}


/*
 * Called during trusty initialization to allocate speace in shared buffer.
 * All calls to this routine has to be complete before LK_INIT_LEVEL_APPS-2
 * init level.
 */
void sm_wall_register_per_cpu_item(struct sm_wall_item *wi)
{
    struct sm_wall_item *tmp;

    ASSERT(wi);
    ASSERT(!list_in_list(&wi->node));
    ASSERT(!wall_registration_closed);

    /* check for item_id duplicates and add to the list */
    lock_wall();
    list_for_every_entry(&per_cpu_items, tmp, struct sm_wall_item, node) {
        ASSERT(tmp->item_id == wi->item_id);
    }
    list_add_tail(&per_cpu_items, &wi->node);
    wi->offset = per_cpu_sz;
    per_cpu_sz = ALIGN(wi->offset + wi->size, ITEM_ALIGNMENT);
    per_cpu_item_cnt++;
    unlock_wall();
}

/*
 * Invoked at boot to close wall registration
 */
static void sm_wall_finish_init(uint lvl)
{
    ASSERT(!wall_registration_closed);

    /* close registration */
    wall_registration_closed = true;

    /* calculate total requred wall buffer size */
    wall_sz = sizeof(struct sm_wall_toc) +
              sizeof(struct sm_wall_toc_item) * per_cpu_item_cnt;
    wall_sz = ALIGN(wall_sz, ITEM_ALIGNMENT);
    wall_sz += SMP_MAX_CPUS * per_cpu_sz;
    wall_sz = ALIGN(wall_sz, PAGE_SIZE);
}

LK_INIT_HOOK_FLAGS(sm_wall_finish_init, sm_wall_finish_init,
        LK_INIT_LEVEL_APPS - 2, LK_INIT_FLAG_PRIMARY_CPU);

