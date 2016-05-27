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

#include <debug.h>
#include <uthread.h>
#include <stdlib.h>
#include <string.h>
#include <compiler.h>
#include <assert.h>
#include <lk/init.h>
#include <trace.h>

#include <kernel/mutex.h>

#if UTHREAD_WITH_MEMORY_MAPPING_SUPPORT
#include <lib/sm.h>

#ifndef USER_PAGE_SIZE
#define USER_PAGE_SIZE PAGE_SIZE
#endif
#endif

#define LOCAL_TRACE 0

static int uthread_startup(void *arg)
{
	struct uthread *ut = (struct uthread *) tls_get(TLS_ENTRY_UTHREAD);

	vmm_set_active_aspace(ut->aspace);

	arch_enter_uspace(ut->entry, ROUNDDOWN(ut->start_stack, 8),
	                  ARCH_ENTER_USPACE_FLAG_32BIT, 0);
	__UNREACHABLE;
}

uthread_t *uthread_create(const char *name, vaddr_t entry, int priority,
		vaddr_t start_stack, size_t stack_size, void *private_data)
{
	uthread_t *ut = NULL;
	status_t err;
	vaddr_t stack_bot;

	ut = (uthread_t *)calloc(1, sizeof(uthread_t));
	if (!ut)
		goto err_done;

	err = vmm_create_aspace(&ut->aspace, name, 0);
	if (err) {
		TRACEF("vmm_create_aspace failed: %d\n", err);
		goto err_create_aspace;
	}

	ut->private_data = private_data;
	ut->entry = entry;

	stack_bot = start_stack - stack_size;

	/* Allocate and map in a stack region */
	err = vmm_alloc(ut->aspace, "stack", stack_size, (void**)&stack_bot,
			PAGE_SIZE_SHIFT, VMM_FLAG_VALLOC_SPECIFIC,
			ARCH_MMU_FLAG_PERM_USER | ARCH_MMU_FLAG_PERM_NO_EXECUTE);
	if (err) {
		TRACEF("failed to allocate stack: %d\n", err);
		goto err_stack_alloc;
	}
	assert(stack_bot == start_stack - stack_size);

	ut->start_stack = start_stack;

	ut->thread = thread_create(name,
			uthread_startup,
			NULL,
			priority,
			DEFAULT_STACK_SIZE);
	if (!ut->thread)
		goto err_thread_create;

	/* store user thread struct into TLS slot 0 */
	ut->thread->tls[TLS_ENTRY_UTHREAD] = (uintptr_t) ut;

	return ut;

err_thread_create:
err_free_ut:
err_stack_alloc:
	vmm_free_aspace(ut->aspace);
err_create_aspace:
	free(ut);

err_done:
	return NULL;
}

status_t uthread_start(uthread_t *ut)
{
	if (!ut || !ut->thread)
		return ERR_INVALID_ARGS;

	return thread_resume(ut->thread);
}

void __NO_RETURN uthread_exit(int retcode)
{
	uthread_t *ut;

	ut = uthread_get_current();
	if (ut) {
		vmm_free_aspace(ut->aspace);
		free(ut);
	} else {
		TRACEF("WARNING: unexpected call on kernel thread %s!",
				get_current_thread()->name);
	}

	thread_exit(retcode);
}

void uthread_context_switch(thread_t *oldthread, thread_t *newthread)
{
}

bool uthread_is_valid_range(uthread_t *ut, vaddr_t vaddr, size_t size)
{
	ASSERT(uthread_get_current() == ut);

	size = ROUNDUP(size + (vaddr & (PAGE_SIZE - 1)), PAGE_SIZE);
	vaddr = ROUNDDOWN(vaddr, PAGE_SIZE);

	while (size) {
		if (!is_user_address(vaddr) || !vaddr_to_paddr((void*)vaddr)) {
			return false;
		}
		vaddr += PAGE_SIZE;
		size -= PAGE_SIZE;
	}
	return true;
}

#if UTHREAD_WITH_MEMORY_MAPPING_SUPPORT

static status_t uthread_translate_ns_pte(paddr_t *pfn_list, uint32_t npages,
                                         uint *arch_mmu_flags,
                                         uint64_t *ns_pte_list)
{
	u_int pg;
	status_t err = ERR_NOT_VALID;
	uint first_arch_mmu_flags = ~0;

	for (pg = 0; pg < npages; pg++) {
		ns_addr_t paddr;
		uint page_arch_mmu_flags;
		struct ns_page_info ns_page_info = { .attr = ns_pte_list[pg] };

		err = sm_decode_ns_memory_attr(&ns_page_info, &paddr,
		                               &page_arch_mmu_flags);
		if (err) {
			TRACEF("sm_decode_ns_memory_attr 0x%llx failed: %d\n",
			       ns_page_info.attr, err);
			return err;
		}
		LTRACEF("ns_pte_list[%d] 0x%llx -> paddr 0x%llx, attr 0x%x\n",
		        pg, ns_page_info.attr, paddr, page_arch_mmu_flags);
		if (pg == 0) {
			first_arch_mmu_flags = page_arch_mmu_flags;
		} else if (first_arch_mmu_flags != page_arch_mmu_flags) {
			TRACEF("arch_mmu_flags for 0x%llx, 0x%x does not match first page, 0x%x\n",
			       ns_page_info.attr, page_arch_mmu_flags, first_arch_mmu_flags);
			return ERR_INVALID_ARGS;
		}
		pfn_list[pg] = paddr;
	}
	*arch_mmu_flags = first_arch_mmu_flags;
	return 0;
}

static status_t uthread_get_page_list(paddr_t *pages, uint npages,
                                      uint *arch_mmu_flags_p,
                                      vmm_aspace_t *aspace, vaddr_t src)
{
	status_t err;
	uint i;
	uint arch_mmu_flags;
	uint arch_mmu_flags_prev;

	for (i = 0; i < npages; i++, src += USER_PAGE_SIZE) {
		err = arch_mmu_query(&aspace->arch_aspace, src,
		                     &pages[i], &arch_mmu_flags);
		if (err) {
			TRACEF("arch_mmu_query failed for 0x%lx\n", src);
			return err;
		}
		if (i && arch_mmu_flags != arch_mmu_flags_prev) {
			TRACEF("arch_mmu_flags for 0x%lx, 0x%x does not match prev page, 0x%x\n",
			       src, arch_mmu_flags, arch_mmu_flags_prev);
			return ERR_INVALID_ARGS;
		}
		arch_mmu_flags_prev = arch_mmu_flags;
	}
	*arch_mmu_flags_p = arch_mmu_flags;
	return 0;
}

status_t uthread_grant_pages(uthread_t *ut_target, ext_vaddr_t vaddr_src,
		size_t size, u_int flags, vaddr_t *vaddr_target, bool ns_src,
		uint64_t *ns_page_list)
{
	u_int npages;
	paddr_t *pfn_list;
	status_t err;
	u_int offset;
	uint arch_mmu_flags;
	uint arch_mmu_flags_src;

	if (size == 0) {
		*vaddr_target = 0;
		return 0;
	}

	offset = vaddr_src & (PAGE_SIZE -1);
	vaddr_src = ROUNDDOWN(vaddr_src, PAGE_SIZE);
	size = ROUNDUP((size + offset), PAGE_SIZE);
	npages = size / PAGE_SIZE;

	pfn_list = malloc(npages * sizeof(paddr_t));
	if (!pfn_list) {
		return ERR_NO_MEMORY;
	}

	arch_mmu_flags = ARCH_MMU_FLAG_PERM_USER | ARCH_MMU_FLAG_PERM_NO_EXECUTE;
	if (!(flags & UTM_W)) {
		arch_mmu_flags |= ARCH_MMU_FLAG_PERM_RO;
	}

	uthread_t *ut_src = ns_src ? NULL : uthread_get_current();

	if (ns_src) {
		if (!ns_page_list) {
			err = ERR_INVALID_ARGS;
			goto err_out;
		}

		err = uthread_translate_ns_pte(pfn_list, npages,
		                               &arch_mmu_flags_src,
		                               ns_page_list);
		if (err) {
			goto err_out;
		}
		assert(arch_mmu_flags_src & ARCH_MMU_FLAG_NS);
	} else {
		/* ns_page_list should only be passes for NS src -> secure target
		 * mappings
		 */
		ASSERT(!ns_page_list);

		/* Only a vaddr_t sized vaddr_src is supported
		 * for secure src -> secure target mappings.
		 */
		ASSERT(vaddr_src == (vaddr_t)vaddr_src);

		err = uthread_get_page_list(pfn_list, npages, &arch_mmu_flags_src,
		                            ut_src->aspace, vaddr_src);
		if (err) {
			goto err_out;
		}
	}
	if ((arch_mmu_flags_src & ARCH_MMU_FLAG_PERM_RO) &&
	    !(arch_mmu_flags & ARCH_MMU_FLAG_PERM_RO)) {
		TRACEF("Making a writable mapping to read-only page\n");
		err = ERR_INVALID_ARGS;
		goto err_out;
	}
	if (arch_mmu_flags_src & ARCH_MMU_FLAG_NS) {
		arch_mmu_flags |= ARCH_MMU_FLAG_NS;
	}
	arch_mmu_flags |= arch_mmu_flags_src & ARCH_MMU_FLAG_CACHE_MASK;


	err = vmm_alloc_physical_etc(ut_target->aspace, "copy", size,
	                             (void **)vaddr_target,
	                             PAGE_SIZE_SHIFT, pfn_list, npages,
	                             0, arch_mmu_flags);

	LTRACEF("va 0x%lx, pa 0x%lx..., size %zd, arch_mmu_flags 0x%x, err %d\n",
	        *vaddr_target, pfn_list[0], size, arch_mmu_flags, err);

	/* Add back the offset after translation and mapping */
	*vaddr_target += offset;

err_free_pfn_list:
err_out:
	free(pfn_list);
	return err;
}

status_t uthread_revoke_pages(uthread_t *ut, vaddr_t vaddr, size_t size)
{
	u_int offset = vaddr & (PAGE_SIZE - 1);

	if (size == 0)
		return 0;

	vaddr = ROUNDDOWN(vaddr, PAGE_SIZE);
	size  = ROUNDUP(size + offset, PAGE_SIZE);

	LTRACEF("va %lx, size %zd\n", vaddr, size);

	return vmm_free_region_etc(ut->aspace, vaddr, size, 0);
}
#endif
