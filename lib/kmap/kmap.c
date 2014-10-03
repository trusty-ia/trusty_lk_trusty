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

#include <assert.h>
#include <list.h>
#include <string.h>
#include <lk/init.h>
#include <lib/kmap.h>

#include <kernel/vm.h>

static uint kmap_to_arch_mmu_flags(uint flags)
{
	uint arch_flags = 0;

	if (flags & KM_IO)
		arch_flags |= ARCH_MMU_FLAG_UNCACHED_DEVICE;
	else if (flags & KM_UC)
		arch_flags |= ARCH_MMU_FLAG_UNCACHED;
	else
		arch_flags |= ARCH_MMU_FLAG_CACHED;

	if (flags & KM_NS_MEM)
		arch_flags |= ARCH_MMU_FLAG_NS;

	if (flags & (KM_NONE | KM_X)) {
		panic("%s: %x flags not supported\n", __func__, flags);
	} else {
		DEBUG_ASSERT(flags & (KM_R | KM_W));
		if (flags & KM_R) {
			arch_flags |= ARCH_MMU_FLAG_PERM_RO;
		}
	}
	return arch_flags;
}

status_t kmap(paddr_t *pfn_list, size_t size, u_int flags,
		u_int align, vaddr_t *vaddrp)
{
	panic("%s: implement me\n", __func__);
	return ERR_NOT_SUPPORTED;
}

status_t kunmap(vaddr_t vaddr, size_t size)
{
	return vmm_free_region(vmm_get_kernel_aspace(), vaddr);
}


status_t kmap_contig(paddr_t paddr, size_t size, u_int flags,
		u_int align, vaddr_t *vaddrp)
{
	u_int offset;
	status_t err;
	void *vptr = NULL;

	if (!paddr) {
		if (vaddrp) {
			*vaddrp = (vaddr_t) NULL;
		}
		return ERR_INVALID_ARGS;
	}

	offset = paddr & (align - 1);
	paddr  = ROUNDDOWN(paddr, align);
	size   = ROUNDUP((size + offset), align);

	err = vmm_alloc_physical(vmm_get_kernel_aspace(), "kmap",
				 size, &vptr, paddr,  0,
				 kmap_to_arch_mmu_flags(flags));
	if (err)
		return err;

	if (vaddrp) {
		*vaddrp = (vaddr_t)vptr +  offset;
	}
	return NO_ERROR;
}
