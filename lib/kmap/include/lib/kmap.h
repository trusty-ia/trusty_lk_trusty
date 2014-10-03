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

#ifndef __LIB_KMAP_H
#define __LIB_KMAP_H

#ifndef WITH_KERNEL_VM
#error "libkmap needs KERNEL_VM enabled"
#endif

#include <compiler.h>
#include <err.h>
#include <list.h>
#include <stdlib.h>
#include <sys/types.h>

/* This library only allocates 1MB pages */
#define PAGE_SIZE_1M	(1024 * 1024)

typedef struct kmap
{
	vaddr_t vaddr;
	size_t size;
	u_int flags;
	u_int align;
	struct list_node node;
	paddr_t pfn_list[];
} kmap_t;

/* Kernel mapping flags */
enum
{
	KM_R		= 1 << 0,
	KM_W		= 1 << 1,
	KM_X		= 1 << 2,
	KM_NONE		= 1 << 3,	/* No permissions */
	KM_PHYS_CONTIG	= 1 << 4,	/* Physically contiguious */
	KM_NS_MEM	= 1 << 5,	/* Non-secure memory */
	KM_IO		= 1 << 6,	/* MMIO registers */
	KM_UC		= 1 << 7,	/* Bypass CPU cache(s) */
};

/* Map in a list of physical pages into a contiguous virtual address range */
status_t kmap(paddr_t *pfn_list, size_t size, u_int flags,
		u_int align, vaddr_t *vaddrp);

/* Unmap a previously made mapping */
status_t kunmap(vaddr_t vaddr, size_t size);

status_t kmap_contig(paddr_t paddr, size_t size, u_int flags,
		u_int align, vaddr_t *vaddrp);


#endif /* __LIB_KMAP_H */
