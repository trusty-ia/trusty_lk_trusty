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
#include <kernel/mutex.h>
#include <lk/init.h>
#include <lib/kmap.h>
#include <lib/kmap/arch_kmap.h>

static vaddr_t kmap_start;
static vaddr_t kmap_end;

/* List of all kernel mappings */
static struct list_node kmap_list;

/* Lock to protect operations on kernel page tables */
static mutex_t kmap_lock;

static vaddr_t kmap_find_va_space(size_t size, u_int flags, u_int align)
{
	vaddr_t start, end;
	kmap_t *mp;

	start = kmap_start;
	end = start + size;

	/* find first fit */
	list_for_every_entry(&kmap_list, mp, kmap_t, node) {
		if (end < mp->vaddr)
			break;

		start = MAX(start, ROUNDUP((mp->vaddr + mp->size), align));
		end = start + size;

		if (end > kmap_end)
			return 0L;
	}
	return start;
}

static status_t kmap_alloc(vaddr_t vaddr, paddr_t *pfn_list, size_t size,
		u_int flags, u_int align, kmap_t **mpp)
{
	kmap_t *mp, *mp_lst;
	status_t err = NO_ERROR;
	uint32_t npages;

	ASSERT(!(size & (PAGE_SIZE_1M - 1)));

	if (flags & KM_PHYS_CONTIG)
		npages = 1;
	else
		npages = (size / PAGE_SIZE_1M);

	mp = malloc(sizeof(kmap_t) + (npages * sizeof(mp->pfn_list[0])));
	if (!mp) {
		err = ERR_NO_MEMORY;
		goto err_out;
	}

	mp->vaddr = vaddr;
	mp->size = size;
	mp->flags = flags;
	mp->align = align;
	memcpy(mp->pfn_list, pfn_list, npages*sizeof(paddr_t));

	list_for_every_entry(&kmap_list, mp_lst, kmap_t, node) {
		if (mp_lst->vaddr > mp->vaddr) {
			if((mp->vaddr + mp->size) > mp_lst->vaddr) {
				err = ERR_INVALID_ARGS;
				goto err_free_mp;
			}
			list_add_before(&mp_lst->node, &mp->node);
			goto out;
		}
	}

	list_add_tail(&kmap_list, &mp->node);
out:
	if (mpp)
		*mpp = mp;
	return NO_ERROR;

err_free_mp:
	free(mp);
err_out:
	if (mpp)
		*mpp = NULL;
	return err;
}

static kmap_t *kmap_find(vaddr_t vaddr, size_t size)
{
	kmap_t *mp;

	list_for_every_entry(&kmap_list, mp, kmap_t, node) {
		if ((mp->vaddr <= vaddr) &&
		    ((mp->vaddr + mp->size) >= (vaddr + size))) {
			return mp;
		}
	}

	return NULL;
}

/* caller ensures mp is in the mapping list */
static void kmap_remove(kmap_t *mp)
{
	list_delete(&mp->node);
	free(mp);
}

status_t kmap(paddr_t *pfn_list, size_t size, u_int flags,
		u_int align, vaddr_t *vaddrp)
{
	kmap_t *mp = NULL;
	status_t err;

	if (!pfn_list || !vaddrp) {
		err = ERR_INVALID_ARGS;
		goto done;
	}

	if((size & (PAGE_SIZE_1M - 1))) {
		err = ERR_NOT_VALID;
		goto done;
	}

	mutex_acquire(&kmap_lock);

	*vaddrp = kmap_find_va_space(size, flags, align);

	if (!(*vaddrp)) {
		err = ERR_NO_MEMORY;
		goto unlock;
	}

	err = kmap_alloc(*vaddrp, pfn_list, size, flags, align, &mp);
	if(err)
		goto unlock;

	err = arch_kmap(mp);

	if (!err)
		kmap_remove(mp);
unlock:
	mutex_release(&kmap_lock);
done:
	return err;
}

status_t kunmap(vaddr_t vaddr, size_t size)
{
	kmap_t *mp;
	status_t err;

	if (!vaddr) {
		err = ERR_INVALID_ARGS;
		goto done;
	}

	mutex_acquire(&kmap_lock);

	mp = kmap_find(vaddr, size);
	if(!mp) {
		err = ERR_NOT_FOUND;
		goto unlock;
	}

	err = arch_kunmap(mp);
	if (err)
		goto unlock;

	kmap_remove(mp);
unlock:
	mutex_release(&kmap_lock);
done:
	return err;
}

status_t kmap_set_valloc_range(vaddr_t start, vaddr_t end)
{
	if (start > end)
		return ERR_INVALID_ARGS;

	kmap_start = start;
	kmap_end = end;

	return NO_ERROR;
}

static void kmap_init(uint level)
{
	mutex_init(&kmap_lock);
	list_initialize(&kmap_list);
}

LK_INIT_HOOK(libkmap, kmap_init, LK_INIT_LEVEL_ARCH_EARLY);
