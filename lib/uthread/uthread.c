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

#include <uthread.h>
#include <stdlib.h>
#include <string.h>
#include <compiler.h>
#include <assert.h>
#include <lk/init.h>

/* Global list of all userspace threads */
static struct list_node uthread_list;

/* Monotonically increasing thread id for now */
static uint32_t next_utid;

/* TODO: implement a utid hashmap */
static uint32_t uthread_alloc_utid(void)
{
	enter_critical_section();
	next_utid++;
	exit_critical_section();

	return next_utid;
}

/* TODO: */
static void uthread_free_utid(uint32_t utid)
{
}

static vaddr_t uthread_find_va_space(uthread_t *ut, size_t size,
		u_int flags, u_int align)
{
	vaddr_t start, end;
	uthread_map_t *mp;

	start = ROUNDUP(ut->start_stack, align);
	end = start + size;

	/* find first fit */
	list_for_every_entry(&ut->map_list, mp, uthread_map_t, node) {
		if (end < mp->vaddr)
			break;

		start = MAX(start, ROUNDUP((mp->vaddr + mp->size), align));
		end = start + size;
	}
	return start;
}

static status_t uthread_map_alloc(uthread_t *ut, uthread_map_t **mpp,
		vaddr_t vaddr, paddr_t *pfn_list, size_t size, u_int flags)
{
	uthread_map_t *mp, *mp_lst;
	status_t err = NO_ERROR;
	uint32_t npages;

	ASSERT(!(size & (PAGE_SIZE - 1)));

	if (flags & UTM_PHYS_CONTIG)
		npages = 1;
	else
		npages = (size / PAGE_SIZE);

	mp = malloc(sizeof(uthread_map_t) + (npages * sizeof(mp->pfn_list[0])));
	if (!mp) {
		err = ERR_NO_MEMORY;
		goto err_out;
	}

	mp->vaddr = vaddr;
	mp->size = size;
	mp->flags = flags;
	memcpy(mp->pfn_list, pfn_list, npages*sizeof(paddr_t));

	list_for_every_entry(&ut->map_list, mp_lst, uthread_map_t, node) {
		if (mp_lst->vaddr > mp->vaddr) {
			if((mp->vaddr + mp->size) > mp_lst->vaddr) {
				err = ERR_INVALID_ARGS;
				goto err_free_mp;
			}
			list_add_before(&mp_lst->node, &mp->node);
			goto out;
		}
	}

	list_add_tail(&ut->map_list, &mp->node);
out:
	*mpp = mp;
	return NO_ERROR;

err_free_mp:
	free(mp);
err_out:
	*mpp = NULL;
	return err;
}

static uthread_map_t *uthread_map_find(uthread_t *ut, vaddr_t vaddr, size_t size)
{
	uthread_map_t *mp = NULL;

	/* TODO: Fuzzy comparisions for now */
	list_for_every_entry(&ut->map_list, mp, uthread_map_t, node) {
		if ((mp->vaddr <= vaddr) &&
		    ((mp->vaddr + mp->size) >= (vaddr + size))) {
			break;
		}
	}

	return mp;
}

/* caller ensures mp is in the mapping list */
static void uthread_map_remove(uthread_t *ut, uthread_map_t *mp)
{
	list_delete(&mp->node);
	free(mp);
}

static void uthread_free_maps(uthread_t *ut)
{
	uthread_map_t *mp, *tmp;
	list_for_every_entry_safe(&ut->map_list, mp, tmp,
			uthread_map_t, node) {
		list_delete(&mp->node);
		free(mp);
	}
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

	list_initialize(&ut->map_list);

	ut->id = uthread_alloc_utid();
	ut->private_data = private_data;
	ut->entry = entry;

	/* Allocate and map in a stack region */
	ut->stack = memalign(PAGE_SIZE, stack_size);
	if(!ut->stack)
		goto err_free_ut;

	stack_bot = start_stack - stack_size;
	err = uthread_map_contig(ut, &stack_bot, kvaddr_to_paddr(ut->stack),
				stack_size,
				UTM_W | UTM_R | UTM_STACK | UTM_FIXED,
				UT_MAP_ALIGN_4KB);
	if (err)
		goto err_free_ut_stack;

	ut->start_stack = start_stack;

	ut->thread = thread_create(name,
			(thread_start_routine)arch_uthread_startup,
			NULL,
			priority,
			DEFAULT_STACK_SIZE);
	if (!ut->thread)
		goto err_free_ut_maps;

	err = arch_uthread_create(ut);
	if (err)
		goto err_free_ut_maps;

	/* store user thread struct into TLS slot 0 */
	ut->thread->tls[TLS_ENTRY_UTHREAD] = (uint32_t) ut;

	/* Put it in global uthread list */
	enter_critical_section();
	list_add_head(&uthread_list, &ut->uthread_list_node);
	exit_critical_section();

	return ut;

err_free_ut_maps:
	uthread_free_maps(ut);

err_free_ut_stack:
	free(ut->stack);

err_free_ut:
	uthread_free_utid(ut->id);
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

void uthread_context_switch(thread_t *oldthread, thread_t *newthread)
{
	uthread_t *old_ut = (uthread_t *)oldthread->tls[TLS_ENTRY_UTHREAD];
	uthread_t *new_ut = (uthread_t *)newthread->tls[TLS_ENTRY_UTHREAD];

	/* nothing more to do if newthread is a kthread */
	if (!new_ut)
		return;

	arch_uthread_context_switch(old_ut, new_ut);
}

status_t uthread_map(uthread_t *ut, vaddr_t *vaddrp, paddr_t *pfn_list,
		size_t size, u_int flags, u_int align)
{
	uthread_map_t *mp = NULL;
	status_t err = NO_ERROR;

	if (!ut || !pfn_list || !vaddrp) {
		err = ERR_INVALID_ARGS;
		goto done;
	}

	if((size & (PAGE_SIZE - 1))) {
		err = ERR_NOT_VALID;
		goto done;
	}

	if(!(flags & UTM_FIXED)) {
		*vaddrp = uthread_find_va_space(ut, size, flags, align);

		if (!(*vaddrp)) {
			err = ERR_NO_MEMORY;
			goto done;
		}
	}

	err = uthread_map_alloc(ut, &mp, *vaddrp, pfn_list, size, flags);
	if(err)
		goto done;

	err = arch_uthread_map(ut, mp);
done:
	return err;
}

status_t uthread_unmap(uthread_t *ut, vaddr_t vaddr, size_t size)
{
	uthread_map_t *mp;
	status_t err = NO_ERROR;

	if (!ut || !vaddr) {
		err = ERR_INVALID_ARGS;
		goto done;
	}

	mp = uthread_map_find(ut, vaddr, size);
	if(!mp) {
		err = ERR_NOT_FOUND;
		goto done;
	}

	err = arch_uthread_unmap(ut, mp);
	if (err)
		goto done;

	uthread_map_remove(ut, mp);
done:
	return err;
}

bool uthread_is_valid_range(uthread_t *ut, vaddr_t vaddr, size_t size)
{
	return uthread_map_find(ut, vaddr, size) != NULL ? true : false;
}

status_t copy_from_user(void *kdest, user_addr_t usrc, size_t len)
{
	/* TODO: be smarter about handling invalid addresses... */
	if (!uthread_is_valid_range(uthread_get_current(), (vaddr_t)usrc, len))
		return ERR_FAULT;
	memcpy(kdest, (void *)usrc, len);
	return NO_ERROR;
}

status_t copy_to_user(user_addr_t udest, const void *ksrc, size_t len)
{
	/* TODO: be smarter about handling invalid addresses... */
	if (!uthread_is_valid_range(uthread_get_current(), (vaddr_t)udest, len))
		return ERR_FAULT;
	memcpy((void *)udest, ksrc, len);
	return NO_ERROR;
}

static void uthread_init(uint level)
{
	list_initialize(&uthread_list);
	arch_uthread_init();
}

/* this has to come up early because we have to reinitialize the MMU on
 * some arch's
 */
LK_INIT_HOOK(libuthread, uthread_init, LK_INIT_LEVEL_ARCH_EARLY);
