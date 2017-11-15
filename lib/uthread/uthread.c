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
