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

#ifndef __UTHREAD_H
#define __UTHREAD_H

#include <sys/types.h>
#include <compiler.h>
#include <err.h>
#include <kernel/thread.h>
#include <arch/uthread.h>

#if WITH_KERNEL_VM
#include <kernel/vm.h>
#endif

typedef struct uthread
{
	vaddr_t start_stack;

	vaddr_t entry;

	vmm_aspace_t *aspace;

	thread_t *thread;
	void *private_data;
} uthread_t;

/* uthread_grant_pages flags */
enum
{
	UTM_R		= 1 << 0,
	UTM_W		= 1 << 1,
};

/* Create a new user thread */
uthread_t *uthread_create(const char *name, vaddr_t entry, int priority,
		vaddr_t stack_top, size_t stack_size, void *private_data);

/* Start the user thread */
status_t uthread_start(uthread_t *ut);

/* Exit current uthread */
void uthread_exit(int retcode) __NO_RETURN;

/* Check if the given user address range has a valid mapping */
bool uthread_is_valid_range(uthread_t *ut, vaddr_t vaddr, size_t size);

static inline status_t copy_from_user(void *kdest, user_addr_t usrc, size_t len)
{
	return arch_copy_from_user(kdest, usrc, len);
}

static inline status_t copy_to_user(user_addr_t udest, const void *ksrc, size_t len)
{
	return arch_copy_to_user(udest, ksrc, len);
}

static inline ssize_t  strncpy_from_user(char *kdest, user_addr_t usrc, size_t len)
{
	/* wrapper for now, the old strncpy_from_user was closer to strlcpy than
	 * strncpy behaviour, but could return an unterminated string */
	return arch_strlcpy_from_user(kdest, usrc, len);
}

static inline ssize_t  strlcpy_from_user(char *kdest, user_addr_t usrc, size_t len)
{
	return arch_strlcpy_from_user(kdest, usrc, len);
}

static inline uthread_t *uthread_get_current(void)
{
	return (uthread_t *)tls_get(TLS_ENTRY_UTHREAD);
}

#if UTHREAD_WITH_MEMORY_MAPPING_SUPPORT
/* Translate virtual address to physical address */
status_t uthread_virt_to_phys(uthread_t *ut, vaddr_t vaddr, paddr_t *paddr);

/* Grant pages from current context into target uthread */
status_t uthread_grant_pages(uthread_t *ut_target, ext_vaddr_t vaddr_src,
		size_t size, u_int flags, vaddr_t *vaddr_target, bool ns_src,
		uint64_t *ns_page_list);

/* Revoke mappings from a previous grant */
status_t uthread_revoke_pages(uthread_t *ut, vaddr_t vaddr, size_t size);
#endif

#endif /* __UTHREAD_H */
