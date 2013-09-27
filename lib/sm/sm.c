/*
 * Copyright (c) 2013 Google Inc. All rights reserved
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
#include <kernel/thread.h>
#include <lib/sm.h>
#include <lk/init.h>
#include <sys/types.h>

extern unsigned long monitor_vector_table;
static trusted_service_handler_routine ts_handler;

static void sm_wait_for_smcall(void)
{
	long ret = 0;
	ts_args_t *ns_args, args;

	while (true) {
		enter_critical_section();

		thread_yield();
		ns_args = sm_sched_nonsecure(ret);

		if (!ns_args) {
			ret = SM_ERR_UNEXPECTED_RESTART;
			exit_critical_section();
			continue;
		}

		/* Pull args out before enabling interrupts */
		args = *ns_args;
		exit_critical_section();

		/* Dispatch service handler */
		if (ts_handler)
			ret = ts_handler(&args);
		else {
			dprintf(CRITICAL,
				"No service handler registered!\n");
			ret = SM_ERR_NOT_SUPPORTED;
		}
	}
}

/* per-cpu secure monitor initialization */
void sm_secondary_init(void)
{
	/* let normal world enable SMP, lock TLB, access CP10/11 */
	__asm__ volatile (
		"mrc	p15, 0, r1, c1, c1, 2	\n"
		"orr	r1, r1, #0xC00		\n"
		"orr	r1, r1, #0x60000	\n"
		"mcr	p15, 0, r1, c1, c1, 2	@ NSACR	\n"
		::: "r1"
	);

	__asm__ volatile (
		"mcr	p15, 0, %0, c12, c0, 1	\n"
		: : "r" (&monitor_vector_table)
	);
}

static void sm_init(uint level)
{
	sm_secondary_init();

	thread_t *nsthread = thread_create("ns-switch",
				(thread_start_routine)sm_wait_for_smcall,
				NULL, LOWEST_PRIORITY + 1, DEFAULT_STACK_SIZE);

	if (!nsthread) {
		dprintf(CRITICAL, "failed to create NS switcher thread!\n");
		halt();
	}

	thread_resume(nsthread);
}

LK_INIT_HOOK(libsm, sm_init, LK_INIT_LEVEL_PLATFORM - 1);

status_t sm_register_trusted_service_handler(trusted_service_handler_routine fn)
{
	if (ts_handler)
		return ERR_ALREADY_EXISTS;

	enter_critical_section();
	ts_handler = fn;
	exit_critical_section();

	return NO_ERROR;
}
