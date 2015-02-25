/*
 * Copyright (c) 2013, Google, Inc. All rights reserved
 * Copyright (c) 2013, NVIDIA CORPORATION. All rights reserved
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
#include <debug.h>
#include <err.h>
#include <kernel/thread.h>
#include <stdlib.h>
#include <string.h>

#include <platform.h>
#include <uthread.h>
#include <lib/trusty/trusty_app.h>

#ifdef WITH_LIB_OTE
#include <lib/ote.h>
#endif

static bool valid_address(vaddr_t addr, u_int size)
{
	return uthread_is_valid_range(uthread_get_current(), addr, size);
}

long sys_write(uint32_t fd, void *msg, uint32_t size)
{
	/* check buffer is in task's address space */
	if (valid_address((vaddr_t)msg, size) == false) {
		return ERR_INVALID_ARGS;
	}

	if ((fd == 1) || (fd == 2)) {
		/* handle stdout/stderr */
		int dbg_lvl = (fd == 2) ? INFO : SPEW;
		dwrite(dbg_lvl, msg, size);
		return size;
	}

#ifdef WITH_LIB_OTE
	return ote_sys_write(fd, msg, size);
#else
	return ERR_INVALID_ARGS;
#endif
}

long sys_brk(u_int brk)
{
	trusty_app_t *trusty_app = uthread_get_current()->private_data;

	/* update brk, if within range */
	if ((brk >= trusty_app->start_brk) && (brk < trusty_app->end_brk)) {
		trusty_app->cur_brk = brk;
	}
	return (long) trusty_app->cur_brk;
}

long sys_exit_group(void)
{
	thread_t *current = get_current_thread();
	dprintf(CRITICAL, "exit called, thread %p, name %s\n",
		current, current->name);
	uthread_exit(0);
	return 0L;
}

#ifdef WITH_LIB_OTE
long sys_read(uint32_t fd, void *msg, uint32_t size)
{
	return ote_sys_read(fd, msg, size);
}

long sys_ioctl(uint32_t fd, uint32_t req, void *buf)
{
	return ote_sys_ioctl(fd, req, buf);
}
#else
long sys_read(uint32_t fd, void *msg, uint32_t size)
{
	return ERR_NOT_SUPPORTED;
}

long sys_ioctl(uint32_t fd, uint32_t req, void *buf)
{
	return ERR_NOT_SUPPORTED;
}
#endif /* WITH_LIB_OTE */

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

long sys_nanosleep(uint32_t clock_id, uint32_t flags, uint64_t sleep_time)
{
	thread_sleep((lk_time_t)(DIV_ROUND_UP(sleep_time, 1000 * 1000)));

	return NO_ERROR;
}

long sys_gettime(uint32_t clock_id, uint32_t flags, int64_t *time)
{
	// return time in nanoseconds
	lk_bigtime_t t = current_time_hires() * 1000;

	return copy_to_user((user_addr_t)time, &t, sizeof(int64_t));
}
