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
		u_int i;
		/* handle stdout/stderr */
		for (i = 0; i < size; i++) {
			dprintf(SPEW, "%c", ((char *)msg)[i]);
		}
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
	thread_exit(0);
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
