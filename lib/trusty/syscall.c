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
#include <kernel/mutex.h>
#include <stdlib.h>
#include <string.h>

#include <platform.h>
#include <uthread.h>
#include <lib/trusty/sys_fd.h>
#include <lib/trusty/trusty_app.h>

static int32_t sys_std_write(uint32_t fd, user_addr_t user_ptr, uint32_t size);

static mutex_t fd_lock = MUTEX_INITIAL_VALUE(fd_lock);

static const struct sys_fd_ops sys_std_fd_op = {
	.write = sys_std_write,
};

static struct sys_fd_ops const *sys_fds[MAX_SYS_FD_HADLERS] = {
	[1] = &sys_std_fd_op,  /* stdout */
	[2] = &sys_std_fd_op,  /* stderr */
};

status_t install_sys_fd_handler(uint32_t fd, const struct sys_fd_ops *ops)
{
	status_t ret;

	if (fd >= countof(sys_fds))
		return ERR_INVALID_ARGS;

	mutex_acquire(&fd_lock);
	if (!sys_fds[fd]) {
		sys_fds[fd] = ops;
		ret = NO_ERROR;
	} else {
		ret = ERR_ALREADY_EXISTS;
	}
	mutex_release(&fd_lock);
	return ret;
}

static const struct sys_fd_ops *get_sys_fd_handler(uint32_t fd)
{
	if (fd >= countof(sys_fds))
		return NULL;

	return sys_fds[fd];
}

static bool valid_address(vaddr_t addr, u_int size)
{
	return uthread_is_valid_range(uthread_get_current(), addr, size);
}

/* handle stdout/stderr */
static int32_t sys_std_write(uint32_t fd, user_addr_t user_ptr, uint32_t size)
{
	/* check buffer is in task's address space */
	if (!valid_address((vaddr_t)user_ptr, size))
		return ERR_INVALID_ARGS;

	dwrite((fd == 2) ? INFO : SPEW, (const void *)(uintptr_t)user_ptr, size);
	return size;
}

long sys_write(uint32_t fd, user_addr_t user_ptr, uint32_t size)
{
	const struct sys_fd_ops *ops = get_sys_fd_handler(fd);

	if (ops && ops->write)
		return ops->write(fd, user_ptr, size);

	return ERR_NOT_SUPPORTED;
}

long sys_brk(u_int brk)
{
	trusty_app_t *trusty_app = uthread_get_current()->private_data;

	/* update brk, if within range */
	if ((brk >= trusty_app->start_brk) && (brk <= trusty_app->end_brk)) {
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

long sys_read(uint32_t fd, user_addr_t user_ptr, uint32_t size)
{
	const struct sys_fd_ops *ops = get_sys_fd_handler(fd);

	if (ops && ops->read)
		return ops->read(fd, user_ptr, size);

	return ERR_NOT_SUPPORTED;
}

long sys_ioctl(uint32_t fd, uint32_t req, user_addr_t user_ptr)
{
	const struct sys_fd_ops *ops = get_sys_fd_handler(fd);

	if (ops && ops->ioctl)
		return ops->ioctl(fd, req, user_ptr);

	return ERR_NOT_SUPPORTED;
}

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

long sys_nanosleep(uint32_t clock_id, uint32_t flags,
		   uint32_t sleep_time_l, uint32_t sleep_time_h)
{
	uint64_t sleep_time = sleep_time_l + ((uint64_t)sleep_time_h << 32);
	thread_sleep((lk_time_t)(DIV_ROUND_UP(sleep_time, 1000 * 1000)));

	return NO_ERROR;
}

long sys_gettime(uint32_t clock_id, uint32_t flags, user_addr_t time)
{
	// return time in nanoseconds
	lk_bigtime_t t = current_time_hires() * 1000;

	return copy_to_user(time, &t, sizeof(int64_t));
}
