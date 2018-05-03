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
#include <mm.h>
#include <stdlib.h>
#include <string.h>

#include <platform.h>
#include <uthread.h>
#include <lib/trusty/sys_fd.h>
#include <lib/trusty/trusty_app.h>
#include <platform/sand.h>
#include <lib/trusty/trusty_device_info.h>

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
	uint8_t kbuf[size];
	/* check buffer is in task's address space */
	if (!valid_address((vaddr_t)user_ptr, size))
		return ERR_INVALID_ARGS;

	copy_from_user(kbuf, user_ptr, size);

	dwrite((fd == 2) ? INFO : SPEW, (const void *)(uintptr_t)kbuf, size);
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

long sys_mmap(user_addr_t uaddr, uint32_t size, uint32_t flags, uint32_t handle)
{
	trusty_app_t *trusty_app = uthread_get_current()->private_data;
	vaddr_t vaddr;
	long ret;

	/*
	 * Only allows mapping on IO region specified by handle (id) and uaddr
	 * must be 0 for now.
	 * TBD: Add support in uthread_map to use uaddr as a hint.
	 */
	if (flags != MMAP_FLAG_IO_HANDLE || uaddr != 0)
		return ERR_INVALID_ARGS;

	ret = trusty_app_setup_mmio(trusty_app, handle, &vaddr, size);
	if (ret != NO_ERROR)
		return ret;

	return vaddr;
}

long sys_munmap(user_addr_t uaddr, uint32_t size)
{
	trusty_app_t *trusty_app = uthread_get_current()->private_data;

	/*
	 * uthread_unmap always unmaps whole region.
	 * TBD: Add support to unmap partial region when there's use case.
	 */
	return uthread_unmap(trusty_app->ut, uaddr, size);
}

#if UTHREAD_WITH_MEMORY_MAPPING_SUPPORT

long sys_prepare_dma(user_addr_t uaddr, uint32_t size, uint32_t flags,
		user_addr_t pmem)
{
	uthread_t *current = uthread_get_current();
	struct dma_pmem kpmem;
	uint32_t mapped_size = 0;
	uint32_t entries = 0;
	long ret;

	if (size == 0 || !valid_address((vaddr_t)uaddr, size))
		return ERR_INVALID_ARGS;

	do {
		ret = uthread_virt_to_phys(current,
				(vaddr_t)uaddr + mapped_size, &kpmem.paddr);
		if (ret != NO_ERROR)
			return ret;

		kpmem.size = MIN(size - mapped_size,
			PAGE_SIZE - (kpmem.paddr & (PAGE_SIZE - 1)));

		ret = copy_to_user(pmem, &kpmem, sizeof(struct dma_pmem));
		if (ret != NO_ERROR)
			return ret;

		pmem += sizeof(struct dma_pmem);

		mapped_size += kpmem.size;
		entries++;

	} while (mapped_size < size && (flags & DMA_FLAG_MULTI_PMEM));

	if (flags & DMA_FLAG_FROM_DEVICE)
		arch_clean_invalidate_cache_range(uaddr, mapped_size);
	else
		arch_clean_cache_range(uaddr, mapped_size);

	if (!(flags & DMA_FLAG_ALLOW_PARTIAL) && mapped_size != size)
		return ERR_BAD_LEN;

	return entries;
}

long sys_finish_dma(user_addr_t uaddr, uint32_t size, uint32_t flags)
{
	/* check buffer is in task's address space */
	if (!valid_address((vaddr_t)uaddr, size))
		return ERR_INVALID_ARGS;

	if (flags & DMA_FLAG_FROM_DEVICE)
		arch_clean_invalidate_cache_range(uaddr, size);

	return NO_ERROR;
}

#else /* !UTHREAD_WITH_MEMORY_MAPPING_SUPPORT */

long sys_prepare_dma(user_addr_t uaddr, uint32_t size, uint32_t flags,
		user_addr_t pmem)
{
	return ERR_NOT_SUPPORTED;
}

long sys_finish_dma(user_addr_t uaddr, uint32_t size, uint32_t flags)
{
	return ERR_NOT_SUPPORTED;
}

#endif

static bool valid_ta_to_retrieve_seed(void)
{
	uuid_t white_list[] = {
		HWCRYPTO_SRV_APP_UUID,
		KEYMASTER_SRV_APP_UUID
		/* Add more TAs which are trusted to retrieve the seed */
		};
	uint i;

	trusty_app_t *trusty_app = uthread_get_current()->private_data;
	for (i=0; i<sizeof(white_list)/sizeof(white_list[0]); i++) {
		/* matches one in the whitelist */
		if (!memcmp(&trusty_app->props.uuid, &white_list[i], sizeof(uuid_t)))
			return true;
	}
	return false;
}

/*
 * Based on the design the IMR region for LK will reserved some bytes for ROT
 * and seed storage (size = sizeof(seed_response_t)+sizeof(rot_data_t))
 */
long sys_get_device_info(user_addr_t info, bool need_seed)
{
	long ret = 0;
	trusty_device_info_t dev_info;

	if (need_seed && !valid_ta_to_retrieve_seed())
		panic("the caller is invalid!\n");

	if(g_trusty_startup_info.size_of_this_struct != sizeof(trusty_startup_info_t))
		panic("trusty_startup_info_t size mismatch!\n");

	/* make sure the shared structure are same in tos loader, LK kernel */
	if(g_dev_info->size != sizeof(trusty_device_info_t))
		panic("trusty_device_info_t size mismatch!\n");

	/* memcpy may result to klocwork scan error, so size is checked before memcpy is called. */
	memcpy(&dev_info, g_dev_info, sizeof(trusty_device_info_t));

	/* for Km1.0 no need the osVersion and patchMonthYear */
	dev_info.rot.osVersion = 0;
	dev_info.rot.patchMonthYear = 0;

	if (!need_seed)
		/* seed is the sensitive secret date, do not return to user app if it is not required. */
		memset(dev_info.seed_list, 0, sizeof(dev_info.seed_list));

	dev_info.state.data = 0;

	ret = copy_to_user(info, &dev_info, sizeof(trusty_device_info_t));
	memset(&dev_info, 0, sizeof(dev_info));

	if (ret != NO_ERROR)
		panic("failed (%ld) to copy structure to user\n", ret);

	return NO_ERROR;
}

