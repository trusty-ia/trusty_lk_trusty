/*
 * Copyright (c) 2013, Google, Inc. All rights reserved
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

#define LOCAL_TRACE 1

#include <bits.h>
#include <err.h>
#include <list.h> // for containerof
#include <platform.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <trace.h>
#include <uthread.h>

#include <kernel/event.h>
#include <kernel/thread.h>
#include <kernel/wait.h>

#include <lib/syscall.h>
#include <lib/trusty/handle.h>
#include <lib/trusty/trusty_app.h>
#include <lib/trusty/uctx.h>

/* must be a multiple of sizeof(unsigned long) */
#define IPC_MAX_HANDLES		64

struct uctx {
	/* protects the inuse and handles fields */
	mutex_t			lock;
	unsigned long		inuse[BITMAP_NUM_WORDS(IPC_MAX_HANDLES)];
	handle_t		*handles[IPC_MAX_HANDLES];

	void			*priv;
	handle_list_t		handle_list;
};

int uctx_create(void *priv, uctx_t **ctx)
{
	uctx_t *new_ctx;

	new_ctx = calloc(1, sizeof(uctx_t));
	if (!new_ctx)
		return ERR_NO_MEMORY;

	new_ctx->priv = priv;

	mutex_init(&new_ctx->lock);
	handle_list_init(&new_ctx->handle_list);

	*ctx = new_ctx;

	return NO_ERROR;
}

void uctx_destroy(uctx_t *ctx)
{
	int i;

	mutex_acquire(&ctx->lock);
	for (i = 0; i < IPC_MAX_HANDLES; i++) {
		if (ctx->handles[i]) {
			TRACEF("destroying a non-empty uctx!!!\n");
			handle_list_del(&ctx->handle_list, ctx->handles[i]);
			handle_close(ctx->handles[i]);
			ctx->handles[i] = NULL;
		}
	}
	mutex_release(&ctx->lock);
	free(ctx);
}

void *uctx_get_priv(uctx_t *ctx)
{
	return ctx->priv;
}


/* Note: The caller transfers its ownership (and thus its ref) of the handle
 * to this function, which is handed off to the handle table of the user
 * process.
 */
int uctx_handle_install(uctx_t *ctx, handle_t *handle, int *id)
{
	int ret = NO_ERROR;
	int new_id;

	mutex_acquire(&ctx->lock);

	new_id = bitmap_ffz(ctx->inuse, IPC_MAX_HANDLES);
	if (unlikely(new_id < 0)) {
		ret = ERR_NO_RESOURCES;
		goto out;
	}
	bitmap_set(ctx->inuse, new_id);

	ASSERT(ctx->handles[new_id] == NULL);

	ctx->handles[new_id] = handle;
	handle_list_add(&ctx->handle_list, handle);
	*id = new_id;
out:
	mutex_release(&ctx->lock);
	return ret;
}

static inline int uctx_handle_id_remove_locked(
		uctx_t *ctx, int handle_id, handle_t **handle_ptr)
{
	handle_t *handle;

	if (unlikely(handle_id < 0 || handle_id >= IPC_MAX_HANDLES))
		return ERR_BAD_HANDLE;
	if (!bitmap_test(ctx->inuse, handle_id))
		return ERR_BAD_HANDLE;

	bitmap_clear(ctx->inuse, handle_id);
	handle = ctx->handles[handle_id];
	ctx->handles[handle_id] = NULL;
	handle_list_del(&ctx->handle_list, handle);
	*handle_ptr = handle;

	return NO_ERROR;
}

static int uctx_handle_get_locked(uctx_t *ctx, int handle_id,
				  handle_t **handle_ptr)
{
	handle_t *handle;

	if (unlikely(handle_id < 0 || handle_id >= IPC_MAX_HANDLES))
		return ERR_INVALID_ARGS;
	if (!bitmap_test(ctx->inuse, handle_id))
		return ERR_NOT_FOUND;

	handle = ctx->handles[handle_id];
	/* take a reference on the handle we looked up */
	handle_incref(handle);

	*handle_ptr = handle;
	return NO_ERROR;
}

int uctx_handle_get(uctx_t *ctx, int handle_id, handle_t **handle_ptr)
{
	int ret;

	mutex_acquire(&ctx->lock);
	ret = uctx_handle_get_locked(ctx, handle_id, handle_ptr);
	mutex_release(&ctx->lock);

	return ret;
}

static int uctx_handle_find_id_locked(uctx_t *ctx, handle_t *handle,
				      int *id_ptr)
{
	int i;

	for (i = 0; i < IPC_MAX_HANDLES; i++) {
		if (ctx->handles[i] == handle) {
			*id_ptr = i;
			return 0;
		}
	}
	return ERR_NOT_FOUND;
}

/* fills in the handle that has a pending event. The reference taken by the list
 * is not dropped until the caller has had a chance to process the handle.
 */
int uctx_handle_wait_any(uctx_t *ctx, handle_t **handle_ptr,
			 uint32_t *event_ptr, lk_time_t timeout)
{
	return handle_list_wait(&ctx->handle_list, handle_ptr, event_ptr,
				timeout);
}

/******************************************************************************/

/* definition shared with userspace */
typedef struct uevent {
	int			handle;
	uint32_t		event;
	user_addr_t		cookie;
} uevent_t;

/* wait on integer handle id */
long __SYSCALL sys_wait(int handle_id, user_addr_t user_event,
			unsigned long timeout_msecs)
{
	trusty_app_t *tapp = uthread_get_current()->private_data;
	uctx_t *ctx = tapp->uctx;
	handle_t *handle;
	uevent_t tmp_event;
	int ret;

	ret = uctx_handle_get(ctx, handle_id, &handle);
	if (ret)
		return ret;

	ret = handle_wait(handle, &tmp_event.event,
			  MSECS_TO_LK_TIME(timeout_msecs));
	if (ret != 0)
		goto out;

	tmp_event.handle = handle_id;
	tmp_event.cookie = (user_addr_t)handle_get_cookie(handle);
	copy_to_user(user_event, &tmp_event, sizeof(tmp_event));
out:
	handle_decref(handle);
	return ret;
}

/* wait on integer handle id */
long __SYSCALL sys_wait_any(user_addr_t user_event, unsigned long timeout_msecs)
{
	trusty_app_t *tapp = uthread_get_current()->private_data;
	uctx_t *ctx = tapp->uctx;
	handle_t *handle;
	uevent_t tmp_event;
	int ret;
	int find_ret;

	LTRACE_ENTRY;

	ret = uctx_handle_wait_any(ctx, &handle, &tmp_event.event,
				   MSECS_TO_LK_TIME(timeout_msecs));
	if (ret <= 0) {
		LTRACEF("erroring out? %d\n", ret);
		goto out;
	}

	mutex_acquire(&ctx->lock);
	find_ret = uctx_handle_find_id_locked(ctx, handle, &tmp_event.handle);
	mutex_release(&ctx->lock);

	tmp_event.cookie = (user_addr_t)handle_get_cookie(handle);

	/* drop the reference that was taken by wait_any */
	handle_decref(handle);

	if (find_ret) {
		ret = ERR_NOT_READY;
		goto out;
	}

	copy_to_user(user_event, &tmp_event, sizeof(tmp_event));
out:
	LTRACE_EXIT;
	return ret;
}

long __SYSCALL sys_close(int handle_id)
{
	trusty_app_t *tapp = uthread_get_current()->private_data;
	uctx_t *ctx = tapp->uctx;
	handle_t *handle;
	int ret;

	mutex_acquire(&ctx->lock);

	LTRACEF("clearing out handle %d\n", handle_id);

	ret = uctx_handle_id_remove_locked(ctx, handle_id, &handle);
	mutex_release(&ctx->lock);

	if (ret)
		return ret;

	LTRACEF("cleared out handle %d\n", handle_id);

	handle_close(handle);
	return 0;
}

long __SYSCALL sys_set_cookie(int handle_id, user_addr_t cookie)
{
	trusty_app_t *tapp = uthread_get_current()->private_data;
	uctx_t *ctx = tapp->uctx;
	handle_t *handle;
	int ret;

	ret = uctx_handle_get(ctx, handle_id, &handle);
	if (ret)
		return ret;

	handle_set_cookie(handle, (void *)cookie);

	handle_decref(handle);
	return 0;
}
