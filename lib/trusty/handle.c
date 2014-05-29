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

#define LOCAL_TRACE 0

#include <debug.h>
#include <err.h>
#include <list.h> // for containerof
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <trace.h>

#include <kernel/event.h>
#include <kernel/wait.h>

#include <lib/syscall.h>
#include <lib/trusty/ipc.h>

int handle_alloc(struct handle_ops *ops, void *priv, handle_t **handle_ptr)
{
	handle_t *handle;

	DEBUG_ASSERT(handle_ptr);

	handle = malloc(sizeof(handle_t));
	if (!handle)
		return ERR_NO_MEMORY;

	refcount_init(&handle->refcnt);
	handle->ops = ops;
	handle->priv = priv;
	handle->wait_event = NULL;
	handle->cookie = NULL;
	list_clear_node(&handle->waiter_node);
	list_clear_node(&handle->hlist_node);

	*handle_ptr = handle;
	return NO_ERROR;
}

static inline void __handle_free(handle_t *handle)
{
	DEBUG_ASSERT(handle);
	free(handle);
}

static void __handle_destroy_ref(refcount_t *ref)
{
	DEBUG_ASSERT(ref);

	handle_t *handle = containerof(ref, handle_t, refcnt);

	if (handle->ops && handle->ops->destroy)
		handle->ops->destroy(handle);
	__handle_free(handle);
}

void handle_incref(handle_t *handle)
{
	DEBUG_ASSERT(handle);
	refcount_inc(&handle->refcnt);
}

void handle_decref(handle_t *handle)
{
	DEBUG_ASSERT(handle);
	refcount_dec(&handle->refcnt, __handle_destroy_ref);
}

void handle_close(handle_t *handle)
{
	DEBUG_ASSERT(handle);
	if (handle->ops && handle->ops->shutdown)
		handle->ops->shutdown(handle);
	handle_decref(handle);
}

static int __do_wait(event_t *ev, lk_time_t timeout)
{
	int ret;

	LTRACEF("waiting\n");
	ret = event_wait_timeout(ev, timeout);
	LTRACEF("waited\n");
	return ret;
}

static int _prepare_wait_handle(event_t *ev, handle_t *handle)
{
	int ret = 0;

	enter_critical_section();
	if (unlikely(handle->wait_event)) {
		LTRACEF("someone is already waiting on handle %p?!\n",
			handle);
		ret = ERR_ALREADY_STARTED;
	} else {
		handle->wait_event = ev;
	}
	exit_critical_section();
	return ret;
}

static void _finish_wait_handle(event_t *ev, handle_t *handle)
{
	/* clear out our event ptr */
	enter_critical_section();
	if (unlikely(handle->wait_event != ev))
		TRACEF("handle %p stolen in wait!! %p != %p\n", handle,
		       handle->wait_event, ev);
	handle->wait_event = NULL;
	exit_critical_section();
}

int handle_wait(handle_t *handle, uint32_t *handle_event, lk_time_t timeout)
{
	status_t status;
	event_t ev;
	int ret = 0;

	if (!handle || !handle_event)
		return ERR_INVALID_ARGS;

	event_init(&ev, false, EVENT_FLAG_AUTOUNSIGNAL);

	ret = _prepare_wait_handle(&ev, handle);
	if (ret) {
		LTRACEF("someone is already waiting on handle %p\n", handle);
		goto err_prepare_wait;
	}

	*handle_event = handle->ops->poll(handle);
	if (*handle_event != 0) {
		ret = 1;
		goto got_event;
	} else if (timeout == 0) {
		ret = 0;
		goto err_timed_out;
	}

	status = __do_wait(&ev, timeout);

	*handle_event = handle->ops->poll(handle);
	if (*handle_event != 0) {
		ret = 1;
		goto got_event;
	} else if (status == ERR_TIMED_OUT) {
		ret = 0;
		goto err_timed_out;
	}

	LTRACEF("%s: error waiting %d\n", __func__, status);
	ret = ERR_IO;

err_timed_out:
got_event:
	_finish_wait_handle(&ev, handle);
err_prepare_wait:
	event_destroy(&ev);
	return ret;
}

void handle_notify(handle_t *handle)
{
	DEBUG_ASSERT(handle);

	/* TODO: need to keep track of the number of events posted? */

	enter_critical_section();
	if (handle->wait_event) {
		LTRACEF("notifying handle %p wait_event %p\n",
			handle, handle->wait_event);
		event_signal(handle->wait_event, true);
	}
	exit_critical_section();
}

void handle_list_init(handle_list_t *hlist)
{
	DEBUG_ASSERT(hlist);

	*hlist = (handle_list_t)HANDLE_LIST_INITIAL_VALUE(*hlist);
}

void handle_list_add(handle_list_t *hlist, handle_t *handle)
{
	DEBUG_ASSERT(hlist);
	DEBUG_ASSERT(handle);
	DEBUG_ASSERT(!list_in_list(&handle->hlist_node));

	handle_incref(handle);
	mutex_acquire(&hlist->lock);
	list_add_tail(&hlist->handles, &handle->hlist_node);
	mutex_release(&hlist->lock);
}

static void _handle_list_del_locked(handle_list_t *hlist, handle_t *handle)
{
	DEBUG_ASSERT(hlist);
	DEBUG_ASSERT(handle);
	DEBUG_ASSERT(list_in_list(&handle->hlist_node));

	list_delete(&handle->hlist_node);
	handle_decref(handle);
}

void handle_list_del(handle_list_t *hlist, handle_t *handle)
{
	DEBUG_ASSERT(hlist);
	DEBUG_ASSERT(handle);

	mutex_acquire(&hlist->lock);
	_handle_list_del_locked(hlist, handle);
	mutex_release(&hlist->lock);
}

void handle_list_delete_all(handle_list_t *hlist)
{
	DEBUG_ASSERT(hlist);

	mutex_acquire(&hlist->lock);
	while (!list_is_empty(&hlist->handles)) {
		handle_t *handle;

		handle = list_peek_head_type(&hlist->handles, handle_t,
					     hlist_node);
		_handle_list_del_locked(hlist, handle);
	}
	mutex_release(&hlist->lock);
}

/* fills in the handle that has a pending event. The reference taken by the list
 * is not dropped until the caller has had a chance to process the handle.
 */
int handle_list_wait(handle_list_t *hlist, handle_t **handle_ptr,
                     uint32_t *event_ptr, lk_time_t timeout)
{
	handle_t *handle;
	handle_t *tmp;
	int ret = 0;
	struct list_node wait_handles = LIST_INITIAL_VALUE(wait_handles);
	event_t ev;
	int num_ready = 0;
	uint32_t handle_event;

	DEBUG_ASSERT(hlist);
	DEBUG_ASSERT(handle_ptr);
	DEBUG_ASSERT(event_ptr);

	event_init(&ev, false, EVENT_FLAG_AUTOUNSIGNAL);

	*event_ptr = 0;
	*handle_ptr = 0;

	mutex_acquire(&hlist->lock);
	list_for_every_entry(&hlist->handles, handle, handle_t, hlist_node) {
		/* this should NEVER happen! the handle can't already
		 * be on a poll list
		 */
		DEBUG_ASSERT(!list_in_list(&handle->waiter_node));

		if (timeout) {
			ret = _prepare_wait_handle(&ev, handle);
			if (ret) {
				mutex_release(&hlist->lock);
				goto err_prepare_wait;
			}

			list_add_tail(&wait_handles, &handle->waiter_node);
			handle_incref(handle);
		}

		/* We need to do this *after* adding the event ptr to the
		 * handle. If we did it before then it would have been possible
		 * for someone to signal the handle just after the poll, which
		 * would mean that we'd have nothing to notify later and wait
		 * forever.
		 */
		handle_event = handle->ops->poll(handle);
		if (handle_event != 0) {
			LTRACEF("got event 0x%x on %p\n", handle_event, handle);
			num_ready++;
			if (*handle_ptr == 0) {
				handle_incref(handle);
				*handle_ptr = handle;
				*event_ptr = handle_event;
			}
		}
	}
	mutex_release(&hlist->lock);

	if (num_ready || !timeout) {
		ret = num_ready;
		goto cleanup;
	} else if (list_is_empty(&wait_handles)) {
		/* nothing to do? no handles? */
		ret = ERR_NOT_FOUND;
		goto cleanup;
	}

	/* assume that this will only return when timeout has expired or someone
	 * woke us up with an event
	 */
	__do_wait(&ev, timeout);

	list_for_every_entry(&wait_handles, handle, handle_t, waiter_node) {
		handle_event = handle->ops->poll(handle);
		if (handle_event != 0) {
			LTRACEF("got event 0x%x on %p\n", handle_event, handle);
			num_ready++;
			if (*handle_ptr == 0) {
				handle_incref(handle);
				*handle_ptr = handle;
				*event_ptr = handle_event;
			}
		}
	}
	ret = num_ready;

err_prepare_wait:
cleanup:
	list_for_every_entry_safe(&wait_handles, handle, tmp, handle_t,
				  waiter_node) {
		if (timeout) {
			list_delete(&handle->waiter_node);
			_finish_wait_handle(&ev, handle);
			handle_decref(handle);
		}
	}
	event_destroy(&ev);
	return ret;
}
