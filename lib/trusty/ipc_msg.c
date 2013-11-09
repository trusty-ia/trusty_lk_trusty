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

/**
 * @file
 * @brief  IPC message management primitives
 * @defgroup ipc IPC
 *
 * Provides low level data structures for managing message
 * areas for the ipc contexts.
 *
 * Also provides user syscall implementations for message
 * send/receive mechanism.
 *
 * @{
 */

#include <err.h>
#include <list.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <trace.h>
#include <uthread.h>

#include <lib/syscall.h>
#include <lib/trusty/handle.h>
#include <lib/trusty/ipc.h>
#include <lib/trusty/ipc_msg.h>
#include <lib/trusty/trusty_app.h>
#include <lib/trusty/uctx.h>

#define min(a, b) ((a) < (b) ? (a) : (b))

extern mutex_t ipc_lock;

enum {
	MSG_ITEM_STATE_FREE	= 0,
	MSG_ITEM_STATE_FILLED	= 1,
	MSG_ITEM_STATE_READ	= 2,
};

typedef struct msg_item {
	uint8_t			id;
	uint8_t			state;
	int			num_handles;
	int			handles[MAX_MSG_HANDLES];
	size_t			len;
	struct list_node	node;
} msg_item_t;

typedef struct ipc_msg_queue {
	struct list_node	free_list;
	struct list_node	filled_list;
	struct list_node	read_list;

	uint32_t		num_items;
	size_t			item_sz;

	uint8_t			*buf;

	/* store the message descriptors in the queue,
	 * and the buffer separately. The buffer could
	 * eventually move to a separate area that can
	 * be mapped into the process directly.
	 */
	msg_item_t		items[0];
} ipc_msg_queue_t;

enum {
	IPC_MSG_BUFFER_USER	= 0,
	IPC_MSG_BUFFER_KERNEL	= 1,
};

typedef struct msg_desc {
	int type;
	union {
		ipc_msg_kern_t	kern;
		ipc_msg_user_t	user;
	};
} msg_desc_t;

typedef struct iovec_desc {
	int type;
	union {
		iovec_kern_t	kern;
		iovec_user_t	user;
	};
} iovec_desc_t;

/**
 * @brief  Create IPC message queue
 *
 * Stores up-to a predefined number of equal-sized items in a circular
 * buffer (FIFO).
 *
 * @param num_items   Number of messages we need to store.
 * @param item_sz     Size of each message item.
 * @param mq          Pointer where to store the ptr to the newly allocated
 *                    message queue.
 *
 * @return  Returns NO_ERROR on success, ERR_NO_MEMORY on error.
 */
int ipc_msg_queue_create(int num_items, size_t item_sz, ipc_msg_queue_t **mq)
{
	ipc_msg_queue_t *tmp_mq;
	int ret;

	tmp_mq = calloc(1, (sizeof(ipc_msg_queue_t) +
			    num_items * sizeof(msg_item_t)));
	if (!tmp_mq) {
		dprintf(CRITICAL, "cannot allocate memory for message queue\n");
		return ERR_NO_MEMORY;
	}

	tmp_mq->buf = malloc(num_items * item_sz);
	if (!tmp_mq->buf) {
		dprintf(CRITICAL,
			"cannot allocate memory for message queue buf\n");
		ret = ERR_NO_MEMORY;
		goto err_alloc_buf;
	}

	tmp_mq->num_items = num_items;
	tmp_mq->item_sz = item_sz;
	list_initialize(&tmp_mq->free_list);
	list_initialize(&tmp_mq->filled_list);
	list_initialize(&tmp_mq->read_list);

	for (int i = 0; i < num_items; i++) {
		tmp_mq->items[i].id = i;
		list_add_tail(&tmp_mq->free_list, &tmp_mq->items[i].node);
	}
	*mq = tmp_mq;
	return 0;

err_alloc_buf:
	free(tmp_mq);
	return ret;
}

void ipc_msg_queue_destroy(ipc_msg_queue_t *mq)
{
	free(mq->buf);
	free(mq);
}

bool ipc_msg_queue_is_empty(ipc_msg_queue_t *mq)
{
	return list_is_empty(&mq->filled_list);
}

bool ipc_msg_queue_is_full(ipc_msg_queue_t *mq)
{
	return list_is_empty(&mq->free_list);
}

static inline uint8_t *msg_queue_get_buf(ipc_msg_queue_t *mq, msg_item_t *item)
{
	return mq->buf + item->id * mq->item_sz;
}

static inline msg_item_t *msg_queue_get_item(ipc_msg_queue_t *mq, uint32_t id)
{
	return id < mq->num_items ? &mq->items[id] : NULL;
}

static void _init_msg_kernel(msg_desc_t *msg, ipc_msg_kern_t *kern_msg)
{
	msg->type = IPC_MSG_BUFFER_KERNEL;
	memcpy(&msg->kern, kern_msg, sizeof(ipc_msg_kern_t));
}

static int _init_msg_user(msg_desc_t *msg, user_addr_t user_msg_addr)
{
	msg->type = IPC_MSG_BUFFER_USER;
	if (copy_from_user(&msg->user, user_msg_addr, sizeof(ipc_msg_user_t)))
		return ERR_FAULT;
	return 0;
}

static int _get_iov(msg_desc_t *msg, int i, iovec_desc_t *iov)
{
	iov->type = msg->type;
	if (msg->type == IPC_MSG_BUFFER_USER) {
		user_addr_t iov_uaddr;

		iov_uaddr = msg->user.iov + i * sizeof(iovec_user_t);
		return copy_from_user(&iov->user, iov_uaddr,
				      sizeof(iovec_user_t));
	}
	memcpy(&iov->kern, &msg->kern.iov[i], sizeof(iovec_kern_t));
	return 0;
}

static int _put_iov(msg_desc_t *msg, int i, iovec_desc_t *iov)
{
	if (msg->type == IPC_MSG_BUFFER_USER) {
		user_addr_t iov_uaddr;

		iov_uaddr = msg->user.iov + i * sizeof(iovec_user_t);
		return copy_to_user(iov_uaddr, &iov->user,
				    sizeof(iovec_user_t));
	}
	memcpy(&msg->kern.iov[i], &iov->kern, sizeof(iovec_kern_t));
	return 0;
}

static int _copy_from_iov(uint8_t *buf, iovec_desc_t *iov)
{
	if (iov->type == IPC_MSG_BUFFER_USER)
		return copy_from_user(buf, iov->user.base, iov->user.len);
	memcpy(buf, iov->kern.base, iov->kern.len);
	return 0;
}

static int _copy_to_iov(iovec_desc_t *iov, void *buf)
{
	if (iov->type == IPC_MSG_BUFFER_USER)
		return copy_to_user(iov->user.base, buf, iov->user.len);
	memcpy(iov->kern.base, buf, iov->kern.len);
	return 0;
}

static int msg_write_locked(ipc_msg_queue_t *mq, msg_desc_t *msg)
{
	uint8_t *buf;
	int i;
	msg_item_t *item;

	if (ipc_msg_queue_is_full(mq))
		return ERR_NOT_ENOUGH_BUFFER;

	item = list_peek_head_type(&mq->free_list, msg_item_t, node);
	buf = msg_queue_get_buf(mq, item);

	assert(item->state == MSG_ITEM_STATE_FREE);

	/* TODO: figure out what to do about handles */
	item->num_handles = msg->kern.num_handles;
	item->len = 0;

	for (i = 0; i < msg->kern.num_iov; i++) {
		iovec_desc_t iov;
		int ret;

		ret = _get_iov(msg, i, &iov);
		if (ret)
			return ERR_FAULT;

		if (mq->item_sz - item->len < iov.kern.len)
			return ERR_TOO_BIG;

		ret = _copy_from_iov(buf, &iov);
		if (ret)
			return ERR_FAULT;

		buf += iov.kern.len;
		item->len += iov.kern.len;
	}

	list_delete(&item->node);
	list_add_tail(&mq->filled_list, &item->node);
	item->state = MSG_ITEM_STATE_FILLED;

	return item->len;
}

/*
 * reads the specified message by copying the data into the iov list
 * provided by msg. The message must have been previously moved
 * to the read list (and thus put into READ state) by calling msg_get_filled.
 */
static int msg_read_locked(ipc_msg_queue_t *mq, uint32_t msg_id,
			   uint32_t offset, msg_desc_t *msg)
{
	uint8_t *buf;
	uint8_t *buf_start;
	msg_item_t *item;
	size_t bytes_left;
	int num_bytes;
	int ret;

	LTRACE_ENTRY;

	item = msg_queue_get_item(mq, msg_id);
	if (!item) {
		LTRACEF("invalid msg id %d\n", msg_id);
		ret = ERR_INVALID_ARGS;
		goto err;
	}

	if (item->state != MSG_ITEM_STATE_READ) {
		LTRACEF("asked to read a message not in READ state (%d)\n",
			item->id);
		ret = ERR_NO_MSG;
		goto err;
	}

	buf_start = msg_queue_get_buf(mq, item);

	if (offset >= item->len) {
		ret = ERR_INVALID_ARGS;
		goto err;
	}

	/* TODO: figure out what to do about handles */
	msg->kern.num_handles = item->num_handles;

	buf = buf_start + offset;
	bytes_left = item->len - offset;
	num_bytes = 0;

	for (int iov_idx = 0; iov_idx < msg->kern.num_iov; iov_idx++) {
		iovec_desc_t iov;
		int ret;

		ret = _get_iov(msg, iov_idx, &iov);

		iov.kern.len = min(iov.kern.len, bytes_left);
		ret = _copy_to_iov(&iov, buf);
		if (ret)
			return ERR_FAULT;
		ret = _put_iov(msg, iov_idx, &iov);
		if (ret)
			return ERR_FAULT;

		buf += iov.kern.len;
		bytes_left -= iov.kern.len;
		num_bytes += iov.kern.len;

		if (bytes_left == 0) {
			msg->kern.num_iov = iov_idx + 1;
			break;
		}
	}

	ret = num_bytes;

err:
	LTRACE_EXIT;
	return ret;
}

static int msg_get_filled_locked(ipc_msg_queue_t *mq, msg_item_t **item_ptr)
{
	msg_item_t *item;
	int ret = 0;

	LTRACE_ENTRY;

	if (ipc_msg_queue_is_empty(mq)) {
		ret = ERR_NO_MSG;
		goto out;
	}

	item = list_peek_head_type(&mq->filled_list, msg_item_t, node);

	list_delete(&item->node);
	list_add_tail(&mq->read_list, &item->node);
	item->state = MSG_ITEM_STATE_READ;

	*item_ptr = item;

out:
	LTRACE_EXIT;
	return ret;
}

static int msg_put_read_locked(ipc_msg_queue_t *mq, uint32_t msg_id)
{
	msg_item_t *item = msg_queue_get_item(mq, msg_id);

	if (!item || item->state != MSG_ITEM_STATE_READ)
		return ERR_INVALID_ARGS;

	list_delete(&item->node);
	/* put it on the head since it was just taken off here */
	list_add_head(&mq->free_list, &item->node);
	item->state = MSG_ITEM_STATE_FREE;

	return 0;
}

/* *MUST ONLY EVER BE CALLED* if a failure occurs after do_get_filled_msg(),
 * since this puts the unprocessed mesasge back onto the filled list to be
 * picked up again.
 */
static void msg_return_to_filled_locked(ipc_msg_queue_t *mq, int msg_id)
{
	msg_item_t *item = msg_queue_get_item(mq, msg_id);

	assert(item);
	assert(item->state == MSG_ITEM_STATE_READ);

	list_delete(&item->node);
	/* put it on the head since it was just taken off here */
	list_add_head(&mq->filled_list, &item->node);
	item->state = MSG_ITEM_STATE_FILLED;
}

static int do_get_filled_msg(handle_t *chandle, ipc_msg_info_t *info)
{
	ipc_chan_t *chan = chandle->priv;
	msg_item_t *item;
	int ret;

	LTRACEF("getting message\n");

	mutex_acquire(&ipc_lock);
	if (chan->state != IPC_CHAN_STATE_CONNECTED) {
		if (chan->state == IPC_CHAN_STATE_DISCONNECTING)
			ret = ERR_CHANNEL_CLOSED;
		else
			ret = ERR_NOT_READY;
		goto err_not_connected;
	}

	ret = msg_get_filled_locked(chan->msg_queue, &item);
	if (ret)
		goto err_get;

	info->len = item->len;
	info->id = item->id;

	mutex_release(&ipc_lock);
	return ret;

err_get:
err_not_connected:
	mutex_release(&ipc_lock);
	return ret;
}

static int do_put_read_msg(handle_t *chandle, uint32_t msg_id)
{
	ipc_chan_t *chan = chandle->priv;
	int ret;

	LTRACEF("putting read message\n");

	mutex_acquire(&ipc_lock);
	if (chan->state != IPC_CHAN_STATE_CONNECTED) {
		if (chan->state == IPC_CHAN_STATE_DISCONNECTING)
			ret = ERR_CHANNEL_CLOSED;
		else
			ret = ERR_NOT_READY;
		goto err_not_connected;
	}

	ret = msg_put_read_locked(chan->msg_queue, msg_id);

err_not_connected:
	mutex_release(&ipc_lock);
	return ret;
}

static int do_send_msg(handle_t *chandle, msg_desc_t *msg)
{
	ipc_chan_t *chan = chandle->priv;
	ipc_chan_t *peer = chan->peer;
	int ret;

	LTRACEF("sending message\n");
	LTRACEF("  passing %d handles\n", msg->kern.num_handles);
	LTRACEF("  passing %d iov\n", msg->kern.num_iov);

	mutex_acquire(&ipc_lock);
	if (chan->state != IPC_CHAN_STATE_CONNECTED) {
		if (chan->state == IPC_CHAN_STATE_DISCONNECTING)
			ret = ERR_CHANNEL_CLOSED;
		else
			ret = ERR_NOT_READY;
		goto err_not_connected;
	}

	ret = msg_write_locked(peer->msg_queue, msg);
	if (ret < 0)
		goto err_msg_write;
	handle_notify(peer->handle);

	mutex_release(&ipc_lock);
	return ret;

err_msg_write:
err_not_connected:
	mutex_release(&ipc_lock);
	return ret;
}

long __SYSCALL sys_send_msg(int handle_id, user_addr_t user_msg)
{
	trusty_app_t *tapp = uthread_get_current()->private_data;
	uctx_t *ctx = tapp->uctx;
	handle_t *chandle;
	msg_desc_t tmp_msg;
	int ret;

	LTRACEF("%s:%d\n", __func__, __LINE__);
	ret = uctx_handle_get(ctx, handle_id, &chandle);
	if (ret)
		return ERR_BAD_HANDLE;

	LTRACEF("%s:%d\n", __func__, __LINE__);
	if (!ipc_is_channel(chandle)) {
		ret = ERR_INVALID_ARGS;
		goto out;
	}

	LTRACEF("%s:%d\n", __func__, __LINE__);
	if (_init_msg_user(&tmp_msg, user_msg)) {
		ret = ERR_FAULT;
		goto out;
	}
	LTRACEF("%s:%d\n", __func__, __LINE__);
	if (tmp_msg.user.num_handles) {
		/* FIXME: figure out what to do here */
		dprintf(CRITICAL, ">>>> SENDING HANDLES NOT SUPPORTED\n");
		tmp_msg.user.num_handles = 0;
	}

	ret = do_send_msg(chandle, &tmp_msg);
out:
	handle_decref(chandle);
	return ret;
}

int ipc_send_msg(handle_t *chandle, ipc_msg_kern_t *msg)
{
	msg_desc_t tmp_msg;

	if (!ipc_is_channel(chandle))
		return ERR_INVALID_ARGS;

	_init_msg_kernel(&tmp_msg, msg);

	if (tmp_msg.kern.num_handles) {
		/* FIXME: figure out what to do here */
		dprintf(CRITICAL, ">>>> SENDING HANDLES NOT SUPPORTED\n");
		tmp_msg.kern.num_handles = 0;
	}

	return do_send_msg(chandle, &tmp_msg);
}

static int do_read_msg(handle_t *chandle, uint32_t msg_id,
		       uint32_t offset, msg_desc_t *msg)
{
	ipc_chan_t *chan = chandle->priv;
	int ret;

	LTRACE_ENTRY;

	LTRACEF("receiving message @ offs %u\n", offset);
	LTRACEF("  passing %d iov\n", msg->kern.num_iov);

	mutex_acquire(&ipc_lock);
	if (chan->state != IPC_CHAN_STATE_CONNECTED) {
		ret = ERR_NOT_READY;
		goto err_not_connected;
	}

	ret = msg_read_locked(chan->msg_queue, msg_id, offset, msg);
	if (ret < 0)
		goto err_msg_add;

	mutex_release(&ipc_lock);
	LTRACE_EXIT;
	return ret;

err_msg_add:
err_not_connected:
	mutex_release(&ipc_lock);
	LTRACE_EXIT;
	return ret;
}

long __SYSCALL sys_get_msg(int handle_id, user_addr_t user_msg_info)
{
	trusty_app_t *tapp = uthread_get_current()->private_data;
	uctx_t *ctx = tapp->uctx;
	handle_t *handle;
	ipc_msg_info_t msg_info;
	int ret;

	LTRACE_ENTRY;

	ret = uctx_handle_get(ctx, handle_id, &handle);
	if (ret) {
		ret = ERR_BAD_HANDLE;
		goto out;
	}

	if (!ipc_is_channel(handle)) {
		ret = ERR_INVALID_ARGS;
		goto err;
	}

	ret = do_get_filled_msg(handle, &msg_info);
	if (ret)
		goto err;

	ret = copy_to_user(user_msg_info, &msg_info, sizeof(ipc_msg_info_t));
	if (ret < 0) {
		ipc_chan_t *chan = handle->priv;

		LTRACEF("returning message to filled after error\n");

		mutex_acquire(&ipc_lock);
		msg_return_to_filled_locked(chan->msg_queue, msg_info.id);
		mutex_release(&ipc_lock);
	}
err:
	handle_decref(handle);
out:
	LTRACE_EXIT;
	return ret;
}

int ipc_get_msg(handle_t *chandle, ipc_msg_info_t *msg_info)
{
	if (!ipc_is_channel(chandle))
		return ERR_INVALID_ARGS;

	return do_get_filled_msg(chandle, msg_info);
}

long __SYSCALL sys_put_msg(int handle_id, uint32_t msg_id)
{
	trusty_app_t *tapp = uthread_get_current()->private_data;
	uctx_t *ctx = tapp->uctx;
	handle_t *handle;
	int ret;

	LTRACE_ENTRY;

	ret = uctx_handle_get(ctx, handle_id, &handle);
	if (ret) {
		ret = ERR_BAD_HANDLE;
		goto out;
	}

	if (!ipc_is_channel(handle)) {
		ret = ERR_INVALID_ARGS;
		goto err;
	}

	ret = do_put_read_msg(handle, msg_id);
err:
	handle_decref(handle);
out:
	LTRACE_EXIT;
	return ret;
}

int ipc_put_msg(handle_t *chandle, uint32_t msg_id)
{
	if (!ipc_is_channel(chandle))
		return ERR_INVALID_ARGS;

	return do_put_read_msg(chandle, msg_id);
}

long __SYSCALL sys_read_msg(int handle_id, uint32_t msg_id, uint32_t offset,
			    user_addr_t user_msg)
{
	trusty_app_t *tapp = uthread_get_current()->private_data;
	uctx_t *ctx = tapp->uctx;
	handle_t *handle;
	msg_desc_t tmp_msg;
	int ret;

	LTRACE_ENTRY;

	ret = uctx_handle_get(ctx, handle_id, &handle);
	if (ret) {
		ret = ERR_BAD_HANDLE;
		goto out;
	}

	if (!ipc_is_channel(handle)) {
		ret = ERR_INVALID_ARGS;
		goto err;
	}
	if (_init_msg_user(&tmp_msg, user_msg)) {
		ret = ERR_FAULT;
		goto err;
	}
	if (tmp_msg.user.num_handles) {
		/* FIXME: figure out what to do here */
		dprintf(CRITICAL, ">>>> RECEIVING HANDLES NOT SUPPORTED\n");
		tmp_msg.user.num_handles = 0;
	}

	ret = do_read_msg(handle, msg_id, offset, &tmp_msg);
	if (ret >= 0) {
		int rc;
		rc = copy_to_user(user_msg, &tmp_msg.user, sizeof(ipc_msg_user_t));
		if (rc < 0)
			ret = rc;

		/* TODO: once we manage handles and we have an error
		 * copying the structs to userspace, we need to make sure to
		 * drop references to the handles here since userspace
		 * will get an error and would not know to do so.
		 */
	}

err:
	handle_decref(handle);
out:
	LTRACE_EXIT;
	return ret;
}

int ipc_read_msg(handle_t *chandle, uint32_t msg_id, uint32_t offset,
		 ipc_msg_kern_t *msg)
{
	msg_desc_t tmp_msg;
	int ret;

	if (!ipc_is_channel(chandle))
		return ERR_INVALID_ARGS;

	_init_msg_kernel(&tmp_msg, msg);

	if (tmp_msg.kern.num_handles) {
		/* FIXME: figure out what to do here */
		dprintf(CRITICAL, ">>>> RECEIVING HANDLES NOT SUPPORTED\n");
		tmp_msg.kern.num_handles = 0;
	}

	ret = do_read_msg(chandle, msg_id, offset, &tmp_msg);
	if (ret)
		return ret;
	memcpy(msg, &tmp_msg, sizeof(ipc_msg_kern_t));
	return 0;
}
