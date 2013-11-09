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

#include <err.h>
#include <list.h>
#include <stdlib.h>
#include <string.h>
#include <trace.h>
#include <uthread.h>

#include <lk/init.h>
#include <kernel/mutex.h>

#include <lib/syscall.h>
#include <lib/trusty/ipc.h>
#include <lib/trusty/trusty_app.h>
#include <lib/trusty/uctx.h>

static struct list_node ipc_port_list = LIST_INITIAL_VALUE(ipc_port_list);

mutex_t ipc_lock = MUTEX_INITIAL_VALUE(ipc_lock);

static uint32_t port_poll(handle_t *handle);
static void port_handle_destroy(handle_t *handle);
static uint32_t chan_poll(handle_t *handle);
static void chan_shutdown(handle_t *handle);
static void chan_handle_destroy(handle_t *handle);

static struct handle_ops ipc_port_handle_ops = {
	.poll		= port_poll,
	.destroy	= port_handle_destroy,
};

static struct handle_ops ipc_chan_handle_ops = {
	.poll		= chan_poll,
	.shutdown	= chan_shutdown,
	.destroy	= chan_handle_destroy,
};

bool ipc_is_channel(handle_t *handle)
{
	return likely(handle->ops == &ipc_chan_handle_ops);
}

bool ipc_is_port(handle_t *handle)
{
	return likely(handle->ops == &ipc_port_handle_ops);
}

/* server allocates a new port at the given path */
int ipc_port_create(const char *path, int num_recv_bufs,
		    size_t recv_buf_size, uint32_t flags,
		    handle_t **phandle_ptr)
{
	ipc_port_t *new_port;
	handle_t *new_phandle;
	int ret = 0;

	if (num_recv_bufs > IPC_CHAN_MAX_BUFS ||
	    recv_buf_size > IPC_CHAN_MAX_BUF_SIZE)
		return ERR_INVALID_ARGS;

	new_port = calloc(1, sizeof(ipc_port_t));
	if (!new_port) {
		dprintf(INFO, "cannot allocate memory for port\n");
		return ERR_NO_MEMORY;
	}

	ret = strlcpy(new_port->path, path, IPC_PORT_PATH_MAX);
	if (ret > IPC_PORT_PATH_MAX) {
		dprintf(INFO, "path too long\n");
		ret = ERR_TOO_BIG;
		goto err_copy_path;
	}

	new_port->num_recv_bufs = num_recv_bufs;
	new_port->recv_buf_size = recv_buf_size;
	new_port->flags = flags;

	new_port->state = IPC_PORT_STATE_LISTENING;
	list_initialize(&new_port->pending_list);
	refcount_init(&new_port->refcount);

	ret = handle_alloc(&ipc_port_handle_ops, new_port, &new_phandle);
	if (ret) {
		dprintf(INFO, "cannot add port to context\n");
		goto err_handle_alloc;
	}

	new_port->handle = new_phandle;

	/* this is needed so we can find the right port in the global list */
	mutex_acquire(&ipc_lock);
	list_add_tail(&ipc_port_list, &new_port->node);
	mutex_release(&ipc_lock);

	*phandle_ptr = new_phandle;

	return NO_ERROR;

err_handle_alloc:
err_copy_path:
	free(new_port);
	return ret;
}

static void __port_destroy(refcount_t *ref)
{
	ipc_port_t *port = containerof(ref, ipc_port_t, refcount);

	LTRACEF("destroying port %p '%s'\n", port, port->path);
	free(port);
}

void port_incref(ipc_port_t *port)
{
	refcount_inc(&port->refcount);
	LTRACEF("taking ref on port %p\n", port);
}

void port_decref(ipc_port_t *port)
{
	refcount_dec(&port->refcount, __port_destroy);
	LTRACEF("dropping ref on port %p\n", port);
}

/* TODO: we need a port_shutdown handle op so that the owner can indicate
 * that the port is closing, and not rely on handle refs to signal that.
 */

/* takes the ipc_lock, be careful when releasing handles as they
 * can end up in here with badness.
 */
static void port_handle_destroy(handle_t *phandle)
{
	ipc_port_t *port = phandle->priv;

	ASSERT(ipc_is_port(phandle));

	LTRACEF("destroying handle to port '%s'\n", port->path);

	/* someone could have looked the port up in the ipc_ports_list and
	 * bumped the port back up, so we may not actually free the port
	 * here
	 */
	mutex_acquire(&ipc_lock);
	list_delete(&port->node);
	port->state = IPC_PORT_STATE_CLOSING;
	mutex_release(&ipc_lock);

	port_decref(port);
}

/* returns handle id for the new port */
long __SYSCALL sys_port_create(user_addr_t path, int num_recv_bufs,
			       size_t recv_buf_size, uint32_t flags)
{
	trusty_app_t *tapp = uthread_get_current()->private_data;
	uctx_t *ctx = tapp->uctx;
	handle_t *phandle;
	int ret;
	int handle_id;
	char tmp_path[IPC_PORT_PATH_MAX];

	if (strlcpy_from_user(tmp_path, path, IPC_PORT_PATH_MAX))
		return ERR_FAULT;

	ret = ipc_port_create(tmp_path, num_recv_bufs, recv_buf_size,
			      flags, &phandle);
	if (ret != NO_ERROR)
		goto err_port_create;

	ret = uctx_handle_install(ctx, phandle, &handle_id);
	if (ret != NO_ERROR)
		goto err_install;

	return handle_id;

err_install:
	handle_decref(phandle);
err_port_create:
	return ret;
}

/* assumes ipc_lock is held */
static ipc_port_t *port_find_locked(const char *path)
{
	ipc_port_t *port;

	list_for_every_entry(&ipc_port_list, port, ipc_port_t, node) {
		if (!strcmp(path, port->path))
			return port;
	}
	return NULL;
}

/* assumes ipc_lock is held */
static int port_add_pending_locked(ipc_port_t *port, ipc_chan_t *chan)
{
	list_add_tail(&port->pending_list, &chan->node);
	handle_notify(port->handle);
	return 0;
}

static uint32_t port_poll(handle_t *handle)
{
	ipc_port_t *port = handle->priv;
	uint32_t events = 0;

	if (!ipc_is_port(handle)) {
		dprintf(CRITICAL, "invalid handle %p to port\n", handle);
		return 0;
	}

	mutex_acquire(&ipc_lock);
	if (port->state != IPC_PORT_STATE_LISTENING)
		events |= IPC_HANDLE_POLL_ERROR;
	else if (!list_is_empty(&port->pending_list))
		events |= IPC_HANDLE_POLL_READY;
	LTRACEF("%s in state %d events %x\n", port->path, port->state, events);
	mutex_release(&ipc_lock);

	return events;
}

static ipc_chan_t *chan_alloc(uint32_t init_state, uint32_t flags,
			      int num_bufs, size_t buf_size)
{
	ipc_chan_t *chan;
	handle_t *chandle;
	int ret;

	chan = calloc(1, sizeof(ipc_chan_t));
	if (!chan) {
		dprintf(INFO, "cannot allocate memory for channel\n");
		return NULL;
	}

	ret = ipc_msg_queue_create(num_bufs, buf_size, &chan->msg_queue);
	if (ret != NO_ERROR)
		goto err_mq_init;

	chan->state = init_state;
	chan->flags = flags;

	ret = handle_alloc(&ipc_chan_handle_ops, chan, &chandle);
	if (ret != NO_ERROR)
		goto err_handle_alloc;

	chan->handle = chandle;
	return chan;

err_handle_alloc:
	ipc_msg_queue_destroy(chan->msg_queue);
err_mq_init:
	free(chan);
	return NULL;
}

static void chan_shutdown_locked(handle_t *handle)
{
	ipc_chan_t *chan = handle->priv;
	ipc_chan_t *peer = chan->peer;

	if (chan->state == IPC_CHAN_STATE_DISCONNECTING)
		return;

	chan->state = IPC_CHAN_STATE_DISCONNECTING;
	handle_notify(chan->handle);
	if (peer) {
		peer->state = IPC_CHAN_STATE_DISCONNECTING;
		peer->peer = NULL;
		chan->peer = NULL;
		handle_notify(peer->handle);
	}
}

static void chan_shutdown(handle_t *handle)
{
	LTRACE_ENTRY;
	mutex_acquire(&ipc_lock);
	chan_shutdown_locked(handle);
	mutex_release(&ipc_lock);
	LTRACE_EXIT;
}

/* Note: be careful when destroying handles to channels in other places.
 * Ensure that the ipc lock is not held since this function needs it.
 */
static void chan_handle_destroy(handle_t *handle)
{
	ipc_chan_t *chan = handle->priv;

	LTRACE_ENTRY;
	mutex_acquire(&ipc_lock);
	chan_shutdown_locked(handle);
	if (chan->msg_queue)
		ipc_msg_queue_destroy(chan->msg_queue);
	free(chan);
	mutex_release(&ipc_lock);
	LTRACE_EXIT;
}

static uint32_t chan_poll(handle_t *handle)
{
	ipc_chan_t *chan = handle->priv;
	uint32_t events = 0;

	/* TODO: finer locking? */
	mutex_acquire(&ipc_lock);

	/* server accepted our connection */
	if (chan->state == IPC_CHAN_STATE_CONNECTING &&
	    chan->peer->state == IPC_CHAN_STATE_CONNECTED)
		events |= IPC_HANDLE_POLL_READY;
	if (chan->state == IPC_CHAN_STATE_DISCONNECTING || chan->peer == NULL)
		events |= IPC_HANDLE_POLL_HUP;

	/* have a pending message? */
	if (!ipc_msg_queue_is_empty(chan->msg_queue))
		events |= IPC_HANDLE_POLL_READY | IPC_HANDLE_POLL_MSG;

	mutex_release(&ipc_lock);
	return events;
}

/* client requests a connection to a port */
int ipc_port_connect(const char *path, lk_time_t timeout, handle_t **chandle_ptr)
{
	ipc_port_t *port;
	ipc_chan_t *client = NULL;
	ipc_chan_t *server = NULL;
	int ret;
	uint32_t client_event;

	mutex_acquire(&ipc_lock);
	port = port_find_locked(path);
	if (!port) {
		LTRACEF("cannot find port %s\n", path);
		ret = ERR_NOT_FOUND;
		goto err_find_ports;
	}

	if (port->state != IPC_PORT_STATE_LISTENING) {
		LTRACEF("port not in listening state (%d)\n", port->state);
		ret = ERR_NOT_READY;
		goto err_state;
	}

	client = chan_alloc(IPC_CHAN_STATE_CONNECTING, 0,
			    port->num_recv_bufs, port->recv_buf_size);
	server = chan_alloc(IPC_CHAN_STATE_ACCEPTING, IPC_CHAN_FLAG_SERVER,
			    port->num_recv_bufs, port->recv_buf_size);
	if (!client || !server) {
		ret = ERR_NO_MEMORY;
		goto err_chan_alloc;
	}

	client->peer = server;
	server->peer = client;

	/* pending connection
	 *   - server's channel sits in the port pending connection
	 *     list and is not added to the ctx' handle list until accepted.
	 *   - client's channel gets allocated a handle and added to the ctx
	 */
	ret = port_add_pending_locked(port, server);
	if (ret) {
		LTRACEF("couldn't add server channel to port pending list (%d)\n",
			ret);
		goto err_add_pending;
	}
	/* hold a ref to the port while there's a pending connection */
	port_incref(port);

	mutex_release(&ipc_lock);

	/* now we wait for server to accept */
	/* TODO: should we figure out how to not wait here but wait
	 * for an event later?
	 */
	ret = handle_wait(client->handle, &client_event, timeout);

	mutex_acquire(&ipc_lock);

	if (ret <= 0 || !(client_event & IPC_HANDLE_POLL_READY)) {
		LTRACEF("error while waiting for server (ret %d event=0x%x)\n",
			ret, client_event);
		/* had an error, need to tear down */
		goto err_wait;
	}

	client->state = IPC_CHAN_STATE_CONNECTED;

	mutex_release(&ipc_lock);

	*chandle_ptr = client->handle;

	return NO_ERROR;

err_wait:
	port_decref(port);
	/* TODO: tear down connection */
err_add_pending:
	/* TODO: remove chan from client ctx somehow! */
err_chan_alloc:
err_state:
err_find_ports:
	mutex_release(&ipc_lock);
	/* dec the refs on the new channels after dropping the lock
	 * since the destructors take the lock */
	if (client)
		handle_decref(client->handle);
	if (server)
		handle_decref(server->handle);
	return ret;
}

/* returns handle id for the new port */
long __SYSCALL sys_connect(user_addr_t path, unsigned long timeout_msecs)
{
	trusty_app_t *tapp = uthread_get_current()->private_data;
	uctx_t *ctx = tapp->uctx;
	handle_t *chandle;
	char tmp_path[IPC_PORT_PATH_MAX];
	int ret;
	int handle_id;

	if (strlcpy_from_user(tmp_path, path, IPC_PORT_PATH_MAX))
		return ERR_FAULT;

	ret = ipc_port_connect(tmp_path, MSECS_TO_LK_TIME(timeout_msecs),
			       &chandle);
	if (ret != NO_ERROR)
		goto err_connect;

	ret = uctx_handle_install(ctx, chandle, &handle_id);
	if (ret != NO_ERROR)
		goto err_install;

	return handle_id;

err_install:
	handle_decref(chandle);
err_connect:
	return ret;
}

int ipc_port_accept(handle_t *phandle, handle_t **chandle_ptr)
{
	ipc_port_t *port = phandle->priv;
	ipc_chan_t *server = NULL;
	ipc_chan_t *client = NULL;
	int ret = NO_ERROR;

	if (!ipc_is_port(phandle)) {
		dprintf(CRITICAL, "invalid port handle %p\n", phandle);
		return ERR_INVALID_ARGS;
	}

	mutex_acquire(&ipc_lock);
	if (port->state != IPC_PORT_STATE_LISTENING) {
		ret = ERR_CHANNEL_CLOSED;
		goto err;
	}

	/* TODO: should we block waiting for a new connection if one
	 * is not pending? if so, need an optional argument maybe.
	 */
	server = list_remove_head_type(&port->pending_list, ipc_chan_t, node);
	if (!server) {
		ret = ERR_NO_MSG;
		goto err;
	}

	/* drop the ref the client took in connect() */
	port_decref(port);

	client = server->peer;

	if (!client ||
	    server->state != IPC_CHAN_STATE_ACCEPTING ||
	    client->state != IPC_CHAN_STATE_CONNECTING) {
		ret = ERR_CHANNEL_CLOSED;
		goto err;
	}

	server->state = IPC_CHAN_STATE_CONNECTED;
	/* Note: we let client transition itself, so it can poll on this
	 * condition
	 */

	handle_notify(client->handle);

	mutex_release(&ipc_lock);

	*chandle_ptr = server->handle;

	return NO_ERROR;

err:
	mutex_release(&ipc_lock);
	if (server)
		handle_decref(server->handle);
	return ret;
}

long __SYSCALL sys_accept(int handle_id)
{
	trusty_app_t *tapp = uthread_get_current()->private_data;
	uctx_t *ctx = tapp->uctx;
	handle_t *phandle;
	handle_t *new_chandle;
	int ret;
	int new_id;

	ret = uctx_handle_get(ctx, handle_id, &phandle);
	if (ret)
		return ERR_INVALID_ARGS;

	ret = ipc_port_accept(phandle, &new_chandle);
	if (ret != NO_ERROR)
		goto err_accept;

	ret = uctx_handle_install(ctx, new_chandle, &new_id);
	if (ret != NO_ERROR)
		goto err_install;

	handle_decref(phandle);
	return new_id;

err_install:
	handle_decref(new_chandle);
err_accept:
	handle_decref(phandle);
	return ret;
}
