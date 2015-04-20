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

#include <assert.h>
#include <err.h>
#include <list.h>
#include <stdlib.h>
#include <string.h>
#include <trace.h>
#include <uthread.h>
#include <platform.h>

#include <lk/init.h>
#include <kernel/mutex.h>
#include <kernel/event.h>

#include <lib/syscall.h>

#include <lib/trusty/uuid.h>

#if WITH_TRUSTY_IPC

#include <lib/trusty/ipc.h>
#include <lib/trusty/trusty_app.h>
#include <lib/trusty/uctx.h>
#include <lib/trusty/tipc_dev.h>

static struct list_node ipc_port_list = LIST_INITIAL_VALUE(ipc_port_list);

mutex_t ipc_lock = MUTEX_INITIAL_VALUE(ipc_lock);

static event_t srv_event = EVENT_INITIAL_VALUE(srv_event, false, 0);

static uint32_t port_poll(handle_t *handle);
static void port_shutdown(handle_t *handle);
static void port_handle_destroy(handle_t *handle);

static uint32_t chan_poll(handle_t *handle);
static void chan_finalize_event(handle_t *handle, uint32_t event);
static void chan_shutdown(handle_t *handle);
static void chan_handle_destroy(handle_t *handle);

static ipc_port_t *port_find_locked(const char *path);
static void chan_shutdown_locked(ipc_chan_t *chan);

static struct handle_ops ipc_port_handle_ops = {
	.poll		= port_poll,
	.shutdown	= port_shutdown,
	.destroy	= port_handle_destroy,
};

static struct handle_ops ipc_chan_handle_ops = {
	.poll		= chan_poll,
	.finalize_event = chan_finalize_event,
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

/*
 *  Called by user task to create a new port at the given path.
 *  The returned handle will be later installed into uctx.
 */
int ipc_port_create(const uuid_t *sid, const char *path,
                    uint num_recv_bufs, size_t recv_buf_size,
                    uint32_t flags,  handle_t **phandle_ptr)
{
	ipc_port_t *new_port;
	handle_t *new_phandle;
	int ret = 0;

	LTRACEF("creating port (%s)\n", path);

	if (!sid) {
		/* server uuid is required */
		LTRACEF("server uuid is required\n");
		return ERR_INVALID_ARGS;
	}

	if (!num_recv_bufs || num_recv_bufs > IPC_CHAN_MAX_BUFS ||
	    !recv_buf_size || recv_buf_size > IPC_CHAN_MAX_BUF_SIZE) {
		LTRACEF("Invalid buffer sizes: %d x %ld\n",
		        num_recv_bufs, recv_buf_size);
		return ERR_INVALID_ARGS;
	}

	new_port = calloc(1, sizeof(ipc_port_t));
	if (!new_port) {
		LTRACEF("cannot allocate memory for port\n");
		return ERR_NO_MEMORY;
	}

	ret = strlcpy(new_port->path, path, sizeof(new_port->path));
	if (ret == 0) {
		LTRACEF("path is empty\n");
		ret = ERR_INVALID_ARGS;
		goto err_copy_path;
	}

	if ((uint) ret >= sizeof(new_port->path)) {
		LTRACEF("path is too long (%d)\n", ret);
		ret = ERR_TOO_BIG;
		goto err_copy_path;
	}

	new_port->uuid = sid;
	new_port->num_recv_bufs = num_recv_bufs;
	new_port->recv_buf_size = recv_buf_size;
	new_port->flags = flags;

	new_port->state = IPC_PORT_STATE_INVALID;
	list_initialize(&new_port->pending_list);

	ret = handle_alloc(&ipc_port_handle_ops, new_port, &new_phandle);
	if (ret) {
		LTRACEF("cannot allocate handle for port\n");
		goto err_handle_alloc;
	}

	LTRACEF("new port %p created (%s)\n", new_port, new_port->path);

	new_port->handle = new_phandle;
	*phandle_ptr = new_phandle;

	return NO_ERROR;

err_handle_alloc:
err_copy_path:
	free(new_port);
	return ret;
}


/*
 * Shutting down port
 *
 * Called by controlling handle gets closed.
 */
static void port_shutdown(handle_t *phandle)
{
	ASSERT(phandle);
	ASSERT(ipc_is_port(phandle));

	mutex_acquire(&ipc_lock);

	ipc_port_t *port = phandle->priv;

	LTRACEF("shutting down port %p\n", port);

	/* change status to closing  */
	port->state = IPC_PORT_STATE_CLOSING;

	/* detach it from global list if it is in the list */
	if (list_in_list(&port->node))
		list_delete(&port->node);

	/* tear down pending connections */
	ipc_chan_t *server = list_remove_head_type(&port->pending_list,
	                                           ipc_chan_t, node);
	while (server) {
		/* pending server channel in not in user context table
		   so we can just call shutdown and delete it. Client
		   side will be deleted  by the other side
		 */
		chan_shutdown_locked(server);
		handle_decref(server->handle);

		/* decrement usage count on port as pending connection
		   is gone
		 */
		handle_decref(phandle);

		/* get next pending connection */
		server = list_remove_head_type(&port->pending_list,
		                                ipc_chan_t, node);
	}

	mutex_release(&ipc_lock);
}

/*
 * Destroy port controlled by handle
 *
 * Called when controlling handle refcount reaches 0.
 */
static void port_handle_destroy(handle_t *phandle)
{
	ASSERT(phandle);
	ASSERT(ipc_is_port(phandle));

	ipc_port_t *port = phandle->priv;
	DEBUG_ASSERT(port);

	/* pending list should be empty and
	   node should not be in the list
	 */
	DEBUG_ASSERT(list_is_empty(&port->pending_list));
	DEBUG_ASSERT(!list_in_list(&port->node));

	LTRACEF("destroying port %p ('%s')\n", port, port->path);

	/* mark it as invalid */
	port->state = IPC_PORT_STATE_INVALID;

	/* detach handle from port */
	port->handle  = NULL;

	free(port);
}

/*
 *   Make specified port publically available for operation.
 */
static int ipc_port_publish(handle_t *phandle)
{
	int ret = NO_ERROR;

	DEBUG_ASSERT(phandle);
	DEBUG_ASSERT(ipc_is_port(phandle));

	mutex_acquire(&ipc_lock);

	ipc_port_t *port = phandle->priv;
	DEBUG_ASSERT(port);
	DEBUG_ASSERT(!list_in_list(&port->node));

	/* Check for duplicates */
	if (port_find_locked(port->path)) {
		LTRACEF("path already exists\n");
		ret = ERR_ALREADY_EXISTS;
	} else {
		port->state = IPC_PORT_STATE_LISTENING;
		list_add_tail(&ipc_port_list, &port->node);
		/* kick all threads that are waiting for services */
		event_signal(&srv_event, false);
		event_unsignal(&srv_event);
	}
	mutex_release(&ipc_lock);

	return ret;
}


/*
 *  Called by user task to create new port.
 *
 *  On success - returns handle id (small integer) for the new port.
 *  On error   - returns negative error code.
 */
long __SYSCALL sys_port_create(user_addr_t path, uint num_recv_bufs,
                               size_t recv_buf_size, uint32_t flags)
{
	uthread_t *ut = uthread_get_current();
	trusty_app_t *tapp = ut->private_data;
	uctx_t *ctx = current_uctx();
	handle_t *port_handle = NULL;
	int ret;
	handle_id_t handle_id;
	char tmp_path[IPC_PORT_PATH_MAX];

	/* copy path from user space */
	ret = (int) strncpy_from_user(tmp_path, path, sizeof(tmp_path));
	if (ret < 0)
		return (long) ret;

	if ((uint)ret >= sizeof(tmp_path)) {
		/* string is too long */
		return ERR_INVALID_ARGS;
	}

	/* create new port */
	ret = ipc_port_create(&tapp->props.uuid, tmp_path,
		              (uint) num_recv_bufs, recv_buf_size,
		              flags, &port_handle);
	if (ret != NO_ERROR)
		goto err_port_create;

	/* install handle into user context */
	ret = uctx_handle_install(ctx, port_handle, &handle_id);
	if (ret != NO_ERROR)
		goto err_install;

	/* publish for normal operation */
	ret = ipc_port_publish(port_handle);
	if (ret != NO_ERROR)
		goto err_publish;

	return (long) handle_id;

err_publish:
	(void) uctx_handle_remove(ctx, handle_id, &port_handle);
err_install:
	handle_decref(port_handle);
err_port_create:
	return (long) ret;
}

/*
 *  Look up and port with given name (ipc_lock must be held)
 */
static ipc_port_t *port_find_locked(const char *path)
{
	ipc_port_t *port;

	list_for_every_entry(&ipc_port_list, port, ipc_port_t, node) {
		if (!strcmp(path, port->path))
			return port;
	}
	return NULL;
}

static uint32_t port_poll(handle_t *phandle)
{
	DEBUG_ASSERT(phandle);
	DEBUG_ASSERT(ipc_is_port(phandle));

	ipc_port_t *port = phandle->priv;
	uint32_t events = 0;

	mutex_acquire(&ipc_lock);
	if (port->state != IPC_PORT_STATE_LISTENING)
		events |= IPC_HANDLE_POLL_ERROR;
	else if (!list_is_empty(&port->pending_list))
		events |= IPC_HANDLE_POLL_READY;
	LTRACEF("%s in state %d events %x\n", port->path, port->state, events);
	mutex_release(&ipc_lock);

	return events;
}

/*
 *  Allocate and initialize new channel.
 */
static ipc_chan_t *chan_alloc(uint32_t init_state, uint32_t flags,
                              uint num_bufs, size_t buf_size)
{
	ipc_chan_t *chan;
	handle_t *chandle;
	int ret;

	chan = calloc(1, sizeof(ipc_chan_t));
	if (!chan) {
		TRACEF("cannot allocate memory for channel\n");
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

static void chan_shutdown_locked(ipc_chan_t *chan)
{
	LTRACEF("chan %p: peer %p\n", chan, chan->peer);

	if (chan->state == IPC_CHAN_STATE_DISCONNECTING)
		return;

	chan->state = IPC_CHAN_STATE_DISCONNECTING;
	handle_notify(chan->handle);

	ipc_chan_t *peer = chan->peer;
	if (peer) {
		peer->state = IPC_CHAN_STATE_DISCONNECTING;
		peer->peer = NULL;
		chan->peer = NULL;
		handle_notify(peer->handle);
	}
}

/*
 *  Called when caller closes handle.
 */
static void chan_shutdown(handle_t *chandle)
{
	DEBUG_ASSERT(chandle);
	DEBUG_ASSERT(ipc_is_channel(chandle));

	mutex_acquire(&ipc_lock);

	ipc_chan_t *chan = chandle->priv;
	DEBUG_ASSERT(chan);

	chan_shutdown_locked(chan);

	mutex_release(&ipc_lock);
}

static void chan_handle_destroy(handle_t *chandle)
{
	DEBUG_ASSERT(chandle);
	DEBUG_ASSERT(ipc_is_channel(chandle));

	ipc_chan_t *chan = chandle->priv;
	DEBUG_ASSERT(chan);

	LTRACEF("chan = %p\n", chan);

	/* should not point to peer */
	DEBUG_ASSERT(chan->peer == NULL);

	if (chan->msg_queue) {
		ipc_msg_queue_destroy(chan->msg_queue);
		chan->msg_queue = NULL;
	}
	free(chan);
}

/*
 *  Poll channel state
 */
static uint32_t chan_poll(handle_t *chandle)
{
	DEBUG_ASSERT(chandle);
	DEBUG_ASSERT(ipc_is_channel(chandle));

	/* TODO: finer locking? */
	mutex_acquire(&ipc_lock);

	ipc_chan_t *chan = chandle->priv;
	DEBUG_ASSERT(chan);

	uint32_t events = 0;

	if (chan->state == IPC_CHAN_STATE_INVALID) {
		/* channel is in invalid state */
		events |= IPC_HANDLE_POLL_ERROR;
		goto done;
	}

	/*  peer is closing connection */
	if (chan->state == IPC_CHAN_STATE_DISCONNECTING || chan->peer == NULL) {
		events |= IPC_HANDLE_POLL_HUP;
	}

	/* server accepted our connection */
	if (chan->state == IPC_CHAN_STATE_CONNECTING &&
	    chan->peer->state == IPC_CHAN_STATE_CONNECTED) {
		events |= IPC_HANDLE_POLL_READY;
	}

	/* have a pending message? */
	if (!ipc_msg_queue_is_empty(chan->msg_queue)) {
		events |= IPC_HANDLE_POLL_READY | IPC_HANDLE_POLL_MSG;
	}

	/* check if we were send blocked */
	if (chan->aux_state & IPC_CHAN_AUX_STATE_SEND_UNBLOCKED) {
		events |= IPC_HANDLE_POLL_SEND_UNBLOCKED;
	}

done:
	mutex_release(&ipc_lock);
	return events;
}

static void chan_finalize_event(handle_t *chandle, uint32_t event)
{
	DEBUG_ASSERT(chandle);
	DEBUG_ASSERT(ipc_is_channel(chandle));

	if (event & IPC_HANDLE_POLL_SEND_UNBLOCKED) {
		mutex_acquire(&ipc_lock);
		ipc_chan_t *chan = chandle->priv;
		chan->aux_state &= ~IPC_CHAN_AUX_STATE_SEND_UNBLOCKED;
		mutex_release(&ipc_lock);
	}
}

/*
 *  Lookup an existing port or wait for up to specified timeout
 */
static ipc_port_t *wait_for_port_locked(const char * path, lk_time_t timeout)
{
	lk_time_t elapsed = 0;
	lk_time_t start_ts = current_time();

	for (;;) {
		ipc_port_t *port = port_find_locked(path);
		if (port)
			return port;

		if (elapsed >= timeout)
			return NULL;

		/* wait for port to become available */
		mutex_release(&ipc_lock);
		event_wait_timeout (&srv_event, timeout - elapsed);
		mutex_acquire(&ipc_lock);

		if (timeout != INFINITE_TIME) {
			/* keep track of elapsed time */
			elapsed = current_time() - start_ts;
		}
	}
}


/*
 *  Check if connection to specified port is allowed
 */
static int check_access(ipc_port_t *port, const uuid_t *uuid)
{
	if (!uuid)
		return ERR_ACCESS_DENIED;

	if (is_ns_client(uuid)) {
		/* check if this port allows connection from NS clients */
		if (port->flags & IPC_PORT_ALLOW_NS_CONNECT)
			return NO_ERROR;
	} else {
		/* check if this port allows connection from Trusted Apps */
		if (port->flags & IPC_PORT_ALLOW_TA_CONNECT)
			return NO_ERROR;
	}

	return ERR_ACCESS_DENIED;
}

/*
 * Client requests a connection to a port. It can be called in context
 * of user task as well as vdev RX thread.
 */
int ipc_port_connect(const uuid_t *cid, const char *path, size_t max_path,
                     lk_time_t timeout, handle_t **chandle_ptr)
{
	ipc_port_t *port;
	ipc_chan_t *client = NULL;
	ipc_chan_t *server = NULL;
	int ret;
	uint32_t client_event = 0;

	if (!cid) {
		/* client uuid is required */
		LTRACEF("client uuid is required\n");
		return ERR_INVALID_ARGS;
	}

	if (strnlen(path, max_path) >= max_path) {
		/* unterminated string */
		LTRACEF("invalid path specified\n");
		return ERR_INVALID_ARGS;
	}
	/* After this point path is zero terminated */

	LTRACEF("Connecting to '%s'\n", path);

	mutex_acquire(&ipc_lock);

	/* lookup an existing port */
	port = wait_for_port_locked(path, timeout);
	if (!port) {
		LTRACEF("cannot find port '%s'\n", path);
		ret = ERR_NOT_FOUND;
		goto err_find_ports;
	}

	/* found  */
	if (port->state != IPC_PORT_STATE_LISTENING) {
		LTRACEF("port %s is not in listening state (%d)\n",
		         path, port->state);
		ret = ERR_NOT_READY;
		goto err_state;
	}

	/* check if we are allowed to connect */
	ret = check_access(port, cid);
	if (ret != NO_ERROR) {
		LTRACEF("access denied: %d\n", ret);
		goto err_access;
	}

	/* allocate client channel */
	client = chan_alloc(IPC_CHAN_STATE_CONNECTING, 0,
			    port->num_recv_bufs, port->recv_buf_size);
	if (!client) {
		ret = ERR_NO_MEMORY;
		goto err_chan_alloc;
	}

	/* allocate server channel */
	server = chan_alloc(IPC_CHAN_STATE_ACCEPTING, IPC_CHAN_FLAG_SERVER,
			    port->num_recv_bufs, port->recv_buf_size);
	if (!server) {
		handle_decref(client->handle);
		ret = ERR_NO_MEMORY;
		goto err_chan_alloc;
	}

	/* attach identity */
	client->uuid = cid;
	server->uuid = port->uuid;

	/* tie them together */
	client->peer = server;
	server->peer = client;

	LTRACEF("new connection: client %p: peer %p\n", client, server);

	/* and add them to pending connection list */
	list_add_tail(&port->pending_list, &server->node);

	/* bump a ref to the port while there's a pending connection */
	handle_incref(port->handle);

	/* Notify port that there is a pending connection */
	handle_notify(port->handle);

	mutex_release(&ipc_lock);

	/* now we wait for server to accept */
	/* TODO: should we figure out how to not wait here but wait
	 * for an event later?
	 */
	ret = handle_wait(client->handle, &client_event, timeout);

	mutex_acquire(&ipc_lock);

	if (ret < 0) {
		/* The only reason it could happen besides memory corruption
		 * is if someone is waiting on client handle in context of the
		 * other thread which is a gross non user task programming error.
		 */
		panic ("failed (%d) to wait for connection\n", ret);
	}

	if (ret == 0 || !(client_event & IPC_HANDLE_POLL_READY)) {
		/* it is either server timed out (ret == 0) or
		   peer channel is not in connected state (maybe server closed
		   or refused to accept connection). */
		LTRACEF("error while waiting for server (ret %d event=0x%x)\n",
			ret, client_event);

		/* tear down connection  */
		chan_shutdown_locked (client);

		/* destroy client channel. server channel will be destroyed by server */
		handle_decref(client->handle);

		if (ret == 0) {
			/* server failed to respond in time */
			ret = ERR_TIMED_OUT;
		} else {
			if (client_event & IPC_HANDLE_POLL_HUP) {
				/* connection closed by peer */
				ret = ERR_CHANNEL_CLOSED;
			} else {
				/* port in some sort of error state */
				ret = ERR_NOT_READY;
			}
		}

		goto err_wait;
	}

	/* success */
	client->state = IPC_CHAN_STATE_CONNECTED;

	mutex_release(&ipc_lock);

	*chandle_ptr = client->handle;

	return NO_ERROR;

err_wait:
err_chan_alloc:
err_access:
err_state:
err_find_ports:
	mutex_release(&ipc_lock);
	return ret;
}

/* returns handle id for the new channel */
long __SYSCALL sys_connect(user_addr_t path, unsigned long timeout_msecs)
{
	uthread_t *ut = uthread_get_current();
	trusty_app_t *tapp = ut->private_data;
	uctx_t *ctx = current_uctx();
	handle_t *chandle;
	char tmp_path[IPC_PORT_PATH_MAX];
	int ret;
	handle_id_t handle_id;

	ret = (int) strncpy_from_user(tmp_path, path, sizeof(tmp_path));
	if (ret < 0)
		return (long) ret;

	if ((uint)ret >= sizeof(tmp_path))
		return (long) ERR_INVALID_ARGS;

	ret = ipc_port_connect(&tapp->props.uuid, tmp_path, sizeof(tmp_path),
                               timeout_msecs, &chandle);
	if (ret != NO_ERROR)
		return (long) ret;

	ret = uctx_handle_install(ctx, chandle, &handle_id);
	if (ret != NO_ERROR) {
		/* Failed to install handle into user context */
		handle_close(chandle);
		return (long) ret;
	}

	return (long) handle_id;
}

/*
 *  Called by user task to accept incomming connection
 */
int ipc_port_accept(handle_t *phandle, handle_t **chandle_ptr,
                    const uuid_t **uuid_ptr)
{
	ipc_port_t *port = phandle->priv;
	ipc_chan_t *server = NULL;
	ipc_chan_t *client = NULL;
	int ret = NO_ERROR;

	DEBUG_ASSERT(chandle_ptr);
	DEBUG_ASSERT(uuid_ptr);

	if (!phandle || !ipc_is_port(phandle)) {
		LTRACEF("invalid port handle %p\n", phandle);
		return ERR_INVALID_ARGS;
	}

	mutex_acquire(&ipc_lock);

	if (port->state != IPC_PORT_STATE_LISTENING) {
		/* Not in listening state: caller should close port.
		 * is it really possible to get here?
		 */
		ret = ERR_CHANNEL_CLOSED;
		goto err;
	}

	/* get next pending connection */
	server = list_remove_head_type(&port->pending_list, ipc_chan_t, node);
	if (!server) {
		/* TODO: should we block waiting for a new connection if one
		 * is not pending? if so, need an optional argument maybe.
		 */
		ret = ERR_NO_MSG;
		goto err;
	}

	/* it must be a server side channel */
	DEBUG_ASSERT(server->flags & IPC_CHAN_FLAG_SERVER);

	/* drop the ref to port we took in connect() */
	handle_decref(port->handle);

	client = server->peer;

	/* there must be a client, it must be in CONNECTING state and
	   server must be in ACCEPTING state */
	if (!client ||
	    server->state != IPC_CHAN_STATE_ACCEPTING ||
	    client->state != IPC_CHAN_STATE_CONNECTING) {
		LTRACEF("Drop connection: client %p (0x%x) to server %p (0x%x):\n",
			client, client ? client->state : 0xDEADBEEF,
			server, server->state);
		chan_shutdown_locked(server);
		handle_decref(server->handle);
		ret = ERR_CHANNEL_CLOSED;
		goto err;
	}

	server->state = IPC_CHAN_STATE_CONNECTED;
	/* Note: we let client transition itself, so it can poll on this
	 * condition
	 */
	handle_notify(client->handle);

	*chandle_ptr = server->handle;
	*uuid_ptr = client->uuid;

	ret = NO_ERROR;
err:
	mutex_release(&ipc_lock);

	return ret;
}

long __SYSCALL sys_accept(uint32_t handle_id, user_addr_t user_uuid)
{
	uctx_t *ctx = current_uctx();
	handle_t *phandle = NULL;
	handle_t *chandle = NULL;
	int ret;
	handle_id_t new_id;
	const uuid_t *peer_uuid_ptr;

	ret = uctx_handle_get(ctx, handle_id, &phandle);
	if (ret != NO_ERROR)
		return (long) ret;

	ret = ipc_port_accept(phandle, &chandle, &peer_uuid_ptr);
	if (ret != NO_ERROR)
		goto err_accept;

	ret = uctx_handle_install(ctx, chandle, &new_id);
	if (ret != NO_ERROR)
		goto err_install;

	/* copy peer uuid into userspace */
	ret = copy_to_user(user_uuid, peer_uuid_ptr, sizeof(uuid_t));
	if (ret != NO_ERROR)
		goto err_uuid_copy;

	handle_decref(phandle);
	return (long) new_id;

err_uuid_copy:
	uctx_handle_remove(ctx, new_id, &chandle);
err_install:
	handle_close(chandle);
err_accept:
	handle_decref(phandle);
	return (long) ret;
}

#else /* WITH_TRUSTY_IPC */

long __SYSCALL sys_port_create(user_addr_t path, uint num_recv_bufs,
                               size_t recv_buf_size, uint32_t flags)
{
	return (long) ERR_NOT_SUPPORTED;
}

long __SYSCALL sys_connect(user_addr_t path, unsigned long timeout_msecs)
{
	return (long) ERR_NOT_SUPPORTED;
}

long __SYSCALL sys_accept(uint32_t handle_id, uuid_t *peer_uuid)
{
	return (long) ERR_NOT_SUPPORTED;
}

#endif /* WITH_TRUSTY_IPC */

