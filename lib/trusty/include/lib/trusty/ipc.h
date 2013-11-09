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

#ifndef __LIB_TRUSTY_IPC_H
#define __LIB_TRUSTY_IPC_H

#include <bits.h>
#include <kernel/mutex.h>
#include <kernel/thread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include <lib/trusty/handle.h>
#include <lib/trusty/ipc_msg.h>

enum {
	IPC_PORT_STATE_INVALID		= 0,
	IPC_PORT_STATE_LISTENING	= 1,
	IPC_PORT_STATE_CLOSING		= 2,
};

enum {
	IPC_PORT_NOTIFY_CREATE		= 1,
	IPC_PORT_NOTIFY_DESTROY		= 2,
};

#define IPC_PORT_PATH_MAX	64

typedef struct ipc_port {
	/* e.g. /service/sys/crypto, /service/usr/drm/widevine */
	char			path[IPC_PORT_PATH_MAX];
	/* TODO: need a uuid too? */

	uint32_t		state;
	uint32_t		flags;

	int			num_recv_bufs;
	size_t			recv_buf_size;

	handle_t		*handle;

	/* TODO: how do we validate that client *can* open a connection
	 * to a port?
	 */

	struct list_node	pending_list;

	struct list_node	node;

	refcount_t		refcount;
} ipc_port_t;

enum {
	IPC_CHAN_STATE_INVALID		= 0,
	IPC_CHAN_STATE_ACCEPTING	= 1,
	IPC_CHAN_STATE_CONNECTING	= 2,
	IPC_CHAN_STATE_CONNECTED	= 3,
	IPC_CHAN_STATE_DISCONNECTING	= 4,
};

enum {
	IPC_CHAN_FLAG_SERVER		= 0x1,
};

#define IPC_CHAN_MAX_BUFS	32
#define IPC_CHAN_MAX_BUF_SIZE	512

typedef struct ipc_chan {
	struct ipc_chan		*peer;

	uint32_t		state;
	uint32_t		flags;

	handle_t		*handle;

	/* used for port's pending list */
	struct list_node	node;

	ipc_msg_queue_t		*msg_queue;
} ipc_chan_t;

/* server allocates a new port at the given path */
int ipc_port_create(const char *path, int num_recv_bufs,
		    size_t recv_buf_size, uint32_t flags,
		    handle_t **phandle_ptr);

/* server calls to accept a pending connection */
int ipc_port_accept(handle_t *phandle, handle_t **chandle_ptr);

/* client requests a connection to a port */
int ipc_port_connect(const char *path, lk_time_t timeout,
		     handle_t **chandle_ptr);

void port_incref(ipc_port_t *port);
void port_decref(ipc_port_t *port);

bool ipc_is_channel(handle_t *handle);
bool ipc_is_port(handle_t *handle);

#endif
