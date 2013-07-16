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

#ifndef __LIB_TRUSTY_UCTX_H
#define __LIB_TRUSTY_UCTX_H

#include <stdint.h>
#include <sys/types.h>

#include <lib/trusty/handle.h>

typedef struct uctx uctx_t;

int uctx_create(void *priv, uctx_t **ctx);
void uctx_destroy(uctx_t *ctx);
void *uctx_get_priv(uctx_t *ctx);

int uctx_handle_install(uctx_t *ctx, handle_t *handle, int *id);
int uctx_handle_get(uctx_t *ctx, int handle_id, handle_t **handle_ptr);
int uctx_handle_wait_any(uctx_t *ctx, handle_t **handle_ptr,
			 uint32_t *event_ptr, lk_time_t timeout);
#endif
