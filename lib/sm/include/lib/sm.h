/*
 * Copyright (c) 2013 Google Inc. All rights reserved
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
#ifndef __SM_H
#define __SM_H

/* Errors from the monitor */
#define SM_ERR_NOT_SUPPORTED		-1
#define SM_ERR_INVALID_PARAMETERS	-2
#define SM_ERR_INTERRUPTED		-3	/* Got interrupted. Call back with restart SMC */
#define SM_ERR_UNEXPECTED_RESTART	-4	/* Got an restart SMC when we didn't expect it */
#define SM_ERR_BUSY			-5	/* Temporarily busy. Call back with original args */
#define SM_ERR_INTERLEAVED_SMC		-6	/* Got a trusted_service SMC when a restart SMC is required */
#define SM_ERR_INTERNAL_FAILURE		-7	/* Unknown error */

#ifndef ASSEMBLY
#include <sys/types.h>

typedef struct ts_args {
	uint32_t smc_nr;
	uint32_t arg0;
	uint32_t arg1;
	uint32_t arg2;
} ts_args_t;

typedef long (*trusted_service_handler_routine)(ts_args_t *args);

/* Initialize secure monitor on a secondary cpu */
void sm_secondary_init(void);

/* Schedule Secure OS */
long sm_sched_secure(ts_args_t *ts_args);

/* Schedule Non-secure OS */
ts_args_t *sm_sched_nonsecure(long retval);

/* Register a service handler for the trusted_service smc */
status_t sm_register_trusted_service_handler(trusted_service_handler_routine fn);

/* Handle an interrupt */
enum handler_return sm_handle_irq(void);

#endif /* ASSEMBLY */
#endif /* __SM_H */

