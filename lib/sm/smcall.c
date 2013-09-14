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

/* secure monitor call table definition
 *
 * The user of this library must:
 * - define WITH_SMCALL_TABLE
 * - provide a file named smcall_table.h in the include path
 * - provide DEF_SMCALL macros in smcall_table.h with
 *   number, name, #args followed by argument type defintions.
 * - SMC numbers must start from 0x4. The first 4 numbers are reserved.
 */
#include <debug.h>
#include <compiler.h>
#include <err.h>
#include <lib/sm.h>

/* Defined elsewhere */
long smc_go_nonsecure(uint32_t smc_nr, uint32_t retval);
long smc_fiq_exit(uint32_t r0, uint32_t r1, uint32_t r2, uint32_t r3);

static long smc_undefined(uint32_t smc_nr, uint32_t arg0,
		uint32_t arg1, uint32_t arg2)
{
	dprintf(CRITICAL, "Undefined SMC call 0x%x!"
			"args: 0x%x, 0x%x, 0x%x\n", smc_nr, arg0,
			arg1, arg2);
	return ERR_NOT_SUPPORTED;
}

static long smc_restart_last(uint32_t smc_nr)
{
	return sm_sched_secure(NULL);
}

static long smc_trusted_service(uint32_t smc_nr, uint32_t arg0,
		uint32_t arg1, uint32_t arg2)
{
	ts_args_t ts_args;

	/* Push args on monitor mode stack */
	ts_args.smc_nr = smc_nr;
	ts_args.arg0 = arg0;
	ts_args.arg1 = arg1;
	ts_args.arg2 = arg2;

	return sm_sched_secure(&ts_args);
}

#ifdef WITH_SMCALL_TABLE

/* Generate fake function prototypes */
#define DEF_SMCALL(nr, fn, rtype, nr_args, ...) void smc_##fn (void);
#include <smcall_table.h>
#undef DEF_SMCALL

#endif

#define DEF_SMCALL(nr, fn, rtype, nr_args, ...) [(nr)] = (unsigned long) (smc_##fn),
const unsigned long smcall_table [] = {
	DEF_SMCALL(0, undefined, long, 4)
	DEF_SMCALL(1, go_nonsecure, ns_args_t*, 2)
	DEF_SMCALL(2, restart_last, long, 1)
	DEF_SMCALL(3, trusted_service, long, 4)
	DEF_SMCALL(4, intc_request_fiq, status_t, 2, u_int fiq, bool enable)
	DEF_SMCALL(5, fiq_exit, long, 4)

#ifdef WITH_SMCALL_TABLE
#include <smcall_table.h>
#endif

};
#undef DEF_SMCALL

unsigned long nr_smcalls = countof(smcall_table);
