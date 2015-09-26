/*
 * Copyright (c) 2013-2015, Google Inc. All rights reserved
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions
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

 #include <asm.h>
 #include <lib/sm/monitor.h>
 #include <lib/sm/smcall.h>
 #include <lib/sm/sm_err.h>
 #include <kernel/vm.h>
 /*
  * Monitor stacks:
  *  secure context
  *  non-secure context
  *
  * Context:
  *  mon_lr
  *  usr/sys_sp, usr/sys_lr
  *  und_spsr, und_sp, und_lr
  *  abt_spsr, abt_sp, abt_lr
  *  svc_spsr, svc_sp, svc_lr
  *  irq_spsr, irq_sp, irq_lr
  *  fiq_spsr, fiq_r8-fiq_lr
  *  r4-r11, lr
  *  r0-r3, ip
  *  lr, spsr
  *
  */
  #define CONTEXT_SIZE_RETURN (2 * 4)
  #define CONTEXT_SIZE_SCRATCH_GEN_REGS ((5 + 9) * 4)
  #define CONTEXT_SIZE_MODE_REGS_MON_RETURN ((8 + 3 + 3 + 3 + 3 + 2 + 1) * 4)
  #define CONTEXT_SIZE (CONTEXT_SIZE_RETURN + CONTEXT_SIZE_SCRATCH_GEN_REGS + CONTEXT_SIZE_MODE_REGS_MON_RETURN)
  #define MONITOR_STACK_SIZE (CONTEXT_SIZE * 2)

FUNCTION(monitor_reset)
	ret
FUNCTION(monitor_init_mmu_on)
	ret
FUNCTION(mon_initial_ns_return)
	ret
