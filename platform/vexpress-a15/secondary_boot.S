/*
 * Copyright (c) 2013, Google Inc. All rights reserved.
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

#include <asm.h>
#include <platform/vexpress-a15.h>
#if WITH_LIB_SM
#include <lib/sm/monitor.h>
#endif

.section ".text"

FUNCTION(platform_secondary_entry)
	/* earlier spin_unlock call performs dsb needed entering wfi below */
	ldr	r0, =SECONDARY_BOOT_ADDR
1:
	wfi
	ldr	r2, [r0]
	cmp	r2, r5
	beq	1b
	tst	r2, r2
	beq	1b

#if WITH_LIB_SM
	/* Switch to monitor mode */
	cps	#MODE_MON

	SWITCH_SCR_TO_NONSECURE	r3
#endif

	mov	r3, #0x93 /* svc mode with IRQ disabled */
	msr	spsr_cfsx, r3

	movs	pc, r2

.ltorg

