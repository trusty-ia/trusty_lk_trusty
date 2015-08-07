/*
 * Copyright (c) 2015, Google Inc. All rights reserved
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
#include <arch/asm_macros.h>
#include <err.h>

/**
 * int mmutest_arch_rodata_pnx(void) - Test that rodata section is mapped pnx
 *
 * Returns ERR_FAULT is rodata is not executable.
 * Return 0 if rodata is executable.
 */
.section .rodata
.align 2
FUNCTION(mmutest_arch_rodata_pnx)
	set_fault_handler	.Lmmutest_fault
	mov	x0, #0

	ret

/**
 * int mmutest_arch_data_pnx(void) - Test that data section is mapped pnx
 *
 * Returns ERR_FAULT is data is not executable.
 * Return 0 if data is executable.
 */
.section .data
.align 2
FUNCTION(mmutest_arch_data_pnx)
	set_fault_handler	.Lmmutest_fault
	mov	x0, #0

	ret
.section .text

/**
 * int mmutest_arch_rodata_ro(void) - Test that rodata section is mapped read-only
 *
 * Returns ERR_FAULT is rodata is not writeable
 * Returns 1 if write to rodata is silently dropped
 * Returns 0 if rodata is writable
 */
FUNCTION(mmutest_arch_rodata_ro)
	adr	x0, .Ltest_rodata_long

	set_fault_handler	.Lmmutest_fault
	str	wzr, [x0]

	ldr	w0, [x0]
	ret

.section .rodata
.Ltest_rodata_long:
	.long	0x1

.section .text
.Lmmutest_fault:
	mov	x0, #ERR_FAULT
	ret
