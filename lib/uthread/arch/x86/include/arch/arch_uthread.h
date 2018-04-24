/*
 * Copyright (c) 2015 Intel Corporation
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

#ifndef __X86_ARCH_UTHREAD_H
#define __X86_ARCH_UTHREAD_H

#define CF_MASK	 		0x0000
#define PA_MASK			0x0001
#define PF_MASK			0x0020
#define TF_MASK			0x0100
#define IF_MASK			0x0200
#define	IOPL_MASK		0x3000
#define NTi_MASK		0x4000
#define RSVD			0x0002

#define USER_EFLAGS	(IF_MASK|IOPL_MASK|RSVD) //0x3202

/* SYSCALL Handling */
#define SYSENTER_CS_MSR    0x174
#define SYSENTER_ESP_MSR   0x175
#define SYSENTER_EIP_MSR   0x176

struct uthread;

struct arch_uthread
{
	uint32_t asid;
	vaddr_t kstack;
	struct uthread *uthread;
#if defined (STACK_PROTECTOR) && defined (__clang__)
	vaddr_t fs_base;
#endif
};

#endif
