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

/* DEF_SYSCALL(syscall_nr, syscall_name, return type, nr_args, [argument list])
 *
 * Please keep this table sorted by syscall number
 */

DEF_SYSCALL(0x1, write, long, 3, uint32_t fd, void* msg, uint32_t size)
DEF_SYSCALL(0x2, brk, long, 1, uint32_t brk)
DEF_SYSCALL(0x3, exit_group, long, 0)
DEF_SYSCALL(0x4, read, long, 3, uint32_t fd, void* msg, uint32_t size)
DEF_SYSCALL(0x5, ioctl, long, 3, uint32_t fd, uint32_t req, void* buf)
DEF_SYSCALL(0x6, nanosleep, long, 3, uint32_t clock_id, uint32_t flags, uint64_t sleep_time)
