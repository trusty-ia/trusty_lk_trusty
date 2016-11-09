/*
 * Copyright (c) 2015, Google, Inc. All rights reserved
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
#pragma once

#include <sys/types.h>

typedef struct uuid
{
	uint32_t time_low;
	uint16_t time_mid;
	uint16_t time_hi_and_version;
	uint8_t clock_seq_and_node[8];
} uuid_t;

#define ZERO_UUID \
	{ 0x0, 0x0, 0x0, \
		{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0} }

extern const struct uuid zero_uuid;

/* IPC_UNITTEST Main App UUID */
#define IPC_UNITTEST_MAIN_APP_UUID \
	{ 0x766072e8, 0x414e, 0x48fc, \
		{ 0x9f, 0x8f, 0xfb, 0x9a, 0x6f, 0x14, 0x41, 0x24 }}

/* IPC_UNITTEST Srv App UUID */
#define IPC_UNITTEST_SRV_APP_UUID \
	{ 0xfee67f9f, 0xe1b1, 0x4e3d, \
		{ 0x84, 0x55, 0x04, 0x7f, 0x60, 0x01, 0xaf, 0xef }}

/* HWCRYPTO Server App UUID */
#define HWCRYPTO_SRV_APP_UUID \
	{ 0x23fe5938, 0xccd5, 0x4a78, \
		{ 0x8b, 0xaf, 0x0f, 0x3d, 0x05, 0xff, 0xc2, 0xdf }}

/* HWCRYPTO unittest App UUID */
#define HWCRYPTO_UNITTEST_APP_UUID \
	{ 0xab742471, 0xd6e6, 0x4806, \
		{ 0x85, 0xf6, 0x05, 0x55, 0xb0, 0x24, 0xf4, 0xda }}

/* Secure Storage Server App UUID */
#define SECURE_STORAGE_SERVER_APP_UUID \
	{0xcea8706d, 0x6cb4, 0x49f3, \
		{ 0xb9, 0x94, 0x29, 0xe0, 0xe4, 0x78, 0xbd, 0x29 }}

/* Secure Storage Uinittest App UUID */
#define STORAGE_UNITTEST_APP_UUID  \
	{ 0x1c1c3151, 0xf04f, 0x4012, \
		{ 0xbf, 0xd7, 0x59, 0xab, 0x76, 0xbc, 0x79, 0x12 }}

/* Keymaster Server App UUID */
#define KEYMASTER_SRV_APP_UUID \
	{ 0x5f902ace, 0x5e5c, 0x4cd8, \
		{ 0xae, 0x54, 0x87, 0xb8, 0x8c, 0x22, 0xdd, 0xaf }}

/* Gatekeeper Server App UUID */
#define GATEKEEPER_SRV_APP_UUID \
	{ 0x38ba0cdc, 0xdf0e, 0x11e4, \
		{ 0x98, 0x69, 0x23, 0x3f, 0xb6, 0xae, 0x47, 0x95 }}
