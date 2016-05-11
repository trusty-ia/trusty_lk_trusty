/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef __TRUSTY_DEVICE_INFO_H
#define __TRUSTY_DEVICE_INFO_H

#include <sys/types.h>


/*
* These structure definitions are shared with user space
* Do remember the structure definitions MUST match with
* trusty/lib/include/trusty_device_info.h
*/
#define BUP_MKHI_BOOTLOADER_SEED_LEN    32

/*
*Structure for RoT info (fields defined by Google Keymaster2)
*Note that please pad this structure in multiple of 64bits.
*/
typedef struct _rot_data_t {
    /* version 2 for current TEE keymaster2 */
    uint32_t    version;

    /* 0: unlocked, 1: locked, others not used */
    uint32_t    deviceLocked;

    /* GREEN:0, YELLOW:1, ORANGE:2, others not used (no RED for TEE) */
    uint32_t    verifiedBootState;

    /*
    * The current version of the OS as an integer in the format MMmmss,
    * where MM is a two-digit major version number, mm is a two-digit,
    * minor version number, and ss is a two-digit sub-minor version number.
    * For example, version 6.0.1 would be represented as 060001;
    */
    uint32_t   osVersion;

    /*
    * The month and year of the last patch as an integer in the format,
    * YYYYMM, where YYYY is a four-digit year and MM is a two-digit month.
    * For example, April 2016 would be represented as 201604.
    */
    uint32_t    patchMonthYear;

    /*
    * A secure hash (SHA-256 recommended by Google) of the key used to verify the system image
    * key_size (in bytes) is zero: denotes no key provided by Bootloader. When key_size is 32, it denotes
    * key_hash256 is available. Other values not defined now.
    */
    uint32_t    keySize;
    uint8_t     keyHash256[32];

}__attribute__((packed, aligned(8))) rot_data_t;


typedef struct trusty_device_info{
    /* the size of the structure, used to sync up in different modules(tos loader, TA, LK kernel) */
    uint32_t   size;

    /* used as the HUK derived from CSE by kernelflinger */
    uint8_t         seed[BUP_MKHI_BOOTLOADER_SEED_LEN];

    /* root of trusty field used to binding the hw-backed key */
    rot_data_t      rot;
} trusty_device_info_t;

#endif

