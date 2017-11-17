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

/* BXT uses HECI1 */
#define HECI1_BUS       (0)
#define HECI1_DEV       (15)
#define HECI1_FUNC      (0)
#define HECI1_REG       (0x40)

#define PCI_READ_FUSE(DEVICE_PLATFORM) pci_read32 \
                                       ( DEVICE_PLATFORM##_BUS, \
                                         DEVICE_PLATFORM##_DEV, \
                                         DEVICE_PLATFORM##_FUNC, \
                                         DEVICE_PLATFORM##_REG ) \


/*
* These structure definitions are shared with user space
* Do remember the structure definitions MUST match with
* trusty/lib/include/trusty_device_info.h
*/
#define BOOTLOADER_SEED_MAX_ENTRIES     4
#define BUP_MKHI_BOOTLOADER_SEED_LEN    32
#define MMC_PROD_NAME_WITH_PSN_LEN      15

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

typedef union hfs1 {
        struct {
                uint32_t working_state: 4;   /* Current working state */
                uint32_t manuf_mode: 1;      /* Manufacturing mode */
                uint32_t part_tbl_status: 1; /* Indicates status of flash partition table */
                uint32_t reserved: 25;       /* Reserved for further use */
                uint32_t d0i3_support: 1;    /* Indicates D0i3 support */
        } field;
        uint32_t data;
} hfs1_t;

/* Structure of seed info */
typedef struct _seed_info {
    uint8_t svn;
    uint8_t padding[3];
    uint8_t seed[BUP_MKHI_BOOTLOADER_SEED_LEN];
}__attribute__((packed)) seed_info_t;

/* AttKB size is limited to 16KB */
#define MAX_ATTKB_SIZE    (16*1024)

typedef struct trusty_device_info{
    /* the size of the structure, used to sync up in different modules(tos loader, TA, LK kernel) */
    uint32_t        size;

    /* seed */
    uint32_t        num_seeds;
    seed_info_t     seed_list[BOOTLOADER_SEED_MAX_ENTRIES];

    /* root of trusty field used to binding the hw-backed key */
    rot_data_t      rot;

    /* used for getting device end of manufacturing or other states */
    hfs1_t          state;

    /* Concatenation of mmc product name with a string representation of PSN */
    char serial[MMC_PROD_NAME_WITH_PSN_LEN];

    /* attestation keybox info */
    uint32_t     attkb_size;
    uint8_t      attkb[0];
}__attribute__((packed)) trusty_device_info_t;

#define ATTKB_INFO_OFFSET    __offsetof(struct trusty_device_info, attkb_size)

#define   GET_SEED         (1<<0)
#define   GET_ATTKB        (1<<1)
#endif

