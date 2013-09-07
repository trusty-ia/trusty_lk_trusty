/*
 * Copyright (c) 2012 Travis Geiselbrecht
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
#include <arch/arm/mmu.h>
#include <err.h>
#include <debug.h>
#include <dev/interrupt/arm_gic.h>
#include <platform.h>
#include <platform/vexpress-a15.h>
#include "platform_p.h"

void platform_init_mmu_mappings(void)
{
#if WITH_MMU_RELOC
	arm_mmu_map_section(REGISTER_BANK_0_PADDR, REGISTER_BANK_0_VADDR,
		MMU_MEMORY_L1_TYPE_DEVICE_SHARED | MMU_MEMORY_L1_AP_P_RW_U_NA);
	arm_mmu_map_section(REGISTER_BANK_1_PADDR, REGISTER_BANK_1_VADDR,
		MMU_MEMORY_L1_TYPE_DEVICE_SHARED | MMU_MEMORY_L1_AP_P_RW_U_NA);
	arm_mmu_map_section(REGISTER_BANK_2_PADDR, REGISTER_BANK_2_VADDR,
		MMU_MEMORY_L1_TYPE_DEVICE_SHARED | MMU_MEMORY_L1_AP_P_RW_U_NA);
#endif
}

void platform_early_init(void)
{
	/* initialize the interrupt controller */
	arm_gic_init();

#if !WITH_LIB_SM
	/* initialize the timer block */
	platform_init_timer();
#endif
}

void platform_init(void)
{
}

