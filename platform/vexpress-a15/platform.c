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
#include <arch.h>
#include <arch/arm.h>
#include <arch/arm/mmu.h>
#include <arch/arm/ops.h>
#include <err.h>
#include <debug.h>
#include <dev/interrupt/arm_gic.h>
#include <lk/init.h>
#include <platform.h>
#include <platform/gic.h>
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

static uint32_t read_mpidr(void)
{
	int mpidr;
	__asm__ volatile("mrc		p15, 0, %0, c0, c0, 5"
		: "=r" (mpidr)
		);
	return mpidr;
}

#if WITH_SMP
#define GICC_IAR                (GICC_OFFSET + 0x000c)
#define GICC_EOIR               (GICC_OFFSET + 0x0010)

static void platform_secondary_init(uint level)
{
	u_int val;
	dprintf(INFO, "Booted secondary CPU, MPIDR = %x\n", read_mpidr());
	val = *REG32(GICBASE(0) + GICC_IAR);
	if (val)
		dprintf(INFO, "bad interrupt number on secondary CPU: %x\n", val);
	*REG32(GICBASE(0) + GICC_EOIR) = val & 0x3ff;
	arm_gic_init_secondary_cpu();
}

LK_INIT_HOOK_FLAGS(vexpress_a15, platform_secondary_init, LK_INIT_LEVEL_PLATFORM, LK_INIT_FLAG_SECONDARY_CPUS);
#endif

void platform_init(void)
{
#if WITH_SMP
	dprintf(INFO, "Booting secondary CPUs. Main CPU MPIDR = %x\n", read_mpidr());
	writel(kvaddr_to_paddr(arm_secondary_entry), SECONDARY_BOOT_ADDR);
	arm_gic_sgi(0, ARM_GIC_SGI_FLAG_TARGET_FILTER_NOT_SENDER, 0);
#endif
}

