LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

ARCH := arm
ARM_CPU := cortex-a15

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include

MODULE_SRCS += \
	$(LOCAL_DIR)/debug.c \
	$(LOCAL_DIR)/platform.c \
	$(LOCAL_DIR)/timer.c

MEMBASE := 0x80000000
MEMSIZE := 0x10000000	# 256MB

MODULE_DEPS += \
	dev/interrupt/arm_gic

GLOBAL_DEFINES += \
	MEMBASE=$(MEMBASE) \
	MEMSIZE=$(MEMSIZE)

LINKER_SCRIPT += \
	$(BUILDDIR)/system-onesegment.ld

include make/module.mk
