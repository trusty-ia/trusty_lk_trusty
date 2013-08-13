LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS += \
	$(LOCAL_DIR)/syscall.c

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include

include $(LOCAL_DIR)/arch/$(ARCH)/rules.mk

include make/module.mk
