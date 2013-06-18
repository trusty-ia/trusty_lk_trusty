LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_INCLUDES :=

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include \

MODULE_DEPS += kernel

MODULE_SRCS += \
	$(LOCAL_DIR)/uthread.c

include $(LOCAL_DIR)/arch/$(ARCH)/rules.mk
include $(LOCAL_DIR)/test/rules.mk

include make/module.mk
