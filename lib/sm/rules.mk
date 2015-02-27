LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include

MODULE_SRCS += \
	$(LOCAL_DIR)/sm.c \
	$(LOCAL_DIR)/smcall.c \

include $(LOCAL_DIR)/arch/$(ARCH)/rules.mk

include make/module.mk
