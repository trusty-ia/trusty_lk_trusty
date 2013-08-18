LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include

MODULE_ARM_OVERRIDE_SRCS += \
	$(LOCAL_DIR)/entry.S \
	$(LOCAL_DIR)/sm.c \
	$(LOCAL_DIR)/smcall.c \

include make/module.mk
