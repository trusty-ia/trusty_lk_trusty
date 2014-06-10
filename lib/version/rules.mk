LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include

MODULE_SRCS := \
	$(LOCAL_DIR)/version.c \

include make/module.mk

EXTRA_BUILDRULES += lib/version/version.mk
