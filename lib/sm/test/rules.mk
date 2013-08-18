LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS += \
	$(LOCAL_DIR)/smcall_test.c \

GLOBAL_DEFINES += \
	WITH_SMCALL_TABLE=1 \

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include \

include make/module.mk
