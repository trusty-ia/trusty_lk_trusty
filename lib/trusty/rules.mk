LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS := \
	$(LOCAL_DIR)/trusty.c \
	$(LOCAL_DIR)/trusty_app.c \
	$(LOCAL_DIR)/syscall.c \

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include \

MODULE_DEPS += \
	lib/uthread \
	lib/syscall \
	lib/version \

GLOBAL_DEFINES += \
	WITH_SYSCALL_TABLE=1 \

include make/module.mk
