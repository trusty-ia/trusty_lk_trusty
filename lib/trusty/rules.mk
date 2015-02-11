LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS := \
	$(LOCAL_DIR)/trusty.c \
	$(LOCAL_DIR)/trusty_app.c \
	$(LOCAL_DIR)/syscall.c \
	$(LOCAL_DIR)/handle.c \
	$(LOCAL_DIR)/uctx.c \
	$(LOCAL_DIR)/ipc.c \
	$(LOCAL_DIR)/ipc_msg.c \
	$(LOCAL_DIR)/iovec.c \
	$(LOCAL_DIR)/uuid.c


ifeq (true,$(call TOBOOL,$(WITH_TRUSTY_IPC)))
GLOBAL_DEFINES += WITH_TRUSTY_IPC=1
endif

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include \

MODULE_DEPS += \
	lib/uthread \
	lib/syscall \
	lib/version \

GLOBAL_DEFINES += \
	WITH_SYSCALL_TABLE=1 \

include make/module.mk
