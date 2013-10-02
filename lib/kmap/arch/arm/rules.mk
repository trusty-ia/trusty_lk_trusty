LOCAL_DIR = $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_DEPS += arch/arm \

MODULE_SRCS += \
	$(LOCAL_DIR)/kmap.c \

include make/module.mk
