LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include \

MODULE_DEPS += kernel \
	       $(LOCAL_DIR)/arch/$(ARCH) \

MODULE_SRCS += \
	$(LOCAL_DIR)/kmap.c

include make/module.mk
