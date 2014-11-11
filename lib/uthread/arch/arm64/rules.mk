CUR_DIR := $(GET_LOCAL_DIR)

GLOBAL_INCLUDES += \
	$(CUR_DIR)/include \

MODULE_SRCS += \
	$(CUR_DIR)/uthread.c \

CUR_DIR :=
