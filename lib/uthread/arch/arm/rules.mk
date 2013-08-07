CUR_DIR := $(GET_LOCAL_DIR)

MODULE_INCLUDES += \
		-I$(CUR_DIR)/include \

MODULE_ARM_OVERRIDE_SRCS += \
	$(CUR_DIR)/uthread.c \
	$(CUR_DIR)/uthread_mmu.c \

CUR_DIR :=
