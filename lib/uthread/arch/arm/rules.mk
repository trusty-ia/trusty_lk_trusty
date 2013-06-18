CUR_DIR := $(GET_LOCAL_DIR)

MODULE_INCLUDES += \
		-I$(CUR_DIR)/include \

MODULE_SRCS += \
	$(CUR_DIR)/uthread.c \
	$(CUR_DIR)/uthread_mmu.c \
	$(CUR_DIR)/uthread_asm.S

CUR_DIR :=
