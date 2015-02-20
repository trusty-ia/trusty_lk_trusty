CUR_DIR := $(GET_LOCAL_DIR)

MODULE_SRCS += \
	$(CUR_DIR)/entry.S \

ifneq (,$(findstring WITH_LIB_SM_MONITOR=1,$(GLOBAL_DEFINES)))

MODULE_SRCS += \
	$(CUR_DIR)/monitor.S \

endif

CUR_DIR :=
