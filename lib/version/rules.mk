LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include

MODULE_SRCS := \
	$(LOCAL_DIR)/version.c \

ifneq ($(VERSION_MAJOR),)
MODULE_CFLAGS += \
	-DVERSION_MAJOR=$(VERSION_MAJOR)
endif

ifneq ($(VERSION_MINOR),)
MODULE_CFLAGS += \
	-DVERSION_MINOR=$(VERSION_MINOR)
endif

ifneq ($(BUILDID),)
MODULE_CFLAGS += \
	-DBUILDID=$(BUILDID)
endif

include make/module.mk

EXTRA_BUILDRULES += lib/version/version.mk
