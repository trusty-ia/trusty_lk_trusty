LOCAL_DIR := $(GET_LOCAL_DIR)

# common user task related globals
XBIN_LDFLAGS := --gc-sections

#include arch specific support for trusty user tasks

include  $(LOCAL_DIR)/arch/$(ARCH)/rules.mk
