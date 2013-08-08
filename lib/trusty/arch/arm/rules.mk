CUR_DIR := $(GET_LOCAL_DIR)

# some linkers set the default arm pagesize to 32K. No idea why.
GLOBAL_USER_LDFLAGS += \
	-z max-page-size=0x1000

GENERATED += \
	$(BUILDDIR)/user/user_task.ld

$(BUILDDIR)/user/user_task.ld: $(CUR_DIR)/user_task-trusty.ld
	@echo generating $@
	@$(MKDIR)
	$(NOECHO)cp $< $@

CUR_DIR :=
