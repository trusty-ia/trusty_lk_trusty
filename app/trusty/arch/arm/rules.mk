LOCAL_DIR := $(GET_LOCAL_DIR)

# some linkers set the default arm pagesize to 32K. No idea why.
XBIN_LDFLAGS += \
	-z max-page-size=0x1000

# linking script to link this user task
USER_TASK_LINKER_SCRIPT := $(BUILDDIR)/user_task.ld

# rule to copy it to BUILD directory
$(USER_TASK_LINKER_SCRIPT): $(LOCAL_DIR)/user_task-trusty.ld
	@echo generating $@
	@$(MKDIR)
	$(NOECHO)cp $< $@

GENERATED +=  $(USER_TASK_LINKER_SCRIPT)

LOCAL_DIR :=
