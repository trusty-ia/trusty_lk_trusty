# This gets included after recurse.mk, and thus the individual inter-module
# dependencies are known. Now propogate all those dependencies to each
# task so it can link everything together.

# start with the list of required modules for the task and expand it
# to include all the dependent modules
#   $(1): name of varialbe that contains the original list (will be modified)
#   $(2): the list of dependencies to add
define expand-required-deps
$(eval _new_deps := \
  $(sort $(filter-out $($(1)),$(foreach d,$(2),$(ALLUSER_MODULES.$(d).DEPS)))))\
$(if $(_new_deps),\
  $(eval $(1) += $(_new_deps)) \
  $(call expand-required-deps,$(1),$(_new_deps)))
endef

#
# generate the task build rule
#   $(1): task
#   $(2): dependent module objects
define gen-task-build-rule
$(eval USER_TASK_ELF := $(ALLUSER_TASKS.$(1).OBJECT_NAME_BASE).usertask.elf)
$(eval USER_TASK_SYMS_ELF := $(ALLUSER_TASKS.$(1).OBJECT_NAME_BASE).usertask.syms.elf)
$(eval USER_TASK_CRTBEGIN_OBJS := $(BUILDDIR)/user/crtbegin.o)
$(eval USER_TASK_CRTEND_OBJS := $(BUILDDIR)/user/crtend.o)
$(eval USER_TASK_LINKER_SCRIPT := $(BUILDDIR)/user/user_task.ld)
$(USER_TASK_SYMS_ELF): PRIVATE_USER_TASK_LINKER_SCRIPT := $(USER_TASK_LINKER_SCRIPT)
$(USER_TASK_SYMS_ELF): PRIVATE_USER_TASK_OBJS := $(ALLUSER_TASKS.$(1).OBJECT)
$(USER_TASK_SYMS_ELF): PRIVATE_USER_TASK_DEPS_OBJS := $(2)
$(USER_TASK_SYMS_ELF): PRIVATE_USER_TASK_CRTBEGIN_OBJS := $(USER_TASK_CRTBEGIN_OBJS)
$(USER_TASK_SYMS_ELF): PRIVATE_USER_TASK_CRTEND_OBJS := $(USER_TASK_CRTEND_OBJS)
$(USER_TASK_SYMS_ELF): $(USER_TASK_LINKER_SCRIPT) $(USER_TASK_CRTBEGIN_OBJS) $(USER_TASK_CRTEND_OBJS) $(ALLUSER_TASKS.$(1).OBJECT) $(2)
	@$(MKDIR)
	@echo linking $$@
	$(NOECHO)$(LD) $(GLOBAL_USER_LDFLAGS) -T $$(PRIVATE_USER_TASK_LINKER_SCRIPT) $$(PRIVATE_USER_TASK_CRTBEGIN_OBJS) $$(PRIVATE_USER_TASK_OBJS) $$(PRIVATE_USER_TASK_DEPS_OBJS) $$(PRIVATE_USER_TASK_CRTEND_OBJS) $(LIBGCC) -o $$@
$(USER_TASK_ELF): $(USER_TASK_SYMS_ELF)
	@$(MKDIR)
	@echo stripping $$<
	$(STRIP) -s $$< -o $$@
$(eval ALLUSER_TASK_OBJS := $(ALLUSER_TASK_OBJS) $(USER_TASK_ELF))
$(eval USER_TASK_CRTBEGIN_OBJS :=)
$(eval USER_TASK_CRTEND_OBJS :=)
$(eval USER_TASK_ELF :=)
$(eval USER_TASK_SYMS_ELF :=)
$(eval USER_TASK_LINKER_SCRIPT :=)
endef

$(foreach t,$(ALLUSER_TASKS), \
  $(call expand-required-deps,ALLUSER_TASKS.$(t).DEPS,$(ALLUSER_TASKS.$(t).DEPS)) \
  $(if $(ALLUSER_TASKS.$(t).DEPS), \
    $(eval _dep_objs := $(foreach m,$(ALLUSER_TASKS.$(t).DEPS),$(ALLUSER_MODULES.$(m).OBJECT))) \
    $(eval $(call gen-task-build-rule,$(t),$(_dep_objs)))))
