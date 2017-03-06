# Copyright (C) 2017 The Android Open Source Project
# Copyright (c) 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

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
