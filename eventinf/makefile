################################################################################
# eventinf library builder
################################################################################
CC := g++
AR := ar
RM := rm -rf

#
BUILD_ARTIFACT_NAME := eventinf
BUILD_ARTIFACT_EXTENSION := a
BUILD_ARTIFACT_PREFIX := lib
BUILD_ARTIFACT := $(BUILD_ARTIFACT_PREFIX)$(BUILD_ARTIFACT_NAME)$(if $(BUILD_ARTIFACT_EXTENSION),.$(BUILD_ARTIFACT_EXTENSION),)
BUILD_DIR := ../lib

#
OBJS_DIR := ./obj
CPP_SRCS := ./$(BUILD_ARTIFACT_NAME).cpp
CPP_DEPS := $(OBJS_DIR)/$(BUILD_ARTIFACT_NAME).d 
OBJS := $(OBJS_DIR)/$(BUILD_ARTIFACT_NAME).o 
DEPS := ./eventinf.hh

#
$(BUILD_DIR):
	@echo "Creating '$@' folder"
	@mkdir -p $@
	
#
$(OBJS_DIR):
	@echo "Creating '$@' folder"
	@mkdir -p $@

#
$(OBJS_DIR)/%.o: ./%.cpp $(OBJS_DIR) $(DEPS) makefile
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	$(CC) -std=c++1y -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '
	
# All Target
all: main-build

# Main-build Target
main-build: $(BUILD_DIR) $(BUILD_DIR)/$(BUILD_ARTIFACT)

# Tool invocations
$(BUILD_DIR)/$(BUILD_ARTIFACT): $(OBJS) makefile
	@echo 'Building target: $@'
	@echo 'Invoking: GCC Archiver'
	$(AR) -r -P $(BUILD_DIR)/$(BUILD_ARTIFACT) $(OBJS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(BUILD_DIR)/$(BUILD_ARTIFACT) $(CPP_DEPS) $(OBJS)

.PHONY: all clean main-build
