################################################################################
# SNMONIROR builder
################################################################################
CC := g++
RM := rm -rf
MAKEFLAGS += --no-print-directory

BUILD_ARTIFACT_NAME := snmonitor
BUILD_ARTIFACT_EXTENSION :=
BUILD_ARTIFACT_PREFIX :=
BUILD_ARTIFACT := $(BUILD_ARTIFACT_PREFIX)$(BUILD_ARTIFACT_NAME)$(if $(BUILD_ARTIFACT_EXTENSION),.$(BUILD_ARTIFACT_EXTENSION),)

MAKEFILE_LIST := makefile snmonitor.mk

INCLUDE_DIR_BASE64 := ./base64
INCLUDE_DIR_EVENTINFO := ./eventinf
INCLUDE_DIR_SMTP := ./smtp
INCLUDE_DIR_HTTPNANOSRV := ./httpnanosrv

CPPS_DIR := ./src
LIBS_DIR := ./lib
OBJS_DIR := ./obj
LIB_DEPS := $(LIBS_DIR)/libbase64.a $(LIBS_DIR)/libsmtp.a $(LIBS_DIR)/libhttpnanosrv.a
CPP_SRCS := $(wildcard $(CPPS_DIR)/*.cpp)
OBJS := $(patsubst $(CPPS_DIR)/%.cpp,$(OBJS_DIR)/%.o,$(CPP_SRCS))
INCLUDE_DEPS := $(wildcard $(CPPS_DIR)/*.hh) $(wildcard $(CPPS_DIR)/*.h) 
INCLUDE_DEPS += $(wildcard $(INCLUDE_DIR_BASE64)/*.hh) $(wildcard $(INCLUDE_DIR_EVENTINFO)/*.hh)
INCLUDE_DEPS += $(wildcard $(INCLUDE_DIR_SMTP)/*.hh) $(wildcard $(INCLUDE_DIR_SMTP)/*.h)
INCLUDE_DEPS += $(wildcard $(INCLUDE_DIR_HTTPNANOSRV)/*.hh) $(wildcard $(INCLUDE_DIR_HTTPNANOSRV)/*.h)
CPP_DEPS := $(patsubst %.o,%.d,$(OBJS))

#
$(OBJS_DIR):
	@echo "Creating '$@' folder"
	@mkdir -p $@
	
#
$(OBJS_DIR)/%.o: $(CPPS_DIR)/%.cpp $(INCLUDE_DEPS) $(MAKEFILE_LIST)
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++1y -I"$(CPPS_DIR)" -I"$(INCLUDE_DIR_BASE64)" -I"$(INCLUDE_DIR_EVENTINFO)" -I"$(INCLUDE_DIR_SMTP)" -I"$(INCLUDE_DIR_HTTPNANOSRV)" -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '
	
# All Target
all: main-build

# Main-build Target
main-build: $(BUILD_ARTIFACT)

# Tool invocations
$(BUILD_ARTIFACT): $(OBJS_DIR) $(OBJS) $(LIB_DEPS) $(MAKEFILE_LIST)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C++ Linker'
	$(CC) -L"$(LIBS_DIR)" -o "$(BUILD_ARTIFACT)" $(OBJS) -lhttpnanosrv -leventinf -lsqlite3 -lpthread -lsmtp -lbase64 -lssl -lcrypto
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(BUILD_ARTIFACT) $(CPP_DEPS) $(OBJS)

.PHONY: all clean main-build

