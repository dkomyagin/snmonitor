################################################################################
# Project SNMONITOR builder
################################################################################
MAKEFLAGS += --no-print-directory
	
# All Target
all: libs main-build

# Libraries
libs:
	@cd base64 && $(MAKE) -s all
	@cd eventinf && $(MAKE) -s all
	@cd smtp && $(MAKE) -s all
	@cd httpnanosrv && $(MAKE) -s all
	
# Main Target	
main-build:
	@$(MAKE) -f snmonitor.mk all

# Other Targets
clean:
	-@$(MAKE) -f snmonitor.mk clean
	-@cd base64 && $(MAKE) clean
	-@cd eventinf && $(MAKE) clean
	-@cd smtp && $(MAKE) clean
	-@cd httpnanosrv && $(MAKE) clean
	-@echo ' '

.PHONY: libs all clean main-build

