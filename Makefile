ifeq ("$(origin V)", "command line")
VERBOSE = $(V)
endif
ifndef VERBOSE
VERBOSE = 0
endif

ifeq ($(VERBOSE),0)
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
else
	Q =
	msg =
endif

SRC := src
COMMON := common
LIBS := $(SRC)/libs
DEPS := $(COMMON) $(LIBS)
TESTS := libpcap xdp_tc # uprobe tracepoint

.PHONY: help clean clean_tests clean_deps test $(TESTS) $(DEPS)

all: $(TESTS)

$(TESTS): $(DEPS)
	$(call msg,BUILD_TEST,$@)
	$(Q)$(MAKE) -C $(SRC)/$@

$(DEPS):
	$(call msg,BUILD_DEPENDENCY,$@)
	$(Q)$(MAKE) -C $@

clean: clean_tests clean_deps

clean_tests:
	$(call msg,CLEAN_TESTS,$@)
	@for i in $(TESTS); \
		do $(MAKE) -C $(SRC)/$$i clean; done

clean_deps:
	$(call msg,CLEAN_DEPS,$@)
	@for i in $(DEPS); \
    	do $(MAKE) -C $$i clean; done

# Define targets clean_X for each X in tests
$(patsubst %,clean_%,$(TESTS)):
	$(call msg,CLEAN_TEST,$(patsubst clean_%,%,$@))
	$(Q)$(MAKE) -C $(SRC)/$(patsubst clean_%,%,$@) clean

test: $(TESTS)
	$(call msg,RUN_TESTS,$@)
	@for i in $(TESTS_DIRS); \
		do $(MAKE) -C $$i test; done

# Define targets test_X for each X in tests
$(patsubst %,test_%,$(TESTS)): test_%: %
	$(call msg,RUN_TEST,$(patsubst clean_%,%,$@))
	$(Q)$(MAKE) -C $(SRC)/$(patsubst test_%,%,$@) test

TESTS_LIST := $(shell echo $(TESTS) | sed 's/ /, /g')
help:
	@echo "Make Targets:"
	@echo " all                 - build all tests and dependencies"
	@echo " clean               - remove products of build for tests and dependencies"
	@echo " test               	- run all tests"
	@echo " test_{TEST}			- run specific test, where TEST can be $(TESTS_LIST)"
	@echo " clean_{TEST}		- remove product of build for specific test, where TEST can be $(TESTS_LIST)"
	@echo ""
	@echo "Make Arguments:"
	@echo " V=[0|1]             - set build verbosity level"