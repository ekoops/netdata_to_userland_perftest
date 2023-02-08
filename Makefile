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
		      "$(patsubst $(abspath $(OUTPUT_DIR))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
else
	Q =
	msg =
endif


### Base directories ###
SRC_DIR := src
OUTPUT_DIR := .output
SCRIPTS_DIR := scripts
COMMON_SRC_DIR := $(SRC_DIR)/common
LIBS_SRC_DIR := $(SRC_DIR)/libs
COMMON_OUTPUT_DIR := $(OUTPUT_DIR)/common
LIBS_OUTPUT_DIR := $(OUTPUT_DIR)/libs


### Packet handler library ###
PACKET_HANDLER_DIR := $(LIBS_SRC_DIR)/packet_handler
PCAPPLUSPLUS_DIR := $(PACKET_HANDLER_DIR)/pcapplusplus
PCAPPLUSPLUS_HEADER := $(PCAPPLUSPLUS_DIR)/header
PCAPPLUSPLUS_LIBS := $(PCAPPLUSPLUS_DIR)/libs
PACKET_HANDLER_LIBS := -lpcap $(realpath $(PCAPPLUSPLUS_LIBS)/libPcap++.a $(PCAPPLUSPLUS_LIBS)/libPacket++.a $(PCAPPLUSPLUS_LIBS)/libCommon++.a)


### Tests variables ###
TESTS_EBPF := xdp_tc uprobe tracepoint
TESTS_GENERIC := libpcap
TESTS := $(TESTS_EBPF) $(TESTS_GENERIC)
TESTS_SCRIPTS_DIR := $(SCRIPTS_DIR)/tests


### Tools variables ###
TOOLS := tcpgen
TOOLS_SRC_DIR := $(SRC_DIR)/tools
TOOLS_OUTPUT_DIR := $(OUTPUT_DIR)/tools


### Misc ###
OUTPUT_DIRS := $(COMMON_OUTPUT_DIR) $(LIBS_OUTPUT_DIR) $(TOOLS_OUTPUT_DIR) $(foreach test, $(TESTS), $(OUTPUT_DIR)/$(test)/) # notice: without the trailing / prerequisites will not work for tests


### Compilation variables ###
CLANG := clang
CLANG++ := clang++
INCLUDES := -Iinclude -I$(PCAPPLUSPLUS_HEADER) -I$(PACKET_HANDLER_DIR)
BPFTOOL := bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')


.PHONY: help clean $(TESTS) $(TOOLS) $(addprefix clean_, $(TESTS)) test $(addprefix test_, $(TESTS)) $(OUTPUT_DIRS)

all: $(TESTS)

.SECONDEXPANSION:
$(TESTS): %: $(OUTPUT_DIR)/$$(basename %)/% # e.g.: testX depends on .output/testX/testX


### BPF based tests building ###
TESTS_EBPF_OUTPUT_PREFIX :=  $(foreach test, $(TESTS_EBPF), $(OUTPUT_DIR)/$(test)/$(test))

# Build BPF code
.SECONDEXPANSION:
$(addsuffix .bpf.o, $(TESTS_EBPF_OUTPUT_PREFIX)): $(OUTPUT_DIR)/%.bpf.o: $(SRC_DIR)/%.bpf.c | $(OUTPUT_DIR)/$$(dir %)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) $(INCLUDES) -g -Wall -O2 -target bpf -D__TARGET_ARCH_$(ARCH)  -c $< -o $@

# Build BPF skeleton
.SECONDEXPANSION:
$(addsuffix .skel.h, $(TESTS_EBPF_OUTPUT_PREFIX)): $(OUTPUT_DIR)/%.skel.h: $(OUTPUT_DIR)/%.bpf.o | $(OUTPUT_DIR)/$$(dir %)
	$(call msg,SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
.SECONDEXPANSION:
$(TESTS_EBPF_OUTPUT_PREFIX): $(OUTPUT_DIR)/%: $(SRC_DIR)/%.cpp $(OUTPUT_DIR)/%.skel.h | $(OUTPUT_DIR)/$$(dir %)
	$(call msg,BINARY,$@)
	$(Q)$(CLANG++) $(INCLUDES) -I$(OUTPUT_DIR)/$(dir $*) -lbpf -lelf -lz $< -o $@


### Generic tests building ###
TEST_GENERIC_OUTPUT_PREFIX := $(foreach test, $(TESTS_GENERIC), $(OUTPUT_DIR)/$(test)/$(test))

# Build user-space code
.SECONDEXPANSION:
$(TEST_GENERIC_OUTPUT_PREFIX): $(OUTPUT_DIR)/%: $(SRC_DIR)/%.cpp $(LIBS_OUTPUT_DIR)/packet_handler.o | $(OUTPUT_DIR)/$$(dir %)
	$(call msg,BINARY,$@)
	$(Q)$(CLANG++) $(INCLUDES) $^ $(PACKET_HANDLER_LIBS) -o $@


## Library and common building ###
# TODO: fix prerequisites... actually packet handler is rebuilt each time
$(LIBS_OUTPUT_DIR)/packet_handler.o: $(PACKET_HANDLER_DIR)/*.cpp $(PACKET_HANDLER_DIR)/*.h $(PCAPPLUSPLUS_HEADER)/* $(PCAPPLUSPLUS_LIBS)/* $(COMMON_OUTPUT_DIR)/dropper.bpf.o tcpgen | $(LIBS_OUTPUT_DIR)
		$(Q)$(CLANG++) $(INCLUDES) -c $(PACKET_HANDLER_DIR)/PacketHandler.cpp -o $@

$(COMMON_OUTPUT_DIR)/%.bpf.o: $(COMMON_SRC_DIR)/%.bpf.c | $(COMMON_OUTPUT_DIR)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) $(INCLUDES) -g -Wall -O2 -target bpf -D__TARGET_ARCH_$(ARCH)  -c $< -o $@


### Tools building ###
.SECONDEXPANSION:
$(TOOLS): %: $(TOOLS_OUTPUT_DIR)/%

# Build user-space code
$(addprefix $(TOOLS_OUTPUT_DIR)/, $(TOOLS)): $(TOOLS_OUTPUT_DIR)/%: $(TOOLS_SRC_DIR)/$$(basename %)/%.c | $(TOOLS_OUTPUT_DIR)
	$(call msg,BINARY,$@)
	$(Q)$(CLANG) $(INCLUDES) $< -o $@


### clean{_*}, test_{_*} targets ###
clean:
	$(call msg,CLEAN_ALL,$(OUTPUT_DIR))
	$(Q)rm -rf $(OUTPUT_DIR)

$(addprefix clean_, $(TESTS)): # Define targets clean_X for each X in tests
	$(call msg,CLEAN_TEST,$(OUTPUT_DIR)/$(patsubst clean_%,%,$@))
	$(Q)rm -rf $(OUTPUT_DIR)/$(patsubst clean_%,%,$@)

test: $(TESTS)
	$(call msg,RUN_TESTS,$(TESTS_SCRIPTS_DIR))
	@for i in $(TESTS); \
		do sudo -E OUTPUT_DIR=$(OUTPUT_DIR) $(Q)$(TESTS_SCRIPTS_DIR)/$$i.sh; done

$(addprefix test_, $(TESTS)): test_%: % # Define targets test_X for each X in tests
	$(call msg,RUN_TEST,$(TESTS_SCRIPTS_DIR)/$<.sh)
	$(Q)sudo -E OUTPUT_DIR=$(OUTPUT_DIR) $(TESTS_SCRIPTS_DIR)/$<.sh


### Output directories targets ###
$(OUTPUT_DIRS):
	$(call msg,OUTPUT_DIR,$(patsubst %/, %, $@))
	$(Q)mkdir -p $@


### Help target ###
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