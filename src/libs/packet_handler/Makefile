.PHONY: build-bpf build-cp

OUTPUT := .output
PCAPPLUSPLUS := pcapplusplus
PCAPPLUSPLUS_HEADER := $(PCAPPLUSPLUS)/header
PCAPPLUSPLUS_LIBS := $(PCAPPLUSPLUS)/libs
CLANG := clang
CLANG++ := clang++
INCLUDES := -I$(pcap) -I$(PCAPPLUSPLUS_HEADER)
LIBS := -lpcap $(PCAPPLUSPLUS_LIBS)/libPcap++.a $(PCAPPLUSPLUS_LIBS)/libPacket++.a $(PCAPPLUSPLUS_LIBS)/libCommon++.a
APP := main

all: $(APP)

# Build user-space code
$(APP): $(APP).cpp PacketHandler.cpp
	$(call msg,BINARY,$@)
	$(Q)$(CLANG++) $(INCLUDES) main.cpp PacketHandler.cpp $(LIBS) -o $@
