.PHONY: build-bpf build-cp

OUTPUT := .output
PACKET_HANDLER_DIR := ../libs/packet_handler
PCAPPLUSPLUS_DIR := $(PACKET_HANDLER_DIR)/pcapplusplus
PCAPPLUSPLUS_HEADER := $(PCAPPLUSPLUS_DIR)/header
PCAPPLUSPLUS_LIBS := $(PCAPPLUSPLUS_DIR)/libs
CLANG++ := clang++
INCLUDES := -I$(pcap) -I$(PCAPPLUSPLUS_HEADER) -I$(PACKET_HANDLER_DIR)
LIBS := -lpcap $(PCAPPLUSPLUS_LIBS)/libPcap++.a $(PCAPPLUSPLUS_LIBS)/libPacket++.a $(PCAPPLUSPLUS_LIBS)/libCommon++.a
APP := libpcap

all: $(OUTPUT)/$(APP)

test: $(OUTPUT)/$(APP)
	sudo -E $(Q)./test.sh

clean:
	$(Q)rm -rf $(OUTPUT)

$(OUTPUT):
	$(Q)mkdir -p $@

# Build user-space code
$(OUTPUT)/$(APP): $(APP).cpp | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CLANG++) $(INCLUDES) $(APP).cpp $(PACKET_HANDLER_DIR)/PacketHandler.cpp $(LIBS) -o $@
