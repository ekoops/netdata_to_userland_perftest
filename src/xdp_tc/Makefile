OUTPUT := .output
CLANG := clang
CLANG++ := clang++
BPFTOOL := bpftool
INCLUDES := -I../../include -I$(OUTPUT)
APP := xdp_tc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

.PHONY: test clean

all: $(OUTPUT)/$(APP) $(OUTPUT)/$(APP).bpf.o

test: $(OUTPUT)/$(APP) $(OUTPUT)/$(APP).bpf.o
	$(call msg,TEST,$@)
	sudo -E $(Q)./test.sh

clean:
	$(call msg,CLEAN,$@)
	$(Q)rm -rf $(OUTPUT)

$(OUTPUT):
	$(Q)mkdir -p $@

# Build BPF code
$(OUTPUT)/$(APP).bpf.o: $(APP).bpf.c | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -Wall -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $(APP).bpf.c -o $@

# Build BPF skeleton
$(OUTPUT)/$(APP).skel.h: $(OUTPUT)/$(APP).bpf.o | $(OUTPUT)
	$(call msg,SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $(OUTPUT)/$(APP).bpf.o > $@

# Build user-space code
$(OUTPUT)/$(APP): $(APP).cpp $(OUTPUT)/$(APP).skel.h | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CLANG++) $(INCLUDES) -lbpf -lelf -lz $(APP).cpp -o $@
