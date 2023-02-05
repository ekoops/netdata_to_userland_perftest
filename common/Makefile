OUTPUT := .output
CLANG := clang
BPFTOOL := bpftool
INCLUDES := -I../include
APPS := dropper
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

.PHONY: clean

all: $(patsubst %,$(OUTPUT)/%.bpf.o,$(APPS))

clean:
	$(Q)rm -rf $(OUTPUT)

$(OUTPUT):
	$(Q)mkdir -p $@
#
## Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -Wall -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $(filter %.c,$^) -o $@

