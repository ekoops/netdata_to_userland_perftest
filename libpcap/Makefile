.PHONY: build-bpf build-cp

OUTPUT := .output
CLANG := clang
CLANG++ := clang++
INCLUDES := -I../include -I$(OUTPUT)
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
	$(Q)$(CLANG++) $(INCLUDES) -lpcap $(APP).cpp -o $@
