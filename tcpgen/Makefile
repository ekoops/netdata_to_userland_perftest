OUTPUT := .output
CLANG := clang
APP := tcpgen

all: $(OUTPUT)/$(APP)

clean:
	$(Q)rm -rf $(OUTPUT)

$(OUTPUT):
	$(Q)mkdir -p $@

# Build user-space code
$(OUTPUT)/$(APP): $(APP).c | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CLANG) $(INCLUDES) $(APP).c -o $@
