OUTPUT := .output
CLANG++ := clang++
APP := tcpgen

all: $(OUTPUT)/$(APP)

clean:
	$(Q)rm -rf $(OUTPUT)

$(OUTPUT):
	$(Q)mkdir -p $@

# Build user-space code
$(OUTPUT)/$(APP): $(APP).cpp | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CLANG++) $(INCLUDES) $(APP).cpp -o $@
