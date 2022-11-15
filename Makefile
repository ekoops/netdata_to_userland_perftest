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

SUBDIRS := perf_buffer libpcap

.PHONY: help clean $(SUBDIRS)

all: $(SUBDIRS)

clean:
	@for i in $(SUBDIRS); \
	do $(MAKE) -C $$i clean; done

help:
	@echo "Make Targets:"
	@echo " all                 - build binaries"
	@echo " clean               - remove products of build"
	@echo " test               	- execute tests"
	@echo ""
	@echo "Make Arguments:"
	@echo " V=[0|1]             - set build verbosity level"

$(SUBDIRS):
	$(MAKE) -C $@

test:
	@for i in $(SUBDIRS); \
	do $(MAKE) -C $$i test; done