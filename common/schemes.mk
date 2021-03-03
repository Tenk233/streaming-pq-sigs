_git_submodule_update_mupq := $(shell git submodule update --init --recursive mupq)


SIGN_SEARCH_PATHS = \
	crypto_sign_stream 

# findschemes = $(foreach spath,$(1),$(wildcard $(spath)*/))
# KEM_SCHEMES := $(call findschemes,$(KEM_SEARCH_PATHS))
# KEM_SCHEMES := $(call findschemes,$(KEM_SCHEMES))

# $(info KEM_SCHEMES: $(KEM_SCHEMES))

# .PHONY: obj/.schemes.mk
obj/.schemes.mk:
	$(Q)echo "" >> $@
	$(Q)echo "SIGN_SCHEMES := \\" >> $@
	$(Q)for SPATH in $(SIGN_SEARCH_PATHS); do \
		SCHEMES=$$(find $${SPATH} -mindepth 1 -maxdepth 1 -type d); \
		for SCHEME in $${SCHEMES}; do \
			find $${SCHEME} -mindepth 1 -maxdepth 1 -type d \! \( -name avx -or -name avx2 -or -name sse -or -name vec -or -name aesni \) -printf "\\t%p \\\\\\n"  >> $@; \
		done; \
	done;

-include obj/.schemes.mk

SIGN_SCHEMES := $(filter-out $(EXCLUDED_SCHEMES),$(SIGN_SCHEMES))

schemename = $(subst /,_,$(1))
schemesrc = $(wildcard $(1)/*.c) $(wildcard $(1)/*.s) $(wildcard $(1)/*.S)
namespace = $(shell echo $(if $(filter mupq_pqclean_%,$(1)),$(subst mupq_pqclean_crypto_$(2)_,pqclean_,$(1))_) | tr '[:lower:]' '[:upper:]' | tr -d '-')

define compiletest =
	@echo "  CC      $@"
	$(Q)[ -d $(@D) ] || mkdir -p $(@D)
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(if $(AIO),$(filter %.c %.S %.s,$^),$<) -Wl,--start-group $(LDLIBS) -Wl,--end-group
endef

define schemelib =
obj/lib$(2).a: $(call objs,$(call schemesrc,$(1)))
libs: obj/lib$(2).a
elf/$(2)_%.elf: CPPFLAGS+=-I$(1)
elf/$(2)_%.elf: CPPFLAGS+=-DMUPQ_NAMESPACE=$(call namespace,$(2),$(3))
elf/$(2)_hashing.elf: PROFILE_HASHING=1
ifeq ($(AIO),1)
elf/$(2)_%.elf: crypto_$(3)_stream/%.c $(call schemesrc,$(1)) $(LINKDEPS)
	$$(compiletest)
else
elf/$(2)_%.elf: LDLIBS+=-l$(2)
elf/$(2)_%.elf: crypto_$(3)_stream/%.c obj/lib$(2).a $(LINKDEPS)
	$$(compiletest)
endif

tests:  elf/$(2)_test.elf elf/$(2)_cycles.elf elf/$(2)_stack.elf elf/$(2)_hashing.elf
tests-bin: bin/$(2)_test.bin  bin/$(2)_cycles.elf bin/$(2)_cycles.bin bin/$(2)_hashing.bin
endef

elf/mupq_pqclean_%.elf: MUPQ_NAMESPACE=$(shell tr)

$(foreach scheme,$(SIGN_SCHEMES), \
	$(eval $(call schemelib,$(scheme),$(call schemename,$(scheme)),sign)))
