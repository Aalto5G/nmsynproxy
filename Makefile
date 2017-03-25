
.PHONY: all

all: $(MODULES)
clean: $(patsubst %,clean_%,$(MODULES))
distclean: $(patsubst %,distclean_%,$(MODULES))

$(foreach module,$(MODULES),$(eval \
    include $(DIR$(module))/module.mk))
