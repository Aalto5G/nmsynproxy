CC := cc
#CC := clang

.SUFFIXES:

CFLAGS := -g -O2 -Wall -Werror

.PHONY: all clean distclean unit

all: $(MODULES)
clean: $(patsubst %,clean_%,$(MODULES))
distclean: $(patsubst %,distclean_%,$(MODULES))
unit: $(patsubst %,unit_%,$(MODULES))

MAKEFILES_COMMON := Makefile

$(foreach module,$(MODULES),$(eval \
    include $(DIR$(module))/module.mk))
