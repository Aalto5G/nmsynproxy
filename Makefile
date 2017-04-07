CC := cc
#CC := clang

.SUFFIXES:

DIRSYNPROXY := synproxy
LCSYNPROXY := synproxy
MODULES += SYNPROXY

DIRSACKHASH := sackhash
LCSACKHASH := sackhash
MODULES += SACKHASH

CFLAGS := -g -O2 -Wall -Wextra -Wno-missing-field-initializers -Wno-unused-parameter -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith -Werror -std=gnu11

.PHONY: all clean distclean unit

all: $(MODULES)
clean: $(patsubst %,clean_%,$(MODULES))
distclean: $(patsubst %,distclean_%,$(MODULES))
unit: $(patsubst %,unit_%,$(MODULES))

MAKEFILES_COMMON := Makefile opts.mk

WITH_NETMAP=no
NETMAP_INCDIR=
include opts.mk

$(foreach module,$(MODULES),$(eval \
    include $(DIR$(module))/module.mk))

opts.mk:
	touch opts.mk
