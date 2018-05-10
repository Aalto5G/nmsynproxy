CC := cc
#CC := clang

.SUFFIXES:

DIRSYNPROXY := synproxy
LCSYNPROXY := synproxy
MODULES += SYNPROXY

DIRSACKHASH := sackhash
LCSACKHASH := sackhash
MODULES += SACKHASH

DIRTHREETUPLE := threetuple
LCTHREETUPLE := threetuple
MODULES += THREETUPLE

DIRDYNARR := pptk/dynarr
LCDYNARR := dynarr
MODULES += DYNARR

DIRMISC := pptk/misc
LCMISC := misc
MODULES += MISC

DIRHASHLIST := pptk/hashlist
LCHASHLIST := hashlist
MODULES += HASHLIST

DIRHASHTABLE := pptk/hashtable
LCHASHTABLE := hashtable
MODULES += HASHTABLE

DIRLINKEDLIST := pptk/linkedlist
LCLINKEDLIST := linkedlist
MODULES += LINKEDLIST

DIRTIMERLINKHEAP := pptk/timerlinkheap
LCTIMERLINKHEAP := timerlinkheap
MODULES += TIMERLINKHEAP

DIRLOG := pptk/log
LCLOG := log
MODULES += LOG

DIRIPHDR := pptk/iphdr
LCIPHDR := iphdr
MODULES += IPHDR

DIRPACKET := pptk/packet
LCPACKET := packet
MODULES += PACKET

DIRPORTS := pptk/ports
LCPORTS := ports
MODULES += PORTS

DIRALLOC := pptk/alloc
LCALLOC := alloc
MODULES += ALLOC

DIRDATABUF := pptk/databuf
LCDATABUF := databuf
MODULES += DATABUF

DIRNETMAP := pptk/netmap
LCNETMAP := netmap
MODULES += NETMAP

DIRIPHASH := pptk/iphash
LCIPHASH := iphash
MODULES += IPHASH

DIRMYPCAP := pptk/mypcap
LCMYPCAP := mypcap
MODULES += MYPCAP

DIRLDP := pptk/ldp
LCLDP := ldp
MODULES += LDP

CFLAGS := -g -O2 -Wall -Wextra -Wno-missing-field-initializers -Wno-unused-parameter -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith -Werror -std=gnu11 -fPIC

.PHONY: all clean distclean unit

all: $(MODULES)
clean: $(patsubst %,clean_%,$(MODULES))
distclean: $(patsubst %,distclean_%,$(MODULES))
unit: $(patsubst %,unit_%,$(MODULES))

MAKEFILES_COMMON := Makefile opts.mk

WITH_NETMAP=no
NETMAP_INCDIR=
WITH_ODP=no
ODP_DIR=/usr/local
LIBS_ODPDEP=/usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libcrypto.a
include opts.mk

$(foreach module,$(MODULES),$(eval \
    include $(DIR$(module))/module.mk))

opts.mk:
	touch opts.mk
