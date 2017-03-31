SYNPROXY_SRC_LIB := synproxy.c
SYNPROXY_SRC := $(SYNPROXY_SRC_LIB) workeronlyperf.c netmapsend.c

SYNPROXY_SRC_LIB := $(patsubst %,$(DIRSYNPROXY)/%,$(SYNPROXY_SRC_LIB))
SYNPROXY_SRC := $(patsubst %,$(DIRSYNPROXY)/%,$(SYNPROXY_SRC))

SYNPROXY_OBJ_LIB := $(patsubst %.c,%.o,$(SYNPROXY_SRC_LIB))
SYNPROXY_OBJ := $(patsubst %.c,%.o,$(SYNPROXY_SRC))

SYNPROXY_DEP_LIB := $(patsubst %.c,%.d,$(SYNPROXY_SRC_LIB))
SYNPROXY_DEP := $(patsubst %.c,%.d,$(SYNPROXY_SRC))

CFLAGS_SYNPROXY := -I$(DIRPACKET) -I$(DIRLINKEDLIST) -I$(DIRIPHDR) -I$(DIRMISC) -I$(DIRLOG) -I$(DIRHASHTABLE) -I$(DIRHASHLIST) -I$(DIRPORTS) -I$(DIRALLOC) -I$(DIRTIMERLINKHEAP)

MAKEFILES_SYNPROXY := $(DIRSYNPROXY)/module.mk

LIBS_SYNPROXY := $(DIRALLOC)/liballoc.a $(DIRIPHDR)/libiphdr.a $(DIRLOG)/liblog.a $(DIRPORTS)/libports.a $(DIRHASHTABLE)/libhashtable.a $(DIRHASHLIST)/libhashlist.a $(DIRTIMERLINKHEAP)/libtimerlinkheap.a

.PHONY: SYNPROXY clean_SYNPROXY distclean_SYNPROXY unit_SYNPROXY $(LCSYNPROXY) clean_$(LCSYNPROXY) distclean_$(LCSYNPROXY) unit_$(LCSYNPROXY)

$(LCSYNPROXY): SYNPROXY
clean_$(LCSYNPROXY): clean_SYNPROXY
distclean_$(LCSYNPROXY): distclean_SYNPROXY
unit_$(LCSYNPROXY): unit_SYNPROXY

SYNPROXY: $(DIRSYNPROXY)/libsynproxy.a $(DIRSYNPROXY)/workeronlyperf

ifeq ($(WITH_NETMAP),yes)
SYNPROXY: $(DIRSYNPROXY)/netmapsend
CFLAGS_SYNPROXY += -I$(NETMAP_INCDIR)
endif

unit_SYNPROXY: $(DIRSYNPROXY)/workeronlyperf
	$(DIRSYNPROXY)/workeronlyperf

$(DIRSYNPROXY)/libsynproxy.a: $(SYNPROXY_OBJ_LIB) $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	rm -f $@
	ar rvs $@ $(filter %.o,$^)

$(DIRSYNPROXY)/workeronlyperf: $(DIRSYNPROXY)/workeronlyperf.o $(DIRSYNPROXY)/libsynproxy.a $(LIBS_SYNPROXY) $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_SYNPROXY) -lpthread

$(DIRSYNPROXY)/netmapsend: $(DIRSYNPROXY)/netmapsend.o $(DIRSYNPROXY)/libsynproxy.a $(LIBS_SYNPROXY) $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_SYNPROXY) -lpthread

$(SYNPROXY_OBJ): %.o: %.c %.d $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	$(CC) $(CFLAGS) -c -o $*.o $*.c $(CFLAGS_SYNPROXY)

$(SYNPROXY_DEP): %.d: %.c $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	$(CC) $(CFLAGS) -MM -MP -MT "$*.d $*.o" -o $*.d $*.c $(CFLAGS_SYNPROXY)

clean_SYNPROXY:
	rm -f $(SYNPROXY_OBJ) $(SYNPROXY_DEP)

distclean_SYNPROXY: clean_SYNPROXY
	rm -f $(DIRSYNPROXY)/libsynproxy.a $(DIRSYNPROXY)/workeronlyperf

-include $(DIRSYNPROXY)/*.d
