SYNPROXY_SRC_LIB := synproxy.c yyutils.c secret.c ctrl.c
SYNPROXY_SRC := $(SYNPROXY_SRC_LIB) workeronlyperf.c netmapproxy1.c netmapsend.c secrettest.c conftest.c pcapngworkeronly.c unittest.c sizeof.c

SYNPROXY_LEX_LIB := conf.l
SYNPROXY_LEX := $(SYNPROXY_LEX_LIB)

SYNPROXY_YACC_LIB := conf.y
SYNPROXY_YACC := $(SYNPROXY_YACC_LIB)

SYNPROXY_LEX_LIB := $(patsubst %,$(DIRSYNPROXY)/%,$(SYNPROXY_LEX_LIB))
SYNPROXY_LEX := $(patsubst %,$(DIRSYNPROXY)/%,$(SYNPROXY_LEX))

SYNPROXY_YACC_LIB := $(patsubst %,$(DIRSYNPROXY)/%,$(SYNPROXY_YACC_LIB))
SYNPROXY_YACC := $(patsubst %,$(DIRSYNPROXY)/%,$(SYNPROXY_YACC))

SYNPROXY_LEXGEN_LIB := $(patsubst %.l,%.lex.c,$(SYNPROXY_LEX_LIB))
SYNPROXY_LEXGEN := $(patsubst %.l,%.lex.c,$(SYNPROXY_LEX))

SYNPROXY_YACCGEN_LIB := $(patsubst %.y,%.tab.c,$(SYNPROXY_YACC_LIB))
SYNPROXY_YACCGEN := $(patsubst %.y,%.tab.c,$(SYNPROXY_YACC))

SYNPROXY_GEN_LIB := $(patsubst %.l,%.lex.c,$(SYNPROXY_LEX_LIB)) $(patsubst %.y,%.tab.c,$(SYNPROXY_YACC_LIB))
SYNPROXY_GEN := $(patsubst %.l,%.lex.c,$(SYNPROXY_LEX)) $(patsubst %.y,%.tab.c,$(SYNPROXY_YACC))

SYNPROXY_SRC_LIB := $(patsubst %,$(DIRSYNPROXY)/%,$(SYNPROXY_SRC_LIB))
SYNPROXY_SRC := $(patsubst %,$(DIRSYNPROXY)/%,$(SYNPROXY_SRC))

SYNPROXY_OBJ_LIB := $(patsubst %.c,%.o,$(SYNPROXY_SRC_LIB))
SYNPROXY_OBJ := $(patsubst %.c,%.o,$(SYNPROXY_SRC))

SYNPROXY_OBJGEN_LIB := $(patsubst %.c,%.o,$(SYNPROXY_GEN_LIB))
SYNPROXY_OBJGEN := $(patsubst %.c,%.o,$(SYNPROXY_GEN))

SYNPROXY_DEP_LIB := $(patsubst %.c,%.d,$(SYNPROXY_SRC_LIB))
SYNPROXY_DEP := $(patsubst %.c,%.d,$(SYNPROXY_SRC))

SYNPROXY_DEPGEN_LIB := $(patsubst %.c,%.d,$(SYNPROXY_GEN_LIB))
SYNPROXY_DEPGEN := $(patsubst %.c,%.d,$(SYNPROXY_GEN))

CFLAGS_SYNPROXY := -I$(DIRPACKET) -I$(DIRLINKEDLIST) -I$(DIRIPHDR) -I$(DIRMISC) -I$(DIRLOG) -I$(DIRHASHTABLE) -I$(DIRHASHLIST) -I$(DIRPORTS) -I$(DIRALLOC) -I$(DIRTIMERLINKHEAP) -I$(DIRMYPCAP) -I$(DIRDYNARR) -I$(DIRIPHASH) -I$(DIRSACKHASH) -I$(DIRTHREETUPLE) -I$(DIRDATABUF)

MAKEFILES_SYNPROXY := $(DIRSYNPROXY)/module.mk

LIBS_SYNPROXY := $(DIRSACKHASH)/libsackhash.a $(DIRIPHASH)/libiphash.a $(DIRMYPCAP)/libmypcap.a $(DIRDYNARR)/libdynarr.a $(DIRALLOC)/liballoc.a $(DIRIPHDR)/libiphdr.a $(DIRLOG)/liblog.a $(DIRPORTS)/libports.a $(DIRHASHTABLE)/libhashtable.a $(DIRHASHLIST)/libhashlist.a $(DIRTIMERLINKHEAP)/libtimerlinkheap.a $(DIRMISC)/libmisc.a $(DIRTHREETUPLE)/libthreetuple.a $(DIRDATABUF)/libdatabuf.a

.PHONY: SYNPROXY clean_SYNPROXY distclean_SYNPROXY unit_SYNPROXY $(LCSYNPROXY) clean_$(LCSYNPROXY) distclean_$(LCSYNPROXY) unit_$(LCSYNPROXY)

$(LCSYNPROXY): SYNPROXY
clean_$(LCSYNPROXY): clean_SYNPROXY
distclean_$(LCSYNPROXY): distclean_SYNPROXY
unit_$(LCSYNPROXY): unit_SYNPROXY

SYNPROXY: $(DIRSYNPROXY)/libsynproxy.a $(DIRSYNPROXY)/workeronlyperf $(DIRSYNPROXY)/secrettest $(DIRSYNPROXY)/conftest $(DIRSYNPROXY)/pcapngworkeronly $(DIRSYNPROXY)/unittest $(DIRSYNPROXY)/sizeof

ifeq ($(WITH_NETMAP),yes)
SYNPROXY: $(DIRSYNPROXY)/netmapproxy1 $(DIRSYNPROXY)/netmapsend
CFLAGS_SYNPROXY += -I$(NETMAP_INCDIR)
endif

unit_SYNPROXY: $(DIRSYNPROXY)/workeronlyperf $(DIRSYNPROXY)/secrettest $(DIRSYNPROXY)/unittest
	$(DIRSYNPROXY)/workeronlyperf
	$(DIRSYNPROXY)/secrettest
	$(DIRSYNPROXY)/unittest

$(DIRSYNPROXY)/libsynproxy.a: $(SYNPROXY_OBJ_LIB) $(SYNPROXY_OBJGEN_LIB) $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	rm -f $@
	ar rvs $@ $(filter %.o,$^)

$(DIRSYNPROXY)/workeronlyperf: $(DIRSYNPROXY)/workeronlyperf.o $(DIRSYNPROXY)/libsynproxy.a $(LIBS_SYNPROXY) $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_SYNPROXY) -lpthread

$(DIRSYNPROXY)/netmapproxy1: $(DIRSYNPROXY)/netmapproxy1.o $(DIRSYNPROXY)/libsynproxy.a $(LIBS_SYNPROXY) $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_SYNPROXY) -lpthread

$(DIRSYNPROXY)/netmapsend: $(DIRSYNPROXY)/netmapsend.o $(DIRSYNPROXY)/libsynproxy.a $(LIBS_SYNPROXY) $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_SYNPROXY) -lpthread

$(DIRSYNPROXY)/secrettest: $(DIRSYNPROXY)/secrettest.o $(DIRSYNPROXY)/libsynproxy.a $(LIBS_SYNPROXY) $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_SYNPROXY) -lpthread

$(DIRSYNPROXY)/conftest: $(DIRSYNPROXY)/conftest.o $(DIRSYNPROXY)/libsynproxy.a $(LIBS_SYNPROXY) $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_SYNPROXY) -lpthread

$(DIRSYNPROXY)/pcapngworkeronly: $(DIRSYNPROXY)/pcapngworkeronly.o $(DIRSYNPROXY)/libsynproxy.a $(LIBS_SYNPROXY) $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_SYNPROXY) -lpthread

$(DIRSYNPROXY)/unittest: $(DIRSYNPROXY)/unittest.o $(DIRSYNPROXY)/libsynproxy.a $(LIBS_SYNPROXY) $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_SYNPROXY) -lpthread

$(DIRSYNPROXY)/sizeof: $(DIRSYNPROXY)/sizeof.o $(DIRSYNPROXY)/libsynproxy.a $(LIBS_SYNPROXY) $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_SYNPROXY) -lpthread

$(SYNPROXY_OBJ): %.o: %.c %.d $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	$(CC) $(CFLAGS) -c -o $*.o $*.c $(CFLAGS_SYNPROXY)
$(SYNPROXY_OBJGEN): %.o: %.c %.h %.d $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	$(CC) $(CFLAGS) -c -o $*.o $*.c $(CFLAGS_SYNPROXY) -Wno-sign-compare -Wno-missing-prototypes

$(SYNPROXY_DEP): %.d: %.c $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	$(CC) $(CFLAGS) -MM -MP -MT "$*.d $*.o" -o $*.d $*.c $(CFLAGS_SYNPROXY)
$(SYNPROXY_DEPGEN): %.d: %.c %.h $(MAKEFILES_COMMON) $(MAKEFILES_SYNPROXY)
	$(CC) $(CFLAGS) -MM -MP -MT "$*.d $*.o" -o $*.d $*.c $(CFLAGS_SYNPROXY)

$(DIRSYNPROXY)/conf.lex.d: $(DIRSYNPROXY)/conf.tab.h $(DIRSYNPROXY)/conf.lex.h
$(DIRSYNPROXY)/conf.lex.o: $(DIRSYNPROXY)/conf.tab.h $(DIRSYNPROXY)/conf.lex.h
$(DIRSYNPROXY)/conf.tab.d: $(DIRSYNPROXY)/conf.lex.h $(DIRSYNPROXY)/conf.tab.h
$(DIRSYNPROXY)/conf.tab.o: $(DIRSYNPROXY)/conf.lex.h $(DIRSYNPROXY)/conf.tab.h

$(DIRSYNPROXY)/CONF.LEX.INTERMEDIATE: $(DIRSYNPROXY)/conf.l
	mkdir -p $(DIRSYNPROXY)/intermediatestore
	flex --outfile=$(DIRSYNPROXY)/intermediatestore/conf.lex.c --header-file=$(DIRSYNPROXY)/intermediatestore/conf.lex.h $(DIRSYNPROXY)/conf.l
	touch $(DIRSYNPROXY)/CONF.LEX.INTERMEDIATE
$(DIRSYNPROXY)/CONF.TAB.INTERMEDIATE: $(DIRSYNPROXY)/conf.y
	mkdir -p $(DIRSYNPROXY)/intermediatestore
	bison --defines=$(DIRSYNPROXY)/intermediatestore/conf.tab.h --output=$(DIRSYNPROXY)/intermediatestore/conf.tab.c $(DIRSYNPROXY)/conf.y
	touch $(DIRSYNPROXY)/CONF.TAB.INTERMEDIATE
$(DIRSYNPROXY)/conf.lex.c: $(DIRSYNPROXY)/CONF.LEX.INTERMEDIATE
	cp $(DIRSYNPROXY)/intermediatestore/conf.lex.c $(DIRSYNPROXY)
$(DIRSYNPROXY)/conf.lex.h: $(DIRSYNPROXY)/CONF.LEX.INTERMEDIATE
	cp $(DIRSYNPROXY)/intermediatestore/conf.lex.h $(DIRSYNPROXY)
$(DIRSYNPROXY)/conf.tab.c: $(DIRSYNPROXY)/CONF.TAB.INTERMEDIATE
	cp $(DIRSYNPROXY)/intermediatestore/conf.tab.c $(DIRSYNPROXY)
$(DIRSYNPROXY)/conf.tab.h: $(DIRSYNPROXY)/CONF.TAB.INTERMEDIATE
	cp $(DIRSYNPROXY)/intermediatestore/conf.tab.h $(DIRSYNPROXY)

clean_SYNPROXY:
	rm -f $(SYNPROXY_OBJ) $(SYNPROXY_OBJGEN) $(SYNPROXY_DEP) $(SYNPROXY_DEPGEN)
	rm -rf $(DIRSYNPROXY)/intermediatestore
	rm -f $(DIRSYNPROXY)/CONF.TAB.INTERMEDIATE
	rm -f $(DIRSYNPROXY)/CONF.LEX.INTERMEDIATE
	rm -f $(DIRSYNPROXY)/conf.lex.c
	rm -f $(DIRSYNPROXY)/conf.lex.h
	rm -f $(DIRSYNPROXY)/conf.tab.c
	rm -f $(DIRSYNPROXY)/conf.tab.h

distclean_SYNPROXY: clean_SYNPROXY
	rm -f $(DIRSYNPROXY)/libsynproxy.a $(DIRSYNPROXY)/workeronlyperf $(DIRSYNPROXY)/netmapproxy $(DIRSYNPROXY)/netmapsend $(DIRSYNPROXY)/secrettest $(DIRSYNPROXY)/conftest $(DIRSYNPROXY)/pcapngworkeronly $(DIRSYNPROXY)/unittest $(DIRSYNPROXY)/sizeof

-include $(DIRSYNPROXY)/*.d
