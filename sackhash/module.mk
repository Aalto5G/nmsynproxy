SACKHASH_SRC_LIB := 
SACKHASH_SRC := $(SACKHASH_SRC_LIB) sackhashtest.c sackhashtest2.c

SACKHASH_SRC_LIB := $(patsubst %,$(DIRSACKHASH)/%,$(SACKHASH_SRC_LIB))
SACKHASH_SRC := $(patsubst %,$(DIRSACKHASH)/%,$(SACKHASH_SRC))

SACKHASH_OBJ_LIB := $(patsubst %.c,%.o,$(SACKHASH_SRC_LIB))
SACKHASH_OBJ := $(patsubst %.c,%.o,$(SACKHASH_SRC))

SACKHASH_DEP_LIB := $(patsubst %.c,%.d,$(SACKHASH_SRC_LIB))
SACKHASH_DEP := $(patsubst %.c,%.d,$(SACKHASH_SRC))

CFLAGS_SACKHASH := -I$(DIRHASHLIST) -I$(DIRMISC) -I$(DIRHASHTABLE) -I$(DIRTIMERLINKHEAP) -I$(DIRLINKEDLIST)
LIBS_SACKHASH := $(DIRTIMERLINKHEAP)/libtimerlinkheap.a

MAKEFILES_SACKHASH := $(DIRSACKHASH)/module.mk

.PHONY: SACKHASH clean_SACKHASH distclean_SACKHASH unit_SACKHASH $(LCSACKHASH) clean_$(LCSACKHASH) distclean_$(LCSACKHASH) unit_$(LCSACKHASH)

$(LCSACKHASH): SACKHASH
clean_$(LCSACKHASH): clean_SACKHASH
distclean_$(LCSACKHASH): distclean_SACKHASH
unit_$(LCSACKHASH): unit_SACKHASH

SACKHASH: $(DIRSACKHASH)/libsackhash.a $(DIRSACKHASH)/sackhashtest $(DIRSACKHASH)/sackhashtest2

unit_SACKHASH:
	@true

$(DIRSACKHASH)/libsackhash.a: $(SACKHASH_OBJ_LIB) $(MAKEFILES_COMMON) $(MAKEFILES_SACKHASH)
	rm -f $@
	ar rvs $@ $(filter %.o,$^)

$(DIRSACKHASH)/sackhashtest: $(DIRSACKHASH)/sackhashtest.o $(DIRSACKHASH)/libsackhash.a $(LIBS_SACKHASH) $(MAKEFILES_COMMON) $(MAKEFILES_SACKHASH)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_SACKHASH)

$(DIRSACKHASH)/sackhashtest2: $(DIRSACKHASH)/sackhashtest2.o $(DIRSACKHASH)/libsackhash.a $(LIBS_SACKHASH) $(MAKEFILES_COMMON) $(MAKEFILES_SACKHASH)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_SACKHASH)

$(SACKHASH_OBJ): %.o: %.c %.d $(MAKEFILES_COMMON) $(MAKEFILES_SACKHASH)
	$(CC) $(CFLAGS) -c -o $*.o $*.c $(CFLAGS_SACKHASH)

$(SACKHASH_DEP): %.d: %.c $(MAKEFILES_COMMON) $(MAKEFILES_SACKHASH)
	$(CC) $(CFLAGS) -MM -MP -MT "$*.d $*.o" -o $*.d $*.c $(CFLAGS_SACKHASH)

clean_SACKHASH:
	rm -f $(SACKHASH_OBJ) $(SACKHASH_DEP)

distclean_SACKHASH: clean_SACKHASH
	rm -f $(DIRSACKHASH)/libsackhash.a $(DIRSACKHASH)/sackhashtest $(DIRSACKHASH)/sackhashtest2

-include $(DIRSACKHASH)/*.d
