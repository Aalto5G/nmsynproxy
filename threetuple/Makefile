MODULE:=THREETUPLE

all:
	while [ `pwd` != "/" -a \! -e INCLUSIVE_MAKE_ROOT ]; do cd ..; done; $(MAKE) $(MODULE)

clean:
	while [ `pwd` != "/" -a \! -e INCLUSIVE_MAKE_ROOT ]; do cd ..; done; $(MAKE) clean_$(MODULE)

distclean:
	while [ `pwd` != "/" -a \! -e INCLUSIVE_MAKE_ROOT ]; do cd ..; done; $(MAKE) distclean_$(MODULE)

unit:
	while [ `pwd` != "/" -a \! -e INCLUSIVE_MAKE_ROOT ]; do cd ..; done; $(MAKE) unit_$(MODULE)
