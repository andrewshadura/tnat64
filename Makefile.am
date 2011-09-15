ACLOCAL_AMFLAGS = -I m4

bin_SCRIPTS = tnat64

do_subst =  sed -e 's,[@]libdir[@],$(libdir),g' \
		-e 's,[@]pkglibdir[@],$(pkglibdir),g' \
		-e 's,[@]bindir[@],$(bindir),g' \
		-e 's,[@]CONF_FILE[@],$(CONF_FILE),g' \
		-e 's,[@]PERL[@],$(PERL),g' \
		-e 's,[@]PACKAGE[@],$(PACKAGE),g' \
		-e 's,[@]VERSION[@],$(VERSION),g'

# It is tempting to generate tnat64 from tnat64.in during ./configure
# by adding it to AC_CONFIG_FILES() in configure.ac, but that has a
# horrible bug of leaving unexpanded variables in paths, which is
# unpleasant to work around.  The below is the recommended procedure.
tnat64: tnat64.in Makefile
	$(do_subst) < $(srcdir)/tnat64.in > tnat64
	chmod +x tnat64

tnat64.8: tnat64.8.in Makefile
	$(do_subst) < $(srcdir)/tnat64.8.in > tnat64.8

EXTRA_DIST = tnat64.in tnat64.8.in

bin_PROGRAMS = validateconf

validateconf_SOURCES = validateconf.c common.c parser.c
validateconf_CFLAGS = $(AM_CFLAGS) # this renames object files

pkglib_LTLIBRARIES = libtnat64.la

libtnat64_la_SOURCES = tnat64.c common.c parser.c
libtnat64_la_LDFLAGS = -Wc,-nostdlib
libtnat64_la_LIBADD = -ldl -lc

man_MANS = tnat64.1 tnat64.8 tnat64.conf.5

doc_DATA = tnat64.conf.complex.example tnat64.conf.simple.example

install-exec-hook:
	cd $(DESTDIR)$(pkglibdir) && \
	 rm -f libtnat64.a && \
	 rm -f libtnat64.la && \
	 rm -f libtnat64.so && \
	 rm -f libtnat64.so.0 && \
	 mv libtnat64.so.0.0.0 libtnat64.so
