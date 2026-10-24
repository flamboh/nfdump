
bin_PROGRAMS = nfanon

compat16 = ../nfdump/compat_1_6_x/convert.c ../nfdump/compat_1_6_x/nfx.c ../nfdump/compat_1_6_x/nfx.h ../nfdump/compat_1_6_x/nfdump_1_6_x.h

nfanon_SOURCES = nfanon.c panonymizer.c panonymizer.h rijndael.c rijndael.h $(compat16)

nfanon_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/nfdump/compat_1_6_x -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libnffile -I$(top_srcdir)/src/libnffile/conf -I$(top_srcdir)/src/inline $(DEPS_CFLAGS)
nfanon_CFLAGS = $(PTHREAD_CFLAGS)

nfanon_LDADD = -lnffile $(PTHREAD_LIBS)
nfanon_LDFLAGS = -L../libnffile

CLEANFILES = *.gch
