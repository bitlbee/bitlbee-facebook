libdir = $(plugindir)
lib_LTLIBRARIES = facebook.la

facebook_la_CFLAGS  = \
	$(BITLBEE_CFLAGS) \
	$(JSON_CFLAGS) \
	$(GLIB_CFLAGS)

facebook_la_LDFLAGS = \
	$(BITLBEE_LIBS) \
	$(JSON_LIBS) \
	$(GLIB_LIBS)

facebook_la_SOURCES = \
	facebook-marshal.c \
	facebook-marshal.h \
	facebook.c \
	facebook-api.c \
	facebook-api.h \
	facebook-data.c \
	facebook-data.h \
	facebook-glib.h \
	facebook-http.c \
	facebook-http.h \
	facebook-id.h \
	facebook-json.c \
	facebook-json.h \
	facebook-mqtt.c \
	facebook-mqtt.h \
	facebook-thrift.c \
	facebook-thrift.h \
	facebook-util.c \
	facebook-util.h

# Build the library as a module
facebook_la_LDFLAGS += -module -avoid-version

EXTRA_DIST = \
	marshaller.list

CLEANFILES = \
	facebook-marshal.c \
	facebook-marshal.h

facebook-marshal.c: $(srcdir)/marshaller.list facebook-marshal.h
	$(AM_V_GEN)echo "#include \"facebook-marshal.h\"" > $@
	$(AM_V_at)$(GLIB_GENMARSHAL) --prefix=fb_marshal --body $(srcdir)/marshaller.list >> $@

facebook-marshal.h: $(srcdir)/marshaller.list
	$(AM_V_GEN)$(GLIB_GENMARSHAL) --prefix=fb_marshal --header $(srcdir)/marshaller.list > $@
