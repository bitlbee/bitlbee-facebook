libdir           = $(plugindir)
lib_LTLIBRARIES  = facebook.la

facebook_la_CFLAGS  = $(BITLBEE_CFLAGS) $(GLIB_CFLAGS)
facebook_la_LDFLAGS = $(BITLBEE_LIBS)   $(GLIB_LIBS)
facebook_la_SOURCES = \
	facebook.c \
	facebook.h

# Build the library as a module
facebook_la_LDFLAGS += -module -avoid-version
