
PIDGIN_TREE_TOP ?= ../pidgin-2.10.11
PIDGIN3_TREE_TOP ?= ../pidgin-main
LIBPURPLE_DIR ?= $(PIDGIN_TREE_TOP)/libpurple
WIN32_DEV_TOP ?= $(PIDGIN_TREE_TOP)/../win32-dev

WIN32_CC ?= $(WIN32_DEV_TOP)/mingw-4.7.2/bin/gcc
MAKENSIS ?= makensis

PKG_CONFIG ?= pkg-config

CFLAGS	?= -O2 -g -pipe
LDFLAGS ?= 

# Do some nasty OS and purple version detection
ifeq ($(OS),Windows_NT)
  #only defined on 64-bit windows
  PROGFILES32 = ${ProgramFiles(x86)}
  ifndef PROGFILES32
    PROGFILES32 = $(PROGRAMFILES)
  endif
  PULSESMS_TARGET = libpulsesms.dll
  PULSESMS_DEST = "$(PROGFILES32)/Pidgin/plugins"
  PULSESMS_ICONS_DEST = "$(PROGFILES32)/Pidgin/pixmaps/pidgin/protocols"
  MAKENSIS = "$(PROGFILES32)/NSIS/makensis.exe"
else

  UNAME_S := $(shell uname -s)

  #.. There are special flags we need for OSX
  ifeq ($(UNAME_S), Darwin)
    #
    #.. /opt/local/include and subdirs are included here to ensure this compiles
    #   for folks using Macports.  I believe Homebrew uses /usr/local/include
    #   so things should "just work".  You *must* make sure your packages are
    #   all up to date or you will most likely get compilation errors.
    #
    INCLUDES = -I/opt/local/include -lz $(OS)

    CC = gcc
  else
    INCLUDES = 
    CC ?= gcc
  endif

  ifeq ($(shell $(PKG_CONFIG) --exists purple-3 2>/dev/null && echo "true"),)
    ifeq ($(shell $(PKG_CONFIG) --exists purple 2>/dev/null && echo "true"),)
      PULSESMS_TARGET = FAILNOPURPLE
      PULSESMS_DEST =
	  PULSESMS_ICONS_DEST =
    else
      PULSESMS_TARGET = libpulsesms.so
      PULSESMS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple`
	  PULSESMS_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple`/pixmaps/pidgin/protocols
    endif
  else
    PULSESMS_TARGET = libpulsesms3.so
    PULSESMS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple-3`
	PULSESMS_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple-3`/pixmaps/pidgin/protocols
  endif
endif

WIN32_CFLAGS = -I$(WIN32_DEV_TOP)/glib-2.28.8/include -I$(WIN32_DEV_TOP)/glib-2.28.8/include/glib-2.0 -I$(WIN32_DEV_TOP)/glib-2.28.8/lib/glib-2.0/include -I$(WIN32_DEV_TOP)/json-glib-0.14/include/json-glib-1.0 -DENABLE_NLS -DPACKAGE_VERSION='"$(PLUGIN_VERSION)"' -Wall -Wextra -Werror -Wno-deprecated-declarations -Wno-unused-parameter -fno-strict-aliasing -Wformat
WIN32_LDFLAGS = -L$(WIN32_DEV_TOP)/glib-2.28.8/lib -L$(WIN32_DEV_TOP)/json-glib-0.14/lib -lpurple -lintl -lglib-2.0 -lgobject-2.0 -ljson-glib-1.0 -g -ggdb -static-libgcc -lz
WIN32_PIDGIN2_CFLAGS = -I$(PIDGIN_TREE_TOP)/libpurple -I$(PIDGIN_TREE_TOP) $(WIN32_CFLAGS)
WIN32_PIDGIN3_CFLAGS = -I$(PIDGIN3_TREE_TOP)/libpurple -I$(PIDGIN3_TREE_TOP) -I$(WIN32_DEV_TOP)/gplugin-dev/gplugin $(WIN32_CFLAGS)
WIN32_PIDGIN2_LDFLAGS = -L$(PIDGIN_TREE_TOP)/libpurple $(WIN32_LDFLAGS)
WIN32_PIDGIN3_LDFLAGS = -L$(PIDGIN3_TREE_TOP)/libpurple -L$(WIN32_DEV_TOP)/gplugin-dev/gplugin $(WIN32_LDFLAGS) -lgplugin

C_FILES := aes.c pbkdf2_hmac_sha256.c
PURPLE_COMPAT_FILES := purple2compat/http.c purple2compat/purple-socket.c
PURPLE_C_FILES := libpulsesms.c $(C_FILES)



.PHONY:	all install FAILNOPURPLE clean

all: $(PULSESMS_TARGET)

libpulsesms.so: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(CC) -fPIC $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) `$(PKG_CONFIG) purple glib-2.0 json-glib-1.0 --libs --cflags`  $(INCLUDES) -Ipurple2compat -g -ggdb

libpulsesms3.so: $(PURPLE_C_FILES)
	$(CC) -fPIC $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) `$(PKG_CONFIG) purple-3 glib-2.0 json-glib-1.0 --libs --cflags` $(INCLUDES)  -g -ggdb

libpulsesms.dll: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(WIN32_CC) -shared -o $@ $^ $(WIN32_PIDGIN2_CFLAGS) $(WIN32_PIDGIN2_LDFLAGS) -Ipurple2compat

libpulsesms3.dll: $(PURPLE_C_FILES)
	$(WIN32_CC) -shared -o $@ $^ $(WIN32_PIDGIN3_CFLAGS) $(WIN32_PIDGIN3_LDFLAGS)

install: $(PULSESMS_TARGET) install-icons
	mkdir -p $(PULSESMS_DEST)
	install -p $(PULSESMS_TARGET) $(PULSESMS_DEST)

install-icons: pulsesms16.png pulsesms22.png pulsesms48.png
	mkdir -p $(PULSESMS_ICONS_DEST)/16
	mkdir -p $(PULSESMS_ICONS_DEST)/22
	mkdir -p $(PULSESMS_ICONS_DEST)/48
	install pulsesms16.png $(PULSESMS_ICONS_DEST)/16/pulsesms.png
	install pulsesms22.png $(PULSESMS_ICONS_DEST)/22/pulsesms.png
	install pulsesms48.png $(PULSESMS_ICONS_DEST)/48/pulsesms.png

FAILNOPURPLE:
	echo "You need libpurple development headers installed to be able to compile this plugin"

clean:
	rm -f $(PULSESMS_TARGET)


installer: purple-pulsesms.nsi libpulsesms.dll
	$(MAKENSIS) purple-pulsesms.nsi
