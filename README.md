# PulseSMS Plugin for Pidgin

This plugin adds support for an additional protocol to Pidgin and libpurple-based instant messenger clients (eg bitlbee, spectrum2, Finch) to connect to the PulseSMS SMS relay app that runs on your Android phone.

# Requirements #
* An account at https://messenger.klinkerapps.com/overview/index.html
* The [PulseSMS Android app](https://play.google.com/store/apps/details?id=xyz.klinker.messenger&hl=en)

# Supported Features #
* one-to-one SMS
* image/MMS receiving

# Currently known issues #
* Messages can take up to 60s to appear in Pidgin due to message polling
* Group SMS/MMS don't display correctly

# Installation #
## Linux install ##
Requires devel headers/libs for libpurple and libjson-glib [libglib2.0-dev, libjson-glib-dev and libpurple-dev]
```bash
	git clone git://github.com/EionRobb/purple-pulsesms.git
	cd purple-pulsesms
	make
	sudo make install
```

## Windows install ##
Download nightly builds of [libpulsesms.dll](https://eion.robbmob.com/libpulsesms.dll) and copy into your C:\Program Files (x86)\Pidgin\plugins\ folder

