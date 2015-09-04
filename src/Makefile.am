WARNING_FLAGS= -Wall -Wshadow -Wmissing-declarations -Wmissing-prototypes \
		       -Wdeclaration-after-statement -Wstrict-prototypes \
		       -Wfloat-equal -Wno-unused-parameter -Wno-sign-compare

PROG_CFLAGS = -DDU_BIN_PATH=\"$(DU_BIN_PATH)\" \
			  -DMKFS_BIN_PATH=\"$(MKFS_BIN_PATH)\" \
			  -DCRYPTSETUP_BIN_PATH=\"$(CRYPTSETUP_BIN_PATH)\" \
			  -DPAMCONFIG_BIN_PATH=\"$(PAMCONFIG_BIN_PATH)\" \
              -DSYSCONFDIR=\"$(sysconfdir)\"

sbin_PROGRAMS = cryptconfig
cryptconfig_SOURCES = cryptconfig.c cryptconfig.h cryptconfig-lib.c
cryptconfig_LDFLAGS = $(GLIB_LIBS) `pkg-config --libs libcrypto` $(LIBXML_LIBS)
cryptconfig_CFLAGS = $(AM_CFLAGS) $(WARNING_FLAGS) $(PROG_CFLAGS) $(GLIB_CFLAGS) $(LIBXML_CFLAGS)

moduledir = @PAM_MODDIR@
module_LTLIBRARIES = pam_cryptpass.la
pam_cryptpass_la_SOURCES = cryptconfig.h cryptconfig-lib.c pam_cryptpass.c
pam_cryptpass_la_LDFLAGS = -module -avoid-version -lpam $(GLIB_LIBS) `pkg-config --libs libcrypto` $(LIBXML_LIBS)
pam_cryptpass_la_CFLAGS = $(AM_CFLAGS) $(WARNING_FLAGS) $(PROG_CFLAGS) $(GLIB_CFLAGS) $(LIBXML_CFLAGS)

CLEANFILES = $(sbin_PROGRAMS) $(module_LT_LIBRARIES)
