# This file is part of nss-mdns.
#
# nss-mdns is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# nss-mdns is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with nss-mdns; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

EXTRA_DIST=bootstrap.sh README.md ACKNOWLEDGEMENTS.md NEWS.md LICENSE
ACLOCAL_AMFLAGS=-I m4

# src
EXTRA_DIST += lib/map-file

AM_CFLAGS = \
	-DMDNS_ALLOW_FILE=\"$(MDNS_ALLOW_FILE)\" \
 	-DAVAHI_SOCKET=\"$(AVAHI_SOCKET)\"

AM_LDFLAGS=-avoid-version -module -export-dynamic

lib_LTLIBRARIES = \
	libnss_mdns.la \
	libnss_mdns4.la \
	libnss_mdns6.la \
	libnss_mdns_minimal.la \
	libnss_mdns4_minimal.la \
	libnss_mdns6_minimal.la

## check_PROGRAMS = nss-test avahi-test

libnss_mdns_la_SOURCES=lib/lnss.c lib/util.c lib/util.h lib/buff.c lib/buff.h lib/mdns.c lib/mdns.h lib/name.c lib/name.h lib/sock.c lib/sock.h
libnss_mdns_la_CFLAGS=$(AM_CFLAGS)
libnss_mdns_la_LDFLAGS=$(AM_LDFLAGS) -shrext .so.2 -Wl,-version-script=$(srcdir)/lib/map-file

libnss_mdns_minimal_la_SOURCES=$(libnss_mdns_la_SOURCES)
libnss_mdns_minimal_la_CFLAGS=$(libnss_mdns_la_CFLAGS) -DMDNS_MINIMAL
libnss_mdns_minimal_la_LDFLAGS=$(libnss_mdns_la_LDFLAGS)

libnss_mdns4_la_SOURCES=$(libnss_mdns_la_SOURCES)
libnss_mdns4_la_CFLAGS=$(libnss_mdns_la_CFLAGS) -DNSS_IPV4_ONLY=1
libnss_mdns4_la_LDFLAGS=$(libnss_mdns_la_LDFLAGS)

libnss_mdns4_minimal_la_SOURCES=$(libnss_mdns_la_SOURCES)
libnss_mdns4_minimal_la_CFLAGS=$(libnss_mdns_la_CFLAGS) -DNSS_IPV4_ONLY=1 -DMDNS_MINIMAL
libnss_mdns4_minimal_la_LDFLAGS=$(libnss_mdns_la_LDFLAGS)

libnss_mdns6_la_SOURCES=$(libnss_mdns_la_SOURCES)
libnss_mdns6_la_CFLAGS=$(libnss_mdns_la_CFLAGS) -DNSS_IPV6_ONLY=1
libnss_mdns6_la_LDFLAGS=$(libnss_mdns_la_LDFLAGS)

libnss_mdns6_minimal_la_SOURCES=$(libnss_mdns_la_SOURCES)
libnss_mdns6_minimal_la_CFLAGS=$(libnss_mdns_la_CFLAGS) -DNSS_IPV6_ONLY=1 -DMDNS_MINIMAL
libnss_mdns6_minimal_la_LDFLAGS=$(libnss_mdns_la_LDFLAGS)


install-exec-hook:
	rm -f $(DESTDIR)$(libdir)/libnss_mdns.la
	rm -f $(DESTDIR)$(libdir)/libnss_mdns_minimal.la
	rm -f $(DESTDIR)$(libdir)/libnss_mdns4.la
	rm -f $(DESTDIR)$(libdir)/libnss_mdns4_minimal.la
	rm -f $(DESTDIR)$(libdir)/libnss_mdns6.la
	rm -f $(DESTDIR)$(libdir)/libnss_mdns6_minimal.la

uninstall-hook:
	rm -f $(DESTDIR)$(libdir)/libnss_mdns.so.2
	rm -f $(DESTDIR)$(libdir)/libnss_mdns_minimal.so.2
	rm -f $(DESTDIR)$(libdir)/libnss_mdns4.so.2
	rm -f $(DESTDIR)$(libdir)/libnss_mdns4_minimal.so.2
	rm -f $(DESTDIR)$(libdir)/libnss_mdns6.so.2
	rm -f $(DESTDIR)$(libdir)/libnss_mdns6_minimal.so.2

