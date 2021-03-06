# nss-mdns

_Copyright 2004-2007 Lennart Poettering &lt;mzaffzqaf (at) 0pointer
(dot) de&gt;_

- [License](#license)
- [Overview](#overview)
- [Current Status](#current-status)
- [Documentation](#documentation)
- [Requirements](#requirements)
- [Installation](#installation)

## License

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

## Overview

`nss-mdns` is a plugin for the GNU Name Service Switch (NSS)
functionality of the GNU C Library (`glibc`) providing host name
resolution via [Multicast DNS](http://www.multicastdns.org/) (aka
_Zeroconf_, aka _Apple Rendezvous_, aka _Apple Bonjour_), effectively
allowing name resolution by common Unix/Linux programs in the ad-hoc
mDNS domain `.local`.

`nss-mdns` provides client functionality only, which
means that you have to run a mDNS responder daemon seperately
from `nss-mdns` if you want to register the local host name via
mDNS. I recommend [Avahi](http://avahi.org/).

`nss-mdns` is very lightweight (9 KByte stripped binary
`.so` compiled with `-DNDEBUG=1 -Os` on i386, `gcc`
4.0), has no dependencies besides the `glibc` and requires only
minimal configuration.

`nss-mdns` tries to contact a running
[avahi-daemon](http://avahi.org/) for resolving host names and
addresses and making use of its superior record cacheing. If
Avahi is not available at lookup time, the lookups will fail.

## Current Status

It works!

## Documentation

### Libraries

After compiling and installing `nss-mdns` you'll find six
new NSS modules in `/lib`:

- `libnss_mdns.so.2`
- `libnss_mdns4.so.2`
- `libnss_mdns6.so.2`
- `libnss_mdns_minimal.so.2`
- `libnss_mdns4_minimal.so.2`
- `libnss_mdns6_minimal.so.2`

`libnss_mdns.so.2`
resolves both IPv6 and IPv4 addresses, `libnss_mdns4.so.2` only
IPv4 addresses and `libnss_mdns6.so.2` only IPv6 addresses. Due
to the fact that most mDNS responders only register local IPv4
addresses via mDNS, most people will want to use
`libnss_mdns4.so.2` exclusively. Using
`libnss_mdns.so.2` or `libnss_mdns6.so.2` in such a
situation causes long timeouts when resolving hosts since most modern
Unix/Linux applications check for IPv6 addresses first, followed by a
lookup for IPv4.

`libnss_mdns{4,6,}_minimal.so` (new in version 0.8) is mostly
identical to the versions without `_minimal`. However, they differ in
one way. The minimal versions will always deny to resolve host names
that don't end in `.local` or addresses that aren't in the range
`169.254.x.x` (the range used by
[IPV4LL/APIPA/RFC3927](http://files.zeroconf.org/rfc3927.txt).)
Combining the `_minimal` and the normal NSS modules allows us to make
mDNS authoritative for Zeroconf host names and addresses (and thus
creating no extra burden on DNS servers with always failing requests)
and use it as fallback for everything else.

### Activation

To activate one of the NSS modules you have to edit
`/etc/nsswitch.conf` and add `mdns4` and
`mdns4_minimal` (resp. `mdns`, `mdns6`) to the
line starting with "`hosts:`". On Debian this looks like
this:

<pre># /etc/nsswitch.conf

passwd:         compat
group:          compat
shadow:         compat

hosts:          files <b>mdns4_minimal [NOTFOUND=return]</b> dns <b>mdns4</b>
networks:       files

protocols:      db files
services:       db files
ethers:         db files
rpc:            db files

netgroup:       nis</pre>

That's it. You should now be able to resolve hosts from the
`.local` domain with all your applications. For a quick check
use `glibc`'s `getent` tool:

<pre>$ getent hosts <i>foo</i>.local
192.168.50.4    foo.local</pre>

Replace _foo_ whith a host name that has been registered with
an mDNS responder. (Don't try to use the tools `host` or
`nslookup` for these tests! They bypass the NSS and thus
`nss-mdns` and issue their DNS queries directly.)

If you run a firewall, don't forget to allow UDP traffic to the the
mDNS multicast address `224.0.0.251` on port 5353.

## Requirements

Currently, `nss-mdns` is tested on Linux only. A fairly modern `glibc`
installation with development headers (2.0 or newer) is required. Not
suprisingly `nss-mdns` requires a kernel compiled with IPv4
multicasting support enabled. [Avahi](http://avahi.org/) is a hard
dependency when `nss-mdns` is used, however it is not a build-time
requirement.

`nss-mdns` was developed and tested on Debian GNU/Linux
"testing" from December 2004, it should work on most other Linux
distributions (and maybe Unix versions) since it uses GNU autoconf and
GNU libtool for source code configuration and shared library
management.

## Installation

As this package is made with the GNU autotools you should run
`./configure` inside the distribution directory for configuring
the source tree. After that you should run `make` for
compilation and `make install` (as root) for installation of
`nss-mdns`.
