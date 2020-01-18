What is TNAT64?
===============

TNAT64 is an interceptor which redirects outgoing TCPv4 connections
through NAT64, thus enabling an application running on an IPv6-only host
to communicate with the IPv4 world, even if that application does not
support IPv6 at all.

TNAT64 is based on the original code of [tsocks].

What is NAT64?
==============

According to [Wikipædia], '*NAT64 is a mechanism to allow IPv6 hosts to
communicate with IPv4 servers. The NAT64 server is the endpoint for at
least one IPv4 address and an IPv6 network segment of 32-bits (e.g.
64:FF9B::/96). The IPv6 client embeds the IPv4 address it wishes to
communicate with using these bits, and sends its packets to the
resulting address. The NAT64 server then creates a NAT-mapping between
the IPv6 and the IPv4 address, allowing them to communicate.*'

How does it work?
=================

From the user’s point of view, the application is run by prepending its
name with *tnat64*:

    $ tnat64 some-old-application

And then magic happens: when on an IPv6-only network, the application
uses NAT64 facilities to contact IPv4 hosts, and when IPv6 is not
available, but IPv4 is functional, IPv4 is used. Everything happens
without the need to reconfigure or recompile anything.

But how does it work deep inside?
=================================

TNAT64 is implemented as a shared object library which is loaded into
your application by means of the [ld.so(8)] `LD_PRELOAD` feature. The
library intercepts certain BSD socket calls (namely, [socket(2)] and
[connect(2)]). When an application creates a socket of `AF_INET` family
and `SOCK_STREAM` type, that is, a TCPv4 socket, that call is
intercepted, and an `AF_INET6` socket is returned instead. Following
this, any `connect(2)` call on this socket is also intercepted.
TNAT64 then decides whether the destination host is reachable over IPv4,
or instead needs to be forwarded to the NAT64.

The decision is made as follows:

1.  First, the configuration file is consulted to find the appropriate
    NAT64 prefix. If the prefix isn\'t specified for the destination
    network, this issue is reported to the user.
2.  The NAT64 destination address is constructed by appending the IPv4
    destination address to the NAT64 prefix. E.g. the destination
    address 198.51.100.192 and the NAT64 prefix [64:ff9b::/96] would
    result in the NAT64 address 64:ff9b::198.51.100.192 (aka
    64:ff9b::c933:64c0).
3.  A connection attempt is performed to that address.
4.  If the connection attempt fails because the destination network is
    unreachable, the IPv4-mapped IPv6 address is constructed and a
    connection attempt to that address is performed. These addresses
    have the prefix ::ffff:0:0/96 and are constructed just as described
    above. The connect call to this address is interpreted by the
    network stack the same way as if an TCPv4 connection was requested,
    thus the connection is made over IPv4 and not IPv6. This way the
    host can be reached via IPv4 when IPv6 networking is not available.
5.  The next time the connection is requested, the host is contacted
    using the last successful method.

[tsocks]: http://tsocks.sourceforge.net/
[Wikipædia]: http://en.wikipedia.org/wiki/NAT64
[ld.so(8)]: http://linux.die.net/man/8/ld.so
[socket(2)]: http://linux.die.net/man/2/socket
[connect(2)]: http://linux.die.net/man/2/connect
[64:ff9b::/96]: http://tools.ietf.org/html/rfc6052
