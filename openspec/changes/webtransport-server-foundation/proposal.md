# WebTransport server foundation

Implement the first runnable server milestone on `feat/webtransport_16`,
based on `feat/webtransport_spec` at
`ab292cf812e0d864652e885da061d7d0870ceff9`.

The immutable server API inventory has 19 missing functions and three
callback-name gaps. Existing context ownership and stream dispatch are not
usable by the normal HTTP/3 demo. The first milestone provides a loopback
server, explicit session acceptance/rejection, basic stream/datagram echo,
and safe close handling through the server API.

Chrome interoperability is a compatibility milestone. Upstream QUICHE
currently negotiates draft-02/07. Draft-16 remains the production target;
this milestone must not advertise draft-16 or claim its conformance without
its required negotiation and RESET_STREAM_AT transport support.

Non-goals for this milestone: HTTP/2 capsule adapter, W3C client wrapper,
full implementation of every missing server API, and full draft-16 support.

The user explicitly selected the `feat/webtransport_16` branch name, which
overrides the repository's default feature prefix.
