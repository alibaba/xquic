# Requirements

## Shared context registration

Registration must preserve ordinary HTTP/3 callbacks and all existing
application user data. Repeated or invalid registration must fail without
partially replacing the active configuration.

The engine implementation and destruction order remain unchanged. Connection
teardown uses connection-owned callback and configuration copies after ALPN
registration storage has been released. CONNECT routing uses existing H3
request callbacks in the WT adapter, without changing H3 request internals.

WT owns ALPN registration, connection callback wrapping and stream dispatch.
H3 exposes only SETTINGS entry/completion access and its existing input parser;
it has no WT registration framework or per-stream extension state.
WT stream classification and buffering belong to the WT H3 stream adapter.
Fragmented WT prefixes must classify once; non-WT prefixes must reach the
ordinary H3 parser unchanged. Closing during classification frees its state,
and read backpressure preserves both payload and FIN for retry.

## Server acceptance

A supported, authorized CONNECT request establishes a session on the
existing H3 connection. Unsupported endpoints and disallowed origins receive
an explicit rejection and never produce a successful session notification.

## Basic data exchange

An accepted session can exchange a bidirectional stream and a datagram.
Unknown session IDs must not deliver data to another session. Short writes
must preserve the unaccepted suffix and never count internal stream prefixes
as accepted application bytes.

## Lifetime

Closing and final close remain distinct. Application context and close
information remain usable during final notification. Local close, peer
close, and connection teardown must not double-release handles or leave
lookup entries pointing at freed sessions.

## Local demonstration

The demo listens on loopback with a configurable port. Its browser page
reports readiness, echo results, rejection and close distinctly. Protocol
version and browser version are recorded with the test results.
