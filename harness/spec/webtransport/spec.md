# WebTransport over HTTP/3

## Scope and authority

The native binding implements
[draft-ietf-webtrans-http3-16](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-16.html)
and the compatibility binding from
[draft-ietf-webtrans-http3-07](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-07.html).
It uses HTTP/3 Extended CONNECT (RFC 9220), HTTP Datagrams and capsules
(RFC 9297), QUIC DATAGRAM (RFC 9221), and
[Reliable Stream Reset](../reliable-stream-reset/spec.md).
HTTP/2 transport and Docker interoperability infrastructure are outside this
capability. Unless otherwise qualified, section references below target -16.

## Build configuration

`XQC_ENABLE_WEBTRANSPORT` defaults to `OFF`. Enable it at configure time with
`-DXQC_ENABLE_WEBTRANSPORT=ON` to compile the native binding, public WT API,
private message wrapper, HTTP/3 framing guard, transport preparation hook,
WT unit tests, endpoint binary and demo echo handlers. Disabled builds omit
those sources, declarations and state; demo WT options are unavailable.
Reliable Reset, QUIC Datagram and generic HTTP/3 SETTINGS remain independent.

The laboratory CI driver explicitly enables WebTransport for both TLS jobs.
Endpoint groups require enabled CMake cache evidence; retain `CMakeCache.txt`
after compilation so the selector can distinguish enabled and disabled builds.
Validation enables WT by default. Use
`XQC_ENABLE_WEBTRANSPORT=OFF ./scripts/validate.sh test` for disabled coverage,
including in a reused build tree. `--feature webtransport` explicitly enables
it and adds focused feature checks to the complete unit suite. With WT OFF,
ordinary HTTP/3 continues to treat unnegotiated extension frame types as unknown
frames.

## Initialization and negotiation

Applications register their ordinary HTTP/3 callbacks before `xqc_wt_ctx_init`.
The binding preserves those callbacks and their application user data. Settings
and pending-datagram policy are configured before the first connection starts.
Default configuration supports one session, 128 streams per direction and a
1 MiB receive window. `draft_version` sets the highest supported revision:
the default -16 advertises both -16 and -07; an explicit -07 advertises only
-07. Both enable QUIC DATAGRAM; -16 also enables Reliable Stream Reset.
Configured uni/bidi stream counts must not exceed 2^60 (RFC 9000 Section 18.2).
Per-connect overrides retain the transport's zero-value defaults. Explicit
uni stream credit of one or two is rejected because the native HTTP/3 binding
requires a control stream and two QPACK streams; valid receive-window overrides
remain supported.

Section 3.1 requires SETTINGS_WT_ENABLED, H3_DATAGRAM, both QUIC transport
capabilities, and server ENABLE_CONNECT_PROTOCOL. A client sends no CONNECT
until peer SETTINGS and the TLS handshake complete. The highest common
revision wins (-07 Section 6, -16 Section 7.1). Draft-07 is selected only when
-16 is not shared and SETTINGS_WEBTRANSPORT_MAX_SESSIONS (0xc671706a) is
nonzero. It requires H3_DATAGRAM, QUIC DATAGRAM and server
ENABLE_CONNECT_PROTOCOL, without requiring Reliable Stream Reset
(-07 Sections 3.1 and 3.2). Missing -16 prerequisites do not trigger fallback
after -16 has been selected. Unknown peer settings remain compatible with
other extensions.
Malformed boolean values and out-of-range stream limits fail negotiation
without publishing partial WebTransport state. Settings use the internal
[batch registry contract](../http3-settings-registration/spec.md).
Local WT settings are committed atomically. If the application has left too
few registry slots, initialization logs an error, disables WT advertisement
and retains ordinary HTTP/3 on that connection. Missing peer Datagram support
disables the entire native WT binding, while ordinary HTTP/3 remains usable.

CONNECT uses `:method=CONNECT`, `:protocol=webtransport-h3` for -16 or
`:protocol=webtransport` for -07 (-07 Section 3.3), `:scheme=https`,
and nonempty authority plus an absolute path (Section 3.2; RFC 9114
Section 4.3.1). Required pseudo-header names occur exactly once, including
when a duplicate carries a different or empty value. Undefined or response-only
pseudo-headers are rejected before application acceptance. The server's acceptance
callback must validate application policy, including Origin for browser
clients; it receives the HTTP/3 connection user data. A missing callback
rejects with 403. Only successful 2xx responses
open a session. The acceptance callback supplies exactly one three-digit final
status; invalid local response headers abort CONNECT before transmission.
Responses reject request-only and undefined pseudo-headers before opening WT.
The response-status getter records the actual final status. Rejection,
malformed responses and unsupported prerequisites
never trigger a successful session notification. Section 3.3 application
protocol negotiation uses Structured Fields strings with bounded list sizes.
A nonempty application-protocol requirement fails locally when -07 is
selected, including a CONNECT queued before peer SETTINGS. The private msg
wrapper requires no such negotiation and works with either revision.
Terminal CONNECT send failures log the cause and notify session closure once.
The request retains session ownership until its normal destruction; a failed
CONNECT does not turn a session failure into an HTTP/3 connection failure.
A QPACK-blocked request may outlive its transport stream; failure still
notifies session closure but sends no transport frames once that stream is gone.

## Streams, datagrams and lifecycle

Sections 4.1 through 4.4 govern raw stream types, Session ID prefixes and
application error mapping. Prefixes are incrementally parsed; partial input,
partial writes, FIN-only delivery and receive backpressure must preserve
payload boundaries. Send APIs return accepted payload bytes, excluding the
prefix. Read callbacks consume the complete offered buffer with XQC_OK or
consume none with -XQC_EAGAIN. The FIN getters disambiguate zero-byte reads.
Stream callbacks may close their stream or session without use-after-free.
RFC 9000 Sections 10.1 and 10.2 also allow a connection to terminate while
WebTransport streams remain open. Once the QUIC connection enters CLOSING,
WT stream cleanup releases wrappers and sends final close notifications
without queuing RESET_STREAM, STOP_SENDING, or a deferred reliable prefix,
and without scheduling that connection again. Before CLOSING, session cleanup
retains its normal stream reset and stop behavior. Native endpoint regressions
cover client/server close, peer disappearance, and idle expiry with unread,
unfinished bidirectional streams for both negotiated WT revisions.
Send buffers are immutable. The public API exposes session and stream
lifecycle, flow control, datagrams and application protocol selection.
Connection access reuses the HTTP/3 handle; stream termination uses FIN,
RESET or STOP_SENDING. Revision selection remains internal to the binding;
applications configure the highest supported revision before connections start.

For -16, reliable size includes the stream type and Session ID for locally
initiated streams. A reset or STOP_SENDING arriving before the prefix can be queued
defers reset completion until the writable path queues that prefix. The
first STOP_SENDING error is retained. Deferred prefix storage outlives session
detachment. QUIC owns retransmission and directional reset errors. Short reads
that complete a reliable prefix still drain the pending reset notification while
QUIC marks the stream readable; no new peer traffic is needed. Ordinary HTTP/3
streams retain their existing behavior. Draft-07 uses ordinary RESET_STREAM
and does not defer STOP_SENDING to send a reliable prefix. When the prefix is
lost, only a connection configured for one session forwards a valid application
reset to its sole active session (-07 Section 4.3). This also applies before
the internal H3 stream object exists. Known ordinary H3 streams, known other
Session IDs, closed sessions, reserved error codes and pooled connections are
never guessed into that session. After either revision is negotiated,
0x41 is accepted only as the initial bidirectional WebTransport signal
(-07 Section 4.2, -16 Section 4.3). If the common HTTP/3 frame parser decodes it
as a frame type,
the connection fails with H3_FRAME_ERROR immediately after the type varint,
without waiting for a length or payload. Other unknown HTTP/3 frames remain
ignorable, and payload bytes are never treated as stream-start signals.

Datagrams encode Session ID / 4 and preserve one application message per
QUIC DATAGRAM. Sends reject oversize payloads atomically. Early datagrams and
unknown-session streams are bounded; stale, rejected and closed sessions
cannot receive application callbacks. Sent-datagram ownership survives loss
and late acknowledgement without calling a freed session.
Only streams awaiting a complete Session ID or a writable session occupy the
64-entry pending-stream queue. Immediately attachable streams bypass this
budget. At capacity, a new waiter replaces the oldest waiter, closing its
available directions with the buffered-stream-rejected code (-16 Section 4.6,
-07 Section 4.5). Fragmented prefixes retain their original queue position;
opening a session resumes its retained streams. Reclamation is driven by
capacity and stream/session lifecycle, without a fixed waiting timeout.
Session rejection and closure immediately reclaim early-datagram count and
byte budgets, including closure from a read callback. Retired session IDs
cannot reenter the early-datagram queue; ID zero before the first CONNECT
remains eligible for buffering. After a successful send,
WT retains only acknowledgement/loss metadata; the transport owns the payload
needed for retransmission.
When sent metadata reaches its limit, sends return -XQC_EAGAIN; an
acknowledgement or final loss that releases capacity resumes the writer.
Retransmission keeps its metadata slot. MSS notifications report the same
payload bound as the send API, including the Session ID prefix. The binding
registers transport datagram user data so transport MSS changes reach WT.
Raw stream adapters use a connection-local Stream
ID index for I/O lookup, retaining their list only for teardown. Ordinary H3
handoff and final stream closure remove the corresponding index entry.

Section 5 controls -16 pooling. Without negotiated per-session flow control,
-16 permits only one live session. Draft-07 instead uses the advertised
MAX_SESSIONS limit (-07 Section 3.4); clients respect both the peer limit and
local cap, while servers reject excess CONNECTs with H3_REQUEST_REJECTED.
Draft-07 neither enables per-session flow control nor emits -16 flow-control
capsules. Shared QUIC limits still apply. Pooling uses the configured
active-session limit, including values above 64; closed sessions awaiting destruction do not
occupy active slots. Pending CONNECTs count toward this limit even in
single-session mode before peer SETTINGS. Pooled sessions maintain independent
byte and uni/bidi stream credit, exchange WT_MAX_* and WT_*_BLOCKED capsules,
and reject overflow or credit violations. RESET final size remains chargeable
after local STOP_SENDING; already-accounted bytes are not charged again.
Discarded final bytes trigger the normal receive-window update policy without
waiting for the opposite direction of a bidirectional stream to close.
Unknown capsules are skipped without
unbounded allocation. Section 6 (-07 Section 5) governs DRAIN and CLOSE: validate
the UTF-8 reason (at most 1024 bytes), preserve the 32-bit application error, respond to
CLOSE before peer FIN, and notify final closure once. Later CONNECT reset
notifications preserve an established application close code. GOAWAY drains
sessions.
Borrowed strings and handles expire at their final close notification.
The final session notification receives NULL headers.

## Optional private message framing

The optional `xqc_webtransport_msg.h` wrapper implements the private v0 format
from [upstream PR 915](https://github.com/alibaba/xquic/pull/915). It borrows
one bidirectional stream and adds no WebTransport negotiation or stream type:

```
version (1 byte, 0) | flags (1 byte) | payload length (QUIC varint) | payload
```

Flag bit 0 selects text (1) or binary (0); other bits are ignored on receipt.
The length follows RFC 9000 Section 16. Empty messages, fragmented input and
multiple messages in one read are supported. A configured nonzero bound limits
each payload before allocation. Unknown versions, excessive lengths and FIN
in a partial header or payload produce terminal receive errors. Applications
choose the stream reset/STOP_SENDING code for these errors.

Sending copies one message at a time. A second message returns -XQC_EAGAIN
while the first remains queued. Short writes and flow-control blocking retain
the unsent bytes; the write callback resumes with `xqc_wt_msg_stream_flush`.
`xqc_wt_msg_stream_finish` queues FIN after the message and forbids later sends.
The complete-message callback borrows the payload only for its duration.
Destruction inside a callback is deferred until the active operation returns;
recursive receive or send flush is rejected. The application destroys the
wrapper by the underlying stream's final close notification.

## C demo echo

`demo_server -W` accepts `/wt` with exactly one Origin equal to
`http://127.0.0.1:8080` or `http://localhost:8080`. It echoes bidirectional
stream bytes and FIN, and each received Datagram. Ordinary HTTP/3 requests
continue through the existing callbacks. The demo's pending echo buffer is
bounded at 64 KiB per stream; a full buffer pauses reads until writable
notifications drain the echo and resume reading. Datagram sends blocked by
-XQC_EAGAIN are retried on writable notification, with at most 64 pending
datagrams across the demo. Queue exhaustion and permanent send errors are
logged; this bounded demo does not guarantee reliable datagram delivery.

`demo_client -W` negotiates one session (preferring -16) and verifies a binary
stream echo
(including embedded NUL bytes), FIN and a Datagram before closing the session.
Adding `-H <length>` sends a private framed text message containing that many
`d` bytes and verifies the echoed type, length and payload. Lengths must be
1..16777216, and `-H` requires `-W`. `-j` changes the Origin for rejection checks.
The existing `-K` option sets the total client lifetime in seconds; WT defaults
to 10 seconds when omitted. Failure, rejection or timeout exits nonzero.
These demos reuse their existing
TLS and event-loop setup and require no external server implementation.

From a build directory containing the existing `server.crt` and `server.key`:

```sh
./demo/demo_server -W -p 8443
./demo/demo_client -W -a 127.0.0.1 -p 8443
./demo/demo_client -W -H 65536 -a 127.0.0.1 -p 8443
```

## Validation

The enabled build includes the library API; no demo or Docker dependency is
required. Unit coverage pairs normal and abnormal paths for SETTINGS,
CONNECT/protocol selection, pooling, partial prefixes, capsules, UTF-8,
datagrams, HTTP/3 coexistence, reset deferral and callback reentrancy.

The native `webtransport.core` case group runs real client/server engines
over ephemeral UDP loopback sockets. `webtransport_transfer` covers delayed
CONNECT, streams in both directions, datagrams, reliable reset, DRAIN and
CLOSE. `webtransport_reject_origin` and `webtransport_missing_reset` cover
application rejection and failed transport prerequisites.
`webtransport_draft07_client` and `webtransport_draft07_server` each pair an
explicit -07 endpoint with a default dual-version peer, exercise the same
transfer/DRAIN/CLOSE paths and ordinary reset before the stream prefix.
`webtransport_draft07_reject_origin` and
`webtransport_draft07_misplaced_stream_type` cover rejection and the shared
0x41 frame guard on -07.
`webtransport_misplaced_stream_type` checks that a fragmented 0x41 on an
established CONNECT causes a peer-visible H3_FRAME_ERROR without a length.
`webtransport_settings_capacity` and `webtransport_missing_datagram` verify
WT refusal while an ordinary GET/200 exchange succeeds on the same connection.
`webtransport_pending_datagram_reject` fills the early queue, rejects the
corresponding session, then verifies another session can queue and receive
its datagram on the same connection.
`webtransport_session_limit` accepts 65 pooled sessions and rejects the next
CONNECT at the configured server limit. Unit tests also cover reuse of a
closed slot and failure of a QPACK-blocked request after transport closure.
`webtransport_reset_credit` exhausts a session window through reliable reset
and verifies another stream can send after receiving fresh WT_MAX_DATA.
`webtransport_connect_pseudo_headers` establishes a valid session, then checks
that an ambiguous CONNECT/GET request fails with peer-visible H3_MESSAGE_ERROR
without closing the HTTP/3 connection.
The `webtransport.demo` group runs the shipped C client and echo server:
raw bidi/Datagram echo, framed messages across varint boundaries up to 16 MiB,
Origin/path rejection, invalid message-length options, and ordinary HTTP/3.
Message unit tests cover binary/text and empty messages, fragmented/coalesced
input, nonminimal varints, partial writes, blocked FIN, malformed/truncated
input, size limits, and callback destruction. Malformed-message peer injection
is covered by units rather than an extra demo command mode.
The groups use named native cases and allocates no `test_client -x` numeric
selectors.
Use the repository validation entry point for the full unit suite, and:

```sh
XQC_BUILD_DIR=build/validation bash scripts/case_test.sh \
    --execute --module webtransport
```

Browser verification uses the C demo server and a local, uncommitted HTML
page. Start Chrome with `--enable-quic`,
`--enable-features=EnableWebTransportDraft07` and
`--origin-to-force-quic-on=127.0.0.1:8443`. For a self-signed test certificate,
use its exact `--ignore-certificate-errors-spki-list` value or pass its SHA-256
fingerprint through `serverCertificateHashes`; the latter requires a supported
short-lived certificate. Restart Chrome fully for startup flags to take effect.
Check ready, binary echo/FIN, a transfer larger than the demo buffer, private
msg bytes, Datagram, session close, and Origin/path rejection. Confirm the
server selected -07 in its debug log. HTML, certificate keys and browser
evidence stay outside Git. Browser checks supplement the committed native
cases; they do not cover malformed wire injection, HTTP/2 or other peers.
Existing HTTP/3 and Reliable Reset endpoint regressions remain required when
changing their shared paths.
