# XQUIC WebTransport Specification

## Status and Scope

This document defines the target functional behavior, protocol-layer
boundaries, object model, and public C API for WebTransport over HTTP/3 in
XQUIC. It is a design specification; it does not claim that the current
implementation satisfies these requirements.

The protocol baseline is
[`draft-ietf-webtrans-http3-16`](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16),
published on 6 July 2026. The
[version-independent Datatracker page](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/)
must be checked before implementation starts because this is a work in
progress.

The initial XQUIC implementation targets the native HTTP/3 binding identified
by the `webtransport-h3` upgrade token. Capsule-based WebTransport using the
`webtransport` token, HTTP/2 transport, and intermediary translation are out
of scope.

Normative dependencies are:

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000): QUIC transport and
  streams.
- [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114): HTTP/3 stream and
  connection semantics.
- [RFC 9220](https://www.rfc-editor.org/rfc/rfc9220): Extended CONNECT for
  HTTP/3.
- [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221): QUIC DATAGRAM.
- [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297): HTTP Datagrams and the
  Capsule Protocol.
- [QUIC Stream Resets with Partial Delivery](https://datatracker.ietf.org/doc/draft-ietf-quic-reliable-stream-reset/):
  `RESET_STREAM_AT`.

## Protocol-Stack Position

WebTransport is an application transport protocol bound to HTTP/3. It is not
a replacement for QUIC and it is not a normal HTTP request body protocol.
HTTP/3 supplies connection negotiation, origin-aware session establishment,
the lifetime-bearing CONNECT stream, and capsule delivery. After a session is
established, WebTransport data uses native QUIC streams and QUIC DATAGRAMs
with a short session-association prefix.

```text
application protocol using WebTransport
                |
XQUIC WebTransport session / stream / datagram API
                |
WebTransport over HTTP/3
  - Extended CONNECT and capsules: HTTP/3 control plane
  - WT stream prefixes and HTTP Datagrams: data association
                |
HTTP/3 connection, SETTINGS, request dispatch, QPACK
                |
QUIC streams, QUIC DATAGRAM, RESET_STREAM_AT, flow control
                |
QUIC-TLS / UDP / IP
```

An HTTP/3 connection can simultaneously carry ordinary HTTP requests and
multiple WebTransport sessions. A WebTransport session therefore must not be
modeled as a QUIC connection or as the sole owner of an HTTP/3 connection.

## Object Model

The target ownership hierarchy is:

```text
xqc_engine_t
  `- xqc_h3_conn_t                 one per QUIC connection
       |- ordinary HTTP/3 requests
       `- internal WebTransport connection state
            |- xqc_wt_session_t    zero or more sessions
            |    |- CONNECT stream and capsule state
            |    |- xqc_wt_stream_t children
            |    `- session flow-control state
            `- bounded pending streams and datagrams
```

`xqc_wt_session_t` and `xqc_wt_stream_t` are public opaque handles. The
WebTransport connection wrapper, request parser, wire parser, flow-control
state, and pending-object registries are internal.

The internal WebTransport connection state is owned by `xqc_h3_conn_t`. It
must not replace `xqc_engine_t.user_data`, the application's HTTP/3 connection
user data, or transport user data.

## Stream and Datagram Mapping

| WebTransport concept | HTTP/3 role | QUIC mapping | Wire prefix |
|----------------------|-------------|--------------|-------------|
| Carrier connection | One HTTP/3 connection | One QUIC connection | HTTP/3 SETTINGS and QUIC transport parameters |
| Session / CONNECT stream | Extended CONNECT request and capsule stream | One client-initiated bidirectional QUIC stream | HTTP/3 HEADERS, then capsules |
| Unidirectional data stream | HTTP/3 extension stream type | One native unidirectional QUIC stream | Stream type `0x54`, Session ID, application bytes |
| Bidirectional data stream | Alternative HTTP/3 request-stream syntax | One native bidirectional QUIC stream | Signal value `0x41`, Session ID, application bytes |
| Datagram | HTTP Datagram associated with the CONNECT request | One QUIC DATAGRAM | Quarter Stream ID, application bytes |

### Session and CONNECT Stream

A client creates a session with an Extended CONNECT request as specified by
Sections 3.1 and 3.2 of the WebTransport draft. The request contains:

- `:method = CONNECT`;
- `:protocol = webtransport-h3`;
- `:scheme = https`;
- non-empty `:authority` and `:path`; and
- `Origin` when the application is a browser or otherwise requires origin
  validation.

The server accepts the session with a 2xx response. The session is open for
the client after receiving that response and for the server after sending it.
Redirects must be reported to the application and must not be followed
automatically. A WebTransport CONNECT request must not be initiated in 0-RTT.

The QUIC stream ID of the CONNECT stream is the Session ID. It is always a
client-initiated bidirectional stream ID. The CONNECT stream remains an HTTP/3
request stream for its lifetime and carries capsules after the 2xx response.
It is not counted as a WebTransport bidirectional data stream.

Closing the CONNECT stream or sending or receiving `WT_CLOSE_SESSION`
terminates the session. Session termination closes all associated data
streams with `WT_SESSION_GONE` and prevents new streams and datagrams.

### Unidirectional Data Streams

Each WebTransport unidirectional stream maps one-to-one to a native QUIC
unidirectional stream. Its first two values are:

```text
Stream Type = 0x54
Session ID  = CONNECT stream ID
```

All remaining bytes are application data. They are not HTTP/3 frames and must
not pass through QPACK or the HTTP request-body parser.

The local endpoint can send only on a locally initiated unidirectional
stream. A remotely initiated unidirectional stream is receive-only.

### Bidirectional Data Streams

Each WebTransport bidirectional stream maps one-to-one to a native QUIC
bidirectional stream. Its first two values are:

```text
Signal Value = 0x41
Session ID   = CONNECT stream ID
```

All remaining bytes are application data. `0x41` is registered as
`WT_STREAM` to avoid HTTP/3 frame-type collisions, but it has no length field
and is not an ordinary HTTP/3 frame.

On a client-initiated bidirectional stream, the HTTP/3 dispatcher must
distinguish a WebTransport stream from an ordinary request stream without
losing bytes. On a server-initiated bidirectional stream, the dispatcher can
accept the stream only after WebTransport support has been negotiated. After
classification, neither direction uses `xqc_h3_request_t` or the generic
HTTP/3 bytestream object.

### XQUIC H3 Stream Representation

Every WebTransport data stream has exactly one underlying `xqc_stream_t`.
XQUIC may retain an `xqc_h3_stream_t` as the HTTP/3 connection's dispatch and
lifetime container, but it must classify it as a WebTransport data stream.
The container must then route payload directly to `xqc_wt_stream_t` instead
of treating it as an HTTP request, QPACK stream, control stream, or generic
HTTP/3 bytestream.

The mapping is therefore:

```text
CONNECT stream: xqc_stream_t <-> xqc_h3_stream_t <-> xqc_h3_request_t
                                      `-> xqc_wt_session_t

WT data stream: xqc_stream_t <-> xqc_h3_stream_t <-> xqc_wt_stream_t
```

Public WebTransport APIs must not expose `xqc_h3_stream_t` or require an
application to construct internal H3 stream objects.

### Datagrams

WebTransport datagrams use HTTP Datagrams as specified by Section 4.5 of the
WebTransport draft and Section 2 of RFC 9297. The QUIC DATAGRAM payload is:

```text
Quarter Stream ID = CONNECT stream ID / 4
WebTransport application payload
```

The WebTransport payload is not fragmented by the WebTransport layer. A send
larger than the session datagram MSS fails; silently splitting it into
multiple datagrams would change application message boundaries.

Datagram APIs are session-scoped. A connection-scoped send API is ambiguous
when several sessions share one HTTP/3 connection and is not part of the
target API.

## Functional Requirements

### Capability Negotiation

Before a session can be created, XQUIC must validate the requirements in
Section 3.1 of the WebTransport draft:

- the server advertises `SETTINGS_WT_ENABLED = 1`;
- the server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`;
- both endpoints advertise `SETTINGS_H3_DATAGRAM = 1`;
- both endpoints enable QUIC DATAGRAM with a non-zero
  `max_datagram_frame_size`; and
- both endpoints negotiate `reset_stream_at`.

Draft-version codepoints must be kept in one internal version table. The
highest mutually supported version is selected. The initial implementation
supports draft 16 only; old draft-02 or draft-07 header conventions must not
be accepted under the draft-16 setting.

The client must not send a `webtransport-h3` CONNECT request until the
server's SETTINGS and required transport parameters have been validated. A
settings value or dependency violation produces the specific HTTP/3 or
WebTransport error required by the draft.

### Session Establishment and Protocol Negotiation

XQUIC owns all mandatory pseudo-header fields and validates the response
status. Applications supply the authority, path, optional origin, optional
additional safe headers, and optional ordered application protocol list.

When `WT-Available-Protocols` is supplied, the server can select one value in
`WT-Protocol`. XQUIC validates Structured Field syntax and rejects a selected
value that was not offered with `WT_ALPN_ERROR`.

Server acceptance is explicit. XQUIC must not send an implicit 200 response
before the application has accepted the authority, path, origin, and optional
application protocol.

### Optimistic Data and Demultiplexing

Streams and datagrams can arrive before the corresponding CONNECT response or
even before the CONNECT request is processed. The WebTransport connection
state therefore maintains bounded pending registries keyed by Session ID.

Pending data is not delivered to the application until its session is open.
There is no fallback to a default session. Unknown or closed Session IDs must
never be delivered to another session.

When pending-stream limits are exceeded, XQUIC rejects a stream with
`WT_BUFFERED_STREAM_REJECTED`. When pending-datagram limits are exceeded, it
drops a datagram. Counts and byte limits are configurable and enforced per
HTTP/3 connection.

Stream type and Session ID parsing must tolerate arbitrary fragmentation
across QUIC receive callbacks. Application payload is delivered only after
both values have been parsed and validated.

### Flow Control and Fairness

QUIC connection and stream flow control remain authoritative at the transport
layer. WebTransport additionally applies per-session stream-count and data
limits from Section 5 of the draft.

XQUIC automatically sends and consumes `WT_MAX_STREAMS`,
`WT_STREAMS_BLOCKED`, `WT_MAX_DATA`, and `WT_DATA_BLOCKED` capsules. The
application configures receive windows and limits; it does not encode
capsules directly.

If more than one WebTransport session can share an HTTP/3 connection, session
flow control is mandatory. A new stream can open only when both the QUIC
connection-level limit and WebTransport session-level limit permit it.

Scheduling must preserve fairness between ordinary HTTP traffic and
WebTransport sessions, and between sessions on the same connection. Session
priority follows RFC 9218. WebTransport does not define priority signaling
between streams inside one session.

### Reset, Close, and Drain

Public stream reset and stop-sending APIs use unsigned 32-bit WebTransport
application error codes. XQUIC maps them to and from the
`WT_APPLICATION_ERROR` HTTP/3 error range and skips reserved HTTP/3
codepoints as required by Section 4.4 of the draft.

Resetting a WebTransport data stream uses `RESET_STREAM_AT` with a reliable
size covering the complete stream type or signal value and Session ID. This
keeps the session association reliably deliverable.

`xqc_wt_session_close()` sends `WT_CLOSE_SESSION`, sends FIN on the CONNECT
stream, and terminates the session without closing unrelated sessions or the
HTTP/3 connection. `xqc_wt_session_drain()` sends `WT_DRAIN_SESSION` and
notifies the peer to begin graceful shutdown while allowing existing session
traffic to continue.

Receiving HTTP/3 GOAWAY prevents new sessions on that HTTP/3 connection and
notifies every existing session to drain. It does not immediately destroy
those sessions.

### Security and Resource Limits

Server applications are responsible for authorization of authority, path,
and Origin. XQUIC provides the parsed request and does not bypass the
application decision.

XQUIC enforces limits for sessions, pending decisions, streams, datagrams,
pending bytes, and session flow-control credit. Malformed settings, invalid
Session IDs, illegal stream prefixes, excessive buffering, and data after
session closure use the most specific error required by the draft.

TLS exporter support is session-separated using the
`EXPORTER-WebTransport` label and the context defined by Section 4.8 of the
draft.

## Module Boundaries

### Public API

`include/xquic/xqc_webtransport.h` contains only opaque handles, public value
types, callbacks, and exported functions. It can depend on public XQUIC and
HTTP/3 types but not on `src/` headers, demo code, or internal H3 stream
structures.

### WebTransport Module

`src/webtransport/` owns:

- engine-level WebTransport context and callback registration;
- per-H3-connection capability and session registries;
- CONNECT request validation and session state machines;
- stream prefix encoding, incremental parsing, and Session ID binding;
- HTTP Datagram context mapping;
- capsule handling and session-level flow control;
- application error conversion; and
- bounded optimistic-data buffering.

The module depends downward on explicit HTTP/3 and transport interfaces. It
must not dereference `xqc_h3_stream_t` or `xqc_stream_t` fields directly.

### HTTP/3 Module

`src/http3/` owns generic HTTP/3 mechanisms:

- SETTINGS encoding, parsing, and validation;
- Extended CONNECT request and response processing;
- Capsule Protocol framing on CONNECT streams;
- HTTP Datagram context encoding and decoding;
- HTTP/3 stream creation, lifetime, and first-value dispatch; and
- GOAWAY and RFC 9218 priority handling.

HTTP/3 exposes an internal extension-registration interface for
WebTransport. The HTTP/3 core does not include WebTransport headers or encode
WebTransport session policy. This dependency inversion allows HTTP/3 to call
registered WebTransport handlers without making ordinary HTTP/3 depend on the
optional feature module.

The existing generic HTTP/3 bytestream extension is not the WebTransport
stream abstraction and must not be reused as if its wire format were
compatible.

### QUIC Transport Module

`src/transport/` owns native stream creation and I/O, QUIC flow control,
QUIC DATAGRAM, final-size accounting, `RESET_STREAM_AT`, transport parameter
negotiation, and TLS exporter access. It contains no WebTransport session or
HTTP/3 framing logic.

The transport layer supplies enough internal API for WebTransport to:

- create unidirectional and bidirectional streams;
- send, receive, finish, reset, and stop a stream;
- preserve a reliable WebTransport stream header during reset;
- query final sizes for session flow-control accounting;
- send and receive QUIC DATAGRAM payloads; and
- derive session-specific exporter material through the TLS layer.

## Target Public API

The names below define the target source contract. Exact field ordering is an
ABI decision for implementation, but the stated behavior and ownership are
normative.

### Opaque Handles and State

```c
typedef struct xqc_wt_session_s xqc_wt_session_t;
typedef struct xqc_wt_stream_s  xqc_wt_stream_t;

typedef enum {
    XQC_WT_SESSION_CONNECTING,
    XQC_WT_SESSION_PENDING_ACCEPT,
    XQC_WT_SESSION_OPEN,
    XQC_WT_SESSION_DRAINING,
    XQC_WT_SESSION_CLOSED,
} xqc_wt_session_state_t;

typedef enum {
    XQC_WT_STREAM_UNIDIRECTIONAL,
    XQC_WT_STREAM_BIDIRECTIONAL,
} xqc_wt_stream_direction_t;
```

There is no public `xqc_wt_conn_t`. Applications use `xqc_h3_conn_t` for the
carrier connection and `xqc_wt_session_t` for WebTransport operations.

### Context Configuration

```c
xqc_int_t xqc_wt_ctx_init(xqc_engine_t *engine,
    const xqc_wt_settings_t *settings,
    const xqc_wt_callbacks_t *callbacks);

xqc_int_t xqc_wt_ctx_destroy(xqc_engine_t *engine);
```

`xqc_wt_ctx_init()` is called after `xqc_h3_ctx_init()` and before creating an
HTTP/3 connection. XQUIC copies the settings and callback table. It registers
the WebTransport extension without replacing existing HTTP/3 callbacks or
application user data.

`xqc_wt_settings_t` includes:

- maximum sessions per HTTP/3 connection;
- initial per-session bidirectional and unidirectional stream limits;
- initial per-session data window;
- maximum pending sessions, streams, datagrams, and pending bytes;
- session decision timeout; and
- automatic flow-control window update thresholds.

When settings allow more than one simultaneous session, non-zero session flow
control is required.

### Connection Capability Notification

```c
xqc_bool_t xqc_wt_conn_is_ready(xqc_h3_conn_t *h3_conn);
```

The callback table includes `wt_conn_ready_notify`. It fires after peer
SETTINGS and required QUIC transport parameters have been validated. The
boolean result distinguishes a WebTransport-capable HTTP/3 connection from a
normal HTTP/3 connection. Session creation before readiness fails with
`-XQC_EAGAIN`; it does not send a CONNECT request speculatively.

### Session APIs

```c
xqc_wt_session_t *xqc_wt_session_create(xqc_engine_t *engine,
    const xqc_cid_t *cid, const xqc_wt_session_config_t *config,
    void *session_user_data);

xqc_int_t xqc_wt_session_accept(xqc_wt_session_t *session,
    const xqc_str_t *selected_protocol,
    const xqc_http_headers_t *extra_response_headers);

xqc_int_t xqc_wt_session_reject(xqc_wt_session_t *session,
    uint16_t status_code,
    const xqc_http_headers_t *extra_response_headers);

xqc_int_t xqc_wt_session_close(xqc_wt_session_t *session,
    uint32_t application_error_code, const char *reason,
    size_t reason_len);

xqc_int_t xqc_wt_session_drain(xqc_wt_session_t *session);

xqc_wt_session_state_t
xqc_wt_session_get_state(const xqc_wt_session_t *session);

uint64_t xqc_wt_session_get_id(const xqc_wt_session_t *session);

void xqc_wt_session_set_user_data(xqc_wt_session_t *session,
    void *user_data);

void *xqc_wt_session_get_user_data(xqc_wt_session_t *session);
```

`xqc_wt_session_config_t` contains authority, path, optional Origin,
application protocols in preference order, optional safe extra headers, and
optional RFC 9218 priority. XQUIC copies all input strings and headers before
the call returns.

The callback table includes:

- `session_request_notify`: server authorization point; the application calls
  accept or reject, synchronously or before the decision timeout;
- `session_ready_notify`: the 2xx response has established the session;
- `session_drain_notify`: `WT_DRAIN_SESSION` or HTTP/3 GOAWAY was received;
  and
- `session_close_notify`: final callback with local or remote origin,
  optional 32-bit application error, protocol error, and reason.

No implicit session acceptance is permitted. After `session_close_notify`,
the session handle and borrowed close information are invalid.

### Stream APIs

```c
xqc_wt_stream_t *xqc_wt_stream_create(xqc_wt_session_t *session,
    xqc_wt_stream_direction_t direction,
    const xqc_stream_settings_t *settings, void *stream_user_data);

ssize_t xqc_wt_stream_send(xqc_wt_stream_t *stream,
    const unsigned char *data, size_t data_len, uint8_t fin);

ssize_t xqc_wt_stream_recv(xqc_wt_stream_t *stream,
    unsigned char *buf, size_t buf_size, uint8_t *fin);

xqc_int_t xqc_wt_stream_finish(xqc_wt_stream_t *stream);

xqc_int_t xqc_wt_stream_reset(xqc_wt_stream_t *stream,
    uint32_t application_error_code);

xqc_int_t xqc_wt_stream_stop_sending(xqc_wt_stream_t *stream,
    uint32_t application_error_code);

uint64_t xqc_wt_stream_get_id(const xqc_wt_stream_t *stream);

void xqc_wt_stream_set_user_data(xqc_wt_stream_t *stream,
    void *user_data);

void *xqc_wt_stream_get_user_data(xqc_wt_stream_t *stream);
```

A locally created unidirectional stream is send-only. A remotely created
unidirectional stream is receive-only. Invalid-direction operations fail
without changing stream state.

The callback table includes stream create, read, write, closing, and close
notifications. The create callback is delivered only after the stream is
bound to an open session. The closing callback reports whether a valid
WebTransport application error code was present. The close callback is the
last use of the stream handle.

Send and receive return the number of application bytes consumed, not bytes
used by the WebTransport prefix. Prefix bytes and retry state are entirely
owned by XQUIC.

### Datagram APIs

```c
size_t xqc_wt_datagram_get_mss(const xqc_wt_session_t *session);

xqc_int_t xqc_wt_datagram_send(xqc_wt_session_t *session,
    const void *data, size_t data_len, uint64_t *datagram_id,
    xqc_data_qos_level_t qos_level);
```

The returned MSS is the maximum WebTransport application payload after the
HTTP Datagram context prefix. An oversize send fails atomically.

The callback table includes session-scoped datagram read, write, acknowledged,
lost, and MSS-updated notifications. Received payload pointers are borrowed
for the callback duration. A lost notification never causes automatic
retransmission by the WebTransport layer.

### Session Exporter API

```c
xqc_int_t xqc_wt_session_export_keying_material(
    xqc_wt_session_t *session, const unsigned char *label,
    size_t label_len, const unsigned char *context, size_t context_len,
    unsigned char *output, size_t output_len);
```

XQUIC constructs the complete `EXPORTER-WebTransport` context internally.
Applications provide only their label and optional context.

## Prototype API Migration

The target API intentionally narrows the current prototype surface:

- `xqc_webtransport_connect()` is replaced by normal HTTP/3 connection
  creation followed by `xqc_wt_session_create()`, allowing connection reuse
  and multiple sessions.
- `xqc_wt_session_init()`, `xqc_wt_create_unistream()`, and constructors that
  accept `xqc_h3_stream_t *` become internal.
- Separate public uni- and bidirectional handle families are replaced by one
  `xqc_wt_stream_t` with an explicit direction.
- Connection-scoped datagram send becomes session-scoped.
- Public H3-stream getters and setters are removed.
- Session IDs are always derived from CONNECT stream IDs and are never
  application-assigned.
- Callback tables and configuration are copied into module-owned context;
  borrowed callback-structure pointers are not retained.

Compatibility aliases can exist during migration, but they must not preserve
obsolete draft-02 wire behavior under draft-16 negotiation.

## Non-Goals

- Capsule-based WebTransport data streams over one CONNECT stream.
- WebTransport over HTTP/2.
- HTTP/2-to-HTTP/3 intermediary translation.
- Automatic redirect following.
- WebTransport session creation in 0-RTT.
- Application-visible encoding of HTTP/3 settings, stream prefixes, HTTP
  Datagram context IDs, capsules, or WebTransport error-code mappings.

## Acceptance Criteria for a Future Implementation

A future implementation satisfies this specification when:

- ordinary HTTP/3 requests and multiple WebTransport sessions coexist on one
  connection without object or callback collisions;
- session negotiation enforces all draft-16 settings and transport
  dependencies;
- CONNECT, unidirectional, bidirectional, and datagram mappings match the
  table in this document;
- fragmented prefixes, optimistic arrival, unknown sessions, and bounded
  buffering are handled without cross-session delivery;
- session flow control and fairness protect co-resident sessions and HTTP
  traffic;
- reset, close, drain, GOAWAY, and exporter behavior use the required
  protocol semantics;
- no public API exposes internal H3 or QUIC stream structures; and
- happy-path and abnormal-path unit and endpoint tests cover every public
  behavior above.
