# XQUIC WebTransport Implementation Specification

## Purpose and Scope

This document defines only the XQUIC-specific implementation architecture,
object ownership, module interfaces, public C API, and migration constraints
for WebTransport over HTTP/3. It does not redefine the WebTransport protocol.

The initial implementation target is the native HTTP/3 binding in
[`draft-ietf-webtrans-http3-16`](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16).
Before implementation or review begins, the version-independent
[IETF Datatracker entry](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/)
must be checked for a newer draft or a published RFC.

This is a target design. Existing prototype symbols under
`include/xquic/xqc_webtransport.h` and `src/webtransport/` do not establish
conformance with this document.

## Authority and Conformance

An XQUIC WebTransport implementation must satisfy both:

1. the governing IETF WebTransport over HTTP/3 specification; and
2. the XQUIC implementation and API requirements in this document.

The governing IETF source owns all protocol behavior, including wire values,
HTTP fields, SETTINGS and transport parameters, frame and capsule formats,
state transitions, flow-control rules, error codes, and security requirements.
Those requirements are incorporated here by reference and are intentionally
not repeated.

Authority is resolved in this order:

1. an applicable published IETF RFC;
2. while no RFC exists, the draft revision selected by XQUIC's advertised
   compatibility version; and
3. this project specification for XQUIC choices not fixed by the IETF source.

If this document conflicts with a governing RFC or draft, the IETF source
wins. The conflict is a defect in this document and must be corrected before,
or in the same change as, the affected implementation. Implementers must not
retain behavior solely because it appears in this document.

Section references below use draft 16. They are navigation links, not copied
protocol requirements:

- [Sections 3.1-3.3](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-3)
  govern connection and session setup. This document owns the XQUIC readiness
  gate, application decision API, and callback ownership.
- [Section 3.4](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-3.4)
  governs prioritization. This document owns integration with the existing
  XQUIC scheduler.
- [Sections 4.2-4.6](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-4.2)
  govern streams and datagrams. This document owns object binding,
  incremental dispatch, buffering, and the public I/O API.
- [Section 4.4](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-4.4)
  and [Section 4.8](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-4.8)
  govern stream resets and exporters. This document owns the transport and
  TLS adapter contracts.
- [Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-5)
  governs session flow control. This document owns accounting structures,
  configured limits, and the local window-update policy.
- [Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-6)
  governs session termination. This document owns teardown ordering and
  callback lifetime.
- [Section 7.1](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-7.1)
  governs draft compatibility. This document owns version tables and codec
  selection.

## Design Scope

The first production implementation supports native WebTransport over HTTP/3.
Capsule-based WebTransport data transport, HTTP/2 transport, and intermediary
translation are outside this implementation scope. This scope decision does
not alter any requirement for the supported native binding.

XQUIC exposes WebTransport as an application-facing service above HTTP/3 and
uses QUIC streams, QUIC DATAGRAM, and TLS through internal adapters. Protocol
encoding and decoding remain internal; applications operate on sessions,
streams, datagrams, and application error values.

The implementation must allow ordinary HTTP/3 requests and multiple
WebTransport sessions to share one HTTP/3 connection. A session is therefore
not represented as a QUIC connection and does not own connection-wide
application user data.

## Ownership and Object Model

The target ownership hierarchy is:

```text
xqc_engine_t
  `- xqc_h3_conn_t
       |- ordinary HTTP/3 request objects
       `- internal WebTransport connection state
            |- capability and version state
            |- session registry
            |- bounded unresolved-input registries
            `- xqc_wt_session_t
                 |- carrier request reference
                 |- xqc_wt_stream_t children
                 |- datagram state
                 `- session flow-control accounting
```

`xqc_wt_session_t` and `xqc_wt_stream_t` are public opaque handles. The
connection extension state, request adapter, protocol codec, flow-control
accounting, and unresolved-input registries are private.

The WebTransport connection state is allocated and freed with
`xqc_h3_conn_t`. It must not replace or alias any of the following:

- `xqc_engine_t.user_data`;
- HTTP/3 connection application data;
- QUIC transport application data; or
- another HTTP/3 extension's private state.

A session owns its WebTransport stream handles and session-scoped pending
callbacks. It borrows its carrier HTTP/3 connection and transport objects.
Connection teardown invalidates sessions only after their close callbacks have
completed.

## Internal Integration Design

### HTTP/3 Extension Boundary

`src/http3/` remains responsible for generic HTTP/3 connection and stream
mechanisms. It exposes an internal extension interface that allows the
WebTransport module to:

- register capability SETTINGS and validate their parsed peer values;
- register the supported Extended CONNECT protocol token;
- receive the carrier request and response state transitions;
- register first-value classifiers for extension streams;
- send and receive capsules through a generic capsule codec;
- send and receive HTTP Datagram contexts; and
- observe connection drain and close events.

The extension callbacks receive parsed values and stable object references.
They do not require WebTransport to access private `xqc_h3_conn_t` or
`xqc_h3_stream_t` fields.

HTTP/3 owns generic parsing, QPACK, request lifetime, and extension dispatch.
It must not own WebTransport session policy, application callbacks, per-session
limits, or WebTransport public handles.

The existing generic HTTP/3 bytestream extension is not used as the public
WebTransport stream abstraction. A shared internal dispatch primitive is
acceptable only when the two extensions retain separate protocol codecs and
lifetimes.

### QUIC Transport Boundary

`src/transport/` remains unaware of WebTransport sessions. It supplies stable
internal operations for the WebTransport and HTTP/3 layers to:

- create and operate native unidirectional and bidirectional streams;
- expose stream direction and initiator metadata;
- retain protocol header bytes required by reliable reset;
- obtain final-size information for session accounting;
- send and receive QUIC DATAGRAM payloads;
- query the application-payload MSS after caller-supplied overhead; and
- access the TLS exporter through the TLS integration layer.

Transport APIs report QUIC state and errors without translating them into
WebTransport application errors. That translation belongs to the
WebTransport protocol adapter.

### WebTransport Module

`src/webtransport/` owns:

- engine-level settings and callback registration;
- per-HTTP/3-connection capability, version, and session registries;
- the application-facing session state machine;
- incremental protocol-prefix dispatch and session binding;
- session-scoped datagram routing;
- capsule handlers and session flow-control accounting;
- conversion between public application errors and protocol errors; and
- bounded buffering for input whose session cannot yet be resolved.

The module depends on explicit HTTP/3, QUIC, and TLS adapter APIs. Production
code under `src/webtransport/` must not dereference private HTTP/3 or transport
object fields.

### Internal Object Binding

The carrier request keeps the normal HTTP/3 request representation and stores
a reference to its `xqc_wt_session_t`. Each WebTransport data stream has one
underlying `xqc_stream_t` and one WebTransport stream handle.

An `xqc_h3_stream_t` may remain as the HTTP/3 dispatch and lifetime container,
but after classification it routes application bytes to
`xqc_wt_stream_t`. It must not also expose those bytes through HTTP request,
QPACK, control-stream, or generic bytestream callbacks.

```text
carrier request: xqc_stream_t <-> xqc_h3_stream_t <-> xqc_h3_request_t
                                                       `-> xqc_wt_session_t

data stream:     xqc_stream_t <-> dispatch container <-> xqc_wt_stream_t
```

Public APIs never expose the dispatch container or accept an internal HTTP/3
stream pointer.

### Incremental Dispatch

The WebTransport codec consumes protocol prefixes incrementally. Parser state
is stored on the candidate stream so any split across receive callbacks is
handled without copying already-consumed bytes or exposing prefix bytes to the
application.

Classification has exactly three outcomes:

- `need more data`: retain bounded parser state;
- `bound`: attach the stream to one resolved session and switch permanently
  to WebTransport application-byte delivery; or
- `reject`: invoke the protocol adapter's error path and never deliver the
  bytes to an application.

There is no fallback or default session. A stream or datagram that cannot be
resolved must not be delivered to another session.

### Unresolved Input

The connection extension state contains bounded registries for streams and
datagrams that arrive before their session can be resolved. Limits include
object counts, aggregate bytes, and a lifetime deadline. The public settings
provide the bounds; internal defaults must be finite.

Once the session becomes deliverable, queued objects are drained in arrival
order per object class. Once the session is rejected, closed, or times out,
the registries discard or reject queued input through the governing protocol
error path.

No application callback is invoked for unresolved input. Buffer ownership
remains inside XQUIC until delivery or disposal.

### Flow-Control Accounting

Session accounting is separate from QUIC connection and stream accounting.
The WebTransport module stores, for each direction and stream class:

- the effective peer and local limits;
- opened and closed stream counts;
- application bytes consumed against the session data limit;
- the last advertised limits; and
- blocked notification state.

The accounting layer obtains stream final sizes from the transport adapter and
excludes internal protocol-prefix bytes. Limit changes are serialized through
the carrier request's capsule sender. Local window-update heuristics use
configurable thresholds and remain subordinate to the governing IETF rules.

The scheduler reuses the existing HTTP/3 priority state associated with the
carrier request for competition among HTTP requests and WebTransport
sessions. The first API version does not add XQUIC-specific priority signaling
among streams inside one session.

### Error and Teardown Isolation

The protocol codec owns the tables and algorithms that map application errors
to protocol codepoints. Public APIs accept and report only the application
error width defined by the governing IETF source; raw mapped HTTP/3 values are
not public inputs.

A stream failure tears down only that stream unless the governing IETF source
classifies it as a session or connection error. A session close tears down its
owned streams, queued input, and callbacks without closing unrelated sessions
or ordinary HTTP/3 requests unless the governing source requires a connection
error.

Teardown order is:

1. stop new application operations on the object;
2. detach it from lookup registries;
3. complete its final application callback;
4. release child and buffered objects; and
5. release the opaque handle.

Callbacks may inspect borrowed close information only for the duration of the
callback. A handle is invalid after its final close callback returns.

### Version Adapter

All revision-specific identifiers and codecs live in one internal immutable
version table. Session, stream, datagram, and capsule paths select one table
from the negotiated connection version and never mix tables on a connection.

The initial table targets draft 16. Adding another draft or RFC requires:

- reviewing the current version-independent IETF source;
- adding or updating one version table and its codec tests;
- updating compatibility declarations exposed by XQUIC; and
- updating this document only when an XQUIC-owned design or API changes.

Protocol constants must not be copied into public API headers unless they are
part of an application-visible value type required by the API.

## Target Public API

The declarations below define the target XQUIC source contract. Exact field
ordering and symbol visibility are implementation-time ABI decisions, but
ownership, lifetime, and observable behavior are normative project choices.

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
HTTP/3 connection. XQUIC copies the settings and callback table. Registration
must not replace existing HTTP/3 callbacks or application user data.

`xqc_wt_settings_t` contains:

- maximum sessions per HTTP/3 connection;
- initial per-session stream and data limits;
- maximum unresolved sessions, streams, datagrams, and bytes;
- application decision timeout; and
- automatic window-update thresholds.

Initialization rejects settings that cannot support the configured pooling
mode under the governing IETF flow-control requirements.

### Connection Capability

```c
xqc_bool_t xqc_wt_conn_is_ready(xqc_h3_conn_t *h3_conn);
```

The callback table contains `wt_conn_ready_notify`. It fires once the
WebTransport module has a final capability result from the HTTP/3 and
transport adapters. Session creation before a positive result fails with
`-XQC_EAGAIN` and performs no partial request creation.

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

`xqc_wt_session_config_t` contains authority, path, optional origin,
application protocols in preference order, optional additional safe headers,
and optional HTTP priority. XQUIC copies every input string and header before
the create call returns.

The callback table contains:

- `session_request_notify`: the server application's authorization point;
- `session_ready_notify`: the protocol adapter reports an established
  session;
- `session_drain_notify`: the protocol adapter reports a drain signal; and
- `session_close_notify`: the final callback, including close origin,
  application error if present, protocol error, and borrowed reason.

Server acceptance is always an explicit application decision. A decision may
be synchronous or may remain pending until the configured deadline. Calls
made in the wrong state fail without emitting additional protocol output.

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

Direction-invalid operations fail without changing stream state. The callback
table contains stream create, read, write, closing, and close notifications.
The create callback is emitted only after the stream is bound to a deliverable
session. The close callback is the last valid use of the stream handle.

Send and receive counts contain application bytes only. Internal prefix bytes
and retry state never appear in application buffers or return values.

### Datagram APIs

```c
size_t xqc_wt_datagram_get_mss(const xqc_wt_session_t *session);

xqc_int_t xqc_wt_datagram_send(xqc_wt_session_t *session,
    const void *data, size_t data_len, uint64_t *datagram_id,
    xqc_data_qos_level_t qos_level);
```

The reported MSS is the maximum application payload after internal protocol
overhead. An oversize send fails atomically. Datagram routing is always
session-scoped; no connection-scoped public send API is provided.

The callback table contains session-scoped datagram read, write,
acknowledged, lost, and MSS-updated notifications. Received payload pointers
are borrowed for the callback duration. The WebTransport module never
retransmits an application datagram automatically.

### Session Exporter API

```c
xqc_int_t xqc_wt_session_export_keying_material(
    xqc_wt_session_t *session, const unsigned char *label,
    size_t label_len, const unsigned char *context, size_t context_len,
    unsigned char *output, size_t output_len);
```

The WebTransport module constructs the protocol-defined exporter input and
delegates cryptographic derivation to the TLS adapter. Applications provide
only their application label and optional context.

## Prototype API Migration

The production API intentionally narrows the prototype surface:

- `xqc_webtransport_connect()` is replaced by ordinary HTTP/3 connection
  creation followed by `xqc_wt_session_create()`, enabling connection reuse;
- `xqc_wt_session_init()`, `xqc_wt_create_unistream()`, and constructors that
  accept `xqc_h3_stream_t *` become private;
- separate public unidirectional and bidirectional handle families become one
  `xqc_wt_stream_t` with an explicit direction;
- connection-scoped datagram send becomes session-scoped;
- public HTTP/3-stream getters and setters are removed;
- session identifiers are derived internally and are never assigned by the
  application; and
- settings and callback tables are copied into module-owned storage.

Compatibility aliases may be retained temporarily at the public API boundary.
They must delegate to the selected version adapter and must not retain an
obsolete wire codec under a newer advertised compatibility version.

## Non-Goals

- defining or summarizing WebTransport wire behavior;
- capsule-based WebTransport data transport;
- WebTransport over HTTP/2;
- HTTP/2-to-HTTP/3 intermediary translation;
- automatic redirect policy in the XQUIC transport API;
- application-visible protocol encoding or codepoint mapping; and
- exposing private HTTP/3 or QUIC stream objects through the public API.

## Implementation Acceptance Criteria

An implementation satisfies this project specification when:

- its declared protocol revision passes tests derived directly from the
  governing IETF source;
- ordinary HTTP/3 requests and multiple sessions coexist without ownership,
  callback, or user-data collisions;
- every data stream has one transport object and one opaque WebTransport
  handle, with prefix bytes hidden from the application;
- incremental classification and bounded unresolved-input handling never
  deliver data across sessions;
- per-session accounting composes with, rather than replaces, QUIC flow
  control;
- session and stream teardown preserves callback and handle lifetimes and
  isolates unrelated HTTP/3 work;
- all public inputs are copied or documented as borrowed, and every final
  callback has an explicit invalidation point;
- no public API exposes private HTTP/3 or QUIC objects; and
- happy-path and abnormal-path tests cover every public API state transition
  and each internal adapter boundary.

Protocol conformance criteria belong in tests that cite the exact governing
IETF section. They must not be recreated as a second protocol specification in
this file.
