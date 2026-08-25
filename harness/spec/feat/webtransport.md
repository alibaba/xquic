# XQUIC WebTransport Implementation Specification

## Purpose and Scope

This document defines only the XQUIC-specific implementation architecture,
object ownership, binding interfaces, public C API, and migration constraints
for WebTransport. It does not redefine any WebTransport protocol binding.

The default built-in implementation targets the native HTTP/3 binding in
[`draft-ietf-webtrans-http3-16`](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16).
The common core and binding interface also reserve an integration path for the
capsule-based binding in
[`draft-ietf-webtrans-http2-15`](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http2-15).
Before implementation or review begins, the version-independent IETF entries
for [HTTP/3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/) and
[HTTP/2](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http2/) must be
checked for a newer draft or a published RFC.

This is a target design. Existing prototype symbols under
`include/xquic/xqc_webtransport.h` and `src/webtransport/` do not establish
conformance with this document.

## Authority and Conformance

An XQUIC WebTransport implementation must satisfy both:

1. the governing IETF specification for its selected binding; and
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
- [HTTP/2 Sections 2 and 5](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http2-15#section-2)
  govern the capsule-based transport model and properties. This document owns
  the external carrier callback boundary and its translation into common
  WebTransport events.
- [HTTP/2 Appendix A](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http2-15#appendix-A)
  describes reuse with other HTTP versions. This document owns how XQUIC
  registers additional carrier implementations.

## Design Scope

The first production implementation ships native WebTransport over HTTP/3.
The core object model and public application API are binding-neutral. A
lightweight callback interface allows a future capsule binding to be driven by
an external HTTP/2 implementation without adding an HTTP/2 stack to XQUIC.

The abstraction is:

```text
Common WebTransport abstraction
  session / stream / datagram / close / drain / flow control
                       |
          +------------+------------+
          |                         |
   HTTP/3 native binding      HTTP/2 capsule binding
   QUIC stream/datagram       CONNECT stream + Capsule
```

Applications operate on common sessions, streams, datagrams, and application
errors. A binding translates those operations to its carrier. Protocol
encoding and decoding remain below the common API.

`xqc_wt_session_t` is the central WebTransport entity. It is neither an HTTP/3
request nor a QUIC connection. It is associated with one abstract carrier,
while the carrier can host multiple sessions when its governing binding
permits pooling.

## Ownership and Object Model

The target ownership hierarchy is:

```text
xqc_wt_ctx_t
  `- xqc_wt_carrier_t
       |- binding operations and private binding data
       |- negotiated capabilities and transport properties
       |- session and unresolved-input registries
       `- xqc_wt_session_t
            |- binding-neutral session state and callbacks
            |- binding-specific session handle
            |- xqc_wt_stream_t children
            |- datagram state
            `- session flow-control accounting
```

`xqc_wt_ctx_t`, `xqc_wt_carrier_t`, `xqc_wt_session_t`, and
`xqc_wt_stream_t` are opaque handles. The carrier owns the lookup references
that bind sessions to one underlying connection. The common WebTransport core
owns session and stream memory and releases it only after final callbacks.

The carrier binding borrows its underlying HTTP connection and CONNECT-stream
objects. Closing the underlying carrier notifies the common core, which then
terminates affected sessions using the binding's governing IETF rules.

The default HTTP/3 binding may store a non-owning carrier reference on
`xqc_h3_conn_t` for dispatch. It must not make `xqc_h3_conn_t` the owner or
public identity of a WebTransport session.

No carrier or session state may replace or alias:

- `xqc_engine_t.user_data`;
- HTTP connection application data;
- underlying transport application data; or
- another protocol extension's private state.

A session owns its WebTransport stream handles and session-scoped pending
callbacks. Carrier teardown invalidates sessions only after their close
callbacks have completed.

## Internal Integration Design

### Carrier Binding Interface

The common core communicates with every underlying protocol through a small
`xqc_wt_binding_ops_t` interface. The interface exchanges WebTransport
semantic operations and events; it does not expose HTTP/3 or QUIC object
layouts.

"Lightweight" describes the narrow callback boundary, not a stateless
implementation. A binding retains only the protocol-specific stream maps,
codec state, and carrier flow-control state required by its governing IETF
specification; application session policy remains in the common core.

```text
xqc_wt_session_t / xqc_wt_stream_t
                 |
        xqc_wt_binding_ops_t
          |               |
  built-in H3 binding     capsule binding
  XQUIC H3/QUIC objects   WT Capsule codec
                                  |
                         capsule I/O callbacks
                                  |
                         external HTTP/2 stack
```

The outbound binding operations cover:

- opening, sending, finishing, resetting, and stopping a stream;
- sending a datagram;
- accepting, rejecting, closing, and draining a session;
- deriving session exporter material;
- querying readiness, writable state, payload limits, and transport
  properties; and
- releasing binding-owned session and stream handles.

The inbound core entry points cover:

- carrier readiness, drain, and close;
- incoming session requests and session establishment results;
- stream creation, readable, writable, reset, and close events;
- datagram delivery and optional delivery-status events; and
- binding-specific flow-control updates translated into common credit.

Each operation carries an opaque binding handle. Input buffers are borrowed
only for the duration of the call unless the receiver explicitly copies them.
Callbacks must not retain HTTP/2, HTTP/3, or QUIC objects in common core
structures.

The binding reports transport properties separately from API availability.
An application can therefore use the same session and stream API while
discovering whether a carrier provides unreliable datagrams, stream
independence, pooling, or delivery-status notifications.

### Default HTTP/3 Binding

XQUIC provides the default `h3-native` binding. It translates common
WebTransport operations directly to XQUIC HTTP/3 connection and request
objects, native QUIC streams, QUIC DATAGRAM, and the XQUIC TLS exporter.

The binding is registered automatically by the WebTransport HTTP/3
integration helper. Applications using the built-in path do not implement
`xqc_wt_binding_ops_t` and do not pass internal H3 objects to the common API.

#### HTTP/3 Extension Boundary

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

#### QUIC Transport Boundary

`src/transport/` remains unaware of WebTransport sessions. It supplies stable
internal operations for the `h3-native` binding and HTTP/3 layer to:

- create and operate native unidirectional and bidirectional streams;
- expose stream direction and initiator metadata;
- retain protocol header bytes required by reliable reset;
- obtain final-size information for session accounting;
- send and receive QUIC DATAGRAM payloads;
- query the application-payload MSS after caller-supplied overhead; and
- access the TLS exporter through the TLS integration layer.

Transport APIs report QUIC state and errors without translating them into
WebTransport application errors. That translation belongs to the
HTTP/3 binding.

### External Capsule Binding

The capsule binding permits integration with an HTTP/2 implementation that is
not part of XQUIC. The external adapter owns:

- HTTP/2 connection and stream lifetime;
- Extended CONNECT request and response framing;
- HTTP/2 SETTINGS and DATA frame parsing;
- generic Capsule envelope parsing and serialization; and
- delivery of parsed settings, writable, drain, and close events.

The capsule binding, rather than the external stack, validates the
WebTransport-specific settings and fields and decides carrier readiness.

For input, the external adapter passes the CONNECT-stream identity, Capsule
type, and complete Capsule payload to the XQUIC capsule binding. The capsule
binding validates and decodes WebTransport-specific payloads, updates the
common session and stream objects, and emits application callbacks.

For output, the capsule binding encodes the WebTransport-specific Capsule
payload and invokes the external adapter's `send_capsule` callback. The
external adapter wraps it in its HTTP/2 and generic Capsule framing.

This boundary intentionally does not accept already-interpreted WebTransport
events from arbitrary external parsers. Keeping WebTransport Capsule
validation in one XQUIC binding prevents different HTTP/2 integrations from
implementing conflicting protocol semantics.

The capsule binding can also be reused with another HTTP version when the
governing IETF specification permits the capsule-based protocol. HTTP-version
negotiation and framing remain the external adapter's responsibility.

### WebTransport Module

The target internal layout is:

```text
src/webtransport/core/              binding-neutral objects and public API
src/webtransport/bindings/h3/       built-in XQUIC HTTP/3 native binding
src/webtransport/bindings/capsule/  external carrier callback integration
```

The binding-neutral core owns:

- context-level settings and application callback registration;
- carrier, session, stream, and unresolved-input registries;
- the application-facing session state machine;
- session-scoped datagram dispatch;
- common session flow-control accounting;
- transport-property reporting; and
- bounded buffering for input whose session cannot yet be resolved.

Each binding owns its wire codec, carrier error mapping, stream representation,
and translation between carrier flow control and common session credit. Only
the built-in H3 binding depends on XQUIC HTTP/3, QUIC, and TLS adapter APIs.

Production common-core code must not include HTTP/2, HTTP/3, QUIC, or TLS
private headers.

### HTTP/3 Native Object Binding

For the built-in H3 binding, the carrier request keeps the normal HTTP/3
request representation and stores a non-owning reference to its
`xqc_wt_session_t`. Each WebTransport data stream has one underlying
`xqc_stream_t`, one binding handle, and one common WebTransport stream handle.

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

### HTTP/3 Incremental Dispatch

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

The carrier state contains bounded registries for streams and
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

Session accounting is separate from the carrier's connection-level and
per-stream accounting. The WebTransport core stores, for each direction and
stream class:

- the effective peer and local limits;
- opened and closed stream counts;
- application bytes consumed against the session data limit;
- the last advertised limits; and
- blocked notification state.

The accounting layer obtains final accounting sizes from the binding and
excludes binding-specific framing bytes. The binding serializes limit changes
using its governing protocol. Local window-update heuristics use configurable
thresholds and remain subordinate to the governing IETF rules.

The built-in H3 binding reuses the existing HTTP/3 priority state associated
with the carrier request. Other bindings report their scheduling capabilities
and translate common priority requests when supported. The first API version
does not add XQUIC-specific priority signaling among streams inside one
session.

### Error and Teardown Isolation

The protocol codec owns the tables and algorithms that map application errors
to protocol codepoints. Public APIs accept and report only the application
error width defined by the governing IETF source; raw carrier error values are
not public inputs.

A stream failure tears down only that stream unless the governing IETF source
classifies it as a session or connection error. A session close tears down its
owned streams, queued input, and callbacks without closing unrelated sessions
or carrier work unless the governing source requires a connection error.

Teardown order is:

1. stop new application operations on the object;
2. detach it from lookup registries;
3. complete its final application callback;
4. release child and buffered objects; and
5. release the opaque handle.

Callbacks may inspect borrowed close information only for the duration of the
callback. A handle is invalid after its final close callback returns.

### Version Adapter

All revision-specific identifiers and codecs live in immutable tables owned by
their binding. Session, stream, datagram, and capsule paths select one table
from the negotiated carrier version and never mix tables on a carrier.

The initial H3 table targets HTTP/3 draft 16. The capsule integration target is
HTTP/2 draft 15. Adding another draft or RFC requires:

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
typedef struct xqc_wt_ctx_s     xqc_wt_ctx_t;
typedef struct xqc_wt_carrier_s xqc_wt_carrier_t;
typedef struct xqc_wt_session_s xqc_wt_session_t;
typedef struct xqc_wt_stream_s  xqc_wt_stream_t;

typedef struct xqc_wt_binding_ops_s    xqc_wt_binding_ops_t;
typedef struct xqc_wt_capsule_io_ops_s xqc_wt_capsule_io_ops_t;
typedef struct xqc_wt_http_fields_s    xqc_wt_http_fields_t;
typedef struct xqc_wt_http_setting_s   xqc_wt_http_setting_t;

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

`xqc_wt_carrier_t` is the backend-neutral connection handle. Application data
operations use `xqc_wt_session_t` and `xqc_wt_stream_t`; integration code uses
the carrier handle to attach a binding. The common API does not expose an
HTTP/2 connection, `xqc_h3_conn_t`, or a QUIC connection.

### Context Configuration

```c
xqc_wt_ctx_t *xqc_wt_ctx_create(
    const xqc_wt_settings_t *settings,
    const xqc_wt_callbacks_t *callbacks);

void xqc_wt_ctx_destroy(xqc_wt_ctx_t *ctx);

xqc_int_t xqc_wt_h3_binding_register(xqc_wt_ctx_t *ctx,
    xqc_engine_t *engine);

xqc_wt_carrier_t *xqc_wt_carrier_create(xqc_wt_ctx_t *ctx,
    const xqc_wt_binding_ops_t *binding_ops, void *binding_data);

xqc_wt_carrier_t *xqc_wt_capsule_carrier_create(xqc_wt_ctx_t *ctx,
    const xqc_wt_capsule_io_ops_t *io_ops, void *io_data);
```

XQUIC copies the settings, callback table, and binding operation table. The
default H3 helper is registered after `xqc_h3_ctx_init()` and before creating
an HTTP/3 connection. It creates and destroys carriers automatically with H3
connections. External protocol integrations create carriers explicitly. An
HTTP/2 integration uses `xqc_wt_capsule_carrier_create()` so that XQUIC, not
the external stack, owns WebTransport Capsule semantics.

Binding registration must not replace HTTP-stack callbacks or application
user data.

`xqc_wt_settings_t` contains:

- maximum sessions per carrier;
- initial per-session stream and data limits;
- maximum unresolved sessions, streams, datagrams, and bytes;
- application decision timeout; and
- automatic window-update thresholds.

Initialization rejects settings that cannot support the configured pooling
mode under the governing IETF flow-control requirements.

### External Capsule Integration

The capsule binding exposes input entry points for an external HTTP stack:

```c
xqc_int_t xqc_wt_capsule_binding_on_settings(
    xqc_wt_carrier_t *carrier,
    const xqc_wt_http_setting_t *settings, size_t setting_count);

xqc_int_t xqc_wt_capsule_binding_on_request(
    xqc_wt_carrier_t *carrier, void *connect_stream_data,
    const xqc_wt_http_fields_t *request);

xqc_int_t xqc_wt_capsule_binding_on_response(
    xqc_wt_carrier_t *carrier, void *connect_stream_data,
    const xqc_wt_http_fields_t *response);

xqc_int_t xqc_wt_capsule_binding_on_capsule(
    xqc_wt_carrier_t *carrier, void *connect_stream_data,
    uint64_t capsule_type, const unsigned char *payload,
    size_t payload_len);

void xqc_wt_capsule_binding_on_close(
    xqc_wt_carrier_t *carrier, void *connect_stream_data,
    xqc_int_t carrier_error);
```

The settings, request, and response types are immutable, backend-neutral views
of parsed HTTP values. `connect_stream_data` is owned by the external stack.
Capsule payloads contain one complete generic Capsule payload without the type
and length envelope and are borrowed for the duration of the call.

For output, `xqc_wt_capsule_io_ops_t` provides at least `send_request`,
`send_response`, `send_capsule`, `close_connect_stream`, writable-state, and
exporter callbacks. XQUIC invokes those callbacks synchronously and does not
assume ownership of external HTTP objects.

These functions are integration APIs, not application data APIs. The built-in
H3 binding bypasses them and emits the same common-core events directly from
XQUIC HTTP/3 and QUIC callbacks.

### Carrier Capability

```c
xqc_bool_t xqc_wt_carrier_is_ready(const xqc_wt_carrier_t *carrier);

xqc_int_t xqc_wt_carrier_get_properties(
    const xqc_wt_carrier_t *carrier,
    xqc_wt_transport_properties_t *properties);
```

The callback table contains `wt_carrier_ready_notify`. It fires once the
binding has a final capability result. Session creation before a positive
result fails with `-XQC_EAGAIN` and performs no partial request creation.

`xqc_wt_transport_properties_t` reports pooling, unreliable datagrams, stream
independence, delivery-status notifications, and binding-defined payload
limits. Property values describe the selected carrier and are not inferred
from whether a common API function exists.

### Session APIs

```c
xqc_wt_session_t *xqc_wt_session_create(xqc_wt_carrier_t *carrier,
    const xqc_wt_session_config_t *config,
    void *session_user_data);

xqc_int_t xqc_wt_session_accept(xqc_wt_session_t *session,
    const xqc_str_t *selected_protocol,
    const xqc_wt_http_fields_t *extra_response_fields);

xqc_int_t xqc_wt_session_reject(xqc_wt_session_t *session,
    uint16_t status_code,
    const xqc_wt_http_fields_t *extra_response_fields);

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
application protocols in preference order, optional additional safe fields,
and optional HTTP priority. XQUIC copies every input string and field before
the create call returns. `xqc_wt_http_fields_t` is independent of QPACK and
HPACK storage.

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
    const xqc_wt_stream_settings_t *settings, void *stream_user_data);

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
Stream identifiers are scoped to their WebTransport session and must not be
interpreted as QUIC stream identifiers by common application code.

### Datagram APIs

```c
size_t xqc_wt_datagram_get_mss(const xqc_wt_session_t *session);

xqc_int_t xqc_wt_datagram_send(xqc_wt_session_t *session,
    const void *data, size_t data_len, uint64_t *datagram_id,
    const xqc_wt_datagram_options_t *options);
```

The reported MSS is the maximum application payload after internal protocol
overhead. An oversize send fails atomically. Datagram routing is always
session-scoped; no connection-scoped public send API is provided.

The callback table contains session-scoped datagram read, write,
delivery-status, and MSS-updated notifications. Delivery-status callbacks are
emitted only when the carrier reports that capability. Received payload
pointers are borrowed for the callback duration. The WebTransport core never
requests automatic retransmission that would contradict the selected
binding's transport properties.

### Session Exporter API

```c
xqc_int_t xqc_wt_session_export_keying_material(
    xqc_wt_session_t *session, const unsigned char *label,
    size_t label_len, const unsigned char *context, size_t context_len,
    unsigned char *output, size_t output_len);
```

The WebTransport core constructs the protocol-defined exporter input and
delegates cryptographic derivation to the selected binding. The H3 binding
uses the XQUIC TLS adapter; an external capsule carrier uses its exporter
callback. Applications provide only their application label and optional
context.

## Prototype API Migration

The production API intentionally narrows the prototype surface:

- `xqc_webtransport_connect()` is replaced by carrier creation followed by
  `xqc_wt_session_create()`, with the default H3 helper attaching carriers to
  ordinary XQUIC HTTP/3 connections;
- `xqc_wt_session_init()`, `xqc_wt_create_unistream()`, and constructors that
  accept `xqc_h3_stream_t *` become private;
- separate public unidirectional and bidirectional handle families become one
  `xqc_wt_stream_t` with an explicit direction;
- `xqc_stream_settings_t`, `xqc_cid_t`, and `xqc_h3_conn_t` are removed from
  the binding-neutral session and stream APIs;
- connection-scoped datagram send becomes session-scoped;
- public HTTP/3-stream getters and setters are removed;
- carrier and stream identifiers are interpreted by the selected binding and
  are never assigned by the application; and
- settings and callback tables are copied into module-owned storage.

Compatibility aliases may be retained temporarily at the public API boundary.
They must delegate to the selected version adapter and must not retain an
obsolete wire codec under a newer advertised compatibility version.

## Non-Goals

- defining or summarizing WebTransport wire behavior;
- implementing a general-purpose HTTP/2 stack inside XQUIC;
- making the external HTTP stack depend on private XQUIC HTTP/3 or QUIC types;
- HTTP/2-to-HTTP/3 intermediary translation;
- automatic redirect policy in the XQUIC transport API;
- application-visible protocol encoding or codepoint mapping; and
- exposing private HTTP/3 or QUIC stream objects through the public API.

## Implementation Acceptance Criteria

An implementation satisfies this project specification when:

- its declared protocol revision passes tests derived directly from the
  governing IETF source;
- `xqc_wt_session_t` and `xqc_wt_stream_t` contain no HTTP/2, HTTP/3, QUIC, or
  TLS private object dependency;
- the built-in H3 binding supports ordinary HTTP/3 requests and multiple
  sessions without ownership, callback, or user-data collisions;
- an external capsule carrier can drive session, stream, datagram, close,
  drain, and flow-control events without constructing XQUIC H3 objects;
- every data stream has one opaque WebTransport handle and one binding handle,
  with binding framing hidden from the application;
- incremental classification and bounded unresolved-input handling never
  deliver data across sessions;
- per-session accounting composes with, rather than replaces, carrier flow
  control;
- transport properties prevent applications from assuming HTTP/3-native
  reliability or stream-independence behavior on another binding;
- session and stream teardown preserves callback and handle lifetimes and
  isolates unrelated carrier work;
- all public inputs are copied or documented as borrowed, and every final
  callback has an explicit invalidation point;
- no public API exposes private HTTP/3 or QUIC objects; and
- happy-path and abnormal-path tests cover every public API state transition
  and each internal adapter boundary.

Protocol conformance criteria belong in tests that cite the exact governing
IETF section. They must not be recreated as a second protocol specification in
this file.
