# XQUIC WebTransport Implementation Specification

## Purpose and Scope

This document defines only the XQUIC-specific implementation architecture,
object ownership, adapter interfaces, public C API, and migration constraints
for WebTransport. It does not redefine any WebTransport protocol binding.

The default built-in implementation targets the native HTTP/3 binding in
[`draft-ietf-webtrans-http3-16`](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16).
The common core and adapter interface also reserve an integration path for the
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
  the external HTTP/2 callback boundary and its translation into common
  WebTransport events.
- [HTTP/2 Appendix A](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http2-15#appendix-A)
  describes reuse with other HTTP versions. This document owns how XQUIC
  registers additional adapter implementations.

## Design Scope

The first production implementation ships native WebTransport over HTTP/3.
The core object model and public application API are binding-neutral. A
lightweight adapter interface allows a future capsule binding to be driven by
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
errors. An adapter translates those operations to the selected protocol
binding and concrete HTTP stack. Protocol encoding and decoding remain below
the common API.

`xqc_wt_session_t` is the central WebTransport entity. It is neither an HTTP/3
request nor an HTTP or QUIC connection. Each session selects one adapter when
it is created and keeps that adapter for its complete lifetime.

The terms have distinct meanings in this document:

- a **binding** is an IETF-defined mapping of WebTransport onto an HTTP
  version;
- an **adapter** is XQUIC infrastructure that implements a binding against a
  concrete protocol stack; and
- `xqc_wt_adapter_ops_t` is the operation table used by the common core to
  invoke that infrastructure.

Adapter terminology must not be replaced with network-endpoint terminology.
Application event notification tables remain named callbacks; the adapter
operation table remains named `xqc_wt_adapter_ops_t` because it represents a
set of callable capabilities rather than one passive callback.

## W3C Semantic Mapping and RTQ Boundary

The [W3C WebTransport API](https://www.w3.org/TR/webtransport/) is the semantic
reference for an RTQ or other web-facing adapter. It is not the source of
XQUIC wire behavior and is not copied as a WebIDL-shaped C API. The governing
IETF source remains authoritative for protocol behavior. When an RTQ claims
W3C API compatibility, the W3C source is authoritative for that RTQ mapping.

XQUIC exposes non-blocking protocol operations, state, capabilities, and
callbacks. RTQ maps those primitives to promises, Web Streams, web objects,
and endpoint policy:

| W3C semantic | XQUIC protocol API | RTQ or web-facing layer |
|--------------|--------------------|-------------------------|
| `ready`, `draining`, `closed` | Session state and notifications | Promise or future objects |
| Create unidirectional or bidirectional stream | `xqc_wt_stream_create()` | W3C stream objects |
| Incoming streams | Stream-create notification | Incoming `ReadableStream` queues |
| Datagrams | Send, receive, maximum size, writable notification | Duplex stream, buffering, and expiration policy |
| `close()` and close information | `xqc_wt_session_close()` and structured close notification | W3C close dictionary conversion |
| Reliability properties | Session transport properties | W3C reliability enum conversion |
| Exporter | Raw session exporter operation | Promise and `BufferSource` conversion |
| `getStats()` | Raw session and stream counters | Aggregation, privacy filtering, and W3C field layout |

The mapping preserves semantic correspondence without copying camel-case
names. Public XQUIC symbols use the `xqc_wt_` prefix and lowercase words
separated by underscores. For example,
`createBidirectionalStream()` maps to `xqc_wt_stream_create()` with an explicit
direction, and `maxDatagramSize` maps to
`xqc_wt_datagram_get_max_size()`.

XQUIC retains protocol negotiation, validation, session and stream state,
flow-control accounting, protocol error mapping, Capsule processing, and the
H3 and Capsule adapters. RTQ must not parse WebTransport wire syntax or
reimplement those state machines. RTQ owns URL and header objects, promises,
Web Stream wrappers, browser-style errors, application buffering and expiry
policy, and W3C-specific statistics presentation.

## MoQT Integration Boundary

[MOQT](https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-19#section-3.1)
can use either a WebTransport session or a native QUIC connection as its
Transport Session. The MoQT module therefore remains above WebTransport and
QUIC and selects one transport through a per-session
`xqc_moq_transport_adapter_t`:

```text
xqc_moq_session_t
  `- xqc_moq_transport_adapter_t
       |- WebTransport implementation -> xqc_wt_session_t
       `- native QUIC implementation  -> xqc_connection_t
```

The adapter is intentionally small. It contains one operation table and one
opaque transport-session reference:

```c
typedef struct xqc_moq_transport_adapter_s {
    const xqc_moq_transport_adapter_ops_t *ops;
    void                                  *transport_session;
} xqc_moq_transport_adapter_t;
```

The operations normalize only the transport capabilities required by MoQT:
opening and operating unidirectional and bidirectional streams, sending and
receiving datagrams, reporting writable state and payload limits, applying
scheduling hints, and closing the Transport Session. MoQT framing, Track and
Object state, subscriptions, delivery timeout policy, and relay behavior
remain in `xqc_moq_session_t` and the MoQT module.

The WebTransport implementation stores an `xqc_wt_session_t` as its transport
session and invokes only the public WebTransport session, stream, and datagram
APIs. It must not call `xqc_wt_adapter_ops_t` or access H3 and Capsule adapter
state directly. The native QUIC implementation stores an `xqc_connection_t`
and maps the same MoQT transport operations to native QUIC streams, QUIC
DATAGRAM, connection state, and connection close.

Transport-specific establishment and version selection remain in the two
adapter implementations. The MoQT core receives a ready transport session and
normalized capabilities, so changing between WebTransport and native QUIC
does not change Track, Object, subscription, or relay logic. The
`xqc_moq_transport_adapter_t` is a MoQT infrastructure object scoped to one
MoQT session; it is not part of the WebTransport object model and is not a
shared connection entity.

## Ownership and Object Model

The target ownership hierarchy is:

```text
xqc_wt_ctx_t
  |- settings and application callbacks
  `- session repository
       `- xqc_wt_session_t
            |- binding-neutral session state
            |- const xqc_wt_adapter_ops_t *adapter_ops
            |- void *adapter_session_ctx
            |- xqc_wt_stream_t children
            |- datagram state
            `- session flow-control accounting
```

`xqc_wt_ctx_t`, `xqc_wt_session_t`, and `xqc_wt_stream_t` are opaque handles.
The common WebTransport core owns session and stream memory and releases it
only after final callbacks. Each adapter owns its private session context and
releases that context through `xqc_wt_adapter_ops_t` after the common session
has detached it.

In domain terms, `xqc_wt_session_t` is the aggregate root and
`xqc_wt_stream_t` is a child entity. `xqc_wt_ctx_t` provides configuration and
the session repository. Adapters and their connection contexts are
infrastructure, not WebTransport domain entities.

There is no binding-neutral per-connection WebTransport handle. Connection
aggregation is a property of an adapter and must not become a prerequisite for
the common session API. This avoids forcing the HTTP/2 capsule path to
duplicate connection state already owned by the external HTTP/2 stack.

The built-in H3 adapter nevertheless requires one private
`xqc_wt_h3_conn_ctx_t` per `xqc_h3_conn_t` because capability negotiation,
version selection, native stream and datagram dispatch, unresolved-input
routing, and connection-close fan-out are connection-scoped in that binding:

```text
xqc_h3_conn_t
  `- xqc_wt_h3_conn_ctx_t
       |- negotiated H3 WebTransport state
       |- session lookup references
       `- bounded unresolved native input

external_h2_conn_ctx
  `- CONNECT stream
       `- xqc_wt_capsule_session_ctx_t
            `- xqc_wt_session_t
```

`xqc_wt_h3_conn_ctx_t` is private to the H3 adapter, borrows its H3
connection, and contains references rather than ownership of common sessions.
The external HTTP/2 stack owns `external_h2_conn_ctx`; XQUIC creates only one
capsule adapter context for each CONNECT stream. Closing an H3 connection is
fanned out by the H3 adapter. Closing an HTTP/2 connection is fanned out by
the external stack through its affected CONNECT sessions.

No adapter or session state may replace or alias:

- `xqc_engine_t.user_data`;
- HTTP connection application data;
- underlying transport application data; or
- another protocol extension's private state.

A session owns its WebTransport stream handles and session-scoped pending
callbacks. Adapter teardown invalidates a session only after its close
callback has completed.

## Internal Integration Design

### Adapter Interface

The common core communicates with every underlying protocol through a small
`xqc_wt_adapter_ops_t` interface. The interface exchanges WebTransport
semantic operations and events; it does not expose HTTP/2, HTTP/3, or QUIC
object layouts.

"Lightweight" describes the narrow callback boundary, not a stateless
implementation. An adapter retains only the protocol-specific stream maps,
codec state, and lower-layer flow-control state required by its governing
IETF specification; application session policy remains in the common core.

```text
xqc_wt_session_t / xqc_wt_stream_t
                 |
        xqc_wt_adapter_ops_t
          |               |
  built-in H3 adapter     capsule adapter
  XQUIC H3/QUIC objects   WT Capsule codec
                                  |
                         capsule I/O callbacks
                                  |
                         external HTTP/2 stack
```

The common core invokes `xqc_wt_adapter_ops_t` for outbound operations that
cover:

- opening, sending, finishing, resetting, and stopping a stream;
- sending a datagram;
- accepting, rejecting, closing, and draining a session;
- deriving session exporter material;
- querying writable state, payload limits, and transport properties; and
- releasing adapter-owned session and stream handles.

Adapters invoke explicit internal `xqc_wt_core_on_*()` entry points for inbound
events that cover:

- incoming session requests and session establishment results;
- session drain and close;
- stream creation, readable, writable, reset, and close events;
- datagram delivery and optional delivery-status events; and
- adapter-specific flow-control updates translated into common credit.

Every operation is scoped by `xqc_wt_session_t` or `xqc_wt_stream_t`; the
common session stores the selected operation table and an opaque
`adapter_session_ctx`. Input buffers are borrowed only for the duration of the
call unless the receiver explicitly copies them. The common core must not
retain HTTP/2, HTTP/3, or QUIC objects.

The adapter reports transport properties separately from API availability.
An application can therefore use the same session and stream API while
discovering whether the selected binding provides unreliable datagrams, stream
independence, pooling, or delivery-status notifications.

### Default HTTP/3 Binding

XQUIC provides the default `h3-native` adapter. It translates common
WebTransport operations directly to XQUIC HTTP/3 connection and request
objects, native QUIC streams, QUIC DATAGRAM, and the XQUIC TLS exporter.

The adapter is registered by the WebTransport HTTP/3
integration helper. Applications using the built-in path do not implement
`xqc_wt_adapter_ops_t` and do not pass internal H3 objects to the common API.

`xqc_wt_h3_conn_ctx_t` is created and destroyed with its H3 connection. It
pins the negotiated compatibility table, tracks whether new sessions can be
created, maps protocol session identifiers to common session handles, buffers
bounded native input that cannot yet be resolved, and fans out connection
drain and close events. It must not contain application policy or become an
application-visible handle.

#### HTTP/3 Extension Boundary

`src/http3/` remains responsible for generic HTTP/3 connection and stream
mechanisms. It exposes an internal extension interface that allows the
WebTransport module to:

- register capability SETTINGS and validate their parsed peer values;
- register the supported Extended CONNECT protocol token;
- receive the CONNECT request and response state transitions;
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
internal operations for the `h3-native` adapter and HTTP/3 layer to:

- create and operate native unidirectional and bidirectional streams;
- expose stream direction and initiator metadata;
- retain protocol header bytes required by reliable reset;
- obtain final-size information for session accounting;
- send and receive QUIC DATAGRAM payloads;
- query the application-payload MSS after caller-supplied overhead; and
- access the TLS exporter through the TLS integration layer.

Transport APIs report QUIC state and errors without translating them into
WebTransport application errors. That translation belongs to the HTTP/3
adapter.

### External Capsule Binding

The capsule adapter permits integration with an HTTP/2 implementation that is
not part of XQUIC. The external adapter owns:

- HTTP/2 connection and stream lifetime;
- Extended CONNECT request and response framing;
- HTTP/2 SETTINGS and DATA frame parsing;
- generic Capsule envelope parsing and serialization; and
- delivery of parsed settings, writable, drain, and close events.

The capsule adapter, rather than the external stack, validates the
WebTransport-specific settings and fields. The external stack supplies each
CONNECT session with the parsed peer-settings snapshot from its HTTP/2
connection; XQUIC does not retain a parallel HTTP/2 connection object.

For input, the external adapter passes the CONNECT-stream identity, Capsule
type, and complete Capsule payload to the XQUIC capsule binding. The capsule
adapter validates and decodes WebTransport-specific payloads, updates the
common session and stream objects, and emits application callbacks.

For output, the capsule adapter encodes the WebTransport-specific Capsule
payload and invokes the external adapter's `send_capsule` callback. The
external adapter wraps it in its HTTP/2 and generic Capsule framing.

This boundary intentionally does not accept already-interpreted WebTransport
events from arbitrary external parsers. Keeping WebTransport Capsule
validation in one XQUIC binding prevents different HTTP/2 integrations from
implementing conflicting protocol semantics.

Each CONNECT stream has one `xqc_wt_capsule_session_ctx_t` containing the
copied I/O operation table, the external stream identity, selected
compatibility table, and capsule codec state. Connection-wide pooling,
scheduling, settings storage, and close fan-out remain in the external HTTP/2
stack. Capsule input is already scoped to a CONNECT stream, so the capsule
adapter does not create an H3-style connection registry.

The capsule binding can also be reused with another HTTP version when the
governing IETF specification permits the capsule-based protocol. HTTP-version
negotiation and framing remain the external adapter's responsibility.

### WebTransport Module

The target internal layout is:

```text
src/webtransport/core/              binding-neutral objects and public API
src/webtransport/adapters/h3/       built-in XQUIC HTTP/3 native adapter
src/webtransport/adapters/capsule/  external Capsule I/O integration
```

The binding-neutral core owns:

- context-level settings and application callback registration;
- the session repository and per-session stream registry;
- the application-facing session state machine;
- session-scoped datagram dispatch;
- common session flow-control accounting;
- transport-property reporting; and
- common buffer ownership and callback-lifetime rules.

Each adapter owns its wire codec, protocol error mapping, stream
representation, unresolved pre-session input, and translation between
lower-layer flow control and common session credit. Only the built-in H3
adapter depends on XQUIC HTTP/3, QUIC, and TLS adapter APIs.

Production common-core code must not include HTTP/2, HTTP/3, QUIC, or TLS
private headers.

### HTTP/3 Native Object Binding

For the built-in H3 adapter, the CONNECT request keeps the normal HTTP/3
request representation and stores a non-owning reference to its
`xqc_wt_session_t`. Each WebTransport data stream has one underlying
`xqc_stream_t`, one adapter-private stream handle, and one common WebTransport
stream handle.

An `xqc_h3_stream_t` may remain as the HTTP/3 dispatch and lifetime container,
but after classification it routes application bytes to
`xqc_wt_stream_t`. It must not also expose those bytes through HTTP request,
QPACK, control-stream, or generic bytestream callbacks.

```text
CONNECT request: xqc_stream_t <-> xqc_h3_stream_t <-> xqc_h3_request_t
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

`xqc_wt_h3_conn_ctx_t` contains bounded registries for native streams and
datagrams that arrive before their session can be resolved. Limits include
object counts, aggregate bytes, and a lifetime deadline. H3 adapter settings
provide the bounds; internal defaults must be finite.

Once the session becomes deliverable, queued objects are drained in arrival
order per object class. Once the session is rejected, closed, or times out,
the registries discard or reject queued input through the governing protocol
error path.

No application callback is invoked for unresolved input. Buffer ownership
remains inside XQUIC until delivery or disposal.

### Flow-Control Accounting

Session accounting is separate from the binding's connection-level and
per-stream accounting. The WebTransport core stores, for each direction and
stream class:

- the effective peer and local limits;
- opened and closed stream counts;
- application bytes consumed against the session data limit;
- the last advertised limits; and
- blocked notification state.

The accounting layer obtains final accounting sizes from the adapter and
excludes binding-specific framing bytes. The adapter serializes limit changes
using its governing protocol. Local window-update heuristics use configurable
thresholds and remain subordinate to the governing IETF rules.

The built-in H3 adapter reuses the existing HTTP/3 priority state associated
with the CONNECT request. Other adapters report their scheduling capabilities
and translate common priority requests when supported. The first API version
does not add XQUIC-specific priority signaling among streams inside one
session.

### Error and Teardown Isolation

The protocol codec owns the tables and algorithms that map application errors
to protocol codepoints. Public APIs accept and report only the application
error width defined by the governing IETF source; raw lower-layer error values
are not public inputs.

A stream failure tears down only that stream unless the governing IETF source
classifies it as a session or connection error. A session close tears down its
owned streams, queued input, and callbacks without closing unrelated sessions
or lower-layer work unless the governing source requires a connection error.

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
their adapter. Session, stream, datagram, and capsule paths select one table
from the negotiated binding version and never mix tables within a session.
The H3 adapter pins one compatible table on `xqc_wt_h3_conn_ctx_t`; the capsule
adapter pins one table on each `xqc_wt_capsule_session_ctx_t`.

The initial H3 table targets HTTP/3 draft 16. The capsule integration target is
HTTP/2 draft 15. Adding another draft or RFC requires:

- reviewing the current version-independent IETF source;
- adding or updating one version table and its codec tests;
- updating compatibility declarations exposed by XQUIC; and
- updating this document only when an XQUIC-owned design or API changes.

Protocol constants must not be copied into public API headers unless they are
part of an application-visible value type required by the API.

## Target API

The declarations below define the target XQUIC application and external-stack
integration contract. `xqc_wt_adapter_ops_t` remains internal to XQUIC; the
other declarations in this section are public API. Exact field ordering and
symbol visibility are implementation-time ABI decisions, but ownership,
lifetime, and observable behavior are normative project choices.

### Opaque Handles and Adapter Types

```c
typedef struct xqc_wt_ctx_s     xqc_wt_ctx_t;
typedef struct xqc_wt_session_s xqc_wt_session_t;
typedef struct xqc_wt_stream_s  xqc_wt_stream_t;

typedef struct xqc_wt_adapter_ops_s    xqc_wt_adapter_ops_t;
typedef struct xqc_wt_capsule_io_ops_s xqc_wt_capsule_io_ops_t;
typedef struct xqc_wt_http_fields_s    xqc_wt_http_fields_t;
typedef struct xqc_wt_http_setting_s   xqc_wt_http_setting_t;
typedef struct xqc_wt_settings_s       xqc_wt_settings_t;
typedef struct xqc_wt_callbacks_s      xqc_wt_callbacks_t;
typedef struct xqc_wt_session_config_s xqc_wt_session_config_t;
typedef struct xqc_wt_h3_adapter_settings_s
    xqc_wt_h3_adapter_settings_t;

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

Application data operations use only `xqc_wt_session_t` and
`xqc_wt_stream_t`. `xqc_wt_adapter_ops_t` is an internal operation-table
contract between the common core and an XQUIC adapter; it is not an
application callback table or a separately allocated object. The H3 and
capsule integration APIs select and attach the appropriate table when they
create a common session.

### Context Configuration

```c
xqc_wt_ctx_t *xqc_wt_ctx_create(
    const xqc_wt_settings_t *settings,
    const xqc_wt_callbacks_t *callbacks);

void xqc_wt_ctx_destroy(xqc_wt_ctx_t *ctx);

xqc_int_t xqc_wt_h3_adapter_register(xqc_wt_ctx_t *ctx,
    xqc_engine_t *engine,
    const xqc_wt_h3_adapter_settings_t *h3_settings);
```

XQUIC copies the settings and application callback table. The default H3
adapter is registered after `xqc_h3_ctx_init()` and before creating an HTTP/3
connection. It creates and destroys private `xqc_wt_h3_conn_ctx_t` instances
with H3 connections. Registration must not replace HTTP-stack callbacks or
application user data.

`xqc_wt_settings_t` contains:

- maximum active sessions in one WebTransport context;
- initial per-session stream and data limits;
- application decision timeout; and
- automatic window-update thresholds.

`xqc_wt_h3_adapter_settings_t` contains the maximum sessions per H3
connection and the object-count, aggregate-byte, and deadline bounds for
unresolved native input. Initialization rejects settings that cannot support
the configured H3 pooling mode under the governing IETF flow-control
requirements.

### Adapter-Specific Session Creation

```c
xqc_wt_session_t *xqc_wt_h3_session_create(
    xqc_wt_ctx_t *ctx, xqc_engine_t *engine, const xqc_cid_t *cid,
    const xqc_wt_session_config_t *config,
    void *session_user_data);

xqc_wt_session_t *xqc_wt_capsule_session_create(
    xqc_wt_ctx_t *ctx, const xqc_wt_capsule_io_ops_t *io_ops,
    void *connect_stream_data,
    const xqc_wt_session_config_t *config,
    void *session_user_data);
```

The H3 factory is an adapter-specific integration API and follows the existing
XQUIC engine-and-CID connection-selection convention. It resolves the private
`xqc_wt_h3_conn_ctx_t`, attaches the built-in operation table, and creates the
CONNECT request. An H3 connection without a positive capability result causes
the call to fail without partially creating a request. Incoming server
sessions are created by the H3 adapter and delivered through the common
session callback.

The capsule factory creates one common session and one private
`xqc_wt_capsule_session_ctx_t` for an existing external CONNECT stream. XQUIC
copies `io_ops`; it borrows `connect_stream_data` until the final session close
callback. The external HTTP stack creates one capsule session for each
CONNECT stream and does not create a binding-neutral connection object.

### External Capsule Integration

The capsule adapter exposes session-scoped input entry points for an external
HTTP stack:

```c
xqc_int_t xqc_wt_capsule_session_on_peer_settings(
    xqc_wt_session_t *session,
    const xqc_wt_http_setting_t *settings, size_t setting_count);

xqc_int_t xqc_wt_capsule_session_on_request(
    xqc_wt_session_t *session,
    const xqc_wt_http_fields_t *request);

xqc_int_t xqc_wt_capsule_session_on_response(
    xqc_wt_session_t *session,
    const xqc_wt_http_fields_t *response);

xqc_int_t xqc_wt_capsule_session_on_capsule(
    xqc_wt_session_t *session,
    uint64_t capsule_type, const unsigned char *payload,
    size_t payload_len);

void xqc_wt_capsule_session_on_writable(xqc_wt_session_t *session);
void xqc_wt_capsule_session_on_drain(xqc_wt_session_t *session);
void xqc_wt_capsule_session_on_close(xqc_wt_session_t *session,
    xqc_int_t lower_layer_error);
```

The settings, request, and response types are immutable, backend-neutral views
of parsed HTTP values. The external stack passes the connection's relevant
peer settings to each new session before its request or response input. The
capsule adapter validates those settings and pins the selected compatibility
table on the session context. Capsule payloads contain one complete generic
Capsule payload without the type and length envelope and are borrowed for the
duration of the call.

For output, `xqc_wt_capsule_io_ops_t` provides at least `send_request`,
`send_response`, `send_capsule`, `close_connect_stream`, writable-state, and
exporter callbacks. XQUIC invokes those callbacks synchronously and does not
assume ownership of external HTTP objects.

These functions are integration APIs, not application data APIs. The built-in
H3 adapter bypasses them and emits the same common-core events directly from
XQUIC HTTP/3 and QUIC callbacks.

The external HTTP/2 stack must invoke the close entry point for every affected
CONNECT session before releasing their borrowed stream identities. XQUIC does
not provide a connection-close API because it does not own or mirror the
external HTTP/2 connection.

### Session Transport Properties

```c
xqc_int_t xqc_wt_session_get_transport_properties(
    const xqc_wt_session_t *session,
    xqc_wt_transport_properties_t *properties);
```

`xqc_wt_transport_properties_t` reports pooling, unreliable datagrams, stream
independence, delivery-status notifications, and binding-defined payload
limits. Property values describe the selected session binding and are not
inferred from whether a common API function exists. A query before the
properties are final returns `-XQC_EAGAIN` without modifying the output.

### Session APIs

```c
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
size_t xqc_wt_datagram_get_max_size(const xqc_wt_session_t *session);

xqc_int_t xqc_wt_datagram_send(xqc_wt_session_t *session,
    const void *data, size_t data_len, uint64_t *datagram_id,
    const xqc_wt_datagram_options_t *options);
```

The reported maximum size is the largest application datagram payload after
internal protocol overhead. An oversize send fails atomically. Datagram
routing is always session-scoped; no connection-scoped public send API is
provided.

The callback table contains session-scoped datagram read, write,
delivery-status, and maximum-size-updated notifications. Delivery-status
callbacks are emitted only when the selected adapter reports that capability.
Received payload pointers are borrowed for the callback duration. The
WebTransport core never requests automatic retransmission that would
contradict the selected binding's transport properties.

### Session Exporter API

```c
xqc_int_t xqc_wt_session_export_keying_material(
    xqc_wt_session_t *session, const unsigned char *label,
    size_t label_len, const unsigned char *context, size_t context_len,
    unsigned char *output, size_t output_len);
```

The WebTransport core constructs the protocol-defined exporter input and
delegates cryptographic derivation to the selected adapter. The H3 adapter
uses the XQUIC TLS adapter; an external capsule adapter uses its exporter
callback. Applications provide only their application label and optional
context.

## Prototype API Migration

The production API intentionally narrows the prototype surface:

- `xqc_webtransport_connect()` is split into ordinary `xqc_h3_connect()`
  connection establishment followed by `xqc_wt_h3_session_create()`;
- `xqc_wt_create_conn()` and `xqc_wt_conn_t` are removed without a
  binding-neutral replacement; H3 connection state is private to the H3
  adapter;
- `xqc_wt_session_init()`, `xqc_wt_create_unistream()`, and constructors that
  accept `xqc_h3_stream_t *` become private;
- separate public unidirectional and bidirectional handle families become one
  `xqc_wt_stream_t` with an explicit direction;
- `xqc_stream_settings_t`, `xqc_cid_t`, and `xqc_h3_conn_t` are removed from
  the binding-neutral session and stream APIs;
- connection-scoped datagram send becomes session-scoped;
- public HTTP/3-stream getters and setters are removed;
- session and stream identifiers are interpreted by the selected binding and
  are never assigned by the application; and
- settings and callback tables are copied into module-owned storage.

Compatibility aliases may be retained temporarily at the public API boundary.
They must delegate to the selected version adapter and must not retain an
obsolete wire codec under a newer advertised compatibility version.

## Non-Goals

- defining or summarizing WebTransport wire behavior;
- implementing a general-purpose HTTP/2 stack inside XQUIC;
- making the external HTTP stack depend on private XQUIC HTTP/3 or QUIC types;
- introducing a binding-neutral per-connection WebTransport object;
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
- the built-in H3 adapter supports ordinary HTTP/3 requests and multiple
  sessions without ownership, callback, or user-data collisions;
- an external capsule adapter can drive session, stream, datagram, close,
  drain, and flow-control events without constructing XQUIC H3 objects;
- every data stream has one opaque WebTransport handle and one adapter-private
  stream handle, with binding framing hidden from the application;
- incremental classification and bounded unresolved-input handling never
  deliver data across sessions;
- per-session accounting composes with, rather than replaces, lower-layer flow
  control;
- transport properties prevent applications from assuming HTTP/3-native
  reliability or stream-independence behavior on another binding;
- session and stream teardown preserves callback and handle lifetimes and
  isolates unrelated adapter work;
- all public inputs are copied or documented as borrowed, and every final
  callback has an explicit invalidation point;
- no public API exposes private HTTP/3 or QUIC objects;
- `xqc_moq_transport_adapter_t` can bind an MoQT session to WebTransport or
  native QUIC without the MoQT core accessing private WebTransport adapter
  state; and
- happy-path and abnormal-path tests cover every public API state transition
  and each internal adapter boundary.

Protocol conformance criteria belong in tests that cite the exact governing
IETF section. They must not be recreated as a second protocol specification in
this file.
