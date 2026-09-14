# WebTransport Server Module: Immutable XQUIC API Specification

The server module calls **23 XQUIC APIs**, all provided through three public
headers. The server API names, callback fields, ctx usage, and lifecycle
semantics below MUST remain unchanged.

```c
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include <xquic/xqc_webtransport.h>
```

## 1. Engine and Context Initialization

Initialization takes place in
`ngx_http_webtransport.c::ngx_http_wt_ctx_init` during startup.

| API | Contract |
|---|---|
| `xqc_wt_ctx_init` | Register the three WT callback groups and bind them to the XQUIC engine shared with Nginx. |
| `xqc_wt_engine_set_default_settings` | Configure WT mode, stream limits, flow control, and datagram enablement. |
| `xqc_wt_ctx_set_pending_datagram_policy` | Configure the pending-datagram window, count limit, and byte limit for unknown sessions. |

## 2. Data and Control APIs

### 2.1 Session Lifecycle and Queries

| API | Contract |
|---|---|
| `xqc_wt_session_close_with_error` | Close a session with an error code. |
| `xqc_wt_session_drain` | Enter the draining state for graceful shutdown. |
| `xqc_wt_session_get_close_error_code` | Retrieve the close error code. |
| `xqc_wt_session_get_close_reason` | Retrieve the close reason string. |
| `xqc_wt_session_get_h3_conn` | Retrieve the underlying H3 connection from a WT session. |
| `xqc_wt_session_datagram_send` | Send a WT datagram. |

### 2.2 Bidirectional Streams

| API | Contract |
|---|---|
| `xqc_wt_bidistream_send` | Send data with short-write semantics, returning the number of bytes actually accepted. |
| `xqc_wt_bidistream_reset` | Abort sending with RESET_STREAM, carrying an application error code. |
| `xqc_wt_bidistream_stop_sending` | Abort receiving with STOP_SENDING. |
| `xqc_wt_bidistream_set_read_paused` | Pause or resume reading; receive backpressure is reversible. |
| `xqc_wt_bidistream_closing_is_stop_sending` | Determine whether closing was triggered by peer STOP_SENDING. |
| `xqc_wt_bidistream_id` | Retrieve the QUIC stream ID for use as a red-black-tree key. Wrapper addresses are reused and MUST NOT be used as keys. |

### 2.3 Unidirectional Streams

| API | Contract |
|---|---|
| `xqc_wt_session_create_uni_stream` | Create a unidirectional stream, with an `*err` output parameter to distinguish failure causes. |
| `xqc_wt_unistream_send` | Send data with short-write semantics. |
| `xqc_wt_unistream_reset` | Abort sending with RESET_STREAM. |
| `xqc_wt_unistream_stop_sending` | Apply STOP_SENDING to an incoming unidirectional stream. |
| `xqc_wt_unistream_set_read_paused` | Pause or resume reading. |
| `xqc_wt_unistream_closing_is_stop_sending` | Query the closing cause. |
| `xqc_wt_unistream_id` | Retrieve the QUIC stream ID, with the same keying rules as bidirectional streams. |

Outgoing uni streams MUST use the persistent-stream model:

- The `fake` context retains `uni_send_stream` across messages.
- Every message is sent on the same stream without FIN.
- Close-frame handling or cleanup terminates the stream.
- After a short write, the unsent bytes are stored in `uni_send_pending_data`.
- `wt_unistream_write_notify` wakes the corresponding pending writer to
  continue sending.

### 2.4 Engine and Connection Bridge

| API | Contract |
|---|---|
| `xqc_h3_conn_get_user_data` | Retrieve `ngx_http_xquic_connection_t` from the H3 connection and reuse the connection established by the Nginx XQUIC module. The WT module MUST NOT manage the QUIC connection itself. |

The module MUST NOT call `xqc_engine_finish_send` directly to drive packet
output. It uses `ngx_xquic_engine_set_event_timer`, exported by the Nginx
XQUIC module, to schedule a 1 ms timer. The event loop flushes the engine
after the current callback chain returns. Calling `finish_send` inside a
callback can reenter stream-close callbacks and cause use-after-free.

## 3. Callbacks Implemented by the Module

The module registers **20 hooks** in three callback structures through
`xqc_wt_ctx_init`.

### 3.1 `xqc_webtransport_dgram_callbacks_t`: 5 Hooks

| Callback field | Trigger |
|---|---|
| `dgram_read_notify` | A datagram is received from the peer. |
| `dgram_write_notify` | Datagrams can be written. The module implements this as a no-op and does not retry dropped datagrams. |
| `dgram_acked_notify` | A datagram is acknowledged by the peer. |
| `dgram_lost_notify` | A datagram is declared lost. |
| `dgram_mss_updated_notify` | The datagram MSS is updated. |

### 3.2 `xqc_webtransport_session_callbacks_t`: 5 Hooks

| Callback field | Trigger |
|---|---|
| `webtransport_will_create_session_notify` | A session is about to be created; the module can reject it. |
| `webtransport_session_create_notify` | Session creation completes. |
| `webtransport_session_close_notify` | The session closes. |
| `webtransport_conn_handshake_finished_notify` | The underlying QUIC handshake completes. |
| `webtransport_session_drain_notify` | The session enters draining. |

### 3.3 `xqc_webtransport_stream_callbacks_t`: 10 Hooks

| Bidirectional callback | Unidirectional callback | Trigger |
|---|---|---|
| `wt_bidistream_create_notify` | `wt_unistream_create_notify` | The stream is created. |
| `wt_bidistream_read_notify` | `wt_unistream_read_notify` | The stream is readable. |
| `wt_bidistream_write_notify` | `wt_unistream_write_notify` | The stream becomes writable as flow control permits. |
| `wt_bidistream_closing_notify` | `wt_unistream_closing_notify` | The stream enters closing because of STOP_SENDING or RESET_STREAM. |
| `wt_bidistream_close_notify` | `wt_unistream_close_notify` | The stream closes. |

All ten stream callbacks MUST be registered. Within
`wt_*stream_closing_notify`, `closing_is_stop_sending` distinguishes the two
termination semantics:

- STOP_SENDING terminates only the sending direction; receiving continues.
- RESET_STREAM terminates the receiving direction. RESET_STREAM_AT may still
  require delivery of a reliable prefix.

## 4. Types and Constants

### 4.1 Types

| Type | Purpose |
|---|---|
| `xqc_wt_session_t` | Opaque WT session handle. |
| `xqc_wt_bidistream_t` | Opaque WT bidirectional stream handle. |
| `xqc_wt_unistream_t` | Opaque WT unidirectional stream handle. |
| `xqc_engine_t` | Opaque XQUIC engine handle. |
| `xqc_h3_conn_t` | Opaque H3 connection handle. |
| `xqc_h3_stream_t` | Opaque H3 stream handle. |
| `xqc_stream_id_t` | QUIC stream ID returned by `xqc_wt_*stream_id`. |

### 4.2 Error Codes and Boolean Constants

| Constant | Meaning |
|---|---|
| `XQC_OK` / `XQC_ERROR` | Generic success / failure. |
| `XQC_EAGAIN` | Temporarily not writable; retry later. Read callbacks also use this code to indicate backpressure. |
| `XQC_ESTATE` | The state machine does not permit the operation. |
| `XQC_ECONN_BLOCKED` | Connection-level flow-control blocking. |
| `XQC_ESTREAM_BLOCKED` | Stream-level flow-control blocking. |
| `XQC_TRUE` / `XQC_FALSE` | Boolean results. |

### 4.3 WT Constants

| Constant | Purpose |
|---|---|
| `XQC_WT_STREAM_TYPE_SEND` | Select an outgoing unidirectional stream. |
| `XQC_WEBTRANSPORT_DEFAULT_DGRAM_MSS` | Default datagram MSS. |
| `XQC_WEBTRANSPORT_DEFAULT_PENDING_DGRAM_COUNT_MAX` | Default pending-datagram count limit. |
| `XQC_WEBTRANSPORT_DEFAULT_PENDING_DGRAM_BYTES_MAX` | Default pending-datagram byte limit. |
| `XQC_WEBTRANSPORT_DEFAULT_UNKNOWN_SESSION_DGRAM_WINDOW` | Default datagram window for unknown sessions. |

## 5. Additional WT APIs Used by the Demos

The two clients in `demo/` run independently of the Nginx module. In addition
to the 23 server APIs above, they use the following WT-related APIs.

The demos also depend on generic XQUIC infrastructure: engine creation,
destruction and main-loop processing, packet input, receive-batch completion,
`xqc_server_set_conn_settings`, and congestion-control callbacks. These are
common to standalone QUIC programs and are not listed as WT-specific APIs.

### 5.1 `wt_test_client.c`: Test Client

| API | Purpose |
|---|---|
| `xqc_wt_client_open_session` | Open a WT session from the client. |
| `xqc_wt_session_create_bidi_stream` | Create a bidirectional stream with an `*err` output parameter. |
| `xqc_wt_conn_get_h3_conn` | Retrieve the underlying H3 connection from a WT connection. |
| `xqc_wt_bidistream_get_peer_reset_error` | Retrieve the peer RESET_STREAM error code. |
| `xqc_wt_bidistream_get_peer_stop_sending_error` | Retrieve the peer STOP_SENDING error code. |
| `xqc_h3_ext_bytestream_create` | Create an H3 extension bytestream to carry WT capsules. |
| `xqc_h3_ext_bytestream_send` | Send data through the bytestream. |
| `xqc_h3_ext_datagram_send` | Send an H3 datagram underlying WT datagram transport. |

### 5.2 `wt_api_client.c`: W3C High-Level API Client Demo

This client uses the separate `xqc_webtransport_*` high-level API from
`<xquic/xqc_webtransport_api.h>`, which encapsulates engine, connection,
session, and stream management.

| API | Purpose |
|---|---|
| `xqc_webtransport_engine_create` | Create a high-level WT engine. |
| `xqc_webtransport_engine_destroy` | Destroy the engine. |
| `xqc_webtransport_engine_process` | Run the engine through timer or event processing. |
| `xqc_webtransport_engine_feed_packet` | Feed a received UDP packet into the engine. |
| `xqc_webtransport_engine_finish_recv` | Mark the end of the current receive batch. |
| `xqc_webtransport_new` | Create a WT connection/session. |
| `xqc_webtransport_destroy` | Destroy the WT instance. |
| `xqc_webtransport_close` | Close the WT session. |
| `xqc_webtransport_parse_url` | Parse a WT URL to extract authority and path. |
| `xqc_webtransport_create_bidirectional_stream` | Create a bidirectional stream. |
| `xqc_webtransport_stream_write` | Write data to a stream. |

## Appendix: Complete API Inventory

### Server Module: 23 APIs

```text
xqc_h3_conn_get_user_data
xqc_wt_bidistream_closing_is_stop_sending
xqc_wt_bidistream_id
xqc_wt_bidistream_reset
xqc_wt_bidistream_send
xqc_wt_bidistream_set_read_paused
xqc_wt_bidistream_stop_sending
xqc_wt_ctx_init
xqc_wt_ctx_set_pending_datagram_policy
xqc_wt_engine_set_default_settings
xqc_wt_session_close_with_error
xqc_wt_session_create_uni_stream
xqc_wt_session_datagram_send
xqc_wt_session_drain
xqc_wt_session_get_close_error_code
xqc_wt_session_get_close_reason
xqc_wt_session_get_h3_conn
xqc_wt_unistream_closing_is_stop_sending
xqc_wt_unistream_id
xqc_wt_unistream_reset
xqc_wt_unistream_send
xqc_wt_unistream_set_read_paused
xqc_wt_unistream_stop_sending
```

### Additional Demo APIs: 19 APIs

```text
xqc_h3_ext_bytestream_create
xqc_h3_ext_bytestream_send
xqc_h3_ext_datagram_send
xqc_webtransport_close
xqc_webtransport_create_bidirectional_stream
xqc_webtransport_destroy
xqc_webtransport_engine_create
xqc_webtransport_engine_destroy
xqc_webtransport_engine_feed_packet
xqc_webtransport_engine_finish_recv
xqc_webtransport_engine_process
xqc_webtransport_new
xqc_webtransport_parse_url
xqc_webtransport_stream_write
xqc_wt_bidistream_get_peer_reset_error
xqc_wt_bidistream_get_peer_stop_sending_error
xqc_wt_client_open_session
xqc_wt_conn_get_h3_conn
xqc_wt_session_create_bidi_stream
```
