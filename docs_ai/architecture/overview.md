# XQUIC Architecture Overview

## System Layers

XQUIC implements a layered QUIC/HTTP3 protocol stack. Each layer has a clear responsibility boundary and communicates through well-defined internal interfaces.

```
+-----------------------------------------------------------------------+
|                        Application Layer                               |
|   demo_client / demo_server / mini_client / mini_server / user app     |
+-----------------------------------------------------------------------+
          |                                    |
          | xqc_http3.h API                    | xquic.h API
          v                                    v
+-----------------------------+   +-----------------------------+
|     HTTP/3 Layer            |   |   Direct Transport Access   |
|  (RFC 9114 + RFC 9204)      |   |   (Stream/Datagram API)     |
|  h3_conn, h3_request,       |   |                             |
|  h3_stream, QPACK           |   |                             |
+-----------------------------+   +-----------------------------+
          |                                    |
          +----------------+-------------------+
                           |
                           v
+-----------------------------------------------------------------------+
|                     QUIC Transport Layer                               |
|                       (RFC 9000)                                       |
|   engine, conn, stream, packet, frame, send_ctl, recv_record,         |
|   multipath, scheduler, reinjection, datagram, fec                    |
+-----------------------------------------------------------------------+
          |                        |
          v                        v
+-------------------------+  +----------------------------------+
| Congestion Control      |  |   TLS 1.3 Integration            |
| (Pluggable)             |  |   (RFC 9001)                     |
| Cubic, BBR, BBR2,       |  |   xqc_tls, xqc_crypto, xqc_hkdf |
| NewReno, Copa            |  |                                  |
+-------------------------+  +----------------------------------+
                                       |
                    +------------------+------------------+
                    |                                     |
                    v                                     v
          +------------------+                  +------------------+
          |   BoringSSL      |                  |   BabaSSL        |
          |   Backend        |                  |   (Tongsuo)      |
          +------------------+                  +------------------+
                    |                                     |
                    +------------------+------------------+
                                       |
                                       v
+-----------------------------------------------------------------------+
|                     Common Utilities                                   |
|   log, time, random, str, huffman, vint, ring_array, ring_mem,        |
|   var_buf, 2d_hash, memory_pool, priority_q, rbtree, list             |
+-----------------------------------------------------------------------+
```

## Module Dependency Graph

```
include/xquic/xqc_http3.h  (HTTP/3 public API)
    |
    v
src/http3/                  HTTP/3 connection, stream, request, QPACK
    |
    v
src/transport/              QUIC transport: engine, conn, stream, packet, frame
    |
    +---> src/transport/scheduler/            Multipath schedulers
    +---> src/transport/reinjection_control/  Multipath reinjection
    +---> src/transport/fec_schemes/          Forward Error Correction
    |
    +---> src/congestion_control/             Pluggable CC: Cubic, BBR, BBR2, Reno, Copa
    |
    v
src/tls/                    TLS 1.3 state machine, QUIC packet protection
    |
    +---> src/tls/boringssl/   (if SSL_TYPE=boringssl)
    +---> src/tls/babassl/     (if SSL_TYPE=babassl)
    |
    v
src/common/                 Shared utilities (no upward dependencies)
```

## Key Entry Points

| Use Case | Entry Point Function | Header |
|----------|---------------------|--------|
| Create QUIC engine | `xqc_engine_create()` | `include/xquic/xquic.h` |
| Create client connection | `xqc_connect()` | `include/xquic/xquic.h` |
| Process incoming packet | `xqc_engine_packet_process()` | `include/xquic/xquic.h` |
| Get next timer event | `xqc_engine_main_logic()` | `include/xquic/xquic.h` |
| Create HTTP/3 connection | `xqc_h3_connect()` | `include/xquic/xqc_http3.h` |
| Create HTTP/3 request | `xqc_h3_request_create()` | `include/xquic/xqc_http3.h` |
| Send HTTP/3 headers | `xqc_h3_request_send_headers()` | `include/xquic/xqc_http3.h` |
| Send HTTP/3 body | `xqc_h3_request_send_body()` | `include/xquic/xqc_http3.h` |
| Read HTTP/3 response | `xqc_h3_request_recv_headers()` / `xqc_h3_request_recv_body()` | `include/xquic/xqc_http3.h` |

## Callback / Plugin Architecture

XQUIC uses an event-driven callback model. The application registers callback structs at engine/connection/stream creation time.

### Transport-Level Callbacks (`xqc_transport_callbacks_t`)

Registered via `xqc_engine_create()`. The application must implement:

- **`write_socket`**: Send UDP packet to network
- **`set_event_timer`**: Set timer for `xqc_engine_main_logic()` invocation
- **`conn_create_notify`** / **`conn_close_notify`**: Connection lifecycle events
- **`stream_create_notify`** / **`stream_close_notify`**: Stream lifecycle events
- **`stream_read_notify`** / **`stream_write_notify`**: Stream data events

### HTTP/3-Level Callbacks (`xqc_h3_conn_callbacks_t`)

Registered via `xqc_h3_ctx_init()`. Layered on top of transport callbacks:

- **`h3_conn_create_notify`** / **`h3_conn_close_notify`**: HTTP/3 connection events
- **`h3_request_create_notify`** / **`h3_request_close_notify`**: Request lifecycle
- **`h3_request_read_notify`**: Headers/body/trailer received
- **`h3_request_write_notify`**: Ready to send data

### Pluggable Congestion Control

Congestion control algorithms are registered as `xqc_cong_ctrl_callback_t` structs containing function pointers for:

- `xqc_cong_ctl_init` / `xqc_cong_ctl_reinit`
- `xqc_cong_ctl_on_ack` / `xqc_cong_ctl_on_lost`
- `xqc_cong_ctl_get_cwnd` / `xqc_cong_ctl_get_pacing_rate`

Built-in algorithms: Cubic (default), BBR, BBRv2, NewReno, Copa, Unlimited.

### Pluggable TLS Backend

The TLS layer uses a backend abstraction (`xqc_ssl_if.h`) that isolates the protocol stack from the specific SSL library. Two backends are provided:

- **BoringSSL** (`src/tls/boringssl/`): Google's OpenSSL fork, used in Chromium
- **BabaSSL/Tongsuo** (`src/tls/babassl/`): Alibaba's OpenSSL fork with Chinese cryptographic algorithm support

Selected at compile time via `SSL_TYPE` CMake variable.

### Multipath Scheduler Plugin

For Multipath QUIC, schedulers are registered as `xqc_scheduler_callback_t` structs:

- MinRTT: Always choose the lowest-latency path
- Backup: Primary/backup model with automatic failover
- RAP: Redundant ACK path for reliability
