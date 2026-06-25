# AI Code Map

Source: project root, `docs_ai/codebase_index.md`, module-level `CLAUDE.md` files

This document is the agent-facing navigation map for XQUIC. Use it to choose the first code paths to inspect before changing behavior. Keep `docs_ai/codebase_index.md` as the full file inventory; keep this file as the conceptual map.

## Maintenance Contract

Update this file when a change:

- Adds, removes, renames, or moves a module or important source file.
- Changes ownership of a behavior between modules.
- Adds a new plugin interface, callback family, feature gate, or generated artifact.
- Reveals a more accurate call path during debugging.

For small function-local fixes, no update is required unless the existing map would mislead the next agent.

## Module Entry Template

Use this structure for new or expanded modules:

```md
### `<module/path>`

Purpose:
- What the module owns.

Primary files:
- `path/file.c` -- role.

Main entry points:
- `symbol()` -- when it is called and by whom.

State and ownership:
- Key structs, lifecycle owner, memory owner, timer owner, callback owner.

Upstream/downstream:
- Depends on: modules or public APIs.
- Used by: modules or applications.

Feature gates:
- `XQC_ENABLE_*`, `SSL_TYPE`, generated headers, or none.

First files to inspect:
- For behavior A: `path/file.c`.
- For bug B: `path/file.c`.
```

## High-Level Runtime Path

1. Applications create an engine through `xqc_engine_create()` in `include/xquic/xquic.h`.
2. Client connections enter through `xqc_connect()` or HTTP/3 `xqc_h3_connect()`.
3. UDP input is delivered to `xqc_engine_packet_process()`, which dispatches packets into transport connection processing.
4. Transport parses packets and frames, updates connection/stream/send/receive state, and calls TLS and congestion-control hooks as needed.
5. HTTP/3 sits above transport streams and owns request/control/QPACK stream semantics.
6. The application drives timers through `xqc_engine_main_logic()` and receives callbacks registered at engine, transport, and HTTP/3 setup time.

## Core Modules

### `include/xquic/`

Purpose:
- Public C API for transport, HTTP/3, error codes, typedefs, and generated feature configuration.

Primary files:
- `include/xquic/xquic.h` -- core engine, connection, stream, datagram, settings, callbacks, congestion-control API.
- `include/xquic/xqc_http3.h` -- HTTP/3 connection/request API, HTTP header containers, HTTP/3 callbacks and settings.
- `include/xquic/xqc_errno.h` -- public error-code space.
- `include/xquic/xqc_configure.h` -- generated feature configuration from CMake.

State and ownership:
- Public handles such as `xqc_engine_t`, `xqc_connection_t`, `xqc_stream_t`, `xqc_h3_conn_t`, and `xqc_h3_request_t` are opaque to applications.
- Applications own user data and callback implementations; XQUIC owns internal connection, stream, packet, and HTTP/3 objects.

Upstream/downstream:
- Depends on: public typedefs and generated configuration.
- Used by: every application, demo, mini, test client/server, and internal modules that expose callback interfaces.

First files to inspect:
- Transport API behavior: `include/xquic/xquic.h`, then `src/transport/xqc_engine.c`, `src/transport/xqc_conn.c`, or `src/transport/xqc_stream.c`.
- HTTP/3 API behavior: `include/xquic/xqc_http3.h`, then `src/http3/xqc_h3_conn.c` or `src/http3/xqc_h3_request.c`.

### `src/transport/`

Purpose:
- QUIC transport implementation: engine lifecycle, connection state machine, packet/frame parsing, stream flow control, send control, timers, datagram, multipath, reinjection, and FEC integration.

Primary files:
- `src/transport/xqc_engine.c` -- engine lifecycle, connection lookup, packet dispatch, timer drive.
- `src/transport/xqc_conn.c` -- connection lifecycle, handshake state, close/error handling, path and timer orchestration.
- `src/transport/xqc_stream.c` -- stream lifecycle, stream frame send/receive, flow-control interaction.
- `src/transport/xqc_packet_in.c` / `xqc_packet_out.c` -- inbound and outbound packet objects.
- `src/transport/xqc_packet_parser.c` / `xqc_frame_parser.c` -- packet and frame decoding/encoding.
- `src/transport/xqc_send_ctl.c` -- congestion/loss send-control integration.
- `src/transport/xqc_timer.c` -- timer registration and expiration handling.
- `src/transport/xqc_transport_params.c` -- QUIC transport-parameter encode/decode.

State and ownership:
- `xqc_engine_t` owns connection indexes, global callbacks, TLS context, and timer scheduling integration.
- `xqc_connection_t` owns streams, paths, packet number spaces, send queues, receive records, TLS state, and feature-specific state such as multipath/FEC.
- Packet lifetimes are managed by send/receive queues; do not free packet objects outside their owning queue paths.

Upstream/downstream:
- Depends on: `src/common/`, `src/tls/`, `src/congestion_control/`.
- Used by: HTTP/3, demos, tests, and direct transport API users.

Feature gates:
- `XQC_ENABLE_FEC` for FEC transport parameters, frames, packet repair paths, and HTTP/3 request integration.
- `XQC_ENABLE_MP_INTEROP` for multipath interop scheduler code.
- `XQC_ENABLE_EVENT_LOG` for qlog event emission.

First files to inspect:
- Packet input behavior: `xqc_engine.c`, `xqc_packet_parser.c`, `xqc_conn.c`, `xqc_frame_parser.c`.
- Send behavior: `xqc_conn.c`, `xqc_send_ctl.c`, `xqc_packet_out.c`, `xqc_send_queue.c`.
- Flow-control or stream behavior: `xqc_stream.c`, `xqc_frame_parser.c`, `xqc_packet_out.c`.
- FEC behavior: `xqc_fec.c`, `xqc_fec_scheme.c`, `fec_schemes/`, `xqc_frame_parser.c`, `xqc_packet_out.c`.

### `src/transport/scheduler/`

Purpose:
- Multipath packet scheduler strategies.

Primary files:
- `xqc_scheduler_common.c` -- scheduler interface helpers.
- `xqc_scheduler_minrtt.c` -- prefer lowest RTT path.
- `xqc_scheduler_backup.c` -- primary/backup path scheduling.
- `xqc_scheduler_backup_fec.c` -- backup scheduling with FEC interaction.
- `xqc_scheduler_rap.c` -- redundant ACK path behavior.
- `xqc_scheduler_interop.c` -- interop scheduler guarded by `XQC_ENABLE_MP_INTEROP`.

State and ownership:
- Scheduler state is connection/path scoped and selected by multipath configuration.

Upstream/downstream:
- Depends on: transport connection/path state.
- Used by: `src/transport/xqc_multipath.c` and packet send paths.

First files to inspect:
- Scheduler selection: `src/transport/xqc_conn.c`, `src/transport/xqc_multipath.c`.
- Path choice logic: the concrete scheduler file.

### `src/transport/reinjection_control/`

Purpose:
- Multipath packet reinjection policy.

Primary files:
- `xqc_reinj_default.c` -- default reinjection policy.
- `xqc_reinj_deadline.c` -- deadline-aware reinjection.
- `xqc_reinj_dgram.c` -- datagram reinjection.

Upstream/downstream:
- Depends on: transport packet/path state.
- Used by: `src/transport/xqc_reinjection.c`.

First files to inspect:
- Reinjection trigger and common flow: `src/transport/xqc_reinjection.c`.
- Policy decision: matching file under `reinjection_control/`.

### `src/transport/fec_schemes/`

Purpose:
- FEC scheme implementations used by the transport FEC framework.

Primary files:
- `xqc_xor.c` -- XOR FEC scheme.
- `xqc_reed_solomon.c` -- Reed-Solomon FEC scheme.
- `xqc_packet_mask.c` -- packet-mask FEC scheme.
- `xqc_galois_calculation.c` -- Galois-field arithmetic for Reed-Solomon.

Feature gates:
- `XQC_ENABLE_FEC` enables framework integration.
- `XQC_ENABLE_XOR`, `XQC_ENABLE_RSC`, and `XQC_ENABLE_PKM` compile concrete schemes.

First files to inspect:
- Scheme registration: `src/transport/xqc_fec.c`.
- Scheme interface: `src/transport/xqc_fec_scheme.c`, `src/transport/xqc_fec_scheme.h`.

### `src/congestion_control/`

Purpose:
- Pluggable congestion-control algorithms and shared sampling/filtering infrastructure.

Primary files:
- `xqc_cubic.c` -- Cubic, always compiled and default.
- `xqc_bbr.c` -- BBRv1, always compiled.
- `xqc_bbr2.c` -- BBRv2, gated by `XQC_ENABLE_BBR2`.
- `xqc_new_reno.c` -- NewReno, gated by `XQC_ENABLE_RENO`.
- `xqc_copa.c` -- Copa, gated by `XQC_ENABLE_COPA`.
- `xqc_unlimited_cc.c` -- unlimited testing CC, gated by `XQC_ENABLE_UNLIMITED`.
- `xqc_sample.c` -- ACK/loss sample generation shared by algorithms.
- `xqc_window_filter.c` -- min/max window filters used by BBR variants.

State and ownership:
- Algorithms implement `xqc_cong_ctrl_callback_t` and are driven by transport send-control code.
- Congestion window values are bytes; time values are microseconds.

Upstream/downstream:
- Depends on: `src/common/`.
- Used by: `src/transport/xqc_send_ctl.c`.

First files to inspect:
- Algorithm behavior: the concrete `xqc_<algo>.c`.
- Integration behavior: `src/transport/xqc_send_ctl.c` and `src/congestion_control/xqc_sample.c`.

### `src/tls/`

Purpose:
- QUIC-TLS state machine, packet protection, HKDF key derivation, and SSL backend abstraction.

Primary files:
- `xqc_tls.c` -- TLS handshake driver used by transport.
- `xqc_tls_ctx.c` -- per-engine TLS context, certificate, session ticket, ALPN setup.
- `xqc_crypto.c` -- QUIC packet protection and key material handling.
- `xqc_hkdf.c` -- key derivation wrappers.
- `xqc_ssl_if.h` -- backend abstraction.
- `boringssl/*.c` and `babassl/*.c` -- backend-specific implementations.

State and ownership:
- The engine owns TLS context.
- Connections own TLS sessions, key material, packet-protection state, and handshake progress.

Feature gates:
- `SSL_TYPE=boringssl` or `SSL_TYPE=babassl` selects backend implementation at build time.

First files to inspect:
- Handshake behavior: `xqc_tls.c`, backend `xqc_ssl_if_impl.c`, then transport callers in `xqc_conn.c`.
- Packet protection: `xqc_crypto.c`, backend `xqc_crypto_impl.c`.
- ALPN/session-ticket behavior: `xqc_tls_ctx.c`, backend `xqc_ssl_if_impl.c`.

### `src/http3/`

Purpose:
- HTTP/3 connection, request, stream, frame, header, datagram/bytestream extension, and QPACK orchestration.

Primary files:
- `xqc_h3_conn.c` -- HTTP/3 connection lifecycle, SETTINGS/control stream handling, GOAWAY.
- `xqc_h3_stream.c` -- HTTP/3 stream type handling and stream callbacks.
- `xqc_h3_request.c` -- request lifecycle, header/body send/receive, request stats.
- `xqc_h3_header.c` -- header and pseudo-header validation.
- `frame/xqc_h3_frame.c` -- HTTP/3 frame parse/generate.
- `qpack/xqc_qpack.c`, `xqc_encoder.c`, `xqc_decoder.c` -- QPACK encode/decode orchestration.
- `qpack/dtable/xqc_dtable.c`, `qpack/stable/xqc_stable.c` -- dynamic/static table behavior.

State and ownership:
- HTTP/3 connection state is layered over one transport connection.
- Request objects are tied to bidirectional transport streams.
- QPACK encoder/decoder streams are unidirectional stream state owned by the HTTP/3 connection.

Upstream/downstream:
- Depends on: `src/transport/`, `src/common/`, QPACK utilities.
- Used by: HTTP/3 public API users, demos, and tests.

Feature gates:
- `XQC_ENABLE_FEC` adds request-body handling paths in `xqc_h3_request.c`.

First files to inspect:
- Request send/receive behavior: `xqc_h3_request.c`, `xqc_h3_stream.c`.
- SETTINGS/control stream behavior: `xqc_h3_conn.c`, `xqc_h3_stream.c`, `frame/xqc_h3_frame.c`.
- Header validation/compression: `xqc_h3_header.c`, `qpack/`.

### `src/common/`

Purpose:
- Shared utilities with no upward dependency: logging, time, random, string, memory, containers, hashes, buffers, and protocol utility codecs.

Primary files:
- `xqc_log.c` / `xqc_log_event_callback.c` -- log and qlog callback support.
- `xqc_time.c`, `xqc_random.c`, `xqc_str.c` -- common platform helpers.
- `xqc_malloc.h`, `xqc_memory_pool.h`, `xqc_object_manager.h` -- allocation helpers.
- `utils/huffman/` -- Huffman codec for header compression.
- `utils/vint/` -- QUIC variable-length integer support.
- `utils/ringarray/`, `ringmem/`, `2d_hash/`, `var_buf/` -- reusable data structures.

Upstream/downstream:
- Depends on: no project modules.
- Used by: all internal modules.

First files to inspect:
- QPACK/HTTP header text behavior: `utils/huffman/`.
- Packet/frame integer encoding: `utils/vint/`.
- Logging and observability: `xqc_log.c`, `xqc_log.h`, `xqc_log_event_callback.c`.

### `tests/` and `scripts/`

Purpose:
- Unit, integration, and CI validation harnesses.

Primary files:
- `tests/unittest/main.c` -- CUnit test registration.
- `tests/unittest/xqc_*_test.c` -- focused unit test suites.
- `tests/test_client.c`, `tests/test_server.c` -- integration test binaries.
- `scripts/case_test.sh` -- localhost UDP integration test runner.
- `scripts/xquic_test.sh` -- Linux CI runner for both SSL backends and coverage.
- `scripts/goal.sh` -- long-running task launcher referenced by `AGENTS.md`.

First files to inspect:
- Test mapping and commands: `docs_ai/validation_guide.md`, `docs_ai/testing/test_guide.md`.
- Adding an integration case: `tests/CLAUDE.md`, `tests/test_client.c`, `tests/test_server.c`, `scripts/case_test.sh`.
