# AI Behavior Specifications

Source: `docs_ai/code_map.md`, module-level `CLAUDE.md`, public headers, and source inspection

This document captures behavior that agents must preserve when modifying XQUIC. It is not a complete protocol specification; it is the project-local contract that prevents accidental semantic drift.

## Maintenance Contract

Update this file when a change:

- Changes public API behavior, callback timing, error handling, lifecycle, ownership, or stats semantics.
- Changes protocol behavior, state transitions, feature negotiation, default values, or compatibility behavior.
- Adds a feature gate or changes what a gate enables.
- Fixes a bug by clarifying an invariant that was previously implicit.

If a behavior is intentionally changed, add or update a decision in `docs_ai/decision_records.md`.

## Spec Entry Template

Use this structure for new specs:

```md
### <behavior name>

Scope:
- Modules and files covered.

Contract:
- Required behavior and invariants.

Call path:
- Entry point -> important functions -> callback/output.

State and ownership:
- Who owns objects, memory, timers, callbacks, and user data.

Failure behavior:
- Return codes, connection errors, close behavior, and logs.

Validation:
- Tests or commands that prove the contract.

Open questions:
- Unknowns that need source confirmation before future edits.
```

## Cross-Module Invariants

### Naming, Return, Time, and Memory

Scope:
- All internal modules.

Contract:
- Internal symbols use the `xqc_` prefix; HTTP/3 symbols use `xqc_h3_` where appropriate.
- Functions returning `xqc_int_t` use `XQC_OK` for success and negative `XQC_E*` values for failure unless the local API documents another convention.
- Time values are monotonic microseconds (`xqc_usec_t`) unless a field explicitly uses milliseconds.
- Internal allocation goes through XQUIC wrappers such as `xqc_malloc`, `xqc_calloc`, and `xqc_free`.
- Logs use pipe-delimited key/value formatting through `xqc_log()`.

Validation:
- Compile warnings and existing unit tests catch some violations; code review must enforce naming, unit, and ownership semantics.

### Public Handles and User Data

Scope:
- `include/xquic/xquic.h`, `include/xquic/xqc_http3.h`, transport and HTTP/3 implementation.

Contract:
- Public handles are opaque to applications.
- Application-owned user data must not be freed or mutated by XQUIC except through documented callback arguments.
- XQUIC-owned connection, stream, packet, TLS, and HTTP/3 objects must be destroyed through their lifecycle owners.
- Callback timing is part of the API contract; changing when create/read/write/close callbacks fire is a behavior change.

Validation:
- API changes require full unit and integration validation.
- Callback lifecycle changes should add or extend tests where possible.

### Feature Gates

Scope:
- `CMakeLists.txt`, `cmake/CMakeLists.txt`, `include/xquic/xqc_configure.h`, gated source files.

Contract:
- Feature-gated code must compile both when the gate is enabled and disabled.
- `SSL_TYPE` chooses exactly one active SSL backend.
- New gates must be documented in build docs, code map, and behavior specs.
- Generated configuration headers must reflect CMake options; do not rely on stale generated values as source truth.

Validation:
- Build at least the affected gate-enabled configuration.
- For default behavior changes, also build the default configuration.

## Transport Behavior

### Engine Drive Model

Scope:
- `src/transport/xqc_engine.c`, public engine APIs.

Contract:
- Applications drive network input through `xqc_engine_packet_process()`.
- Applications drive timers and deferred work through `xqc_engine_main_logic()` and the registered event timer callback.
- The engine owns connection lookup tables and dispatches packets by connection ID.
- Engine lifecycle changes must preserve callback registration and timer scheduling contracts.

Call path:
- UDP input -> `xqc_engine_packet_process()` -> connection lookup/create path -> packet parser -> connection packet processing.
- Timer event -> `xqc_engine_main_logic()` -> connection/timer processing -> packet output callbacks.

Validation:
- `engine_test` plus integration cases for runtime behavior.

### Connection State and Close

Scope:
- `src/transport/xqc_conn.c`, `src/transport/xqc_conn.h`.

Contract:
- Client and server handshake states converge to established state before normal application data flow.
- Connection state changes must update stringification helpers when new states are added.
- Transport errors should use connection error helpers/macros rather than ad hoc flag mutation.
- Close handling must preserve lifecycle callbacks and packet/timer cleanup.

Failure behavior:
- Protocol or internal errors set connection error state and move toward closing/draining behavior through existing helpers.

Validation:
- `conn_test` and `case_test.sh` for handshake/close behavior.

### Packet Number Spaces

Scope:
- `src/transport/xqc_packet*.c`, `src/transport/xqc_frame*.c`, `src/transport/xqc_conn.c`.

Contract:
- Initial, Handshake, and 1-RTT packet number spaces are separate.
- ACK, loss detection, packet protection, and receive records must use the matching packet number space.
- Do not mix packet number controllers or keys across spaces.

Validation:
- `packet_test`, `process_frame_test`, TLS/crypto tests, and integration cases.

### Send Control, Congestion Control, and Pacing

Scope:
- `src/transport/xqc_send_ctl.c`, `src/transport/xqc_pacing.c`, `src/congestion_control/*`.

Contract:
- Send control owns congestion-window checks, loss detection integration, inflight accounting, pacing interaction, and CC callbacks.
- Congestion-control algorithms must not be called directly from unrelated modules.
- Congestion window units are bytes; sample and RTT time units are microseconds.
- App-limited, ACK, and loss samples must be generated and validated before algorithm use.

Validation:
- `send_ctl_test`, CC-specific tests, and `case_test.sh`.

### Streams and Flow Control

Scope:
- `src/transport/xqc_stream.c`, frame parser/writer paths.

Contract:
- Stream lifecycle and flow-control accounting must remain consistent with STREAM, RESET_STREAM, STOP_SENDING, MAX_DATA, and MAX_STREAM_DATA frame handling.
- Stream read/write callbacks are observable API behavior.
- Stream FIN handling must preserve final-size and lifecycle semantics.

Validation:
- `stream_frame_test`, `process_frame_test`, and integration tests.

### FEC and Repair

Scope:
- `src/transport/xqc_fec.c`, `xqc_fec_scheme.c`, `fec_schemes/`, FEC frame and packet paths, FEC transport parameters.

Contract:
- FEC framework behavior is enabled by `XQC_ENABLE_FEC`; concrete schemes are separately gated.
- Scheme registration and dispatch must match enabled scheme flags.
- Repair frame parsing/writing must remain wire-compatible with the transport parameter negotiation.
- FEC changes that affect packet send, repair-only behavior, or recovery semantics are transport behavior changes, not only codec changes.

Validation:
- FEC-enabled build, `fec_test`, `fec_scheme_test`, `galois_test`, and integration validation for send/receive path changes.

## TLS and Crypto Behavior

### Backend Abstraction

Scope:
- `src/tls/xqc_ssl_if.h`, `src/tls/boringssl/*`, `src/tls/babassl/*`.

Contract:
- Core TLS code depends on `xqc_ssl_if.h`, not backend headers.
- Backend directories implement the same abstraction surface.
- Backend-specific code must remain isolated to backend implementation files.

Validation:
- Backend-specific build and TLS/crypto unit tests.

### Handshake, ALPN, 0-RTT, and Key Updates

Scope:
- `src/tls/xqc_tls.c`, `xqc_tls_ctx.c`, `xqc_crypto.c`, transport handshake callers.

Contract:
- ALPN must be registered before connection creation.
- Initial secrets derive from the original DCID; Retry or Version Negotiation paths must re-derive when required by existing TLS reset logic.
- 0-RTT depends on session tickets and backend early-data acceptance.
- Key updates and packet protection changes must preserve packet number space and encryption-level boundaries.

Validation:
- `tls_test`, `crypto_test`, key-update integration case when key update behavior changes.

## HTTP/3 and QPACK Behavior

### HTTP/3 Stream Types and SETTINGS

Scope:
- `src/http3/xqc_h3_conn.c`, `xqc_h3_stream.c`, `frame/xqc_h3_frame.c`.

Contract:
- Request streams are bidirectional.
- Control, push, and QPACK encoder/decoder streams are unidirectional.
- The first frame on a control stream must be SETTINGS.
- SETTINGS ordering and received-state flags are observable protocol behavior.

Validation:
- `h3_test`, `h3_ext_test`, and integration cases.

### Request Lifecycle

Scope:
- `src/http3/xqc_h3_request.c`, `xqc_h3_stream.c`, public HTTP/3 request API.

Contract:
- Request creation binds an HTTP/3 request object to an HTTP/3 stream and application user data.
- Header/body send and receive APIs update request stats and lifecycle timestamps.
- Header, body, empty-FIN, finish, closing, and close paths must preserve callback timing.
- When `XQC_ENABLE_FEC` is enabled, request body handling includes FEC-related paths and must stay consistent with transport FEC negotiation.

Validation:
- `h3_test`, `h3_ext_test`, integration cases, and FEC-enabled validation for FEC paths.

### Header Validation and QPACK

Scope:
- `src/http3/xqc_h3_header.c`, `src/http3/qpack/*`, `src/common/utils/huffman/`.

Contract:
- HTTP/3 pseudo-headers must obey ordering and presence rules.
- QPACK dynamic table capacity changes can fail when entries are referenced; callers must check return values.
- Huffman and prefixed integer/string codecs are shared infrastructure for QPACK behavior.

Validation:
- `qpack_test`, `encoder_test`, `prefixed_str_test`, `stable_test`, `dtable_test`, and huffman tests for codec changes.

## Common Utilities Behavior

### Encoding Utilities

Scope:
- `src/common/utils/vint/`, `src/common/utils/huffman/`.

Contract:
- VINT behavior must remain compatible with QUIC packet/frame encoding.
- Huffman behavior must remain compatible with QPACK/HPACK header compression expectations.
- Codec changes require downstream parser/encoder validation, not only utility tests.

Validation:
- `vint_test`, `huffman_test`, and downstream packet/QPACK tests.

### Logging and Event Logs

Scope:
- `src/common/xqc_log.*`, `src/common/xqc_log_event_callback.*`.

Contract:
- Log schema and levels are part of diagnostics.
- qlog/event logging under `XQC_ENABLE_EVENT_LOG` must not change normal code paths when disabled.
- If changing log formats used by tests or scripts, update tests and docs.

Validation:
- Affected tests/scripts plus manual log evidence when behavior is diagnostic-only.

## Open Specification Gaps

These areas need deeper source-backed specs before large future changes:

- Exact connection state transition matrix in `xqc_conn.c`.
- Exact timer ownership and expiration order across connection, path, loss, PTO, and general-purpose timers.
- Exact FEC block/recovery lifecycle across frame parse, packet output, scheduler, and HTTP/3 request paths.
- Exact MoQ API and behavior under `include/moq/xqc_moq.h` if MoQ work becomes active in this workspace.
