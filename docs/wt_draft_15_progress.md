# WebTransport draft-15 migration progress

## 2026-05-18

### Step 1: wire constants and negotiation

- Switched `WT_DRAIN_SESSION` from legacy `0x2844` to draft-15 `0x78ae`.
- Added draft-15 H3 settings IDs:
  - `SETTINGS_WT_ENABLED = 0x2c7cf000`
  - `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI = 0x2b64`
  - `SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI = 0x2b65`
  - `SETTINGS_WT_INITIAL_MAX_DATA = 0x2b61`
- SETTINGS emission now defaults to draft-15 WT settings while retaining an
  explicit legacy browser mode for Safari versions that cancel CONNECT when
  `WT_INITIAL_MAX_*` settings are present.
- Client CONNECT now sends `:protocol = webtransport-h3`; server checks the
  same token.
- Verification:
  - `bash scripts/build_wt_py.sh`
  - `python3 -m pytest tests/test_wire.py::test_drain_capsule tests/test_wire.py::test_settings_constants -v`

Remaining steps: datagram/session demux, pre-2xx rejection, session flow
control capsules, termination rules, RESET_STREAM_AT, full verification.

### Step 2: HTTP Datagram session demux

- Added HTTP Datagram Quarter Stream ID helpers:
  - `xqc_wt_encode_h3_datagram_session_id()`
  - `xqc_wt_decode_h3_datagram_session_id()`
- Datagram send now prefixes the HTTP Datagram Quarter Stream ID derived from
  the CONNECT stream id, instead of prepending the raw WebTransport session id.
- Client/server Python C API datagram send paths now pass the concrete
  `xqc_wt_session_t` to avoid default-session routing.
- Datagram receive paths decode Quarter Stream ID back to the CONNECT stream id
  and no longer fall back to the default session when lookup fails.
- Stream receive paths now treat unknown session ids as `H3_ID_ERROR` instead
  of silently routing to the default session.
- Verification:
  - `bash scripts/build_wt_py.sh`
  - `python3 -m pytest tests/test_wire.py::test_h3_datagram_session_id_uses_quarter_stream_id tests/test_wire.py::test_h3_datagram_session_id_rejects_non_client_bidi_stream_id -v`
- Note: a broader Python 3.14 run crashed in CFFI callback allocation before
  entering xquic logic; re-run broader E2E after the next build checkpoint.

### Step 3a: client-side WT SETTINGS gate

- Added `xqc_wt_py_client_peer_wt_ready()` for Python to observe whether peer
  SETTINGS have advertised draft-15 WebTransport support.
- Python `open_session()` now waits until peer SETTINGS contain:
  `SETTINGS_WT_ENABLED`, `SETTINGS_ENABLE_CONNECT_PROTOCOL`, and
  `SETTINGS_H3_DATAGRAM`.
- `xqc_wt_py_open_session()` and lower-level `xqc_wt_client_open_session()`
  reject session creation before those SETTINGS are received.
- Verification:
  - `bash scripts/build_wt_py.sh`
  - `python3 -m pytest tests/test_wire.py -v`
  - `python3 -m py_compile pyxquic_wt/*.py`

### Step 3b: pre-2xx session rejection

- Server route rejection now stays on the Extended CONNECT response path:
  unaccepted sessions get a non-2xx response with FIN instead of a
  WebTransport close capsule on an established session.
- Client response handling now forwards both 2xx and non-2xx CONNECT response
  headers into the WT layer.
- Python C API added `XQC_WT_PY_EVENT_REJECTED`; Python `open_session()` maps
  it to `SessionRejectedError(status_code)` instead of waiting for
  `SESSION_OPEN_TIMEOUT`.
- Verification:
  - `rm -rf build_wt && bash scripts/build_wt_py.sh`
  - `python3 -m pytest tests/test_e2e.py::test_route_reject_raises_session_rejected tests/test_e2e.py::test_bidi_echo -q`

### Step 4a: flow-control capsule wire/state path

- Added draft-15 flow-control capsule constants:
  - `WT_MAX_STREAMS` bidi/uni: `0x190B4D3F`, `0x190B4D40`
  - `WT_STREAMS_BLOCKED` bidi/uni: `0x190B4D43`, `0x190B4D44`
  - `WT_MAX_DATA`: `0x190B4D3D`
  - `WT_DATA_BLOCKED`: `0x190B4D41`
- Added `xqc_wt_encode_flow_control_capsule()` and
  `xqc_wt_decode_flow_control_capsule_value()` wire helpers.
- Session state now tracks draft-15 initial local/peer WT limits from H3
  SETTINGS, incoming/outgoing stream counters, and incoming/outgoing session
  body bytes.
- CONNECT stream capsule parsing now consumes flow-control capsules:
  `WT_MAX_STREAMS_*` and `WT_MAX_DATA` update peer limits monotonically;
  decreases close the WebTransport session with `WT_FLOW_CONTROL_ERROR`.
  `WT_*_BLOCKED` capsules are parsed and consumed.
- Data-stream receive paths now enforce local advertised stream/data limits.
  Outgoing stream creation and outgoing body sends check peer advertised
  limits.
- Verification:
  - `bash scripts/build_wt_py.sh`
  - `python3 -m pytest tests/test_wire.py::test_flow_control_capsule_roundtrip tests/test_wire.py::test_flow_control_capsule_constants_from_draft15 -q`
  - `python3 -m pytest tests/test_e2e.py::test_bidi_echo tests/test_e2e.py::test_bidi_large_payload tests/test_e2e.py::test_route_reject_raises_session_rejected tests/test_stream_unit.py::test_session_recv_fast_path_multichunk -q`

### Step 5a: RESET_STREAM_AT wire support

- Added the provisional `reset_stream_at` transport parameter
  `0x17f7586d2cb571` with empty-value encode/decode.
- Added `RESET_STREAM_AT` frame type `0x24` generation, parsing, packet write,
  and receive dispatch.
- Python WT client/server connection settings now advertise `reset_stream_at`.
- WebTransport stream reset helpers now call
  `xqc_write_reset_stream_at_to_packet()` with reliable size equal to the
  current sent offset, falling back to regular `RESET_STREAM` if the peer did
  not negotiate the extension.
- Verification:
  - `rm -rf build_wt && bash scripts/build_wt_py.sh`
  - `python3 -m pytest tests/test_wire.py tests/test_e2e_lowlevel.py tests/test_e2e.py tests/test_echo.py tests/test_stream_unit.py -q`
  - `python3 -m py_compile pyxquic_wt/*.py`
- Caveat: this is the transport wire path needed by WebTransport, but
  reliable-size retransmission behavior still needs targeted transport-level
  tests before calling the underlying QUIC extension mature.

### Step 6: termination, optimistic buffering, and error-code mapping

- Added bounded optimistic buffering for data that arrives before the
  WebTransport session is established:
  - stream payload buffers live on the WT stream wrapper and are flushed after
    the Extended CONNECT response establishes the session;
  - datagrams are buffered on the WT connection by CONNECT stream/session id
    and flushed once the matching session is established.
- Added session lifecycle flags:
  - `established` gates outgoing streams/datagrams;
  - `terminated` blocks new stream/data/datagram sends;
  - `close_capsule_received` rejects later CONNECT stream DATA with
    `H3_MESSAGE_ERROR = 0x10e`.
- Sending or receiving `WT_CLOSE_SESSION`, or closing the CONNECT stream, now
  marks the session terminated and resets/stops associated WT streams with
  `WT_SESSION_GONE`.
- CLOSE capsule encoding/decoding now enforces the draft-15 1024-byte reason
  limit.
- Added WebTransport application error-code mapping helpers for the registered
  HTTP/3 reserved range and use that mapping for WT stream reset/stop-sending.
- Core request header storage is now length-aware and no longer treats H3
  header iovecs as NUL-terminated strings.
- Added optional browser Origin allowlist plumbing through
  `serve(..., allowed_origins=[...])`; when configured, requests with missing
  or non-matching `origin` are rejected before sending a 2xx response.
- Verification:
  - `rm -rf build_wt && bash scripts/build_wt_py.sh`
  - `XQUIC_LIB_PATH=/Users/sy03/github_xquic/xquic/xquic_webtransport/python/pyxquic_wt python3 -m pytest xquic_webtransport/python/tests/test_wire.py xquic_webtransport/python/tests/test_e2e_lowlevel.py xquic_webtransport/python/tests/test_e2e.py xquic_webtransport/python/tests/test_echo.py xquic_webtransport/python/tests/test_stream_unit.py -q`

## 2026-05-21

### Step 8: C draft-15 hardening and bash e2e

- Standard `h3` ALPN now installs the H3 datagram callbacks when H3 extensions
  are enabled, so draft-15 WebTransport datagrams over standard H3 reach the WT
  demux path instead of being limited to the old `h3-ext` ALPN.
- H3 bytestream creation is now allowed for standard H3 connections that have
  WebTransport enabled, which is required for WT bidi data streams using stream
  type `0x41`.
- Client-side 2xx session creation now marks the WT session established before
  invoking the application session-create callback, so callbacks can immediately
  send streams or datagrams without hitting `-XQC_ESTATE`.
- Incoming WT stream session-id varints are reassembled across read callbacks;
  a split varint header now waits for the remaining bytes instead of raising an
  H3 decode error.
- WT stream resets prepare the WT header first and set RESET_STREAM_AT final /
  reliable size to at least the WT header length.
- The C bash e2e now covers bidi echo, datagram echo, local close gates,
  RESET_STREAM_AT reliable prefix, multiple WT sessions on one H3 connection,
  split session-id header reassembly, session flow-control blocked paths,
  compat/legacy mode, strict legacy rejection, invalid datagram session id, and
  sequential session churn.
- Verification:
  - `WT_E2E_SCENARIOS='bidi datagram close-gates reset-prefix multi-session split-header fc-data-blocked fc-stream-blocked compat-legacy strict-reject-legacy invalid-datagram churn' WT_E2E_CLIENT_RUNS=2 scripts/wt_draft15_e2e.sh`

### Step 7: review blocker follow-ups

- Unified the advanced Python bidi stream API with the WT bidistream wrapper:
  `create_bidirectional_stream()` now records an active WT wrapper and
  `stream.write_all()` sends through `xqc_wt_bidistream_send()`, so it enforces
  the same outgoing WT stream/data limits as one-shot `send_bidi()`.
- Fixed the local active bytestream callback split: H3 bytestream creation no
  longer pre-registers locally initiated WT_BIDI streams as passive wrappers.
- Datagram receive is now strict for session ids: malformed Quarter Stream ID
  or unknown CONNECT stream id closes the H3 connection with `H3_ID_ERROR`.
  Optimistic datagram buffering is only used for known but not-yet-established
  sessions; overflow closes the WT session explicitly.
- RESET_STREAM_AT receive handling now preserves reliable prefix semantics:
  buffered data beyond `reliable_size` is dropped/truncated, late STREAM frames
  within the reliable prefix are still accepted after RESET_STREAM_AT, and
  applications can read the reliable prefix before observing reset.
- Outgoing WT session flow-control now uses an explicit
  reservation/commit/rollback path. One-shot `send_bidi()` reserves stream and
  data quota before touching QUIC, commits only accepted payload bytes, rolls
  the reservation back if the combined operation fails before data is written,
  and advanced stream creation rolls stream quota back if wrapper or
  pending-stream registration fails.
- Origin allowlist failures now reject the Extended CONNECT response with
  status `403`, while route misses still use `404`.
- WT stream send wrappers return the number of application payload bytes
  accepted by xquic instead of translating EAGAIN/partial-send state to
  success-like `0`; unaccepted payload bytes are rolled back from WT session
  data quota.
- Strict/compat/legacy behavior is selected by an explicit `xqc_wt_mode_t`
  instead of a pair of browser booleans. Strict draft-15 requires peer
  `WT_INITIAL_MAX_*` SETTINGS; compat keeps draft-15 server SETTINGS but falls
  back to QUIC flow control if a browser peer advertises no WT session budgets;
  legacy omits draft-15 WT_INITIAL settings for Safari.
- Incoming WT data/streams now auto-extend local receive windows with
  `WT_MAX_DATA` / `WT_MAX_STREAMS_*` capsules, and received
  `WT_DATA_BLOCKED` / `WT_STREAMS_BLOCKED` capsules trigger an explicit local
  limit increase plus MAX response.
- Python stream `write_all()` / `write()` now retry partial accepted writes and
  `-XQC_EAGAIN` through `await drain()`. Hard peer WT FC blocks still surface as
  errors after C sends the matching `WT_*_BLOCKED` capsule.
- Verification:
  - `bash scripts/build_wt_py.sh`
  - `XQUIC_LIB_PATH=/Users/sy03/github_xquic/xquic/xquic_webtransport/python/pyxquic_wt python3 -m pytest xquic_webtransport/python/tests/test_e2e.py::test_bidi_echo xquic_webtransport/python/tests/test_e2e.py::test_send_bidi_respects_session_flow_limits xquic_webtransport/python/tests/test_e2e.py::test_create_bidi_stream_respects_session_flow_limits xquic_webtransport/python/tests/test_e2e.py::test_bidi_writes_respect_session_data_limit -q`
  - `XQUIC_LIB_PATH=/Users/sy03/github_xquic/xquic/xquic_webtransport/python/pyxquic_wt python3 -m pytest xquic_webtransport/python/tests/test_e2e.py::test_failed_one_shot_bidi_send_rolls_back_stream_quota -q`
  - `XQUIC_LIB_PATH=/Users/sy03/github_xquic/xquic/xquic_webtransport/python/pyxquic_wt python3 -m pytest xquic_webtransport/python/tests/test_wire.py xquic_webtransport/python/tests/test_e2e_lowlevel.py xquic_webtransport/python/tests/test_e2e.py xquic_webtransport/python/tests/test_echo.py xquic_webtransport/python/tests/test_stream_unit.py -q`
