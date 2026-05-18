# WebTransport draft-15 migration progress

## 2026-05-18

### Step 1: wire constants and negotiation

- Switched `WT_DRAIN_SESSION` from legacy `0x2844` to draft-15 `0x78ae`.
- Added draft-15 H3 settings IDs:
  - `SETTINGS_WT_ENABLED = 0x2c7cf000`
  - `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI = 0x2b64`
  - `SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI = 0x2b65`
  - `SETTINGS_WT_INITIAL_MAX_DATA = 0x2b61`
- SETTINGS emission now sends draft-15 WT settings instead of the legacy
  WebTransport max-sessions setting.
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
