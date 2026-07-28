# WebTransport over HTTP/3 draft-15 alignment TODO

This note compares the current local WebTransport implementation with
`wt_draft_15.txt`, which is `draft-ietf-webtrans-http3-15` dated 2026-03-02
(`wt_draft_15.txt:1`, `wt_draft_15.txt:11`, `wt_draft_15.txt:14`).

## Current target status

This document was originally written before the draft-15 migration started.
As of the current working tree, SETTINGS, `webtransport-h3`, HTTP Datagram
Quarter Stream ID demux, `WT_DRAIN_SESSION = 0x78ae`, strict invalid
session-id handling, pre-2xx rejection, session flow-control capsules,
transactional outgoing quota reservation/commit/rollback on one-shot plus
advanced bidi send paths, dynamic `WT_MAX_DATA` / `WT_MAX_STREAMS_*` issuance,
`WT_DATA_BLOCKED` / `WT_STREAMS_BLOCKED` handling, `RESET_STREAM_AT`
reliable-prefix receive handling, bounded optimistic stream/datagram buffering
with explicit overflow handling, session termination gating, optional browser
Origin allowlist with 403 rejection, close reason limits, WT app error-code
mapping, split WT stream session-id header reassembly, standard-H3 datagram
callback delivery, and length-aware H3 header storage are implemented.
Remaining tracked items are adjacent SDK/runtime gaps, not known draft-15 wire
blockers.

Runtime caveat: Python stream writes now retry partial writes and `-XQC_EAGAIN`
through `await drain()`. Hard WT session-flow-control blocks such as peer max
data/streams exhaustion still surface as `WebTransportError` after sending the
appropriate `WT_*_BLOCKED` capsule; they require the peer to send a later
`WT_MAX_*` capsule before a retry can succeed.

## P0: wire compatibility blockers

- [x] Replace/augment WebTransport SETTINGS for draft-15.
  Draft-15 requires servers to send `SETTINGS_WT_ENABLED > 0`,
  `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`, `SETTINGS_H3_DATAGRAM = 1`,
  `max_datagram_frame_size > 0`, and an empty `reset_stream_at` transport
  parameter; draft clients also send the draft-specific `SETTINGS_WT_ENABLED`
  (`wt_draft_15.txt:364`, `wt_draft_15.txt:397`, `wt_draft_15.txt:402`,
  `wt_draft_15.txt:415`, `wt_draft_15.txt:427`). Current code emits/parses
  `XQC_H3_SETTINGS_ENABLE_WEBTRANSPORT = 0x2b603742` and
  `XQC_H3_SETTINGS_WEBTRANSPORT_MAX_SESSIONS = 0xc671706a`
  (`src/http3/xqc_h3_defs.h:50`, `src/http3/frame/xqc_h3_frame.c:436`,
  `src/http3/xqc_h3_conn.c:739`). Draft-15 needs `0x2c7cf000`, plus
  `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI = 0x2b64`,
  `SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI = 0x2b65`, and
  `SETTINGS_WT_INITIAL_MAX_DATA = 0x2b61`
  (`wt_draft_15.txt:1667`, `wt_draft_15.txt:1688`,
  `wt_draft_15.txt:1701`, `wt_draft_15.txt:1714`).
  Safari 26.4 still requires the legacy max-sessions setting path; this is
  exposed explicitly as `serve(..., webtransport_mode="legacy")` so the
  draft-15 default does not silently downgrade. Browser interop that sends
  draft-15 SETTINGS but tolerates legacy-only peer SETTINGS is exposed
  separately as `serve(..., webtransport_mode="compat")`.

- [x] Gate session creation on negotiated WT support.
  Draft-15 says clients MUST NOT establish WT sessions until receiving the
  server's WT support setting (`wt_draft_15.txt:367`). The Python path opens a
  session as soon as the QUIC/TLS handshake future is done
  (`xquic_webtransport/python/pyxquic_wt/_connection.py:125`), and the C open
  path sends CONNECT immediately without checking peer WT settings
  (`src/webtransport/xqc_webtransport_ctx.c:907`). This is not just cosmetic:
  it can send draft-15-invalid CONNECT to a plain H3 endpoint.

- [x] Switch the HTTP upgrade token to `webtransport-h3`.
  Draft-15 explicitly distinguishes H3 WT from the capsule-based H2 token:
  this document uses `webtransport-h3`; H2 uses `webtransport`
  (`wt_draft_15.txt:285`, `wt_draft_15.txt:472`,
  `wt_draft_15.txt:1653`). Current client sends `webtransport`
  (`src/webtransport/xqc_webtransport_ctx.c:925`), and current server only
  accepts `webtransport` (`src/webtransport/xqc_webtransport_ctx.c:259`).
  Keep `webtransport` only as an explicit legacy compatibility mode.

- [x] Fix DATAGRAM wire format and demux.
  Draft-15 WebTransport datagrams are HTTP Datagrams whose payload follows the
  HTTP Datagram Quarter Stream ID and is otherwise unmodified
  (`wt_draft_15.txt:828`). The WT layer now encodes/decodes the HTTP Datagram
  Quarter Stream ID derived from the CONNECT stream id and leaves the
  WebTransport application datagram payload unchanged. Standard `h3` ALPN also
  registers the H3 datagram callbacks, so this path is no longer limited to
  `h3-ext`.

- [x] Update `WT_DRAIN_SESSION` capsule type.
  Draft-15 registers `WT_DRAIN_SESSION = 0x78ae`
  (`wt_draft_15.txt:885`, `wt_draft_15.txt:1896`). Current code uses
  `0x2844` (`src/webtransport/xqc_webtransport_wire.h:17`), so DRAIN is
  guaranteed to be invisible to draft-15 peers.

- [x] Implement initial `RESET_STREAM_AT` for WebTransport data stream resets.
  Draft-15 relies on the `reset_stream_at` transport parameter and says WT data
  stream resets use `RESET_STREAM_AT` with a reliable size at least large enough
  to carry the WT stream header (`wt_draft_15.txt:397`,
  `wt_draft_15.txt:812`). Current WT reset helpers call regular
  `RESET_STREAM` packet writing and pass user error codes directly
    (`src/webtransport/xqc_webtransport_stream.c:477`,
    `src/webtransport/xqc_webtransport_stream.c:489`,
    `src/webtransport/xqc_webtransport_stream.c:520`). There is no evidence of
    `reset_stream_at` transport parameter support in the current WT path.
    Current transport receive handling records `reliable_size`, preserves or
    truncates buffered STREAM data up to that prefix, accepts late STREAM frames
    inside the reliable prefix after RESET_STREAM_AT, and only reports reset to
    the application after the reliable prefix is drained.

- [x] Validate session IDs strictly.
  Draft-15 session IDs are CONNECT stream IDs and MUST correspond to
  client-initiated bidirectional streams; invalid IDs require closing the H3
  connection with `H3_ID_ERROR` (`wt_draft_15.txt:641`,
  `wt_draft_15.txt:653`). Current stream/datagram receive paths decode a
  session ID and then fall back to `wt_conn->wt_session` if lookup fails
    (`src/webtransport/xqc_webtransport_ctx.c:566`,
    `src/webtransport/xqc_webtransport_ctx.c:684`,
    `src/webtransport/xqc_webtransport_ctx.c:769`). That fallback turns malformed
    or cross-session data into valid application data. It is a protocol violation.
    Current stream and datagram receive paths close the H3 connection with
    `H3_ID_ERROR` for malformed or unknown session ids. Optimistic buffering is
    only used after the session id resolves to a known, not-yet-established
    session.

- [x] Buffer streams/datagrams until their session association is known, with
  bounded buffers.
  Draft-15 allows optimistic streams/datagrams before the 2xx response, and
  endpoints SHOULD buffer them until associated while bounding the buffer
  (`wt_draft_15.txt:646`, `wt_draft_15.txt:845`). Current code often drops,
  errors, or routes to the default session when `wt_session` is missing
  (`src/webtransport/xqc_webtransport_ctx.c:506`,
  `src/webtransport/xqc_webtransport_ctx.c:620`,
  `src/webtransport/xqc_webtransport_ctx.c:650`). This needs a real pending
  association table keyed by session ID plus limits and rejection behavior.
    The core now buffers pre-established stream payload on the WT stream wrapper
    and datagrams on the WT connection, with fixed count/byte limits, then flushes
    them once the Extended CONNECT response establishes the session. Stream buffer
    overflows return an error to the H3 callback; datagram buffer overflow closes
    the target WT session with `XQC_WT_ERROR_BUFFERED_STREAM_REJECTED`.

- [x] Reassemble WT stream session-id headers across read callbacks.
  QUIC STREAM delivery can split the WT stream header. The receive path now
  buffers partial session-id varints and the C bash e2e `split-header` scenario
  opens session id `64`, sends the two-byte varint across two callbacks, and
  verifies the server routes the payload to that session.

## P1: session establishment and security semantics

- [x] Reject before `2xx`, not by closing an already accepted session.
  Draft-15 says missing resource should be `404` and failed Origin should be
  `403` before accepting; the session is established once a `2xx` is sent
  (`wt_draft_15.txt:484`, `wt_draft_15.txt:496`). Core C currently has a
  `TODO send 403/404 headers` branch (`src/webtransport/xqc_webtransport_ctx.c:287`).
  The Python server route callback rejects by sending a WT close capsule with
  code `404` after session creation (`src/webtransport/xqc_wt_py_api.c:1249`).
  That is semantically too late.

- [x] Validate browser `Origin`.
  Draft-15 requires `:scheme = https`, both `:authority` and `:path`, and
  browser-origin validation (`wt_draft_15.txt:475`, `wt_draft_15.txt:477`,
  `wt_draft_15.txt:480`). Server-side pseudo-header validation now checks
  method, protocol, scheme, authority, and path before returning 2xx. Browser
  `Origin` policy is now exposed as `serve(..., allowed_origins=[...])`; when
  configured, non-matching or missing Origin is rejected before session
  creation.

- [x] Do not initiate WebTransport in 0-RTT.
  Draft-15 forbids initiating WT in 0-RTT because CONNECT is not safe
  (`wt_draft_15.txt:515`). Current code does not appear to implement 0-RTT WT
  session resumption; the client also waits for peer H3 SETTINGS before opening
  a WT session, so it cannot send WT CONNECT in early data. Keep this invariant
  explicit if session resumption is added later.

- [ ] TLS verification must become a real SDK option.
  This is not a draft-15 wire-format item, but it is a release blocker for a
  browser/security-facing SDK. Python passes `no_verify_cert = 1` unconditionally
  (`xquic_webtransport/python/pyxquic_wt/_client.py:61`) and documents
  `cert_hash` as ignored (`xquic_webtransport/python/pyxquic_wt/_client.py:106`).

## P1: session-level flow control

- [x] Implement the draft-15 session flow-control model or explicitly disable
  configurations that need it.
  Draft-15 introduces session-level flow control and its initial SETTINGS
  (`wt_draft_15.txt:981`, `wt_draft_15.txt:1138`). It defines
  `WT_MAX_STREAMS` for bidi/uni (`0x190B4D3F`, `0x190B4D40`),
  `WT_STREAMS_BLOCKED` (`0x190B4D43`, `0x190B4D44`), `WT_MAX_DATA`
  (`0x190B4D3D`), and `WT_DATA_BLOCKED` (`0x190B4D41`)
  (`wt_draft_15.txt:1237`, `wt_draft_15.txt:1302`,
  `wt_draft_15.txt:1349`, `wt_draft_15.txt:1408`). Current capsule parser only
  handles CLOSE and DRAIN (`src/webtransport/xqc_webtransport_ctx.c:371`,
  `src/webtransport/xqc_webtransport_ctx.c:398`), and current H3 settings
  struct has only `webtransport_max_sessions`
    (`include/xquic/xqc_http3.h:287`). There is no enforcement for cumulative
    stream counts, monotonic limit updates, or per-session max data.
    Current send paths use WT wrappers for one-shot `send_bidi()` and the
    advanced `create_bidirectional_stream().write_all()` path, so outgoing stream
    count and session data checks are not bypassed by the Python high-level API.

- [x] Close sessions with `WT_FLOW_CONTROL_ERROR` on limit violations.
  Draft-15 requires closing the WT session if incoming streams/data exceed the
  advertised limits or if received `WT_MAX_*` decreases
  (`wt_draft_15.txt:1275`, `wt_draft_15.txt:1380`). The registered error code
  is `0x045d4487` (`wt_draft_15.txt:1812`). Current code has no such constant
  or close path (`rg` only finds the draft text and no source definition).

## P1: session termination and error mapping

- [x] Reset/abort all associated streams on session termination.
  Draft-15 says a session terminates when the CONNECT stream closes or a
  `WT_CLOSE_SESSION` capsule is sent/received, then all associated streams must
  be reset/aborted with `WT_SESSION_GONE` and no new datagrams/streams may be
  sent (`wt_draft_15.txt:1436`, `wt_draft_15.txt:1446`). Current close handling
  stores close state and notifies callbacks (`src/webtransport/xqc_webtransport_ctx.c:371`),
  but session destruction deliberately frees WT wrappers without closing QUIC
  streams (`src/webtransport/xqc_webtransport_session.c:58`). That may be
  necessary for ownership safety, but draft-15 still needs a separate
  protocol-level reset/abort pass before object teardown. The core now marks
  sessions terminated when `WT_CLOSE_SESSION` is sent/received or the CONNECT
  stream closes, blocks new streams/datagrams, and resets/stops associated
  streams with `WT_SESSION_GONE`.

- [x] Enforce CONNECT-stream post-close rules.
  Draft-15 requires FIN immediately after sending `WT_CLOSE_SESSION`; after
  receiving it, extra CONNECT stream data must reset with `H3_MESSAGE_ERROR`
  (`wt_draft_15.txt:1491`, `wt_draft_15.txt:1495`). Current send path does send
  FIN (`src/webtransport/xqc_webtransport_session.c:194`), but the receive path
  does not mark the CONNECT stream as closed-for-capsules and reject later DATA
  (`src/webtransport/xqc_webtransport_ctx.c:371`). The receive path now marks
  `close_capsule_received` and rejects subsequent CONNECT DATA with
  `H3_MESSAGE_ERROR = 0x10e`.

- [x] Enforce close reason length and error-code mapping.
  Draft-15 says close message length MUST NOT exceed 1024 bytes
  (`wt_draft_15.txt:1480`) and registers the WT application error-code range
  (`wt_draft_15.txt:1864`). Current encode uses a 512-byte stack buffer
  (`src/webtransport/xqc_webtransport_session.c:186`), which rejects long
  messages indirectly but does not implement the draft limit or error behavior.
  Stream reset helpers also pass user error codes straight to QUIC
  (`src/webtransport/xqc_webtransport_stream.c:489`), instead of mapping
  WebTransport application error codes into the registered HTTP/3 range. The
  close capsule codec now enforces the 1024-byte reason limit, and stream reset
  / stop-sending helpers map WT application error codes into the registered
  HTTP/3 reserved range.

## P2: implementation correctness issues adjacent to draft-15

- [x] Stop treating HTTP header iovecs as NUL-terminated strings in core parsing.
  `xqc_wt_h3_request_read_notify()` casts `iov_base` to `char *` and calls
  `strcmp`-based helpers (`src/webtransport/xqc_webtransport_ctx.c:227`,
  `src/webtransport/xqc_webtransport_ctx.c:181`). `xqc_wt_py_api.c` now has a
  safer length-aware extraction path for Python route callbacks
  (`src/webtransport/xqc_wt_py_api.c:1231`), but the core request table insert
  still copies using `strlen` (`src/webtransport/xqc_webtransport_request.c:52`).
  This can read past header buffers depending on H3 decoder storage. Core
  request table insertion is now length-aware and `xqc_wt_h3_request_read_notify`
  passes H3 iovec lengths instead of relying on NUL termination.

- [x] Remove default-session fallback after multi-session hash maps were added.
  The new hash map storage is the right direction, but fallback routing
  (`src/webtransport/xqc_webtransport_ctx.c:90`,
  `src/webtransport/xqc_webtransport_ctx.c:568`,
  `src/webtransport/xqc_webtransport_ctx.c:686`) masks wrong session IDs and
  makes multi-session behavior non-deterministic.

- [x] Fix Python server session bookkeeping.
  The Python server now stores sessions only under the actual C session ID,
  so close callbacks remove the same entry that data callbacks use
  (`xquic_webtransport/python/pyxquic_wt/_server.py`).

- [ ] Finish IPv6 sockaddr support in Python I/O.
  The C client creation path now uses `inet_pton(AF_INET6)` when constructing
  peer addresses (`src/webtransport/xqc_wt_py_api.c:416`), but the Python
  runtime still builds sockaddr bytes via `socket.inet_aton`
  (`xquic_webtransport/python/pyxquic_wt/_connection.py:193`,
  `xquic_webtransport/python/pyxquic_wt/_server.py:145`). IPv6 sockets will
  still fail in Python feed/send paths.

- [x] Remove release docs that call this "RFC 9297 WebTransport".
  The README now describes this as "WebTransport over HTTP/3 core" and avoids
  claiming full RFC/draft-15 compatibility while the draft-15 migration remains
  open. Keep future docs precise: RFC 9220 for Extended CONNECT, RFC 9297 for
  HTTP Datagram/Capsule, and `draft-ietf-webtrans-http3-15` for WebTransport
  over HTTP/3.

## Already close to draft-15

- Bidi WT stream signal `0x41` and uni WT stream type `0x54` match draft-15
  (`wt_draft_15.txt:741`, `wt_draft_15.txt:699`,
  `src/webtransport/xqc_webtransport_wire.h:10`).
- `WT_CLOSE_SESSION = 0x2843` matches draft-15
  (`wt_draft_15.txt:1463`, `src/webtransport/xqc_webtransport_wire.h:17`).
- Client CONNECT includes `:scheme = https`, `:authority`, and `:path`
  (`src/webtransport/xqc_webtransport_ctx.c:927`,
  `src/webtransport/xqc_webtransport_ctx.c:929`,
  `src/webtransport/xqc_webtransport_ctx.c:931`).
