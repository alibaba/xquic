# Reliable Stream Reset Specification

This specification defines XQUIC's QUIC reliable stream reset capability. It
is independent from HTTP/3 SETTINGS registration; a higher-layer protocol can
depend on either capability or both.

## Scope and Authority

Wire behavior follows
[draft-ietf-quic-reliable-stream-reset-09](https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-09),
especially Sections
[3](https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-09#section-3),
[4](https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-09#section-4),
and
[5 through 5.4](https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-09#section-5).
[RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) remains authoritative
for the underlying stream, reset, final-size, and flow-control rules.

The `-09` revision is intentionally pinned because
[WebTransport over HTTP/3 draft-16](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16)
normatively depends on that revision. Upgrading the reliable reset draft
requires a separate compatibility review.

## Ownership and Dependencies

The QUIC transport layer owns capability negotiation, frame processing,
stream state, recovery, and flow-control accounting. HTTP/3 and application
protocols only select a reliable prefix and consume reset notifications.

WebTransport over HTTP/3 draft-16 is the primary intended downstream
consumer:

- [Section 3.1](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-3.1)
  requires both endpoints to advertise `reset_stream_at`.
- [Section 4.4](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-4.4)
  requires `RESET_STREAM_AT` when a WebTransport data stream is reset, with a
  Reliable Size that covers at least the WebTransport stream header.

This capability does not implement WebTransport and does not depend on
HTTP/3, the generic SETTINGS registry, Datagram, or Capsule Protocol.

## Public API Contract

The public declarations are in
[`include/xquic/xquic.h`](../../../include/xquic/xquic.h).

| Interface | Contract |
|-----------|----------|
| `xqc_conn_settings_t.enable_reset_stream_at` | Enables the local receive capability and advertises the empty `reset_stream_at` transport parameter. The default is disabled. |
| `xqc_stream_set_reliable_size(stream, reliable_size)` | Configures a 62-bit prefix length on a send-capable stream. A positive value requires current-handshake peer support. Zero selects ordinary reset and does not require the extension. Before reset, the value can be replaced; after a reliable reset is sent, it can only decrease. |
| `xqc_stream_reset(stream, error_code)` | Resets only the send direction. A configured positive prefix sends `RESET_STREAM_AT`; zero or no configured prefix sends ordinary `RESET_STREAM`. A successful reset rejects later application data and FIN writes. |
| `xqc_stream_close(stream)` | Uses the same atomic send-reset path, then closes the applicable receive direction. A previously committed send reset keeps its error, including when its ACKs are still pending. An ordinary send direction already in Data Recvd stays terminal while the local close error remains visible to the application. It returns `-XQC_EAGAIN` without changing reset state when a configured prefix exceeds bytes already accepted by XQUIC. |
| `stream_stop_sending_notify` | Optionally reports the peer's 62-bit `STOP_SENDING` error. Retransmissions can repeat the callback. The notification does not require the application to submit more data after a reset request. |
| `xqc_stream_recv()` | Delivers at most the reliable prefix, then reports `-XQC_ESTREAM_RESET`; bytes after the reliable boundary are not delivered. |

`xqc_stream_set_reliable_size()` returns `-XQC_EPARAM` for an invalid stream,
receive-only direction, or value outside the QUIC varint range. For a positive
value it returns `-XQC_ESTATE` before handshake completion, without peer
negotiation, or when an already-sent boundary would increase. A sent boundary
can decrease, including to zero, while Final Size and Application Error Code
remain fixed.

If a configured prefix exceeds the current send offset,
`xqc_stream_reset()` returns `-XQC_EAGAIN` atomically: it records no reset,
queues no frame, and leaves application writes legal. The application can send
more data and retry. After success, repeating the same boundary and error is
idempotent. After lowering the configured boundary, repeating the same error
queues the lower-boundary update; changing the error returns `-XQC_ESTATE`.

The public flow API does not initiate reliable reset in 0-RTT. Transport
parameter persistence and receive processing must still obey the protocol's
0-RTT rules. Applications pass scalar values only; callback stream pointers
are borrowed for the callback duration. Callbacks can re-enter XQUIC, so the
implementation must complete stream access before notification or otherwise
keep the stream alive.

This version adds fields to `xqc_conn_settings_t` and
`xqc_stream_callbacks_t`. Mixing an application built with the old layouts
and a library built with the new layouts is unsupported; consumers must
recompile all callers against the matching public headers.

## Wire and State Invariants

The original `RESET_STREAM` codec remains unchanged. Connections
that advertise `reset_stream_at` dispatch ordinary resets through an
extension-specific path for mixed-frame validation and final-size accounting;
other connections retain ordinary-reset processing with guards preserving
committed send resets and terminal stream states.

An ordinary peer reset retains XQUIC's implicit reverse-reset policy for an
open sending side. A committed reliable send reset keeps its error, final size
and reliable prefix, regardless of local receive capability. In the extension
path, an uncommitted prefix that still needs application data falls back to
ordinary reset, as with `STOP_SENDING`. A send failure is returned before
receive completion or closing notification.

- `reset_stream_at` is transport parameter `0x1d` with an empty value. A
  non-empty or duplicate value is a `TRANSPORT_PARAMETER_ERROR`.
- Both endpoints remember the parameter for 0-RTT. A server that accepts
  0-RTT cannot disable a capability remembered by the client. Implementations
  that cannot preserve it have to reject early data, as specified below.
- `RESET_STREAM_AT` is frame type `0x24`, followed by Stream ID, Application
  Error Code, Final Size, and Reliable Size as QUIC variable-length integers.
- The frame is ack-eliciting, belongs only in application-data packet number
  space, and is retransmitted on loss while it remains relevant.
- Reliable Size cannot exceed Final Size. Final Size is charged to stream and
  connection flow control. Violations use the draft's specific transport
  errors.
- Later frames for one stream cannot change Application Error Code or Final
  Size. Reliable Size can decrease but cannot increase; a reordered larger
  value is ignored. Connections advertising the extension also validate
  these fields on duplicate ordinary resets, even before any RESET_STREAM_AT.
- The receive path accepts a later, lower Reliable Size. The current public
  send API exposes the same monotonic lowering rule after the first reset.
- Reliable data acknowledgement uses a per-stream continuous acknowledged
  offset plus a sorted, merged list of later ACK ranges. Duplicate,
  retransmitted, PTO, and multipath-copy ACKs are idempotent; dropping data is
  never counted as acknowledgement. Track data ACKs only when the peer
  advertises `reset_stream_at`, including ACKs before the application selects
  a reliable prefix or resets the stream. A late control-frame ACK after loss
  still counts, even when the packet is no longer in flight.
- The sender remains incomplete until the control frame carrying the current
  smallest reliable boundary and every byte before that boundary are
  acknowledged. Data outside that boundary no longer needs reliable retention
  and SHOULD NOT be retransmitted. Lowering the boundary immediately
  recomputes completion and cleans all reachable send queues.
- The receiver remains in `Size Known` until every byte before the smallest
  reliable boundary is available, delivers that prefix, and only then reports
  the reset. Send and receive directions of a bidirectional stream remain
  independent.
- A local zero boundary emits ordinary `RESET_STREAM`. A received
  `RESET_STREAM_AT` with zero boundary still requires extension authorization
  and frame validation, then enters the ordinary reset path with identical
  state, accounting, cleanup, and callback behavior. Extension provenance is
  retained to validate the immutable receive error and final size of later
  resets and STREAM FINs, independently of any local send reset.
- `Data Read` is terminal. Ordinary and reliable reset share idempotent Final
  Size accounting, connection flow-control progress, shutdown, and callback
  ordering. All stream access completes before a closing callback that can
  re-enter XQUIC or destroy the stream.

## 0-RTT Session Tickets

The early-data TP list currently contains only `reset_stream_at`, encoded as
one byte (0 or 1). Context construction and ticket appdata share this encoding;
additional TPs must extend both the encoding and the per-parameter checks.
Either capability mismatch
rejects only 0-RTT, retains valid session resumption, and lets rejected stream
data replay in 1-RTT. Matching values add no rejection. Other transport
parameters keep their existing policy; ticket encoding, authentication and
keys remain native TLS. Missing or malformed reset bindings reject early data.

BoringSSL appends the byte to the `xquic` early-data context. BabaSSL keeps
the original fixed native context because it copies that context on renewal;
its public TP ticket callbacks renew the authenticated TP data in ticket
appdata, and `xqc_ssl_tp_allow_early_data_cb` validates its length and checks
each included parameter before acceptance.

Every successful handshake installs and persists the newly received transport
parameters, replacing the cached reset capability even after 0-RTT rejection.
New tickets record the current capability for subsequent resumptions.

## Validation Contract

The registered tests in
[`tests/unittest/xqc_reliable_reset_test.c`](../../../tests/unittest/xqc_reliable_reset_test.c)
cover transport parameters, receive ordering and errors, ACK/loss ordering,
`STOP_SENDING`, API state, and varint boundaries. Frame-bit tests cover
ack-eliciting, in-flight, and retransmission classification.

Required validation also includes:

- a client-only library build;
- a server 0-RTT capability-retention test;
- a closing callback that re-enters and releases the stream;
- a connection `MAX_DATA` assertion after discarding the unreliable suffix;
- continuous ACK range insertion, merge, duplicate, and gap-fill cases;
- local and received zero-boundary equivalence;
- monotonic send-boundary updates and current-control-frame ACK selection;
- send/high-priority/unacked/lost/PTO/multipath queue cleanup; and
- client-to-server happy and rejection cases.

These requirements define completion of the capability; passing only the
registered unit tests is insufficient.

The `transport.stream` case group registers endpoint coverage for negotiated
prefix delivery, invalid reliable size, closing after a send reset, and changed
final size or error after a zero-boundary reset. Cases 744–746 cover opposite
send/receive errors across zero-boundary retransmissions, a changed STREAM FIN
after zero-boundary reset, and ordinary send reset followed by an idempotent
close that sends STOP_SENDING. The regular CI case runner
includes these cases; they can also be selected individually with `--case`.
The `tls.handshake` group requires these real ticket-resumption cases:

| Case | Cached/server reset | Required outcome |
|------|---------------------|------------------|
| 909 | 1/0 | Reject 0-RTT, retain TLS resumption, complete the request in 1-RTT, and update negotiated and saved reset to 0. |
| 910 | 0/1 | Reject 0-RTT, retain TLS resumption, complete the request in 1-RTT, and update negotiated and saved reset to 1. |
| 911, 912 | 0/0, 1/1 | Accept 0-RTT and complete the request with the matching reset capability. |

Each case also resumes with the refreshed ticket and transport parameters,
requiring accepted 0-RTT and the current capability. Cases 722, 723, 1014, and
1020 cover ordinary reset final sizes and application close errors after
sending has completed.
Existing receive-cancellation cases 21 and 28 require `Reset Read` on the
receive side and retain the local application error. Per RFC 9000 Sections
3.1 and 3.4, their send side can finish as `Data Recvd` if already
acknowledged, or `Reset Recvd` if cancelled before completion.
