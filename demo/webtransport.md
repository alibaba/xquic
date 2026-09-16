# WebTransport loopback demo

Client API and ctx lifecycle contracts are defined in the
[immutable client API specification](../harness/spec/feat/webtransport-client-api-spec.md).

`demo_server -W` serves WebTransport at `/wt` alongside ordinary HTTP/3.
`demo_client -W` opens one session, resets a data stream, then checks exact
bidirectional echo with FIN, datagram echo, and session close. Both programs
accept `-v 16` (the default, advertising draft-07 and draft-16) or `-v 7`
(advertising only draft-07). They print the negotiated draft when ready.

The draft-16 mode supports one simultaneous session per connection and
negotiates reliable stream reset. It does not enable session-level flow
control or pooling, as permitted by
[draft-16 Section 5.1](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-16.html#section-5.1).

Run from the repository root after building the demos. Substitute your
`XQC_BUILD_DIR` for `build` when using a separate build directory:

```sh
sh demo/generate-webtransport-cert.sh
build/demo/demo_server -W -p 8443 \
    -K build/webtransport-cert/server.key \
    -T build/webtransport-cert/server.crt \
    -L build/webtransport-cert/server.log \
    -k build/webtransport-cert/server.keys
```

The certificate uses EC P-256, a 13-day lifetime, and loopback SANs. Generated
keys and certificates stay in the ignored `build/` directory. The script
prints the SHA-256 certificate fingerprint and refuses to overwrite an
existing certificate. No system trust changes are needed.

Run the native client in a second terminal:

```sh
build/demo/demo_client -W -v 16 -a 127.0.0.1 \
    -J build/webtransport-cert/server.crt \
    -U https://localhost:8443/wt \
    -L build/webtransport-cert/client.log \
    -k build/webtransport-cert/client.keys
```

WT mode enables certificate verification. `-J <PEM file>` trusts the supplied
test certificate for this connection and is accepted only for loopback peers.
Signature, validity, and hostname checks remain enabled; the URL uses
`localhost` to match its DNS SAN. Without `-J`, the client loads the TLS
backend's default trust paths. `-K` remains the client lifetime option.

Success prints `WT ready: draft=16 status=200`, byte and FIN checks, then
`WT PASS`, and exits with status zero. A mismatch, rejected session, or
10-second timeout returns nonzero. The server's `WT stream closing` line
for the reset stream verifies that the reset reached the peer; sending a
reset alone is not a peer acknowledgement.

Use `-H <length>` to replace the normal echo sequence with the optional
message-framing probe. The client opens one draft-16 bidirectional stream and
sends one text message containing exactly `length` bytes whose value is `d`.
The length must be between 1 and 16 MiB; `-H` requires `-W -v 16`. Except for
internal validation, it cannot be combined with `-X`. The mode succeeds only
after one complete text message with the same length and payload is decoded on
that stream. The probe queues FIN after its single message. FIN ends the
sending direction; transport read chunks and FIN do not define message
boundaries.

`-H` is an explicit demo opt-in. The selected endpoint must use the same
framing; the option does not change HTTP/3 or WebTransport negotiation, and
omitting it retains the raw WebTransport echo behavior. Use `-g` to print each
complete decoded message in framing mode. In normal mode it prints raw data
from WebTransport stream and datagram callbacks. Printable ASCII is shown
directly; quotes, backslashes, control characters, and binary bytes are
escaped. For example:

```sh
build/demo/demo_client -W -v 16 -H 16 -g -a 127.0.0.1 \
    -J build/webtransport-cert/server.crt \
    -U https://localhost:8443/wt
```

Run the client with `-v 7` against the same server to verify draft-07.
Restart the server with `-v 7` and run the client with `-v 16` to verify
fallback. Both runs should report `draft=7` and pass the echo checks.

The default URL is `https://localhost:8443/wt`, connecting to `127.0.0.1`,
and the default Origin is `http://127.0.0.1:8080`. Use `-U` and `-j` to
exercise rejection:

```sh
build/demo/demo_client -W -a 127.0.0.1 \
    -J build/webtransport-cert/server.crt \
    -U https://localhost:8443/not-wt
build/demo/demo_client -W -a 127.0.0.1 \
    -J build/webtransport-cert/server.crt \
    -U https://localhost:8443/wt -j http://127.0.0.1:8081
```

These commands must return nonzero, print `ready=0` and the response status,
and produce a matching `WT reject` server log. Ordinary HTTP/3 remains
available through `demo_client -A h3` without `-W`.

For Chrome, serve the existing browser page:

```sh
python3 -m http.server 8080 --bind 127.0.0.1 --directory demo
```

Open [the test page](http://127.0.0.1:8080/webtransport.html), paste the
certificate fingerprint, and click **Run allowed-Origin checks**. The page
uses `serverCertificateHashes` and records the browser version, connection,
stream echo with FIN, datagram echo, invalid-path rejection, and close.

Chromium currently gates draft-07 behind
[`EnableWebTransportDraft07`](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/base/features.cc).
When the running browser advertises only draft-02, fully quit Chrome and
restart it with `--enable-features=EnableWebTransportDraft07`. This demo
supports only draft-07 and draft-16; the page cannot select the wire draft.

For browser Origin rejection, serve the page on port 8081, open
[the disallowed-Origin page](http://127.0.0.1:8081/webtransport.html), paste
the same fingerprint, and click **Reject this Origin**. Confirm the server
prints `WT reject` with `allowed_origin=0`.

The application accepts exactly `/wt` and one Origin header equal to
`http://127.0.0.1:8080` or `http://localhost:8080`. Stream callback state is
keyed by session and QUIC stream ID, retained across short writes, and freed
at stream or session close. Pending echo data is bounded to 64 KiB per
bidirectional stream; overflow resets that stream. Datagram send failures
are reported and are not retried. Callback sends schedule a 1 ms engine
event, preserving the shared HTTP/3 and engine user data.

Incoming unidirectional streams are consumed without an echo. These demos
do not implement unidirectional echo, pooling, HTTP/2, or the complete
frozen server API contract.

## Native CI cases

The `webtransport.core` group runs the built demo endpoints over loopback,
using the existing build certificate and isolated case-runner work directory.
It requires no browser, proxy, peer implementation, or additional package.
The existing CI case-test stage discovers the group and runs it in parallel
with the other module groups. Cases within the group run sequentially.

```sh
XQC_BUILD_DIR=build bash scripts/case_test.sh --execute \
    --parallel --jobs auto --group webtransport.core
```

Both demos accept `-W -X <case-id>` for these cases; omitting `-X` retains
the normal demo behavior. Case-only malformed input and receive observations
are isolated in `case_test/webtransport/xqc_webtrans_test_cases.c` and are
not library APIs.

| Case IDs | Coverage |
|---|---|
| 1801, 1802 | Draft-07 and draft-16 handshake, 1,048,576 bytes uploaded and echoed back, exact byte comparison and FIN in both directions. |
| 1803, 1804 | CONNECT accepted; disallowed Origin rejected with 403 and no session-ready notification. |
| 1805, 1806 | Bidirectional echo and peer receipt of RESET_STREAM_AT with the complete reliable header; invalid Session ID rejected with H3_ID_ERROR. |
| 1807, 1808 | Exact unidirectional payload and FIN at the receiver; invalid Session ID rejected with H3_ID_ERROR. |
| 1809, 1810 | Datagram echo; unassociated Quarter Stream ID actually received without application delivery or buffering, followed by successful valid traffic. |
| 1811, 1812 | CLOSE code and reason received; invalid UTF-8 rejected with H3_MESSAGE_ERROR. |
| 1813, 1814 | Empty DRAIN received while data exchange continues; nonempty DRAIN rejected with H3_MESSAGE_ERROR. |
| 1815, 1816 | One session succeeds; a second CONNECT is rejected with H3_REQUEST_REJECTED while pooling is disabled. |

The paired protocol cases follow
[draft-16 §§3.2, 4–4.7, 5.1, and 6](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-16.html).
Every negative case checks the specific peer response or error; a timeout,
crash, TLS failure, or missing echo cannot satisfy it. The namespace ledger
is maintained in the [validation specification](../harness/spec/validation.md#client-to-server-case-id-namespace).

## Interoperability application

On POSIX platforms, enable the WebTransport feature profile to link the
interop application into the normal `demo_client` and `demo_server` binaries:

```sh
./scripts/validate.sh build --feature webtransport_interop
```

The profile sets `XQC_ENABLE_WEBTRANSPORT_INTEROP=ON`. With the runner's
`ROLE` and `TESTCASE` environment present, the demos select the interop
callbacks and policy before parsing their shared `-W` and `-X` options.
Without that environment they retain the echo behavior. Unsupported role/case
combinations exit 127; interop mode requires `-W` and rejects `-X`.

The interop application implements the runner's
[handshake and file transfer contract](https://github.com/quic-interop/quic-interop-runner/blob/master/webtransport.md).
It uses `xqc_wt_select_application_protocol` to select the client's first
common application protocol, writes `negotiated_protocol.txt`, and transfers
files in both directions using
unidirectional streams (UR/US), bidirectional streams (BR/BS), or datagrams
(DR/DS). Unidirectional responses use `PUSH`; bidirectional responses reuse
the request stream and carry raw file bytes. A datagram contains one complete
`GET` or `PUSH` message. The requester closes the session only after every
file is received, with FIN required for stream transfers. The application
bounds stream state and pending data, and confines file access to the
configured input and output directories. Request names share one owned
`REQUESTS` buffer; outgoing datagrams use a fixed 256-slot queue with 1200
bytes per slot, retaining the queued payload when sending is blocked.
Datagram requesters keep one GET outstanding and send the next after receiving
the complete PUSH response, avoiding bursts of small packets.
Before session readiness, it buffers at most 256 datagrams and 300 KiB of
payload so the runner's 200 requests may arrive before the CONNECT response.

The runner supplies `ROLE`, `TESTCASE`, `PROTOCOLS`, and `REQUESTS`.
For receive cases the client requests file URLs. For send cases the server
requests relative paths such as `wt/file.bin`, while the client connects to
the session URL with `TESTCASE=transfer` and serves files. The generic
`transfer` role responds on all three carriers and waits for the requester's
session close before reporting success.
`XQC_WT_WWW` and `XQC_WT_DOWNLOADS` override the default `/www` and
`/downloads` directories. The container entrypoint passes `-A` explicitly
so the interop server listens on all interfaces. Its application policy
permits an explicit `-J` trust file for remote peers while retaining
certificate and hostname verification. The echo policy retains its loopback
trust-file restriction and accepts native case IDs.

The `webtransport.core` CI group also keeps the message-framing pair:

| Case ID | Coverage |
|---|---|
| 1833, 1834 | Optional message framing exact echo; oversized peer and local message declarations rejected. |

The public interop runner is the sole owner of handshake and file-transfer
cases H, UR/US, BR/BS, and DR/DS. IDs 1817–1832 are retired from native CI
and remain reserved in the namespace ledger. Protocol-level rejection cases
remain in the native CI group; parser, ownership, backpressure, and filesystem
boundary checks remain in CUnit.

The `dev/webtransport-refactor` push workflow builds the image from that
branch's exact commit and runs the public runner with xquic as client and
server against every registered peer, including xquic itself. Its JSON and
endpoint logs are retained as CI artifacts. A successful local build or native
case run does not substitute for that external matrix.

## Draft-16 coverage boundary

The current HTTP/3 implementation is a draft-16 MVP, not a claim that every
optional API in the draft is exposed. The evidence is divided deliberately:

| Area | Local evidence | External evidence |
|---|---|---|
| SETTINGS and draft negotiation, CONNECT acceptance and rejection, application protocol selection | CUnit and native cases 1801–1804 | Runner handshake |
| Bidirectional and unidirectional streams, FIN, reliable reset, Session ID validation | CUnit and native cases 1805–1808 | Runner UR/US/BR/BS |
| Datagram association and buffering | CUnit and native cases 1809–1810 | Runner DR/DS |
| CLOSE, DRAIN, GOAWAY and one-session limit without session flow control | CUnit and native cases 1811–1816, except GOAWAY is CUnit-only | Runner session close |
| Input bounds, filesystem confinement and backpressure in the interop application | CUnit | Runner file transfers |

Session-level flow control and pooling are deliberately disabled under
[draft-16 §5.1](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-5.1).
The session exporter (§4.8), explicit WebTransport priority controls (§3.4),
HTTP/2 binding and 0-RTT CONNECT are not implemented by this MVP; neither the
native CI cases nor the public interop runner establishes their support.

For a quick local run after the feature-profile build:

```sh
XQC_BUILD_DIR=build/validation bash scripts/case_test.sh --execute \
    --group webtransport.core
```

These native cases use the existing case runner's fixtures, isolated work
directory, process lifecycle, and log assertions. They require no Docker,
browser, packet capture, or external peer. Parser, callback ownership, stream
and datagram bounds, and filesystem boundary checks run in the complete
CUnit suite.

Interop image builds must run the complete unit suite and these native cases
before copying the same tested binaries into the final image. A final-image
self test checks packaging, and external peer matrices remain the evidence
for interoperability with other implementations.
See the [container packaging instructions](../interop/webtransport/README.md)
for image builds, local runner execution, and publication.

## Application protocol negotiation

Native clients that require an application protocol can use
`xqc_wt_client_open_session_with_protocols(h3_conn, authority, path, origin,
protocols, protocol_count, &err)`. The array lists protocols in preference
order. XQUIC copies the strings and encodes `WT-Available-Protocols`, including
quoted-string escaping. Each protocol may contain up to 1024 printable ASCII
bytes; the encoded list may contain up to 4096 bytes.

With a nonzero count, a successful CONNECT must select an offered protocol
in `WT-Protocol`; missing, malformed, duplicate, or unoffered selections close
the session with `WT_ALPN_ERROR` without reporting it ready. Structured Field
parameters are ignored after validation, following
[draft-16 Section 3.3](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-16.html#section-3.3)
and [RFC 9651](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2).
The ready callback can read the decoded selection using
`xqc_wt_session_get_application_protocol(session)`; its storage is borrowed
through the final close callback. The getter returns `NULL` when no client
protocol was negotiated. The original `xqc_wt_client_open_session` API and a
zero protocol count retain optional negotiation behavior.
