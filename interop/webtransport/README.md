# WebTransport interop image

This image runs the XQUIC `demo_client` and `demo_server` binaries, with the
interop application selected by the runner environment. Its entrypoint maps the standard
[runner environment and application contract](https://github.com/quic-interop/quic-interop-runner/blob/master/webtransport.md)
to demo arguments. It supports handshake (H) and file transfers over
unidirectional streams (UR/US), bidirectional streams (BR/BS), and datagrams
(DR/DS). Receive cases make the client request files; send cases make the
server request files from a client running `transfer`. Unsupported role/case
combinations exit 127 before simulator setup. Clients verify `/certs/ca.pem`
and the requested hostname. Native protocol behavior is described in
[the WebTransport specification](../../harness/spec/webtransport/spec.md).
Both roles enable the demos' existing transport pacing option for the
simulator's bounded network queue; the runner's case behavior is unchanged.

Build an image from the XQUIC repository root:

```sh
python3 interop/webtransport/test_endpoint.py
docker build --platform linux/amd64 -f interop/webtransport/Dockerfile \
    --build-arg XQUIC_REVISION="$(git rev-parse HEAD)" \
    -t xquic-webtransport-interop:local .
```

The builder runs the entrypoint tests, complete CUnit suite and focused native
WebTransport core/demo groups before copying the same tested binaries into the image.
It selects the `webtransport_interop` validation profile, which links the
interop application into the normal demo binaries.

Run all seven cases from a
[runner checkout](https://github.com/quic-interop/quic-interop-runner)
with XQUIC registered:

```sh
python3 run.py -p webtransport -s xquic -c xquic \
    -r xquic=xquic-webtransport-interop:local
```

The [publication workflow](../../.github/workflows/webtransport-interop-docker.yml)
builds the checked-out `alibaba/xquic` commit only on `main` and publishes
`ghcr.io/alibaba/xquic/xquic-webtransport-interop` with `sha-<xquic-commit>`
and `latest` tags. Only the official repository publishes this image, using
`interop/webtransport/Dockerfile`; the existing QUIC image remains at
`ghcr.io/alibaba/xquic/xquic-interop` with `interop/Dockerfile`.
The image revision label identifies the XQUIC commit; use the published
digest to reproduce an image.
Run the cross-implementation matrix locally when changing the interop demo
or image. Retain the runner matrices and endpoint logs as validation evidence,
and inspect them for `WT INTEROP FAIL` even when the runner marks a case
successful because the peer exited first. Repository CI exercises XQUIC's
native functional cases; it does not run this external matrix.

## Interoperability application

On POSIX platforms, enable the WebTransport feature profile to link the
interop application into the normal `demo_client` and `demo_server` binaries:

```sh
./scripts/validate.sh build --feature webtransport_interop
```

The profile sets `XQC_ENABLE_WEBTRANSPORT=ON` and
`XQC_ENABLE_WEBTRANSPORT_INTEROP=ON`. With the runner's
`ROLE` and `TESTCASE` environment present, the demos select the interop
callbacks and policy before parsing their `-W` option.
Without that environment they retain the echo behavior. Unsupported role/case
combinations exit 127; interop mode requires `-W` and rejects `-H`.

The interop application implements the runner's
[handshake and file transfer contract](https://github.com/quic-interop/quic-interop-runner/blob/master/webtransport.md).
It uses `xqc_wt_select_application_protocol` to select the client's first
common application protocol, writes `negotiated_protocol.txt`, and transfers
files in both directions using
unidirectional streams (UR/US), bidirectional streams (BR/BS), or datagrams
(DR/DS). Unidirectional responses use `PUSH`; bidirectional responses reuse
the request stream and carry raw file bytes. A datagram contains one complete
`GET` or `PUSH` message. For handshake-only cases, the server closes the
accepted session after writing its negotiated-protocol file so a peer waiting
for session completion can exit. The requester closes transfer sessions only
after every file is received, with FIN required for stream transfers. The
application bounds stream state and pending data, and confines file access to
the configured input and output directories. Request names share one owned
`REQUESTS` buffer; outgoing datagrams use a fixed 256-slot queue with 1200
bytes per slot, retaining the queued payload when sending is blocked.
The responder drains at most one queued datagram per 2 ms through a separate
demo application timer. It runs the engine after each send to flush output,
without replacing the engine's own wakeup deadline. This limits bursts in
the runner's bounded network queue without changing the transport's
unreliable-delivery semantics.
The client acting as a responder finishes on a normal peer close only after
it sent a response and drained all pending streams and datagrams. The runner
verifies file counts and contents; peer application close codes are not a
file-transfer success signal.
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
`/downloads` directories. The interop server uses the demo
server's default binding on all interfaces. Its application policy
permits an explicit `-J` trust file for remote peers while retaining
certificate and hostname verification.
