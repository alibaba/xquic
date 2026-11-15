# MoQT parser demo

On POSIX hosts with MoQ and WebTransport enabled, `demo_server --moqt` runs a
bounded MoQT draft-22 parser/sink. It accepts native QUIC ALPN `moqt-22` and
WebTransport CONNECT `/moqt` on one UDP port. It opts into WT draft-07
compatibility for browsers while also accepting draft-16. Both require
WT-Available-Protocols/WT-Protocol to select `moqt-22`; there is no draft-02
or absent-protocol fallback.

Build through the repository entry point:

```sh
./scripts/validate.sh build --feature moqt_webtransport
cd build/validation
./demo/demo_server --moqt -p 8443
```

The process reads `server.crt` (complete PEM chain) and `server.key` from its
working directory. The default port is 8443. Its separate event loop and
callbacks leave the ordinary HTTP/3 and WebTransport echo modes unchanged.
The mode reuses the native endpoint socket helpers for its small POSIX driver.

Browser Origin defaults to `http://localhost:8080`. Set
`XQC_MOQT_ALLOWED_ORIGIN` to a comma-separated list of exact allowed Origins.
Wildcard entries are not supported. Requests without Origin remain eligible
for native clients. Invalid paths, unoffered protocols, duplicate Origin and
disallowed Origin receive HTTP 403.

Validated SETUP is accepted. PUBLISH and PUBLISH_NAMESPACE receive REQUEST_OK;
stream and datagram object payloads are logged as at most 64 hexadecimal
bytes per chunk. SUBSCRIBE, FETCH and discovery requests receive NOT_SUPPORTED.
This example has no relay forwarding or storage. It admits at most 64 live
connections and retains the protocol layer's configured memory/stream limits.

Chromium versions that require the draft-07 feature flag can use:

```text
--enable-features=EnableWebTransportDraft07
--enable-experimental-web-platform-features
```

Use a trusted certificate and a domain URL such as
`https://example.test:8443/moqt`. Draft-07 compatibility preserves its original
stream resets and best-effort reset association; it does not provide the
reliable prefix guarantees of draft-16. The default library APIs remain
draft-16-only; applications opt in through the `_compat` constructors.

For local self-signed fixtures, the same mode includes a leaf-pinned probe.
The loopback probe validates the `localhost` hostname. Convert that fixture's
leaf to `server.der` first, then select the target port:

```sh
openssl x509 -in server.crt -outform DER -out server.der
XQC_MOQT_DEMO_PORT=8443 ./demo/demo_server --moqt --probe wt07 127.0.0.1
```

`wt` and `quic` exercise draft-16 and native MoQT. Rejection probes are
`bad-path07`, `bad-protocol07` and `bad-origin07`. PASS requires readiness,
REQUEST_OK, both objects and a final zero-error WT close; rejection PASS
requires HTTP 403 without readiness. Native endpoint cases 1493/1494 exercise
these paths and the two-session compatibility fixture.
