# WebTransport loopback demo

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

Incoming unidirectional streams are consumed without an echo. Native and
browser checks described here do not cover unidirectional echo, pooling,
HTTP/2, or the complete frozen server API contract. They are runnable demo
checks and are not integrated into the legacy numeric case suite.
