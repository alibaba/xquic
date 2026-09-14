# WebTransport loopback demo

`demo_server -W` enables the draft-07 HTTP/3 compatibility mode at `/wt`,
alongside ordinary HTTP/3. It binds IPv4 and IPv6 loopback and echoes
bidirectional stream payloads and datagrams. Incoming unidirectional
streams are consumed. This mode does not implement draft-16.

After building the demo, run from the repository root (substitute your
`XQC_BUILD_DIR` for `build` when using a separate build directory):

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

Serve the page in a second terminal:

```sh
python3 -m http.server 8080 --bind 127.0.0.1 --directory demo
```

Open [the test page](http://127.0.0.1:8080/webtransport.html) in Chrome, paste
the fingerprint, and click **Run allowed-Origin checks**. The page passes
the hash through `serverCertificateHashes` and records the browser version,
connection, stream echo with FIN, datagram echo, invalid-path rejection,
and close results in the page.

To exercise Origin rejection, run another page server:

```sh
python3 -m http.server 8081 --bind 127.0.0.1 --directory demo
```

Open [the disallowed-Origin page](http://127.0.0.1:8081/webtransport.html),
paste the same fingerprint, and click **Reject this Origin**. Confirm the
server prints `WT reject` with `allowed_origin=0`; a browser connection
failure alone cannot distinguish policy rejection from a network failure.

The application accepts exactly `/wt` and one Origin header equal to
`http://127.0.0.1:8080` or `http://localhost:8080`. Its stream callback state
is keyed by session and QUIC stream ID, retained across short writes, and
freed at stream or session close. The pending echo buffer is bounded to
64 KiB per bidirectional stream; overflow resets that stream. Datagram
send failures are reported and are not retried. Callback sends schedule a
1 ms engine event, preserving the shared HTTP/3 and engine user data.

Remaining work after this milestone:

- Chrome interoperability is pending a working browser extension connection.
- Full draft-16 negotiation, session flow control and HTTP/2 binding.
- Peer STOP_SENDING notification and independent RESET/STOP semantics in the
  transport layer; the current closing callback reports RESET_STREAM only.
- Datagram late-ACK-after-loss bookkeeping and broader stream error coverage.
- Browser unidirectional echo and server-initiated stream interoperability.

The API names are present for this foundation; this milestone does not claim
complete implementation of the frozen server API contract.
