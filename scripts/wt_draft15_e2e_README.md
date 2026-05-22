# WebTransport draft-15 C E2E

This document explains how to run the C WebTransport-over-HTTP/3 draft-15
end-to-end gate.

The harness is:

```bash
scripts/wt_draft15_e2e.sh
```

It builds:

- `build_wt_e2e/src/webtransport/wt_test_server`
- `build_wt_e2e/src/webtransport/wt_test_client`

`wt_test_server` is compiled from `src/webtransport/wt_demo_server.c`.
`wt_test_client` is compiled from `src/webtransport/wt_test_client.c`.

## Prerequisites

Install libevent and pkg-config.

macOS:

```bash
brew install libevent pkg-config
```

Linux:

```bash
sudo apt-get install -y libevent-dev pkg-config
```

The default TLS backend is BabaSSL:

```bash
third_party/babassl/libssl.a
third_party/babassl/libcrypto.a
```

To use BoringSSL instead:

```bash
SSL_BACKEND=boringssl scripts/wt_draft15_e2e.sh
```

## Certificates

The script expects:

```bash
certs/localhost.crt
certs/localhost.key
```

Generate local test certificates if they do not exist:

```bash
mkdir -p certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout certs/localhost.key -out certs/localhost.crt \
  -days 14 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

## Quick Run

Run a small smoke test:

```bash
WT_E2E_SCENARIOS='bidi datagram' \
WT_E2E_CLIENT_RUNS=1 \
scripts/wt_draft15_e2e.sh
```

Run the default draft-15 gate:

```bash
WT_E2E_CLIENT_RUNS=1 scripts/wt_draft15_e2e.sh
```

Run with ASan/UBSan:

```bash
WT_E2E_ASAN=1 \
WT_E2E_CLIENT_RUNS=1 \
scripts/wt_draft15_e2e.sh
```

Keep logs after a failure:

```bash
WT_E2E_KEEP_LOGS=1 scripts/wt_draft15_e2e.sh
```

Use an existing build:

```bash
WT_E2E_SKIP_BUILD=1 scripts/wt_draft15_e2e.sh
```

## Scenarios

The default scenario list covers:

- `bidi`: basic WebTransport bidirectional stream echo.
- `datagram`: WebTransport datagram echo through HTTP/3 Datagram.
- `large-datagram-reject`: reject a WT datagram larger than the configured MSS.
- `pre-session-datagram`: buffer a datagram that arrives before the CONNECT
  session is established.
- `pre-session-stream-overflow`: reject an overflowing pre-session WT stream
  and verify the connection can still establish a normal session afterwards.
- `close-gates`: reject send/open/datagram operations after session close.
- `peer-close-fin`: verify close capsule plus CONNECT FIN handling.
- `reset-prefix`: verify RESET_STREAM_AT reliable prefix behavior.
- `server-bidi`: verify server-initiated bidirectional WT streams.
- `multi-session`: verify routing for multiple WT sessions on one QUIC
  connection.
- `split-header`: verify WT stream header/session id parsing across read
  callback boundaries.
- `fc-disabled-single-session`: verify zero WT flow-control settings do not
  enable WT flow control.
- `fc-data-blocked`: verify WT session data limit blocking.
- `fc-stream-blocked`: verify WT session stream-count blocking.
- `compat-legacy`: verify browser compatibility mode with legacy server mode.
- `strict-reject-legacy`: verify strict draft-15 client rejects legacy mode
  before sending CONNECT.
- `client-reject-missing-*`: verify the client rejects a server missing required
  draft-15 SETTINGS or transport parameters.
- `strict-missing-*`: verify a strict server rejects a client missing required
  draft-15 SETTINGS or transport parameters.
- `invalid-datagram`: verify invalid WT datagram/session id handling.
- `churn`: verify repeated sequential sessions.

Run one or more selected scenarios:

```bash
WT_E2E_SCENARIOS='server-bidi multi-session split-header' \
WT_E2E_CLIENT_RUNS=1 \
scripts/wt_draft15_e2e.sh
```

## Static Gates

Before running clients, the script checks several source-level invariants:

- WT draft-15 datagrams must enter through the H3 Datagram path, not a direct
  QUIC datagram handler.
- The C e2e client must not send WT test datagrams with the raw
  `xqc_datagram_send()` API.
- WT datagram send must preserve message boundaries and must not fragment one
  WT datagram into multiple H3 datagrams.
- Strict draft-15 requirements must not treat WT flow-control SETTINGS as
  mandatory.
- `WT_DRAIN_SESSION` must not block opening new WebTransport streams.
- Prohibited per-stream flow-control capsules must be handled as session
  errors.
- Oversized `WT_MAX_STREAMS` must close with `H3_DATAGRAM_ERROR`.
- Buffered WT stream overflow must reject the stream with
  `WT_BUFFERED_STREAM_REJECTED`.

## Manual Client/Server Run

Prefer the script for normal validation. For debugging, the binaries can be run
manually after a successful build:

```bash
./build_wt_e2e/src/webtransport/wt_test_server \
  -p 18443 -c certs/localhost.crt -k certs/localhost.key \
  -l e -m draft15 -d 16777216 -b 1024 -u 1024
```

In another shell:

```bash
./build_wt_e2e/src/webtransport/wt_test_client \
  127.0.0.1 18443 --scenario bidi --mode draft15
```

A successful client run ends with:

```text
WebTransport client interop: PASS
```

## Current Limits

This is an xquic C self-test gate. It is not a substitute for browser or
third-party implementation interop.

Known non-goals for this harness:

- It does not test `WT-Available-Protocols` / `WT-Protocol`.
- It does not test TLS exporter APIs.
- It does not directly inspect every peer-observed stream close error through a
  public API; some close-code invariants are covered by static gates plus
  behavioral tests.
