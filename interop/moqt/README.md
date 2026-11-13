# MoQT interop

`moqt_interop` adapts the public draft-22 endpoint APIs to the
[MoQ interop runner interface][interface]. It negotiates only `moqt-22` over
Native QUIC or WebTransport draft-16. Build both with
`./scripts/validate.sh build --feature moqt_webtransport`.

```sh
./build/validation/tests/moqt_interop --list
python3 interop/moqt/test_cli.py
python3 interop/moqt/test_endpoint.py
RELAY_URL=moqt://localhost:4443/ TLS_DISABLE_VERIFY=1 \
    ./build/validation/tests/moqt_interop
./build/validation/tests/moqt_interop --server --port 4443 \
    --cert /path/to/test-cert.pem --key /path/to/test-key.pem
RELAY_URL=https://localhost:4443/moq TLS_DISABLE_VERIFY=1 \
    ./build/validation/tests/moqt_interop --test setup-only
./build/validation/tests/moqt_interop --server --transport webtransport \
    --port 4443 --cert /path/to/test-cert.pem --key /path/to/test-key.pem
./build/validation/tests/moqt_interop --relay-server --transport dual \
    --port 4443 --cert /path/to/test-cert.pem --key /path/to/test-key.pem
```

The client accepts `--relay`, `--test`, `--transport`, `--verbose`, and
`--tls-disable-verify`. Corresponding environment variables are `RELAY_URL`,
`TESTCASE`, `MOQT_TRANSPORT`, `VERBOSE`, and `TLS_DISABLE_VERIFY`; explicit
flags take priority. HTTPS selects WT. A canonical `moqt://` URI uses QUIC by
default or WT with `--transport webtransport`. Server mode uses the same
transport option/environment, defaulting to QUIC. The two transports reuse
the same scenario drivers and complete payload oracles. Server-only `dual`
registers Native QUIC and WT ALPNs on one UDP listener. Each accepted peer
selects its endpoint constructor from its actual transport.
Omitting the test runs every listed case. Stdout is TAP v14; diagnostics go to
stderr. Exit codes are 0 (pass), 1 (failure), and 127 (unknown/unsupported case,
reported as SKIP). URI resolution currently uses IPv4. A build without WT
reports its unavailable transport as SKIP. Test certificates require the
explicit TLS verification bypass. There is no session resumption.

The WT path selects `moqt-22` in CONNECT, then starts the existing MoQT
session through its WT constructor. CONNECT carries authority/path/query;
the WT SETUP omits those options. Both SETUPs still govern readiness.
MoQT is destroyed in the WT close callback before H3 destruction. The test
server authorizes an anonymous CONNECT with the offered protocol, with one
WT session per scenario peer. TAP records `webtransport` only after MoQT
readiness, independently of successful HTTP/3/CONNECT establishment.

The client implements SETUP, namespace publication/withdrawal, subscription
errors and rendezvous timeout, publisher/subscriber ordering, namespace
discovery lifecycle, direct PUBLISH and PUBLISH/subscription,
`data-subgroup-basic`, eight `moq-test-*` scenarios, multi-publisher namespace
retention, standalone `fetch`, and `join` with draft-22 Fill. Case definitions
come from runner `2afe7b428e9ebf7277fef0d6b9701af4aefe60b0`; deterministic vectors
follow aiomoqt 0.14.1. `--list` exposes 26 implemented cases: C01–C22,
FETCH/Join and two media rejection/recovery extensions, including
SUBSCRIBE_TRACKS-based `namespace-discovery`. It publishes a namespace and
Track, discovers the namespace, then verifies the complete Track name offered
on an independent PUBLISH.

`publish-subscribe-media` adds a bounded C22 VP8 profile. Independent
publisher/subscriber Sessions first exchange an MSF-01 independent catalog
on `catalog` (Group 0, Subgroup 0, Object 0). The subscriber decodes it using
`xqc_msf_catalog_decode`, selects its inherited-namespace `video` Track,
then subscribes to that name. Each of three 16×16 VP8 keyframes is its own
GOP/Group, with Object 0 on a new Subgroup 0 stream (MSF-01 §§4.1, 5, 6).
LOC-05 §2.3 public properties carry `vp8`, Timescale 1000 and timestamps
0/40/80; payloads are clear elementary samples without legacy prefixes.
The oracle assembles fragments, validates identities/properties and exact
fixture bytes, and requires PUBLISH_DONE plus every stream FIN.

After reception, an independent FFmpeg process decodes the received samples
as IVF into grayscale pixels. The client renders all three decoded frames
as terminal luma art on stderr. Success requires three complete frames,
normal decoder exit within five seconds, and normal transport completion.
Decoder absence, zero/partial output, failure or timeout fails the case.
Install FFmpeg for native media runs; `XQC_INTEROP_FFMPEG` optionally selects
its executable. The runner's client image includes FFmpeg. Old cases and
the relay require no decoder. This is a headless terminal renderer, not
moqy/WebCodecs player interoperability or complete MSF workflow coverage.

The encoded frame in `media.c` was generated independently with FFmpeg
8.1.1/libvpx using `-f lavfi -i color=c=red:s=16x16:r=25 -frames:v 3
-c:v libvpx -g 1 -threads 1 -deadline best -f ivf`. The resulting IVF SHA256
is `050ec4966ac00baed45ec7e266ae6e2fb2a6f1d10e18bbd3cf7d7db11c15ac92`.
The fixture repeats one keyframe with distinct Group identities/timestamps;
it is synthesized test content and contains no third-party media.

`media-catalog-error` rejects an unsupported MSF version before selecting
media. `media-loc-error` rejects a zero Timescale whose MoQT KVP framing is
valid. Both then deliver the valid catalog/media and decode/render on the
same two Sessions, proving application rejection does not poison transport
state. Recovery uses a fresh namespace so completed Tracks remain ended.
These are named interop extensions, not numeric native case selectors.
Audio, encryption/private properties, ABR, delta catalogs, Joining FETCH of
live snapshots and general-purpose player integration remain separate work.

The retention case uses two publishers, a synchronization namespace and three
observers. It checks complete names, rejects premature withdrawal and requires
both late observers to see the namespace until its last publisher withdraws.
Its overall deadline is eight seconds.

The history cases publish six groups of five deterministic objects, pause
after group 2's first object reaches the live observer, then open an independent
fetcher/joiner. FETCH verifies all five objects of historical group 1. JOIN
uses SUBSCRIBE with FILL_PARAMETERS: six historical objects and nineteen
subsequent live objects have independent oracles and completion conditions.
Both cases require the original live observer to receive all thirty objects;
an OK response or a partial history stream is insufficient.
The bounded history publisher retains two independent upstream subscriptions
for the live observer and joiner. A new Join does not restart the source or
replace the original delivery; each demand has its own stream and completion
count. Historical data remains available while both live deliveries progress.

Data cases use fresh random namespaces, independent publisher and subscriber
sessions, bounded phase/delivery deadlines and paced objects. The oracle
checks complete object identities, payload fragments and bytes, delivery mode,
Subgroup, priority, properties, EOG and PUBLISH_DONE. Stream Count/FIN never
substitutes for object completeness. Unknown Stream Count is `UINT64_MAX` per
draft-22; wire values are not changed to match an older peer oracle.
The controlled publisher uses property IDs 2 and 5 with known values so relay
checks compare their bytes. Direct-origin checks validate those IDs and the
complete property encoding while allowing random values, as specified by
[MoQT Test -00 §§2.14–2.15](https://datatracker.ietf.org/doc/html/draft-afrind-moq-test-00#section-2.14).

`--server` selects a direct endpoint/origin. Each
connection independently accepts PUBLISH_NAMESPACE/PUBLISH, rejects unknown
SUBSCRIBE with DOES_NOT_EXIST, and serves bounded MoQT Test tuples.
Direct-origin probes use client `--origin`, whose `--list` contains five
control cases and eight deterministic data vectors. These 13 probes reuse
the full object oracle and require PUBLISH_DONE and all declared stream FINs.
They are recorded separately from relay scenarios.

`--relay-server` selects the existing bounded relay core. Its peers use public
Native QUIC or WT relay constructors, explicit anonymous test policies, and
one copied test Scope. The application processes relay work outside callbacks
after engine events, destroys peers at transport close, and reclaims closed
connection wrappers outside callbacks. Routing, namespace retention,
SUBSCRIBE_TRACKS, fanout, and FETCH/Fill forwarding belong to the shared core;
the adapter adds no alternate protocol engine or history cache. The anonymous
Scope is intended for controlled local interoperability testing.

The origin accepts at most 256 objects per tuple, payloads at most 1024 bytes,
and pacing at most 100 ms. Dense subgroup fixtures without markers/properties
also supply finite history through FETCH/Fill; FETCH supports both group
orders and rejects invalid ranges without ending the session. This history
is deterministic application data rather than a relay cache. It supports
the vector property IDs 2 and 5 with
fixed integer/byte values. It is an anonymous local test fixture; deployment
authorization belongs to an application.

The Fill codec is shared by both transports: FILL_PARAMETERS contains a
length-delimited sequence of inner parameters. aiomoqt 0.14.1's default Join sender includes an
inner parameter count, which this codec rejects. Record that reverse-direction
encoding mismatch separately; manually adjusted wire diagnostics do not count
as unmodified-peer interoperability passes.

The runner builds current draft-22 role images from `dev/moqt-interop`:
`xquic-client:latest` starts the client, and `xquic-relay:latest` starts the
relay with both transports. Append `--server` for direct-origin mode. In a
runner checkout:

```sh
./builds/xquic/build.sh --local /path/to/xquic
docker run --rm xquic-client:latest --list
docker run --rm -e RELAY_URL=moqt://relay:4443 -e TLS_DISABLE_VERIFY=1 \
    xquic-client:latest
docker run --rm -e RELAY_URL=https://relay:4443 -e TLS_DISABLE_VERIFY=1 \
    xquic-client:latest
docker run --rm -p 4443:4443/udp -v /path/to/test-certs:/certs:ro \
    xquic-relay:latest
docker run --rm -e MOQT_TRANSPORT=webtransport -p 4443:4443/udp \
    -v /path/to/test-certs:/certs:ro xquic-relay:latest
```

The test certificate directory contains disposable `cert.pem` and `priv.key`.
The runner registry key is `xquic`, with draft-22 only. Its build configuration
and image workflows use the same development branch; previous draft-14/18
image definitions are retired. Use `--target client` or `--target relay` to
build one role. Direct-origin probes remain separate from relay cases.

[interface]: https://github.com/englishm/moq-interop-runner/blob/2afe7b428e9ebf7277fef0d6b9701af4aefe60b0/docs/TEST-CLIENT-INTERFACE.md
