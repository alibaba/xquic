# MoQT endpoint interop

`moqt_interop` adapts the public draft-22 endpoint APIs to the
[MoQ interop runner interface][interface]. It negotiates only `moqt-22` over
Native QUIC. Build it with `./scripts/validate.sh build --feature moqt`.

```sh
./build/validation/tests/moqt_interop --list
python3 interop/moqt/test_cli.py
RELAY_URL=moqt://localhost:4443/ TLS_DISABLE_VERIFY=1 \
    ./build/validation/tests/moqt_interop
./build/validation/tests/moqt_interop --server --port 4443 \
    --cert /path/to/test-cert.pem --key /path/to/test-key.pem
```

The client accepts `--relay`, `--test`, `--verbose`, and
`--tls-disable-verify`. Corresponding environment variables are `RELAY_URL`,
`TESTCASE`, `VERBOSE`, and `TLS_DISABLE_VERIFY`; explicit flags take priority.
Omitting the test runs every listed case. Stdout is TAP v14; diagnostics go to
stderr. Exit codes are 0 (pass), 1 (failure), and 127 (unknown/unsupported case,
reported as SKIP). URI resolution currently uses IPv4. Native QUIC is the
only transport; WebTransport is unsupported. Test certificates require the
explicit TLS verification bypass. There is no session resumption.

The client implements SETUP, namespace publication/withdrawal, subscription
errors and rendezvous timeout, publisher/subscriber ordering, namespace
discovery lifecycle, direct PUBLISH and PUBLISH/subscription,
`data-subgroup-basic`, eight `moq-test-*` scenarios, multi-publisher namespace
retention, standalone `fetch`, and `join` with draft-22 Fill. Case definitions
come from runner `2afe7b428e9ebf7277fef0d6b9701af4aefe60b0`; deterministic vectors
follow aiomoqt 0.14.1. `--list` is the implemented set. SUBSCRIBE_TRACKS-based
`namespace-discovery` and media decoding cases remain unsupported.

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

Data cases use fresh random namespaces, independent publisher and subscriber
sessions, bounded phase/delivery deadlines and paced objects. The oracle
checks complete object identities, payload fragments and bytes, delivery mode,
Subgroup, priority, properties, EOG and PUBLISH_DONE. Stream Count/FIN never
substitutes for object completeness. Unknown Stream Count is `UINT64_MAX` per
draft-22; wire values are not changed to match an older peer oracle.

The server is a direct endpoint/origin, without cross-connection routing,
fanout, caching, rendezvous, or namespace notification propagation. Each
connection independently accepts PUBLISH_NAMESPACE/PUBLISH, rejects unknown
SUBSCRIBE with DOES_NOT_EXIST, and serves bounded MoQT Test tuples.
It must not be registered as a relay. Runner cases requiring a relay use an
independent relay. Direct-origin probes are separate evidence.

The origin accepts at most 256 objects per tuple, payloads at most 1024 bytes,
and pacing at most 100 ms. Dense subgroup fixtures without markers/properties
also supply finite history through FETCH/Fill; FETCH supports both group
orders and rejects invalid ranges without ending the session. This history
is deterministic application data rather than a relay cache. It supports
the vector property IDs 2 and 5 with
fixed integer/byte values. It is an anonymous local test fixture; deployment
authorization belongs to an application.

The native Fill codec is unchanged: FILL_PARAMETERS contains a length-delimited
sequence of inner parameters. aiomoqt 0.14.1's default Join sender includes an
inner parameter count, which this codec rejects. Record that reverse-direction
encoding mismatch separately; manually adjusted wire diagnostics do not count
as unmodified-peer interoperability passes.

The runner builds current draft-22 role images from `dev/moqt-interop`:
`xquic-client:latest` starts the client, and `xquic-relay:latest` starts the
direct server. In a runner checkout:

```sh
./builds/xquic/build.sh --local /path/to/xquic
docker run --rm xquic-client:latest --list
docker run --rm -e RELAY_URL=moqt://relay:4443 -e TLS_DISABLE_VERIFY=1 \
    xquic-client:latest
docker run --rm -p 4443:4443/udp -v /path/to/test-certs:/certs:ro \
    xquic-relay:latest
```

The test certificate directory contains disposable `cert.pem` and `priv.key`.
The runner registry key is `xquic`, with draft-22 only. Its build configuration
and image workflows use the same development branch; previous draft-14/18
image definitions are retired. Use `--target client` or `--target relay` to
build one role. Server probes remain separate from relay cases.

[interface]: https://github.com/englishm/moq-interop-runner/blob/2afe7b428e9ebf7277fef0d6b9701af4aefe60b0/docs/TEST-CLIENT-INTERFACE.md
