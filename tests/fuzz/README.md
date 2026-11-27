# Fuzz Targets

libFuzzer targets for the parsers that a peer reaches, built with
AddressSanitizer and UndefinedBehaviorSanitizer.

| Target | Input |
|--------|-------|
| `fuzz_conn` | A client and a server engine connected in memory: frames that one endpoint protects with its own keys and sends to the other, raw datagrams, deliveries, timers and client application calls, over HTTP/3 or the transport ALPN, with multipath, DATAGRAM, ACK_EXTENDED, RESET_STREAM_AT, FEC or a Retry. |
| `fuzz_frame_parse` | A 1-RTT payload for the frame parsers, including ACK, ACK_EXTENDED, the multipath frames, CRYPTO, NEW_CONNECTION_ID, DATAGRAM and STREAM. |
| `fuzz_packet_header` | A datagram for a new server engine, or for a client connection with a known connection ID: long and short headers, Version Negotiation, Retry with a valid integrity tag, stateless resets, coalesced packets. |
| `fuzz_transport_params` | The transport parameters of a ClientHello or EncryptedExtensions, which must encode and decode again to the same values, or the remembered parameters of a 0-RTT client. |
| `fuzz_token` | An address validation token, as is or encrypted with the server's token key. |
| `fuzz_qpack` | Encoder and decoder stream instructions and field sections on four request streams. |
| `fuzz_h3_frame` | An HTTP/3 frame stream, its SETTINGS, or a Priority field value. |
| `fuzz_quic_lb` | A QUIC-LB connection ID to encrypt; XQUIC has no QUIC-LB decoder. |
| `fuzz_wt_capsule` | The capsules of a WebTransport session, with `XQC_ENABLE_WEBTRANSPORT`. |
| `fuzz_moq_message` | A MoQ Transport stream or a catalog, with `XQC_ENABLE_MOQ`. |

Each source file describes the layout of its input. `corpus/<target>/`
holds a few seed inputs built from the unit-test vectors.

## Build

`XQC_ENABLE_FUZZ` needs clang with its libFuzzer runtime. It instruments the
library for coverage and the sanitizers of `XQC_FUZZ_SANITIZERS`
(`address,undefined` by default) and builds the targets; it changes nothing
when it is off. A Debug build keeps the list and assertion checks of
`XQC_DEBUG` and is optimized with `-O1`.

```bash
cmake -S . -B build/fuzz -DCMAKE_C_COMPILER=clang \
    -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_FUZZ=ON \
    -DXQC_ENABLE_WEBTRANSPORT=ON -DXQC_ENABLE_MOQ=ON \
    -DXQC_ENABLE_FEC=1 -DXQC_ENABLE_XOR=1 -DXQC_ENABLE_RSC=1 \
    -DSSL_TYPE=boringssl -DSSL_PATH=third_party/boringssl \
    -DSSL_INC_PATH=third_party/boringssl/include \
    "-DSSL_LIB_PATH=third_party/boringssl/build/libssl.a;third_party/boringssl/build/libcrypto.a"
cmake --build build/fuzz --parallel
```

For another fuzzing engine, such as the one of OSS-Fuzz, pass its link flags
in `XQC_FUZZ_ENGINE` and its sanitizer flags in `CFLAGS`, with an empty
`XQC_FUZZ_SANITIZERS`.

## Run

Keep the seed corpus as it is: give a new directory first, which receives
the inputs that find new coverage.

```bash
mkdir -p build/fuzz/corpus/fuzz_conn
build/fuzz/tests/fuzz/fuzz_conn build/fuzz/corpus/fuzz_conn \
    tests/fuzz/corpus/fuzz_conn -max_total_time=600 -rss_limit_mb=2048
```

A crash leaves its input in a `crash-<sha1>` file; running the target with
that file as its only argument reproduces it. The engines write no log by
default; `XQC_FUZZ_LOG_LEVEL=6` makes them format every debug line and qlog
event, as with `XQC_LOG_DEBUG`, so that the log code runs too. A target
writes its test certificate and key to a new directory of `TMPDIR`, which
it removes when it exits; a crash leaves the directory behind.

`scripts/fuzz_smoke.sh build/fuzz 60` runs every target of a build for 60
seconds from its seeds, and fails if one of them finds a crash, a leak, a
timeout or a sanitizer report. The Fuzz workflow runs it on every pull
request.
