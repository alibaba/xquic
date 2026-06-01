# Features

## Supported TLS 1.3 Cipher Suites

XQUIC supports the following TLS 1.3 cipher suites for QUIC packet protection, as specified in [RFC 9001 Section 5](https://www.rfc-editor.org/rfc/rfc9001#section-5):

| Cipher Suite | AEAD | Header Protection | Status |
|---|---|---|---|
| TLS_AES_128_GCM_SHA256 | AEAD_AES_128_GCM | AES-ECB (128-bit) | Supported |
| TLS_AES_256_GCM_SHA384 | AEAD_AES_256_GCM | AES-ECB (256-bit) | Supported |
| TLS_CHACHA20_POLY1305_SHA256 | AEAD_CHACHA20_POLY1305 | ChaCha20 | Supported |
| TLS_AES_128_CCM_SHA256 | AEAD_AES_128_CCM | — | Not Supported |
| TLS_AES_128_CCM_8_SHA256 | — | — | Not Supported |

The default cipher list is defined by the `XQC_TLS_CIPHERS` macro in `include/xquic/xquic.h`:

```
TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
```

### Why CCM is not supported

CCM-based cipher suites (`TLS_AES_128_CCM_SHA256` and `TLS_AES_128_CCM_8_SHA256`) are not supported for the following reasons:

1. **Optional per RFC 9001**: CCM support is not mandatory for QUIC implementations.
2. **Low security limits**: AEAD_AES_128_CCM has significantly lower confidentiality and integrity limits (2^21.5 ≈ 2,992,530 packets) compared to GCM (confidentiality: 2^23, integrity: 2^52) and ChaCha20-Poly1305 (confidentiality: 2^62, integrity: 2^36). This requires more frequent key updates.
3. **No header protection for CCM_8**: RFC 9001 does not define a header protection scheme for `TLS_AES_128_CCM_8_SHA256`, making it unsuitable for QUIC.

## qlog
Based on qlog ([draft-ietf-quic-qlog-main-schema](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/), [draft-ietf-quic-qlog-quic-events](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-quic-events/) and [draft-ietf-quic-qlog-h3-events](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-h3-events/))，xquic implements quic event logging.

### Activate qlog by DXQC_ENABLE_EVENT_LOG
```shell
cd build
rm -rf * 
# add "-DXQC_ENABLE_EVENT_LOG=1"
cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_ENABLE_RENO=1 -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} ..

make -j
```
### Example
Qlog defines three event importance levels, in decreasing order of importance and expected usage: core, base, extra. The level can be set by "--qlog_importance" argument：
```shell
./tests/test_server -l e -e --qlog_importance extra

./tests/test_client -s 10240 -l e -t 1 -E --qlog_importance extra
```

To disable qlog, using "--qlog_disable":
```shell
./tests/test_server -l e -e --qlog_disable

./tests/test_client -s 10240 -l e -t 1 -E --qlog_disable
```

### JSON format serialization
```shell
python ../scripts/qlog_parser.py --clog clog --slog slog --qlog_path demo_qlog.json
```


