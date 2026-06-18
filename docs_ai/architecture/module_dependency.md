# Module Dependency Reference

## Dependency Matrix

When modifying a module, all downstream dependents may be affected. Use this table to determine test and review scope.

| Module | Depends On | Depended By | Test Scope When Modified |
|--------|-----------|-------------|--------------------------|
| `src/common/` | (none -- leaf) | All other modules | Full unit tests (`run_tests`) |
| `src/common/utils/huffman/` | `src/common/` | `src/http3/qpack/` | `run_tests` (huffman + qpack tests) |
| `src/common/utils/vint/` | `src/common/` | `src/transport/`, `src/http3/` | `run_tests` (vint + transport + h3 tests) |
| `src/tls/` (core) | `src/common/` | `src/transport/` | `run_tests` (tls + crypto + conn tests) |
| `src/tls/boringssl/` | `src/tls/`, BoringSSL lib | `src/transport/` (when SSL_TYPE=boringssl) | `run_tests` (tls + crypto tests) |
| `src/tls/babassl/` | `src/tls/`, BabaSSL lib | `src/transport/` (when SSL_TYPE=babassl) | `run_tests` (tls + crypto tests) |
| `src/congestion_control/` | `src/common/` | `src/transport/xqc_send_ctl.c` | `run_tests` (cubic/reno/cc tests) + case_test.sh |
| `src/transport/` (core) | `src/common/`, `src/tls/`, `src/congestion_control/` | `src/http3/` | `run_tests` (transport tests) + case_test.sh |
| `src/transport/scheduler/` | `src/transport/` | `src/transport/xqc_multipath.c` | `run_tests` + multipath case tests |
| `src/transport/reinjection_control/` | `src/transport/` | `src/transport/xqc_reinjection.c` | `run_tests` + multipath case tests |
| `src/transport/fec_schemes/` | `src/common/` | `src/transport/xqc_fec.c` | `run_tests` (fec + galois tests) |
| `src/http3/` (core) | `src/transport/`, `src/common/` | Application layer | `run_tests` (h3 tests) + case_test.sh |
| `src/http3/qpack/` | `src/common/utils/huffman/`, `src/common/` | `src/http3/xqc_h3_stream.c` | `run_tests` (qpack + stable + dtable + encoder tests) |
| `include/xquic/` | (defines API) | All modules + application | Full `run_tests` + case_test.sh |

## File Impact Analysis Guide

When you need to determine what to test after a code change:

1. **Changed `include/xquic/*.h`** (public API) -> Full `run_tests` + `case_test.sh`. API changes affect all consumers.
2. **Changed `src/common/`** -> Full `run_tests`. Common utilities are used everywhere.
3. **Changed `src/tls/`** -> TLS + crypto + connection tests in `run_tests`.
4. **Changed `src/tls/boringssl/` or `src/tls/babassl/`** -> TLS + crypto tests. Only affects the specific SSL backend.
5. **Changed `src/congestion_control/`** -> CC-specific unit tests + `case_test.sh` (verifies end-to-end behavior).
6. **Changed `src/transport/` core** -> Transport unit tests + `case_test.sh`.
7. **Changed `src/transport/scheduler/` or `reinjection_control/`** -> Multipath-related tests.
8. **Changed `src/http3/`** -> HTTP/3 + QPACK tests + `case_test.sh`.
9. **Changed `src/http3/qpack/`** -> QPACK unit tests (stable, dtable, encoder, qpack, prefixed_str).
10. **Changed `tests/`** -> Rebuild + run affected test binary.
11. **Changed `CMakeLists.txt` or `cmake/`** -> Full rebuild + `run_tests`.
12. **Changed `demo/` or `mini/`** -> Rebuild demo/mini targets, manual verification.
