# Test Guide

> Test mapping and command reference. Agents should use `docs_ai/validation_guide.md` to decide whether tests are needed and which smallest test set to run.

---

## Test Architecture

XQUIC has two categories of tests:

1. **Unit Tests** (`tests/run_tests`): CUnit-based, test individual modules in isolation. Fast, no network I/O.
2. **Integration Tests** (`scripts/case_test.sh`): Client-server interaction tests using `test_client` and `test_server` binaries over localhost UDP. Tests real QUIC handshakes, data transfer, and edge cases.

Both require building with `-DXQC_ENABLE_TESTING=1`.

---

## Feature-to-Test Mapping

Use this table to find the **smallest test set** that proves your change works.

| Modified Area | Unit Test (run_tests) | Integration Test (case_test.sh) | Notes |
|---|---|---|---|
| `src/common/` | All unit tests | Not needed | Common utilities affect everything |
| `src/common/utils/huffman/` | huffman_test | Not needed | |
| `src/common/utils/vint/` | vint_test | Not needed | |
| `src/common/utils/ringarray/` | ring_array_test | Not needed | |
| `src/common/utils/ringmem/` | ring_mem_test | Not needed | |
| `src/common/utils/2d_hash/` | 2d_hash_table_test | Not needed | |
| `src/transport/xqc_conn.c` | conn_test | Full case_test.sh | Connection is core path |
| `src/transport/xqc_engine.c` | engine_test | Full case_test.sh | Engine is core path |
| `src/transport/xqc_stream.c` | stream_frame_test | case_test.sh | |
| `src/transport/xqc_packet*.c` | packet_test | case_test.sh | |
| `src/transport/xqc_frame*.c` | process_frame_test, frame_type_bit_test | case_test.sh | |
| `src/transport/xqc_send_ctl.c` | send_ctl_test | case_test.sh | |
| `src/transport/xqc_recv_record.c` | recv_record_test | Not needed | |
| `src/transport/xqc_cid.c` | cid_test | Not needed | |
| `src/transport/xqc_transport_params.c` | tp_test | Not needed | |
| `src/transport/xqc_datagram.c` | datagram_test | case_test.sh (datagram cases) | |
| `src/transport/xqc_multipath.c` | N/A | case_test.sh (multipath cases) | |
| `src/transport/scheduler/` | N/A | case_test.sh (multipath cases) | |
| `src/transport/fec_schemes/` | fec_test, fec_scheme_test, galois_test | Not needed | Requires `-DXQC_ENABLE_FEC=1` |
| `src/congestion_control/xqc_cubic.c` | cubic_test | case_test.sh | |
| `src/congestion_control/xqc_new_reno.c` | reno_test | case_test.sh | Requires `-DXQC_ENABLE_RENO=1` |
| `src/congestion_control/xqc_bbr*.c` | N/A (no dedicated unit test) | case_test.sh | |
| `src/tls/` | tls_test, crypto_test | case_test.sh | |
| `src/tls/boringssl/` | tls_test, crypto_test | case_test.sh | Only when SSL_TYPE=boringssl |
| `src/tls/babassl/` | tls_test, crypto_test | case_test.sh | Only when SSL_TYPE=babassl |
| `src/http3/` | h3_test, h3_ext_test | case_test.sh | |
| `src/http3/qpack/` | qpack_test, encoder_test, prefixed_str_test | Not needed | |
| `src/http3/qpack/stable/` | stable_test | Not needed | |
| `src/http3/qpack/dtable/` | dtable_test | Not needed | |
| `include/xquic/*.h` | Full run_tests | Full case_test.sh | API changes affect everything |
| `CMakeLists.txt` | Full rebuild + run_tests | Full case_test.sh | |

---

## Test Binaries / Commands

### Unit Tests

| Binary / Command | Location | Scope | Pass Criteria |
|------------------|----------|-------|---------------|
| `./tests/run_tests` | `build/tests/run_tests` | All CUnit test suites | Exit 0, `0 tests FAILED` in output |

Run from the `build/` directory:

```bash
cd build
./tests/run_tests
```

Output format:
```
Test: xqc_random_test ...passed
Test: xqc_pq_test ...passed
...
```

### Integration Tests

| Script / Command | Scope | Prerequisites |
|------------------|-------|---------------|
| `sh scripts/case_test.sh` | Full client-server interaction tests | Build with `XQC_ENABLE_TESTING=1`, SSL certificates generated |

Run from the project root:

```bash
cd build

# Generate test certificates (if not already present)
openssl req -newkey rsa:2048 -x509 -nodes -keyout server.key -new -out server.crt -subj /CN=test.xquic.com

# Run integration tests
sh ../scripts/case_test.sh
```

**macOS note**: If kqueue causes issues, set `export EVENT_NOKQUEUE=1` before running.

The script:
1. Starts `test_server` in background
2. Runs `test_client` with various flags to exercise different code paths
3. Checks `clog`/`slog` for errors
4. Reports pass/fail per case

### Full CI Test Suite

| Script / Command | Scope | Notes |
|------------------|-------|-------|
| `sh scripts/xquic_test.sh` | Build both SSL backends + unit tests + case tests + gcov | Designed for Linux CI. Uses `yum` for dependency installation. Not recommended for local macOS use. |

---

## Test Certificate Generation

Integration tests require a self-signed TLS certificate. Generate from the `build/` directory:

```bash
cd build
openssl req -newkey rsa:2048 -x509 -nodes -keyout server.key -new -out server.crt -subj /CN=test.xquic.com
```

This creates `server.key` and `server.crt` in the build directory, which `test_server` reads at startup.

---

## Success Criteria

| Test Type | Pass Condition |
|-----------|----------------|
| Unit tests (`run_tests`) | Exit 0, all `Test: ... passed`, `0 tests FAILED` |
| Integration tests (`case_test.sh`) | All cases print `pass:1`, no `pass:0` lines |
| Full CI (`xquic_test.sh`) | Summary shows 0 failures for both unit and case tests |

---

## Local macOS Quick Validation

For a fast validation cycle after code changes:

```bash
# From build/ directory (assumes already configured)
make -j && ./tests/run_tests
```

For full validation including integration:

```bash
make -j && ./tests/run_tests && sh ../scripts/case_test.sh
```
