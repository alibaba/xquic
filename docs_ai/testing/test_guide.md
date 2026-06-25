# Test Guide

> Test decision, mapping, execution, and diagnostics. Single source of truth for all testing concerns.
> For build commands and CMake flags, see `docs_ai/build/build_guide.md`.

---

## When to Test

| Change Type | Build Needed? | Tests Needed? |
|-------------|---------------|---------------|
| Production code / headers / build config | Yes | Unit + integration per mapping below |
| Public API or feature switch | Yes | Full unit + full integration |
| Test-only change | Yes (if binaries or registration changed) | Affected suites |
| Script-only change | Only if script depends on rebuilt binaries | Manual or script-specific check |
| Docs-only (wording, no technical claims) | No | No |
| Query / analysis | No | No |

If skipped, state why.

---

## Test Architecture

1. **Unit Tests** (`tests/run_tests`): CUnit-based, test individual modules in isolation. Fast, no network I/O.
2. **Integration Tests** (`scripts/case_test.sh`): Client-server interaction over localhost UDP. Real QUIC handshakes, data transfer, edge cases.

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

## Test Commands

All commands run from the `build/` directory.

### Unit Tests

```bash
./tests/run_tests
```

Output: `Test: xqc_<name>_test ...passed` per suite.

### Integration Tests

```bash
# Generate certificates if missing
if [ ! -f server.key ]; then
    openssl req -newkey rsa:2048 -x509 -nodes -keyout server.key -new -out server.crt -subj /CN=test.xquic.com
fi

# macOS: required to avoid kqueue issues with libevent
export EVENT_NOKQUEUE=1

sh ../scripts/case_test.sh
```

### Running a Single Case Test

```bash
export EVENT_NOKQUEUE=1  # macOS
rm -rf tp_localhost test_session xqc_token
killall test_server test_client 2>/dev/null
sleep 1

# Start server
tests/test_server -l d -e > /dev/null 2>&1 &
sleep 2

# Run specific test (replace <case_number>)
>clog && >slog
tests/test_client -s <size> -l d -E -x <case_number> >> clog 2>&1

# Check results
grep ">>>>>>>> pass" clog       # data transfer result
grep "\[error\]" clog slog      # error logs (should be empty)

killall test_server 2>/dev/null
```

Common case test flags (`-x <N>`):

| Flag | Test | Key Settings |
|------|------|-------------|
| `-x 40` | Key update | `keyupdate_pkt_threshold=30`, needs `-s 102400` |
| `-x 42` | Max packet out size | `max_pkt_out_size=1400` |
| `-x 44` | Log switch off | Verifies logging can be disabled |
| `-x 46` | Server refuse | Tests connection refusal |

### Adding a New Case Test

For step-by-step instructions on adding a new `-x <N>` integration test case (modifying `test_client.c`, `test_server.c`, and `case_test.sh`), see `tests/CLAUDE.md` section "Adding a New Integration Test".

### Quick Validation (rebuild + unit tests)

```bash
cd build && make -j && ./tests/run_tests
```

### Full Validation (rebuild + unit + integration)

```bash
cd build && make -j && ./tests/run_tests && sh ../scripts/case_test.sh
```

---

## Pass Criteria

| Test Type | Pass Condition |
|-----------|----------------|
| Build | Exit 0, no compile/link errors |
| Unit tests (`run_tests`) | Exit 0, all `Test: ... passed`, `0 tests FAILED` |
| Integration tests (`case_test.sh`) | All cases print `pass:1`, no `pass:0` lines |
| Full CI (`xquic_test.sh`) | Summary shows 0 failures for both unit and case tests |

### Case Test Pass Criteria (4 checks, ALL must pass)

1. `grep ">>>>>>>> pass" clog` shows `pass:1` (client data transfer succeeded)
2. Test-specific grep in `slog` matches (server-side behavior verified)
3. Test-specific grep in `clog` matches (client-side behavior verified)
4. `grep "[error]" clog slog` is empty (no error logs)

---

## Diagnosing Failures

**Case test logging**:
- `test_server` writes XQUIC logs to `./slog`
- `test_client` writes XQUIC logs to `./clog`; stdout also redirected to clog
- `clear_log()` in case_test.sh truncates both between tests
- For 0-RTT tests, run client twice (second reuses session ticket from `test_session`, `tp_localhost`)

**Failure diagnosis**:
- `pass:0` in client output: data transfer failed (connection issue, not feature-specific)
- Server grep fails (`slog` empty): feature didn't trigger server-side
- Client grep fails (`clog` missing pattern): feature didn't trigger client-side
- `[error]` present: code path hit an error -- read the log for error code and message

---

## Full CI Test Suite

| Script | Scope | Notes |
|--------|-------|-------|
| `sh scripts/xquic_test.sh` | Build both SSL backends + unit + case + gcov | Linux CI only. Uses `yum`. Not for local macOS. |

---

## Validation Report Template

After validation, summarize:

```text
Validation:
- Needed: yes/no, because <reason>
- Build: <command or skipped reason>
- Tests: <commands or skipped reason>
- Result: <pass/fail/blocker with evidence>
```
