# Test Guide

> Test architecture, commands, pass criteria, and diagnostics.
> For automated change detection and test scope mapping, use `/validate`.
> For build commands and CMake flags, see `docs_ai/build/build_guide.md`.

---

## When to Test

| Change Type | Build Needed? | Tests Needed? |
|-------------|---------------|---------------|
| Production code / headers / build config | Yes | Unit + integration per `/validate --detect` |
| Public API or feature switch | Yes | Full unit + full integration |
| Test-only change | Yes (if binaries or registration changed) | Affected suites |
| Script-only change | Only if script depends on rebuilt binaries | Manual or script-specific check |
| Docs-only (wording, no technical claim change) | No | No |
| Query / analysis | No | No |

If skipped, state why.

---

## Test Architecture

1. **Unit Tests** (`tests/run_tests`): CUnit-based, test individual modules in isolation. Fast, no network I/O.
2. **Integration Tests** (`scripts/case_test.sh`): Client-server interaction over localhost UDP. Real QUIC handshakes, data transfer, edge cases.

Both require building with `-DXQC_ENABLE_TESTING=1`.

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

### Quick Validation (rebuild + unit tests)

```bash
bash scripts/xqc_validate.sh --quick
```

### Full Validation (rebuild + unit + integration)

```bash
bash scripts/xqc_validate.sh --all
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
