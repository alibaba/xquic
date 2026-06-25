---
name: validate
description: Build and run the minimal test set for xquic changes. Use after code changes, before commit, or when asked to validate/test/verify. Supports individual steps (detect, build, unit, e2e) and combined sequential validation.
---

# XQUIC Validate

Two-layer validation: deterministic shell script (`scripts/xqc_validate.sh`) for repeatable operations + AI layer for dynamic scope decisions and targeted e2e test generation.

## Build Prerequisites

- **Compiler**: GCC or Clang with C11 support (C++17 for BoringSSL build)
- **CMake**: >= 3.10
- **SSL Backend**: BoringSSL (recommended for macOS) or BabaSSL/Tongsuo
- **Go**: >= 1.18 (BoringSSL build dependency)
- **Ninja**: any version (BoringSSL build dependency)
- **libevent**: >= 2.0.21 (test/demo binaries)
- **CUnit**: >= 2.1 (unit test framework)
- **OpenSSL CLI**: for generating test TLS certificates

See `docs_ai/build/build_guide.md` for full build instructions and platform-specific notes.

## Operation Modes

This skill supports **individual** and **combined** validation:

| User Intent | Action |
|-------------|--------|
| "validate", "run tests", "verify" | Full workflow (Steps 1-6) |
| "just build", "compile" | Step 3 only (`--build`) |
| "run unit tests" | Step 4 only (`--unit`) |
| "run integration tests", "run e2e" | Step 5 only (`--integration` or targeted) |
| "quick validate", "build and test" | Steps 3+4 (`--quick`) |
| "full validate" | Steps 3+4+5 (`--all`) |
| "detect scope", "what needs testing" | Step 1 only (`--detect`) |

When running individual steps, skip the detect phase and execute directly. When running the full workflow, always start with detect.

## Full Workflow

### Step 1: Detect scope (deterministic)

```bash
bash scripts/xqc_validate.sh --detect
```

Parse the output. Key fields:
- `BUILD_NEEDED`: whether to build
- `UNIT_NEEDED`: whether to run unit tests
- `INTEGRATION_SCOPE`: `none` | `targeted` | `full`
- `INTEGRATION_HINT`: keywords for targeted e2e test selection
- `AFFECTED_MODULES`: which modules changed

If `CHANGED_FILES` is empty, report "No production files changed, validation not needed" and stop.

### Step 2: Determine integration strategy (AI decision)

Based on `INTEGRATION_SCOPE` from Step 1:

| Scope | Action |
|-------|--------|
| `none` | Skip integration tests |
| `targeted` | Use `INTEGRATION_HINT` + E2E Case Catalog below to select specific tests. Generate a standalone e2e test script using the template, or run selected cases manually. |
| `full` | Run `scripts/xqc_validate.sh --integration` |

For `targeted` scope: match `INTEGRATION_HINT` keywords against the E2E Case Catalog. Select the smallest set of cases that covers the changed modules.

### Step 3: Build (deterministic)

```bash
bash scripts/xqc_validate.sh --build
```

If build fails, report error and stop. Do not run tests on a failed build.

### Step 4: Unit tests (deterministic)

```bash
bash scripts/xqc_validate.sh --unit
```

Pass criteria: exit 0, all suites passed, `0 tests FAILED`.

### Step 5: Integration tests (conditional)

**If `full`:**
```bash
bash scripts/xqc_validate.sh --integration
```

**If `targeted`:** Generate and run a standalone e2e test script using the template below, or run individual case tests manually:

```bash
cd build
export EVENT_NOKQUEUE=1  # macOS
rm -rf tp_localhost test_session xqc_token
killall test_server test_client 2>/dev/null || true
sleep 1

# Start server
tests/test_server -l d -e > /dev/null 2>&1 &
sleep 2

# Run specific case
>clog && >slog
echo -e "<test_name> ...\c"
tests/test_client -s <size> -l d -E -x <case_number> >> clog 2>&1

# Check
errlog=$(grep "\[error\]" clog slog 2>/dev/null || true)
clog_res=$(grep "<expected_clog_pattern>" clog || true)
slog_res=$(grep "<expected_slog_pattern>" slog || true)
if [ -z "$errlog" ] && [ -n "$clog_res" ] && [ -n "$slog_res" ]; then
    echo ">>>>>>>> pass:1"
else
    echo ">>>>>>>> pass:0"
fi

killall test_server 2>/dev/null || true
```

For specific case numbers and expected patterns, consult `scripts/case_test.sh` directly.

**If `none`:** Skip.

### Step 6: Report

Output a structured validation report:

```text
Validation:
- Changed files: <list>
- Affected modules: <list>
- Build: <PASS/FAIL/skipped>
- Unit tests: <PASS/FAIL/skipped, with evidence>
- Integration tests: <PASS/FAIL/skipped, scope=none/targeted/full>
- Coverage check: <ok/warnings>
- Result: <PASS/FAIL>
```

## E2E Case Catalog

Module-to-case mapping for targeted integration test selection. Use `INTEGRATION_HINT` keywords to find relevant cases.

### transport:conn
`user_close_connection`, `close_connection_with_error`, `create_connection_fail`, `server_refuse`, `server_cid_negotiate`, `server_refuse_connection`, `stateless_reset`, `stateless_reset_during_hsk`, `linger_close_transport`, `connection_level_flow_control`, `conn_rate_throttling`, `server_amplification_limit`

### transport:stream
`stream_send_pure_fin`, `reset_stream`, `reset_stream_when_receiving`, `fin_only`, `send_data_after_fin`, `stream_level_flow_control`, `stream_concurrency_flow_control`, `stream_rate_throttling`, `create_stream_fail`, `stream_read_notify_fail`, `NULL_stream_callback`, `server_inited_stream`

### transport:packet
`illegal_packet`, `duplicate_packet`, `packet_with_wrong_cid`, `max_pkt_out_size`, `client_initial_dcid_corruption`, `client_initial_scid_corruption`, `server_initial_dcid_corruption`, `server_initial_scid_corruption`, `retry_packet_send`

### transport:frame
All packet tests plus `frame_type_bit_repair_received`, `frame_type_bit_repair_sent`

### transport:send_ctl
`send_1K_data`, `send_1M_data`, `send_10M_data`, `send_4K_every_time`, `spurious_loss_detect_on`, `send_10M_data_mempool_protected`, `1_percent_loss`, `3_percent_loss`, `10_percent_loss`, `large_ack_range_with_30_percent_loss`, `sengmmsg_with_10_percent_loss`

### transport:datagram
All tests matching `*datagram*` pattern (~60 cases). Key ones:
`datagram_acked_callback`, `datagram_lost_callback`, `datagram_frame_size_negotiation`, `datagram_mss_limited_by_MTU`, `datagram_mss_limited_by_max_datagram_frame_size`, `send_0RTT_datagram_*`, `send_1RTT_datagram_*`, `send_oversized_datagram*`, `send_queue_full*`, `timer_based_dgram_probe`

### transport:multipath
All `MP*`, `MPNS*`, `Multipath*`, `freeze_*`, `probing_*`, `NAT_rebinding*` tests. Key ones:
`MPNS_send_1M_data_on_multiple_paths`, `MPNS_multipath_30_percent_loss`, `MPNS_multipath_close_initial_path`, `MPNS_multipath_close_new_path`, `freeze_path0`, `freeze_path1`, `probing_standby_path`, `NAT_rebinding_path_0`, `NAT_rebinding_path_1`, `Multipath_Compensate_and_Accelerate`

### tls
`cert_verify`, `1RTT`, `0RTT_accept`, `0RTT_reject`, `key_update`, `key_update_0RTT`, `set_cipher_suites`, `initial_salt_v1_key_derivation`, `alpn_negotiation_success`, `alpn_negotiation_failure_0x178`, `without_session_ticket`, `no_crypto_with_0RTT`, `no_crypto_without_0RTT`, `crypto_error_cert_verify`, `crypto_error_not_fixed_enum`

### http3
`GET_request`, `h3_stream_send_pure_fin`, `massive_requests_with_massive_header`, `forbidden_header_e2e`, `header_data_fin`, `header_data_header`, `header_header_data`, `header_data_immediate_fin`, `header_fin`, `header_size_constraints`, `empty_header_value`, `uppercase_header`, `linger_close_h3`, `h3_ping`, `request_closing_notify`, `set_h3_settings`, `set_h3_init_settings_cb`, `no_h3_init_settings_cb`, `low_delay_settings`

### http3 (settings API)
`h3_engine_set_settings_api_h3`, `h3_engine_set_settings_api_h3_29`, `h3_engine_set_settings_api_h3_ext`, `h3_engine_set_settings_api_h3_more`, `h3_engine_set_settings_api_h3_29_more`, `h3_engine_set_settings_api_h3_ext_more`

### http3 (h3_ext / bytestream)
`h3_ext_1RTT_send_test`, `h3_ext_0RTT_accept_send_test`, `h3_ext_0RTT_reject_send_test`, `h3_ext_bytestream_send_pure_fin`, `h3_ext_bytestream_blocked_by_*`, `h3_ext_bytestream_full_message_*`, `h3_ext_close_bytestream_during_transmission`, `h3_ext_finish_bytestream_during_transmission`, `h3_ext_is_disabled_on_the_client`, `connect_to_an_h3_ext_disabled_server`

### cc:cubic
`cubic_with_pacing`, `cubic_without_pacing`

### cc:reno
`reno_with_pacing`, `reno_without_pacing`

### cc:bbr
`BBR`, `BBR+`, `BBRv2`, `BBRv2+`

### cc:copa
`copa_with_default_parameters`, `copa_with_customized_parameters`

### misc / cross-cutting
`transport_only`, `transport_ping`, `transport_0RTT`, `version_negotiation`, `version_negotiation_abort_path`, `version_negotiation_close_errno`, `unlimited_cc`, `load_balancer_cid_generate`, `load_balancer_cid_generate_with_encryption`, `server_odcid_hash`, `test_client_long_header`, `test_server_long_header`, `qlog_*`, `ack_ecn_*`, `ack_timestamp_*`, `fec_*`, `SP_*`

## Coverage Gap Analysis

After running tests, check for coverage gaps:

1. If production code in `src/` was changed but no integration test was added/updated:
   ```
   Warning: production code changed but no integration test covers the new behavior.
   ```

2. If a new `-x <N>` case was added to `test_client.c`/`test_server.c` but `case_test.sh` has no matching block:
   ```
   Warning: new test case -x <N> but no verification block in case_test.sh.
   ```

These are advisory warnings -- they do not block validation.

## Failure Diagnosis

### Build failures
- Read the compiler error output directly
- Common causes: missing includes, type mismatches, undefined symbols
- If build config changed, may need `cmake` reconfiguration

### Unit test failures
- Output shows which suite/test failed with CUnit assertions
- Check the specific `xqc_test_<name>` function for the assertion that failed
- Logs: unit tests write to stdout

### Integration test failures
- `pass:0` in output: data transfer or feature verification failed
- Check `build/clog` (client log) and `build/slog` (server log) for `[error]` entries
- Server grep fails (slog empty): feature didn't trigger server-side
- Client grep fails (clog missing pattern): feature didn't trigger client-side
- Port conflicts: `killall test_server test_client` and retry
- macOS kqueue issues: ensure `EVENT_NOKQUEUE=1` is set

### Common case test flags
| Flag | Test | Notes |
|------|------|-------|
| `-x 40` | Key update | needs `-s 102400`, `keyupdate_pkt_threshold=30` |
| `-x 42` | Max packet out size | `max_pkt_out_size=1400` |
| `-x 44` | Log switch off | Verifies logging can be disabled |
| `-x 46` | Server refuse | Tests connection refusal |

For the full mapping of `-x <N>` to test behavior, read `scripts/case_test.sh` directly.

## Guardrails

- Never run `scripts/xquic_test.sh` (CI-only, installs packages via yum).
- Never modify code during validation. This skill is read-only + execute.
- If `build/` directory does not exist, report the blocker and suggest `docs_ai/build/build_guide.md`.
- If integration tests fail with port conflicts, suggest `killall test_server test_client` and retry.
