# src/congestion_control/ -- Pluggable Congestion Control

> Module-level conventions for Claude Code. For architecture overview, see `docs_ai/architecture/overview.md`.

## Plugin Interface

All CC algorithms implement `xqc_cong_ctrl_callback_t` (function pointer struct defined in `include/xquic/xquic.h`). Key callbacks:

- `xqc_cong_ctl_init` / `xqc_cong_ctl_reinit` -- create/reset state
- `xqc_cong_ctl_on_ack` / `xqc_cong_ctl_on_lost` -- congestion events
- `xqc_cong_ctl_get_cwnd` / `xqc_cong_ctl_get_pacing_rate` -- query state

Each algorithm exports a `const xqc_cong_ctrl_callback_t xqc_<algo>_cb` global (e.g., `xqc_cubic_cb`, `xqc_bbr_cb`).

## Algorithm Inventory

| Algorithm | File | Feature Guard | Always Compiled? |
|-----------|------|--------------|-----------------|
| Cubic | `xqc_cubic.c/.h` | (none) | Yes (default) |
| BBRv1 | `xqc_bbr.c/.h` | (none) | Yes |
| BBRv2 | `xqc_bbr2.c/.h` | `XQC_ENABLE_BBR2` | No |
| NewReno | `xqc_new_reno.c/.h` | `XQC_ENABLE_RENO` | No |
| Copa | `xqc_copa.c/.h` | `XQC_ENABLE_COPA` | No |
| Unlimited | `xqc_unlimited_cc.c/.h` | `XQC_ENABLE_UNLIMITED` | No |

## Shared Infrastructure

- **`xqc_sample.c/.h`**: RTT/bandwidth sampling shared by all algorithms. Called from `xqc_send_ctl.c` on ACK processing. The `xqc_sample_t` struct carries delivered bytes, RTT, inflight, and loss data between sample points.
- **`xqc_window_filter.c/.h`**: Min/max windowed filter, used by BBR variants for bandwidth and RTT tracking.
- **`xqc_bbr_common.h`**: Shared constants for BBR/BBRv2.

## Adding a New Algorithm

1. Create `xqc_<name>.c/.h` with a `xqc_cong_ctrl_callback_t` implementation
2. Add `XQC_ENABLE_<NAME>` CMake option in root `CMakeLists.txt`
3. Guard compilation with `#ifdef XQC_ENABLE_<NAME>` in `CMakeLists.txt`
4. Export `const xqc_cong_ctrl_callback_t xqc_<name>_cb`
5. Update `docs_ai/architecture/overview.md` (CC section) and `docs_ai/build/build_guide.md` (feature flags)

## Common Pitfalls

- **Units**: `cwnd` is in **bytes**, not packets. `init_cwnd` in `xqc_cubic_t` is in MSS count but gets converted. Check units carefully.
- **Microseconds**: All time values are `xqc_usec_t` (microseconds). RTT, epoch timestamps, pacing intervals -- all microseconds.
- **Sample validity**: `xqc_generate_sample()` returns `xqc_sample_type_t` -- check for `XQC_RATE_SAMPLE_ACK_NOTHING` and `XQC_RATE_SAMPLE_INTERVAL_TOO_SAMLL` (note: typo in codebase, `SAMLL` not `SMALL`) before using sample data.
- **Integration point**: CC is called from `xqc_send_ctl.c` in the transport layer. Don't call CC functions directly from other modules.

## Impact & Testing

CC changes affect throughput and latency behavior. Run CC-specific unit tests + `case_test.sh` for end-to-end validation. See `docs_ai/architecture/module_dependency.md`.
