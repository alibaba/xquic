# src/transport/ -- QUIC Transport Layer

> Module-level conventions for Claude Code. For architecture overview and file list, see `docs_ai/architecture/overview.md` and `docs_ai/codebase_index.md`.

## Key Conventions

- **Naming**: All symbols use `xqc_` prefix. Structs are `xqc_<name>_s` with `xqc_<name>_t` typedef. Enums use `XQC_` uppercase prefix.
- **Include paths**: Internal headers use `"src/transport/xqc_*.h"` (project-root-relative, quoted). Public headers use `<xquic/xquic.h>` (angle brackets).
- **Logging**: Use `xqc_log(conn->log, XQC_LOG_<LEVEL>, "|key:val|key:val|", ...)` -- pipe-delimited key:value format. Levels: `FATAL`, `ERROR`, `WARN`, `STATS`, `INFO`, `DEBUG`.
- **Error returns**: Functions return `xqc_int_t`. `XQC_OK` (0) on success, negative `XQC_E*` codes on failure. Error codes defined in `include/xquic/xqc_errno.h`.
- **Time**: All timestamps are `xqc_usec_t` (microseconds, monotonic). Use `xqc_monotonic_timestamp()` from `src/common/xqc_time.h`.
- **Memory**: Use `xqc_malloc`/`xqc_free` wrappers from `src/common/xqc_malloc.h`, never raw `malloc`/`free`.

## Connection Flags

`xqc_conn_flag_t` is a `uint64_t` bitmask (not an enum) -- uses shift-based `#define` macros to ensure 64-bit safety on all compilers including MSVC. When adding a new flag:

1. Add a `_SHIFT` entry to `xqc_conn_flag_shift_t` enum (before `XQC_CONN_FLAG_SHIFT_NUM`)
2. Add a `#define` using `((xqc_conn_flag_t)1ULL << XQC_CONN_FLAG_<NAME>_SHIFT)`
3. Update `conn_flag_2_str()` in `xqc_conn.c`

## Connection State Machine

`xqc_conn_state_t` defines separate server/client handshake states converging at `ESTABED`. When adding a state, update `conn_state_2_str()`. State transitions are driven by packet/frame processing -- see `xqc_conn_process_packet()` and TLS callbacks.

## Feature Guards

Conditional features use `#ifdef XQC_ENABLE_*` guards set by CMake:
- `XQC_ENABLE_FEC` -- Forward Error Correction (fec_schemes/, xqc_fec.c)
- `XQC_ENABLE_MP_INTEROP` -- Multipath interop scheduler
- `XQC_ENABLE_EVENT_LOG` -- qlog event logging

## Subdirectories

| Directory | Plugin Interface | How to Add |
|-----------|-----------------|------------|
| `scheduler/` | `xqc_scheduler_callback_t` (function pointer struct) | Implement callbacks, register in `xqc_conn.c` |
| `reinjection_control/` | `xqc_reinj_ctl_callback_t` | Implement callbacks, register in `xqc_reinjection.c` |
| `fec_schemes/` | `xqc_fec_code_callback_t` | Implement scheme, register in `xqc_fec.c` (guarded by `XQC_ENABLE_*`) |

## Common Pitfalls

- **Packet number spaces**: Initial, Handshake, and 1-RTT are separate. Don't mix `pn_ctl` across spaces.
- **Connection close**: Use `XQC_CONN_ERR(conn, err)` macro, not direct flag manipulation. It sets the error, flags, and triggers closing.
- **Send path**: Frames are written into `xqc_packet_out_t` via frame writers. The send queue (`xqc_send_queue`) owns packet lifecycle. Don't free packets directly.
- **Timer management**: All timers go through `xqc_timer.h`. Don't use platform timers directly.

## Impact & Testing

Changes here affect HTTP/3 layer and application. Run unit tests (`run_tests`) + integration tests (`case_test.sh`). See `docs_ai/architecture/module_dependency.md` for full impact matrix.
