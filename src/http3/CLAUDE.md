# src/http3/ -- HTTP/3 Layer

> Module-level conventions for Claude Code. For architecture overview, see `docs_ai/architecture/overview.md`.

## Key Conventions

- **Naming**: All symbols use `xqc_h3_` prefix. Error macros use `XQC_H3_CONN_ERR()` (wraps transport-layer `XQC_CONN_ERR`).
- **Include paths**: Same as transport -- internal `"src/http3/xqc_h3_*.h"`, public `<xquic/xqc_http3.h>`.
- **Error codes**: HTTP/3 errors start at `-XQC_H3_EMALLOC` and go more negative. Transport errors are separate. The `XQC_H3_CONN_ERR` macro checks `ret <= -XQC_H3_EMALLOC` before setting connection error.
- **Stream types**: HTTP/3 uses both bidirectional (request) and unidirectional (control, push, QPACK encoder/decoder) streams. Stream type is determined by the first byte on unidirectional streams.

## Connection Flags

`xqc_http3_conn_flag` is a standard bit-shift enum (unlike transport's uint64_t approach). Flags track received settings, opened streams, GOAWAY state, and extension enablement.

## QPACK (qpack/)

QPACK header compression lives in `qpack/` with its own sub-structure:
- `xqc_encoder.c/.h` / `xqc_decoder.c/.h` -- encode/decode header fields
- `xqc_ins.c/.h` -- encoder/decoder instruction processing
- `xqc_rep.c/.h` -- representation types (indexed, literal, post-base)
- `stable/` -- static table (RFC 9204 Appendix A, read-only)
- `dtable/` -- dynamic table with insert/evict/lookup

**QPACK callback model**: Uses `xqc_qpack_ins_cb_t` with `get_buf_cb` and `write_ins_cb` function pointers. Instructions can be generated during both encoding and decoding operations.

**Dynamic table safety**: The dynamic table has capacity limits. `xqc_qpack_set_dtable_cap()` can fail if referred entries exist. Always check return values.

## Frame Parsing (frame/)

HTTP/3 frames (`DATA`, `HEADERS`, `SETTINGS`, `GOAWAY`, etc.) are parsed in `frame/xqc_h3_frame.c`. Frame type constants are in `frame/xqc_h3_frame_defs.h`. The first frame on a control stream MUST be SETTINGS.

## Common Pitfalls

- **SETTINGS ordering**: The first frame on a control stream must be SETTINGS. Check `XQC_H3_CONN_FLAG_SETTINGS_RECVED` before processing other frames.
- **Header pseudo-validation**: HTTP/3 pseudo-headers (`:method`, `:path`, `:scheme`, `:status`) have strict ordering and presence rules. See `xqc_h3_header.c`.
- **FEC integration**: When `XQC_ENABLE_FEC` is defined, `xqc_h3_request.c` has additional FEC-related logic for request body handling.

## Impact & Testing

Changes here affect application-layer behavior. Run `run_tests` (h3 + qpack tests) + `case_test.sh`. QPACK-only changes can target qpack-specific tests. See `docs_ai/architecture/module_dependency.md`.
