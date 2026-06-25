# AI Change Map

Source: `docs_ai/code_map.md`, `docs_ai/auto_doc_lookup.md`, `docs_ai/testing/test_guide.md`

This document maps a requested change to the files, docs, behavior specs, decisions, and validation evidence an agent must consider. Use it after locating the module in `docs_ai/code_map.md` and before editing.

## Maintenance Contract

Update this file when a change:

- Adds a new source path pattern, feature gate, generated file, test harness, or public workflow.
- Changes the correct validation target for a module.
- Changes which docs must be read or updated for a module.
- Reveals a recurring task pattern that should become a reusable row.

## Change Entry Template

Use this structure for new rows:

```md
### <change family>

Typical requests:
- User phrasing or examples.

Likely files:
- `path/*`

Read before editing:
- Required code/doc paths.

Update after editing:
- Required docs/specs/indexes.

Validation:
- Smallest build/test evidence.

Decision-record trigger:
- When to add an entry to `docs_ai/decision_records.md`.

Notes:
- Common risks, ordering constraints, or feature flags.
```

## Universal Change Procedure

1. Classify the task through `AGENTS.md`.
2. Read the required pipeline document.
3. Locate the relevant module in `docs_ai/code_map.md`.
4. Use this file and `docs_ai/auto_doc_lookup.md` to determine required docs and validation.
5. Inspect the real code path before making claims or edits.
6. After edits, update affected docs, behavior specs, and decision records.
7. Use `docs_ai/validation_guide.md` to record whether validation is needed and what evidence was produced.

## Cross-Cutting Rules

- Public API changes require updates to `docs/API.md`, `docs_ai/architecture/overview.md`, `docs_ai/behavior_specs.md`, and validation with full unit plus integration tests unless blocked.
- New source files require updates to `docs_ai/codebase_index.md`, `docs_ai/code_map.md`, `docs_ai/architecture/module_dependency.md`, and relevant behavior specs.
- New feature gates require updates to `CMakeLists.txt`, `cmake/CMakeLists.txt` if applicable, `docs_ai/build/build_guide.md`, `docs_ai/behavior_specs.md`, and the code map.
- New tests or integration cases require updates to `docs_ai/testing/test_guide.md`.
- Behavior-changing bug fixes require either a regression test or a specific existing test that covers the fixed path.
- Architectural tradeoffs, compatibility choices, or non-obvious constraints require a decision record.

## Change Families

### Public Transport API

Typical requests:
- Add or change engine, connection, stream, datagram, setting, callback, error, or stats APIs.

Likely files:
- `include/xquic/xquic.h`
- `include/xquic/xqc_errno.h`
- `src/transport/*`
- `tests/test_client.c`, `tests/test_server.c`, or `tests/unittest/*`

Read before editing:
- `docs_ai/code_map.md`
- `docs_ai/architecture/overview.md`
- `docs_ai/behavior_specs.md`
- `docs/API.md`
- Relevant transport source path.

Update after editing:
- `docs/API.md`
- `docs_ai/architecture/overview.md`
- `docs_ai/behavior_specs.md`
- `docs_ai/codebase_index.md` and `docs_ai/code_map.md` if files or ownership changed.

Validation:
- Full rebuild, full `./tests/run_tests`, and `sh ../scripts/case_test.sh`.

Decision-record trigger:
- Any ABI/API compatibility choice, callback contract change, default-setting change, or behavior that intentionally differs from RFC text or prior public behavior.

### Public HTTP/3 API

Typical requests:
- Change HTTP/3 connection/request APIs, headers, stats, callbacks, priority, datagram, or bytestream extension.

Likely files:
- `include/xquic/xqc_http3.h`
- `src/http3/*`
- `src/http3/qpack/*`
- `tests/unittest/xqc_h3*_test.c`, `tests/unittest/xqc_qpack_test.c`

Read before editing:
- `docs_ai/code_map.md`
- `docs_ai/architecture/overview.md`
- `docs_ai/behavior_specs.md`
- `docs/API.md`
- HTTP/3 module docs and relevant source.

Update after editing:
- `docs/API.md`
- `docs_ai/architecture/overview.md`
- `docs_ai/behavior_specs.md`
- `docs_ai/testing/test_guide.md` if test patterns change.

Validation:
- HTTP/3/QPACK unit tests plus `case_test.sh`; full validation for public API changes.

Decision-record trigger:
- Changes to header validation, SETTINGS semantics, stream type behavior, request lifecycle, or extension negotiation.

### Transport Core Behavior

Typical requests:
- Change connection state, packet parsing, frame processing, stream flow control, timers, packet output, receive record, ACK behavior, datagram, close/error handling.

Likely files:
- `src/transport/xqc_conn.c`
- `src/transport/xqc_engine.c`
- `src/transport/xqc_stream.c`
- `src/transport/xqc_packet*.c`
- `src/transport/xqc_frame*.c`
- `src/transport/xqc_send_ctl.c`
- `src/transport/xqc_recv_record.c`
- `src/transport/xqc_timer.c`

Read before editing:
- `docs_ai/code_map.md`
- `docs_ai/behavior_specs.md`
- `docs_ai/architecture/module_dependency.md`
- Relevant source and tests.

Update after editing:
- `docs_ai/behavior_specs.md` for changed invariants or protocol behavior.
- `docs_ai/architecture/module_dependency.md` if dependency or test impact changes.
- `docs_ai/testing/test_guide.md` if validation mapping changes.

Validation:
- Targeted transport unit test plus `case_test.sh` for runtime/protocol behavior.
- Full unit tests for broad connection or packet changes.

Decision-record trigger:
- State-machine changes, timer policy, loss/ACK policy, compatibility tradeoff, or any deliberate behavior under feature gates.

### Congestion Control

Typical requests:
- Tune Cubic/BBR/BBR2/NewReno/Copa/Unlimited behavior, add a CC algorithm, or change sampling.

Likely files:
- `src/congestion_control/*`
- `src/transport/xqc_send_ctl.c`
- `include/xquic/xquic.h` for CC callback/API changes.
- `CMakeLists.txt` for new gated algorithms.

Read before editing:
- `docs_ai/code_map.md`
- `docs_ai/behavior_specs.md`
- `src/congestion_control/CLAUDE.md`
- `docs_ai/build/build_guide.md` for feature gates.

Update after editing:
- `docs_ai/behavior_specs.md`
- `docs_ai/architecture/overview.md` for new algorithms.
- `docs_ai/build/build_guide.md` for new gates.
- `docs_ai/testing/test_guide.md` for new tests.

Validation:
- CC-specific unit tests when present plus `case_test.sh`.
- For BBR/Copa paths without dedicated unit tests, integration validation or documented blocker is required.

Decision-record trigger:
- Algorithm defaults, unit conversions, pacing policy, loss response, app-limited handling, or compatibility/performance tradeoffs.

### TLS and Crypto

Typical requests:
- Change handshake state, packet protection, key derivation, ALPN, session tickets, 0-RTT, or backend behavior.

Likely files:
- `src/tls/*`
- `src/tls/boringssl/*`
- `src/tls/babassl/*`
- `src/transport/xqc_conn.c`
- `CMakeLists.txt`, `cmake/*`

Read before editing:
- `docs_ai/code_map.md`
- `docs_ai/behavior_specs.md`
- `src/tls/CLAUDE.md`
- `docs_ai/build/build_guide.md`

Update after editing:
- `docs_ai/behavior_specs.md`
- `docs_ai/build/build_guide.md` for backend/build behavior.
- `docs_ai/architecture/module_dependency.md` if dependency scope changes.

Validation:
- TLS and crypto unit tests.
- Backend-specific build/test for backend-only changes.
- `case_test.sh` when handshake/runtime behavior changes.

Decision-record trigger:
- Backend portability choice, ALPN compatibility, key derivation/retry behavior, 0-RTT policy, or TLS error mapping.

### HTTP/3, QPACK, and Extensions

Typical requests:
- Change request lifecycle, headers, SETTINGS, GOAWAY, QPACK encode/decode, dtable capacity, HTTP/3 datagram, bytestream, or priority.

Likely files:
- `src/http3/*`
- `src/http3/frame/*`
- `src/http3/qpack/*`
- `include/xquic/xqc_http3.h`

Read before editing:
- `docs_ai/code_map.md`
- `docs_ai/behavior_specs.md`
- `src/http3/CLAUDE.md`
- Relevant RFC-facing logic in source.

Update after editing:
- `docs_ai/behavior_specs.md`
- `docs/API.md` for public API behavior.
- `docs_ai/testing/test_guide.md` for new test coverage.

Validation:
- HTTP/3 unit tests and QPACK-specific tests for QPACK-only changes.
- `case_test.sh` for runtime HTTP/3 behavior.

Decision-record trigger:
- Header validation rules, SETTINGS/GOAWAY compatibility, QPACK dynamic table safety, extension negotiation.

### FEC and Repair

Typical requests:
- Change FEC scheme, repair packet generation/decoding, FEC transport parameters, FEC scheduling, or FEC-related HTTP/3 request handling.

Likely files:
- `src/transport/xqc_fec.c`
- `src/transport/xqc_fec_scheme.c`
- `src/transport/fec_schemes/*`
- `src/transport/xqc_frame_parser.c`
- `src/transport/xqc_packet_out.c`
- `src/transport/xqc_transport_params.c`
- `src/http3/xqc_h3_request.c`
- `CMakeLists.txt`

Read before editing:
- `docs_ai/code_map.md`
- `docs_ai/behavior_specs.md`
- `src/transport/CLAUDE.md`
- FEC-related tests under `tests/unittest/`.

Update after editing:
- `docs_ai/behavior_specs.md`
- `docs_ai/architecture/module_dependency.md`
- `docs_ai/build/build_guide.md` if feature gates change.
- `docs_ai/testing/test_guide.md` if FEC test mapping changes.

Validation:
- Build with `-DXQC_ENABLE_FEC=1` and relevant scheme flags.
- FEC unit tests: `fec_test`, `fec_scheme_test`, `galois_test`.
- Integration validation when packet send/receive, scheduling, or HTTP/3 request behavior changes.

Decision-record trigger:
- Repair-only congestion-control behavior, wire-format compatibility, block sizing, recovery policy, or scheme default changes.

### Common Utilities

Typical requests:
- Change containers, time/random/string/logging, Huffman, VINT, buffers, hash tables, or allocators.

Likely files:
- `src/common/*`
- `src/common/utils/*`
- Dependent parser/codec modules.

Read before editing:
- `docs_ai/code_map.md`
- `docs_ai/architecture/module_dependency.md`
- Relevant tests.

Update after editing:
- `docs_ai/codebase_index.md` and `docs_ai/code_map.md` for new utilities.
- `docs_ai/behavior_specs.md` if utility semantics or invariants change.
- `docs_ai/testing/test_guide.md` for new tests.

Validation:
- Full unit tests for broad common changes.
- Targeted utility plus downstream tests for Huffman/VINT changes.

Decision-record trigger:
- Memory ownership semantics, compatibility of encoding/decoding, logging schema, or reusable data-structure invariants.

### Build, Feature Gates, and Generated Configuration

Typical requests:
- Add build option, change default backend, alter compiler flags, change generated feature headers.

Likely files:
- `CMakeLists.txt`
- `cmake/CMakeLists.txt`
- `xqc_configure.h.in`, generated `include/xquic/xqc_configure.h`
- `docs_ai/build/build_guide.md`

Read before editing:
- `docs_ai/build/build_guide.md`
- `docs_ai/code_map.md`
- Current CMake feature-gate blocks.

Update after editing:
- `docs_ai/build/build_guide.md`
- `docs_ai/behavior_specs.md` for feature semantics.
- `docs_ai/code_map.md` for new gates.
- `docs_ai/auto_doc_lookup.md` if path mapping changes.

Validation:
- Reconfigure and rebuild.
- Run tests mapped to the enabled feature.

Decision-record trigger:
- Default option changes, backend selection, platform-specific build behavior, generated-file policy.

### Tests and Validation Harness

Typical requests:
- Add unit test, integration case, CI script behavior, goal harness, log parser, or validation command.

Likely files:
- `tests/unittest/*`
- `tests/unittest/main.c`
- `tests/test_client.c`
- `tests/test_server.c`
- `scripts/case_test.sh`
- `scripts/xquic_test.sh`
- `scripts/goal.sh`

Read before editing:
- `docs_ai/validation_guide.md`
- `docs_ai/testing/test_guide.md`
- `tests/CLAUDE.md`

Update after editing:
- `docs_ai/testing/test_guide.md`
- `docs_ai/validation_guide.md` for policy changes.
- `docs_ai/codebase_index.md` for new harness files.

Validation:
- Run the affected test or script.
- For registration changes, rebuild and run the affected test binary.

Decision-record trigger:
- New validation policy, skip policy, platform-specific test behavior, or harness output contract.
