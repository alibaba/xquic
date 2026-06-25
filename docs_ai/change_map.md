# AI Change Map

Source: `docs_ai/code_map.md`, `docs_ai/auto_doc_lookup.md`

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
7. Use `/validate` to run the appropriate build/test set and record the evidence produced.

## Cross-Cutting Rules

- Public API changes require updates to `docs/API.md`, `docs_ai/architecture/overview.md`, `docs_ai/behavior_specs.md`, and validation with full unit plus integration tests unless blocked.
- New source files require updates to `docs_ai/codebase_index.md`, `docs_ai/code_map.md`, `docs_ai/architecture/module_dependency.md`, and relevant behavior specs.
- New feature gates require updates to `CMakeLists.txt`, `cmake/CMakeLists.txt` if applicable, `docs_ai/build/build_guide.md`, `docs_ai/behavior_specs.md`, and the code map.
- New tests or integration cases should be reflected in `/validate` scope (see `.claude/skills/validate/SKILL.md`).
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
- `/validate` (auto-detects `api` module -> full scope).

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
Validation:
- `/validate` (auto-detects `http3`/`http3:qpack` modules -> targeted or full scope).

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
Validation:
- `/validate` (auto-detects transport sub-modules -> targeted or full scope).

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

Validation:
- `/validate` (auto-detects `cc:*` modules -> targeted scope with CC-specific integration tests).

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
- `/validate` (auto-detects `tls` module -> targeted scope with handshake/crypto integration tests).

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
Validation:
- `/validate` (auto-detects `http3`/`http3:qpack` modules).

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
Validation:
- `/validate` (auto-detects `transport:fec` module -> none scope; requires FEC-enabled build with `-DXQC_ENABLE_FEC=1`).

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
Validation:
- `/validate` (auto-detects `common` module -> unit tests only, no integration).

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
- `/validate` (auto-detects `build` module -> full scope).

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
- `tests/CLAUDE.md`
- `.claude/skills/validate/SKILL.md`

Update after editing:
- `docs_ai/codebase_index.md` for new harness files.

Validation:
- `/validate` (auto-detects `test` module; for registration changes, rebuild and run affected binary).

Decision-record trigger:
- New validation policy, skip policy, platform-specific test behavior, or harness output contract.
