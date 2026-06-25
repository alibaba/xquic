# XQUIC

XQUIC is a QUIC and HTTP/3 protocol library implemented in C, developed by Alibaba. It provides a high-performance, cross-platform implementation of the IETF QUIC transport protocol and the HTTP/3 application protocol.

## Temporary Test-Stage Response Checklist

During the current project testing stage, every answer to the user MUST include a concise status block that answers the questions below. If any item is unclear, unknown, or cannot be determined from the currently inspected files, say so directly and name what must be read, run, or confirmed next.

Required status block:

```text
Test-stage status:
- Task type: <which task category this is, or unclear>
- Required reading: <files/docs that must be read before acting, or unclear>
- Editable scope: <files/areas that may be changed, or unclear>
- Docs to sync: <docs that must be updated after changes, or none/unclear>
- Minimal validation: <smallest build/test/check command, or unclear>
- Failure diagnosis: <where to inspect logs/errors if tests fail, or unclear>
- Stop/confirm conditions: <operations that require stopping or user confirmation>
- Final evidence: <what proof must be reported at completion>
```

For test/build work, use `/validate` for automated validation. For diagnostics details, see `docs_ai/testing/test_guide.md`. For code or bug-fix work, also consult `AGENTS.md`, `docs_ai/dev_pipeline.md`, `docs_ai/bugfix_pipeline.md`, `docs_ai/code_map.md`, `docs_ai/change_map.md`, and `docs_ai/behavior_specs.md` as applicable.

## Project Structure

Each `src/` module and `tests/` has its own `CLAUDE.md` with module-specific conventions, data structures, and pitfalls.

```
xquic_ops/
├── src/
│   ├── transport/                # QUIC transport: conn, engine, stream, packet, send_ctl, cid, fec, datagram
│   │                             #   CLAUDE.md: conn flags (uint64 bitmask), state machine, scheduler/FEC plugins
│   ├── http3/                    # HTTP/3 + QPACK: h3_conn, h3_stream, h3_request, frame/, qpack/
│   │                             #   CLAUDE.md: error handling, SETTINGS ordering, stream types
│   ├── tls/                      # TLS 1.3: boringssl/ & babassl/ backends, crypto, hkdf
│   │                             #   CLAUDE.md: backend abstraction, key derivation ordering
│   ├── congestion_control/       # BBR/BBR2/CUBIC/Reno/Copa, rate sampling, window filter
│   │                             #   CLAUDE.md: xqc_cong_ctrl_callback_t plugin interface
│   └── common/                   # Shared utils: log, memory pool, str, utils/
│                                 #   CLAUDE.md: leaf module (no upward deps), memory allocation
├── include/xquic/                # Public API: xquic.h, xqc_http3.h, xqc_errno.h, xquic_typedef.h
├── tests/                        # CUnit unit tests (unittest/) + integration client/server
│                                 #   CLAUDE.md: test conventions, adding new tests
├── demo/                         # HQ demo client/server
├── mini/                         # Minimal client/server examples
├── moq/                          # Media over QUIC (MoQ) transport, demo, tests
├── interop/                      # QUIC interop runner (Docker)
├── third_party/boringssl/        # BoringSSL source
├── cmake/                        # CMake modules (FindCUnit, FindSSL, etc.)
├── scripts/                      # Build and test scripts
├── docs_ai/                      # Dev reference docs (see Reference Documents below)
├── CMakeLists.txt                # Root build configuration
├── xqc_configure.h.in           # Configure header template -> include/xquic/xqc_configure.h
└── xqc_build.sh                  # Convenience build script
```

## Coding Guidelines

Follow [karpathy-guidelines](~/.claude/plugins/marketplaces/karpathy-skills/CLAUDE.md) for general coding discipline (think before coding, simplicity first, surgical changes, goal-driven execution).

Project-specific rules:

1. **Naming**: Use `snake_case` with `xqc_` prefix. Comments explain "why", not "what".
2. **Code-doc sync**: When modifying a module, update corresponding docs (see `docs_ai/auto_doc_lookup.md`). When changing public APIs, update `include/xquic/` header docs. When adding new files, update `docs_ai/codebase_index.md`.
3. **Documentation minimalism**: Follow `docs_ai/doc_style_guide.md`. Keep generated comments/docs short, source-backed, non-duplicative, and focused on durable constraints.
4. **Testing**: Non-trivial changes must include tests and pass before completion. Use `/validate` to auto-detect changed files, build, and run the minimal test set. For adding new unit tests, see `tests/CLAUDE.md`.

## Reference Documents

| Topic | Path |
|-------|------|
| System architecture | `docs_ai/architecture/overview.md` |
| Module dependencies | `docs_ai/architecture/module_dependency.md` |
| Build guide | `docs_ai/build/build_guide.md` |
| Test guide | `docs_ai/testing/test_guide.md` |
| Documentation style | `docs_ai/doc_style_guide.md` |
| Codebase file index | `docs_ai/codebase_index.md` |
| Source-to-doc mapping | `docs_ai/auto_doc_lookup.md` |
