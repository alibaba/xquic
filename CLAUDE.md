# XQUIC

XQUIC is a QUIC and HTTP/3 protocol library implemented in C, developed by Alibaba. It provides a high-performance, cross-platform implementation of the IETF QUIC transport protocol and the HTTP/3 application protocol.

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

## Build Dependencies

- **Compiler**: GCC or Clang with C11 support (C++17 for BoringSSL build)
- **CMake**: >= 3.10
- **SSL Backend**: BoringSSL (recommended for macOS) or BabaSSL/Tongsuo
- **Go**: >= 1.18 (BoringSSL build dependency)
- **Ninja**: any version (BoringSSL build dependency)
- **libevent**: >= 2.0.21 (test/demo binaries)
- **CUnit**: >= 2.1 (unit test framework)
- **OpenSSL CLI**: for generating test TLS certificates

See `docs_ai/build/build_guide.md` for full build instructions.

## Git Conventions

### Remotes

```
origin  -> git@github.com:alibaba/xquic.git     (upstream, read-only for pushes)
fork    -> git@github.com:cherylsy/xquic.git     (fork, push target)
```

- Issue branches (`issue-<N>-*`) are pushed to the `fork` remote.
- PRs target origin: `gh pr create --repo alibaba/xquic --head cherylsy:<branch>`.

### Worktree Convention

Each issue uses an independent git worktree for parallel isolation:

```
<project-root>/                     (main worktree)
../xquic-issue-<N>/                 (issue worktree)
```

Lifecycle: `git worktree add` -> work -> push to fork -> create PR -> `git worktree remove`.

## Coding Guidelines

Follow [karpathy-guidelines](~/.claude/plugins/marketplaces/karpathy-skills/CLAUDE.md) for general coding discipline (think before coding, simplicity first, surgical changes, goal-driven execution).

Project-specific rules:

1. **Naming**: Use `snake_case` with `xqc_` prefix. Comments explain "why", not "what".
2. **Code-doc sync**: When modifying a module, update corresponding docs (see `docs_ai/auto_doc_lookup.md`). When changing public APIs, update `include/xquic/` header docs. When adding new files, update `docs_ai/codebase_index.md`.
3. **Testing**: Non-trivial changes must include tests and pass before completion. Use `/validate` to auto-detect changed files, build, and run the minimal test set. For adding new tests, see `tests/CLAUDE.md`; for the full feature-to-test mapping, see `docs_ai/testing/test_guide.md`.

## Reference Documents

| Topic | Path |
|-------|------|
| System architecture | `docs_ai/architecture/overview.md` |
| Module dependencies | `docs_ai/architecture/module_dependency.md` |
| Build guide | `docs_ai/build/build_guide.md` |
| Test guide | `docs_ai/testing/test_guide.md` |
| Codebase file index | `docs_ai/codebase_index.md` |
| Source-to-doc mapping | `docs_ai/auto_doc_lookup.md` |
