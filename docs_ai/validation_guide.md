# Validation Guide

> Build/test decision and execution rules. Use this document whenever a task may require compilation, tests, or explicit verification evidence.

## Core Rule

Claude decides the validation scope from the actual change and user request. Do not default to the largest suite. When validation is needed, use the smallest build/test set that can prove the change.

## When Validation Is Required

Run or explicitly plan validation when any of these apply:

- The user asks to build, test, verify, run CI-equivalent checks, or prove behavior.
- Production code, public headers, build config, scripts, tests, or generated config templates changed.
- Documentation claims about behavior, APIs, flags, commands, or tests changed and can be checked against source.
- A bug fix, regression fix, feature switch, or public API changed.

Validation may be skipped for pure analysis, read-only queries, or documentation-only wording changes that do not alter technical claims. If skipped, state why.

## Mandatory Execution Constraints

- Prefer targeted validation over full suites.
- Report the exact command, exit status, and pass/fail evidence. If validation cannot run, report the blocker and the closest completed check.

## Build Decision

| Change Type | Build Needed? | Build Profile |
|-------------|---------------|---------------|
| Production code/header/build-config change | Yes | Development build |
| Public API or feature switch change | Yes | Development build plus relevant ON/OFF flag check when practical |
| Test-only change | Usually yes | Development build if binaries or registration changed; otherwise existing build may be reused |
| Script-only change | Only if script depends on rebuilt binaries | Existing build or script-specific check |
| Docs-only change | Usually no | Re-read docs/source consistency instead |
| Query/analysis only | No | None |

## Build Commands

### Development Build (macOS with BoringSSL)

```bash
cd build
cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug \
      -DXQC_ENABLE_TESTING=1 \
      -DXQC_ENABLE_EVENT_LOG=1 \
      -DXQC_ENABLE_BBR2=1 \
      -DXQC_ENABLE_RENO=1 \
      -DSSL_TYPE=boringssl \
      -DSSL_PATH=$(pwd)/../third_party/boringssl \
      ..
make -j
```

### Development Build (Linux with BoringSSL)

```bash
cd build
cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug \
      -DXQC_ENABLE_TESTING=1 \
      -DXQC_SUPPORT_SENDMMSG_BUILD=1 \
      -DXQC_ENABLE_EVENT_LOG=1 \
      -DXQC_ENABLE_BBR2=1 \
      -DXQC_ENABLE_RENO=1 \
      -DSSL_TYPE=boringssl \
      -DSSL_PATH=$(pwd)/../third_party/boringssl \
      ..
make -j
```

### Incremental Rebuild (after code changes, from build/)

```bash
cd build && make -j
```

Build passes only when the command exits 0 with no compilation or link errors.

## Test Selection

Use the mapping in `docs_ai/testing/test_guide.md` and `docs_ai/auto_doc_lookup.md` to select the smallest test set that covers the changed path.

| Modified Area | Default Test Target |
|---------------|---------------------|
| `src/common/*` | `./tests/run_tests` |
| `src/transport/*` | `./tests/run_tests` + `sh ../scripts/case_test.sh` |
| `src/http3/*` | `./tests/run_tests` + `sh ../scripts/case_test.sh` |
| `src/http3/qpack/*` | `./tests/run_tests` (qpack suite only) |
| `src/tls/*` | `./tests/run_tests` (tls + crypto suites) |
| `src/congestion_control/*` | `./tests/run_tests` (cc suites) + `sh ../scripts/case_test.sh` |
| `include/xquic/*` | Full `./tests/run_tests` + `sh ../scripts/case_test.sh` |
| `tests/*` | `./tests/run_tests` |
| `CMakeLists.txt` / `cmake/*` | Full rebuild + `./tests/run_tests` |
| `demo/*` / `mini/*` | Rebuild targets, manual verification |

## Test Commands

### Unit Tests (from build/ directory)

```bash
./tests/run_tests
```

### Integration Tests (from build/ directory)

```bash
# Generate certificates if missing
if [ ! -f server.key ]; then
    openssl req -newkey rsa:2048 -x509 -nodes -keyout server.key -new -out server.crt -subj /CN=test.xquic.com
fi

# macOS: uncomment if kqueue issues arise
# export EVENT_NOKQUEUE=1

sh ../scripts/case_test.sh
```

### Quick Validation (rebuild + unit tests)

```bash
cd build && make -j && ./tests/run_tests
```

### Full Local Validation (rebuild + unit + integration)

```bash
cd build && make -j && ./tests/run_tests && sh ../scripts/case_test.sh
```

## Pass Criteria

| Validation Type | Pass Condition |
|-----------------|----------------|
| Build | Exit 0, no compile/link errors |
| Unit tests | Exit 0, all `Test: ... passed`, `0 tests FAILED` |
| Integration tests | All cases print `pass:1`, no `pass:0` |
| Docs-only consistency check | Updated docs match current code, flags, paths, and commands |

## Reporting Template

End with:

```text
Validation:
- Needed: yes/no, because <reason>
- Build: <command or skipped reason>
- Tests: <commands or skipped reason>
- Result: <pass/fail/blocker with evidence>
```
