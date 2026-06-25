# Validation Guide

> Build/test validation policy entry point. For exact unit/integration commands and diagnostics, see `docs_ai/testing/test_guide.md`.

## When to Use

Read this file for any task that:

- Requests build, test, verification, or validation.
- Changes code, public headers, build configuration, scripts, tests, or behavior-bearing documentation.
- Needs to decide whether validation can be skipped.

## Validation Decision

Use the smallest evidence that proves the changed behavior:

| Change Type | Validation Needed | Minimum Evidence |
|---|---|---|
| Docs-only wording with no technical claim change | No | Re-read changed docs and check links/references |
| Agent workflow docs | Usually no build/test | Re-read changed docs, check referenced paths exist |
| Public API/header change | Yes | Rebuild, full `./tests/run_tests`, full `case_test.sh` |
| Production C code | Yes | Rebuild plus mapped unit/integration tests |
| Bug fix | Yes | Regression test or existing exact-path test plus mapped validation |
| Build config or feature gate | Yes | Reconfigure/rebuild with affected gate/backend plus mapped tests |
| Test code/harness | Yes | Rebuild if binaries changed; run affected test or script |
| Script-only diagnostics | Script-specific | Run script or document blocker |

If validation is skipped, state the reason. If blocked, state the blocker and the closest completed check.

## How to Map Tests

1. Identify modified files.
2. Use `docs_ai/change_map.md` for change-family obligations.
3. Use `docs_ai/auto_doc_lookup.md` for source-to-doc and source-to-validation mapping.
4. Use `docs_ai/testing/test_guide.md` for exact commands and pass criteria.
5. For cross-module changes, use the broadest affected module's validation scope.

## Standard Commands

All build/test commands assume an existing configured `build/` directory unless the task changes CMake configuration.

Quick rebuild plus unit tests:

```bash
cd build && make -j && ./tests/run_tests
```

Full local validation:

```bash
cd build && make -j && ./tests/run_tests && sh ../scripts/case_test.sh
```

macOS integration tests need:

```bash
export EVENT_NOKQUEUE=1
```

For detailed setup, single-case execution, logs, and pass criteria, read `docs_ai/testing/test_guide.md`.

## Documentation Verification

For docs-only tasks:

1. Re-read every changed document.
2. Confirm referenced paths exist or are intentionally future-facing and labeled as such.
3. Confirm task routing still points to existing files.
4. Confirm new maintenance rules do not contradict `AGENTS.md`.
5. Run a reference check with `rg` or equivalent when practical.

## Validation Report Template

```text
Validation:
- Needed: yes/no, because <reason>
- Build: <command or skipped reason>
- Tests: <commands or skipped reason>
- Docs/checks: <commands or manual checks>
- Result: <pass/fail/blocker with evidence>
```
