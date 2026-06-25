---
name: validate
description: Build and run the minimal test set for xquic changes. Use after code changes, before commit, or when asked to validate/test/verify.
---

# XQUIC Validate

Automated build + test validation. Determines the smallest test set from changed files, runs it, and reports results.

## Workflow

### 1. Detect changed files

```bash
# Staged + unstaged + untracked production files
git diff --name-only HEAD 2>/dev/null
git diff --cached --name-only 2>/dev/null
git ls-files --others --exclude-standard 2>/dev/null
```

Combine and deduplicate. Filter to production-relevant paths (`src/`, `include/`, `tests/`, `CMakeLists.txt`, `cmake/`, `scripts/`, `demo/`, `mini/`, `moq/`). If no production files changed, report "No validation needed" and stop.

### 2. Map to test scope

Use the feature-to-test mapping from `docs_ai/testing/test_guide.md`. Match each changed file to the table. Merge results into the minimal set:

- If ANY file matches "Full run_tests + Full case_test.sh" (e.g. `include/xquic/*.h`, `CMakeLists.txt`), run full suite.
- Otherwise, collect the union of matched unit test suites and integration test flags.

Determine:
- `NEED_BUILD`: true if any production code/header/build config changed
- `NEED_UNIT`: true if any file maps to unit tests
- `NEED_INTEGRATION`: true if any file maps to case_test.sh

### 3. Check e2e test coverage

If changed files include `src/` production code that adds or modifies user-visible behavior (new feature, new error path, new protocol handling), verify that a corresponding integration test case exists:

1. Identify new `g_test_case == <N>` branches in `test_client.c` or `test_server.c`. Each must have a matching verification block in `scripts/case_test.sh`.
2. If production code changed but no test_client/test_server/case_test.sh changes exist, warn:
   ```
   Warning: production code changed but no integration test added/updated.
   Consider adding a case test. See tests/CLAUDE.md "Adding a New Integration Test".
   ```
3. If a new `-x <N>` case was added to test_client.c/test_server.c but case_test.sh has no matching block, warn:
   ```
   Warning: new test case -x <N> in test_client.c but no verification block in case_test.sh.
   ```

This step is advisory -- it does not block validation, but the warnings appear in the report.

### 4. Build (if needed)

```bash
cd build && make -j
```

If build fails, report the error and stop. Do not run tests on a failed build.

### 5. Run unit tests (if needed)

```bash
cd build && ./tests/run_tests
```

Pass criteria: exit 0, `0 tests FAILED` in output.

### 6. Run integration tests (if needed)

```bash
cd build

# Generate certificates if missing
if [ ! -f server.key ]; then
    openssl req -newkey rsa:2048 -x509 -nodes -keyout server.key -new -out server.crt -subj /CN=test.xquic.com
fi

export EVENT_NOKQUEUE=1  # macOS
sh ../scripts/case_test.sh
```

Pass criteria: all cases `pass:1`, no `[error]` in logs.

### 7. Report

Output a structured validation report:

```text
Validation:
- Changed files: <list of changed production files>
- E2E coverage: <ok/warnings, list any missing case tests>
- Build: <pass/fail/skipped>
- Unit tests: <pass/fail/skipped, with evidence>
- Integration tests: <pass/fail/skipped, with evidence>
- Result: <PASS/FAIL with details>
```

## Guardrails

- Never run `scripts/xquic_test.sh` (CI-only, installs packages via yum).
- Never modify code during validation. This skill is read-only + execute.
- If `build/` directory does not exist or has never been configured, report the blocker and suggest running the build setup from `docs_ai/build/build_guide.md`.
- If integration tests fail with port conflicts, suggest `killall test_server test_client` and retry.
