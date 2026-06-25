# Bug Fix Pipeline

> Complete pipeline for diagnosing and fixing bugs. Referenced by `AGENTS.md`.

All bug fixes MUST follow this pipeline. Use `/validate` for automated validation (change detection, build, unit tests, integration tests).

```
Bug Report -> Root Cause Analysis -> Fix Implementation -> Validation Decision -> Fix Summary -> Complete
                                           ^                         |
                                           |                         |
                                           +-------------------------+
                                              (on failure, return to Fix Implementation)
```

---

## Stage 1: Bug Report

- Capture the failure evidence: CI log, error message, assertion output, crash stack, or user reproduction steps
- Identify the failing test names and assertion counts
- Record the environment: branch, commit, build flags, compiler

**Output**: A clear problem statement with reproducible evidence.

## Stage 2: Root Cause Analysis

- Locate the failing code path using the error message / assertion / stack trace
- Trace backwards from the failure point to find the root cause (not just the symptom)
- Use `docs_ai/code_map.md` to locate the owning module and likely call path
- Use `docs_ai/change_map.md` and `docs_ai/auto_doc_lookup.md` to find relevant module documentation
- Read `docs_ai/behavior_specs.md` for existing invariants before deciding whether behavior or tests are wrong
- Distinguish between:
  - **Regression**: A previously passing code path broke due to a recent change
  - **Test gap**: The test was always wrong / incomplete but a new validation exposed it
  - **Design conflict**: Two correct changes interact to produce incorrect behavior

**Output**: Root cause description identifying the exact code path, the commit or change that introduced the bug (if regression), and the fix strategy.

## Stage 3: Fix Implementation

- Fix the root cause, not the symptom
- Follow existing code style: Follow existing project conventions. Use consistent naming (snake_case or project prefix). Comments explain "why", not "what".
- Minimize fix scope -- do not refactor surrounding code
- Follow `docs_ai/doc_style_guide.md` for comments, fix notes, and generated docs.
- If the bug exposes a missing or misleading invariant, update `docs_ai/behavior_specs.md`
- If the fix depends on a design choice or compatibility tradeoff, update `docs_ai/decision_records.md`
- If the fix requires adding test infrastructure (e.g. test helpers, mock functions), keep them clearly marked and separated from production code
- **Every bug fix MUST have a unit test** -- either an existing test covers the fixed path, or a new test must be written as part of this stage

### Unit Test Requirements

Every fix must be accompanied by a unit test that guards against regression:

```
Fix applied
  |
  v
Does an existing unit test cover the fixed code path?
  |
  +-- YES --> The existing test is the verification target (Stage 4)
  |
  +-- NO  --> Write a new unit test that:
                1. Reproduces the original failure (assert fails without fix)
                2. Passes with the fix applied
                3. Is added to the appropriate test suite
```

- The test MUST exercise the exact code path that was broken
- The test MUST fail without the fix (regression guard)
- The test MUST pass with the fix
- For test setup fixes: the original test IS the verification -- confirm all assertions pass
- For production fixes: add a new test case or extend an existing one

### Where to Add Tests

For unit tests, see `tests/CLAUDE.md`. For the file-to-module mapping and integration test case catalog, use `/validate --detect` or see `.claude/skills/validate/SKILL.md`.

### Post-Modification Verification

After completing the fix and any associated test changes, verify the modification is logically sound:

1. **Re-read the root cause (Stage 2 output)** -- confirm the fix addresses the root cause, not a downstream symptom
2. **Trace the fixed code path** -- verify the fix is reachable from the original failure path and that all callers/callees are consistent with the change
3. **Check fix scope** -- confirm no unrelated production code was modified
4. **Verify test coverage alignment** -- confirm the unit test exercises the exact code path that was broken, not a different path
5. **Verify knowledge-base alignment** -- confirm code map, change map, behavior specs, and decision records remain accurate
6. If any check fails, revise the fix before proceeding to Stage 4.

## Stage 4: Validation Decision

Use `/validate` to auto-detect changed files and run the minimal build/test set that proves the fix.

- Prefer the unit test that covers the original failing path.
- Add targeted E2E only when the fixed behavior is runtime/protocol behavior not proven by unit tests.
- If validation fails because of the fix, return to Stage 3.
- If validation is skipped or blocked, record the reason in the Fix Summary.

## Stage 5: Fix Summary

Every completed bug fix MUST produce a structured summary.

### Summary Template

```
## Fix Summary

### Problem
[One-line description of the failure]

### Root Cause
[Precise explanation: what was wrong, where, and why]

### Fix
[What was changed and in which files]

### Verification
[Validation needed? Which commands ran or why they were skipped/blocked. Include pass/fail evidence.]

### Files Modified
- `path/to/file` -- [what changed]
- `path/to/test` -- [test added/fixed]
```

---

## Enforcement Rules

1. **NEVER** skip root cause analysis. Fixing symptoms creates new bugs.
2. **NEVER** consider a fix complete without validation evidence or a documented validation blocker.
3. **NEVER** fix production code without a regression test, unless the existing test suite already covers the exact path.
4. **NEVER** skip the fix summary. It is the permanent record of what was wrong and how it was resolved.
5. **NEVER** proceed from Stage 4 on a validation failure caused by the fix. Return to Stage 3, fix the issue, and re-run validation.
6. If the fix introduces test infrastructure (helpers, mock functions), document them as test-only in both the code comment and the fix summary.
7. If a fix reveals additional issues, file them separately -- do not scope-creep the current fix.
8. Do not leave behavior specs or decision records stale when a bug fix changes project semantics.
