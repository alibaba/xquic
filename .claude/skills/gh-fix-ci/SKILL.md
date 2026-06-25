---
name: gh-fix-ci
description: Debug and fix failing GitHub PR checks for xquic. Use when a PR, branch, or commit has failed CI, GitHub Actions, build checks, test checks, or requested validation failures that should be diagnosed from logs before editing.
---

# GitHub Fix CI

## Workflow

1. Identify the exact failing check, run ID, job, command, and commit SHA. Use GitHub tools or `gh` when available.
2. Read logs before editing. Capture the first failing command and the most relevant error lines.
3. Map the failure to source using `docs_ai/auto_doc_lookup.md` and read the required docs before changing code.
4. Inspect the real code path or build/test script that produced the failure.
5. Make the smallest fix that addresses the confirmed cause. Preserve unrelated local edits and staged state.
6. Re-run the smallest relevant local validation from `docs_ai/testing/test_guide.md` when feasible. If CI-only, explain why local validation is not equivalent.
7. Report the failing command, cause, changed files, validation result, and any checks that still need remote rerun.

## Guardrails

- Do not guess from check names; logs are required evidence.
- Do not paper over test failures by weakening assertions unless the expected behavior is proven wrong.
- Do not run destructive Git commands unless the user explicitly asks and local changes are preserved.
- Do not push fixes without showing the commit/push scope and receiving confirmation, unless the user already requested push in the same task.
