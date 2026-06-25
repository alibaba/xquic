---
name: gh-address-comments
description: Address actionable GitHub pull request review comments for xquic. Use when asked to handle PR review feedback, requested changes, unresolved inline threads, or reviewer comments while preserving unrelated edits.
---

# GitHub Address Comments

## Workflow

1. Fetch PR review comments and unresolved threads. Prefer thread-level state when available so resolved items are not reworked.
2. Classify each comment as actionable, already addressed, question-only, stale, or blocked.
3. For actionable items, inspect the surrounding source and caller path before editing.
4. Apply the smallest edits needed to satisfy the comment. Keep unrelated files and user-owned changes untouched.
5. Re-read the modified path and verify the reviewer concern is actually handled.
6. Run `/validate` when the edit affects code, build, or tests.
7. Summarize each comment with status: fixed, already addressed, needs user decision, or cannot verify.

## Guardrails

- Do not resolve or reply to review threads unless explicitly asked.
- Do not batch unrelated review comments into broad refactors.
- Preserve staged-only workflows. If files are already staged, inspect staged and unstaged diffs separately before committing.
- For docs-only comments, avoid triggering builds unless the changed docs affect generated commands or scripts.
