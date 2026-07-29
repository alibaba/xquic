---
name: gh-pr-review
description: Review GitHub pull requests and local PR diffs for xquic. Use when asked to review a PR, inspect a branch before merge, summarize review risks, or produce source-backed findings without making code changes unless explicitly requested.
---

# GitHub PR Review

## Workflow

1. Confirm the repository, base branch, head branch, PR number or URL, and whether the task is review-only.
2. Read project rules first: `AGENTS.md`, then the relevant pipeline document if the review becomes a code or test task.
3. Gather evidence before judging: inspect `git status -sb`, `git diff --stat`, the commit range, and changed files. Prefer GitHub PR metadata/tools when a PR URL or number is provided.
4. Trace changed behavior through real callers, callees, parser indices, config plumbing, and tests. Do not infer protocol behavior from filenames alone.
5. Report findings first, ordered by severity. Include file and line references, the observed risk, and the shortest concrete reproduction or reasoning path.
6. Keep summary brief and secondary. If no issues are found, say so clearly and name remaining test gaps or residual risk.

## XQUIC Review Rules

- Keep scope narrow. Separate FEC, RED, MoQ, transport, docs, and build changes when the diff mixes topics.
- For log schema changes, check emitters, fixed-position parsers, docs, and report scripts together.
- For generated headers such as `include/xquic/xqc_configure.h`, verify whether the file is generated before treating changes as source edits.
- For branch or remote review, distinguish local, upstream `origin`, and user fork targets.
- Do not stage, commit, push, resolve review threads, or edit code during a review-only task.

## Output Shape

Use this order:

1. Findings
2. Open questions or assumptions
3. Brief change summary or test notes

When citing local files, use absolute clickable file links when the client supports them.
