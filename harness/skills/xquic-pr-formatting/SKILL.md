---
name: xquic-pr-formatting
description: Format, create, and update concise XQUIC pull request bodies and review-state transitions. Use when asked to prepare or edit an alibaba/xquic PR body, create a draft PR from an already-pushed branch, update a PR after code changes pushed a new head, or move a validated draft toward review.
---

# XQUIC PR Formatting

This skill owns contributor-facing PR content, summary-to-code consistency, and
PR state checks. It does not own local staging, commits, branch pushes, CI
diagnosis, review-comment fixes, or code review.

## Required Workflow

1. Read `CONTRIBUTING.md` and the
   [pull-request specification](../../spec/pull-requests.md).
2. Start from the repository
   [pull-request template](../../../.github/pull_request_template.md).
3. Build and validate the title with the exact shape from
   [Pull Request Title](../../spec/pull-requests.md#pull-request-title): use
   `[<change-id>] Fix #<issue-number>: <English title>` when closing an issue,
   or `[<change-id>]: <English title>` otherwise. Allow only `+`, `-`, `=`, or
   `~` as the change identifier, and write the complete description in English.
4. Treat the template's three concise sections as the canonical PR body
   structure:
   mechanism, validation cases, and aggregate `CONTRIBUTING.md` status.
5. Check the branch name against the task-to-prefix mapping in
   `CONTRIBUTING.md`, then check commit format, CLA state, rebase and squash
   state, code style, complete-unit-suite result, relevant tests, CI state, and
   issue-closing syntax.
6. Explain the changed mechanism and cite the exact RFC or draft section for
   protocol behavior. Include the exact `Fixes: #<issue-number>` line for an
   issue fix.
7. Verify internally that the complete local unit suite passed; a focused unit
   test is insufficient. In the PR, list only executed client-to-server case
   IDs and concise behavior, or concise missing case evidence.
8. For new case IDs, require a fresh, conflict-free reservation scan across
   every other open PR's published head. Keep successful scan details in local
   evidence; expose only a concise blocker when a conflict exists.
9. Check every `CONTRIBUTING.md` item internally. Publish one overall result,
   `Local regression: Complete` or concise failed cases, and `CI: Complete` or
   only incomplete check names.
10. Write multiline descriptions or comments to a Markdown file first.
11. After the development pipeline's validation gate passes and the branch is
    already pushed, create every new code pull request as draft through the
    available GitHub client using that file. Keep follow-up updates in draft
    unless the active task is to move the current published head toward review.
12. After any code push changes the published PR head, rerun this skill against
    the current base-to-head diff before the PR is updated or moved forward.
    Update the mechanism, validation cases, and aggregate gate summary so they
    describe the current code and validation evidence, not a prior head.
13. Fetch the published pull request and confirm its number, URL, base, head,
    canonical title, body, real line breaks, and draft state.
14. Verify the published PR summary matches the current base-to-head diff:
    changed mechanism, protocol citations, issue linkage, case IDs, local gate,
    and CI status must all be current and source-backed.
15. When the active task is to move a code PR out of draft, run
    [`xquic-pr-pre-review`](../xquic-pr-pre-review/SKILL.md) against the
    published pull request. Read
    `~/build/harness/pr-review-<number>/pr-review-<number>.md` and require
    `pre_review_result: true` for its exact published head. Keep the report out
    of the commit and concise PR body. Preserve its sibling abnormal-case
    artifacts as local inputs to the next PR iteration.
16. When moving a PR toward review, immediately repeat the reservation scan with
    the published current PR included. If duplicate case IDs exist, the lowest
    PR number keeps them.
    Keep or return every later PR to draft and send it back through allocation
    and validation before another update.
17. Reflect a collision as an incomplete local gate; keep successful details
    out of the body. Fetch the published pull request and verify its title,
    concise body, real line breaks, RFC and issue links, aggregate statuses,
    base, head, draft or review state, and URL. Update the concise body and
    move an otherwise complete PR to review only after this check passes.

## Pull Request Body

Use `.github/pull_request_template.md` as the single body shape. Do not add
per-check checklists or validation transcripts. Use `Not applicable` with a
short reason when protocol or runtime cases do not apply.

List cases only as:

```text
<case ID> — <concise behavior>
```

## Pull Request Title

Use `[<change-id>] Fix #<issue-number>: <English title>` for an issue-closing
pull request and `[<change-id>]: <English title>` otherwise. The marker is one
of `+`, `-`, `=`, or `~`. Keep the description English-only and use GitHub's
draft state instead of adding status prefixes to the title.

## Guardrails

- Keep claims factual and source-backed.
- Keep the PR body concise; detailed evidence belongs in code, CI, or ignored
  local validation artifacts.
- Do not publish a title that omits the canonical change marker, uses another
  issue syntax, or contains a non-English description.
- Do not use escaped newline strings for multiline GitHub content.
- Do not claim the complete local unit suite passed when only a focused test
  ran.
- Do not leave a PR summary describing an older head after code changes are
  pushed.
- Do not move a production code pull request to review without required unit
  coverage and accepted local gate evidence.
- Do not submit a new production code pull request before the development
  pipeline's validation gate passes, and do not create it initially as ready.
- Do not move a production code pull request to review before its exact
  published current head passes pre-review.
- Do not accept a missing, stale, false, or inconclusive pre-review report.
- Do not publish or update a ready-for-review production PR with a case ID
  reserved by another open PR.
- Do not treat a failed or incomplete open-PR query as an empty reservation
  set.
- Do not leave the later-numbered PR ready after a post-publication collision;
  reallocate its ID and rerun validation.
- Do not publish detailed commands, test function names, case names, logs,
  namespace ranges, tested SHA, or successful reservation snapshots.
- Do not mark the aggregate `CONTRIBUTING.md` result passed when the branch,
  commits, CLA, rebase state, style, local regression, CI, or issue syntax does
  not support it.
- Do not accept an allowed branch prefix when it belongs to a different task
  type.
- Do not include internal agent names, temporary artifacts, or process
  chatter in contributor-facing content.
- Do not stage, commit, push, rebase, or force-push while acting only on PR
  formatting or state.
- Preserve the distinction between issue-independent harness work and a
  product change that happens to exercise it.
