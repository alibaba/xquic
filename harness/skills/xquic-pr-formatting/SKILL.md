---
name: xquic-pr-formatting
description: Format, submit, and update concise XQUIC pull requests, descriptions, comments, and review summaries. Use after the development-pipeline validation gate passes when creating or editing an alibaba/xquic pull request or issue-linked PR body so protocol mechanisms, case summaries, aggregate contribution gates, and Markdown formatting remain consistent.
---

# XQUIC PR Formatting

## Required Workflow

1. Read `CONTRIBUTING.md` and the
   [pull-request specification](../../spec/pull-requests.md).
2. Start from the repository
   [pull-request template](../../../.github/pull_request_template.md).
3. Treat its three concise sections as the canonical PR body structure:
   mechanism, validation cases, and aggregate `CONTRIBUTING.md` status.
4. Check the branch name against the task-to-prefix mapping in
   `CONTRIBUTING.md`, then check commit format, CLA state, rebase and squash
   state, code style, full-suite result, relevant tests, CI state, and
   issue-closing syntax.
5. Explain the changed mechanism and cite the exact RFC or draft section for
   protocol behavior. Include the exact `Fixes: #<issue-number>` line for an
   issue fix.
6. Verify internally that the complete local unit suite and both relevant
   case tests passed; a focused unit test is insufficient. In the PR, list
   only each client-to-server case ID and its concise behavior.
7. For new case IDs, require a fresh, conflict-free reservation scan across
   every other open PR's published head. Keep successful scan details in local
   evidence; expose only a concise blocker when a conflict exists.
8. Check every `CONTRIBUTING.md` item internally. Publish one overall result,
   `Local regression: Complete` or concise failed cases, and `CI: Complete` or
   only incomplete check names.
9. Write multiline descriptions or comments to a Markdown file first.
10. After the development pipeline's validation gate passes, create every new
    code pull request as draft through the available GitHub client using that
    file. Keep follow-up updates in draft until their current head passes
    pre-review.
11. Fetch the published pull request and confirm its number, URL, base, head,
    title, body, real line breaks, and draft state.
12. Run
    [`xquic-pr-pre-review`](../xquic-pr-pre-review/SKILL.md) against the
    published pull request. Read
    `~/build/harness/pr-review-<number>/pr-review-<number>.md` and require
    `pre_review_result: true` for its exact published head. Keep the report out
    of the commit and concise PR body. Preserve its sibling abnormal-case
    artifacts as local inputs to the next PR iteration.
13. Immediately repeat the reservation scan with the published current PR
    included. If duplicate case IDs exist, the lowest PR number keeps them.
    Keep or return every later PR to draft and send it back through allocation
    and validation before another update.
14. Reflect a collision as an incomplete local gate; keep successful details
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

## Guardrails

- Keep claims factual and source-backed.
- Keep the PR body concise; detailed evidence belongs in code, CI, or ignored
  local validation artifacts.
- Do not use escaped newline strings for multiline GitHub content.
- Do not claim a full suite passed when only a focused test ran.
- Do not move a production code pull request to review without paired coverage
  and passing local gate evidence.
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
- Preserve the distinction between issue-independent harness work and a
  product change that happens to exercise it.
