---
name: xquic-pr-formatting
description: Format and update XQUIC pull request descriptions, comments, and review summaries. Use when preparing or editing an alibaba/xquic pull request or issue-linked PR body so contributor requirements, validation evidence, and Markdown formatting remain consistent.
---

# XQUIC PR Formatting

## Required Workflow

1. Read `CONTRIBUTING.md` and the
   [pull-request specification](../../spec/pull-requests.md).
2. Start from the repository
   [pull-request template](../../../.github/pull_request_template.md).
3. Treat that template as the canonical PR body structure. Preserve its
   contribution checklist and harness validation sections rather than
   replacing them with a shorter body.
4. Check the branch name against the task-to-prefix mapping in
   `CONTRIBUTING.md`, then check commit format, CLA state, rebase and squash
   state, code style, full-suite result, relevant tests, CI state, and
   issue-closing syntax.
5. For a production behavior change, require the PR body to name paired
   happy-path and abnormal-path unit tests plus paired client-to-server case
   tests.
6. Require evidence that the complete local unit suite and both relevant case
   tests passed; a focused unit test is insufficient.
7. Include exact validation commands actually run and state limitations
   plainly.
8. For issue fixes, include `Fixes: #<issue-number>`.
9. Write multiline descriptions or comments to a Markdown file first, then
   submit the file through the available GitHub client.
10. Fetch the published body after updating it and verify real line breaks,
   headings, issue links, and test evidence.

## Pull Request Body

Use `.github/pull_request_template.md` as the single body shape. Complete each
applicable field and write `Not applicable` with a reason where the template
allows an exemption. A checkbox is evidence only when the corresponding
branch, commit, command, result, or contributor state supports it.

## Guardrails

- Keep claims factual and source-backed.
- Do not use escaped newline strings for multiline GitHub content.
- Do not claim a full suite passed when only a focused test ran.
- Do not move a production code pull request to review without paired coverage
  and passing local gate evidence.
- Do not accept a checked template box without the corresponding command,
  test or case name, result, and current-head evidence.
- Do not mark a `CONTRIBUTING.md` checkbox complete when the branch, commits,
  CLA, rebase state, style, tests, CI, or issue syntax do not support it.
- Do not accept an allowed branch prefix when it belongs to a different task
  type.
- Do not include internal agent names, temporary artifacts, or process
  chatter in contributor-facing content.
- Preserve the distinction between issue-independent harness work and a
  product change that happens to exercise it.
