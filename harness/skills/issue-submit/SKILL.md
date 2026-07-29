---
name: issue-submit
description: Draft and submit evidence-backed XQUIC GitHub bug issues in the repository's CONTRIBUTING and issue-template format. Use when preparing or opening an alibaba/xquic issue that must identify an exact RFC or draft mechanism, expected-versus-actual behavior, reproduction evidence, and optional verified source root cause; requires issue-check to return true before any GitHub submission.
---

# XQUIC Issue Submit

Prepare one specific, reproducible, non-duplicate issue and publish it only
after the [`issue-check` skill](../issue-check/SKILL.md) clears the claim.

## Required Workflow

1. Read root [`CONTRIBUTING.md`](../../../CONTRIBUTING.md) and the
   [`bug_report.yml`](../../../.github/ISSUE_TEMPLATE/bug_report.yml) issue
   template.
2. Reject public submission of suspected security vulnerabilities. Direct
   them to the repository security policy without disclosing details.
3. Search open and closed issues for duplicates using protocol terms, error
   codes, symptoms, and relevant function names.
4. Draft a single-bug report using the format below.
5. Run the complete
   [`issue-check` workflow](../issue-check/SKILL.md) against the draft and the
   current checkout.
6. Require `check_result: true`. If it is false, stop and return the check
   report; do not create or update a GitHub issue.
7. Confirm the check's commit SHA still matches the source evidence. Re-run
   the check if the draft, relevant source, or governing draft changed.
8. Write the multiline body to a Markdown file and submit that file through
   the available GitHub client.
9. Fetch the published issue and verify its title, headings, links, code
   excerpts, and real line breaks.

## Issue Format

Use the repository bug prefix and template fields:

````markdown
Title: [Bug]: <specific observable failure>

### What happened?

<Concise impact and trigger.>

#### Expected behavior

<Behavior required by the applicable mechanism.>

#### Actual behavior

<Observed XQUIC behavior under the same preconditions.>

#### Governing specification

- Document: <RFC number or exact draft revision>
- Section: <number and title>
- Link: <exact section URL>
- Mechanism: <normative rule, applicability, and concise explanation>

### Steps To Reproduce

1. <environment and configuration>
2. <minimal deterministic action>
3. <observable result>

### Verification evidence

- XQUIC commit: `<full SHA>`
- Protocol version and negotiated features: <values>
- Evidence: <test, log, trace, or packet observation>

### Root cause

<Include only when issue-check verified a useful cause.>

- Source: `<repo-relative path>:<line or narrow range>`
- Permalink: <commit-pinned GitHub URL when available>

```c
<small exact source excerpt>
```

<Explain how this branch causes the expected/actual difference.>

### Relevant log output

```shell
<minimal redacted log, or "Not available">
```
````

Keep expected and actual behavior directly comparable. State endpoint role,
state, protocol version, negotiated parameters, and configuration when they
affect applicability.

## Root-Cause Rules

Include the root-cause section only for evidence classified `confirmed`, or
when a `probable` cause is explicitly labeled and useful to maintainers. Omit
it when unresolved. Never present speculation as fact.

Refresh file line numbers from the verified commit. Keep source quotation
short and include enough surrounding control flow to make the claim
auditable. Do not quote generated or vendored code as the XQUIC root cause.

## Submission Gate

All conditions must hold before GitHub submission:

- the report follows `CONTRIBUTING.md` and the bug template;
- the report is reproducible, specific, unique, and scoped to one bug;
- the exact RFC or draft revision and section are linked;
- expected and actual behavior are separately stated;
- `issue-check` returned `check_result: true`;
- the issue draft matches the checked facts and source commit;
- no security-policy or duplicate-issue blocker remains; and
- logs and excerpts contain no credentials, personal data, or private
  infrastructure details.

The truth gate and publication gate are distinct. A real defect can still be
blocked from public submission because it is security-sensitive or a
duplicate.

## Guardrails

- Never submit when `issue-check` is false or stale.
- Never weaken or omit contradictory evidence to obtain a true result.
- Do not cite an RFC landing page without the applicable section.
- Do not use inline escaped newline strings for a multiline GitHub body.
- Do not create an issue unless the user explicitly requested submission.
- Do not mix multiple independent defects into one issue.
