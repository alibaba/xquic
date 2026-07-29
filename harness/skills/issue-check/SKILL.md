---
name: issue-check
description: Verify whether a proposed XQUIC bug issue is real by checking the cited RFC or Internet-Draft mechanism against the repository's actual source behavior, tracing any root cause to current file and line evidence, and returning a fail-closed boolean gate. Use when validating an issue draft, investigating a claimed QUIC, HTTP/3, QPACK, or MoQT protocol violation, or before issue-submit may publish an issue.
---

# XQUIC Issue Check

Produce an evidence-backed validity report. Do not create or modify a GitHub
issue while performing this check.

## Required Workflow

1. Normalize the claim into:
   - affected protocol, version, and negotiated feature;
   - triggering inputs and configuration;
   - expected behavior;
   - actual behavior; and
   - claimed RFC or draft section.
2. Read the authoritative specification:
   - use RFC Editor for published RFCs;
   - use IETF Datatracker for active Internet-Drafts;
   - identify the exact section and, for a draft, the exact revision; and
   - distinguish normative requirements from explanatory text.
3. Verify applicability. Check protocol version, endpoint role, connection
   state, negotiated parameters, preconditions, and documented exceptions.
4. Inspect the current XQUIC checkout. Trace the relevant parser, state
   transition, caller, error path, and tests rather than relying only on names
   or issue-provided snippets.
5. Reproduce the reported behavior or run the nearest deterministic test when
   practical. Record the exact command, configuration, and result. If the
   behavior is not reproduced, distinguish direct source proof from an
   unverified runtime assumption.
6. Compare the specification mechanism with the implementation logic:
   - state the specification rule in plain language;
   - state the source behavior along the same decision path;
   - identify the exact divergence, if any; and
   - rule out configuration, unsupported-version, permissive-language, and
     documented implementation-choice explanations.
7. Attempt to locate the root cause. Never promote correlation or a nearby
   line into a confirmed cause without tracing how it produces the reported
   behavior.
8. Return the gate report in the format below.

## Specification Evidence

Link to the exact section, not only the RFC or draft landing page. Preserve
normative keywords such as MUST, MUST NOT, SHOULD, and MAY when they determine
the result. Quote only the shortest decisive excerpt and paraphrase its
surrounding mechanism and applicability.

For an Internet-Draft, record both its revision and section because draft
requirements can change. Treat an implementation that follows a different
draft revision as a version mismatch until compatibility expectations prove
otherwise.

## Source and Root-Cause Evidence

Resolve evidence against the current checkout and record `git rev-parse HEAD`.
Re-read line numbers from the file; do not trust stale line references from
the proposed issue.

For each decisive source location, provide:

- the repository-relative path;
- the current commit SHA;
- the smallest useful line range;
- a short exact source excerpt; and
- an explanation of how that branch implements or violates the mechanism.

Use a commit-pinned GitHub permalink when available. Otherwise use
`path:line` with the commit SHA. Distinguish root-cause status as:

- `confirmed`: the traced branch necessarily produces the discrepancy;
- `probable`: evidence points to it but a missing observation remains; or
- `unresolved`: the defect is verified but its cause is not yet isolated.

A verified behavioral defect may pass with an unresolved root cause. Do not
invent file, line, or code evidence to make the report appear complete.

## Gate Decision

Return `check_result: true` only when:

1. the authoritative mechanism applies to the reported scenario;
2. the repository behavior conflicts with that mechanism or contains an
   independently demonstrable logic error; and
3. a reasonable implementation choice, negotiated configuration, or stated
   exception does not explain the difference.

Return `check_result: false` with `classification: not-a-problem` when the
implementation conforms, the requirement does not apply, the text is
permissive, or the difference is a valid implementation tradeoff.

Return `check_result: false` with `classification: inconclusive` when required
specification, source, configuration, or reproduction evidence is missing.
This fails the submission gate; it is not proof that the implementation is
correct.

Source reasoning alone may verify a defect when the relevant branch and
outcome are deterministic. Otherwise, failure to reproduce the claimed
runtime behavior is inconclusive.

A SHOULD-level difference is not automatically a defect: inspect whether the
implementation has valid reasons and understands the consequences. A local
preference cannot override an applicable MUST or MUST NOT.

## Required Output

```yaml
check_result: true | false
classification: verified-defect | not-a-problem | inconclusive
summary: <one-sentence decision>
specification:
  document: <RFC or draft revision>
  section: <section number and title>
  url: <exact section URL>
  requirement: <normative mechanism and applicability>
implementation:
  commit: <full SHA>
  observed_logic: <what the current code does>
  locations:
    - path: <repo-relative path>
      lines: <current line or narrow range>
      excerpt: <short exact source content>
      explanation: <how this code implements the observed behavior>
comparison:
  divergence: <exact mismatch, or none>
  alternatives_ruled_out:
    - <configuration, version, or design explanation checked>
root_cause:
  status: confirmed | probable | unresolved | not-applicable
  locations:
    - path: <repo-relative path>
      lines: <current line or narrow range>
      excerpt: <short exact source content>
      explanation: <causal relationship>
blocking_evidence:
  - <missing evidence; empty when verified>
```

After the YAML block, give a concise human-readable analysis with the
specification evidence, source excerpts, and reasoning needed to audit the
decision.

## Guardrails

- Prefer primary RFC Editor, IETF Datatracker, repository source, tests, and
  captured behavior over secondary summaries.
- Do not return true merely because the issue text cites an RFC.
- Do not treat unsupported functionality as a defect unless support is
  claimed or required for the negotiated protocol.
- Do not expose credentials, private logs, or security-vulnerability details
  in a public-ready report.
- Re-run the check after any relevant source, draft revision, reproduction, or
  issue-claim change.
