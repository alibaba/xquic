---
name: classify-issue-complexity
description: Classify XQUIC GitHub issues with an evidence-backed L1-L4 resolution-complexity label while keeping validity, priority, severity, and disposition separate and skipping uniquely labeled issues unless the user explicitly forces a recheck. Use when triaging one issue or a batch of issues, creating an issue-complexity backlog, or applying or correcting L1-L4 GitHub labels.
---

# Classify XQUIC Issue Complexity

Estimate the work needed to resolve an issue. Do not use complexity as proof
that a report is valid or as a proxy for priority or severity.

## Select the operation

- Use **preliminary triage** for backlog scans. Produce a
  provisional level and confidence. Do not mutate issue labels unless the user
  explicitly authorizes a batch classification and the complexity boundary is
  high confidence for every issue being changed.
- Use **verified classification** before applying a label. Satisfy every
  evidence gate and resolve material uncertainty first.
- Use **label mutation** only when the user authorizes GitHub changes. Preserve
  unrelated labels and make no other issue mutation.
- Use **forced recheck** only when the user explicitly asks to recheck or
  reclassify already-labeled issues. This bypasses only the existing-label
  skip gate; it does not authorize a GitHub mutation.

## Gate repeated classification

1. Read `harness/spec/issue-complexity/spec.md` in full.
2. Resolve the repository and issue, then fetch its current labels before
   refreshing `main`, reading source, or investigating protocol behavior.
3. Select the labels whose names are exactly `L1`, `L2`, `L3`, or `L4`.
4. Continue normally when no complexity label exists.
5. When exactly one complexity label exists and no explicit forced recheck
   applies, stop work on that issue. Report `skipped-existing-label` and the
   existing level without rerunning classification or calling a label API. In
   a batch, continue with the remaining issues and count the skipped row.
6. When exactly one complexity label exists and the user explicitly forces a
   recheck for that issue or batch scope, record the existing level and
   continue. A general request to rerun triage is not a forced recheck.
7. When multiple complexity labels exist, report
   `inconsistent-existing-label` and stop without mutation.

## Load evidence for issues that proceed

1. Resolve the current issue state, body, comments, assignees, and milestone.
2. Refresh the intended base and record the full `origin/main` commit SHA.
   Classify current behavior, not a stale release or issue-provided line number.
3. Use `harness/spec/architecture.md` and
   `harness/spec/harness-manifest.yml` to identify affected modules, public
   APIs, feature gates, tests, and validation boundaries.
4. Read current source, callers, tests, and the closest module documentation.
5. For protocol claims, read the exact RFC Editor section or exact active
   Internet-Draft revision and section. Treat issue text and comparisons with
   another implementation as leads, not authority.

For batch triage, use issue text and focused current-source inspection for the
first pass. Record missing evidence rather than expanding every issue into a
full investigation.

## Separate truth from complexity

Route a claimed QUIC, HTTP/3, QPACK, TLS, recovery, DATAGRAM, multipath, or MoQT
defect through `issue-check` before calling it a verified defect, closing it as
not-a-problem, implementing a fix, or applying a high-confidence label based on
that claim.

Use these disposition values independently from the L1-L4 level:

- `verified-defect`
- `not-a-problem`
- `duplicate-or-obsolete`
- `feature-request`
- `question-or-support`
- `inconclusive`

A not-a-problem closure can be L1 work. A localized interoperability defect
can be L2 despite high severity. An unsupported major feature can be L4 even
when no defect exists.

## Choose the level

Apply every scenario in `harness/spec/issue-complexity/spec.md`. Evaluate:

- resolution type and whether production behavior changes;
- affected modules, layers, public APIs, and TLS backends;
- state-machine and lifetime complexity;
- protocol negotiation and backward-compatibility risk;
- paired unit-test, endpoint, and interoperability obligations; and
- migration or ecosystem impact.

Choose the highest level required by any dimension. Do not average dimensions
or lower the level because the apparent code diff is short. If one issue mixes
independent requests, recommend splitting it; until split, use the highest
level and explain which sub-request controls it.

Set confidence to:

- `high`: current source, intended behavior, affected boundaries, and required
  validation are established;
- `medium`: the likely boundary is established but one non-decisive observation
  or test obligation remains;
- `low`: source applicability, intended behavior, protocol version, or blast
  radius is unresolved.

Only `high` confidence is eligible for label mutation. Confidence applies to
the resolution-complexity boundary, not to whether the issue claim is true. A
preliminary batch may contain medium or low confidence rows when their gaps
are explicit, but those rows remain unlabelled.

## Report the result

For one issue, return:

```yaml
issue: <URL>
status: classified
existing_level: L1 | L2 | L3 | L4 | none
forced_recheck: true | false
inspected_main: <full SHA>
level: L1 | L2 | L3 | L4
confidence: high | medium | low
disposition: <independent disposition value>
rationale: <concise controlling complexity reason>
affected_boundaries:
  - <module, API, or state boundary>
protocol:
  source: <exact RFC/draft section or not-applicable>
  compatibility_risk: low | medium | high
validation:
  unit: <paired coverage or gap>
  endpoint: <paired coverage or gap>
  interoperability: <evidence or gap>
blocking_evidence:
  - <missing evidence; empty when high confidence>
next_action: <verification, closure explanation, design, or implementation gate>
```

For a skipped issue, return only its URL, `status: skipped-existing-label`,
existing level, and skip reason. Do not claim current-`main` revalidation.

For a batch, add one row per issue. Classified rows include issue, level,
confidence, disposition, reason, and next action; skipped rows include issue,
status, and existing level. Include level totals, confidence gaps, skipped
count, and the inspected `main` SHA for classified issues. Keep full evidence
available outside any compact summary.

## Apply GitHub labels

Use these repository labels exactly:

| Label | Color | Description |
|-------|-------|-------------|
| `L1` | `5CC665` | L1 - Local change with simple logic and no peer-visible interoperability impact. |
| `L2` | `F1F665` | L2 - Bounded feature with moderate state reasoning and verified backward-compatible peer behavior. |
| `L3` | `EC5C03` | L3 - Complex state interactions with interoperability or potential legacy-version risk. |
| `L4` | `481BCB` | L4 - Protocol-wide change with extreme reasoning complexity or known incompatibility. |

Before mutation, restate the repository, issue, old complexity label, new
label, inspected SHA, and confidence. Stop if multiple L1-L4 labels already
exist or if the target label definition differs from this table.

When authorized and high confidence:

1. If the recommended label is already the issue's only L1-L4 label, do not
   remove or re-add it.
2. Otherwise, remove the prior L1-L4 label, if any, and add exactly one
   recommended L1-L4 label.
3. Preserve every unrelated label.
4. Re-fetch the issue and verify the final single-label state.
5. Report the mutation or verified no-op; do not close, edit, assign,
   milestone, or comment on the issue unless separately requested.

## Guardrails

- Do not classify pull requests as issues in an age-based issue scan.
- Do not treat a repeated batch-triage request as permission to recheck
  uniquely labeled issues.
- Do not expose private logs or security-sensitive reproduction details.
- Restart active or forced classification after relevant input changes; an
  input change alone does not permit rechecking a labeled issue.
