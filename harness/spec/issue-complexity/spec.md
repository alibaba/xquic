# Issue Complexity Classification Specification

## Purpose

Define a repeatable, evidence-backed L1-L4 scale for XQUIC issue resolution
complexity while preserving separate decisions about validity, priority,
severity, and whether an issue should be closed without a code change.

## Requirements

### Requirement: Existing labels gate repeated classification

The classifier SHALL inspect the current issue labels before starting source
or protocol evidence collection. Exactly one existing `L1`, `L2`, `L3`, or
`L4` label SHALL make classification idempotent by default. Only an explicit
user instruction to force a recheck or reclassify already-labeled issues
SHALL bypass this gate. A general request to rerun backlog triage SHALL NOT
count as an override. The override SHALL NOT by itself authorize label or
other issue mutations.

#### Scenario: Existing unique label without an override

- **WHEN** an issue has exactly one L1-L4 label and the user did not explicitly
  force a recheck of labeled issues
- **THEN** the classifier reports `skipped-existing-label` with the existing
  level, preserves all labels, and does not rerun classification or call a
  label mutation

#### Scenario: User explicitly forces a recheck

- **WHEN** an issue has exactly one L1-L4 label and the user explicitly asks to
  recheck or reclassify that labeled issue
- **THEN** the classifier records the existing level and runs the complete
  evidence and classification workflow, while retaining the separate
  high-confidence and mutation-authorization gates

#### Scenario: Forced recheck confirms the existing level

- **WHEN** a forced recheck recommends the same L1-L4 level already present
- **THEN** the classifier preserves the existing label without removing or
  re-adding it and reports that no mutation was required

#### Scenario: Batch contains labeled and unlabeled issues

- **WHEN** a batch triage contains both uniquely labeled and unlabeled issues
  without an explicit forced-recheck scope
- **THEN** the classifier skips the labeled issues, classifies the unlabeled
  issues, and reports the skipped count separately

### Requirement: Classification uses current evidence

For every issue that proceeds to classification, the classifier SHALL record
the issue URL and state, the inspected `main` commit SHA, relevant issue
comments, affected source and test boundaries, and the governing RFC or
Internet-Draft section when protocol behavior is claimed.

#### Scenario: Protocol issue has sufficient evidence

- **WHEN** an open issue claims a QUIC, HTTP/3, QPACK, TLS, recovery, or MoQT
  protocol violation
- **THEN** the classification names the exact specification section and current
  source boundary used to estimate the resolution complexity

#### Scenario: Evidence is incomplete

- **WHEN** the current source boundary, protocol source, or intended behavior
  cannot be established
- **THEN** the classifier marks the result provisional, lowers confidence, and
  does not mutate the GitHub complexity label

### Requirement: Complexity is independent of disposition

The classifier SHALL report complexity separately from issue validity,
priority, severity, and disposition. A preliminary complexity classification
SHALL NOT claim that a reported bug is real or authorize implementation.

#### Scenario: Report is probably not a problem

- **WHEN** current evidence suggests the issue can be closed as a question,
  duplicate, obsolete report, or specification misunderstanding
- **THEN** the classifier may assign L1 to the closure work while separately
  requiring issue verification before posting the closing explanation

#### Scenario: Small but severe protocol defect

- **WHEN** a severe interoperability or security consequence has a localized
  implementation and test boundary
- **THEN** the classifier may assign L2 while preserving the independent high
  severity and compatibility-risk assessment

### Requirement: L1-L4 boundaries are stable

The classifier SHALL assign the lowest level whose complete definition covers
the expected resolution and SHALL use the highest affected complexity
dimension when several dimensions differ.

#### Scenario: L1 resolution

- **WHEN** resolution is evidence-backed closure without production behavior,
  documentation-only clarification, or a mechanical single-site maintenance
  change with an established validation path
- **THEN** the result is L1

#### Scenario: L2 resolution

- **WHEN** resolution is a localized single-module behavior change with a clear
  invariant, bounded state impact, and existing unit-test surface
- **THEN** the result is L2

#### Scenario: L3 resolution

- **WHEN** resolution crosses layers or modules, changes a public API or
  compatibility boundary, modifies a non-trivial state machine, or requires
  complex protocol/recovery reasoning and interoperability evidence
- **THEN** the result is L3

#### Scenario: L4 resolution

- **WHEN** resolution adds a major feature or protocol extension, changes broad
  negotiated wire behavior, or requires a substantial architecture or public
  API migration
- **THEN** the result is L4

### Requirement: Label mutation is fail closed

The classifier SHALL recommend exactly one of `L1`, `L2`, `L3`, or `L4` only
after meeting the evidence gate. It SHALL preserve unrelated labels and SHALL
not close, edit, or assign an issue unless the user separately requests that
action.

#### Scenario: Reclassifying an issue

- **WHEN** high-confidence evidence changes an issue from one complexity level
  to another and label mutation is authorized
- **THEN** the classifier removes the prior L1-L4 label, adds exactly one new
  level label, preserves all unrelated labels, and reports the mutation

#### Scenario: Multiple complexity labels already exist

- **WHEN** an issue has more than one L1-L4 label
- **THEN** the classifier reports the inconsistent state and does not mutate it
  until the correct single label is supported by evidence

#### Scenario: Explicit batch classification

- **WHEN** the user explicitly authorizes applying a batch classification and
  the resolution-complexity boundary is high confidence for each selected issue
- **THEN** the classifier may apply exactly one complexity label per issue even
  when the independent defect-validity disposition remains inconclusive

### Requirement: Classification output is auditable

For every issue that proceeds to classification, the classifier SHALL output
the recommended level, confidence, concise rationale, affected boundaries,
protocol and compatibility risk, test and interop obligations, disposition
candidate, and next verification action. For every skipped issue, it SHALL
output the issue, `skipped-existing-label` status, existing level, and skip
reason without claiming current-source revalidation.

#### Scenario: Batch triage

- **WHEN** multiple issues are classified in one triage operation
- **THEN** the output includes one auditable row per issue plus level totals,
  separately counted skipped rows, confidence gaps, and the inspected `main`
  SHA for issues that proceeded to classification
