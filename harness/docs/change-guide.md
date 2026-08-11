# Harness Change Guide

Use this informative guide after locating the affected area in
`structure-map.md`. Apply the normative constraints in
`harness/spec/harness-behavior.md` throughout the change.

## Common Public Harness Change

Examples:

- Add a reusable skill.
- Change harness check routing.
- Change generic schema checks.
- Change task-local evidence layout.

Read:

- `harness/README.md`
- `harness/spec/harness-behavior.md`
- `harness/spec/doc-style.md` when adding or reshaping durable documents.
- `harness/spec/run-artifacts.md` when evidence directories or logs change.
- Affected `harness/skills/*/SKILL.md`, `harness/pipelines/*`, or scripts.

Update when affected:

- `harness/README.md` for layout or entry-point changes.
- `harness/spec/harness-manifest.yml` for routing or document-role changes.
- `harness/scripts/xqc_harness_check.sh` for new enforceable structure.

Validate:

- `bash harness/scripts/xqc_harness_check.sh`

## Custom Public XQUIC Harness Change

Examples:

- Change XQUIC validation evidence.
- Change branch or PR guidance.
- Change module or feature routing.

Read:

- `harness/spec/PROJECT_INSTRUCTIONS.md`
- `harness/spec/harness-manifest.yml`
- Affected `harness/spec/*.md`

Update when affected:

- `AGENTS.md` for root discovery changes.
- `harness/spec/harness-manifest.yml` for module, feature, documentation, or
  validation routing changes.
- `harness/decisions/records.md` for a durable design decision.
- `harness/spec/doc-style.md` for documentation-governance changes.

Validate:

- `bash harness/scripts/xqc_harness_check.sh`

## Private Extension Change

Examples:

- Add local adapter notes.
- Add private service runbook pointers.

Apply the private-extension rules in
`harness/spec/harness-behavior.md#source-boundaries`, then run:

- `bash harness/scripts/xqc_harness_check.sh`

## Endpoint Test Routing Change

Examples:

- Add or reclassify endpoint case-test group metadata.
- Add a native endpoint case registration to an existing group runner.
- Move endpoint case bodies from the legacy full suite into module runners.

Read:

- `harness/spec/validation.md`
- `harness/spec/harness-manifest.yml`
- `case_test/manifest.yml`
- `case_test/README.md`

Update when affected:

- `case_test/manifest.yml` for endpoint group metadata and stable shard ports.
- `case_test/<module>/` when native case registrations or selected endpoint
  execution change.
- `harness/spec/harness-manifest.yml` for test-routing entry points.
- `harness/spec/validation.md` when validation contracts change.

Validate:

- `bash harness/scripts/xqc_harness_check.sh`
- `bash scripts/case_test.sh --inventory`
- `bash scripts/case_test.sh --from-path <path> --dry-run`
- `bash scripts/case_test.sh --execute --from-path <path>` only for groups
  marked `execution: implemented`.
- `case_test/lib/architecture_check.rb "$(pwd)" --all` after runner,
  selector, or compatibility-wrapper changes.
