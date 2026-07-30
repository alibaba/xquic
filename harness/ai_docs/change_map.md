# Harness Change Map

Use this file after locating the affected area in `structure_map.md`.

## Common Public Harness Change

Examples:
- Add a reusable skill.
- Change setup/link registration.
- Change generic schema checks.
- Change task-local evidence layout.

Read:
- `harness/README.md`
- `harness/ai_docs/behavior_specs.md`
- `harness/spec/doc-style.md` when adding or reshaping durable docs.
- `harness/spec/run-artifacts.md` when evidence directories or logs change.
- Affected `harness/skills/*/SKILL.md`, `harness/pipelines/*`, or scripts.

Update:
- `harness/README.md` if layout or entry points change.
- `harness/spec/harness-manifest.yml` if routing changes.
- `harness/scripts/xqc_harness_check.sh` if a new harness source must be enforced.

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

Update:
- `AGENTS.md` when root discovery changes.
- `harness/spec/harness-manifest.yml` when module, feature, docs, or validation routing changes.
- `harness/ai_docs/decision_records.md` when the structure or policy changes.
- `harness/spec/doc-style.md` when the durable documentation rules change.

Validate:
- `bash harness/scripts/xqc_harness_check.sh`

## Private Extension Change

Examples:
- Add local adapter notes.
- Add private service runbook pointers.

Rules:
- Keep content under ignored `harness/private/`.
- Do not add private paths as mandatory committed dependencies.
- If a private assumption becomes required for open-source work, promote a
  sanitized public contract into `harness/`.

Validate:
- `bash harness/scripts/xqc_harness_check.sh` to ensure committed docs do not require private content.
