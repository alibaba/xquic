# Harness Structure Map

Use this informative map to locate harness responsibilities before editing.
Authority and document-role rules live in
`harness/spec/harness-behavior.md` and
`harness/spec/harness-manifest.yml`.

## Public Common

Reusable harness shape that should remain project-neutral:

- `harness/README.md`: portable layout, checks, naming, and portability.
- `harness/docs/`: explanatory structure and change guidance.
- `harness/decisions/`: durable design rationale.
- `harness/pipelines/`: ordered workflows.
- `harness/skills/*/SKILL.md`: reusable task procedures.
- `harness/scripts/xqc_harness_check.sh`: structure and synchronization checks.
- `harness/scripts/harness_manifest_check.rb`: manifest schema and reference
  checks.
- `harness/spec/harness-behavior.md`: normative harness invariants.
- `harness/spec/doc-style.md`: durable documentation and comment rules.
- `harness/spec/run-artifacts.md`: task evidence directory contract.

## Public Custom

XQUIC-specific committed guidance:

- `AGENTS.md`: root discovery and hard constraints.
- `harness/spec/PROJECT_INSTRUCTIONS.md`: task routing and project contracts.
- `harness/spec/architecture.md`: architecture and protocol boundaries.
- `harness/spec/validation.md`: validation levels and evidence.
- `harness/spec/pull-requests.md`: pull request evidence contract.
- `harness/spec/harness-manifest.yml`: canonical route, feature, and document
  role map.
- `harness/spec/openspec.md`: long-task OpenSpec integration.

## Private Common

Optional organization-wide adapters can be placed under
`harness/private/common/`, including local organization rules, network
assumptions, or tool adapters.

## Private Custom

Optional XQUIC-specific context can be placed under
`harness/private/xquic/`, including local service names, credentials, internal
dashboards, or private runbooks.

The source boundaries governing both private categories are defined in
`harness/spec/harness-behavior.md`.

## Test Routing

- `case_test/manifest.yml`: endpoint case group metadata for mapping changed
  paths to legacy `case_print_result` names.
- `case_test/lib/selector.rb`: list, inventory, and dry-run selector
  implementation used by `scripts/case_test.sh`.
- `case_test/<module>/`: future module-owned endpoint case runners.
- `tests/unittest/manifest.yml`: unit-test suite ownership and planned port
  ranges for opt-in parallel execution.

The authoritative module and feature map remains
`harness/spec/harness-manifest.yml`.
