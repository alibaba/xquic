# Harness Structure Map

Use this file to locate harness responsibilities before editing.

## Public Common

Reusable harness shape that should remain project-neutral:

- `harness/README.md`: portable harness layout, setup, naming, and portability.
- `harness/pipelines/`: ordered workflows.
- `harness/skills/*/SKILL.md`: reusable task procedures with portable front matter.
- `harness/scripts/setup_harness.sh`: adapter registration into tool-native discovery paths.
- `harness/scripts/harness_trace.sh`: ignored task-local evidence directory setup.
- `harness/scripts/xqc_harness_check.sh`: structural drift checks.
- `harness/spec/doc-style.md`: reusable rules for concise durable docs and comments.
- `harness/spec/run-artifacts.md`: reusable task evidence directory contract.

## Public Custom

XQUIC-specific committed guidance:

- `AGENTS.md`: root discovery and hard constraints.
- `harness/spec/PROJECT_INSTRUCTIONS.md`: XQUIC task routing and project contracts.
- `harness/spec/architecture.md`: XQUIC architecture and protocol boundaries.
- `harness/spec/validation.md`: XQUIC validation levels and evidence.
- `harness/spec/pull-requests.md`: XQUIC pull request evidence contract.
- `harness/spec/harness-manifest.yml`: canonical route, module, feature, and validation map.
- `harness/spec/openspec.md`: long-task OpenSpec integration.

## Private Common

Private organization-wide adapters are optional and ignored:

- `harness/private/common/`: local organization rules, network assumptions, or tool adapters.

Committed harness files may mention this path as an optional extension point
but must not require it for open-source work.

## Private Custom

Private XQUIC-specific context is optional and ignored:

- `harness/private/xquic/`: local service names, credentials, internal dashboards, or private runbooks.

Agents may use it only when the user explicitly provides or authorizes that
context. Do not copy private details into committed docs.
