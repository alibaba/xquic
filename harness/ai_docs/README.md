# Harness AI Docs

This directory is the agent-facing map for the harness itself. It follows the
durable-doc split used by earlier AI docs:

- `structure_map.md`: where harness responsibilities live.
- `change_map.md`: what to read, update, and validate for each harness change.
- `behavior_specs.md`: invariants the harness must preserve.
- `decision_records.md`: why the current structure exists.

## Structure Model

Harness content is organized by two axes:

| Axis | Public / Open | Private / Closed |
|------|----------------|------------------|
| Common | Reusable, tool-neutral harness patterns that can be shared across repositories. | Organization-wide or environment-specific rules that should not be committed here. |
| Custom | XQUIC-specific public routing, validation, and repository conventions. | XQUIC-specific private runbooks, credentials, service names, or local adapters. |

Committed files under `harness/` are public/open unless a document explicitly
marks itself as a template for private use. Closed-source content belongs in
ignored `harness/private/`, not in committed docs.

## Loading Layers

1. Strong injection layer: `AGENTS.md` keeps only task routing, entry points,
   stop conditions, validation gates, and document-sync principles.
2. On-demand reading layer: `harness/pipelines/dev-pipeline.md`,
   `harness/skills/validate/SKILL.md`, `harness/spec/doc-style.md`, and
   selected skills hold detailed procedures.
3. Machine mapping layer: `harness/spec/harness-manifest.yml` maps paths to
   modules, docs, tests, feature flags, and validation levels.
4. Explanation layer: `structure_map.md`, `behavior_specs.md`, and
   `decision_records.md` keep durable context without repeating workflows.
5. Self-check layer: `harness/scripts/xqc_harness_check.sh` and the GitHub workflow
   detect drift across AGENTS, docs, skills, scripts, and manifest routing.

Task-local evidence is not part of the durable explanation layer. Store it in
`build/harness/runs/<task-id>/` using `harness/scripts/harness_trace.sh init
<task-id>`.

## Read Order

For harness structure changes:

1. `AGENTS.md`
2. `harness/README.md`
3. `harness/ai_docs/README.md`
4. `harness/ai_docs/change_map.md`
5. `harness/spec/harness-manifest.yml`
6. The affected `spec/`, `pipelines/`, `skills/`, or `scripts/` files

Run `bash harness/scripts/xqc_harness_check.sh` after changes.
