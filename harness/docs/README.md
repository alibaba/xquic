# Harness Documentation

This directory contains informative maps and guides for understanding and
maintaining the harness. It is organized by semantic role rather than reader:
the same material may be consumed by maintainers, contributors, or agents.

- `structure-map.md`: where harness responsibilities live.
- `change-guide.md`: what to inspect and validate for each harness change.

Authoritative requirements live under `harness/spec/`. Design rationale lives
under `harness/decisions/`. The governing boundary between those roles is in
the [harness behavior specification](../spec/harness-behavior.md), and the
machine-readable role mapping is in the
[harness manifest](../spec/harness-manifest.yml).

## Structure Model

Harness content is organized by two independent scope axes:

| Scope | Public / Open | Private / Closed |
|-------|---------------|------------------|
| Common | Reusable, tool-neutral harness patterns that can be shared across repositories. | Organization-wide or environment-specific material that is not committed here. |
| Custom | XQUIC-specific public routing, validation, and repository conventions. | XQUIC-specific private runbooks, credentials, service names, or local adapters. |

The source and privacy rules for these quadrants are defined normatively in
the [harness behavior specification](../spec/harness-behavior.md).

## Loading Model

Loading is independent from document authority. The manifest describes five
operational layers:

1. Strong injection: `AGENTS.md` provides short routing and stop conditions.
2. On-demand reading: specifications, decisions, pipelines, and skills are
   loaded for matching tasks.
3. Machine mapping: `harness/spec/harness-manifest.yml` maps paths, modules,
   documents, tests, feature flags, and validation levels.
4. Explanation: `harness/docs/` provides optional maps and guidance.
5. Self-checks: harness scripts and workflow wiring detect structural drift.

Task-local evidence is outside these durable layers. Its authoritative storage
contract is in [run-artifacts.md](../spec/run-artifacts.md).

## Read Order

For harness structure changes:

1. `AGENTS.md`
2. `harness/README.md`
3. `harness/spec/harness-behavior.md`
4. `harness/docs/change-guide.md`
5. `harness/spec/harness-manifest.yml`
6. The affected `spec/`, `pipelines/`, `skills/`, or `scripts/` files

Run `bash harness/scripts/xqc_harness_check.sh` after changes.
