# Documentation Style

Use this guide when adding durable comments or repository documentation.

## Purpose

Documentation should preserve context that remains useful after the current
task. Avoid progress notes, issue-specific narration, repeated command output,
or summaries that can be regenerated from nearby code.

## What To Write

- Record behavior contracts, boundaries, commands, validation obligations, and
  decisions that future agents or maintainers must know.
- Prefer links to canonical sources over copied tables or duplicated maps.
- Keep path, module, docs, tests, and feature-gate routing in
  `harness/spec/harness-manifest.yml`.
- Keep harness design rationale in `harness/ai_docs/decision_records.md`.
- Keep behavior invariants in `harness/ai_docs/behavior_specs.md`.

## Comments

- Add implementation comments only for non-obvious invariants, protocol rules,
  lifetime constraints, or compatibility requirements.
- For protocol behavior, cite the exact RFC or draft section when it materially
  explains the invariant.
- Do not comment mechanics that are clear from the code.

## Public And Private Context

Committed docs are public/open unless explicitly marked as templates. Private
or environment-specific context belongs under ignored `harness/private/` and
must not be required for ordinary public tasks.

## Review Checklist

- The new text has a durable reader.
- It does not duplicate manifest routing or validation tables.
- It does not encode a one-off task, issue, branch, or local environment.
- Relative links and referenced commands still resolve.
