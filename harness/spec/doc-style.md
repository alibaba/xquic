# Documentation Specification

This specification governs durable comments and repository documentation.

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
- Keep authoritative requirements and behavior invariants under
  `harness/spec/`.
- Keep informative maps, explanations, and maintenance guidance under
  `harness/docs/`.
- Keep design rationale under `harness/decisions/`. Reflect any ongoing
  requirement created by a decision in the owning specification.

## Authority

- Classify content by semantic role rather than intended reader or tool.
- Specifications may define requirements and are the source of truth for their
  scope.
- Informative documents explain or navigate existing sources and must not
  introduce independent requirements.
- Decision records explain why a design was chosen; they do not replace the
  resulting specification.
- Resolve conflicts using `harness/spec/harness-behavior.md` and update stale
  informative text in the same change.

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
- Its path matches its normative, informative, or decision role.
- It does not duplicate manifest routing or validation tables.
- It does not encode a one-off task, issue, branch, or local environment.
- Relative links and referenced commands still resolve.
