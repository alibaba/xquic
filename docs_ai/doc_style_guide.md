# Agent Documentation Style Guide

Use this guide when adding or editing comments, `docs_ai/` files, API docs, test notes, PR summaries, or final reports. The goal is to keep agent output useful, source-backed, and short.

## Core Rule

Write the minimum durable context the next engineer or agent needs to avoid a wrong edit.

Prefer:
- Source-backed facts over general explanations.
- Invariants, decisions, and commands over prose summaries.
- Links to existing docs over copied background.
- Updating one authoritative doc over repeating the same rule in many places.

Avoid:
- Explaining obvious code flow.
- Repeating file lists already covered by `docs_ai/codebase_index.md`.
- Repeating module summaries already covered by `docs_ai/code_map.md`.
- Creating broad templates unless they will be reused.
- Adding speculative rationale without source evidence.

## Code Comments

Add a comment only when it explains one of these:

- Why the code is non-obvious.
- A protocol/RFC constraint.
- A lifetime, ownership, unit, ordering, or concurrency invariant.
- A compatibility or feature-gate reason.
- A test-only helper or deliberate workaround.

Do not add comments that restate what the next line does.

Length:
- Inline comment: 1 line.
- Block comment: 2-4 lines.
- Longer explanation belongs in `docs_ai/behavior_specs.md` or `docs_ai/decision_records.md`.

## Agent Docs

Use the narrowest durable doc:

| Need | Target |
|---|---|
| Where code lives | `docs_ai/code_map.md` |
| What changes require reading/updating/testing | `docs_ai/change_map.md` |
| Behavior or invariant to preserve | `docs_ai/behavior_specs.md` |
| Why a design choice was made | `docs_ai/decision_records.md` |
| Build/test validation | `/validate` skill; diagnostics in `docs_ai/testing/test_guide.md` |
| Full file inventory | `docs_ai/codebase_index.md` |

Size targets:
- New section: 3-7 bullets.
- New change-map entry: only paths, obligations, validation, and decision trigger.
- New behavior spec: contract, call path if needed, validation.
- New decision record: context, decision, consequences, update trigger, evidence.

## Required Pruning Pass

Before finishing any doc/comment change:

1. Remove duplicated facts already present in a more authoritative doc.
2. Replace long explanations with a link to the source file or existing doc.
3. Delete speculative text that was not confirmed from source.
4. Check whether a comment can be replaced by clearer naming or simpler code.
5. Keep final reports to changed files, behavior impact, validation, and blockers.

## When To Say "No Doc Update"

It is acceptable to skip documentation updates when:

- The change is purely mechanical and does not change behavior, API, architecture, tests, or commands.
- The existing docs already describe the behavior accurately.
- The change is local cleanup with no durable rule for future agents.

When skipping, state the reason briefly in the final response.
