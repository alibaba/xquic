---
name: harness-review
description: Review XQUIC harness structure for bloat, duplicated facts, trigger overlap, reference drift, and missing hard checks. Use when changing AGENTS.md, harness specs, pipelines, skills, setup scripts, validation routing, or when asked to audit harness design.
---

# Harness Review

This skill is a review gate for harness structure. It is usually read-only:
produce findings first, then edit only when the user asks for fixes.

## Review Inputs

1. Read `AGENTS.md`, `harness/README.md`, and
   `harness/spec/harness-behavior.md`.
2. Read `harness/docs/change-guide.md` for the affected harness change type.
3. Read the changed specs, pipelines, skills, setup scripts, or validation
   scripts.
4. Run `bash harness/scripts/xqc_harness_check.sh` after any committed-harness change.

## Checks

- Strong injection stays small and points to durable sources instead of
  repeating them.
- New procedures live in skills or pipelines, not root instructions.
- Machine mappings stay in `harness/spec/harness-manifest.yml`.
- Normative requirements stay in `harness/spec/`; informative documents do
  not create independent requirements; rationale stays in
  `harness/decisions/`.
- Document authority is independent of whether a human or agent consumes it.
- Skill descriptions declare a narrow trigger. Skill bodies declare ownership
  boundaries and avoid competing with existing skills.
- Repeated requirements have one source of truth; other files link to it.
- "Always" or "never" requirements that must be reliable have a script, hook,
  schema check, or permission guard where practical.
- Local adapters such as `.claude/` and `.agents/` do not become required
  committed sources.

## Output

Use this order:

1. Findings: bloat, duplicate facts, overlapping triggers, broken references,
   missing hard checks.
2. Decisions needed: only items that require user policy choice.
3. Proposed movement: keep, merge, delete, move to manifest, move to spec, move
   to skill, or move to script/hook.
4. Validation: exact harness checks run or still needed.
