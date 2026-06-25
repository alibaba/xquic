# AI Decision Records

Source: project history, current docs, source inspection

This document records decisions that future agents must preserve or intentionally revisit. It is not a changelog; write entries only for decisions with ongoing design or compatibility impact.

## Maintenance Contract

Add or update a decision record when a task:

- Chooses between two plausible designs.
- Changes public API, protocol behavior, default behavior, feature gates, validation policy, or compatibility behavior.
- Leaves a known limitation, workaround, or deliberate non-goal.
- Explains why a test/harness/document structure exists.

Do not add entries for routine typo fixes, local refactors with no behavior effect, or obvious implementation details.

## Decision Entry Template

```md
### ADR-XXXX: <short title>

Status: Proposed | Accepted | Superseded by ADR-YYYY

Date: YYYY-MM-DD

Context:
- What problem or ambiguity existed.

Decision:
- What the project chose.

Consequences:
- Benefits, costs, compatibility impact, and validation implications.

Update triggers:
- What future changes must revisit this decision.

Evidence:
- Source files, docs, tests, or commands used.
```

## Active Decisions

### ADR-0001: Keep agent-maintained docs under `docs_ai/`

Status: Accepted

Date: 2026-06-25

Context:
- The original project docs live under `docs/`.
- Agent workflows need operational maps, task routing, validation mapping, behavior specs, and maintenance rules that are not necessarily user-facing project documentation.

Decision:
- Keep agent-maintained workflow and analysis documentation under `docs_ai/`.
- Keep original project documentation under `docs/`.
- Public API behavior still updates `docs/API.md` when the public contract changes.

Consequences:
- Agents have a dedicated place for execution-oriented docs.
- Public docs and agent docs must be kept in sync for API changes.

Update triggers:
- Revisit if docs are consolidated or if generated documentation replaces manual agent docs.

Evidence:
- `AGENTS.md`
- `docs_ai/auto_doc_lookup.md`
- `docs_ai/dev_pipeline.md`

### ADR-0002: Use pipeline-first task routing for agent work

Status: Accepted

Date: 2026-06-25

Context:
- Independent agent work needs predictable entry points for code change, bug fix, build, test, analysis, and long-running goals.
- Without routing, agents can skip root-cause analysis, docs updates, or validation evidence.

Decision:
- `AGENTS.md` is the first file for each session.
- Code changes use `docs_ai/dev_pipeline.md`.
- Bug fixes use `docs_ai/bugfix_pipeline.md`.
- Build/test work uses `/validate` skill.
- Long-running goals use `scripts/goal.sh`.

Consequences:
- Every task starts with an explicit workflow.
- Pipeline docs can enforce post-modification review and validation evidence.

Update triggers:
- Revisit if task categories change, if `scripts/goal.sh` contract changes, or if another orchestration harness replaces these entry points.

Evidence:
- `AGENTS.md`
- `docs_ai/dev_pipeline.md`
- `docs_ai/bugfix_pipeline.md`
- `docs_ai/validation_guide.md`

### ADR-0003: Split code map, change map, behavior specs, and decision records

Status: Accepted

Date: 2026-06-25

Context:
- A single file cannot efficiently serve navigation, change planning, behavior preservation, and design rationale.
- Agents need a stable route from request to code path to validation and maintenance obligations.

Decision:
- `docs_ai/code_map.md` answers "where is the behavior?"
- `docs_ai/change_map.md` answers "what else must be read, updated, and validated?"
- `docs_ai/behavior_specs.md` answers "what behavior must not drift?"
- `docs_ai/decision_records.md` answers "why is this the chosen design?"

Consequences:
- The docs are more modular and easier to update incrementally.
- Pipelines must require agents to check these files during edits.

Update triggers:
- Revisit if these files become redundant with generated metadata or if maintenance cost exceeds value.

Evidence:
- `docs_ai/code_map.md`
- `docs_ai/change_map.md`
- `docs_ai/behavior_specs.md`
- `docs_ai/decision_records.md`

### ADR-0004: Use `/validate` skill as the validation entry point

Status: Accepted (supersedes original ADR-0004)

Date: 2026-06-25

Context:
- Original ADR-0004 established `docs_ai/validation_guide.md` as the validation policy entry point, with test mapping in `docs_ai/testing/test_guide.md`.
- This created scattered knowledge: the AI had to read multiple docs, guess test scope, and construct commands manually.

Decision:
- Replace the doc-based validation approach with a two-layer `/validate` skill: deterministic shell script (`scripts/xqc_validate.sh`) for repeatable operations + AI skill (`.claude/skills/validate/SKILL.md`) for dynamic scope decisions.
- `docs_ai/validation_guide.md` becomes a stub pointing to `/validate`.
- `docs_ai/testing/test_guide.md` retains test architecture, commands, and diagnostics only (feature-to-test mapping moved to the skill).
- All pipelines, skills, and docs route validation through `/validate`.

Consequences:
- Change detection, module mapping, and test scope are deterministic and repeatable.
- The AI focuses on targeted e2e test selection rather than reconstructing the full workflow each time.
- `docs_ai/validation_guide.md` is retained for backwards compatibility but is a stub.

Update triggers:
- Revisit if the shell script's file-to-module mapping becomes stale or if CI integrates the script directly.

Evidence:
- `scripts/xqc_validate.sh`
- `.claude/skills/validate/SKILL.md`
- `docs_ai/validation_guide.md` (stub)

### ADR-0005: Preserve SSL backend isolation

Status: Accepted

Date: 2026-06-25

Context:
- XQUIC supports BoringSSL and BabaSSL/Tongsuo through backend-specific implementation directories.
- Core TLS code must remain portable across backends.

Decision:
- Core TLS code depends on `xqc_ssl_if.h`.
- Backend-specific includes and library calls stay inside `src/tls/boringssl/` and `src/tls/babassl/`.
- The active backend is selected by CMake `SSL_TYPE`.

Consequences:
- Backend changes can be validated in isolation when the abstraction contract is unchanged.
- Abstraction changes require broader TLS and transport validation.

Update triggers:
- Revisit when adding another SSL backend, changing `SSL_TYPE` defaults, or changing `xqc_ssl_if.h`.

Evidence:
- `src/tls/CLAUDE.md`
- `src/tls/xqc_ssl_if.h`
- `CMakeLists.txt`

### ADR-0006: Treat behavior-changing bug fixes as test-backed changes

Status: Accepted

Date: 2026-06-25

Context:
- Bug fixes that only patch symptoms can regress.
- Independent agent work needs evidence that the fixed path is covered.

Decision:
- Bug fixes must include a regression test or cite an existing test that exercises the exact fixed path.
- If validation cannot run, the blocker and closest evidence must be reported.

Consequences:
- Fixes carry stronger regression protection.
- Some changes may require adding test infrastructure before being considered complete.

Update triggers:
- Revisit only if a separate automated regression harness guarantees equivalent coverage.

Evidence:
- `docs_ai/bugfix_pipeline.md`
- `docs_ai/validation_guide.md`
