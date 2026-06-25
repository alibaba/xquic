# Development Pipeline

> Complete pipeline for code changes. Referenced by `AGENTS.md`.

All code changes MUST follow this pipeline. Validation scope is selected from `docs_ai/validation_guide.md` based on the actual change and user request.

```
Requirement Analysis -> Code Implementation -> Documentation Maintenance -> Validation Decision -> Complete
```

---

## Stage 1: Requirement Analysis

- Read and understand the task requirements
- Identify affected modules (see `docs_ai/codebase_index.md`)
- Locate the behavior in `docs_ai/code_map.md`
- Look up relevant docs, tests, and maintenance obligations (see `docs_ai/change_map.md` and `docs_ai/auto_doc_lookup.md`)
- Read existing behavior contracts in `docs_ai/behavior_specs.md`
- Identify affected public APIs


## Stage 2: Code Implementation

- Implement the change with minimal scope
- Follow existing code style: Follow existing project conventions. Use consistent naming (snake_case or project prefix). Comments explain "why", not "what".
- Follow `docs_ai/doc_style_guide.md` for any generated comments or documentation.


### Post-Modification Verification

After completing code changes, verify each modification against the requirement and the source code context:

1. **Re-read the modified code path** -- confirm the change addresses the root requirement, not a surface symptom
2. **Trace callers and callees** -- verify modified functions are called with expected arguments and return values are handled correctly by all callers
3. **Check boundary alignment** -- confirm the change is consistent with the assumptions of adjacent code (data types, value ranges, lifecycle)
4. If any check fails, revise the implementation before proceeding to Stage 3.

## Stage 3: Documentation Maintenance

- When modifying any module, update corresponding docs under `docs_ai/` (see `docs_ai/auto_doc_lookup.md` for mapping)
- When changing public APIs, update the interface documentation
- When adding new files, update `docs_ai/codebase_index.md`
- Update `docs_ai/code_map.md` when module ownership, entry points, feature gates, or important files change
- Update `docs_ai/change_map.md` when docs/test/update obligations change
- Update `docs_ai/behavior_specs.md` when behavior, invariants, lifecycle, callbacks, errors, feature gates, or compatibility semantics change
- Update `docs_ai/decision_records.md` when the change encodes a design choice, default behavior, compatibility tradeoff, or non-obvious rationale


### Post-Modification Verification

After updating documentation, verify consistency:

1. **Cross-reference with code** -- confirm documented APIs, parameters, and behaviors match the actual implementation
2. **Check stale content** -- verify no references to removed/renamed functions, flags, or files remain in the updated docs
3. **Check AI knowledge-base consistency** -- confirm `code_map`, `change_map`, `behavior_specs`, and `decision_records` either remain accurate or were updated
4. **Prune generated prose** -- remove duplicated, obvious, speculative, or non-durable documentation per `docs_ai/doc_style_guide.md`
5. If inconsistencies are found, fix them before proceeding to Stage 4.

## Stage 4: Validation Decision

Use `docs_ai/validation_guide.md` to decide whether build/test execution is needed.

- If validation is needed, run the smallest correct build/test set from the guide.
- If validation is skipped, state the reason.
- If validation cannot run, state the blocker and the closest completed check.

## Stage 5: Complete

- Documentation is updated when required.
- AI knowledge-base docs are updated or explicitly not needed.
- The validation decision is recorded with command evidence, skipped reason, or blocker.

---

## Enforcement Rules

1. **NEVER** consider a feature complete without validation evidence or a documented blocker. If an existing test already exercises the exact new code path, cite the specific test case name.
2. If build fails, fix compilation errors before anything else.
3. If tests fail, determine if the failure is caused by your change. If yes, fix it. If pre-existing, document it.
4. When modifying code that lacks tests, add or identify the smallest test that covers the changed path when feasible.
5. Do not make a behavior-changing code edit while leaving stale behavior specs or decision rationale.
