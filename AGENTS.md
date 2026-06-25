# xquic_ops Project Rules

> Universal rules and document index for Codex and other coding agents. Read this file first in every session.

## Task Routing

| Task Type | Examples | Required Entry Point |
|-----------|----------|----------------------|
| **Goal (long task)** | `/goal <desc>`, "background task" | `scripts/goal.sh "<description>"` |
| **Code change** | "Add feature X", "Refactor Y" | `docs_ai/dev_pipeline.md` |
| **Bug fix** | "Fix bug in Y", "Unit test X fails" | `docs_ai/bugfix_pipeline.md` |
| **Test execution** | "Run tests", "Verify X works" | `docs_ai/validation_guide.md` |
| **Build** | "Build the project", "Rebuild with flag" | `docs_ai/validation_guide.md` |
| **Query / Analysis** | "How does X work?", "Explain this module" | Read the relevant code and docs. No workflow document is required unless the task becomes a code/build/test change. |

## Git Branch Policy

- **NEVER push directly to `main` or `master` branch on remote.** All changes must go through a feature/dev branch and be merged via Pull Request.
- Development work should be done on `dev/agent` or other feature branches.
- Use `gh pr create` to submit changes for review. Do not use `git push origin main` or `git push origin master`.

## Global Constraints

1. **Pipeline-first execution**: At task start, choose the task type from **Task Routing**. Read the matching Required Entry Point document in full before acting. Follow that document in order. After compaction or a new session, repeat this step.
2. **Code style**: Follow existing project conventions. Use consistent naming (snake_case or project prefix). Comments explain "why", not "what".
3. **Code-doc sync**: When modifying any module, update corresponding docs using `docs_ai/auto_doc_lookup.md` for mapping. When changing public APIs, update the interface documentation. When adding new files, update `docs_ai/codebase_index.md`.
4. **Evidence-based reasoning**: Read the relevant code path before claiming behavior or applying a fix. For bugs, confirm the cause in source before editing. If multiple causes are possible, inspect each plausible path. If a fix fails, re-read the code before adding another fix.
5. **Post-modification verification**: After every code or documentation change, re-read the modified path and verify the change is logically consistent with the requirement and adjacent code. Each pipeline document contains specific verification checklists at modification stages -- follow them before advancing to build/test.
6. **Validation mapping**: Codex decides whether build/test execution is needed for the task. When build/test execution is needed or requested, follow `docs_ai/validation_guide.md` for the commands, forbidden scripts, and smallest correct test mapping.
7. **AI knowledge-base upkeep**: For code changes, inspect `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, and `docs_ai/decision_records.md`. Update them when the module map, change obligations, behavior contract, or design rationale changes. Do not leave stale guidance for future agents.
8. **Documentation minimalism**: Follow `docs_ai/doc_style_guide.md` for all comments and docs. Prefer source-backed, non-duplicative, durable facts. Remove redundant generated prose before finishing.

## Compact Instructions

When compacting context, preserve:

- Current task goal, task type, and selected pipeline document.
- Hard constraints from this file and the selected pipeline document.
- Current git branch, dirty files, user-owned changes, and any explicit user-requested operation order.
- Files already inspected or edited, docs still needing sync, builds/tests already run, and remaining verification steps.
- Whether `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, or `docs_ai/decision_records.md` were inspected or still need updates.
- Exact failing commands, key error snippets, and hypotheses already confirmed or rejected.

If any required context is uncertain after compaction, follow **Pipeline-first execution** again before proceeding.

## Document Index

| Topic | Document |
|-------|----------|
| **Development pipeline** | **`docs_ai/dev_pipeline.md`** |
| **Bug fix pipeline** | **`docs_ai/bugfix_pipeline.md`** |
| **Build/test validation policy** | **`docs_ai/validation_guide.md`** |
| **Test guide (mapping, execution)** | **`docs_ai/testing/test_guide.md`** |
| Agent workflow notes | `docs_ai/agent_guide.md` |
| Agent documentation style | `docs_ai/doc_style_guide.md` |
| AI code map | `docs_ai/code_map.md` |
| AI change map | `docs_ai/change_map.md` |
| AI behavior specs | `docs_ai/behavior_specs.md` |
| AI decision records | `docs_ai/decision_records.md` |
| Build guide | `docs_ai/build/build_guide.md` |
| Full codebase file tree | `docs_ai/codebase_index.md` |
| Source-path-to-doc mapping | `docs_ai/auto_doc_lookup.md` |
| System architecture | `docs_ai/architecture/overview.md` |
| Module dependencies | `docs_ai/architecture/module_dependency.md` |


## Project Dependencies

- **Compiler**: GCC or Clang with C11 support (C++17 for BoringSSL build)
- **CMake**: >= 3.10
- **SSL Backend**: BoringSSL (recommended for macOS) or BabaSSL/Tongsuo
- **Go**: >= 1.18 (BoringSSL build dependency)
- **Ninja**: any version (BoringSSL build dependency)
- **libevent**: >= 2.0.21 (test/demo binaries)
- **CUnit**: >= 2.1 (unit test framework)
- **OpenSSL CLI**: for generating test TLS certificates

See `docs_ai/build/build_guide.md` for full build instructions and platform-specific notes.
