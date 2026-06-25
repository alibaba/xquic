# Auto-Doc Lookup: Code-to-Documentation Mapping

Source: `docs_ai/`

When starting any task, use this mapping to determine which documentation to read and which to update.

## Lookup Table: Source Path -> Documentation

**Given a source file path, read the corresponding docs BEFORE modifying code, and update them AFTER.** Also inspect `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, and `docs_ai/decision_records.md`; update those files when their maintenance contracts are triggered.

| Source Path Pattern | Read These Docs | Update These Docs | Validation |
|---|---|---|---|
| `include/xquic/xquic.h` | `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, `docs_ai/architecture/overview.md`, `docs/API.md` | `docs/API.md`, `docs_ai/architecture/overview.md`, `docs_ai/behavior_specs.md`, `docs_ai/decision_records.md` when contract/rationale changes | `/validate` (full) |
| `include/xquic/xqc_http3.h` | `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, `docs_ai/architecture/overview.md`, `docs/API.md` | `docs/API.md`, `docs_ai/architecture/overview.md`, `docs_ai/behavior_specs.md`, `docs_ai/decision_records.md` when contract/rationale changes | `/validate` (full) |
| `include/xquic/xqc_errno.h` | `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, `docs_ai/architecture/overview.md` | `docs_ai/architecture/overview.md`, `docs_ai/behavior_specs.md`, `docs_ai/decision_records.md` when error contract changes | `/validate` (full) |
| `src/transport/*` | `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, `docs_ai/architecture/overview.md`, `docs_ai/architecture/module_dependency.md` | `docs_ai/architecture/module_dependency.md`, `docs_ai/behavior_specs.md`, `docs_ai/decision_records.md` when behavior/rationale changes | `/validate` |
| `src/transport/scheduler/*` | `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, `docs_ai/architecture/overview.md` | `docs_ai/architecture/module_dependency.md`, `docs_ai/behavior_specs.md`, `docs_ai/decision_records.md` when scheduling semantics change | `/validate` |
| `src/transport/reinjection_control/*` | `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, `docs_ai/architecture/overview.md` | `docs_ai/architecture/module_dependency.md`, `docs_ai/behavior_specs.md`, `docs_ai/decision_records.md` when reinjection semantics change | `/validate` |
| `src/transport/fec_schemes/*` | `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, `docs_ai/architecture/module_dependency.md` | `docs_ai/architecture/module_dependency.md`, `docs_ai/behavior_specs.md`, `docs_ai/decision_records.md` when FEC behavior/rationale changes | `/validate` |
| `src/http3/*` | `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, `docs_ai/architecture/overview.md` | `docs_ai/architecture/module_dependency.md`, `docs_ai/behavior_specs.md`, `docs_ai/decision_records.md` when HTTP/3 semantics change | `/validate` |
| `src/http3/qpack/*` | `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, `docs_ai/architecture/overview.md` | `docs_ai/architecture/module_dependency.md`, `docs_ai/behavior_specs.md`, `docs_ai/decision_records.md` when QPACK semantics change | `/validate` |
| `src/tls/*` | `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, `docs_ai/architecture/overview.md` | `docs_ai/architecture/module_dependency.md`, `docs_ai/behavior_specs.md`, `docs_ai/decision_records.md` when TLS semantics change | `/validate` |
| `src/tls/boringssl/*` | `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, `docs_ai/architecture/overview.md`, `docs_ai/build/build_guide.md` | `docs_ai/architecture/module_dependency.md`, `docs_ai/behavior_specs.md`, `docs_ai/decision_records.md` when backend semantics change | `/validate` |
| `src/tls/babassl/*` | `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, `docs_ai/architecture/overview.md`, `docs_ai/build/build_guide.md` | `docs_ai/architecture/module_dependency.md`, `docs_ai/behavior_specs.md`, `docs_ai/decision_records.md` when backend semantics change | `/validate` |
| `src/congestion_control/*` | `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, `docs_ai/architecture/overview.md` | `docs_ai/architecture/module_dependency.md`, `docs_ai/behavior_specs.md`, `docs_ai/decision_records.md` when CC semantics change | `/validate` |
| `src/common/*` | `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, `docs_ai/architecture/module_dependency.md` | `docs_ai/architecture/module_dependency.md`, `docs_ai/behavior_specs.md`, `docs_ai/decision_records.md` when utility semantics change | `/validate` |
| `tests/unittest/*` | `docs_ai/change_map.md`, `tests/CLAUDE.md` | `docs_ai/change_map.md` when validation mapping changes | `/validate` |
| `tests/test_client.c` / `tests/test_server.c` | `docs_ai/change_map.md`, `tests/CLAUDE.md` | `docs_ai/change_map.md` when integration mapping changes | `/validate` |
| `demo/*` | `docs/API.md` | (none unless API usage pattern changes) | `/validate --build` |
| `mini/*` | `docs/API.md` | (none unless API usage pattern changes) | `/validate --build` |
| `CMakeLists.txt` | `docs_ai/build/build_guide.md` | `docs_ai/build/build_guide.md` | `/validate` (full) |
| `cmake/*` | `docs_ai/build/build_guide.md` | `docs_ai/build/build_guide.md` | `/validate --build` |
| `scripts/*` | `.claude/skills/validate/SKILL.md` | (none unless validation policy changes) | Run affected script |

## Lookup Procedure (Execute at Stage 1: Requirement Analysis)

```
1. Identify which source files will be modified
2. Look up each file path in the table above
3. READ the corresponding "Read These Docs" files to understand context
4. Check maintenance contracts in `docs_ai/code_map.md`, `docs_ai/change_map.md`, `docs_ai/behavior_specs.md`, and `docs_ai/decision_records.md`
5. After implementation, UPDATE the corresponding "Update These Docs" files
6. Use `/validate` to auto-detect the smallest validation scope based on changed files
```

## Cross-Cutting Concerns

When a change spans multiple modules, read ALL relevant docs. Specifically:
- **Public API change** -> Always read `docs_ai/architecture/overview.md` + `docs/API.md`
- **New module/file** -> Update `docs_ai/architecture/module_dependency.md` + `docs_ai/codebase_index.md`
- **Build system change** -> Read and update `docs_ai/build/build_guide.md`
- **New test pattern** -> See `tests/CLAUDE.md` and `.claude/skills/validate/SKILL.md`
- **New congestion control algorithm** -> Update `docs_ai/architecture/overview.md` (CC section) + `docs_ai/build/build_guide.md` (feature flags)

## Documentation Structure

All agent documentation lives under `docs_ai/`. Original project documentation lives under `docs/`.

```
docs_ai/
  agent_guide.md                   # Agent workflow notes and context-preservation guidance
  doc_style_guide.md               # Minimalist rules for generated comments and documentation
  dev_pipeline.md                  # Development pipeline, enforcement rules
  bugfix_pipeline.md               # Bug fix pipeline, root cause analysis, unit test verification
  validation_guide.md              # Validation policy entry point (points to /validate skill)
  code_map.md                      # Agent-facing module and call-path map
  change_map.md                    # Change-family read/update/validation obligations
  behavior_specs.md                # Behavior contracts and invariants to preserve
  decision_records.md              # Ongoing architecture and workflow decisions
  # Issue triage is handled by the /issue skill: .claude/skills/issue/SKILL.md
  architecture/
    overview.md                    # System architecture, layers, entry points, plugin model
    module_dependency.md           # Module dependency matrix, impact analysis guide
  build/
    build_guide.md                 # Prerequisites, SSL backends, CMake options, platform notes
  testing/
    test_guide.md                  # Test architecture, commands, pass criteria, diagnostics
  codebase_index.md                # Full source file tree with annotations
  auto_doc_lookup.md               # This file: code-to-doc mapping

docs/                              # Original project documentation (do not move to docs_ai/)
  API.md                           # Public API documentation
  Platforms.md                     # Platform support details
  Features.md                      # Feature documentation (qlog, etc.)
  FAQ.md                           # Frequently asked questions
  docs-zh/                         # Chinese documentation
  translation/                     # RFC translation documents
  images/                          # Project images
```

## Documentation Maintenance Rules

1. **Code change -> Doc change**: Every code modification that changes behavior, API, or architecture MUST have a corresponding documentation update. Use the lookup table above to find which docs to update.
2. **New file -> Index update**: When adding new source files, update `docs_ai/codebase_index.md` and `docs_ai/architecture/module_dependency.md`.
3. **New test -> Validate skill update**: When adding new test patterns, see `tests/CLAUDE.md` and `.claude/skills/validate/SKILL.md`.
4. **Doc-first for API changes**: Public API changes should be documented before or alongside implementation.
5. **Keep `docs/` and `docs_ai/` separate**: `docs/` contains original project documentation. `docs_ai/` contains agent workflow and analysis documents.
6. **Knowledge-base upkeep**: Update `code_map`, `change_map`, `behavior_specs`, and `decision_records` whenever their maintenance contracts are triggered.
