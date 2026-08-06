# Case Test Routing and Parallel Endpoint Execution

## Summary

Introduce a test-routing layer that lets agents and maintainers identify the
client-to-server case tests affected by a source change. Keep the existing
`scripts/case_test.sh` entry point compatible while moving case metadata and,
later, case implementations into a structured `case_test/` tree.

## Motivation

`scripts/case_test.sh` currently contains the full endpoint test flow in one
large script. The harness can route source paths to modules and feature gates,
but it cannot deterministically answer which endpoint cases should cover a
changed path.

This change adds machine-readable routing before large test movement. The
first goal is accurate indexing and compatibility. Selected endpoint execution
is opt-in and only schedules groups whose case bodies have been migrated.

## Scope

- Add an OpenSpec-owned design for case-test classification and selected
  endpoint execution.
- Add or update repository metadata so changed paths can route to relevant
  endpoint case tests.
- Preserve `scripts/case_test.sh` as the stable compatibility entry point.
- Add targeted case selection without making the legacy full case suite the
  default local gate.
- Add an opt-in parallel scheduler for migrated endpoint case groups.

## Out Of Scope

- Rewriting every endpoint case in one change.
- Making full case-test execution the default validation path.
- Changing public protocol behavior.
- Replacing CUnit or the existing `tests/test_client` and `tests/test_server`
  binaries.
- Changing `tests/run_tests` or unit-test execution.
- Vendoring OpenSpec source into this repository.

## Proposed Change

1. Create `case_test/manifest.yml` as the case-test metadata source of truth.
2. Reference that metadata from `harness/spec/harness-manifest.yml` instead of
   duplicating case-to-path maps in documentation.
3. Add `scripts/case_test.sh` selectors for listing, dry runs, modules,
   features, individual cases, and changed paths.
4. Move the legacy full-suite body under `case_test/legacy/` while preserving
   the public `scripts/case_test.sh` entry point.
5. Move case blocks from `case_test/legacy/full_suite.sh` to `case_test/<module>/`
   incrementally after selectors prove stable.
6. Schedule migrated endpoint groups with isolated work directories and
   deterministic port assignment when `--execute --parallel` is requested.

## Acceptance Criteria

- A changed source path can be mapped to zero or more case-test IDs through
  committed metadata.
- Existing `scripts/case_test.sh` behavior is preserved when invoked with no
  selector.
- The harness self-check validates case metadata paths, unique IDs, known
  modules, known feature keys, and existing runner files.
- Selected endpoint execution refuses pending groups instead of reporting a
  false pass.
- Parallel endpoint execution is opt-in and assigns deterministic ports per
  scheduled group.
- Documentation updates follow the `harness/spec/`, `harness/docs/`, and
  `harness/decisions/` authority split.

## Risks

- Large shell-script movement may create behavior drift. Mitigate by adding
  metadata and selectors before moving case bodies.
- Some endpoint cases share files, logs, ports, or process names. Keep full
  case execution sequential until those shared resources are isolated.
- Pending module runners may create confusion if executed directly. Make them
  fail clearly until their case bodies are migrated.
