# Case Test Routing and Parallel Unit Tests

## Summary

Introduce a test-routing layer that lets agents and maintainers identify the
client-to-server case tests and unit-test suites affected by a source change.
Keep the existing `scripts/case_test.sh` entry point compatible while moving
case metadata and, later, case implementations into a structured
`case_test/` tree.

## Motivation

`scripts/case_test.sh` currently contains the full endpoint test flow in one
large script. The harness can route source paths to modules and feature gates,
but it cannot deterministically answer which endpoint cases should cover a
changed path. The unit-test entry point also registers one CTest target for
the whole CUnit binary, so `ctest -j` cannot provide useful parallelism.

This change adds machine-readable routing before large test movement. The
first goal is accurate indexing and compatibility; parallel execution becomes
opt-in after test suites have stable port isolation.

## Scope

- Add an OpenSpec-owned design for case-test classification and parallel unit
  execution.
- Add or update repository metadata so changed paths can route to relevant
  case tests and unit suites.
- Preserve `scripts/case_test.sh` as the stable compatibility entry point.
- Add targeted case selection without making the legacy full case suite the
  default local gate.
- Define a unit-test suite and port-allocation strategy that can support
  `ctest -j` without port collisions.

## Out Of Scope

- Rewriting every endpoint case in one change.
- Making full case-test execution the default validation path.
- Changing public protocol behavior.
- Replacing CUnit or the existing `tests/test_client` and `tests/test_server`
  binaries.
- Vendoring OpenSpec source into this repository.

## Proposed Change

1. Create `case_test/manifest.yml` as the case-test metadata source of truth.
2. Reference that metadata from `harness/spec/harness-manifest.yml` instead of
   duplicating case-to-path maps in documentation.
3. Add `scripts/case_test.sh` selectors for listing, dry runs, modules,
   features, individual cases, and changed paths.
4. Move case blocks from `scripts/case_test.sh` to `case_test/<module>/`
   incrementally after selectors prove stable.
5. Split unit-test execution by suite or source file and assign deterministic
   port ranges per suite before enabling parallel jobs.

## Acceptance Criteria

- A changed source path can be mapped to zero or more case-test IDs through
  committed metadata.
- Existing `scripts/case_test.sh` behavior is preserved when invoked with no
  selector.
- The harness self-check validates case metadata paths, unique IDs, known
  modules, known feature keys, and existing runner files.
- Unit tests can remain sequential by default and support an opt-in parallel
  mode only after port ranges are deterministic.
- Documentation updates follow the `harness/spec/`, `harness/docs/`, and
  `harness/decisions/` authority split.

## Risks

- Large shell-script movement may create behavior drift. Mitigate by adding
  metadata and selectors before moving case bodies.
- Some endpoint cases share files, logs, ports, or process names. Keep full
  case execution sequential until those shared resources are isolated.
- Splitting CUnit registration may expose hidden global state. Keep parallel
  execution opt-in and validate suite-by-suite.
