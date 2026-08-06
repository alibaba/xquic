# Tasks

## 1. OpenSpec and Inventory

- [x] Create the OpenSpec change directory.
- [x] Record the design against `origin/main` harness structure.
- [ ] Inventory `scripts/case_test.sh` case names, numeric selectors, shared
  resources, and broad module ownership.
- [ ] Inventory `tests/unittest/*.c` files that open sockets or depend on
  certificates, process-global state, time, or generated files.

## 2. Case-Test Metadata

- [ ] Add `case_test/README.md`.
- [ ] Add `case_test/manifest.yml` with schema notes and an initial set of
  representative cases.
- [ ] Add `case_test/lib/` helpers only when a selector needs shared logic.
- [ ] Update `harness/spec/harness-manifest.yml` to reference the case-test
  manifest without duplicating the case table.
- [ ] Extend `harness/scripts/harness_manifest_check.rb` to validate case-test
  metadata.

## 3. Case-Test Selectors

- [ ] Preserve full-suite behavior for `scripts/case_test.sh` with no
  selector.
- [ ] Add `--list` and `--dry-run` selectors.
- [ ] Add `--case`, `--module`, `--feature`, and `--from-path` selectors.
- [ ] Ensure selector output is deterministic and suitable for agent evidence.
- [ ] Add shell syntax and selector dry-run checks.

## 4. Incremental Case Movement

- [ ] Move low-risk observability or qlog cases into `case_test/`.
- [ ] Move transport stream and datagram cases after selector equivalence is
  proven.
- [ ] Move feature-gated FEC cases only after feature flags and runner
  requirements are explicit in metadata.
- [ ] Keep legacy `case_print_result` names stable unless a separate
  behavior change justifies renaming.

## 5. Unit-Test Suite Routing

- [ ] Add unit-test suite metadata with source files, module ownership, and
  optional feature gates.
- [ ] Extend `tests/run_tests` selection from test name to suite name.
- [ ] Register suite-level CTest entries while keeping the full CUnit run
  available.
- [ ] Update `scripts/validate.sh` to report suite-level evidence.

## 6. Port Isolation and Parallel Mode

- [ ] Identify every unit-test suite that binds or connects sockets.
- [ ] Assign deterministic, non-overlapping port ranges by suite.
- [ ] Add a helper or environment contract for `XQC_TEST_PORT_BASE`.
- [ ] Keep sequential validation as the default.
- [ ] Enable opt-in parallel unit validation through `XQC_TEST_JOBS`.

## 7. Documentation and Decisions

- [ ] Update `harness/spec/validation.md` with targeted case and parallel
  unit-test requirements.
- [ ] Update `harness/docs/structure-map.md` with the informative directory
  navigation.
- [ ] Update `harness/docs/change-guide.md` with how to find relevant case
  tests from changed paths.
- [ ] Update `harness/decisions/records.md` with the rationale for separate
  case metadata and compatibility wrappers.

## 8. Validation

- [ ] Run `bash harness/scripts/xqc_harness_check.sh`.
- [ ] Run `bash -n scripts/case_test.sh`.
- [ ] Run `./scripts/case_test.sh --list`.
- [ ] Run a representative `--from-path` dry run.
- [ ] Run `./scripts/validate.sh test`.
- [ ] After port isolation, run `XQC_TEST_JOBS=4 ./scripts/validate.sh test`.
