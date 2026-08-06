# Tasks

## 1. OpenSpec and Inventory

- [x] Create the OpenSpec change directory.
- [x] Record the design against `origin/main` harness structure.
- [x] Inventory legacy endpoint case names, numeric selectors, shared
  resources, and broad module ownership.

## 2. Case-Test Metadata

- [x] Add `case_test/README.md`.
- [x] Add `case_test/manifest.yml` with schema notes and an initial set of
  representative cases.
- [x] Add `case_test/lib/` helpers only when a selector or runner needs shared
  logic.
- [x] Update `harness/spec/harness-manifest.yml` to reference the case-test
  manifest without duplicating the case table.
- [x] Extend `harness/scripts/harness_manifest_check.rb` to validate case-test
  metadata.

## 3. Case-Test Selectors

- [x] Preserve full-suite behavior for `scripts/case_test.sh` with no
  selector.
- [x] Add `--list` and `--dry-run` selectors.
- [x] Add `--case`, `--module`, `--feature`, and `--from-path` selectors.
- [x] Ensure selector output is deterministic and suitable for agent evidence.
- [x] Add shell syntax and selector dry-run checks.

## 4. Incremental Case Movement

- [x] Move the legacy full-suite body behind the compatibility entry point.
- [ ] Move low-risk observability or qlog cases into module runners.
- [ ] Move transport stream and datagram cases after selector equivalence is
  proven.
- [ ] Move feature-gated FEC cases only after feature flags and runner
  requirements are explicit in metadata.
- [ ] Keep legacy `case_print_result` names stable unless a separate
  behavior change justifies renaming.

## 5. Endpoint Port Isolation and Parallel Mode

- [x] Assign deterministic ports per selected endpoint group.
- [x] Add a helper or environment contract for `CASE_TEST_PORT_BASE`.
- [x] Keep sequential validation as the default.
- [x] Enable opt-in parallel endpoint selected execution through `--parallel`
  and `--jobs`.

## 6. Documentation and Decisions

- [x] Update `harness/spec/validation.md` with targeted case and parallel
  endpoint requirements.
- [x] Update `harness/docs/structure-map.md` with the informative directory
  navigation.
- [x] Update `harness/docs/change-guide.md` with how to find relevant case
  tests from changed paths.
- [x] Update `harness/decisions/records.md` with the rationale for separate
  case metadata and compatibility wrappers.

## 7. Validation

- [x] Run `bash harness/scripts/xqc_harness_check.sh`.
- [x] Run shell syntax checks for `scripts/case_test.sh` and `case_test/`.
- [x] Run `bash scripts/case_test.sh --inventory`.
- [x] Run a representative `--from-path` dry run.
- [x] Run a representative pending selected execution check.
- [x] Run `case_test/lib/architecture_check.rb "$(pwd)" --all`.
- [x] Run `./scripts/validate.sh test --dry-run`.
- [ ] Run `./scripts/validate.sh test`.
