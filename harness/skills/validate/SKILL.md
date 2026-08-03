---
name: validate
description: Enforce XQUIC test coverage and local validation gates. Use when code, build, or test changes need verification; before commit or pull request; or when asked to build, test, validate, or verify XQUIC. Requires paired happy-path and abnormal-path unit tests, the complete local unit suite, and explicit endpoint coverage or gap reporting for production behavior changes.
---

# XQUIC Validate

Use the repository-wide `scripts/validate.sh` interface and the
[validation specification](../../spec/validation.md).

## Coverage Gate

Before running validation for a production behavior change, verify that the
diff contains:

1. Unit coverage tied to the changed path.
2. At least one happy-path unit test.
3. At least one abnormal, rejection, boundary, or error-branch unit test.
4. Endpoint-visible coverage for the happy path.
5. Endpoint-visible abnormal coverage that proves the expected rejection,
   error, close, or recovery behavior.
6. A distinct, never-before-used and currently unreserved ID for each new
   client-to-server case, allocated from the owning layer or module namespace
   in the
   [validation specification](../../spec/validation.md#client-to-server-case-id-namespace).
7. The new IDs recorded in the namespace registry in the same change.

When adding `scripts/case_test.sh` cases, give the two cases distinct
`case_print_result` names. Assert the observable client and server results
needed to prove the behavior. Reusing an unrelated test or case ID, or
asserting only that the process exited, is not sufficient. Active and retired
case IDs are both permanently unavailable for new behavior.

## Workflow

1. Inspect the changed-file scope and preserve unrelated user changes.
2. Apply the Coverage Gate before treating validation as complete.
3. For every new case ID, refresh `origin/main`, check `scripts/case_test.sh`,
   `tests/test_client.c`, `tests/test_server.c`, and their Git history. Require
   no previous allocation and confirm the registry range matches the owning
   protocol layer or module.
4. Query all open pull requests targeting `main` and inspect the exact
   published head SHA for each pull request other than the current one. Require
   the candidate numeric token to be absent from the three selector files.
   Follow the complete fail-closed procedure in the validation specification;
   an incomplete query is not proof that an ID is free.
5. During development, use a focused registered CUnit test for fast feedback:

   ```bash
   XQC_TEST_NAME=<test-name> ./scripts/validate.sh test
   ```

6. For feature-gated paths, select the feature by manifest key:

   ```bash
   ./scripts/validate.sh test --feature <feature>
   ```

   The script reads feature flags and feature unit tests from
   `harness/spec/harness-manifest.yml`. Do not add feature-specific script
   branches when manifest data is sufficient.

7. Before creating or updating a code pull request, clear the focused-test
   selector and run the complete unit suite:

   ```bash
   unset XQC_TEST_NAME
   ./scripts/validate.sh test
   ```

8. Require the emitted CUnit summary to show `Ran == Total` and `Failed == 0`.
   Record the result as `<Ran>/<Total> CUnit tests`; `CTest 1/1` alone is not
   complete-unit-suite evidence.
9. Run targeted client-to-server commands only when the relevant blocks can be
   executed directly and recorded without the legacy full `case_test.sh` suite.
   Use `XQC_BUILD_DIR=build ./scripts/validate.sh full` only when explicitly
   requested or when the change owner accepts the full-suite cost.
10. Require the complete unit suite to pass. For endpoint-visible behavior,
   report targeted case results when available; otherwise report the case-test
   gap instead of claiming local regression is complete.
11. Repeat the open-PR reservation scan for each new case ID after the tests
    pass and immediately before PR submission or update. Record the snapshot
    time, candidate IDs, number of heads checked, current PR exclusion, and
    result.
12. Verify that `include/xquic/xqc_configure.h` and other generated artifacts
   did not enter the source diff.
13. Report the changed scope, CUnit `<Ran>/<Total>` and failed counts, paired
    unit-test names, endpoint coverage or gap status, paired case IDs and
    namespaces when new cases are added, reservation snapshot, exact commands,
    and results in ignored local evidence.
14. Summarize those current-head results in the repository
    [pull-request template](../../../.github/pull_request_template.md). List
    only each executed case ID and its concise behavior, then mark local
    regression `Complete` or name concise failed/gap cases. Do not copy commands, test
    function names, logs, namespace ranges, or reservation snapshots into the
    PR body. Missing, stale, focused-only, or failed local evidence still does
    not pass the gate.
15. After the PR or updated head is published, scan again with the current PR
    included. On a duplicate, the lowest PR number keeps the ID; every later PR
    must return to draft, mark local regression incomplete, reallocate, and
    rerun this workflow.

Documentation-only changes may use link, format, and command-syntax checks
instead of inventing runtime tests. Validation-tooling changes require the
closest deterministic self-checks. State why runtime coverage is not
applicable.

## Guardrails

- Do not add issue-specific validation modes, targets, paths, or flags.
- Do not hard-code one feature's validation path in `scripts/validate.sh`;
  add or update manifest feature data instead.
- Do not install packages, clone dependencies, or modify external services.
- Do not edit production code while acting only on a validation request.
- Stop after a failed build; diagnose it before running tests.
- Do not submit a code pull request with a missing happy-path or abnormal-path
  unit test.
- Do not claim endpoint-visible coverage passed when the relevant case blocks
  were not executed.
- Do not reuse an active or retired case ID, use an ID outside its documented
  namespace, take an ID reserved by another open PR, or give the paired happy
  and abnormal cases the same ID.
- Do not treat a failed or partial open-PR query as an empty reservation set.
- Do not keep a duplicate ID in the later-numbered PR after the
  post-publication collision check.
- Do not use a focused test as pull-request evidence in place of the complete
  local unit suite.
- Do not use the aggregate `CTest 1/1` result in place of the CUnit
  `<Ran>/<Total>` and failed counts.
- Do not treat an environment blocker as a passing gate; keep the pull request
  in draft or resolve the blocker before review.
- Keep raw logs under the ignored validation artifact directory.
- For task-local diagnosis and final evidence, use the run artifact contract
  in `harness/spec/run-artifacts.md`.
