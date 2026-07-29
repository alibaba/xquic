---
name: validate
description: Enforce XQUIC test coverage and local validation gates. Use after code, build, or test changes; before commit or pull request; or when asked to build, test, validate, or verify XQUIC. Requires paired happy-path and abnormal-path unit tests, paired client-to-server case tests, the complete local unit suite, and the relevant case tests for production behavior changes.
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
4. A client-to-server happy-path case in `scripts/case_test.sh`.
5. A client-to-server abnormal-path case that proves the expected rejection,
   error, close, or recovery behavior.

Give the two case tests distinct `case_print_result` names. Assert the
observable client and server results needed to prove the behavior. Reusing an
unrelated test or asserting only that the process exited is not sufficient.

## Workflow

1. Inspect the changed-file scope and preserve unrelated user changes.
2. Apply the Coverage Gate before treating validation as complete.
3. During development, use a focused registered CUnit test for fast feedback:

   ```bash
   XQC_TEST_NAME=<test-name> ./scripts/validate.sh test
   ```

4. Before creating or updating a code pull request, clear the focused-test
   selector and run the complete unit suite:

   ```bash
   unset XQC_TEST_NAME
   ./scripts/validate.sh test
   ```

5. Run both relevant client-to-server case-test blocks, including their setup,
   cleanup, and assertions. Because `scripts/case_test.sh` has no generic
   name filter, use the following conservative command unless the exact
   standalone commands for both blocks are executed and recorded:

   ```bash
   XQC_BUILD_DIR=build ./scripts/validate.sh full
   ```

6. Require the complete unit suite and both relevant case tests to pass. Check
   the case output for both expected `[       OK ]` names and for any
   `[     FAIL ]` or `>>>>>>>> pass:0` result; do not rely only on the script's
   exit code.
7. Verify that `include/xquic/xqc_configure.h` and other generated artifacts
   did not enter the source diff.
8. Report the changed scope, paired unit-test names, paired case-test names,
   exact commands, and pass/fail results.
9. Put those current-head results in the repository
   [pull-request template](../../../.github/pull_request_template.md).
   Missing, stale, focused-only, or failed local evidence does not pass the
   PR gate.

Documentation-only changes may use link, format, and command-syntax checks
instead of inventing runtime tests. Validation-tooling changes require the
closest deterministic self-checks. State why runtime coverage is not
applicable.

## Guardrails

- Do not add issue-specific validation modes, targets, paths, or flags.
- Do not install packages, clone dependencies, or modify external services.
- Do not edit production code while acting only on a validation request.
- Stop after a failed build; diagnose it before running tests.
- Do not submit a code pull request with a missing happy-path or abnormal-path
  unit test.
- Do not submit a code pull request with a missing happy-path or abnormal-path
  client-to-server case test.
- Do not use a focused test as pull-request evidence in place of the complete
  local unit suite.
- Do not treat an environment blocker as a passing gate; keep the pull request
  in draft or resolve the blocker before review.
- Keep raw logs under the ignored validation artifact directory.
- Treat the optional pre-push hook as an early check only. The pull request
  must still contain the required named local evidence.
