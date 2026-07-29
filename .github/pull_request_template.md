### Summary

<!-- Describe the current behavior or need, its impact, the observable
acceptance criteria, and the implementation approach. -->

### Changes

<!-- List the concrete code, test, documentation, or tooling changes. -->

### Related Issue

<!-- Add the exact line `Fixes: #123` when this PR resolves an issue.
Otherwise write `Not applicable`. -->

### Specification

<!-- For protocol behavior, cite the exact RFC or draft revision and section,
state whether the requirement is normative, and describe the expected and
previous wire behavior. Otherwise write `Not applicable`. -->

### CONTRIBUTING.md Checklist

<!-- These checks come from CONTRIBUTING.md and apply in addition to the
harness validation evidence below. -->

- [ ] The branch prefix matches the task type: `dev/` for a new feature,
      `fix/` for a bug fix, `perf/` for a performance optimization or other
      enhancement, or `doc/` for documentation.
- [ ] Commit messages follow `[<type>]: <subject>` using `+`, `-`, `=`, or
      `~`.
- [ ] The change follows the Nginx-derived XQUIC code style, or is
      documentation-only.
- [ ] The full test suite and sufficient relevant tests have passed, with
      exact evidence recorded below, or a documentation/tooling exemption is
      explained.
- [ ] Required continuous-integration checks pass before merge.
- [ ] The branch is rebased on its current base branch, and review-fix commits
      will be squashed before merge.
- [ ] The Contributor License Agreement is signed or will be completed before
      merge.

### Validation

<!-- Production behavior changes must complete every field below with results
from the current PR head. A checked box without the command, name, result, and
tested commit SHA does not pass the gate. Documentation-only or validation-
tooling changes must replace runtime evidence with deterministic checks and
explain why runtime coverage does not apply. -->

- Validation applicability: `<production behavior / documentation / tooling>`
- Runtime-coverage exemption, if applicable: `<reason and deterministic checks>`
- [ ] Tested commit SHA: `<sha>`
- [ ] Complete local unit suite:
  - Command: `unset XQC_TEST_NAME && ./scripts/validate.sh test`
  - Result: `<Ran>/<Total> CUnit tests, Failed=<count>`
- [ ] Happy-path unit test: `<test name and result>`
- [ ] Abnormal-path unit test: `<test name and result>`
- [ ] Happy-path client-to-server case:
  - Case ID and namespace: `<id; [A, B] module>`
  - Case name: `<case_print_result name>`
  - Command: `<exact command>`
  - Result: `<pass/fail>`
- [ ] Abnormal-path client-to-server case:
  - Case ID and namespace: `<different id; [A, B] module>`
  - Case name: `<case_print_result name>`
  - Command: `<exact command>`
  - Result: `<pass/fail>`

### Risk and Scope

<!-- Name affected layers, compatibility risks, untested configurations, and
documentation impact. Confirm generated or temporary artifacts are absent and
that the PR contains one cohesive contribution. -->
