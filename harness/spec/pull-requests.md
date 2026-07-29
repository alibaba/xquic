# Pull Request Evidence

See the [project instructions](PROJECT_INSTRUCTIONS.md) for related
architecture and validation contracts. When drafting or updating a pull
request, follow the
[`xquic-pr-formatting` skill](../skills/xquic-pr-formatting/SKILL.md).
Start from the repository
[pull-request template](../../.github/pull_request_template.md).

Every pull request should let a reviewer answer four questions quickly:

1. What behavior or project capability changes?
2. Why is the change correct?
3. How was it validated?
4. What remains risky or unverified?

## CONTRIBUTING.md Compliance

The repository [contribution guide](../../CONTRIBUTING.md) remains the
authoritative contribution contract. Harness evidence extends it and does not
replace it. Before review, confirm:

- the branch uses the documented pattern for its task type: `dev/` for a new
  feature, `fix/` for a bug fix, `perf/` for a performance optimization or
  other enhancement, or `doc/` for documentation;
- every commit header follows `[<type>]: <subject>` with an allowed `+`, `-`,
  `=`, or `~` type;
- the contributor has signed or will complete the CLA before merge;
- the change follows the Nginx-derived XQUIC code style;
- the full test suite and sufficient relevant tests pass;
- required continuous-integration checks pass before merge;
- the branch is rebased on its current base, and review-fix commits are
  squashed before merge; and
- an issue-closing pull request contains the exact `Fixes: #<number>` line.

Documentation-only changes follow the same review process. They may use the
documented runtime-test exemption, but must provide their applicable link,
format, and command-syntax evidence.

## Required Content

- **Problem:** current behavior and user or protocol impact.
- **Acceptance criteria:** observable conditions that define completion.
- **Approach:** the smallest useful explanation of the implementation.
- **Validation:** the complete local unit-suite command, exact relevant
  case-test commands, and concise pass/fail results.
- **Coverage map:** the happy-path and abnormal-path unit-test names plus the
  matching happy-path and abnormal-path client-to-server case names.
- **Evidence:** relevant tests and, when applicable, logs, traces, packet
  captures, interoperability reports, or screenshots.
- **Risk:** affected layers, compatibility concerns, and untested platforms or
  configurations.
- **Documentation impact:** durable guidance updated, or an explicit statement
  that no project documentation changed.
- **Issue link:** use the repository convention, for example `Fixes: #123`.

## Protocol Changes

For QUIC, HTTP/3, QPACK, or MoQ behavior, also include:

- the exact RFC or draft section;
- whether the requirement is normative;
- the wire-visible behavior before and after the change; and
- the lowest-level regression test that proves the required behavior.

Use interoperability and packet-capture evidence when unit tests cannot prove
the peer-visible outcome.

## Required Test Evidence

Every production behavior change must identify:

- a happy-path unit test;
- an abnormal, rejection, boundary, or error-branch unit test;
- a happy-path client-to-server case in `scripts/case_test.sh`; and
- an abnormal-path client-to-server case in `scripts/case_test.sh`.

The pull request must show that `XQC_TEST_NAME` was unset when the complete
local unit suite ran. It must also show that both relevant case tests passed.
If the case pair cannot run independently, use
`XQC_BUILD_DIR=build ./scripts/validate.sh full`. Evidence must come from the
current pull request head and be refreshed after every code revision.

The PR validation gate is not satisfied by a checkbox alone. The description
must contain the exact complete-suite command and result, both unit-test
names, both client-to-server case names and commands, and the tested commit
SHA. Keep a production code pull request in draft when any field is missing,
failed, stale, or replaced by focused-test output.

Documentation-only changes may replace runtime evidence with link, format, and
command-syntax checks. Validation-tooling changes use the closest
deterministic self-checks and explain why runtime coverage does not apply.

## Scope Rules

- Do not mix harness construction with unrelated product fixes unless the
  harness change is required to validate the fix.
- Do not add issue-specific build directories, targets, options, or CI jobs.
- Keep generated and diagnostic artifacts out of source control unless they
  are stable, intentionally reviewable deliverables.
- A failure discovered during validation is fixed before the pull request is
  presented as ready.
- Keep a production code pull request in draft while paired coverage is
  missing, the complete local unit suite fails, or either relevant case test
  fails.
