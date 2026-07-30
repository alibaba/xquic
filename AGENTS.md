# XQUIC Agent Guide

Keep this file short. It is a map to the repository's sources of truth, not a
replacement for them.

## First-Time Harness Setup

At the first task in a fresh checkout, ensure that the harness skills and
pipeline are registered in the active discovery directories. The default
project-local adapters are `.agents/skills/` and
`.agents/pipelines/dev-pipeline.md`. If either registration is absent, run:

```bash
./scripts/setup_harness.sh
```

Run this bootstrap once per checkout, not once per task. The script is
idempotent and refuses to overwrite existing paths. Pass its directory options
when the active tool uses native discovery paths, and check those targets on
later tasks. Do not install the optional pre-push hook unless the user or
contributor explicitly opts in.

## Mandatory Code-Task Preflight

Before planning, inspecting implementation paths, or editing any code, test,
build script, validation tool, or repository automation, read the
[development pipeline](harness/pipelines/dev-pipeline.md) in full. Apply this
gate at the start of every code task, including a new task in an existing
session. Do not begin implementation until the requirement and acceptance
criteria stages have been completed and the task is on a conforming working
branch.

## Start Here

- Read [`README.md`](README.md) for supported features and dependency setup.
- Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before changing code or preparing
  a pull request.
- Read the [harness index](harness/README.md) to locate project specifications,
  pipelines, and reusable skills.
- Read the
  [project instructions](harness/spec/PROJECT_INSTRUCTIONS.md) for task
  routing and repository-wide constraints.
- Read [`harness/spec/architecture.md`](harness/spec/architecture.md)
  before changing module boundaries.
- Before submitting an issue, use
  [`issue-check`](harness/skills/issue-check/SKILL.md) and then
  [`issue-submit`](harness/skills/issue-submit/SKILL.md).
- After submitting a code pull request as draft and before moving it to
  review, use
  [`xquic-pr-pre-review`](harness/skills/xquic-pr-pre-review/SKILL.md).
- Read the closest module documentation and protocol specification before
  changing wire behavior.

## Build and Validate

The repository-wide validation entry point is:

```bash
./scripts/validate.sh build
./scripts/validate.sh test
XQC_BUILD_DIR=build ./scripts/validate.sh full
```

These commands must remain independent of any feature, bug, issue number, or
pull request. Use tests, not issue-specific build modes, to express a
regression.

The default validation profile is a Debug build with BoringSSL and tests
enabled. It writes only ignored build output beneath `build/validation/`.
Environment overrides and validation levels are documented in the
[validation specification](harness/spec/validation.md). For validation tasks,
also follow the [`validate` skill](harness/skills/validate/SKILL.md).

## Change Rules

- Keep changes scoped to the requested behavior.
- Preserve unrelated user changes and untracked files.
- Do not edit vendored content under `third_party/`.
- For every production behavior change, add or update unit tests that cover
  both the happy path and an abnormal or error branch.
- Add matching client-to-server case tests for both the successful and
  abnormal end-to-end paths.
- For protocol behavior, cite the exact RFC or draft section in the test or
  nearby implementation comment when it materially explains the invariant.
- Follow the Nginx-derived C style in `CONTRIBUTING.md`, including 4-space
  indentation, no `//` comments, and an 80-column target.

## Definition of Done

A code change is done when:

- the requested behavior and its acceptance criteria are satisfied;
- paired happy-path and abnormal-path unit tests cover each production
  behavior change;
- paired client-to-server case tests cover the corresponding end-to-end
  behavior;
- the complete local unit suite and both relevant case tests pass;
- the five-part local pre-review report passes and remains uncommitted;
- the diff has been reviewed for scope and regressions; and
- the pull request contains the evidence required by the
  [pull-request specification](harness/spec/pull-requests.md).

When preparing or updating a pull request, follow
[`xquic-pr-formatting`](harness/skills/xquic-pr-formatting/SKILL.md) to publish
the draft, run
[`xquic-pr-pre-review`](harness/skills/xquic-pr-pre-review/SKILL.md), then
return to the formatting skill to update the pull request and move it to
review.
