# XQUIC Agent Guide

Keep this file short: it is the strong injection layer, not the full harness.

## Mandatory Preflight

Before planning, inspecting implementation paths, or editing code, tests,
build scripts, validation tools, or automation, read the
[development pipeline](harness/pipelines/dev-pipeline.md) in full. Do not
implement before requirement analysis, acceptance criteria, and working-branch
gate are satisfied.

## Sources Of Truth

- Read [`README.md`](README.md) for features and dependency setup.
- Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before code or PR work.
- Read the [harness index](harness/README.md) for specs, pipelines, and skills.
- Read the [harness behavior specification](harness/spec/harness-behavior.md)
  and [harness documentation](harness/docs/README.md) before changing harness
  structure, routing, document roles, or injection rules.
- Read the [manifest](harness/spec/harness-manifest.yml) for canonical path,
  module, docs, feature-gate, and validation routing.
- Read the [project instructions](harness/spec/PROJECT_INSTRUCTIONS.md) for
  task routing and repository-wide constraints.
- Read [`harness/spec/architecture.md`](harness/spec/architecture.md)
  before changing module boundaries.
- Read [`doc-style.md`](harness/spec/doc-style.md) before durable comments or docs.
- For issues and pull requests, choose the relevant skill by task purpose:
  issue checking, issue submission, PR formatting, PR review, comment fixes,
  CI fixes, safe push, and code-PR pre-review are separate entry points.
- Before moving a code PR out of draft, run
  [`xquic-pr-pre-review`](harness/skills/xquic-pr-pre-review/SKILL.md)
  against the published current head.
- Read the closest module documentation and protocol specification before
  changing wire behavior.

## Long Tasks and OpenSpec

Use the active agent runtime's native goal or background-task mechanism for
background work. For long-running feature, refactor, or cross-module work,
create or update an OpenSpec change first; follow the
[OpenSpec integration guide](harness/spec/openspec.md) so proposal, design,
tasks, and requirement deltas are reviewable before implementation.

## Validate

The repository-wide validation entry point is:

```bash
./scripts/validate.sh build
./scripts/validate.sh test
```

These commands stay independent of features, bugs, issues, and PRs. Use tests,
not issue-specific build modes, to express regressions. Validation levels are
in [`harness/spec/validation.md`](harness/spec/validation.md); `full` is an
explicit legacy case-suite check, not the default local gate before
`scripts/case_test.sh` has targeted selectors. Validation tasks also use
[`validate`](harness/skills/validate/SKILL.md). Harness-only changes must run:

```bash
bash harness/scripts/xqc_harness_check.sh
```

## Change Rules

- Keep changes scoped to the requested behavior.
- Preserve unrelated user changes and untracked files.
- Do not edit vendored content under `third_party/`.
- Stop and request confirmation before destructive operations, pushing to
  protected branches, requiring private context, or changing public protocol
  behavior without a source of truth.
- For every production behavior change, add or update unit tests that cover
  both the happy path and an abnormal or error branch.
- For endpoint-visible behavior, identify matching client-to-server coverage
  and record any case-test gap until targeted case execution exists.
- For protocol behavior, cite the exact RFC or draft section in the test or
  nearby implementation comment when it materially explains the invariant.
- Follow the Nginx-derived C style in `CONTRIBUTING.md`, including 4-space
  indentation, no `//` comments, and an 80-column target.

## Done Evidence

A code change is done when acceptance criteria are satisfied, paired unit tests
cover happy and abnormal paths, endpoint-visible coverage or gaps are recorded,
validation passes, durable docs are synchronized, any required local
pre-review report remains uncommitted and passes, and PR evidence follows
[`harness/spec/pull-requests.md`](harness/spec/pull-requests.md).
