# XQUIC Project Instructions

This is the portable project-instruction source and specification index for
coding-agent adapters. Root [`AGENTS.md`](../../AGENTS.md) is the checked-in
discovery entry point; keep its critical constraints aligned with this
document.

## Project

XQUIC is Alibaba's C implementation of QUIC and HTTP/3. The source tree,
dependency direction, and protocol invariants are described in the
[architecture map](architecture.md). Supported features and dependency setup
remain in the root [`README.md`](../../README.md).

## Document Organization

- Root convention files retain their established uppercase names, such as
  `README.md`, `CONTRIBUTING.md`, and `AGENTS.md`.
- Specification documents use lowercase kebab-case names;
  `PROJECT_INSTRUCTIONS.md` retains its adapter-template name.
- Informative structure maps and change guidance live under `harness/docs/`.
- Durable design rationale lives under `harness/decisions/`.
- Normative harness requirements live under `harness/spec/`, independently of
  whether their reader is a maintainer, contributor, or agent.
- Capability-specific behavioral specifications belong under
  `spec/<capability>/spec.md`.
- Pipelines and skills live in the sibling `pipelines/` and `skills/`
  directories rather than being mixed with project facts.
- Durable comments and documentation follow [doc-style.md](doc-style.md).
- Task-specific notes, retrospectives, logs, and generated evidence remain
  outside `harness/`.
- Closed-source or environment-specific instructions remain under ignored
  `harness/private/`; committed harness docs may describe the contract but
  must not require private content to perform ordinary open-source tasks.

## Principles

1. Repository knowledge is discoverable from a short root-level map.
2. Build and validation workflows describe project capabilities, never a
   particular issue or pull request.
3. Behavioral regressions are represented by tests and acceptance criteria,
   not by special build targets or configuration flags.
4. Important constraints are made executable when practical.
5. Guidance grows from recurring, verified development friction instead of
   one-off task details or speculative rules.

## Task Routing

| Task | Required entry point |
|------|----------------------|
| Long-running feature, refactor, or cross-module task | Codex native goal directive plus [OpenSpec integration](openspec.md) |
| Code change, feature, refactor, or bug fix | [Development pipeline](../pipelines/dev-pipeline.md) |
| Compile or configure local build | [Validation specification](validation.md) and [`xquic-build` skill](../skills/xquic-build/SKILL.md) |
| Test, validation, or PR evidence | [Validation specification](validation.md) and [`validate` skill](../skills/validate/SKILL.md) |
| Documentation or comment change | [Documentation style](doc-style.md) plus the closest owning spec |
| Task evidence, command logs, failure trace | [Run artifact contract](run-artifacts.md) |
| Verify an issue or protocol-defect claim | [`issue-check` skill](../skills/issue-check/SKILL.md) |
| Prepare or submit a GitHub issue | [`issue-submit` skill](../skills/issue-submit/SKILL.md), gated by [`issue-check`](../skills/issue-check/SKILL.md) |
| Pre-review a code pull request | [`xquic-pr-pre-review` skill](../skills/xquic-pr-pre-review/SKILL.md), after draft PR publication and before ready-for-review state |
| Pull request preparation or update | [Pull-request specification](pull-requests.md) and the relevant PR skill for formatting, review, comments, or CI |
| Query or analysis | Relevant source, tests, module docs, and [architecture map](architecture.md) |

Read the selected entry point in full before changing code, build behavior, or
pull-request artifacts.

Long tasks use the active agent runtime's native goal or background-task
mechanism and keep OpenSpec artifacts current before implementation.

Task-local evidence follows [run-artifacts.md](run-artifacts.md). Use
`build/harness/runs/<task-id>/` when a task needs durable command logs,
detection output, failed-test hypotheses, or final evidence.

For every code task, the development pipeline is a mandatory preflight. Read
it before planning, inspecting implementation paths, or editing source,
tests, build scripts, validation tooling, or repository automation.

## Git and Scope

- Never push directly to a remote `main` or `master` branch.
- After acceptance criteria and before implementation, follow the
  [working-branch stage](../pipelines/dev-pipeline.md#stage-3-working-branch).
- Match the accepted task to its exact `CONTRIBUTING.md` branch pattern;
  `dev/`, `fix/`, `perf/`, and `doc/` are not interchangeable.
- Use a scoped working branch and submit changes through a pull request.
- Preserve unrelated user changes, staged state, and untracked files.
- Do not edit vendored content under `third_party/`.
- Keep generated headers, validation logs, and temporary evidence out of
  source control.

## Implementation

1. Read the relevant source path before claiming behavior or applying a fix.
2. Express acceptance criteria as observable behavior, independent of an
   issue number, branch, or pull request.
3. Make the smallest change that satisfies the criteria.
4. Follow [`CONTRIBUTING.md`](../../CONTRIBUTING.md), including its
   Nginx-derived C style and commit convention.
5. Add or update happy-path and abnormal-path unit tests for each production
   behavior change.
6. Identify matching happy-path and abnormal-path client-to-server coverage
   for endpoint-visible behavior. Add `scripts/case_test.sh` cases only when
   they can be maintained in the owning native group without making the full
   suite the default local gate.
7. Re-read the modified path and trace affected callers and callees.
8. Update durable project or module documentation when a contract, boundary,
   command, or public API changes.

For protocol behavior, identify the governing RFC or draft section and use the
most specific required error or negotiation behavior.

For a reported-issue fix, follow the development pipeline's issue branch
before implementation. Run `issue-check`, write its complete report to
`build/harness/<task-id>/issue-check.md`, and continue only when
`check_result: true`. Use the verified specification, implementation
comparison, source trace, and root-cause status as inputs to acceptance
criteria and implementation. The report is temporary evidence and must not be
committed.

## Validation

Before a production code pull request, run the complete local unit suite with
the focused-test selector cleared:

```bash
unset XQC_TEST_NAME
./scripts/validate.sh test
```

Run targeted client-to-server commands only when the relevant blocks can be
invoked independently and recorded. Use
`XQC_BUILD_DIR=build ./scripts/validate.sh full` only when explicitly requested
or when the change owner accepts the legacy full case-suite cost. Record exact
commands, paired test names, endpoint coverage or gap status, and results. A
focused unit test is useful during development but cannot satisfy the
pull-request gate.

## Definition of Done

A change is complete when:

- its acceptance criteria are satisfied;
- paired happy-path and abnormal-path unit tests cover every production
  behavior change;
- endpoint-visible behavior has paired happy-path and abnormal-path coverage
  or an explicit case-test gap;
- the complete local unit suite passes and accepted targeted case checks pass;
- generated and temporary artifacts are absent from the diff;
- durable documentation and relative links remain accurate;
- the PR-scoped five-part pre-review report passes, and its local review
  workspace remains uncommitted and reusable for the next iteration; and
- the pull request contains the evidence required by
  [pull-requests.md](pull-requests.md).

## Reference Documents

Public headers, tests, and governing IETF specifications are the
behavior-level sources of truth. When sources disagree, executable behavior
and the governing protocol specification identify the defect; update stale
documentation in the same change when it affects future work.

| Topic | Path |
|-------|------|
| Root discovery and definition of done | [AGENTS.md](../../AGENTS.md) |
| Harness layout and naming | [Harness README](../README.md) |
| Harness behavior requirements | [harness-behavior.md](harness-behavior.md) |
| Harness documentation structure | [docs/README.md](../docs/README.md) |
| Harness design rationale | [decision records](../decisions/records.md) |
| Documentation style | [doc-style.md](doc-style.md) |
| Architecture and dependency boundaries | [architecture.md](architecture.md) |
| Development workflow | [dev-pipeline.md](../pipelines/dev-pipeline.md) |
| Task run artifacts | [run-artifacts.md](run-artifacts.md) |
| Build and test validation | [validation.md](validation.md) |
| Pull-request pre-review | [xquic-pr-pre-review](../skills/xquic-pr-pre-review/SKILL.md) |
| Pull-request evidence | [pull-requests.md](pull-requests.md) |
| Contribution and code style | [CONTRIBUTING.md](../../CONTRIBUTING.md) |
| Supported features and setup | [README.md](../../README.md) |
