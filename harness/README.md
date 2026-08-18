# XQUIC Development Harness

This directory is the repository-owned, tool-neutral source for project
specifications, explanatory documentation, design decisions, development
pipelines, and reusable agent skills. Root `AGENTS.md` remains the broadly
discoverable entry point and links here.

## Layout

```text
harness/
├── docs/        informative structure maps and maintenance guidance
├── decisions/   durable design rationale and ADRs
├── spec/        authoritative requirements, facts, and evidence contracts
├── pipelines/   ordered workflows that apply the specifications
├── scripts/     harness structure and code-synchronization checks
├── skills/      reusable task procedures, one SKILL.md per skill
└── private/     ignored closed-source adapters and local/private runbooks
```

## Entry Points

- [Project instructions](spec/PROJECT_INSTRUCTIONS.md)
- [Harness behavior specification](spec/harness-behavior.md)
- [Harness documentation](docs/README.md)
- [Decision records](decisions/records.md)
- [Development pipeline](pipelines/dev-pipeline.md)
- [Documentation style](spec/doc-style.md)
- [Run artifact contract](spec/run-artifacts.md)
- [Harness review skill](skills/harness-review/SKILL.md)
- [XQUIC build skill](skills/xquic-build/SKILL.md)
- [Validation skill](skills/validate/SKILL.md)
- [Issue verification skill](skills/issue-check/SKILL.md)
- [Issue complexity classification skill](skills/classify-issue-complexity/SKILL.md)
- [Issue submission skill](skills/issue-submit/SKILL.md)
- [Pull request pre-review skill](skills/xquic-pr-pre-review/SKILL.md)
- [Pull request formatting skill](skills/xquic-pr-formatting/SKILL.md)
- [Safe push skill](skills/xquic-safe-push/SKILL.md)
- [GitHub CI fix skill](skills/gh-fix-ci/SKILL.md)
- [GitHub review comment skill](skills/gh-address-comments/SKILL.md)
- [OpenSpec integration guide](spec/openspec.md)

## External References

- [OpenSpec](https://openspec.dev/): open-source spec-driven development
  framework for AI coding assistants.
- [Fission-AI/OpenSpec](https://github.com/Fission-AI/OpenSpec): upstream
  project source and CLI installation reference.

## Checks

Harness scripts are limited to repository-owned consistency checks:

```bash
bash harness/scripts/xqc_harness_check.sh
```

That entry point verifies harness structure and manifest-to-code
synchronization. On pull request events, the workflow also passes the PR body
to the same check so stale repository-path references fail with the current
head. Product build and runtime validation stay in `scripts/validate.sh`.

## Naming

- Top-level harness directories use the stable names `docs/`, `decisions/`,
  `spec/`, `pipelines/`, and `skills/`.
- Markdown filenames use lowercase kebab-case, except conventional
  `README.md`, `SKILL.md`, and the adapter template
  `PROJECT_INSTRUCTIONS.md`.
- Skill directories use the same lowercase hyphenated name as the `name`
  field in their `SKILL.md`.
- Capability behavior specifications use
  `spec/<capability>/spec.md`.
- Harness-wide normative requirements use `spec/harness-behavior.md`.
- Temporary plans, retrospectives, logs, and validation output do not belong
  in `harness/`.
- Task-scoped issue-check reports belong under the ignored
  `build/harness/<task-id>/` directory and must not be committed.
- Task-local run evidence belongs under ignored
  `build/harness/runs/<task-id>/`.
- Tool-native local adapters such as `.claude/` are allowed locally but
  must not become committed sources of truth. Migrate durable skill content to
  `harness/skills/`.
- Closed-source or environment-specific rules belong under ignored
  `harness/private/` and must not be referenced as required public harness
  inputs.
- Pull-request pre-review reports and exploratory bad-case artifacts belong
  together under the local
  `~/build/harness/pr-review-<number>/` directory. The current retrospective
  is `pr-review-<number>.md`; the complete directory remains uncommitted and
  may be reused as input to the next PR iteration.

## Portability

`harness/` is the canonical committed source, independent of a particular
agent product. Tools that require native discovery directories may install or
link these skills into their own ignored directory, but should not maintain a
second committed copy. Every skill keeps its portable instructions in
`SKILL.md`; platform-specific metadata is optional. Project-instruction
adapters should link to or be generated from
`spec/PROJECT_INSTRUCTIONS.md`.

## Document Roles

Document roles are semantic, not audience-specific. The normative boundaries
for specifications, informative documents, and decision records are defined
in [`spec/harness-behavior.md`](spec/harness-behavior.md). Their
machine-readable path assignment is defined in
[`spec/harness-manifest.yml`](spec/harness-manifest.yml).
