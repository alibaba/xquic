# XQUIC Development Harness

This directory is the repository-owned, tool-neutral source for project
specifications, development pipelines, and reusable agent skills. Root
`AGENTS.md` remains the broadly discoverable entry point and links here.

## Layout

```text
harness/
├── ai_docs/     structure maps, change obligations, behavior specs, decisions
├── spec/        project instructions, facts, and evidence contracts
├── pipelines/   ordered workflows that apply the specifications
├── skills/      reusable task procedures, one SKILL.md per skill
└── private/     ignored closed-source adapters and local/private runbooks
```

## Entry Points

- [Project instructions](spec/PROJECT_INSTRUCTIONS.md)
- [AI docs index](ai_docs/README.md)
- [Development pipeline](pipelines/dev-pipeline.md)
- [Documentation style](spec/doc-style.md)
- [Validation skill](skills/validate/SKILL.md)
- [Issue verification skill](skills/issue-check/SKILL.md)
- [Issue submission skill](skills/issue-submit/SKILL.md)
- [Pull request formatting skill](skills/xquic-pr-formatting/SKILL.md)
- [Git workflow skill](skills/git-workflow/SKILL.md)
- [Safe push skill](skills/xquic-safe-push/SKILL.md)
- [GitHub CI fix skill](skills/gh-fix-ci/SKILL.md)
- [GitHub PR review skill](skills/gh-pr-review/SKILL.md)
- [GitHub review comment skill](skills/gh-address-comments/SKILL.md)
- [OpenSpec integration guide](spec/openspec.md)

## Setup

From the repository root, run
[`setup_harness.sh`](../scripts/setup_harness.sh) to register the harness:

```bash
./scripts/setup_harness.sh
```

Root [`AGENTS.md`](../AGENTS.md#first-time-harness-setup) directs agents to
run this bootstrap once when a fresh checkout's active discovery targets have
no registered adapters.

The default registration creates project-local symbolic links under
`.agents/skills/` and `.agents/pipelines/`. These generated adapters are
ignored by Git; `harness/` remains the only committed source. Re-running the
command is safe. Existing files or links to another source are never
overwritten.

Use `--skills-dir` and `--pipelines-dir` to target a tool-native discovery
directory. To install the optional pre-push validation hook:

```bash
./scripts/setup_harness.sh --install-pre-push-hook
```

The [pre-push hook](../scripts/hooks/pre-push) runs the complete local unit
and case-test suites. It is an early failure signal, not a substitute for
naming the relevant happy-path and abnormal-path tests and their current-head
results in the pull request.

## Naming

- Top-level harness directories use the stable names `ai_docs/`, `spec/`,
  `pipelines/`, and `skills/`.
- Markdown filenames use lowercase kebab-case, except conventional
  `README.md`, `SKILL.md`, and the adapter template
  `PROJECT_INSTRUCTIONS.md`.
- Skill directories use the same lowercase hyphenated name as the `name`
  field in their `SKILL.md`.
- Capability behavior specifications use
  `spec/<capability>/spec.md`.
- Temporary plans, retrospectives, logs, and validation output do not belong
  in `harness/`.
- Task-scoped issue-check reports belong under the ignored
  `build/harness/<task-id>/` directory and must not be committed.
- Tool-native local adapters such as `.claude/` are allowed locally but
  must not become committed sources of truth. Migrate durable skill content to
  `harness/skills/`.
- Closed-source or environment-specific rules belong under ignored
  `harness/private/` and must not be referenced as required public harness
  inputs.

## Portability

`harness/` is the canonical committed source, independent of a particular
agent product. Tools that require native discovery directories may install or
link these skills into their own ignored directory, but should not maintain a
second committed copy. Every skill keeps its portable instructions in
`SKILL.md`; platform-specific metadata is optional. Project-instruction
adapters should link to or be generated from
`spec/PROJECT_INSTRUCTIONS.md`.
