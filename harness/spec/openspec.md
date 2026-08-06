# OpenSpec Integration

OpenSpec is the long-task planning layer for this harness. Use it when a task
is long-running, cross-module, design-heavy, or likely to outlive a single
chat context.

## Source

OpenSpec is an open-source spec-driven development framework maintained at
https://github.com/Fission-AI/OpenSpec and documented at
https://openspec.dev/docs. Its model is to agree on specs before code is
written, then keep proposal, design, tasks, and requirement deltas together in
an `openspec/` change directory.

OpenSpec's documented flow for current tools uses commands such as
`/opsx:explore`, `/opsx:propose`, `/opsx:apply`, and `/opsx:archive`; Codex
may expose equivalent prompt names after `openspec init` or `openspec update`.
Use the names installed in the current environment rather than hard-coding a
tool-specific spelling.

## When Required

Use OpenSpec before implementation for:

- long-running goals or background work;
- feature work with ambiguous acceptance criteria;
- cross-module transport, TLS, HTTP/3, MoQ, or harness changes;
- behavior changes that need reviewer alignment before code; and
- changes that should leave durable requirement deltas.

Small bug fixes with clear acceptance criteria may use the development
pipeline directly unless the user asks for OpenSpec.

## Required Artifacts

Before implementation, create or update the task's OpenSpec change with:

- proposal: why the change exists and what is in or out of scope;
- design: source paths, affected protocol boundaries, tradeoffs, and risks;
- tasks: ordered implementation and validation checklist;
- specs: added, modified, or removed requirements with concrete scenarios.

Keep OpenSpec artifacts out of `harness/`; they belong under the
tool-managed `openspec/` tree. Do not vendor the OpenSpec project source into
this repository.

## Completion

Before opening or updating a code pull request for an implemented OpenSpec
change, fold durable conclusions into the repository harness:

- ongoing requirements belong in `harness/spec/`;
- machine routing belongs in `harness/spec/harness-manifest.yml` or another
  declared manifest;
- explanatory navigation belongs in `harness/docs/`;
- durable rationale belongs in `harness/decisions/`; and
- temporary proposals, task lists, and design drafts remain outside the final
  PR unless the PR's explicit purpose is to review the OpenSpec change itself.

If the OpenSpec CLI is available, archive the completed change with the
installed OpenSpec command. If the archive workflow is not available, remove
the completed change directory after its durable content is represented in the
harness.

## Local Setup

If OpenSpec is not installed, prefer a local ignored install before global
installation:

```bash
npm install --prefix .ai-context/openspec-cli @fission-ai/openspec@latest
.ai-context/openspec-cli/node_modules/.bin/openspec --help
```

If the environment already has a trusted global install, `openspec --help`
is also acceptable. Initialize only after confirming the repository should own
an `openspec/` tree:

```bash
openspec init
```

When tool bindings drift after an upgrade or teammate switch, run:

```bash
openspec update
```

Network or package installation requires explicit user approval. If setup
cannot run, draft the intended OpenSpec artifacts in the response and state
the blocker.

When prompting a long-task agent, include this missing-environment hint:

```text
If `openspec` is unavailable, first try
`.ai-context/openspec-cli/node_modules/.bin/openspec`. If that path is missing,
ask before installing with
`npm install --prefix .ai-context/openspec-cli @fission-ai/openspec@latest`.
Do not vendor OpenSpec into the repository.
```

## Codex Goal Usage

For long tasks, use the active agent runtime's native goal/background
directive and include:

- the OpenSpec change name or path;
- the selected harness entry point;
- required source/spec files already read;
- validation evidence expected at completion; and
- stop conditions that require user review.

Keep the OpenSpec change path visible in the long-task prompt so another
agent can resume from the same proposal, design, tasks, and spec deltas.
