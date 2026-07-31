# Harness Decision Records

Record only decisions with ongoing harness impact.

## ADR-H001: Split Harness Docs by Public/Private and Common/Custom

Status: Accepted

Date: 2026-07-29

Context:
- The harness must support reusable open-source guidance and repository-specific
  XQUIC guidance.
- Some environments may need private adapters or runbooks that should not be
  committed.
- Agents need a stable way to decide whether a rule is reusable, project
  specific, or private.

Decision:
- Use `harness/ai_docs/` to document the four-quadrant model:
  public common, public custom, private common, and private custom.
- Keep committed `harness/` public/open by default.
- Keep closed-source content under ignored `harness/private/`.
- Keep routing data in `harness/spec/harness-manifest.yml`.

Consequences:
- Agents can extend the harness without mixing private context into public docs.
- New reusable skills should live under `harness/skills/`.
- New XQUIC-specific facts should live under `harness/spec/` or the manifest.
- Private assumptions must be optional unless explicitly supplied by the user.

Update triggers:
- Revisit if the repository adopts a different public/private split or if
  private content must be packaged separately.

Evidence:
- `harness/README.md`
- `harness/ai_docs/README.md`
- `harness/spec/harness-manifest.yml`
- `harness/scripts/xqc_harness_check.sh`

## ADR-H002: Use Five Harness Loading Layers

Status: Accepted

Date: 2026-07-30

Context:
- Agents need a small always-injected prompt plus enough structure to fetch
  detailed context only when a task needs it.
- Repeating task procedures in root docs, AI docs, skills, and scripts makes
  the harness harder to update safely.
- Machine-readable routing must be separated from explanatory rationale.

Decision:
- Keep `AGENTS.md` as the strong injection layer.
- Put detailed workflows in on-demand pipelines, skills, and specs.
- Keep path, module, docs, tests, feature flags, and validation routing in the
  manifest as the machine mapping layer.
- Keep durable context in AI docs and avoid duplicating procedural workflows.
- Enforce reference consistency through `harness/scripts/xqc_harness_check.sh`.

Consequences:
- Root prompt size stays bounded.
- Agents can load narrow context for the current task.
- Harness edits must update both references and self-checks when the layer
  contract changes.

Evidence:
- `AGENTS.md`
- `harness/ai_docs/README.md`
- `harness/spec/doc-style.md`
- `harness/spec/run-artifacts.md`
- `harness/spec/harness-manifest.yml`
- `harness/scripts/xqc_harness_check.sh`

## ADR-H003: Keep Runtime Evidence Outside Durable Docs

Status: Accepted

Date: 2026-07-30

Context:
- Long tasks and failed validation often need command logs, detection output,
  hypotheses, and final evidence that should not be committed as docs.
- Previous ad hoc locations made it hard for another agent to resume from the
  same evidence chain.

Decision:
- Use ignored `build/harness/runs/<task-id>/` as the task-local run evidence
  directory.
- Create the directory directly when durable task-local evidence is needed.
- Keep OpenSpec proposal, design, tasks, and requirement deltas in
  `openspec/`, and link to them from the run evidence when applicable.

Consequences:
- Durable docs stay concise.
- Validation logs and failed-test analysis have a predictable place.
- Agents can resume a task by reading the same evidence files.

Evidence:
- `harness/spec/run-artifacts.md`
- `harness/spec/openspec.md`

## ADR-H004: Keep Git And PR Skills Purpose-Bound

Status: Accepted

Date: 2026-07-30

Context:
- A single Git workflow skill duplicated branch, commit, PR, and push rules
  already present in `CONTRIBUTING.md`, PR specs, and narrower skills.
- Chaining issue, Git, PR formatting, pre-review, comments, and CI
  skills into one mandatory path reduces agent autonomy and creates redundant
  update points.
- The general PR review trigger overlapped the code-PR pre-review gate, while
  the pre-review skill has the stricter XQUIC-specific report and fail-closed
  output needed before ready-for-review state.

Decision:
- Remove the standalone Git workflow skill.
- Remove the general `gh-pr-review` skill and keep `xquic-pr-pre-review` as the
  code-PR review gate.
- Keep `gh-address-comments` as the post-review comment-fix entry point.
- Keep shared contribution rules in `CONTRIBUTING.md` and PR specs.
- Keep `xquic-safe-push` limited to local Git scope, commit, branch target, and
  push safety.
- Keep `xquic-pr-formatting` limited to PR body content and draft/review state
  checks.
- Select PR, comment-fix, CI, and Git skills by task purpose rather than by a
  fixed skill chain.

Consequences:
- Agents can choose only the skill that matches the active task, without a
  second general PR-review trigger competing with the stricter pre-review gate.
- Git/PR policy changes have fewer sources to update.
- Code-PR pre-review remains a state gate before moving a draft code PR to
  review, not a universal PR-workflow chain step.

Evidence:
- `harness/skills/xquic-pr-pre-review/SKILL.md`
- `harness/skills/gh-address-comments/SKILL.md`
- `harness/skills/xquic-safe-push/SKILL.md`
- `harness/skills/xquic-pr-formatting/SKILL.md`
- `harness/spec/pull-requests.md`
- `harness/pipelines/dev-pipeline.md`
