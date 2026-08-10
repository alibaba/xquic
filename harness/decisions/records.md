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
- Use `harness/docs/README.md` to explain the four-quadrant model:
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
- `harness/docs/README.md`
- `harness/spec/harness-behavior.md`
- `harness/spec/harness-manifest.yml`
- `harness/scripts/xqc_harness_check.sh`

## ADR-H002: Use Five Harness Loading Layers

Status: Accepted

Date: 2026-07-30

Context:
- Agents need a small always-injected prompt plus enough structure to fetch
  detailed context only when a task needs it.
- Repeating task procedures in root docs, explanatory docs, skills, and
  scripts makes the harness harder to update safely.
- Machine-readable routing must be separated from explanatory rationale.

Decision:
- Keep `AGENTS.md` as the strong injection layer.
- Put detailed workflows in on-demand pipelines, skills, and specs.
- Keep path, module, docs, tests, feature flags, and validation routing in the
  manifest as the machine mapping layer.
- Keep durable explanations in `harness/docs/`, design rationale in
  `harness/decisions/`, and avoid duplicating procedural workflows.
- Enforce reference consistency through `harness/scripts/xqc_harness_check.sh`.

Consequences:
- Root prompt size stays bounded.
- Agents can load narrow context for the current task.
- Harness edits must update both references and self-checks when the layer
  contract changes.

Evidence:
- `AGENTS.md`
- `harness/docs/README.md`
- `harness/spec/harness-behavior.md`
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
  `openspec/` while the task is being reviewed or implemented.
- Before a code PR for the implemented result, fold durable conclusions into
  `harness/spec/`, `harness/docs/`, `harness/decisions/`, and machine
  manifests; do not commit completed task checklists as the lasting harness.

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

## ADR-H005: Classify Documents By Authority Rather Than Audience

Status: Accepted

Date: 2026-08-03

Context:

- An `ai_docs` category described a consumer while `spec` described an
  authority level, so the two categories were not mutually exclusive.
- The explanation layer contained behavior specifications and procedural
  change instructions, making it unclear which files could define
  requirements.
- The repository needs paths whose semantic role remains stable for both human
  and agent consumers.

Decision:

- Keep normative requirements and contracts under `harness/spec/`.
- Keep informative maps and maintenance guidance under `harness/docs/`.
- Keep design rationale under `harness/decisions/`.
- Treat audience and loading strategy as independent from document authority.
- Declare document roles in the manifest and validate the directory contract
  in the harness self-check.

Consequences:

- A file's directory identifies whether it can define requirements.
- Informative documents and ADRs link to specifications instead of creating
  independent constraints.
- The same source can serve maintainers, contributors, and agents without an
  audience-specific duplicate.

Evidence:

- `harness/spec/harness-behavior.md`
- `harness/spec/harness-manifest.yml`
- `harness/docs/README.md`
- `harness/scripts/harness_manifest_check.rb`
- `harness/scripts/xqc_harness_check.sh`

## ADR-H006: Keep Public Skills Free Of Contributor Configuration

Status: Accepted

Date: 2026-08-03

Context:

- A public push skill embedded one contributor's fork URL and treated local
  remote names as stable repository identities.
- Remote aliases, writable forks, usernames, and worktree locations vary by
  contributor and machine.
- Executing a hard-coded remote setup can publish to the wrong repository or
  mutate a contributor's Git configuration unexpectedly.

Decision:

- Public skills derive remote names, push URLs, and workspace locations from
  the current repository and explicit user request.
- Public skills do not embed contributor usernames, personal fork URLs, or
  user-specific absolute home paths.
- Push workflows inspect configured remotes and do not create, rename, or
  repoint them without an explicit request.
- Harness self-checks reject hard-coded Git remote URLs in public skills and
  user-specific absolute home paths in committed harness content.

Consequences:

- The same public skill works for maintainers and fork-based contributors.
- Local Git configuration remains user-owned instead of being silently
  rewritten by a repository instruction.
- Canonical public project URLs remain available where repository identity is
  part of the documentation rather than an operational default.

Evidence:

- `harness/skills/xquic-safe-push/SKILL.md`
- `harness/spec/harness-behavior.md`
- `harness/scripts/xqc_harness_check.sh`

## ADR-H007: Route Endpoint Cases Through Metadata Before Moving Bodies

Status: Accepted

Date: 2026-08-06

Context:

- `case_test/legacy/full_suite.sh` contains hundreds of endpoint checks that
  previously lived in `scripts/case_test.sh`.
- Agents need to identify relevant endpoint cases from changed source paths
  without running the full suite during ordinary iteration.
- Moving every case body at once would create high review risk and make
  behavior drift hard to isolate.

Decision:

- Keep `scripts/case_test.sh` as the compatibility entry point.
- Move the full-suite body to `case_test/legacy/full_suite.sh` so the public
  entry point can stay small.
- Add `case_test/manifest.yml` for endpoint case group metadata.
- Let selector mode classify legacy `case_print_result` names from the current
  full-suite body instead of copying every legacy name into multiple durable
  documents.
- Treat `owned_legacy_name_patterns` as the single execution owner map: every
  legacy case has exactly one shard owner even when multiple features are
  relevant to diagnosis.
- Add selected execution and parallel scheduling for groups marked
  `execution: implemented`.
- Give each shard a stable manifest-owned port offset and an isolated work
  directory. Use PID cleanup for migrated shards instead of global process
  termination; keep build-generated certificates as read-only shared inputs.
- Use hand-migrated runners where available, and use the legacy-owned runner
  to extract only a shard's owned case blocks from the legacy suite until the
  bodies are migrated by module.
- Keep moving case bodies into `case_test/<module>/` incrementally after
  generated selected execution is stable.

Consequences:

- Changed paths can be mapped to endpoint case groups while the legacy full
  suite remains available.
- The harness check can detect stale runner paths, unknown modules, unknown
  features, duplicate group IDs, duplicate port offsets, stale legacy
  ownership patterns, repeated case owners, missing case owners, and invalid
  selected execution states.
- Selector output is discovery evidence, not a passing endpoint test result.
  Selected execution evidence requires actually running the owning shard.
- Full-suite parallel requests fail closed while executable shards are
  incomplete. Once the execution plan has no missing cases, each unique legacy
  case is executed by exactly one shard.
- Pending module runners fail clearly when invoked directly.

Evidence:

- `case_test/manifest.yml`
- `case_test/legacy/full_suite.sh`
- `scripts/case_test.sh`
- `harness/spec/validation.md`
- `harness/spec/harness-manifest.yml`
- `harness/scripts/harness_manifest_check.rb`
