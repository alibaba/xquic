# Harness Behavior Specification

This specification defines the normative invariants for the repository-owned
harness. Explanatory documents and decision records may link to these rules but
do not create competing requirements.

## Documentation Authority

- `harness/spec/` contains authoritative, durable requirements and contracts.
- `harness/docs/` contains informative explanations, navigation, examples, and
  maintenance guidance. It must not introduce an independent requirement.
- `harness/decisions/` records design rationale. When an accepted decision
  creates an ongoing requirement, the same change must express that
  requirement in the owning specification.
- The intended reader or tool does not determine authority. Agent-facing and
  human-facing material use the same semantic roles.
- Document authority is independent of loading strategy. A harness-layer
  assignment must not be used to grant or infer normative authority.
- When informative documentation or a decision record conflicts with a
  harness specification, the specification governs and the stale material
  must be corrected.
- `harness/spec/harness-manifest.yml` is the machine-readable source for
  document-role and routing assignments.

## Source Boundaries

- Committed `harness/` content is public/open by default.
- Closed-source content stays under ignored `harness/private/`.
- Local adapter directories such as `.agents/` and `.claude/` are not
  committed sources of truth.
- Public harness tasks must be executable without private context unless the
  user explicitly provides that context.

## Structure Boundaries

- Common guidance avoids XQUIC-specific paths, services, issue numbers, and
  feature names.
- Custom guidance may mention XQUIC paths and protocols but avoids one-off
  task details.
- Feature routing belongs under its owning module in
  `harness/spec/harness-manifest.yml`.
- Manifest hierarchy uses nested maps, not colon-delimited keys.

## Documentation Behavior

- Root documents point to durable sources instead of duplicating their tables.
- Mapping data belongs in `harness/spec/harness-manifest.yml`.
- Documents and skills may point to the manifest but must not maintain a
  second path-to-module, document-role, or path-to-validation map.
- Informative documents may describe how to use mapping data but must not
  maintain competing maps or workflow requirements.
- Durable comments and documentation follow `harness/spec/doc-style.md`.
- Private extension points may be documented as optional, not mandatory.
- Task-local logs, detection output, failure hypotheses, and final evidence
  stay under ignored `build/harness/runs/<task-id>/`.

## Loading Behavior

- `AGENTS.md` stays short enough to serve as the strong injection layer.
- Detailed procedures live in on-demand pipelines and skills.
- Durable requirements live in specifications, independently of how a tool
  loads them.
- The manifest is the single source of truth for path-to-module and
  document-role routing.
- Informative documents explain durable context without duplicating workflow
  steps or normative requirements.
- Skills are selected by the current task purpose. Skill names are entry
  points, not a required linear route.

## Skill Boundaries

- `harness-review` owns harness structure review for bloat, duplicate facts,
  trigger overlap, reference drift, authority drift, and missing hard checks.
  It does not own product validation or PR content updates.
- Code-PR pre-review, review-comment fixes, CI fixes, PR formatting, and safe
  push remain separate entry points.
- `xquic-pr-pre-review` is the only review gate for moving a code pull request
  toward ready-for-review state.
- `gh-address-comments` remains the entry point for editing after reviewer
  comments or requested changes.
- `xquic-safe-push` owns local Git scope, commits, branch targets, and push
  safety. It does not own PR body content, PR review state, CI diagnosis, or
  review-comment fixes.
- `xquic-pr-formatting` owns concise PR body content, summary-to-code
  consistency after published head changes, and draft/review state checks. It
  does not stage, commit, push, rebase, force-push, diagnose CI, or perform
  code review.
- Shared contribution rules point to `CONTRIBUTING.md` and PR specifications
  instead of a separate Git workflow skill.

## Validation Behavior

- Harness changes run `bash harness/scripts/xqc_harness_check.sh`.
- The harness check validates committed harness structure, document roles, and
  synchronization with repository code entry points.
- Pull request events pass the PR body to the same harness check so
  contributor-facing summaries cannot retain missing repository paths after a
  pushed head changes.
- Runtime product validation stays in `scripts/validate.sh` and related
  validation specifications.
