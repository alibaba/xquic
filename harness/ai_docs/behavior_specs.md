# Harness Behavior Specs

These invariants keep the harness useful to agents and safe for public review.

## Source Boundaries

- Committed `harness/` content is public/open by default.
- Closed-source content stays under ignored `harness/private/`.
- Local adapter directories such as `.agents/` and `.claude/` are not
  committed sources of truth.
- Public harness tasks must be executable without private context unless the
  user explicitly provides that context.

## Structure Boundaries

- Common guidance should avoid XQUIC-specific paths, services, issue numbers,
  or feature names.
- Custom guidance may mention XQUIC paths and protocols, but should avoid
  one-off task details.
- Feature routing belongs under its owning module in
  `harness/spec/harness-manifest.yml`.
- Do not encode hierarchy with colon-delimited manifest keys.

## Documentation Behavior

- Root docs point to durable sources instead of duplicating their tables.
- Mapping data belongs in `harness/spec/harness-manifest.yml`.
- AI docs and skills may point to the manifest but must not maintain a second
  path-to-module or path-to-validation map.
- Explanatory docs may describe how to use mapping data but should not
  maintain competing maps.
- Durable comments and documentation follow `harness/spec/doc-style.md`.
- Private extension points may be documented as optional, not mandatory.
- Task-local logs, detection output, failure hypotheses, and final evidence
  stay under ignored `build/harness/runs/<task-id>/`.

## Loading Behavior

- `AGENTS.md` stays short enough to serve as the strong injection layer.
- Detailed procedures live in on-demand pipelines, skills, and specs.
- The manifest is the single source of truth for path-to-module routing.
- AI docs explain durable context; they do not duplicate workflow steps.
- Skills are selected by the current task purpose. Skill names are entry
  points, not a required linear route.

## Skill Boundaries

- `harness-review` owns harness structure review for bloat, duplicate facts,
  trigger overlap, reference drift, and missing hard checks. It does not own
  product validation or PR content updates.
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
- Shared contribution rules point to `CONTRIBUTING.md` and PR specs instead of
  a separate Git workflow skill.

## Validation Behavior

- Harness changes run `bash scripts/xqc_harness_check.sh`.
- Registration changes run `bash scripts/tests/setup_harness_test.sh`.
- Hook changes run `bash scripts/tests/pre_push_hook_test.sh`.
- Runtime product validation stays in `scripts/validate.sh` and related
  validation specs.
