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
- Explanatory docs may describe how to use mapping data but should not
  maintain competing maps.
- Durable comments and documentation follow `harness/spec/doc-style.md`.
- Private extension points may be documented as optional, not mandatory.

## Loading Behavior

- `AGENTS.md` stays short enough to serve as the strong injection layer.
- Detailed procedures live in on-demand pipelines, skills, and specs.
- The manifest is the single source of truth for path-to-module routing.
- AI docs explain durable context; they do not duplicate workflow steps.

## Validation Behavior

- Harness changes run `bash scripts/xqc_harness_check.sh`.
- Registration changes run `bash scripts/tests/setup_harness_test.sh`.
- Hook changes run `bash scripts/tests/pre_push_hook_test.sh`.
- Runtime product validation stays in `scripts/validate.sh` and related
  validation specs.
