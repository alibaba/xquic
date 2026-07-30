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
- `scripts/xqc_harness_check.sh`

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
- Enforce reference consistency through `scripts/xqc_harness_check.sh`.

Consequences:
- Root prompt size stays bounded.
- Agents can load narrow context for the current task.
- Harness edits must update both references and self-checks when the layer
  contract changes.

Evidence:
- `AGENTS.md`
- `harness/ai_docs/README.md`
- `harness/spec/doc-style.md`
- `harness/spec/harness-manifest.yml`
- `scripts/xqc_harness_check.sh`
