---
name: git-workflow
description: Branch naming, commit message markers, and rebase/squash conventions for xquic. Use when creating branches, writing commit messages, preparing a merge request/PR, or rebasing onto the latest trunk.
---

# Git Workflow

Single source of truth for xquic branch, commit, and rebase conventions. Push mechanics (remotes, fork, worktrees) live in the `xquic-safe-push` skill.

## Branch Naming

| Purpose | Pattern | Example |
|---------|---------|---------|
| New feature | `dev/<feature-name>` | `dev/fec-repair` |
| Bug fix | `fix/<module-abbr>` | `fix/qpack` |
| Performance | `perf/<optimization-name>` | `perf/send-ctl` |
| Packaging / submodule sync | `stable/<product-name>` | `stable/tengine` |
| Trunk | `master` | — |

## Stability & Merge Flow

- Stability order: `master` > `stable/*` > dev branches (`dev/*`, `fix/*`, `perf/*`).
- Merge direction: dev branch -> `stable/*` -> `master`. Never merge a lower-stability branch straight into `master`.
- `stable/*` gate: 100% regression pass + new-feature verification / integration done.
- `master` gate:
  - Client: one grayscale release (active UV > 10000) with no crash or monitorable functional regression.
  - Server: >= 24h grayscale in an isolated group with no crash or monitorable functional regression.
- Ship small: open a merge request as soon as one feature/change is done. Do not batch thousands of lines into a single MR.

## Commit Messages

Format: `[<marker>] <change point>`. Markers describe the effect on behavior:

| Marker | Meaning |
|--------|---------|
| `+` | New feature / completed requirement |
| `-` | Removed dead code or functionality |
| `=` | Behavior-preserving change (refactor / optimization) |
| `~` | Behavior change (bug fixes that alter behavior included) |

Rules:
- Description is imperative, lowercase, concise.
- xquic-ops issue work links the issue number: `[+] #<N> <desc>`, optionally with PR ref `[+] #<N> <desc> (#<PR>)`.
- Do NOT use conventional commits (`fix:`, `feat:`, etc.).
- One concern per commit; split unrelated changes.
- `Co-Authored-By:` trailer is optional but recommended for AI-assisted commits.
- Debug/log-only commits made during development should be squashed before the MR (see Squash).

## Rebase Before Merging Trunk

Keep history linear and traceable. Both flows edit only your own branch, then go through a merge request / PR for review (never operate on `master` directly).

Rebase onto the latest `master`:

```bash
git checkout <branch>
git rebase master
git push origin <branch> -f
```

## Squash Local Commits

Fold noisy debug/log commits before review. `~N` is the count of recent commits to rework:

```bash
git rebase -i HEAD~<N>
git push origin <branch> -f
```

In the interactive editor, change `pick` to `s` (squash) on the commits to fold. The first (oldest) line cannot be squashed. Save and exit (`:wq`) twice, then force-push.

Force-push safety: prefer `--force-with-lease` over `-f` on shared branches; only rewrite history on your own branch.
