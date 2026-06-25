---
name: xquic-safe-push
description: Safely commit and push xquic changes after scoped Git checks. Use when asked to stage, commit, push, publish to a fork, create a PR branch, or verify that only intended files will be sent to a remote.
---

# XQUIC Safe Push

## Preflight

1. Read `AGENTS.md` and honor branch policy: never push directly to remote `main` or `master`.
2. Check `git status --short --untracked-files=all`, `git branch --show-current`, and `git remote -v`.
3. **Fork remote check**: Verify the `fork` remote exists and points to `git@github.com:cherylsy/xquic.git`:
   ```bash
   git remote get-url fork 2>/dev/null || \
     git remote add fork git@github.com:cherylsy/xquic.git
   ```
4. **Determine push target**:
   - Issue branches (`issue-*`) -> push to `fork` remote (ALWAYS)
   - Maintenance branches (`dev/agent`, etc.) -> push to `origin` (ops repo only)
   - If uncertain, default to `fork`
5. Show staged and unstaged scopes separately using `git diff --cached --name-status` and `git diff --name-status`.
6. If the user requested staged-only behavior, do not add any other files.
7. If user-owned unrelated edits exist, leave them untouched and name them before proceeding.
8. Confirm the target remote and branch before pushing.

## Commit

- Commit only the intended staged files.
- Use a concise message matching the change type, for example `fix: reject zero-length CID in NEW_CONNECTION_ID`.
- After commit, verify the new commit with `git log --oneline --decorate --max-count=3`.

## Push

Before pushing, show:

- current branch
- target remote and branch (must be `fork` for issue branches)
- commits that will be pushed
- local uncommitted files that will remain local

Push only after the user confirms, unless the same message already explicitly requested the push target and branch.

For issue branches:
```bash
git push fork <branch-name>
```

## Forbidden

- **Do not push issue branches to `origin`**. All issue branches (`issue-*`) must go to the `fork` remote.
- Do not push to `origin main`, `origin master`, or any remote main/master.
- Do not push to `origin` at all for xquic code changes (origin is the upstream `alibaba/xquic` -- read-only for pushes).
- Do not use `--force` unless the user explicitly requested it. Prefer `--force-with-lease` when force is necessary.
- Do not reset, checkout, clean, or remove files to simplify the state unless explicitly requested.

## Fork Remote Reference

```
origin  -> git@github.com:alibaba/xquic.git     (upstream, read-only for pushes)
fork    -> git@github.com:cherylsy/xquic.git     (fork, push target for issue branches)
```
