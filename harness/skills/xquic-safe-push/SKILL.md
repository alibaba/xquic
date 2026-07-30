---
name: xquic-safe-push
description: Safely stage, commit, and push XQUIC changes after scoped Git checks. Use when asked to stage, commit, push, publish a branch to a fork, or verify that only intended files will be sent to a remote.
---

# XQUIC Safe Push

This skill owns local Git scope, commit, and push safety. It does not own pull
request body content, review state, validation semantics, or PR pre-review.
Use PR-specific skills only when those tasks are explicitly in scope.

## Preflight

1. Read `AGENTS.md` and honor branch policy: never push directly to remote `main` or `master`.
2. Check `git status --short --untracked-files=all`, `git branch --show-current`, and `git remote -v`.
3. **Fork remote check**: Verify the `fork` remote exists and points to `git@github.com:cherylsy/xquic.git`:
   ```bash
   git remote get-url fork 2>/dev/null || \
     git remote add fork git@github.com:cherylsy/xquic.git
   ```
4. Determine the push target from the user request and repository remotes. For
   alibaba/xquic contributions, push contribution branches to `fork`.
5. Show staged and unstaged scopes separately using `git diff --cached --name-status` and `git diff --name-status`.
6. If the user requested staged-only behavior, do not add any other files.
7. If user-owned unrelated edits exist, leave them untouched and name them before proceeding.
8. Confirm the target remote and branch before pushing.

## Commit

- Commit only the intended staged files.
- Follow `CONTRIBUTING.md`: commit headers use `[<type>]: <subject>` with
  `+`, `-`, `=`, or `~`.
- Use one concern per commit and keep debug/log-only commits out of the final
  branch history.
- After commit, verify the new commit with `git log --oneline --decorate --max-count=3`.

## Push

Before pushing, show:

- current branch
- target remote and branch (must be `fork` for contribution branches unless the
  user names another writable fork)
- commits that will be pushed
- local uncommitted files that will remain local

Push only after the user confirms, unless the same message already explicitly requested the push target and branch.

For contribution branches:
```bash
git push fork <branch-name>
```

## Forbidden

- Do not push to `origin main`, `origin master`, or any remote main/master.
- Do not push to `origin` at all for xquic code changes (origin is the upstream `alibaba/xquic` -- read-only for pushes).
- Do not use `--force` unless the user explicitly requested it. Prefer `--force-with-lease` when force is necessary.
- Do not reset, checkout, clean, or remove files to simplify the state unless explicitly requested.

## Git Conventions

### Remotes

```
origin  -> git@github.com:alibaba/xquic.git     (upstream, read-only for pushes)
fork    -> git@github.com:cherylsy/xquic.git     (fork, default contribution push target)
```

- Contribution branches are pushed to the `fork` remote unless the user names
  a different writable fork.

### Worktree Convention

Each issue uses an independent git worktree for parallel isolation:

```
<project-root>/                     (main worktree)
../xquic-issue-<N>/                 (issue worktree)
```

Lifecycle: `git worktree add` -> work -> push to fork -> PR handling by the
relevant PR skill -> `git worktree remove`.
