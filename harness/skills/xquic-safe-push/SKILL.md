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
3. Resolve the intended push remote from the user request and the repository's
   current configuration:
   ```bash
   git remote -v
   git remote get-url --push <target-remote>
   ```
   Remote names such as `origin`, `upstream`, or `fork` are local conventions,
   not portable identities. Do not create, rename, or repoint a remote unless
   the user explicitly requests that configuration change.
4. Use an explicitly named target when the user provides one. Otherwise use
   the current branch's configured upstream only when its push URL and intended
   ownership are unambiguous; ask before pushing when multiple or unclear
   writable targets exist.
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
- target remote, resolved push URL, and branch
- commits that will be pushed
- local uncommitted files that will remain local

Push when the requester explicitly asks to push or create a pull request. Also
push when the development pipeline reaches its default publication stage and
the requester has not asked to stop before publication. A missing, ambiguous,
or apparently unwritable target still requires confirmation.

Push to the resolved target without embedding repository ownership in the
skill:

```bash
git push <target-remote> <branch-name>
```

## Forbidden

- Do not push to `origin main`, `origin master`, or any remote main/master.
- Do not assume a remote name identifies an upstream repository, a personal
  fork, or a writable target; resolve its configured push URL first.
- Do not hard-code or automatically add a contributor-owned repository URL.
- Do not use `--force` unless the user explicitly requested it. Prefer `--force-with-lease` when force is necessary.
- Do not reset, checkout, clean, or remove files to simplify the state unless explicitly requested.

## Git Conventions

### Remotes

- Treat all remote names and URLs as repository-local configuration.
- Resolve the selected remote with `git remote get-url --push` immediately
  before pushing.
- Prefer the target named by the user. If none is named, use a configured
  branch upstream only when it is clearly intended and writable.
- Keep contributor usernames, fork URLs, and machine-specific paths out of
  this public skill.

### Worktree Convention

Each issue uses an independent git worktree for parallel isolation:

```
<project-root>/                         (main worktree)
<workspace-parent>/<repo>-<task-id>/    (task worktree)
```

Lifecycle: `git worktree add` -> work -> push to the resolved target -> PR
handling by the relevant PR skill -> `git worktree remove`.
