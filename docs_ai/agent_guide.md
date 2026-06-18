# Agent Workflow Notes

> Non-global operational guidance for agents. Global constraints remain in `CLAUDE.md`; pipeline-specific rules remain in `docs_ai/dev_pipeline.md`, `docs_ai/bugfix_pipeline.md`, and `docs_ai/validation_guide.md`.

## Scope

This document contains guidance that improves agent success rate but is not a strict global project constraint. Use it when the task benefits from a more explicit execution structure, context-preservation checklist, or topic-specific reminder.

## Recommended Workflow For Non-Trivial Work

Use this flow when a task spans multiple files, has uncertain behavior, or could affect public APIs:

1. **Explore**: Read `CLAUDE.md`, classify the task, read the required entry-point doc, inspect relevant source/tests/docs, and summarize findings.
2. **Plan**: State the intended files, behavior change, risks, and verification command(s). For user-facing or high-risk changes, wait for confirmation if the user asked for planning first.
3. **Implement**: Keep edits scoped to the task and follow existing project patterns.
4. **Verify**: Use `docs_ai/validation_guide.md` to decide and run the smallest needed build/test workflow. If verification cannot be run, state why and provide the closest safe evidence.
5. **Report**: Summarize changed files, behavior impact, docs updated, and exact verification result.

For simple query/analysis tasks, answer from inspected code/docs and cite the concrete files or symbols used.

## Prompting Checklist

When a user request is broad, preserve these details before acting:

- Goal and non-goals.
- Relevant files, modules, symbols, and docs.
- Hard constraints from `CLAUDE.md` and from the selected pipeline doc.
- Required verification command(s) and build environment.
- Any user-specified ordering, especially for git, branch, rebase, or release flows.
- Any unresolved decision that needs user confirmation.

## Background Goal Usage

For long-running goals, use:

```bash
./scripts/goal.sh "Implement feature X"
./scripts/goal.sh --list
./scripts/goal.sh --logs <id>
./scripts/goal.sh --attach <id>
./scripts/goal.sh --stop <id>
```
