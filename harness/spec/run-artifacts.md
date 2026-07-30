# Run Artifacts

Use this contract for task-local evidence, command logs, detection output, and
failure analysis. These artifacts are ignored runtime evidence, not durable
repository documentation.

## Directory

The canonical task evidence directory is:

```text
build/harness/runs/<task-id>/
```

Use a stable `<task-id>` that is meaningful for the current task, such as a
short issue id, branch suffix, OpenSpec change name, or timestamped local
label. Do not commit files from this directory.

## Files

Initialize the directory with:

- `task.md`: task type, acceptance criteria, non-goals, stop conditions.
- `read-files.md`: files read before editing and why each one mattered.
- `detect.md`: detection output, manifest route, affected module, selected
  docs, selected tests, and feature gates.
- `commands.log`: exact commands run and where their full output is stored.
- `failures.md`: failed commands, current hypothesis, next diagnostic step,
  and resolved root cause when known.
- `evidence.md`: final evidence, validation status, remaining blockers, and
  documentation synchronization.

OpenSpec long tasks keep proposal, design, tasks, and requirement deltas under
`openspec/`. Mirror only the current run evidence here, and link to the
OpenSpec change path from `task.md` or `evidence.md`.

## Initialization

From the repository root:

```bash
harness/scripts/harness_trace.sh init <task-id>
```

The command prints the created run directory. Re-running it preserves existing
files and creates only missing templates.

## Use

- Start the directory after requirement analysis, before implementation.
- Append command lines to `commands.log` before or immediately after running
  them.
- Put large raw logs beside these files or in validation artifact directories;
  summarize their location in `commands.log`.
- Update `failures.md` after each failed build, test, or CI investigation.
- Summarize final validation and documentation evidence in `evidence.md`.
