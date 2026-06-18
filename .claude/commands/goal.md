Start a background goal-directed long task for the xquic_ops project.

Usage: /goal <task description>

Arguments: $ARGUMENTS

Instructions:

1. Parse the task description from $ARGUMENTS.
2. Read CLAUDE.md to determine the task type (code change / test execution / build / query).
3. Run the goal as a background agent using the Bash tool:

```
bash /Users/suiyi/claude/xquic_ops/scripts/goal.sh "<task description>"
```

4. Report back the session ID and how to check progress:
   - `claude agents` -- list all running goals
   - `claude logs <id>` -- check output
   - `claude attach <id>` -- take over interactively
   - `claude stop <id>` -- cancel

If $ARGUMENTS is empty, ask the user what goal to run.
