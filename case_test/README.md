# Case Test Routing

This directory contains metadata and helpers for routing endpoint
client-to-server case tests. The legacy executable entry point remains
`scripts/case_test.sh`.

## Files

- `manifest.yml` maps source paths, modules, features, and legacy
  `case_print_result` names to case-test groups.
- `lib/selector.rb` powers list, inventory, dry-run, and runner-map output for
  `scripts/case_test.sh`.
- `lib/runner.sh` preserves full-suite compatibility and provides selected
  execution scheduling.
- `legacy/full_suite.sh` contains the current full endpoint suite.
- Module directories hold future case runners. Existing case bodies may remain
  in `legacy/full_suite.sh` until they are moved incrementally.

## Compatibility

Running `scripts/case_test.sh` without selector arguments preserves the legacy
full-suite behavior. Selector mode is used for discovery and dry-run evidence
while case bodies are migrated.

Use `bash scripts/case_test.sh --inventory` to audit how many legacy case
names are matched, unmatched, or matched by multiple groups.

Use the architecture check when changing the runner, selector, or legacy
compatibility wrapper:

```bash
case_test/lib/architecture_check.rb "$(pwd)" --all
```

## Selected Execution

Selected execution is opt-in:

```bash
bash scripts/case_test.sh --execute --from-path src/transport/xqc_stream.c
bash scripts/case_test.sh --execute --parallel --jobs 4 --module transport
```

Only groups marked `execution: implemented` in `manifest.yml` are scheduled.
Groups whose bodies still live in the legacy suite fail clearly instead of
reporting a false pass.
