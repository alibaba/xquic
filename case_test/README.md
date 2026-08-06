# Case Test Routing

This directory contains metadata and helpers for routing endpoint
client-to-server case tests. The legacy executable entry point remains
`scripts/case_test.sh`.

## Files

- `manifest.yml` maps source paths, modules, features, and legacy
  `case_print_result` names to case-test groups.
- `lib/selector.rb` powers list and dry-run selectors for
  `scripts/case_test.sh`.
- Module directories hold future case runners. Existing case bodies may remain
  in `scripts/case_test.sh` until they are moved incrementally.

## Compatibility

Running `scripts/case_test.sh` without selector arguments preserves the legacy
full-suite behavior. Selector mode is used for discovery and dry-run evidence
while case bodies are migrated.

Use `bash scripts/case_test.sh --inventory` to audit how many legacy case
names are matched, unmatched, or matched by multiple groups.
