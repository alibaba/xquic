# Case Test Routing

This directory contains metadata and helpers for routing endpoint
client-to-server case tests. The legacy executable entry point remains
`scripts/case_test.sh`.

## Files

- `manifest.yml` maps source paths, modules, features, fixed port offsets,
  and legacy `case_print_result` owners to case-test groups.
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

Use `bash scripts/case_test.sh --inventory` to audit legacy ownership. Every
legacy case must have exactly one owner; overlapping feature relevance belongs
in documentation or future related-case metadata, not in executable ownership
patterns.

Use the architecture check when changing the runner, selector, or legacy
compatibility wrapper:

```bash
case_test/lib/architecture_check.rb "$(pwd)" --all
```

The architecture check verifies complete and unique legacy ownership, mock
parallel scheduling, stable shard ports and work directories, and static
legacy full-suite equivalence.

## Selected Execution

Selected execution is opt-in:

```bash
bash scripts/case_test.sh --execute --from-path src/transport/xqc_stream.c
bash scripts/case_test.sh --execute --group transport.datagram
bash scripts/case_test.sh --execute --parallel --jobs 4 --module transport
bash scripts/case_test.sh --execution-plan
```

Only groups marked `execution: implemented` in `manifest.yml` are scheduled.
Implemented module runners either contain hand-migrated case bodies or use the
legacy-owned runner to extract only the group's owned case blocks from the
legacy suite. Use `--execution-plan` to inspect implemented groups, missing
cases, and the current maximum safe job count.

Each scheduled shard receives a stable `CASE_TEST_SHARD_ID`, a manifest-owned
port derived from `port_offset`, and an isolated work directory. Generated
logs, tokens, transport-parameter files, and session tickets stay inside that
work directory. Shared certificates are read-only symlinks from the build
directory.

Parallel execution writes each shard's raw output to
`<build>/case_test_parallel/<shard>/case_test.log` and records failed case
result lines in `<build>/case_test_parallel/<shard>/case_test.failures`.
The parent runner reports each shard's exit status and parsed fail count, and
returns nonzero if a shard exits nonzero or prints any `[     FAIL ]` case
result. It also emits ordered legacy-compatible `pass:1` and `pass:0` result
lines parsed from the shard log so existing CI summary checks can count cases
without reading interleaved raw output. On failure, terminal output shows the
failed result lines and a bounded tail of the shard log; use the per-shard log
files, not interleaved terminal output, as the authoritative failure evidence.

Some legacy cases require sudo for client-side network setup. Run `sudo -v`
in the same shell before executing those shards. Generated shards that contain
sudo commands check this before running any case, so missing credentials are
reported as an environment failure rather than case-result failures.

For full-suite CI, the maximum safe case-test job count is the number of
implemented executable shards that together cover all default legacy cases.
`observability.qlog` is hand-migrated; the other implemented shards are
generated from legacy-owned case blocks until their bodies are migrated.
