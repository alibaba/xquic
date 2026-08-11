# Case Test Routing

This directory contains metadata and helpers for routing endpoint
client-to-server case tests. The legacy executable entry point remains
`scripts/case_test.sh`.

## Files

- `manifest.yml` maps source paths, modules, features, fixed port offsets, and
  runner paths to case-test groups.
- `lib/selector.rb` powers list, inventory, dry-run, and runner-map output for
  `scripts/case_test.sh`.
- `lib/runner.sh` preserves full-suite compatibility and provides selected
  execution scheduling.
- `legacy/full_suite.sh` contains the current full endpoint suite.
- Module directories hold executable case runners. A runner may contain
  hand-migrated case bodies or delegate to the legacy-owned runner while the
  body remains in `legacy/full_suite.sh`.

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

## Extending Case Tests

Use `case_test/manifest.yml` as the group routing source of truth. Add new
endpoint cases to the owning group script; do not add new cases to
`legacy/full_suite.sh`. A group script declares its group once, then registers
cases with the common helper.

### Native Case Pattern

The FEC group contains the first native registration example:

```bash
case_test_group "transport.fec"

fec_negotiate_encoder_fec_scheme()
{
    # Start server, run client, inspect clog/slog/stdlog, and return 0 or 1.
}

case_test_case "negotiate_encoder_fec_scheme" \
    --id legacy \
    --run fec_negotiate_encoder_fec_scheme
```

The runner injects group-shared environment before executing the script:

- `CASE_TEST_GROUP`
- `CASE_TEST_MODULE`
- `CASE_TEST_FEATURE`
- `CASE_TEST_PORT`
- `CASE_TEST_SHARD_ID`
- `CASE_TEST_WORK_DIR`

Discovery mode uses the same file without running network tests:

```bash
CASE_TEST_DISCOVER=1 CASE_TEST_GROUP=transport.fec \
    CASE_TEST_MODULE=transport CASE_TEST_FEATURE=fec \
    bash case_test/transport/fec.sh
```

### Add A New FEC Endpoint Case

For a new FEC behavior, add the endpoint case to
`case_test/transport/fec.sh`. For example, a FEC repair-timeout regression
might use:

- case ID: the next available ID in the `[1600, 1699]` FEC namespace from
  `harness/spec/validation.md`;
- case name: `fec_repair_timeout_closes_gap`;
- client/server selector: matching `-x <id>` handling in
  `tests/test_client.c` and `tests/test_server.c`;
- native case body: a shell function in `case_test/transport/fec.sh` that
  starts the needed server mode, runs the client with the allocated ID, checks
  the observable FEC result in `clog`, `slog`, or `stdlog`, and returns success
  or failure;
- registration: one `case_test_case "fec_repair_timeout_closes_gap" --id
  <id> --run <function>` line in the same group script.

Before reserving the ID, search the current tree, history, and open pull
requests as described in `harness/spec/validation.md`. After implementing the
case, use these checks as the minimum routing evidence:

```bash
bash scripts/case_test.sh --inventory
bash scripts/case_test.sh --execution-plan
bash scripts/case_test.sh --group transport.fec --list
bash scripts/case_test.sh --execute --group transport.fec
case_test/lib/architecture_check.rb "$(pwd)" --all
```

Expected routing observations:

- `--inventory` has no missing or repeated case owners;
- `--execution-plan` has `complete=true` and `missing_unique_cases=0`;
- `--group transport.fec --list` includes the new FEC case name as a native
  case and lists it exactly once in the group case set;
- selected execution reports `pass:1` for the new case and no shard failure.
