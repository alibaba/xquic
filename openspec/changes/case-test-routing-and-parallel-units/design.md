# Design

## Baseline

The change is based on `origin/main`. The current harness structure uses:

- `harness/spec/` for normative requirements;
- `harness/docs/` for informative structure and maintenance guidance;
- `harness/decisions/` for durable rationale;
- `harness/spec/harness-manifest.yml` as the machine-readable routing source.

The endpoint suite is implemented by `scripts/case_test.sh`, which runs from a
build directory and invokes `tests/test_client` and `tests/test_server`.
This change does not alter `tests/run_tests` or unit-test execution.

## Case-Test Routing Model

Add `case_test/manifest.yml` as the source of truth for endpoint case metadata.
The harness manifest remains the source of truth for source-path to module and
feature routing. It references the case-test manifest instead of duplicating
the complete case table.

Case metadata fields:

- `id`: stable agent-facing identifier, such as
  `transport.stream.pure-fin`;
- `legacy_name_patterns`: regular expressions that match existing
  `case_print_result` names;
- `module`: owning module from `harness/spec/harness-manifest.yml`;
- `submodule`: optional module subroute from the harness manifest;
- `feature`: optional feature key from the owning module;
- `source_paths`: source globs that make this case relevant;
- `runner`: shell file that owns or will own the case implementation;
- `execution`: `pending` until the case body is migrated, then `implemented`.

The first implementation phase may list cases that still live in
`case_test/legacy/full_suite.sh`. Their module runners fail clearly until the
case body moves.

## Directory Layout

```text
case_test/
  README.md
  manifest.yml
  lib/
    common.sh
    pending_runner.sh
    runner.sh
  legacy/
    full_suite.sh
  transport/
    core.sh
    stream.sh
    packet.sh
    datagram.sh
    multipath.sh
    fec.sh
  http3/
    core.sh
    qpack.sh
    h3-ext.sh
  tls/
    handshake.sh
  congestion/
    core.sh
  observability/
    qlog.sh
```

This layout follows the code and harness module structure. It is not a new
normative module map; module ownership still comes from the harness manifest.

## Selector Behavior

`scripts/case_test.sh` remains the public entry point and supports:

```bash
./scripts/case_test.sh --list
./scripts/case_test.sh --dry-run
./scripts/case_test.sh --case <case-id-or-legacy-name>
./scripts/case_test.sh --module <module>
./scripts/case_test.sh --feature <feature>
./scripts/case_test.sh --from-path <repository-path>
./scripts/case_test.sh --execute --parallel --jobs <n> --module <module>
```

With no selector, it preserves the legacy full-suite behavior. Selector output
must be deterministic and should include the case ID, legacy name, module,
feature, and runner path.

Selected execution uses the same metadata but schedules only groups marked
`execution: implemented`. Each scheduled group receives a deterministic port
based on `CASE_TEST_PORT_BASE` or `--port-base`, and an isolated work directory
under the build tree. Pending groups produce a clear failure instead of a false
pass.

## Harness Integration

Update `harness/spec/harness-manifest.yml` with a test-routing reference, for
example:

```yaml
test_routing:
  case_manifest: case_test/manifest.yml
  case_legacy_full_suite: case_test/legacy/full_suite.sh
```

The harness check validates cross-file consistency:

- manifest paths exist;
- case group IDs are unique;
- case modules and features exist in `harness/spec/harness-manifest.yml`;
- runners exist;
- legacy name patterns match the legacy full-suite case names;
- documentation links to the selected entry points resolve.

Informative updates belong in `harness/docs/structure-map.md` and
`harness/docs/change-guide.md`. Rationale belongs in
`harness/decisions/records.md`. Ongoing requirements belong in
`harness/spec/validation.md` or another owning spec.

## Migration Plan

Start with metadata and selectors, not movement:

1. Create case metadata.
2. Add checks that prove the metadata is internally consistent.
3. Add list and dry-run selectors.
4. Move the full-suite body behind a thin compatibility entry point.
5. Add selected execution and parallel scheduling for migrated groups.
6. Move low-risk case groups one module at a time.

## Validation

Initial metadata and selector work:

```bash
bash harness/scripts/xqc_harness_check.sh
bash -n scripts/case_test.sh
./scripts/case_test.sh --list
./scripts/case_test.sh --from-path src/transport/xqc_stream.c --dry-run
./scripts/case_test.sh --execute --parallel --jobs 2 --from-path src/transport/xqc_stream.c
./scripts/validate.sh test
```

The full endpoint suite remains explicit:

```bash
XQC_BUILD_DIR=build ./scripts/validate.sh full
```
