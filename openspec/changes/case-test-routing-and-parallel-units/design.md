# Design

## Baseline

The change is based on `origin/main`. The current harness structure uses:

- `harness/spec/` for normative requirements;
- `harness/docs/` for informative structure and maintenance guidance;
- `harness/decisions/` for durable rationale;
- `harness/spec/harness-manifest.yml` as the machine-readable routing source.

The endpoint suite is implemented by `scripts/case_test.sh`, which runs from a
build directory and invokes `tests/test_client` and `tests/test_server`.
Unit tests are built into `tests/run_tests` and registered as one CTest target.

## Case-Test Routing Model

Add `case_test/manifest.yml` as the source of truth for endpoint case metadata.
The harness manifest remains the source of truth for source-path to module and
feature routing. It references the case-test manifest instead of duplicating
the complete case table.

Case metadata fields:

- `id`: stable agent-facing identifier, such as
  `transport.stream.pure-fin`;
- `legacy_name`: existing `case_print_result` name;
- `module`: owning module from `harness/spec/harness-manifest.yml`;
- `submodule`: optional module subroute from the harness manifest;
- `feature`: optional feature key from the owning module;
- `source_paths`: source globs that make this case relevant;
- `runner`: shell file that owns or will own the case implementation;
- `selector`: runner-local selector name;
- `case_ids`: optional numeric `-x` values used by the client/server pair;
- `resources`: optional shared resources such as ports, logs, or process
  names.

The first implementation phase may list cases that still live in
`scripts/case_test.sh`; their `runner` can point to the compatibility wrapper
until the case body moves.

## Directory Layout

```text
case_test/
  README.md
  manifest.yml
  lib/
    common.sh
    ports.sh
    runner.sh
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
```

With no selector, it preserves the legacy full-suite behavior. Selector output
must be deterministic and should include the case ID, legacy name, module,
feature, and runner path.

## Harness Integration

Update `harness/spec/harness-manifest.yml` with a test-routing reference, for
example:

```yaml
test_routing:
  case_manifest: case_test/manifest.yml
  unit_manifest: tests/unittest/manifest.yml
```

The harness check validates cross-file consistency:

- manifest paths exist;
- case IDs and legacy names are unique;
- case modules and features exist in `harness/spec/harness-manifest.yml`;
- runners exist;
- numeric case IDs are complete numeric tokens in selector sources when
  declared;
- documentation links to the selected entry points resolve.

Informative updates belong in `harness/docs/structure-map.md` and
`harness/docs/change-guide.md`. Rationale belongs in
`harness/decisions/records.md`. Ongoing requirements belong in
`harness/spec/validation.md` or another owning spec.

## Unit-Test Parallelism

Current CTest registration has one target:

```cmake
add_test(NAME run_tests COMMAND run_tests)
```

Parallel execution needs suite-level isolation before enabling `ctest -j`.
The proposed path is:

1. Add `tests/unittest/manifest.yml` to map unit suites to source files,
   harness modules, optional features, and port ranges.
2. Extend `tests/unittest/main.c` so `tests/run_tests` can select a suite as
   well as an individual test.
3. Register CTest targets by suite or test file in `tests/CMakeLists.txt`.
4. Keep `scripts/validate.sh test` sequential by default.
5. Add `XQC_TEST_JOBS=<n>` as an opt-in parallel mode after port isolation is
   complete.

Port ranges are deterministic, for example:

```yaml
suites:
  xqc_conn_test:
    module: transport
    source: tests/unittest/xqc_conn_test.c
    port_base: 18000
    port_count: 100
  xqc_packet_test:
    module: transport
    source: tests/unittest/xqc_packet_test.c
    port_base: 18100
    port_count: 100
```

Tests that open sockets should derive ports from `XQC_TEST_PORT_BASE` or a
small helper. Pure in-memory tests do not need a port range.

## Migration Plan

Start with metadata and selectors, not movement:

1. Create case and unit metadata.
2. Add checks that prove the metadata is internally consistent.
3. Add list and dry-run selectors.
4. Move low-risk case groups one module at a time.
5. Add suite-level unit-test selectors.
6. Add deterministic port ranges and opt-in parallel validation.

## Validation

Initial metadata and selector work:

```bash
bash harness/scripts/xqc_harness_check.sh
bash -n scripts/case_test.sh
./scripts/case_test.sh --list
./scripts/case_test.sh --from-path src/transport/xqc_stream.c --dry-run
./scripts/validate.sh test
```

Parallel unit-test work:

```bash
./scripts/validate.sh test
XQC_TEST_JOBS=4 ./scripts/validate.sh test
```

The full endpoint suite remains explicit:

```bash
XQC_BUILD_DIR=build ./scripts/validate.sh full
```
