# Validation

XQUIC validation is layered so local development can get fast feedback while
pull requests can provide broader evidence.

See the [project instructions](PROJECT_INSTRUCTIONS.md) for related
architecture and pull-request contracts. Agents executing these commands
should also follow the [`validate` skill](../skills/validate/SKILL.md).

## Entry Point

Use the repository-wide script from the repository root:

```bash
./scripts/validate.sh build
./scripts/validate.sh test
XQC_BUILD_DIR=build ./scripts/validate.sh full
```

The commands are intentionally independent of issue and pull request numbers.
Build and unit-test validation default to `build/validation/`. The full
command uses the root `build/` directory expected by the existing
`scripts/case_test.sh`.

## Required Coverage Contract

Every production behavior change must include tests tied to the changed path.
The required minimum is:

- one happy-path unit test;
- one abnormal, rejection, boundary, or error-branch unit test;
- one client-to-server happy-path case in `scripts/case_test.sh`; and
- one client-to-server abnormal-path case in `scripts/case_test.sh`.

The paired case tests must use distinct `case_print_result` names and exercise
the real `tests/test_client` to `tests/test_server` path. Their assertions must
prove the expected endpoint-visible result. For an error path, prove the
specific rejection, connection error, close, or recovery behavior rather than
accepting any failure.

Documentation-only changes are exempt from runtime test creation and instead
use link, format, and command-syntax checks. Validation-tooling changes require
the closest deterministic self-checks. The pull request must state why paired
runtime coverage does not apply.

## Client-to-Server Case ID Namespace

The `-x <id>` value shared by `tests/test_client` and `tests/test_server`
selects case-specific behavior. A case ID is a permanent behavior identifier,
not a reusable execution slot.

The following registry records IDs present in the current tree or previously
used in repository history. Range boundaries are inclusive. ID `0` means the
normal/default path and must not be allocated. Because the older ranges contain
cross-layer assignments, the complete `[1, 704]` range is frozen for new IDs,
including gaps.

The registry is the permanent ledger for merged and historical allocations.
It cannot show every unmerged branch, so each open pull request also holds a
temporary reservation for every literal case ID present at its published head
in `scripts/case_test.sh`, `tests/test_client.c`, or `tests/test_server.c`.

| Range | Existing namespace | Permanently reserved IDs |
|-------|--------------------|--------------------------|
| `[1, 99]` | Legacy cross-layer QUIC, TLS, HTTP/3, and callback cases | `1-53`, `55-57`, `80`, `99` |
| `[100, 149]` | Multipath QUIC and path management | `100-110` |
| `[150, 199]` | HTTP/3 and QPACK settings | `150-153` |
| `[200, 299]` | QUIC DATAGRAM and HTTP/3 datagram | `200-211` |
| `[300, 399]` | HTTP/3 extension bytestream | `300-315` |
| `[400, 499]` | Transport connection settings and extensions | `400`, `450-455` |
| `[500, 599]` | Frozen legacy cross-layer overflow | `500-502` |
| `[600, 699]` | Frozen test-runtime and transport mechanics | `600-601` |
| `[700, 704]` | Frozen protocol-regression overflow | `700-704` |

New cases must allocate from the following layer or module namespace. Update
the allocated-ID column in the same pull request. An ID remains listed after
its case is retired so later changes cannot reuse it.

| Range | New-case namespace | Allocated IDs |
|-------|--------------------|---------------|
| `[705, 799]` | QUIC Transport core | None |
| `[800, 899]` | Recovery and congestion control | None |
| `[900, 999]` | QUIC-TLS | None |
| `[1000, 1099]` | HTTP/3 framing, streams, and settings | `1000-1012` |
| `[1100, 1149]` | QPACK | None |
| `[1150, 1199]` | HTTP priority | None |
| `[1200, 1299]` | QUIC DATAGRAM | None |
| `[1300, 1399]` | Multipath QUIC | None |
| `[1400, 1499]` | MoQT | None |
| `[1500, 1599]` | LOC and MSF application protocols | None |
| `[1600, 1699]` | FEC and experimental transport extensions | None |
| `[1700, 1799]` | Common runtime, public API, and test harness | None |

Apply these allocation rules before running a new case:

1. Give every new `case_print_result` behavior its own unused ID. The paired
   happy-path and abnormal-path cases must have different IDs.
2. Do not assign an active or retired ID to a new behavior. An existing case
   may keep its ID only when its original behavior contract remains intact.
3. Select the range for the lowest protocol layer or module that owns the
   behavior. Cross-layer cases use the lowest layer that injects the condition.
4. Refresh the intended base, then search the current tree and Git history
   before allocating an ID:

   ```bash
   git fetch origin main
   case_id=1000  # replace with the candidate ID
   rg -n -- "(^|[^0-9])${case_id}([^0-9]|$)" \
       scripts/case_test.sh tests/test_client.c tests/test_server.c
   git log --all -G \
       "(^|[^0-9])${case_id}([^0-9]|$)" -- \
       scripts/case_test.sh tests/test_client.c tests/test_server.c
   ```

   Both commands must return no prior allocation.
5. Query every open pull request targeting `main` and inspect the exact head
   commit SHA returned by the query:

   ```bash
   gh api --paginate \
       "repos/alibaba/xquic/pulls?state=open&base=main&per_page=100" \
       --jq '.[] | {number, created_at, head_sha: .head.sha, url: .html_url}'
   ```

   For each result other than the current pull request, fetch
   `refs/pull/<number>/head`, verify that its fetched commit equals the reported
   `headRefOid`, and search the three selector files for the candidate as a
   complete numeric token. For example:

   ```bash
   pr=123
   head_sha=<head_sha-from-query>
   pr_ref="refs/xquic-harness/pr-${pr}-${head_sha}"
   cleanup_case_ref() { git update-ref -d "${pr_ref}"; }
   trap cleanup_case_ref EXIT HUP INT TERM
   git fetch --quiet origin "refs/pull/${pr}/head:${pr_ref}"
   test "$(git rev-parse "${pr_ref}")" = "${head_sha}"
   git grep -n -E "(^|[^0-9])${case_id}([^0-9]|$)" "${pr_ref}" -- \
       scripts/case_test.sh tests/test_client.c tests/test_server.c
   cleanup_case_ref
   trap - EXIT HUP INT TERM
   ```

   A match means that pull request already reserves the candidate. A failed
   query, fetch, or head-SHA check is inconclusive and fails the allocation
   gate; it must not be treated as an empty result. Record the query time, each
   candidate ID, the number of open pull-request heads checked, the current
   pull request excluded (if any), and any conflicting PR number and head SHA.
6. Add the allocated ID to this registry, implement the matching client and
   server selector behavior, and retain the ID, namespace, case name, command,
   and result in ignored local validation evidence.
7. After the local tests pass and immediately before creating or updating the
   pull request, repeat the open-PR scan. The final validation evidence must use
   this second snapshot; an earlier acceptance-stage scan is not sufficient.
8. Publish a pull request that introduces new case IDs, or an updated head that
   changes them, in draft. Immediately scan again with the current pull request
   included. This closes the race in which two contributors both passed their
   pre-publication scans. If no duplicate exists, retain the result locally and
   the PR may move to review. If duplicate IDs exist, the lowest pull-request
   number keeps each reservation. Every later pull request using that ID must
   remain or return to draft, mark local regression incomplete, allocate a new
   ID, update all selectors and this registry, rerun the complete validation
   gate, and refresh its evidence. A reservation is released when its pull
   request closes without merge or publishes a head that no longer contains
   the ID.

## Levels

### Build

`./scripts/validate.sh build`

- configures a Debug build;
- uses BoringSSL by default;
- enables the core test and example targets;
- enables the congestion-control and QPACK compatibility symbols required by
  the existing test and example targets;
- disables optional MoQ support; and
- compiles the configured targets.

This is the minimum check for documentation that changes build commands and
for implementation work that cannot yet run tests. It is not sufficient
pre-PR evidence for a production behavior change.

### Test

`./scripts/validate.sh test`

Runs the Build level and then the verbose CTest unit suite. The validator
extracts and records CUnit's `Total`, `Ran`, `Passed`, and `Failed` counts.
With `XQC_TEST_NAME` unset, the complete-suite gate requires `Ran == Total`
and `Failed == 0`. A top-level `CTest 1/1` result alone does not satisfy this
gate.

### Full

`XQC_BUILD_DIR=build ./scripts/validate.sh full`

Runs the Test level and the existing `scripts/case_test.sh` integration suite.
This is the conservative pre-PR command: it runs the complete unit suite and
all case tests, including the pair relevant to the current change.

Protocol-specific interoperability, sanitizers, coverage, alternate TLS
backends, optional modules, and platform matrices remain additional checks.
They should be selected by change risk or CI policy rather than hidden inside
an issue-specific build.

## Mandatory Local Pre-PR Gate

Before creating or moving a production code pull request to review:

1. Confirm the paired unit tests and paired client-to-server case tests exist.
   For new cases, confirm their distinct IDs are registered in the correct
   namespace, have never appeared in the current tree or Git history, and are
   not reserved by another open pull request.
2. Run the complete local unit suite with no focused-test selector:

   ```bash
   unset XQC_TEST_NAME
   ./scripts/validate.sh test
   ```

3. Confirm the emitted CUnit summary reports `Ran == Total` and `Failed == 0`.
   Record the real result as `<Ran>/<Total> CUnit tests`; do not use
   `CTest 1/1` as the unit-suite evidence or substitute a fixed example count.
4. Run both relevant case-test blocks, including their server/client setup,
   state cleanup, and assertions.
5. If the case blocks cannot be invoked independently, run the full suite:

   ```bash
   unset XQC_TEST_NAME
   XQC_BUILD_DIR=build ./scripts/validate.sh full
   ```

6. Require all unit tests and both relevant cases to pass before submitting
   the pull request. Confirm both expected `[       OK ]` case names are
   present and no relevant `[     FAIL ]` or `>>>>>>>> pass:0` result exists;
   the legacy case script's process exit code alone is not sufficient.
7. Repeat the open-PR reservation scan for every new case ID. Fail closed when
   the query or any head inspection is incomplete, and do not submit or update
   a pull request while another open pull request reserves an ID.

Retain the detailed gate evidence locally: exact commands, CUnit counts, unit
and case names, case IDs and namespaces, results, and reservation snapshots.
The pull request summarizes only:

- each client-to-server case as `<ID> — <concise behavior>`;
- `Local regression: Complete` after the full local gate passes, or concise
  failed case IDs and meanings when it does not;
- `CI: Complete` after required checks pass, or only incomplete check names;
  and
- the aggregate `CONTRIBUTING.md` result.

Do not copy commands, test function names, case names, logs, namespace ranges,
tested commit SHA, or successful reservation snapshots into the PR body.

A focused unit test is iteration evidence only. A missing test, failed test,
or environment blocker does not satisfy the gate; keep the pull request in
draft until the gate passes. Repeat the gate after every subsequent code
change so the recorded evidence matches the pull request's current head.
After publishing, a collision is reported only as an incomplete local gate and
concise blocker. A later pull request with a duplicate case ID does not pass
the gate even when all runtime tests passed with that ID.

## Optional Pre-Push Gate

Register the repository harness and install its optional pre-push hook with:

```bash
./scripts/setup_harness.sh --install-pre-push-hook
```

The hook clears `XQC_TEST_NAME`, runs
`XQC_BUILD_DIR=build ./scripts/validate.sh full`, and rejects the push if the
command fails or the legacy case output contains a failure result. Existing
hooks are never overwritten. Use `git push --no-verify` only for an explicit
exception; bypassing the hook does not relax the pull-request gate.

Regardless of hook use, a production code pull request must show the concise
current-head local-regression status and paired client-to-server case summary
required above.

## Configuration

The default profile supports macOS and Linux with a prebuilt BoringSSL
checkout. Override paths without editing the script:

```bash
XQC_BUILD_DIR=build/debug \
XQC_SSL_PATH=/path/to/boringssl \
./scripts/validate.sh test
```

During test development, run one registered CUnit test by name:

```bash
XQC_TEST_NAME=xqc_test_h3_stream ./scripts/validate.sh test
```

A focused test is fast feedback, not a replacement for the full Test gate.

Supported environment variables:

- `XQC_BUILD_DIR`: CMake build directory.
- `XQC_BUILD_TYPE`: CMake build type, default `Debug`.
- `XQC_BUILD_JOBS`: maximum parallel build jobs.
- `XQC_SSL_TYPE`: TLS backend name, default `boringssl`.
- `XQC_SSL_PATH`: TLS backend root.
- `XQC_SSL_INCLUDE`: explicit TLS include directory.
- `XQC_SSL_LIBS`: semicolon-separated TLS library paths.
- `XQC_TEST_NAME`: optional registered CUnit test name for focused feedback.
- `XQC_VALIDATION_ARTIFACT_DIR`: validation evidence directory.

The script does not install packages, clone dependencies, or modify external
services. Dependency provisioning remains an explicit environment setup step.

## Artifacts

Each invocation writes ignored artifacts below
`build/validation/artifacts/` by default. The conservative full command writes
them below `build/artifacts/` because it selects `XQC_BUILD_DIR=build`.

- `environment.txt`: commit, branch, platform, compiler, CMake version, and
  selected profile;
- `<level>.log`: complete command output for the selected validation level,
  including the normalized CUnit summary and gate result.

Pull requests summarize the aggregate gate and case meanings without repeating
commands. Raw logs retain the detailed evidence for diagnosis and audit.

The current CMake configuration generates `include/xquic/xqc_configure.h` in
the source tree. The validation script preserves and restores its pre-build
contents so validation does not leave a source diff.
