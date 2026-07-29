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

Runs the Build level and then the CTest unit suite with failure output. This is
the mandatory complete-unit-suite gate for every production code pull request.
`XQC_TEST_NAME` must be unset for this gate.

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
2. Run the complete local unit suite with no focused-test selector:

   ```bash
   unset XQC_TEST_NAME
   ./scripts/validate.sh test
   ```

3. Run both relevant case-test blocks, including their server/client setup,
   state cleanup, and assertions.
4. If the case blocks cannot be invoked independently, run the full suite:

   ```bash
   unset XQC_TEST_NAME
   XQC_BUILD_DIR=build ./scripts/validate.sh full
   ```

5. Require all unit tests and both relevant cases to pass before submitting
   the pull request. Confirm both expected `[       OK ]` case names are
   present and no relevant `[     FAIL ]` or `>>>>>>>> pass:0` result exists;
   the legacy case script's process exit code alone is not sufficient.

The pull request evidence must name:

- the happy-path unit test;
- the abnormal-path unit test;
- the happy-path `case_print_result` case;
- the abnormal-path `case_print_result` case;
- the command that ran the complete unit suite; and
- the commands and results for the relevant case-test pair.

A focused unit test is iteration evidence only. A missing test, failed test,
or environment blocker does not satisfy the gate; keep the pull request in
draft until the gate passes. Repeat the gate after every subsequent code
change so the recorded evidence matches the pull request's current head.

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

Regardless of hook use, a production code pull request must record the
current-head complete unit-suite result and the relevant happy-path and
abnormal-path unit and client-to-server case evidence required above.

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

A focused test is fast feedback, not a replacement for the full Test level in
pull request evidence.

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
- `<level>.log`: complete command output for the selected validation level.

Pull requests should summarize the result and name the commands run. Raw logs
are evidence for diagnosis and audit; they are not a substitute for a concise
pull request summary.

The current CMake configuration generates `include/xquic/xqc_configure.h` in
the source tree. The validation script preserves and restores its pre-build
contents so validation does not leave a source diff.
