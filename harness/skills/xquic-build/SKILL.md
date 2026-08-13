---
name: xquic-build
description: Prepare and run XQUIC local compilation. Use when asked to compile, build, configure, or diagnose the local build environment for XQUIC, especially across macOS/Linux. Detect intent and platform, then delegate actual compilation to scripts/validate.sh instead of hand-writing CMake commands.
---

# XQUIC Build

This skill closes build-only requests by identifying compile parameters and
delegating execution to `scripts/validate.sh build`. It does not own CMake
flags, dependency installation, test policy, or pull-request validation
evidence. Those stay in `scripts/validate.sh`, `README.md`, and
`harness/spec/validation.md`.

## Use When

Use this skill when the task is to:

- compile XQUIC locally;
- configure or refresh a build directory;
- run a build-only smoke check after documentation, script, or compile-scope
  changes;
- check whether the current platform can use the repository build script;
- diagnose a build environment before tests run;
- choose build parameters such as platform, feature profile, TLS backend,
  build directory, build type, or parallelism.

## Not Use When

Do not use this skill as the final gate when the task asks to:

- run unit tests, case tests, or full validation;
- verify a production behavior change;
- prepare pull-request local-regression evidence;
- debug GitHub Actions failures;
- install dependencies, clone TLS libraries, or change external services.

Use `harness/skills/validate/SKILL.md` for tests, validation gates, and PR
evidence. Use this skill first only when the validation task is blocked by an
unclear local build environment.

## Script Boundary

`./scripts/validate.sh build` is the minimum compile path. It writes build
artifacts and logs, prepares the default TLS backend when local source is
already present, configures CMake, compiles targets, prepares local runtime
files needed by test clients/servers, and restores the generated public config
header after the run. It does not run CTest, focused unit tests, or
`case_test.sh`.

## Platform Check

Before running a build command:

1. Identify the host with `uname -s`.
2. Treat the default profile as Linux/BoringSSL, matching the repository
   `scripts/xquic_test.sh` compile path where practical.
3. Treat `Darwin` and `Linux` as supported by `scripts/validate.sh build`;
   the script adds platform-specific CMake arguments.
4. For other platforms, read `README.md` and the platform docs before acting;
   do not invent a local CMake command.
5. Detect whether a feature profile was requested. Use
   `./scripts/validate.sh --list-features` when the feature key is unclear.
6. Check whether a TLS backend path is configured or already present through
   `XQC_SSL_PATH`, `third_party/boringssl`, or the path documented in
   `harness/spec/validation.md`.
7. Decide whether runtime files should be prepared. Leave
   `XQC_PREPARE_RUNTIME_FILES=on` for normal local builds; set it to `off`
   only when the user asks for object compilation without runnable test
   fixtures.
8. If required tools or TLS dependencies are missing, report the exact missing
   item and point to `README.md`; do not install or clone dependencies unless
   the user explicitly asks.

## Parameter Mapping

Prefer the default minimum compile command unless the user or environment
requires a parameter:

- Platform: auto-detected by `scripts/validate.sh` from `uname -s`; do not pass
  ad hoc platform CMake flags from the skill.
- Feature: `./scripts/validate.sh build --feature <feature>`.
- Build directory: `XQC_BUILD_DIR=<dir>`.
- Build type: `XQC_BUILD_TYPE=<Debug|Release|...>`.
- Parallelism: `XQC_BUILD_JOBS=<count>`.
- TLS backend: `XQC_SSL_TYPE=<name>` and `XQC_SSL_PATH=<path>`.
- Explicit TLS paths: `XQC_SSL_INCLUDE=<path>` and
  `XQC_SSL_LIBS='<libssl>;<libcrypto>'`.
- TLS backend build: `XQC_BUILD_SSL=auto|on|off`; `auto` builds BoringSSL only
  when the source tree already exists and the expected static libraries are
  missing.
- Runtime fixture files: `XQC_PREPARE_RUNTIME_FILES=on|off`.

## Compile

Inspect the selected compile plan before the first build when parameters are
not obvious:

```bash
./scripts/validate.sh build --dry-run
```

Then use the repository script as the single build entry point:

```bash
./scripts/validate.sh build
```

For a non-default build directory or TLS backend, pass environment variables
instead of editing scripts:

```bash
XQC_BUILD_DIR=build/debug \
XQC_SSL_PATH=/path/to/boringssl \
./scripts/validate.sh build
```

For feature-gated compilation, use manifest feature keys:

```bash
./scripts/validate.sh build --feature <feature>
```

Do not replace these commands with handwritten `cmake` invocations unless the
user explicitly asks to bypass the harness.

## Output

Report:

- host platform and whether the repository build script supports it;
- selected feature profile or `<none>`;
- build directory and TLS backend path used;
- whether TLS backend build and runtime file preparation were enabled;
- exact command run;
- first failing configure/build command if compilation fails;
- whether the result is build-only evidence or whether a separate validation
  gate is still required.
