#!/bin/bash
#
# Run each fuzz target of a build made with -DXQC_ENABLE_FUZZ=ON for a short
# time from its seed corpus in tests/fuzz/corpus, and fail if one of them
# finds a crash, a leak, a timeout or a sanitizer report.
#
# usage: scripts/fuzz_smoke.sh [build-dir] [seconds-per-target]
#
# The inputs that make a target fail are kept in XQC_FUZZ_ARTIFACT_DIR
# (default: <build-dir>/fuzz-artifacts), with the target's output.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${1:-${ROOT_DIR}/build}"
SECONDS_PER_TARGET="${2:-60}"
ARTIFACT_DIR="${XQC_FUZZ_ARTIFACT_DIR:-${BUILD_DIR}/fuzz-artifacts}"

if [[ ! "${SECONDS_PER_TARGET}" =~ ^[1-9][0-9]*$ ]]; then
    echo "usage: $0 [build-dir] [seconds-per-target]" >&2
    exit 2
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/xqc-fuzz-smoke.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT
mkdir -p "${ARTIFACT_DIR}"

targets=0
failures=0

for target in "${BUILD_DIR}"/tests/fuzz/fuzz_*; do
    if [[ ! -f "${target}" || ! -x "${target}" ]]; then
        continue
    fi

    name="$(basename "${target}")"
    seeds="${ROOT_DIR}/tests/fuzz/corpus/${name}"
    corpus="${WORK_DIR}/${name}"
    log="${WORK_DIR}/${name}.log"
    mkdir -p "${corpus}"
    targets=$((targets + 1))

    if [[ ! -d "${seeds}" ]]; then
        echo "FAIL: ${name} has no seed corpus in tests/fuzz/corpus" >&2
        failures=$((failures + 1))
        continue
    fi

    # new coverage goes to the first directory, the seeds stay as they are;
    # the test certificate of the target goes to the work directory as well
    if TMPDIR="${WORK_DIR}" "${target}" "${corpus}" "${seeds}" \
        -max_total_time="${SECONDS_PER_TARGET}" \
        -timeout=25 \
        -rss_limit_mb=2048 \
        -print_final_stats=1 \
        -artifact_prefix="${ARTIFACT_DIR}/${name}-" \
        > "${log}" 2>&1
    then
        runs="$(awk '/^stat::number_of_executed_units/ {print $NF}' \
            "${log}")"
        echo "PASS: ${name} (${runs:-?} runs, $(find "${corpus}" -type f \
            | wc -l) new inputs)"

    else
        echo "FAIL: ${name}" >&2
        tail -n 80 "${log}" >&2
        cp "${log}" "${ARTIFACT_DIR}/${name}.log"
        failures=$((failures + 1))
    fi
done

if [[ "${targets}" -eq 0 ]]; then
    echo "no fuzz target in ${BUILD_DIR}/tests/fuzz" >&2
    exit 1
fi

if [[ "${failures}" -ne 0 ]]; then
    echo "fuzz smoke: ${failures} of ${targets} target(s) failed" >&2
    exit 1
fi

echo "fuzz smoke: ${targets} target(s) passed"
