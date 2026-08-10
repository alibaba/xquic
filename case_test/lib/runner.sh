#!/bin/bash
#
# Structured endpoint case-test runner.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

LEGACY_SUITE="${CASE_TEST_LEGACY_SUITE:-${ROOT_DIR}/case_test/legacy/full_suite.sh}"
SELECTOR_ARGS=()
SELECTOR_COUNT=0
EXECUTE=0
PARALLEL=0
REQUIRE_COMPLETE=0
JOBS=1
PORT_BASE="${CASE_TEST_PORT_BASE:-18000}"

usage()
{
    cat <<'USAGE'
usage: scripts/case_test.sh [selector options] [execution options]

selector options:
  --list
  --inventory
  --dry-run
  --group <id>
  --case <id-or-name>
  --module <name>
  --feature <name>
  --from-path <path>

execution options:
  --execute
  --parallel
  --require-complete
  --jobs <count>
  --port-base <port>
USAGE
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --execute)
            EXECUTE=1
            shift
            ;;
        --parallel)
            PARALLEL=1
            shift
            ;;
        --require-complete)
            REQUIRE_COMPLETE=1
            shift
            ;;
        --jobs)
            JOBS="${2:?--jobs requires a value}"
            shift 2
            ;;
        --port-base)
            PORT_BASE="${2:?--port-base requires a value}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            SELECTOR_ARGS+=("$1")
            SELECTOR_COUNT=$((SELECTOR_COUNT + 1))
            shift
            ;;
    esac
done

if [[ "${EXECUTE}" -eq 0 && "${SELECTOR_COUNT}" -eq 0 ]]; then
    exec "${LEGACY_SUITE}"
fi

if [[ "${EXECUTE}" -eq 1 ]]; then
    if [[ "${SELECTOR_COUNT}" -gt 0 ]]; then
        for selector_arg in "${SELECTOR_ARGS[@]}"; do
            case "${selector_arg}" in
                --list|--inventory|--dry-run|--runners|--execution-plan)
                    echo "case_test: ${selector_arg} cannot be combined with --execute" >&2
                    exit 2
                    ;;
            esac
        done
    fi
fi

if [[ "${EXECUTE}" -eq 0 ]]; then
    exec ruby "${ROOT_DIR}/case_test/lib/selector.rb" "${ROOT_DIR}" \
        "${SELECTOR_ARGS[@]}"
fi

if ! [[ "${JOBS}" =~ ^[1-9][0-9]*$ ]]; then
    echo "case_test: --jobs must be a positive integer" >&2
    exit 2
fi

if ! [[ "${PORT_BASE}" =~ ^[1-9][0-9]*$ ]]; then
    echo "case_test: --port-base must be a positive integer" >&2
    exit 2
fi

BUILD_DIR="$(case_test_build_dir "${ROOT_DIR}")"
MAP_FILE="$(mktemp "${TMPDIR:-/tmp}/xquic_case_runners.XXXXXX")"
PLAN_FILE="$(mktemp "${TMPDIR:-/tmp}/xquic_case_plan.XXXXXX")"
OWNERSHIP_FILE="$(mktemp "${TMPDIR:-/tmp}/xquic_case_ownership.XXXXXX")"
trap 'rm -f "${MAP_FILE}" "${PLAN_FILE}" "${OWNERSHIP_FILE}"' EXIT

if ! ruby "${ROOT_DIR}/case_test/lib/selector.rb" "${ROOT_DIR}" \
    --inventory > "${OWNERSHIP_FILE}"
then
    cat "${OWNERSHIP_FILE}" >&2
    echo "case_test: legacy case ownership must be complete and unique before execution" >&2
    exit 1
fi

selector_plan()
{
    if [[ "${SELECTOR_COUNT}" -eq 0 ]]; then
        ruby "${ROOT_DIR}/case_test/lib/selector.rb" "${ROOT_DIR}" \
            --execution-plan > "${PLAN_FILE}"

    else
        ruby "${ROOT_DIR}/case_test/lib/selector.rb" "${ROOT_DIR}" \
            --execution-plan "${SELECTOR_ARGS[@]}" > "${PLAN_FILE}"
    fi
}

if selector_plan; then
    PLAN_COMPLETE=1

else
    PLAN_COMPLETE=0
fi

if [[ "${SELECTOR_COUNT}" -eq 0 ]]; then
    ruby "${ROOT_DIR}/case_test/lib/selector.rb" "${ROOT_DIR}" \
        --runners > "${MAP_FILE}"

else
    ruby "${ROOT_DIR}/case_test/lib/selector.rb" "${ROOT_DIR}" \
        --runners "${SELECTOR_ARGS[@]}" > "${MAP_FILE}"
fi

if [[ "${REQUIRE_COMPLETE}" -eq 1 ]]; then
    if [[ "${PLAN_COMPLETE}" -eq 0 ]]; then
        cat "${PLAN_FILE}" >&2
        echo "case_test: selected executable shards do not cover all selected legacy cases" >&2
        exit 1
    fi
fi

if [[ "${SELECTOR_COUNT}" -eq 0 && "${JOBS}" -eq 1 && "${PLAN_COMPLETE}" -eq 0 ]]; then
    echo "[case-test] executable shards are incomplete; running legacy full suite as one shard"
    exec "${LEGACY_SUITE}"
fi

if [[ "${SELECTOR_COUNT}" -eq 0 && "${PLAN_COMPLETE}" -eq 0 ]]; then
    cat "${PLAN_FILE}" >&2
    echo "case_test: full-suite executable shards are incomplete; use --jobs 1 for legacy fallback" >&2
    exit 1
fi

if [[ ! -s "${MAP_FILE}" ]]; then
    if [[ "${SELECTOR_COUNT}" -eq 0 && "${JOBS}" -eq 1 ]]; then
        echo "[case-test] no migrated groups; running legacy full suite as one shard"
        exec "${LEGACY_SUITE}"
    fi

    echo "case_test: selected case-test groups are not executable yet" >&2
    echo "case_test: run with --dry-run to inspect matching legacy cases" >&2
    exit 1
fi

run_group()
{
    local group_id="$1"
    local runner="$2"
    local port_offset="$3"
    local shard_id
    local port
    local work_dir
    local log_file
    local failures_file
    local runner_status
    local run_count
    local ok_count
    local fail_count
    local failure_context_lines

    shard_id="$(case_test_sanitize_id "${group_id}")"
    port=$((PORT_BASE + port_offset))
    work_dir="${BUILD_DIR}/case_test_parallel/${shard_id}"
    log_file="${work_dir}/case_test.log"
    failures_file="${work_dir}/case_test.failures"
    failure_context_lines="${CASE_TEST_FAILURE_CONTEXT_LINES:-120}"

    case_test_prepare_work_dir "${BUILD_DIR}" "${work_dir}"
    : > "${log_file}"
    : > "${failures_file}"

    echo "[case-test] ${group_id} port=${port} runner=${runner}"
    if (
        export XQC_BUILD_DIR="${BUILD_DIR}"
        export CASE_TEST_WORK_DIR="${work_dir}"
        export CASE_TEST_PORT="${port}"
        export CASE_TEST_SHARD_ID="${shard_id}"
        exec "${ROOT_DIR}/${runner}"
    ) > "${log_file}" 2>&1
    then
        runner_status=0
    else
        runner_status="$?"
    fi

    grep -E '^\[     FAIL \] xquic_case_test\.' "${log_file}" > "${failures_file}" || true
    run_count="$(grep -c -E '^\[ RUN      \] xquic_case_test\.' "${log_file}" || true)"
    ok_count="$(grep -c -E '^\[       OK \] xquic_case_test\.' "${log_file}" || true)"
    fail_count="$(wc -l < "${failures_file}" | tr -d ' ')"

    echo "[case-test] ${group_id} result=$([[ "${runner_status}" -eq 0 && "${fail_count}" -eq 0 ]] && echo pass || echo fail) exit=${runner_status} run=${run_count} ok=${ok_count} fail=${fail_count} log=${log_file}"

    if [[ "${fail_count}" -gt 0 ]]; then
        sed "s/^/[case-test:${group_id}] /" "${failures_file}"
    fi

    if [[ "${runner_status}" -ne 0 || "${fail_count}" -ne 0 ]]; then
        echo "[case-test] ${group_id} failed output tail follows; full log=${log_file}"
        tail -n "${failure_context_lines}" "${log_file}" | sed "s/^/[case-test:${group_id}] /"
        return 1
    fi

    return 0
}

if [[ "${PARALLEL}" -eq 0 || "${JOBS}" -eq 1 ]]; then
    index=0
    while IFS=$'\t' read -r group_id runner port_offset; do
        run_group "${group_id}" "${runner}" "${port_offset:-${index}}"
        index=$((index + 1))
    done < "${MAP_FILE}"
    exit 0
fi

active=0
index=0
status=0
pids=()

while IFS=$'\t' read -r group_id runner port_offset; do
    run_group "${group_id}" "${runner}" "${port_offset:-${index}}" &
    pids+=("$!")
    active=$((active + 1))
    index=$((index + 1))

    if [[ "${active}" -ge "${JOBS}" ]]; then
        if ! wait "${pids[0]}"; then
            status=1
        fi
        pids=("${pids[@]:1}")
        active=$((active - 1))
    fi
done < "${MAP_FILE}"

for pid in "${pids[@]}"; do
    if ! wait "${pid}"; then
        status=1
    fi
done

exit "${status}"
