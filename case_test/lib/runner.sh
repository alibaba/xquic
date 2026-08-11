#!/bin/bash
#
# Structured endpoint case-test runner.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

SELECTOR_ARGS=()
SELECTOR_COUNT=0
EXECUTE=0
PARALLEL=0
REQUIRE_COMPLETE=0
JOBS=1
PORT_BASE="${CASE_TEST_PORT_BASE:-18000}"
SHARD_TIMEOUT="${CASE_TEST_SHARD_TIMEOUT:-1800}"
HEARTBEAT_INTERVAL="${CASE_TEST_HEARTBEAT_INTERVAL:-60}"

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
    EXECUTE=1
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

if ! [[ "${SHARD_TIMEOUT}" =~ ^[0-9]+$ ]]; then
    echo "case_test: CASE_TEST_SHARD_TIMEOUT must be a non-negative integer" >&2
    exit 2
fi

if ! [[ "${HEARTBEAT_INTERVAL}" =~ ^[0-9]+$ ]]; then
    echo "case_test: CASE_TEST_HEARTBEAT_INTERVAL must be a non-negative integer" >&2
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

if [[ "${SELECTOR_COUNT}" -eq 0 && "${PLAN_COMPLETE}" -eq 0 ]]; then
    cat "${PLAN_FILE}" >&2
    echo "case_test: executable shards are incomplete" >&2
    exit 1
fi

if [[ ! -s "${MAP_FILE}" ]]; then
    echo "case_test: selected case-test groups are not executable yet" >&2
    echo "case_test: run with --dry-run to inspect matching legacy cases" >&2
    exit 1
fi

run_group()
{
    local group_id="$1"
    local runner="$2"
    local port_offset="$3"
    local module="${4:-}"
    local feature="${5:-}"
    local shard_id
    local port
    local work_dir
    local log_file
    local failures_file
    local results_file
    local runner_status
    local run_count
    local ok_count
    local fail_count
    local failure_context_lines
    local start_epoch
    local end_epoch
    local runner_pid
    local heartbeat_pid

    shard_id="$(case_test_sanitize_id "${group_id}")"
    port=$((PORT_BASE + port_offset))
    work_dir="${BUILD_DIR}/case_test_parallel/${shard_id}"
    log_file="${work_dir}/case_test.log"
    failures_file="${work_dir}/case_test.failures"
    results_file="${work_dir}/case_test.results"
    failure_context_lines="${CASE_TEST_FAILURE_CONTEXT_LINES:-120}"

    case_test_prepare_work_dir "${BUILD_DIR}" "${work_dir}"
    : > "${log_file}"
    : > "${failures_file}"
    : > "${results_file}"

    start_epoch="$(date +%s)"
    echo "[case-test] ${group_id} start ts=$(date -u +%Y-%m-%dT%H:%M:%SZ) port=${port} runner=${runner} log=${log_file}"
    (
        export XQC_BUILD_DIR="${BUILD_DIR}"
        export CASE_TEST_WORK_DIR="${work_dir}"
        export CASE_TEST_PORT="${port}"
        export CASE_TEST_SHARD_ID="${shard_id}"
        export CASE_TEST_GROUP="${group_id}"
        export CASE_TEST_MODULE="${module}"
        export CASE_TEST_FEATURE="${feature}"
        if [[ "${SHARD_TIMEOUT}" -gt 0 ]] && command -v timeout > /dev/null 2>&1; then
            exec timeout "${SHARD_TIMEOUT}" "${ROOT_DIR}/${runner}"
        fi
        exec "${ROOT_DIR}/${runner}"
    ) > "${log_file}" 2>&1 &
    runner_pid="$!"

    heartbeat_pid=""
    if [[ "${HEARTBEAT_INTERVAL}" -gt 0 ]]; then
        (
            sleep_pid=""
            trap 'if [[ -n "${sleep_pid}" ]]; then kill "${sleep_pid}" 2> /dev/null || true; fi; exit 0' TERM INT

            while true; do
                sleep "${HEARTBEAT_INTERVAL}" &
                sleep_pid="$!"
                wait "${sleep_pid}" 2> /dev/null || exit 0
                sleep_pid=""

                if ! kill -0 "${runner_pid}" 2> /dev/null; then
                    exit 0
                fi
                echo "[case-test] ${group_id} running elapsed=$(($(date +%s) - start_epoch))s log=${log_file}"
            done
        ) &
        heartbeat_pid="$!"
    fi

    if wait "${runner_pid}"; then
        runner_status=0
    else
        runner_status="$?"
    fi

    if [[ -n "${heartbeat_pid}" ]]; then
        kill "${heartbeat_pid}" 2> /dev/null || true
    fi

    end_epoch="$(date +%s)"
    if [[ "${runner_status}" -eq 124 ]]; then
        echo "[case-test] ${group_id} timeout elapsed=$((end_epoch - start_epoch))s limit=${SHARD_TIMEOUT}s log=${log_file}"
    fi

    awk -v group_id="${group_id}" '
        function emit(name, result) {
            print "[case-test:" group_id "] " name " >>>>>>>> pass:" result
            emitted[name] = 1
        }

        />>>>>>>> pass:[01]/ {
            result = $0
            sub(/^.*>>>>>>>> pass:/, "", result)
            result = substr(result, 1, 1)
            pending_result = result
            next
        }
        /^\[ RUN      \] xquic_case_test\./ {
            name = $0
            sub(/^\[ RUN      \] xquic_case_test\./, "", name)
            sub(/ .*/, "", name)
            if (pending_result != "") {
                emit(name, pending_result)
                pending_result = ""
            }
            next
        }
        /^\[       OK \] xquic_case_test\./ {
            name = $0
            sub(/^\[       OK \] xquic_case_test\./, "", name)
            sub(/ .*/, "", name)
            if (!emitted[name]) {
                emit(name, "1")
            }
            next
        }
        /^\[     FAIL \] xquic_case_test\./ {
            name = $0
            sub(/^\[     FAIL \] xquic_case_test\./, "", name)
            sub(/ .*/, "", name)
            if (!emitted[name]) {
                emit(name, "0")
            }
            next
        }
    ' "${log_file}" > "${results_file}"
    grep '>>>>>>>> pass:0' "${results_file}" > "${failures_file}" || true
    run_count="$(wc -l < "${results_file}" | tr -d ' ')"
    ok_count="$(grep -c '>>>>>>>> pass:1' "${results_file}" || true)"
    fail_count="$(wc -l < "${failures_file}" | tr -d ' ')"

    echo "[case-test] ${group_id} result=$([[ "${runner_status}" -eq 0 && "${fail_count}" -eq 0 ]] && echo pass || echo fail) exit=${runner_status} elapsed=$((end_epoch - start_epoch))s run=${run_count} ok=${ok_count} fail=${fail_count} log=${log_file}"
    cat "${results_file}"

    if [[ "${runner_status}" -ne 0 || "${fail_count}" -ne 0 ]]; then
        if [[ "${fail_count}" -gt 0 ]]; then
            sed 's/>>>>>>>> pass:0/failed/' "${failures_file}"
        fi
        echo "[case-test] ${group_id} failed output tail follows; full log=${log_file}"
        tail -n "${failure_context_lines}" "${log_file}" |
            sed 's/pass:/raw-pass:/g' |
            sed "s/^/[case-test:${group_id}] /"
        return 1
    fi

    return 0
}

if [[ "${PARALLEL}" -eq 0 || "${JOBS}" -eq 1 ]]; then
    index=0
    while IFS=$'\t' read -r group_id runner port_offset module feature; do
        run_group "${group_id}" "${runner}" "${port_offset:-${index}}" "${module:-}" "${feature:-}"
        index=$((index + 1))
    done < "${MAP_FILE}"
    exit 0
fi

active=0
index=0
status=0
pids=()

while IFS=$'\t' read -r group_id runner port_offset module feature; do
    run_group "${group_id}" "${runner}" "${port_offset:-${index}}" "${module:-}" "${feature:-}" &
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
