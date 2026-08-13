#!/bin/bash
#
# Structured endpoint case-test runner.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

SELECTOR_ARGS=()
SELECTOR_COUNT=0
CASE_FILTERS=()
EXECUTE=0
PARALLEL=0
REQUIRE_COMPLETE=0
JOBS=1
JOBS_EXPLICIT=0
PORT_BASE="${CASE_TEST_PORT_BASE:-18000}"
SHARD_TIMEOUT="${CASE_TEST_SHARD_TIMEOUT:-600}"
HEARTBEAT_INTERVAL="${CASE_TEST_HEARTBEAT_INTERVAL:-60}"
CASE_TIMEOUT="${CASE_TEST_CASE_TIMEOUT:-0}"

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
  --jobs <count|auto>
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
            JOBS_EXPLICIT=1
            shift 2
            ;;
        --port-base)
            PORT_BASE="${2:?--port-base requires a value}"
            shift 2
            ;;
        --case)
            CASE_FILTERS+=("${2:?--case requires a value}")
            SELECTOR_ARGS+=("$1" "$2")
            SELECTOR_COUNT=$((SELECTOR_COUNT + 1))
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

if ! [[ "${CASE_TIMEOUT}" =~ ^[0-9]+$ ]]; then
    echo "case_test: CASE_TEST_CASE_TIMEOUT must be a non-negative integer" >&2
    exit 2
fi

BUILD_DIR="$(case_test_build_dir "${ROOT_DIR}")"
CASE_TEST_RUN_ID="${CASE_TEST_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
CASE_TEST_RUN_ID="$(case_test_sanitize_id "${CASE_TEST_RUN_ID}")"
CASE_TEST_RUN_DIR="${CASE_TEST_RUN_DIR:-${BUILD_DIR}/case_test_parallel/${CASE_TEST_RUN_ID}}"
MAP_FILE="$(mktemp "${TMPDIR:-/tmp}/xquic_case_runners.XXXXXX")"
PLAN_FILE="$(mktemp "${TMPDIR:-/tmp}/xquic_case_plan.XXXXXX")"
OWNERSHIP_FILE="$(mktemp "${TMPDIR:-/tmp}/xquic_case_ownership.XXXXXX")"
trap 'rm -f "${MAP_FILE}" "${PLAN_FILE}" "${OWNERSHIP_FILE}"' EXIT

if ! ruby "${ROOT_DIR}/case_test/lib/selector.rb" "${ROOT_DIR}" \
    --inventory > "${OWNERSHIP_FILE}"
then
    cat "${OWNERSHIP_FILE}" >&2
    echo "case_test: current-suite case ownership must be complete and unique before execution" >&2
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
        echo "case_test: selected executable shards do not cover all selected current-suite cases" >&2
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
    echo "case_test: run with --dry-run to inspect matching current-suite cases" >&2
    exit 1
fi

plan_value()
{
    awk -F= -v key="$1" '
        $1 == key {
            print $2
            found = 1
            exit
        }
        END {
            if (!found) {
                exit 1
            }
        }
    ' "${PLAN_FILE}"
}

if [[ "${PARALLEL}" -eq 1 && "${JOBS_EXPLICIT}" -eq 0 && "${JOBS}" == "1" ]]; then
    JOBS="auto"
fi

if [[ "${JOBS}" == "auto" ]]; then
    if ! JOBS="$(plan_value max_safe_jobs)"; then
        echo "case_test: execution plan does not declare max_safe_jobs" >&2
        exit 2
    fi
fi

if ! [[ "${JOBS}" =~ ^[1-9][0-9]*$ ]]; then
    echo "case_test: --jobs must be a positive integer or auto" >&2
    exit 2
fi

if [[ "${PARALLEL}" -eq 1 && "${#CASE_FILTERS[@]}" -gt 0 ]]; then
    echo "case_test: --case execution is a serial diagnostic selector; omit --parallel" >&2
    exit 2
fi

selected_runners_need_sudo()
{
    local map_file="$1"
    local group_id
    local runner
    local port_offset
    local module
    local feature
    local expected_count
    local selected_cases

    while IFS=$'\t' read -r group_id runner port_offset module feature expected_count selected_cases; do
        if [[ "${feature:-}" = "-" ]]; then
            feature=""
        fi
        if grep -Eq 'case_test_(require_sudo|sudo)' "${ROOT_DIR}/${runner}"; then
            return 0
        fi
    done < "${map_file}"

    return 1
}

if selected_runners_need_sudo "${MAP_FILE}"; then
    if ! command -v sudo > /dev/null 2>&1 || ! sudo -n true 2> /dev/null; then
        echo "case_test: selected case-test groups require sudo; run sudo -v before execution" >&2
        exit 125
    fi
fi

run_group()
{
    local group_id="$1"
    local runner="$2"
    local port_offset="$3"
    local module="${4:-}"
    local feature="${5:-}"
    local case_filter="${6:-}"
    local expected_count="${7:-0}"
    local shard_id
    local port
    local work_dir
    local log_file
    local failures_file
    local results_file
    local events_file
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
    if [[ -n "${case_filter}" ]]; then
        shard_id="${shard_id}/$(case_test_sanitize_id "${case_filter}")"
    fi
    port=$((PORT_BASE + port_offset))
    work_dir="${CASE_TEST_RUN_DIR}/${shard_id}"
    log_file="${work_dir}/case_test.log"
    failures_file="${work_dir}/case_test.failures"
    results_file="${work_dir}/case_test.results"
    events_file="${work_dir}/case_test.events"
    failure_context_lines="${CASE_TEST_FAILURE_CONTEXT_LINES:-120}"

    case_test_prepare_work_dir "${BUILD_DIR}" "${work_dir}"
    : > "${log_file}"
    : > "${failures_file}"
    : > "${results_file}"
    : > "${events_file}"
    echo "[case-test] runner-start group=${group_id} runner=${runner} port=${port} work_dir=${work_dir}" > "${log_file}"

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
        export CASE_TEST_CASE="${case_filter}"
        export CASE_TEST_EVENT_FILE="${events_file}"
        export GCOV_PREFIX="${work_dir}/gcov"
        export GCOV_PREFIX_STRIP=0
        mkdir -p "${GCOV_PREFIX}"
        if [[ "${SHARD_TIMEOUT}" -gt 0 ]] && command -v timeout > /dev/null 2>&1; then
            exec timeout "${SHARD_TIMEOUT}" "${ROOT_DIR}/${runner}"
        fi
        exec "${ROOT_DIR}/${runner}"
    ) >> "${log_file}" 2>&1 &
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

    if wait "${runner_pid}" 2> /dev/null; then
        runner_status=0
    else
        runner_status="$?"
    fi

    if [[ -n "${heartbeat_pid}" ]]; then
        kill "${heartbeat_pid}" 2> /dev/null || true
    fi
    case_test_cleanup_udp_port "${port}"

    end_epoch="$(date +%s)"
    if [[ "${runner_status}" -eq 124 ]]; then
        echo "[case-test] ${group_id} timeout elapsed=$((end_epoch - start_epoch))s limit=${SHARD_TIMEOUT}s log=${log_file}"
    fi

    awk -F '\t' -v group_id="${group_id}" '
        NF >= 2 {
            name = $1
            result = ($2 == "pass") ? "1" : "0"
            if (!(name in seen)) {
                order[++count] = name
                seen[name] = 1
            }
            if (!(name in status) || result == "0") {
                status[name] = result
            }
        }
        END {
            for (i = 1; i <= count; i++) {
                name = order[i]
                print "[case-test:" group_id "] " name " >>>>>>>> pass:" status[name]
            }
        }
    ' "${events_file}" > "${results_file}"
    grep '>>>>>>>> pass:0' "${results_file}" > "${failures_file}" || true
    run_count="$(wc -l < "${results_file}" | tr -d ' ')"
    ok_count="$(grep -c '>>>>>>>> pass:1' "${results_file}" || true)"
    fail_count="$(wc -l < "${failures_file}" | tr -d ' ')"

    if [[ -n "${case_filter}" ]]; then
        expected_count=1
    fi

    if ! [[ "${expected_count}" =~ ^[0-9]+$ ]]; then
        expected_count=0
    fi

    if [[ "${expected_count}" -gt 0 && "${run_count}" -ne "${expected_count}" ]]; then
        echo "[case-test:${group_id}] coverage-mismatch expected=${expected_count} actual=${run_count}" >> "${failures_file}"
        fail_count=$((fail_count + 1))
    fi

    echo "[case-test] ${group_id} result=$([[ "${runner_status}" -eq 0 && "${fail_count}" -eq 0 ]] && echo pass || echo fail) exit=${runner_status} elapsed=$((end_epoch - start_epoch))s run=${run_count} expected=${expected_count} ok=${ok_count} fail=${fail_count} log=${log_file}"
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

run_parallel_map()
{
    local map_file="$1"
    local active=0
    local index=0
    local status=0
    local pids=()
    local group_id
    local runner
    local port_offset
    local module
    local feature
    local expected_count
    local selected_cases

    while IFS=$'\t' read -r group_id runner port_offset module feature expected_count selected_cases; do
        if [[ "${feature:-}" = "-" ]]; then
            feature=""
        fi
        run_group "${group_id}" "${runner}" "${port_offset:-${index}}" "${module:-}" "${feature:-}" "" "${expected_count:-0}" &
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
    done < "${map_file}"

    for pid in "${pids[@]}"; do
        if ! wait "${pid}"; then
            status=1
        fi
    done

    return "${status}"
}

run_serial_map()
{
    local map_file="$1"
    local index=0
    local status=0
    local group_id
    local runner
    local port_offset
    local module
    local feature
    local expected_count
    local selected_cases
    local group_case_filters=()
    local case_filter

    while IFS=$'\t' read -r group_id runner port_offset module feature expected_count selected_cases; do
        if [[ "${feature:-}" = "-" ]]; then
            feature=""
        fi
        if [[ "${#CASE_FILTERS[@]}" -gt 0 ]]; then
            if [[ -z "${selected_cases:-}" || "${selected_cases}" = "-" ]]; then
                group_case_filters=("${CASE_FILTERS[@]}")

            else
                IFS=',' read -r -a group_case_filters <<< "${selected_cases}"
            fi

            for case_filter in "${group_case_filters[@]}"; do
                if ! run_group "${group_id}" "${runner}" "${port_offset:-${index}}" "${module:-}" "${feature:-}" "${case_filter}" "1"; then
                    status=1
                fi
            done

        elif ! run_group "${group_id}" "${runner}" "${port_offset:-${index}}" "${module:-}" "${feature:-}" "" "${expected_count:-0}"; then
            status=1
        fi
        index=$((index + 1))
    done < "${map_file}"

    return "${status}"
}

if [[ "${PARALLEL}" -eq 0 || "${JOBS}" -eq 1 ]]; then
    echo "[case-test] run-id=${CASE_TEST_RUN_ID} run_dir=${CASE_TEST_RUN_DIR}"
    run_serial_map "${MAP_FILE}"
    exit "$?"
fi

echo "[case-test] run-id=${CASE_TEST_RUN_ID} run_dir=${CASE_TEST_RUN_DIR}"
echo "[case-test] scheduling groups with jobs=${JOBS}"
run_parallel_map "${MAP_FILE}"
exit "$?"
