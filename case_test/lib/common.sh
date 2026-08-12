#!/bin/bash
#
# Shared helpers for endpoint case-test runners.

case_test_root()
{
    cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
}

case_test_build_dir()
{
    local root="$1"
    local build_dir="${XQC_BUILD_DIR:-${root}/build}"

    if [[ "${build_dir}" != /* ]]; then
        build_dir="${root}/${build_dir}"
    fi

    printf '%s\n' "${build_dir}"
}

case_test_sanitize_id()
{
    printf '%s' "$1" | tr -c 'A-Za-z0-9_.-' '_'
}

case_test_prepare_work_dir()
{
    local build_dir="$1"
    local work_dir="$2"

    mkdir -p "${work_dir}"

    if [[ -f "${build_dir}/server.key" && ! -e "${work_dir}/server.key" ]]; then
        ln -s "${build_dir}/server.key" "${work_dir}/server.key"
    fi

    if [[ -f "${build_dir}/server.crt" && ! -e "${work_dir}/server.crt" ]]; then
        ln -s "${build_dir}/server.crt" "${work_dir}/server.crt"
    fi
}

case_test_enter_work_dir()
{
    local root
    local build_dir

    if [[ "$(uname -s)" = "Darwin" && -z "${EVENT_NOKQUEUE+x}" ]]; then
        export EVENT_NOKQUEUE=1
    fi

    root="$(case_test_root)"
    build_dir="$(case_test_build_dir "${root}")"
    CASE_TEST_WORK_DIR="${CASE_TEST_WORK_DIR:-${build_dir}}"
    CASE_TEST_SHARD_ID="${CASE_TEST_SHARD_ID:-$(case_test_sanitize_id "$(basename "${CASE_TEST_WORK_DIR}")")}"
    CASE_TEST_PORT="${CASE_TEST_PORT:-}"
    CASE_TEST_PORT_ARG=""
    CASE_TEST_CLIENT_LOG="${CASE_TEST_CLIENT_LOG:-clog}"
    CASE_TEST_SERVER_LOG="${CASE_TEST_SERVER_LOG:-slog}"

    if [[ -n "${CASE_TEST_PORT}" ]]; then
        CASE_TEST_PORT_ARG="-p ${CASE_TEST_PORT}"
    fi

    case_test_prepare_work_dir "${build_dir}" "${CASE_TEST_WORK_DIR}"
    cd "${CASE_TEST_WORK_DIR}"

    CLIENT_BIN="${CASE_TEST_CLIENT_BIN:-${build_dir}/tests/test_client ${CASE_TEST_PORT_ARG} -o ${CASE_TEST_CLIENT_LOG}}"
    SERVER_BIN="${CASE_TEST_SERVER_BIN:-${build_dir}/tests/test_server ${CASE_TEST_PORT_ARG} -o ${CASE_TEST_SERVER_LOG}}"
    CASE_TEST_SERVER_PID=""
    trap 'case_test_stop_server' EXIT
}

case_test_stop_server()
{
    if [[ -n "${CASE_TEST_SERVER_PID:-}" ]]; then
        kill "${CASE_TEST_SERVER_PID}" 2> /dev/null || true
        wait "${CASE_TEST_SERVER_PID}" 2> /dev/null || true
        CASE_TEST_SERVER_PID=""
    fi
}

case_test_group()
{
    CASE_TEST_DECLARED_GROUP="$1"
    CASE_TEST_GROUP="${CASE_TEST_GROUP:-${CASE_TEST_DECLARED_GROUP}}"
}

case_test_is_discovery()
{
    [[ "${CASE_TEST_DISCOVER:-0}" = "1" ]]
}

case_test_kill_tree()
{
    local signal="$1"
    local root_pid="$2"
    local child_pid

    if command -v pgrep > /dev/null 2>&1; then
        while read -r child_pid; do
            if [[ -n "${child_pid}" ]]; then
                case_test_kill_tree "${signal}" "${child_pid}"
            fi
        done < <(pgrep -P "${root_pid}" 2> /dev/null || true)
    fi

    kill "-${signal}" "${root_pid}" 2> /dev/null || true
}

case_test_case_watchdog_start()
{
    local name="$1"
    local id="$2"
    local timeout_s="${CASE_TEST_CASE_TIMEOUT:-0}"
    local owner_pid="$$"

    CASE_TEST_CASE_WATCHDOG_PID=""

    if ! [[ "${timeout_s}" =~ ^[0-9]+$ ]]; then
        echo "case_test: CASE_TEST_CASE_TIMEOUT must be a non-negative integer" >&2
        return 2
    fi

    if [[ "${timeout_s}" -eq 0 ]]; then
        return 0
    fi

    (
        sleep "${timeout_s}"
        if kill -0 "${owner_pid}" 2> /dev/null; then
            echo "[case-test] case-timeout group=${CASE_TEST_GROUP:-} case=${name} id=${id} elapsed=${timeout_s}s"
            case_test_kill_tree TERM "${owner_pid}"
            sleep 2
            if kill -0 "${owner_pid}" 2> /dev/null; then
                case_test_kill_tree KILL "${owner_pid}"
            fi
        fi
    ) &
    CASE_TEST_CASE_WATCHDOG_PID="$!"
}

case_test_case_watchdog_stop()
{
    if [[ -n "${CASE_TEST_CASE_WATCHDOG_PID:-}" ]]; then
        kill "${CASE_TEST_CASE_WATCHDOG_PID}" 2> /dev/null || true
        wait "${CASE_TEST_CASE_WATCHDOG_PID}" 2> /dev/null || true
        CASE_TEST_CASE_WATCHDOG_PID=""
    fi
}

case_test_case_begin()
{
    local name="$1"
    local id="$2"

    echo "[case-test] case-start group=${CASE_TEST_GROUP:-} case=${name} id=${id} ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    case_test_case_watchdog_start "${name}" "${id}"
}

case_test_case_end()
{
    local name="$1"
    local id="$2"
    local status="$3"

    case_test_case_watchdog_stop
    echo "[case-test] case-end group=${CASE_TEST_GROUP:-} case=${name} id=${id} status=${status} ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

case_test_case()
{
    local name="$1"
    local id="native"
    local mode="return-status"
    local run_func=""

    shift
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --id)
                id="${2:?--id requires a value}"
                shift 2
                ;;
            --run)
                run_func="${2:?--run requires a value}"
                shift 2
                ;;
            --mode)
                mode="${2:?--mode requires a value}"
                shift 2
                ;;
            *)
                echo "case_test_case: unknown option: $1" >&2
                return 2
                ;;
        esac
    done

    if [[ -z "${run_func}" ]]; then
        echo "case_test_case: ${name} missing --run" >&2
        return 2
    fi

    if case_test_is_discovery; then
        printf 'native_case\t%s\t%s\t%s\t%s\t%s\n' \
            "${CASE_TEST_GROUP:-${CASE_TEST_DECLARED_GROUP:-}}" \
            "${CASE_TEST_MODULE:-}" \
            "${CASE_TEST_FEATURE:-}" \
            "${name}" \
            "${id}"
        return 0
    fi

    CASE_TEST_CASE_NAMES+=("${name}")
    CASE_TEST_CASE_IDS+=("${id}")
    CASE_TEST_CASE_MODES+=("${mode}")
    CASE_TEST_CASE_RUNNERS+=("${run_func}")
}

case_test_run_self_reporting_case()
{
    local name="$1"
    local run_func="$2"
    local output
    local status

    if output="$("${run_func}" 2>&1)"; then
        status=0
    else
        status="$?"
    fi

    printf '%s\n' "${output}"

    if printf '%s\n' "${output}" | grep -q ">>>>>>>> pass:0"; then
        return 1
    fi

    if printf '%s\n' "${output}" | grep -q "\\[     FAIL \\] xquic_case_test\\.${name} "; then
        return 1
    fi

    if [[ "${status}" -ne 0 ]]; then
        return "${status}"
    fi

    if printf '%s\n' "${output}" | grep -q ">>>>>>>> pass:1"; then
        return 0
    fi

    if printf '%s\n' "${output}" | grep -q "\\[       OK \\] xquic_case_test\\.${name} "; then
        return 0
    fi

    return 1
}

case_test_run()
{
    local selected="${CASE_TEST_CASE:-}"
    local status=0
    local index
    local name
    local id
    local mode
    local run_func

    if case_test_is_discovery; then
        return 0
    fi

    for index in "${!CASE_TEST_CASE_NAMES[@]}"; do
        name="${CASE_TEST_CASE_NAMES[${index}]}"
        id="${CASE_TEST_CASE_IDS[${index}]}"
        mode="${CASE_TEST_CASE_MODES[${index}]}"
        run_func="${CASE_TEST_CASE_RUNNERS[${index}]}"

        if [[ -n "${selected}" && "${selected}" != "${name}" && "${selected}" != "${id}" ]]; then
            continue
        fi

        case_test_case_begin "${name}" "${id}" || return 2
        if [[ "${mode}" = "self-reporting" ]]; then
            if case_test_run_self_reporting_case "${name}" "${run_func}"; then
                case_test_case_end "${name}" "${id}" "pass"
            else
                case_test_case_end "${name}" "${id}" "fail"
                status=1
            fi
            continue
        fi

        if "${run_func}"; then
            echo ">>>>>>>> pass:1"
            case_print_result "${name}" "pass"
            case_test_case_end "${name}" "${id}" "pass"
        else
            echo ">>>>>>>> pass:0"
            case_print_result "${name}" "fail"
            case_test_case_end "${name}" "${id}" "fail"
            status=1
        fi
    done

    return "${status}"
}

case_test_start_server()
{
    case_test_stop_server
    "$@" &
    CASE_TEST_SERVER_PID="$!"
    sleep "${CASE_TEST_SERVER_WAIT:-1}"
}

case_test_require_sudo()
{
    if ! sudo -n true 2> /dev/null; then
        echo "case_test: sudo credentials required for ${CASE_TEST_SHARD_ID:-unknown}; run sudo -v before executing this shard" >&2
        exit 125
    fi
}

case_test_sudo()
{
    case_test_require_sudo
    sudo "$@"
}

clear_log()
{
    >clog
    >slog
}

grep_err_log()
{
    grep "\[error\]" clog
    grep "\[error\]" slog
}

case_print_result()
{
    echo "[ RUN      ] xquic_case_test.$1"
    if [[ "$2" = "pass" ]]; then
        echo "[       OK ] xquic_case_test.$1 (1 ms)"
    else
        echo "[     FAIL ] xquic_case_test.$1 (1 ms)"
    fi
}

CASE_TEST_CASE_NAMES=()
CASE_TEST_CASE_IDS=()
CASE_TEST_CASE_MODES=()
CASE_TEST_CASE_RUNNERS=()
CASE_TEST_CASE_WATCHDOG_PID=""
