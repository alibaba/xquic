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
    trap 'case_test_stop_server; case_test_cleanup_udp_port' EXIT
}

case_test_stop_server()
{
    if [[ -n "${CASE_TEST_SERVER_PID:-}" ]]; then
        kill "${CASE_TEST_SERVER_PID}" 2> /dev/null || true
        wait "${CASE_TEST_SERVER_PID}" 2> /dev/null || true
        CASE_TEST_SERVER_PID=""
    fi
}

case_test_cleanup_udp_port()
{
    local port="${1:-${CASE_TEST_PORT:-}}"
    local pid

    if [[ -z "${port}" ]] || ! command -v lsof > /dev/null 2>&1; then
        return 0
    fi

    while read -r pid; do
        if [[ -n "${pid}" ]]; then
            kill "${pid}" 2> /dev/null || true
        fi
    done < <(lsof -nP -tiUDP:"${port}" 2> /dev/null || true)
}

case_test_replace_in_file()
{
    local pattern="$1"
    local replacement="$2"
    local path="$3"
    local tmp

    tmp="${path}.case-test-tmp.$$"
    sed "s/${pattern}/${replacement}/" "${path}" > "${tmp}"
    mv "${tmp}" "${path}"
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
    local timeout_s="${3:-${CASE_TEST_CASE_TIMEOUT:-0}}"
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
            if [[ -n "${CASE_TEST_EVENT_FILE:-}" ]]; then
                printf '%s\t%s\n' "${name}" "fail" >> "${CASE_TEST_EVENT_FILE}"
            fi
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
    local timeout_s="${3:-}"

    echo "[case-test] case-start group=${CASE_TEST_GROUP:-} case=${name} id=${id} ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    case_test_case_watchdog_start "${name}" "${id}" "${timeout_s}"
}

case_test_case_end()
{
    local name="$1"
    local id="$2"
    local status="$3"

    case_test_case_watchdog_stop
    echo "[case-test] case-end group=${CASE_TEST_GROUP:-} case=${name} id=${id} status=${status} ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if [[ -n "${CASE_TEST_EVENT_FILE:-}" ]]; then
        printf '%s\t%s\n' "${name}" "${status}" >> "${CASE_TEST_EVENT_FILE}"
    fi
}

case_test_case()
{
    local name="$1"
    local id="native"
    local mode="return-status"
    local run_func=""
    local timeout_s=""

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
            --timeout)
                timeout_s="${2:?--timeout requires a value}"
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
    CASE_TEST_CASE_TIMEOUTS+=("${timeout_s}")
}

case_test_run_self_reporting_case()
{
    local name="$1"
    local run_func="$2"
    local case_file_id
    local output_file
    local status

    case_file_id="$(case_test_sanitize_id "${name}")"
    output_file="${CASE_TEST_WORK_DIR:-.}/case-output-${case_file_id}.log"
    : > "${output_file}"

    set +e
    set +o pipefail
    "${run_func}" > "${output_file}" 2>&1
    status="$?"
    set -e
    set -o pipefail

    cat "${output_file}"
    case_test_snapshot_case_logs "${case_file_id}"

    if grep -q ">>>>>>>> pass:0" "${output_file}"; then
        return 1
    fi

    if grep -q "\\[     FAIL \\] xquic_case_test\\.${name} " "${output_file}"; then
        return 1
    fi

    if grep -q ">>>>>>>> pass:1" "${output_file}"; then
        return 0
    fi

    if grep -q "\\[       OK \\] xquic_case_test\\.${name} " "${output_file}"; then
        return 0
    fi

    if [[ "${status}" -ne 0 ]]; then
        return "${status}"
    fi

    return 1
}

case_test_snapshot_case_logs()
{
    local case_file_id="$1"
    local log_dir
    local log_name

    log_dir="${CASE_TEST_WORK_DIR:-.}/case-logs/${case_file_id}"
    mkdir -p "${log_dir}"

    for log_name in stdlog clog slog svr_stdlog ccfc.log; do
        if [[ -f "${log_name}" ]]; then
            cp "${log_name}" "${log_dir}/${log_name}"
        fi
    done
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
    local timeout_s
    local matched=0

    if case_test_is_discovery; then
        return 0
    fi

    if declare -F case_test_group_setup > /dev/null; then
        case_test_group_setup
    fi

    for index in "${!CASE_TEST_CASE_NAMES[@]}"; do
        name="${CASE_TEST_CASE_NAMES[${index}]}"
        id="${CASE_TEST_CASE_IDS[${index}]}"
        mode="${CASE_TEST_CASE_MODES[${index}]}"
        run_func="${CASE_TEST_CASE_RUNNERS[${index}]}"
        timeout_s="${CASE_TEST_CASE_TIMEOUTS[${index}]}"

        if [[ -n "${selected}" && "${selected}" != "${name}" && "${selected}" != "${id}" ]]; then
            continue
        fi

        matched=$((matched + 1))
        case_test_case_begin "${name}" "${id}" "${timeout_s}" || return 2
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

    if [[ -n "${selected}" && "${matched}" -eq 0 ]]; then
        echo "case_test: selected case was not found in ${CASE_TEST_GROUP:-unknown}: ${selected}" >&2
        return 2
    fi

    return "${status}"
}

case_test_start_server()
{
    case_test_stop_server
    "$@" &
    CASE_TEST_SERVER_PID="$!"
    sleep "${CASE_TEST_SERVER_WAIT:-1}"
}

case_test_wait_for_log()
{
    local log_file="$1"
    local pattern="$2"
    local attempts="${3:-20}"
    local interval="${4:-0.1}"
    local attempt=0

    while [[ "${attempt}" -lt "${attempts}" ]]; do
        if grep -q -- "${pattern}" "${log_file}" 2> /dev/null; then
            return 0
        fi

        sleep "${interval}"
        attempt=$((attempt + 1))
    done

    return 1
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
    if [[ -n "${GCOV_PREFIX:-}" ]]; then
        sudo env GCOV_PREFIX="${GCOV_PREFIX}" \
            GCOV_PREFIX_STRIP="${GCOV_PREFIX_STRIP:-0}" "$@"
    else
        sudo "$@"
    fi
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

case_test_should_retry_timeout_or_no_result()
{
    local output_file="$1"
    local errlog="${2:-}"

    if [[ -n "${errlog}" ]]; then
        return 1
    fi

    if [[ ! -s "${output_file}" ]]; then
        return 0
    fi

    if grep -q "xqc_client_timeout_callback | conn_close" "${output_file}"; then
        return 0
    fi

    if ! grep -q ">>>>>>>> pass:" "${output_file}"; then
        return 0
    fi

    return 1
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
CASE_TEST_CASE_TIMEOUTS=()
CASE_TEST_CASE_WATCHDOG_PID=""
