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
}

case_test_stop_server()
{
    if [[ -n "${CASE_TEST_SERVER_PID:-}" ]]; then
        kill "${CASE_TEST_SERVER_PID}" 2> /dev/null || true
        wait "${CASE_TEST_SERVER_PID}" 2> /dev/null || true
        CASE_TEST_SERVER_PID=""
    fi
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
