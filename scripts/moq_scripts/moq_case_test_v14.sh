#!/bin/bash

# Copyright (c) 2022, Alibaba Group Holding Limited

# New MOQ end-to-end test script. Test cases includes:
# 1.publish stream 2.dynamic datachannel, 3.raw object mode.

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
cd "${REPO_ROOT}/build" || exit 1

CLIENT_BIN="moq/demo/moq_demo_client"
SERVER_BIN="moq/demo/moq_demo_server"

SERVER_PID=""
CLIENT_STDLOG=""
SERVER_STDLOG=""
SERVER_BASE_ARGS=("-c" "b" "-p" "4433" "-V")
CLIENT_BASE_ARGS=("-a" "127.0.0.1" "-p" "4433" "-V")
TOTAL_CASES=0
PASSED_CASES=0
FAILED_CASES=()

clear_log() {
    : > clog
    : > slog
}

reset_runtime() {
    rm -rf tp_localhost test_session xqc_token
    clear_log
}

start_server() {
    local case_name=$1
    shift
    SERVER_STDLOG="server_${case_name}.log"
    ${SERVER_BIN} "$@" > "${SERVER_STDLOG}" 2>&1 &
    SERVER_PID=$!
    sleep 1
}

stop_server() {
    if [ -n "${SERVER_PID}" ]; then
        kill "${SERVER_PID}" 2>/dev/null
        wait "${SERVER_PID}" 2>/dev/null
        SERVER_PID=""
    fi
    killall moq_demo_server 2>/dev/null
}

run_client() {
    local case_name=$1
    shift
    CLIENT_STDLOG="client_${case_name}.log"
    ${CLIENT_BIN} "$@" > "${CLIENT_STDLOG}" 2>&1
    return $?
}

get_err_log() {
    local err_clog err_slog output=""
    err_clog=$(grep "\[error\]" clog 2>/dev/null || true)
    err_slog=$(grep "\[error\]" slog 2>/dev/null || true)
    if [ -n "${err_clog}" ]; then
        output="${err_clog}"
    fi
    if [ -n "${err_slog}" ]; then
        if [ -n "${output}" ]; then
            output="${output}"$'\n'"${err_slog}"
        else
            output="${err_slog}"
        fi
    fi
    printf "%s" "${output}"
}

# params: case_name, result
case_print_result() {
    echo "[ RUN      ] moq_case_e2e.$1"
    if [ "$2" = "pass" ]; then
        echo "[       OK ] moq_case_e2e.$1 (1 ms)"
    else
        echo "[     FAIL ] moq_case_e2e.$1 (1 ms)"
    fi
}

record_case_result() {
    local name=$1
    local status=$2
    TOTAL_CASES=$((TOTAL_CASES + 1))
    if [ "${status}" = "pass" ]; then
        PASSED_CASES=$((PASSED_CASES + 1))
    else
        FAILED_CASES+=("${name}")
    fi
}

run_publish_case() {
    local case_name="publish_basic"
    local status="fail"
    echo -e "moq publish only ...\c"
    reset_runtime
    start_server "${case_name}" "${SERVER_BASE_ARGS[@]}" -r pub -n 60
    run_client "${case_name}" "${CLIENT_BASE_ARGS[@]}" -r sub -n 60
    local cli_res errlog
    cli_res=$(grep "|on_video|" clog | grep "seq:59" 2>/dev/null || true)
    errlog=$(get_err_log)
    if [ -n "${cli_res}" ] && [ -z "${errlog}" ]; then
        echo ">>>>>>>> pass:1"
        status="pass"
    else
        echo ">>>>>>>> pass:0"
        echo "${errlog}"
        echo "${cli_res}"
    fi
    case_print_result "${case_name}" "${status}"
    record_case_result "${case_name}" "${status}"
    stop_server
}

run_datachannel_case() {
    local case_name="datachannel_dynamic"
    local status="fail"
    echo -e "moq dynamic datachannel ...\c"
    reset_runtime
    start_server "${case_name}" "${SERVER_BASE_ARGS[@]}" -n 10 -M
    run_client "${case_name}" "${CLIENT_BASE_ARGS[@]}" -n 10 -M
    local cli_create cli_send svr_dc errlog
    cli_create=$(grep "create extra datachannel" "${CLIENT_STDLOG}" 2>/dev/null || true)
    cli_send=$(grep "send msg on extra datachannel" "${CLIENT_STDLOG}" 2>/dev/null || true)
    svr_dc=$(grep "|on_datachannel_msg_detail|" slog 2>/dev/null || true)
    errlog=$(get_err_log)
    if [ -n "${cli_create}" ] && [ -n "${cli_send}" ] && [ -n "${svr_dc}" ] && [ -z "${errlog}" ]; then
        echo ">>>>>>>> pass:1"
        status="pass"
    else
        echo ">>>>>>>> pass:0"
        echo "${errlog}"
        echo "${cli_create}"
        echo "${cli_send}"
        echo "${svr_dc}"
    fi
    case_print_result "${case_name}" "${status}"
    record_case_result "${case_name}" "${status}"
    stop_server
}

run_raw_object_case() {
    local case_name="raw_object_mode"
    local status="fail"
    echo -e "moq raw object (-R) ...\c"
    reset_runtime
    start_server "${case_name}" "${SERVER_BASE_ARGS[@]}" -n 10 -M -R
    run_client "${case_name}" "${CLIENT_BASE_ARGS[@]}" -n 10 -M -R
    local cli_raw svr_raw errlog
    cli_raw=$(grep "|write raw object success|" clog 2>/dev/null || true)
    svr_raw=$(grep "on_raw_object:" "${SERVER_STDLOG}" 2>/dev/null || true)
    errlog=$(get_err_log)
    if [ -n "${cli_raw}" ] && [ -n "${svr_raw}" ] && [ -z "${errlog}" ]; then
        echo ">>>>>>>> pass:1"
        status="pass"
    else
        echo ">>>>>>>> pass:0"
        echo "${errlog}"
        echo "${cli_raw}"
        echo "${svr_raw}"
    fi
    case_print_result "${case_name}" "${status}"
    record_case_result "${case_name}" "${status}"
    stop_server
}

run_publish_case
run_datachannel_case
run_raw_object_case

echo
echo "moq_case_e2e summary: ${PASSED_CASES}/${TOTAL_CASES} passed"
if [ "${PASSED_CASES}" -ne "${TOTAL_CASES}" ]; then
    echo "failed cases: ${FAILED_CASES[*]}"
fi

if [ "${PASSED_CASES}" -ne "${TOTAL_CASES}" ]; then
    exit 1
fi

cd - >/dev/null || exit 0

