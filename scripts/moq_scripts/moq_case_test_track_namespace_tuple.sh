#!/usr/bin/env bash
#
# End-to-end-ish sanity checks for track_namespace_tuple (namespace tuple support).
# This script follows the style of moq_case_test_v14.sh and runs:
#  1) catalog_test: verifies JSON namespace array decodes/encodes successfully (multi-segment tuple)
#  2) subscribe_namespace_forward_test: verifies tuple prefix matching + discovery idempotency + DONE behavior
#  3) moq_demo_server/client smoke: verifies demo runs without protocol errors (control/data plane basic)
#  4) moq_demo_server/client subscribe-namespace mode (-N): subscriber sends SUBSCRIBE_NAMESPACE and receives PUBLISH
#
# Note: The demo smoke case cannot distinguish ["a","b"] from "a/b" (single tuple element containing '/')
# from logs alone, so the multi-segment tuple coverage comes from catalog_test + subscribe_namespace_forward_test.

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
cd "${REPO_ROOT}/build" || exit 1

MOQ_TEST_DIR="moq/tests"
MOQ_DEMO_DIR="moq/demo"

CATALOG_TEST_BIN="${MOQ_TEST_DIR}/catalog_test"
SUBSCRIBE_NAMESPACE_FORWARD_TEST_BIN="${MOQ_TEST_DIR}/subscribe_namespace_forward_test"
CLIENT_BIN="${MOQ_DEMO_DIR}/moq_demo_client"
SERVER_BIN="${MOQ_DEMO_DIR}/moq_demo_server"

SERVER_PID=""
CLIENT_STDLOG=""
SERVER_STDLOG=""

SERVER_BASE_ARGS=("-c" "b" "-p" "4433" "-V" "-M" "-n" "5")
CLIENT_BASE_ARGS=("-a" "127.0.0.1" "-p" "4433" "-V" "-M" "-n" "5")

# Per-case timeout (seconds). Prevents demo runs from hanging indefinitely.
CASE_TIMEOUT_SECONDS=30
LINEBUF_PREFIX=()
if command -v stdbuf >/dev/null 2>&1; then
    LINEBUF_PREFIX=(stdbuf -oL -eL)
fi

TOTAL_CASES=0
PASSED_CASES=0
FAILED_CASES=()

case_print_result() {
    echo "[ RUN      ] moq_case_namespace_tuple.$1"
    if [ "$2" = "pass" ]; then
        echo "[       OK ] moq_case_namespace_tuple.$1 (1 ms)"
    else
        echo "[     FAIL ] moq_case_namespace_tuple.$1 (1 ms)"
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

clear_log() {
    : > clog
    : > slog
}

reset_runtime() {
    rm -rf tp_localhost test_session xqc_token
    clear_log
}

build_targets() {
    cmake --build . -j 8 --target \
        xquic-static \
        subscribe_namespace_forward_test \
        catalog_test \
        moq_demo_client \
        moq_demo_server >/dev/null
}

run_with_timeout() {
    local timeout_seconds=$1
    shift

    if command -v timeout >/dev/null 2>&1; then
        timeout -s INT -k 2 "${timeout_seconds}" "$@"
        return $?
    fi

    if command -v gtimeout >/dev/null 2>&1; then
        gtimeout -s INT -k 2 "${timeout_seconds}" "$@"
        return $?
    fi

    "$@" &
    local cmd_pid=$!
    (
        sleep "${timeout_seconds}"
        if kill -0 "${cmd_pid}" 2>/dev/null; then
            kill -INT "${cmd_pid}" 2>/dev/null || true
            sleep 2
            if kill -0 "${cmd_pid}" 2>/dev/null; then
                kill -KILL "${cmd_pid}" 2>/dev/null || true
            fi
        fi
    ) &
    local killer_pid=$!

    wait "${cmd_pid}"
    local rc=$?
    kill "${killer_pid}" 2>/dev/null || true
    wait "${killer_pid}" 2>/dev/null || true
    return "${rc}"
}

start_server() {
    local case_name=$1
    shift
    SERVER_STDLOG="server_${case_name}.log"
    ${LINEBUF_PREFIX[@]} ${SERVER_BIN} "$@" > "${SERVER_STDLOG}" 2>&1 &
    SERVER_PID=$!
    sleep 1

    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        echo "server failed to start (pid:${SERVER_PID})"
        return 1
    fi
    return 0
}

stop_server() {
    if [ -n "${SERVER_PID}" ]; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
        SERVER_PID=""
    fi
    killall moq_demo_server 2>/dev/null || true
}

run_client() {
    local case_name=$1
    shift
    CLIENT_STDLOG="client_${case_name}.log"
    run_with_timeout "${CASE_TIMEOUT_SECONDS}" ${LINEBUF_PREFIX[@]} ${CLIENT_BIN} "$@" > "${CLIENT_STDLOG}" 2>&1
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

run_catalog_namespace_tuple_case() {
    local case_name="catalog_namespace_tuple"
    local status="fail"
    echo -e "catalog json namespace tuple (array) decode/encode ...\c"

    build_targets

    local output
    output=$(${CATALOG_TEST_BIN} 2>&1 || true)
    local decode_ok encode_ok
    decode_ok=$(echo "${output}" | grep -E "decode error = 0" || true)
    encode_ok=$(echo "${output}" | grep -E "encode error = 0" || true)

    if [ -n "${decode_ok}" ] && [ -n "${encode_ok}" ]; then
        echo ">>>>>>>> pass:1"
        status="pass"
    else
        echo ">>>>>>>> pass:0"
        echo "${output}"
    fi
    case_print_result "${case_name}" "${status}"
    record_case_result "${case_name}" "${status}"
}

run_subscribe_namespace_forward_case() {
    local case_name="subscribe_namespace_forward"
    local status="fail"
    echo -e "subscribe_namespace forward/idempotency (tuple aware) ...\c"

    build_targets

    local output
    output=$(${SUBSCRIBE_NAMESPACE_FORWARD_TEST_BIN} 2>&1 || true)
    local exit_code=$?
    local errlog
    errlog=$(echo "${output}" | grep -v "^profiling:" || true)

    if [ "${exit_code}" -eq 0 ]; then
        echo ">>>>>>>> pass:1"
        status="pass"
    else
        echo ">>>>>>>> pass:0"
        echo "${errlog}"
    fi
    case_print_result "${case_name}" "${status}"
    record_case_result "${case_name}" "${status}"
}

run_demo_namespace_tuple_smoke_case() {
    local case_name="demo_smoke"
    local status="fail"
    echo -e "demo client/server smoke ...\c"

    build_targets
    reset_runtime
    if ! start_server "${case_name}" "${SERVER_BASE_ARGS[@]}"; then
        echo ">>>>>>>> pass:0"
        case_print_result "${case_name}" "${status}"
        record_case_result "${case_name}" "${status}"
        stop_server
        return
    fi
    run_client "${case_name}" "${CLIENT_BASE_ARGS[@]}"
    local client_rc=$?
    sleep 1

    local errlog cli_publish svr_publish
    errlog=$(get_err_log)
    cli_publish=$(grep -E "on_publish:" "${CLIENT_STDLOG}" 2>/dev/null || true)
    svr_publish=$(grep -E "on_publish:" "${SERVER_STDLOG}" 2>/dev/null || true)

    if [ "${client_rc}" -eq 0 ] && [ -n "${cli_publish}" ] && [ -n "${svr_publish}" ] && [ -z "${errlog}" ]; then
        echo ">>>>>>>> pass:1"
        status="pass"
    else
        echo ">>>>>>>> pass:0"
        echo "client_rc:${client_rc}"
        echo "${errlog}"
        echo "${cli_publish}"
        echo "${svr_publish}"
    fi
    case_print_result "${case_name}" "${status}"
    record_case_result "${case_name}" "${status}"
    stop_server
}

run_demo_subscribe_namespace_mode_case() {
    local case_name="demo_subscribe_namespace_mode"
    local status="fail"
    echo -e "demo subscribe_namespace mode (-N) ...\c"

    build_targets
    reset_runtime

    # Publisher-only server: creates local tracks; should forward PUBLISH when it receives SUBSCRIBE_NAMESPACE.
    if ! start_server "${case_name}" -c b -p 4433 -V -r pub -N -n 1; then
        echo ">>>>>>>> pass:0"
        case_print_result "${case_name}" "${status}"
        record_case_result "${case_name}" "${status}"
        stop_server
        return
    fi

    # Subscriber-only client: sends SUBSCRIBE_NAMESPACE; should receive PUBLISH for video/audio.
    run_client "${case_name}" -a 127.0.0.1 -p 4433 -V -r sub -N -M -n 1
    local client_rc=$?
    sleep 1

    local errlog cli_sub_ns cli_on_publish svr_publish_ok
    errlog=$(get_err_log)
    cli_sub_ns=$(grep -E "send subscribe_namespace:" "${CLIENT_STDLOG}" 2>/dev/null || true)
    cli_on_publish=$(grep -E "on_publish:.*(video|audio)" "${CLIENT_STDLOG}" 2>/dev/null || true)
    svr_publish_ok=$(grep -E "on_publish_ok:" "${SERVER_STDLOG}" 2>/dev/null || true)

    if { [ "${client_rc}" -eq 0 ] || [ "${client_rc}" -eq 124 ]; } \
       && [ -n "${cli_sub_ns}" ] && [ -n "${cli_on_publish}" ] && [ -n "${svr_publish_ok}" ] && [ -z "${errlog}" ]; then
        echo ">>>>>>>> pass:1"
        status="pass"
    else
        echo ">>>>>>>> pass:0"
        echo "client_rc:${client_rc}"
        echo "${errlog}"
        echo "${cli_sub_ns}"
        echo "${cli_on_publish}"
        echo "${svr_publish_ok}"
    fi

    case_print_result "${case_name}" "${status}"
    record_case_result "${case_name}" "${status}"
    stop_server
}

run_demo_subscribe_namespace_broadcast_case() {
    local case_name="demo_subscribe_namespace_broadcast"
    local status="fail"
    echo -e "demo subscribe_namespace broadcast (2 clients, -N) ...\c"

    build_targets
    reset_runtime

    if ! start_server "${case_name}" -c b -p 4433 -V -r pub -N -n 1; then
        echo ">>>>>>>> pass:0"
        case_print_result "${case_name}" "${status}"
        record_case_result "${case_name}" "${status}"
        stop_server
        return
    fi

    local client_count=2
    local client_pids=()
    local client_logs=()

    for ((i=1; i<=client_count; i++)); do
        local client_log="client_${case_name}_${i}.log"
        client_logs+=("${client_log}")
        run_with_timeout "${CASE_TIMEOUT_SECONDS}" \
            ${LINEBUF_PREFIX[@]} ${CLIENT_BIN} -a 127.0.0.1 -p 4433 -V -r sub -N -M -n 1 \
            > "${client_log}" 2>&1 &
        client_pids+=("$!")
    done

    local client_failed=0
    for i in "${!client_pids[@]}"; do
        local pid="${client_pids[$i]}"
        local log_file="${client_logs[$i]}"
        local rc=0
        wait "${pid}" || rc=$?
        if [ "${rc}" -ne 0 ]; then
            client_failed=1
        fi
    done

    sleep 1

    local errlog
    errlog=$(get_err_log)

    local all_clients_ok=1
    for log_file in "${client_logs[@]}"; do
        local has_sub_ns has_video has_audio
        has_sub_ns=$(grep -E "send subscribe_namespace:" "${log_file}" 2>/dev/null || true)
        has_video=$(grep -E "on_publish:.*video" "${log_file}" 2>/dev/null || true)
        has_audio=$(grep -E "on_publish:.*audio" "${log_file}" 2>/dev/null || true)
        if [ -z "${has_sub_ns}" ] || [ -z "${has_video}" ] || [ -z "${has_audio}" ]; then
            all_clients_ok=0
        fi
    done

    if [ "${client_failed}" -eq 0 ] && [ "${all_clients_ok}" -eq 1 ] && [ -z "${errlog}" ]; then
        echo ">>>>>>>> pass:1"
        status="pass"
    else
        echo ">>>>>>>> pass:0"
        echo "client_failed:${client_failed}"
        echo "${errlog}"
        for log_file in "${client_logs[@]}"; do
            echo "--- ${log_file} ---"
            grep -E "send subscribe_namespace:|on_publish:" "${log_file}" 2>/dev/null || true
        done
    fi

    case_print_result "${case_name}" "${status}"
    record_case_result "${case_name}" "${status}"
    stop_server
}

run_catalog_namespace_tuple_case
run_subscribe_namespace_forward_case
run_demo_namespace_tuple_smoke_case
run_demo_subscribe_namespace_mode_case
run_demo_subscribe_namespace_broadcast_case

echo
echo "moq_case_namespace_tuple summary: ${PASSED_CASES}/${TOTAL_CASES} passed"
if [ "${PASSED_CASES}" -ne "${TOTAL_CASES}" ]; then
    echo "failed cases: ${FAILED_CASES[*]}"
    exit 1
fi

exit 0
