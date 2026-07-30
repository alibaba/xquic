#!/bin/bash

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
BUILD_DIR="${REPO_ROOT}/build"
SERVER_BIN="${BUILD_DIR}/tests/test_server"
CLIENT_BIN="${BUILD_DIR}/tests/test_client"

if [ ! -x "${SERVER_BIN}" ] || [ ! -x "${CLIENT_BIN}" ]; then
    echo "missing test binaries; run: cmake --build ${BUILD_DIR} --target test_client test_server"
    exit 1
fi

cd "${BUILD_DIR}" || exit 1

if [ ! -f server.key ] || [ ! -f server.crt ]; then
    openssl req -newkey rsa:2048 -x509 -nodes -keyout server.key -new -out server.crt -subj /CN=test.xquic.com >/dev/null 2>&1
fi

TOTAL=0
PASSED=0
FAILED=()

run_case() {
    local name=$1
    local server_case=$2
    local client_case=$3
    local expect_client_write=$4
    local expect_client_parse=$5
    local expect_server_write=$6
    local expect_server_parse=$7
    local expect_request=$8
    local expect_error=${9:-any}

    TOTAL=$((TOTAL + 1))
    rm -f clog slog stdlog

    "${SERVER_BIN}" -l d -e -x "${server_case}" > /dev/null &
    local server_pid=$!
    sleep 1

    "${CLIENT_BIN}" -s 102400 -l d -t 1 -E -x "${client_case}" > stdlog
    local client_rc=$?

    sleep 1
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true

    local client_write client_parse server_write server_parse request_ok client_error server_error error_seen
    client_write=$(grep -c 'xqc_write_packet_receive_timestamps_into_buf|ts_info_len' clog 2>/dev/null || true)
    client_parse=$(grep -c 'xqc_parse_receive_timestamps_in_ack|report_num:' clog 2>/dev/null || true)
    server_write=$(grep -c 'xqc_write_packet_receive_timestamps_into_buf|ts_info_len' slog 2>/dev/null || true)
    server_parse=$(grep -c 'xqc_parse_receive_timestamps_in_ack|report_num:' slog 2>/dev/null || true)
    request_ok=$(grep -c '>>>>>>>> pass:1' stdlog 2>/dev/null || true)
    client_error=$(grep -c 'conn closing: 8\|conn errno:8' stdlog 2>/dev/null || true)
    server_error=$(grep -c '\[error\].*xqc_conn_tls_transport_params_cb\|TRANSPORT_PARAMETER_ERROR\|MALFORMED_TRANSPORT_PARAM' slog 2>/dev/null || true)
    error_seen=$((client_error + server_error))

    local ok=1
    if [ "${expect_request}" = "pass" ]; then
        if [ "${client_rc}" -ne 0 ] || [ "${request_ok}" -eq 0 ]; then
            ok=0
        fi
    else
        if [ "${request_ok}" -ne 0 ]; then
            ok=0
        fi
    fi
    if [ "${expect_error}" = "gt0" ] && [ "${error_seen}" -le 0 ]; then ok=0; fi
    if [ "${expect_error}" = "eq0" ] && [ "${error_seen}" -ne 0 ]; then ok=0; fi
    if [ "${expect_client_write}" = "gt0" ] && [ "${client_write}" -le 0 ]; then ok=0; fi
    if [ "${expect_client_write}" = "eq0" ] && [ "${client_write}" -ne 0 ]; then ok=0; fi
    if [ "${expect_client_parse}" = "gt0" ] && [ "${client_parse}" -le 0 ]; then ok=0; fi
    if [ "${expect_client_parse}" = "eq0" ] && [ "${client_parse}" -ne 0 ]; then ok=0; fi
    if [ "${expect_server_write}" = "gt0" ] && [ "${server_write}" -le 0 ]; then ok=0; fi
    if [ "${expect_server_write}" = "eq0" ] && [ "${server_write}" -ne 0 ]; then ok=0; fi
    if [ "${expect_server_parse}" = "gt0" ] && [ "${server_parse}" -le 0 ]; then ok=0; fi
    if [ "${expect_server_parse}" = "eq0" ] && [ "${server_parse}" -ne 0 ]; then ok=0; fi

    printf '%-28s client_write=%s client_parse=%s server_write=%s server_parse=%s errors=%s ' \
        "${name}" "${client_write}" "${client_parse}" "${server_write}" "${server_parse}" "${error_seen}"

    if [ "${ok}" -eq 1 ]; then
        PASSED=$((PASSED + 1))
        echo "PASS"
    else
        FAILED+=("${name}")
        echo "FAIL"
        tail -n 20 stdlog 2>/dev/null || true
    fi
}

run_case both_enabled 450 450 gt0 gt0 gt0 gt0 pass eq0
run_case server_only_requests 451 450 gt0 gt0 gt0 gt0 pass eq0
run_case client_only_requests 450 451 gt0 gt0 gt0 gt0 pass eq0
run_case client_zero 450 453 gt0 eq0 eq0 gt0 pass eq0
run_case client_invalid_64 450 452 any any any any fail gt0
run_case server_invalid_64 452 450 any any any any fail gt0

echo "receive-ts e2e: ${PASSED}/${TOTAL} passed"
if [ "${PASSED}" -ne "${TOTAL}" ]; then
    echo "failed cases: ${FAILED[*]}"
    exit 1
fi
