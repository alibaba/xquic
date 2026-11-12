#!/bin/bash

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "demo.hq"

hq_request_transfer()
{
    local id="$1"
    local name="$2"
    local initial_fin="$3"
    local build_dir
    local status=0

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    rm -f test_session tp_localhost xqc_token
    clear_log

    # Serve the request bytes to reuse test_client's complete echo comparison.
    printf 'GET /hq-resource\r\n' > hq-resource
    case_test_start_server \
        "${CASE_TEST_SERVER_BIN:-${build_dir}/demo/demo_server}" \
        -p "${CASE_TEST_PORT:-8443}" -D "${CASE_TEST_WORK_DIR}" \
        -l d -L slog > /dev/null 2>&1

    ${CLIENT_BIN} -T 1 -1 -r hq-resource -E -n 2 -t 1 -F 5 \
        -l d -x "${id}" > stdlog 2>&1 || status=1

    case_test_wait_for_log slog \
        'xqc_destroy_stream.*stream_id:4|' || status=1
    kill -0 "${CASE_TEST_SERVER_PID}" 2> /dev/null || status=1
    case_test_stop_server
    case_test_snapshot_case_logs "${name}"

    [[ "${status}" -eq 0 ]] || return 1
    [[ "$(grep -c '>>>>>>>> pass:1' stdlog)" -eq 2 ]] || return 1
    ! grep -q '>>>>>>>> pass:0\|forced conn_close' stdlog || return 1
    grep -q 'alpn:hq-interop' stdlog || return 1
    grep -q 'conn_err:0,' stdlog || return 1

    local stream_id
    for stream_id in 0 4; do
        grep -q "data_length:18|fin:${initial_fin}|stream_id:${stream_id}|" \
            slog || return 1
        if [[ "${initial_fin}" -eq 0 ]]; then
            grep -q "offset:18|data_length:0|fin:1|stream_id:${stream_id}|" \
                slog || return 1
            grep -q "stream_id:${stream_id}|fin_after_response:0|" \
                stdlog || return 1
        fi
    done
}

hq_request_fin()
{
    hq_request_transfer 1702 hq_request_fin 1
}

hq_request_delayed_fin()
{
    hq_request_transfer 1703 hq_request_delayed_fin 0
}

case_test_case "hq_request_fin" --id 1702 --run hq_request_fin --timeout 12
case_test_case "hq_request_delayed_fin" --id 1703 \
    --run hq_request_delayed_fin --timeout 12

# Download a resource from the demo server, which marks its datagrams ECT(0)
# and reports the codepoints it receives (-3); the client does with
# client_ecn set to -3.
demo_ecn_transfer()
{
    local name="$1"
    local client_ecn="$2"
    local port="${CASE_TEST_PORT:-8443}"
    local build_dir
    local status=0

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    rm -rf test_session tp_localhost xqc_token ecn-downloads
    clear_log
    mkdir -p ecn-downloads
    head -c 100000 /dev/urandom > ecn-resource

    case_test_start_server \
        "${CASE_TEST_SERVER_BIN:-${build_dir}/demo/demo_server}" \
        -p "${port}" -D "${CASE_TEST_WORK_DIR}" -l d -L slog -3 \
        > /dev/null 2>&1

    "${build_dir}/demo/demo_client" -a 127.0.0.1 -p "${port}" -l d -L clog \
        -D ecn-downloads -U "https://127.0.0.1:${port}/ecn-resource" -K 10 \
        -o ${client_ecn} > stdlog 2>&1 || status=1

    kill -0 "${CASE_TEST_SERVER_PID}" 2> /dev/null || status=1
    case_test_stop_server
    case_test_snapshot_case_logs "${name}"

    [[ "${status}" -eq 0 ]] || return 1
    cmp -s ecn-resource ecn-downloads/ecn-resource || return 1
}

# RFC 9000 Section 13.4: both endpoints mark, report and validate ECN.
demo_ecn_validated()
{
    local counts='|ACK_ECN frame ECN counts consumed|type:[0-9a-f]*|ect0:[1-9]'

    demo_ecn_transfer demo_ecn_validated -3 || return 1
    grep -a -q "${counts}" slog || return 1
    grep -a -q "${counts}" clog || return 1
    grep -a -q '|ECN validated|path:0|' slog || return 1
    grep -a -q '|ECN validated|path:0|' clog || return 1
    ! grep -a -q 'ECN validation failed' slog clog
}

# RFC 9000 Section 13.4.2.1: a peer that reports no ECN counts fails the
# validation, and the server stops marking.
demo_ecn_not_reported()
{
    demo_ecn_transfer demo_ecn_not_reported "" || return 1
    grep -a -q '|ECN validation failed|path:0|no ECN counts|' slog || return 1
    ! grep -a -q '|ACK_ECN frame ECN counts consumed|' slog
}

case_test_case "demo_ecn_validated" --id native \
    --run demo_ecn_validated --timeout 20
case_test_case "demo_ecn_not_reported" --id native \
    --run demo_ecn_not_reported --timeout 20
if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
case_test_run
