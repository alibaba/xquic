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

# demo_client fetches 3 files from demo_server over <alpn>, with the
# request options that follow, within a 10-second life time. It returns 0
# when the client exits with status 0 after finishing its task, and, with
# <check_files> set, when every file arrived whole.
demo_client_delayed_run()
{
    local alpn="$1"
    local check_files="$2"
    local build_dir
    local url="https://127.0.0.1:${CASE_TEST_PORT:-8443}"
    local file

    shift 2
    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    rm -rf demo-delayed-dl
    mkdir -p demo-delayed-dl
    rm -f session_ticket transport_params token
    clear_log

    "${build_dir}/demo/demo_client" -l d -L clog -D demo-delayed-dl -K 10 \
        -A "${alpn}" "$@" -U "${url}/f1 ${url}/f2 ${url}/f3" \
        > stdlog 2>&1 || return 1
    grep -q 'all tasks are finished' stdlog || return 1
    ! grep -q 'kill it anyway' stdlog || return 1
    if [[ -n "${check_files}" ]]; then
        for file in f1 f2 f3; do
            cmp -s "demo-delayed-www/${file}" "demo-delayed-dl/${file}" \
                || return 1
        done
    fi
}

demo_client_delayed_start()
{
    local build_dir

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    rm -rf demo-delayed-www
    mkdir -p demo-delayed-www
    head -c 5000 /dev/urandom > demo-delayed-www/f1
    head -c 5000 /dev/urandom > demo-delayed-www/f2
    head -c 5000 /dev/urandom > demo-delayed-www/f3
    case_test_start_server \
        "${CASE_TEST_SERVER_BIN:-${build_dir}/demo/demo_server}" \
        -p "${CASE_TEST_PORT:-8443}" \
        -D "${CASE_TEST_WORK_DIR}/demo-delayed-www" \
        -l d -L slog > /dev/null 2>&1
}

# 1713 happy path: demo_client waits 100 ms (-w), then sends its 3
# requests at once, over h3 and over hq-interop.
demo_client_delayed_requests()
{
    local status=0

    demo_client_delayed_start
    demo_client_delayed_run h3 1 -w 100 || status=1
    demo_client_delayed_run hq-interop 1 -w 100 || status=1
    case_test_stop_server
    case_test_snapshot_case_logs demo_client_delayed_requests
    rm -f session_ticket transport_params token
    return "${status}"
}

# 1714 abnormal path: demo_client waits 100 ms, then sends one request per
# batch (-r 1) with 100 ms between batches (-I). Over h3, it sent only the
# first batch and waited for its life time to end; over hq-interop, it
# crashed when the first request closed. hq-interop checks the exit only:
# a request that a stream close and an idle gap both send goes twice.
demo_client_delayed_batches()
{
    local status=0

    demo_client_delayed_start
    demo_client_delayed_run h3 1 -w 100 -r 1 -I 100 || status=1
    demo_client_delayed_run hq-interop "" -w 100 -r 1 -I 100 || status=1
    case_test_stop_server
    case_test_snapshot_case_logs demo_client_delayed_batches
    rm -f session_ticket transport_params token
    return "${status}"
}

case_test_case "hq_request_fin" --id 1702 --run hq_request_fin --timeout 12
case_test_case "hq_request_delayed_fin" --id 1703 \
    --run hq_request_delayed_fin --timeout 12
case_test_case "demo_client_delayed_requests" --id 1713 \
    --run demo_client_delayed_requests --timeout 40
case_test_case "demo_client_delayed_batches" --id 1714 \
    --run demo_client_delayed_batches --timeout 40

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
case_test_run
