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

# demo_client closes its connection once the response is complete, not 3
# PTOs later when xquic destroys the stream: the CONNECTION_CLOSE comes
# before the stream close timer expires.
demo_client_close_after_response()
{
    local build_dir
    local status=0
    local close_line
    local timer_line

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    rm -rf demo-close-www demo-close-dl
    rm -f session_ticket transport_params token
    mkdir -p demo-close-www demo-close-dl
    head -c 200000 /dev/urandom > demo-close-www/resource
    clear_log

    case_test_start_server \
        "${CASE_TEST_SERVER_BIN:-${build_dir}/demo/demo_server}" \
        -p "${CASE_TEST_PORT:-8443}" -D "${CASE_TEST_WORK_DIR}/demo-close-www" \
        -l d -L slog > /dev/null 2>&1

    "${build_dir}/demo/demo_client" -l d -L clog -D demo-close-dl -K 10 -o \
        -U "https://127.0.0.1:${CASE_TEST_PORT:-8443}/resource" \
        > stdlog 2>&1 || status=1

    case_test_stop_server
    case_test_snapshot_case_logs demo_client_close_after_response
    rm -f session_ticket transport_params token

    [[ "${status}" -eq 0 ]] || return 1
    cmp -s demo-close-www/resource demo-close-dl/resource || return 1
    grep -q 'all tasks are finished' stdlog || return 1

    close_line="$(grep -a -n -m1 '|xqc_conn_close|conn:' clog | cut -d: -f1)"
    timer_line="$(grep -a -n -m1 'xqc_timer_stream_close_timeout|' clog \
        | cut -d: -f1)"
    [[ -n "${close_line}" ]] || return 1
    [[ -z "${timer_line}" || "${close_line}" -lt "${timer_line}" ]]
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
case_test_case "demo_client_close_after_response" --id 1705 \
    --run demo_client_close_after_response --timeout 20

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
case_test_run
