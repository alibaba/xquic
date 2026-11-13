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

# demo_client fetches /<file> from demo_server over <alpn>, within a
# 10-second life time. It returns 0 when the client exits with status 0
# after its request ended, with an empty response and, over h3, the
# <status> given.
demo_server_no_content_run()
{
    local alpn="$1"
    local file="$2"
    local status="$3"
    local build_dir

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    rm -rf demo-no-content-dl
    mkdir -p demo-no-content-dl
    rm -f session_ticket transport_params token
    clear_log

    "${build_dir}/demo/demo_client" -l d -L clog -D demo-no-content-dl \
        -K 10 -A "${alpn}" \
        -U "https://127.0.0.1:${CASE_TEST_PORT:-8443}/${file}" \
        > stdlog 2>&1 || return 1
    grep -q 'all tasks are finished' stdlog || return 1
    ! grep -q 'kill it anyway' stdlog || return 1
    [[ -f "demo-no-content-dl/${file}" ]] || return 1
    [[ ! -s "demo-no-content-dl/${file}" ]] || return 1
    if [[ "${alpn}" = h3 ]]; then
        grep -q "^:status = ${status}$" stdlog || return 1
    fi
}

demo_server_no_content_start()
{
    local build_dir

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    rm -rf demo-no-content-www
    mkdir -p demo-no-content-www
    : > demo-no-content-www/empty
    case_test_start_server \
        "${CASE_TEST_SERVER_BIN:-${build_dir}/demo/demo_server}" \
        -p "${CASE_TEST_PORT:-8443}" \
        -D "${CASE_TEST_WORK_DIR}/demo-no-content-www" \
        -l d -L slog > /dev/null 2>&1
}

# 1715 happy path: demo_server ends the response of an empty file, over h3
# with the headers, status 200, and over hq-interop with a FIN.
demo_server_empty_file()
{
    local status=0

    demo_server_no_content_start
    demo_server_no_content_run h3 empty 200 || status=1
    demo_server_no_content_run hq-interop empty || status=1
    case_test_stop_server
    case_test_snapshot_case_logs demo_server_empty_file
    rm -f session_ticket transport_params token
    return "${status}"
}

# 1716 abnormal path: demo_server answers a request for a missing file over
# h3 with status 404, and over hq-interop, which has no status, with an
# empty response.
demo_server_missing_file()
{
    local status=0

    demo_server_no_content_start
    demo_server_no_content_run h3 missing 404 || status=1
    demo_server_no_content_run hq-interop missing || status=1
    case_test_stop_server
    case_test_snapshot_case_logs demo_server_missing_file
    rm -f session_ticket transport_params token
    return "${status}"
}

case_test_case "hq_request_fin" --id 1702 --run hq_request_fin --timeout 12
case_test_case "hq_request_delayed_fin" --id 1703 \
    --run hq_request_delayed_fin --timeout 12
case_test_case "demo_server_empty_file" --id 1715 \
    --run demo_server_empty_file --timeout 40
case_test_case "demo_server_missing_file" --id 1716 \
    --run demo_server_missing_file --timeout 40

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
case_test_run
