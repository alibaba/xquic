#!/bin/bash

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "demo.hq"

# 1706: demo_client downloads over IPv6. Datagrams arrive in bursts, and
# each one must reach the engine as sent: none may be dropped as unparsable,
# and the file must arrive whole.
demo_client_ipv6_download()
{
    local build_dir
    local port="${CASE_TEST_PORT:-8443}"
    local status=0

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    rm -f test_session tp_localhost xqc_token session_ticket
    rm -rf ipv6-downloads
    mkdir -p ipv6-downloads
    clear_log
    head -c 4194304 /dev/urandom > ipv6-resource

    case_test_start_server \
        "${CASE_TEST_SERVER_BIN:-${build_dir}/demo/demo_server}" \
        -p "${port}" -D "${CASE_TEST_WORK_DIR}" -l d -L slog \
        > /dev/null 2>&1

    "${build_dir}/demo/demo_client" \
        -a ::1 -p "${port}" -U "https://localhost:${port}/ipv6-resource" \
        -D ipv6-downloads -l d -L clog -K 10 -o > stdlog 2>&1 || status=1
    case_test_stop_server
    case_test_snapshot_case_logs demo_client_ipv6_download

    grep -q 'addr: ::1:' stdlog || status=1
    cmp -s ipv6-resource ipv6-downloads/ipv6-resource || status=1
    ! grep -a -q 'fail to parse cid' clog || status=1
    rm -rf ipv6-resource ipv6-downloads
    [[ "${status}" -eq 0 ]]
}

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
case_test_case "demo_client_ipv6_download" --id 1706 \
    --run demo_client_ipv6_download --timeout 20
case_test_case "hq_request_delayed_fin" --id 1703 \
    --run hq_request_delayed_fin --timeout 12

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
case_test_run
