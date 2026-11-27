#!/bin/bash

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "demo.hq"
case_test_case "h3_request_delayed_fin" --id native \
    --run h3_request_delayed_fin --timeout 12
case_test_case "demo_client_host_resolved" --id 1720 \
    --run demo_client_host_resolved --timeout 30
case_test_case "demo_client_host_unresolved" --id 1721 \
    --run demo_client_host_unresolved --timeout 30

h3_request_delayed_fin()
{
    local build_dir
    local status=0

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    rm -f test_session tp_localhost xqc_token
    clear_log

    head -c 1000 /dev/zero | tr '\0' x > h3-resource
    case_test_start_server \
        "${CASE_TEST_SERVER_BIN:-${build_dir}/demo/demo_server}" \
        -p "${CASE_TEST_PORT:-8443}" -D "${CASE_TEST_WORK_DIR}" \
        -l d -L slog > /dev/null 2>&1

    # Case 37 sends the request HEADERS, then the FIN alone a second later.
    ${CLIENT_BIN} -G -n 1 -t 3 -l d -x 37 \
        -u https://test.xquic.com/h3-resource > stdlog 2>&1 || status=1

    kill -0 "${CASE_TEST_SERVER_PID}" 2> /dev/null || status=1
    case_test_stop_server
    case_test_snapshot_case_logs h3_request_delayed_fin

    [[ "${status}" -eq 0 ]] || return 1
    grep -q 'alpn:h3' stdlog || return 1
    grep -q 'conn_err:0,' stdlog || return 1
    grep -q 'recv_body_size:1000,.*recv_fin:1,' stdlog || return 1
    grep -q 'recv_fin|' slog || return 1
}

# Run demo_client, with the options given, on one file of demo_server, which
# serves demo-resolve-www, with a 10-second life time. The client saves its
# session ticket, transport parameters and token in the work directory: the
# run starts without them and removes them.
demo_client_resolve_run()
{
    local build_dir status=0

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    rm -rf demo-resolve-www demo-resolve-dl
    mkdir -p demo-resolve-www demo-resolve-dl
    printf 'demo_client resolve test file\n' > demo-resolve-www/f1
    rm -f session_ticket transport_params token
    clear_log
    case_test_start_server \
        "${CASE_TEST_SERVER_BIN:-${build_dir}/demo/demo_server}" \
        -p "${CASE_TEST_PORT:-8443}" \
        -D "${CASE_TEST_WORK_DIR}/demo-resolve-www" \
        -l d -L slog > /dev/null 2>&1
    "${build_dir}/demo/demo_client" -l d -L clog -D demo-resolve-dl -K 10 \
        -A h3 "$@" > stdlog 2>&1 || status=$?
    case_test_stop_server
    rm -f session_ticket transport_params token
    return "${status}"
}

# 1720 happy path: the server name of the URL resolves, and the client
# downloads the file and exits with status 0.
demo_client_host_resolved()
{
    demo_client_resolve_run \
        -U "https://127.0.0.1:${CASE_TEST_PORT:-8443}/f1" || return 1
    cmp -s demo-resolve-www/f1 demo-resolve-dl/f1
}

# 1721 abnormal path: the server name does not resolve, here because the
# client asks for an IPv6 address (-6) of an IPv4 address. The client says
# so and exits with status 1, instead of reading the address that
# getaddrinfo() did not return.
demo_client_host_unresolved()
{
    local status=0

    demo_client_resolve_run -6 \
        -U "https://127.0.0.1:${CASE_TEST_PORT:-8443}/f1" || status=$?
    [[ "${status}" -eq 1 ]] || return 1
    grep -q 'get addr info from hostname' stdlog || return 1
    [[ ! -e demo-resolve-dl/f1 ]]
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
case_test_case "hq_request_delayed_fin" --id 1703 \
    --run hq_request_delayed_fin --timeout 12

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
case_test_run
