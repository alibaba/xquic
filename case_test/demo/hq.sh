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

# Download <count> files of 32 bytes over one connection with demo_client,
# from demo_server in interop mode, which allows 128 bidirectional streams
# as the client's interop mode also does. Both peers run with -o / -i as
# interop/run_endpoint.sh runs them.
demo_client_stream_limit_run()
{
    local count="$1" alpn="$2" build_dir port i status=0
    local urls=()

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    port="${CASE_TEST_PORT:-8443}"
    rm -rf demo-limit-www demo-limit-dl
    mkdir -p demo-limit-www demo-limit-dl
    for ((i = 1; i <= count; i++)); do
        head -c 32 /dev/urandom > "demo-limit-www/f${i}"
        urls+=("https://127.0.0.1:${port}/f${i}")
    done
    # demo_client resumes from the session_ticket, transport_params and
    # token files that an earlier run left in the work directory. With a
    # ticket of the other ALPN, BabaSSL refuses to build the ClientHello
    # ("inconsistent early data alpn"), so every run starts without them
    # and removes its own.
    rm -f session_ticket transport_params token
    clear_log

    case_test_start_server \
        "${CASE_TEST_SERVER_BIN:-${build_dir}/demo/demo_server}" \
        -p "${port}" -D "${CASE_TEST_WORK_DIR}/demo-limit-www" -i \
        -l d -L slog > /dev/null 2>&1

    "${build_dir}/demo/demo_client" -l d -L clog -D demo-limit-dl -K 15 -o \
        -A "${alpn}" -U "${urls[*]}" > stdlog 2>&1 || status=1

    case_test_stop_server
    rm -f session_ticket transport_params token

    [[ "${status}" -eq 0 ]] || return 1
    ! grep -q 'kill it anyway' stdlog || return 1
    [[ "$(grep -c 'open file\[' stdlog)" -eq "${count}" ]] || return 1
    for ((i = 1; i <= count; i++)); do
        cmp -s "demo-limit-www/f${i}" "demo-limit-dl/f${i}" || return 1
    done
}

# 1707 happy path: 100 requests fit in the stream limit; each completes and
# opens one save file.
demo_client_requests_within_limit()
{
    demo_client_stream_limit_run 100 hq || return 1
    ! grep -q 'req blocked' stdlog
}

# 1708 abnormal path: 300 requests exceed the stream limit (RFC 9000
# Section 4.6), so the client creates 128 and the rest are refused. The
# server's MAX_STREAMS comes after those requests close; the client sends the
# refused requests when it arrives, over hq-interop and over h3, and opens
# one save file per request, none for a refused attempt.
demo_client_requests_beyond_limit()
{
    local alpn

    for alpn in hq h3; do
        demo_client_stream_limit_run 300 "${alpn}" || return 1
        grep -q 'req blocked, will try later' stdlog || return 1
    done
}

hq_request_delayed_fin()
{
    hq_request_transfer 1703 hq_request_delayed_fin 0
}

case_test_case "demo_client_requests_within_limit" --id 1707 \
    --run demo_client_requests_within_limit --timeout 30
case_test_case "demo_client_requests_beyond_limit" --id 1708 \
    --run demo_client_requests_beyond_limit --timeout 60
case_test_case "hq_request_fin" --id 1702 --run hq_request_fin --timeout 12
case_test_case "hq_request_delayed_fin" --id 1703 \
    --run hq_request_delayed_fin --timeout 12

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
case_test_run
