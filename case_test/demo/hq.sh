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

# Wait up to 3 seconds for the server to exit, with status <expected> when
# it is given.
demo_server_wait_exit()
{
    local expected="${1:-}"
    local attempt=0
    local exit_status

    while [[ "${attempt}" -lt 30 ]] \
        && kill -0 "${CASE_TEST_SERVER_PID}" 2> /dev/null; do
        sleep 0.1
        attempt=$((attempt + 1))
    done
    if kill -0 "${CASE_TEST_SERVER_PID}" 2> /dev/null; then
        echo "demo_server still runs 3 seconds after SIGTERM"
        case_test_stop_server
        return 1
    fi

    wait "${CASE_TEST_SERVER_PID}"
    exit_status="$?"
    CASE_TEST_SERVER_PID=""
    echo "demo_server exit status: ${exit_status}"
    [[ -z "${expected}" || "${exit_status}" -eq "${expected}" ]]
}

# 1711 happy path: SIGTERM ends the event loop of a demo_server that has
# served a request, and it exits with status 0.
demo_server_sigterm()
{
    local build_dir
    local status=0

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    rm -rf demo-sigterm-www demo-sigterm-dl
    mkdir -p demo-sigterm-www demo-sigterm-dl
    head -c 1000 /dev/urandom > demo-sigterm-www/resource
    rm -f session_ticket transport_params token
    clear_log

    case_test_start_server \
        "${CASE_TEST_SERVER_BIN:-${build_dir}/demo/demo_server}" \
        -p "${CASE_TEST_PORT:-8443}" \
        -D "${CASE_TEST_WORK_DIR}/demo-sigterm-www" \
        -l d -L slog > svr_stdlog 2>&1

    "${build_dir}/demo/demo_client" -l d -L clog -D demo-sigterm-dl -K 10 \
        -U "https://127.0.0.1:${CASE_TEST_PORT:-8443}/resource" \
        > stdlog 2>&1 || status=1
    cmp -s demo-sigterm-www/resource demo-sigterm-dl/resource || status=1

    kill -TERM "${CASE_TEST_SERVER_PID}"
    demo_server_wait_exit 0 || status=1
    case_test_snapshot_case_logs demo_server_sigterm
    rm -f session_ticket transport_params token

    [[ "${status}" -eq 0 ]]
}

# 1712 abnormal path: a SIGTERM that comes while demo_server starts, here
# while it opens its log, a FIFO that nothing reads yet, stops it too
# instead of being lost.
demo_server_sigterm_at_start()
{
    local build_dir
    local reader
    local status=0

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    rm -f demo-sigterm.fifo
    mkfifo demo-sigterm.fifo
    clear_log

    case_test_start_server \
        "${CASE_TEST_SERVER_BIN:-${build_dir}/demo/demo_server}" \
        -p "${CASE_TEST_PORT:-8443}" -L demo-sigterm.fifo \
        > svr_stdlog 2>&1
    case_test_wait_for_log svr_stdlog 'option log directory' || status=1

    kill -TERM "${CASE_TEST_SERVER_PID}"
    # a server that is still running opens its log and serves
    cat demo-sigterm.fifo > slog &
    reader="$!"
    demo_server_wait_exit || status=1
    kill "${reader}" 2> /dev/null
    wait "${reader}" 2> /dev/null
    rm -f demo-sigterm.fifo
    case_test_snapshot_case_logs demo_server_sigterm_at_start

    [[ "${status}" -eq 0 ]]
}

case_test_case "hq_request_fin" --id 1702 --run hq_request_fin --timeout 12
case_test_case "hq_request_delayed_fin" --id 1703 \
    --run hq_request_delayed_fin --timeout 12
case_test_case "demo_server_sigterm" --id 1711 \
    --run demo_server_sigterm --timeout 20
case_test_case "demo_server_sigterm_at_start" --id 1712 \
    --run demo_server_sigterm_at_start --timeout 20

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
case_test_run
