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

# Serve one file with demo_server. demo_client saves its session ticket,
# transport parameters and token in the work directory and resumes from
# them, so the cases start without them and remove their own.
demo_client_connect_start()
{
    local build_dir

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    rm -rf demo-connect-www
    mkdir -p demo-connect-www
    head -c 32 /dev/urandom > demo-connect-www/f1
    rm -f session_ticket transport_params token
    case_test_start_server \
        "${CASE_TEST_SERVER_BIN:-${build_dir}/demo/demo_server}" \
        -p "${CASE_TEST_PORT:-8443}" \
        -D "${CASE_TEST_WORK_DIR}/demo-connect-www" \
        -l d -L slog > /dev/null 2>&1
}

demo_client_connect_stop()
{
    case_test_stop_server
    rm -f session_ticket transport_params token
}

# Download the file with demo_client over <alpn>, with a 10-second life
# time. The client either downloads it and exits with status 0, or, when
# its connection cannot be created, exits at once with status 1.
demo_client_connect_run()
{
    local alpn="$1" build_dir start status=0

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    rm -rf demo-connect-dl
    mkdir -p demo-connect-dl
    clear_log
    start="${SECONDS}"
    "${build_dir}/demo/demo_client" -l d -L clog -D demo-connect-dl -K 10 \
        -A "${alpn}" -U "https://127.0.0.1:${CASE_TEST_PORT:-8443}/f1" \
        > stdlog 2>&1 || status=$?

    ! grep -q 'kill it anyway' stdlog || return 1
    if grep -Fq '|xqc_demo_cli_start FAILED|' stdlog; then
        [[ "${status}" -eq 1 && $((SECONDS - start)) -lt 5 ]] \
            && [[ ! -e demo-connect-dl/f1 ]]
    else
        [[ "${status}" -eq 0 ]] \
            && cmp -s demo-connect-www/f1 demo-connect-dl/f1
    fi
}

# 1709 happy path: the client creates its connection over h3, downloads the
# file and exits with status 0.
demo_client_connect_ok()
{
    local status=0

    demo_client_connect_start
    demo_client_connect_run h3 || status=1
    ! grep -Fq '|xqc_demo_cli_start FAILED|' stdlog || status=1
    demo_client_connect_stop
    return "${status}"
}

# 1710 abnormal path: the client resumes the hq-interop session ticket of its
# first run over h3. BabaSSL refuses to build that ClientHello ("inconsistent
# early data alpn"), and the connection cannot be created: the client exits
# at once with status 1 instead of waiting for its life time to end.
# BoringSSL leaves early data out of that ClientHello and the download
# completes.
demo_client_connect_refused()
{
    local status=0

    demo_client_connect_start
    demo_client_connect_run hq || status=1
    ! grep -Fq '|xqc_demo_cli_start FAILED|' stdlog || status=1
    demo_client_connect_run h3 || status=1
    demo_client_connect_stop
    return "${status}"
}

case_test_case "demo_client_connect_ok" --id 1709 \
    --run demo_client_connect_ok --timeout 30
case_test_case "demo_client_connect_refused" --id 1710 \
    --run demo_client_connect_refused --timeout 30
case_test_case "hq_request_fin" --id 1702 --run hq_request_fin --timeout 12
case_test_case "hq_request_delayed_fin" --id 1703 \
    --run hq_request_delayed_fin --timeout 12

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
case_test_run
