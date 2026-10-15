#!/bin/bash
# Exercise the shipped C demos; no external echo server is required.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "webtransport.demo"

wt_demo_start()
{
    case_test_stop_server
    local binary="$(case_test_build_dir "${ROOT_DIR}")/demo/demo_server"
    "${binary}" -W -p "${CASE_TEST_PORT:-8443}" -l e -D . \
        -L slog > svr_stdlog 2>&1 &
    CASE_TEST_SERVER_PID="$!"
    sleep 0.2
    kill -0 "${CASE_TEST_SERVER_PID}"
}

wt_demo_client()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/demo/demo_client"
    "${binary}" -a 127.0.0.1 -p "${CASE_TEST_PORT:-8443}" -l e \
        -L clog -K 10 "$@" > stdlog 2>&1
}

case_webtransport_demo_raw()
{
    wt_demo_start || return 1
    wt_demo_client -W || return 1
    grep -Fq 'WT PASS: bidi exact echo + FIN, datagram, close' stdlog
}

case_webtransport_demo_msg()
{
    local len
    wt_demo_start || return 1
    for len in 1 63 64 16383 16384 1048576 16777216; do
        wt_demo_client -W -H "${len}" || { cat stdlog; return 1; }
        grep -Fq "WT message verified: type=text bytes=${len}" stdlog \
            || return 1
        grep -Fq 'WT PASS: exact framed message echo, close' stdlog \
            || return 1
        cp stdlog "message-${len}.log"
    done
}

case_webtransport_demo_reject_origin()
{
    wt_demo_start || return 1
    if wt_demo_client -W -j https://untrusted.invalid; then
        return 1
    fi
    grep -Fq 'WT closed: ready=0 status=403' stdlog
}

case_webtransport_demo_reject_path()
{
    wt_demo_start || return 1
    if wt_demo_client -W \
        -U "https://127.0.0.1:${CASE_TEST_PORT:-8443}/other"
    then
        return 1
    fi
    grep -Fq 'WT closed: ready=0 status=403' stdlog
}

case_webtransport_demo_msg_args()
{
    local len
    for len in 0 -1 invalid 16777217 18446744073709551616; do
        if wt_demo_client -W -H "${len}"; then
            return 1
        fi
        grep -Fq 'invalid WebTransport message length' stdlog || return 1
    done
    if wt_demo_client -H 1; then
        return 1
    fi
    grep -Fq -- '-H requires -W' stdlog
}

case_webtransport_demo_http3()
{
    wt_demo_start || return 1
    printf 'HTTP/3 alongside WebTransport\n' > source.txt
    mkdir -p received
    wt_demo_client -A h3 -D ./received \
        -U "https://127.0.0.1:${CASE_TEST_PORT:-8443}/source.txt" || return 1
    cmp source.txt received/source.txt
}

case_test_case "webtransport_demo_raw" --id native \
    --run case_webtransport_demo_raw
case_test_case "webtransport_demo_msg" --id native \
    --run case_webtransport_demo_msg
case_test_case "webtransport_demo_reject_origin" --id native \
    --run case_webtransport_demo_reject_origin
case_test_case "webtransport_demo_reject_path" --id native \
    --run case_webtransport_demo_reject_path
case_test_case "webtransport_demo_msg_args" --id native \
    --run case_webtransport_demo_msg_args
case_test_case "webtransport_demo_http3" --id native \
    --run case_webtransport_demo_http3

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
case_test_run
