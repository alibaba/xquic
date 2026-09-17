#!/bin/bash

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "webtransport.core"

wt_case_run()
{
    local id="$1"
    local name="$2"
    local draft="$3"
    local peer_pattern="$4"
    local build_dir
    local case_args=()
    local status=0
    shift 4

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    if [[ "${id}" -ne 0 ]]; then
        case_args=(-X "${id}")
    fi
    rm -f session_ticket transport_params token
    clear_log

    CASE_TEST_SERVER_WAIT=0 case_test_start_server \
        "${CASE_TEST_SERVER_BIN:-${build_dir}/demo/demo_server}" \
        -W -v "${draft}" "${case_args[@]}" -p "${CASE_TEST_PORT}" \
        -K server.key -T server.crt -l d -L slog -k skeys.log \
        > svr_stdlog 2>&1
    if ! case_test_wait_for_log svr_stdlog \
        'WebTransport maximum draft' 40 0.025
    then
        case_test_stop_server
        case_test_snapshot_case_logs "${name}"
        return 1
    fi

    WT_CASE_CLIENT_STATUS=0
    "${CASE_TEST_CLIENT_BIN:-${build_dir}/demo/demo_client}" \
        -W -v "${draft}" "${case_args[@]}" -a 127.0.0.1 \
        -J server.crt \
        -U "https://test.xquic.com:${CASE_TEST_PORT}/wt" \
        -l d -L clog -k ckeys.log "$@" > stdlog 2>&1 \
        || WT_CASE_CLIENT_STATUS="$?"

    case_test_wait_for_log svr_stdlog "${peer_pattern}" 40 0.025 \
        || status=1
    kill -0 "${CASE_TEST_SERVER_PID}" 2> /dev/null || status=1
    case_test_stop_server
    case_test_snapshot_case_logs "${name}"

    [[ "${status}" -eq 0 ]] || return 1
    grep -q '^WT handshake complete$' svr_stdlog
}

wt_case_success()
{
    local draft="${1:-16}"

    [[ "${WT_CASE_CLIENT_STATUS}" -eq 0 ]] || return 1
    grep -q "^WT ready: draft=${draft} status=200$" stdlog || return 1
    grep -q '^WT PASS:' stdlog || return 1
    grep -q '^WT closed: ready=1 status=200 code=0$' stdlog || return 1
    ! grep -q '^WT FAIL:' stdlog
}

wt_case_error()
{
    local error="$1"

    [[ "${WT_CASE_CLIENT_STATUS}" -eq 1 ]] || return 1
    grep -q '^WT ready: draft=16 status=200$' stdlog || return 1
    grep -Eq "^WT (closed:.* code=${error}|FAIL:.* error=${error})$" \
        stdlog || return 1
    ! grep -q '^WT PASS:' stdlog
}

wt_draft07_1m()
{
    wt_case_run 1801 wt_draft07_1m 7 '^WT closed: code=0$' || return 1
    wt_case_success 7 || return 1
    grep -q '^WT bidi verified: bytes=1048576 fin=1$' stdlog || return 1
    grep -q '^WT transfer: sent=1048576 received=1048576$' stdlog
}

wt_draft16_1m()
{
    wt_case_run 1802 wt_draft16_1m 16 '^WT closed: code=0$' || return 1
    wt_case_success || return 1
    grep -q '^WT bidi verified: bytes=1048576 fin=1$' stdlog || return 1
    grep -q '^WT transfer: sent=1048576 received=1048576$' stdlog
}

# draft-ietf-webtrans-http3-16 Section 3.2: extended CONNECT admission.
wt_connect_accepted()
{
    wt_case_run 1803 wt_connect_accepted 16 '^WT closed: code=0$' || return 1
    wt_case_success || return 1
    grep -q '^WT ready: draft=16 session=' svr_stdlog
}

wt_connect_rejected()
{
    wt_case_run 1804 wt_connect_rejected 16 \
        '^WT reject: path=1 allowed_origin=0 origin_count=1$' \
        -j http://127.0.0.1:8081 || return 1
    [[ "${WT_CASE_CLIENT_STATUS}" -eq 1 ]] || return 1
    grep -q '^WT closed: ready=0 status=403 ' stdlog || return 1
    ! grep -q '^WT ready:\|^WT PASS:' stdlog || return 1
    ! grep -q '^WT ready:' svr_stdlog
}

# draft-ietf-webtrans-http3-16 Sections 4, 4.3, 4.4: bidi ID and reset.
# reliable-stream-reset-09 Section 4: preserve the reliable stream prefix.
wt_bidi_session_id()
{
    wt_case_run 1805 wt_bidi_session_id 16 \
        '^WT case reset: reliable=3 error=91141958510854$' || return 1
    wt_case_success || return 1
    grep -q '^WT bidi verified:.* fin=1$' stdlog
}

wt_bidi_invalid_session_id()
{
    wt_case_run 1806 wt_bidi_invalid_session_id 16 \
        '^WT case connection: error=264$' || return 1
    wt_case_error 264
}

# draft-ietf-webtrans-http3-16 Sections 4, 4.2: uni stream association.
wt_uni_session_id()
{
    wt_case_run 1807 wt_uni_session_id 16 \
        '^WT case uni: bytes=15 fin=1 match=1$' || return 1
    wt_case_success
}

wt_uni_invalid_session_id()
{
    wt_case_run 1808 wt_uni_invalid_session_id 16 \
        '^WT case connection: error=264$' || return 1
    wt_case_error 264
}

# draft-ietf-webtrans-http3-16 Sections 4.5, 4.6: datagram association.
wt_datagram_session_id()
{
    wt_case_run 1809 wt_datagram_session_id 16 \
        '^WT datagram echo: bytes=15 result=0$' || return 1
    wt_case_success || return 1
    grep -q '^WT datagram verified: bytes=15$' stdlog
}

wt_datagram_unknown_session()
{
    wt_case_run 1810 wt_datagram_unknown_session 16 \
        '^WT case datagram unknown: received=1 delivered=0 buffered=0$' \
        || return 1
    wt_case_success || return 1
    grep -q '^WT datagram verified: bytes=15$' stdlog
}

# draft-ietf-webtrans-http3-16 Section 6: close capsule and UTF-8 reason.
wt_close_capsule()
{
    wt_case_run 1811 wt_close_capsule 16 \
        '^WT case close: code=0 reason_len=13 match=1$' || return 1
    wt_case_success || return 1
    grep -q '^WT close sent$' stdlog
}

wt_close_bad_utf8()
{
    wt_case_run 1812 wt_close_bad_utf8 16 '^WT closed: code=270$' || return 1
    wt_case_error 270
}

# draft-ietf-webtrans-http3-16 Section 4.7: empty DRAIN_WEBTRANSPORT_SESSION.
wt_drain_capsule()
{
    wt_case_run 1813 wt_drain_capsule 16 '^WT draining$' || return 1
    wt_case_success
}

wt_drain_bad_length()
{
    wt_case_run 1814 wt_drain_bad_length 16 '^WT closed: code=270$' || return 1
    wt_case_error 270
}

# draft-ietf-webtrans-http3-16 Section 5.1: one-session connection limit.
wt_single_session()
{
    wt_case_run 1815 wt_single_session 16 '^WT closed: code=0$' || return 1
    wt_case_success || return 1
    [[ "$(grep -c '^WT ready: draft=16 session=' svr_stdlog)" -eq 1 ]]
}

wt_second_session_rejected()
{
    wt_case_run 1816 wt_second_session_rejected 16 \
        '^WT case connection: error=0$' || return 1
    [[ "${WT_CASE_CLIENT_STATUS}" -eq 1 ]] || return 1
    grep -q '^WT ready: draft=16 status=200$' stdlog || return 1
    grep -q '^WT case second CONNECT sent: session=4$' stdlog || return 1
    grep -q '^WT closed: ready=1 status=0 code=267$' stdlog || return 1
    ! grep -q '^WT PASS:' stdlog || return 1
    [[ "$(grep -c '^WT ready: draft=16 session=' svr_stdlog)" -eq 1 ]] \
        || return 1
    grep -Fq 'xqc_write_reset_stream_to_packet|stream_id:4|' slog || return 1
    grep -Eq 'xqc_parse_(reset_stream|stop_sending)_frame\|type:[34]\|stream_id:4\|err_code:267\|' \
        clog
}

wt_message_framing()
{
    wt_case_run 0 wt_message_framing 16 \
        '^WT closed: code=0$' -H 5 -g || return 1
    wt_case_success || return 1
    grep -q '^WT message queued: type=text bytes=5 fill=d$' stdlog \
        || return 1
    grep -q '^WT recv message text: id=[0-9]* bytes=5 data="ddddd"$' \
        stdlog || return 1
    grep -q '^WT message verified: type=text bytes=5$' stdlog
}

wt_message_length_rejected()
{
    local build_dir
    local status=0

    wt_case_run 1834 wt_message_length_rejected 16 \
        '^WT case message oversized: declared=6 bytes=3 fin=1$' \
        -H 5 -g || return 1
    [[ "${WT_CASE_CLIENT_STATUS}" -eq 1 ]] || return 1
    grep -q '^WT ready: draft=16 status=200$' stdlog || return 1
    grep -q '^WT message queued: type=text bytes=5 fill=d$' stdlog \
        || return 1
    grep -q '^WT FAIL: message parse error=-613$' stdlog || return 1
    ! grep -q '^WT PASS:' stdlog || return 1

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    "${CASE_TEST_CLIENT_BIN:-${build_dir}/demo/demo_client}" \
        -W -v 16 -H 16777217 > length_stdlog 2>&1 || status="$?"
    [[ "${status}" -ne 0 ]] || return 1
    grep -q '^WT message length must be an integer from 1 through 16777216$' \
        length_stdlog
}


case_test_case "wt_draft07_1m" --id 1801 --run wt_draft07_1m --timeout 15
case_test_case "wt_draft16_1m" --id 1802 --run wt_draft16_1m --timeout 15
case_test_case "wt_connect_accepted" --id 1803 \
    --run wt_connect_accepted --timeout 15
case_test_case "wt_connect_rejected" --id 1804 \
    --run wt_connect_rejected --timeout 15
case_test_case "wt_bidi_session_id" --id 1805 \
    --run wt_bidi_session_id --timeout 15
case_test_case "wt_bidi_invalid_session_id" --id 1806 \
    --run wt_bidi_invalid_session_id --timeout 15
case_test_case "wt_uni_session_id" --id 1807 \
    --run wt_uni_session_id --timeout 15
case_test_case "wt_uni_invalid_session_id" --id 1808 \
    --run wt_uni_invalid_session_id --timeout 15
case_test_case "wt_datagram_session_id" --id 1809 \
    --run wt_datagram_session_id --timeout 15
case_test_case "wt_datagram_unknown_session" --id 1810 \
    --run wt_datagram_unknown_session --timeout 15
case_test_case "wt_close_capsule" --id 1811 \
    --run wt_close_capsule --timeout 15
case_test_case "wt_close_bad_utf8" --id 1812 \
    --run wt_close_bad_utf8 --timeout 15
case_test_case "wt_drain_capsule" --id 1813 \
    --run wt_drain_capsule --timeout 15
case_test_case "wt_drain_bad_length" --id 1814 \
    --run wt_drain_bad_length --timeout 15
case_test_case "wt_single_session" --id 1815 \
    --run wt_single_session --timeout 15
case_test_case "wt_second_session_rejected" --id 1816 \
    --run wt_second_session_rejected --timeout 15
case_test_case "wt_message_framing" --id 1833 \
    --run wt_message_framing --timeout 15
case_test_case "wt_message_length_rejected" --id 1834 \
    --run wt_message_length_rejected --timeout 15

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
case_test_run
