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
    local status=0
    shift 4

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    rm -f session_ticket transport_params token
    clear_log

    CASE_TEST_SERVER_WAIT=0 case_test_start_server \
        "${CASE_TEST_SERVER_BIN:-${build_dir}/demo/demo_server}" \
        -W -v "${draft}" -X "${id}" -p "${CASE_TEST_PORT}" \
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
        -W -v "${draft}" -X "${id}" -a 127.0.0.1 -J server.crt \
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

wt_interop_prepare()
{
    local name="$1"

    mkdir -p "${CASE_TEST_WORK_DIR}/case-logs/${name}" || return 1
    WT_INTEROP_DIR="$(mktemp -d \
        "${CASE_TEST_WORK_DIR}/case-logs/${name}/interop.XXXXXX")" || return 1
    mkdir -p "${WT_INTEROP_DIR}/server-www/wt" \
        "${WT_INTEROP_DIR}/server-downloads" \
        "${WT_INTEROP_DIR}/client-downloads" || return 1
    WT_INTEROP_CLIENT_CASE=handshake
    WT_INTEROP_SERVER_CASE=handshake
    WT_INTEROP_CLIENT_PROTOCOLS='client-only first second'
    WT_INTEROP_SERVER_PROTOCOLS='second first server-only'
    WT_INTEROP_HOST=test.xquic.com
    WT_INTEROP_CA="${PWD}/server.crt"
    WT_INTEROP_REQUESTS="https://${WT_INTEROP_HOST}:${CASE_TEST_PORT}/wt"
    rm -f session_ticket transport_params token
    clear_log
}

wt_interop_run()
{
    local name="$1"
    local peer_pattern="${2:-}"
    local build_dir
    local status=0

    build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    CASE_TEST_SERVER_WAIT=0 case_test_start_server env ROLE=server \
        TESTCASE="${WT_INTEROP_SERVER_CASE}" \
        PROTOCOLS="${WT_INTEROP_SERVER_PROTOCOLS}" \
        XQC_WT_WWW="${WT_INTEROP_DIR}/server-www" \
        XQC_WT_DOWNLOADS="${WT_INTEROP_DIR}/server-downloads" \
        "${build_dir}/demo/wt_interop_server" \
        -W -v 16 -p "${CASE_TEST_PORT}" -K server.key -T server.crt \
        -l d -L slog -k skeys.log > svr_stdlog 2>&1
    if ! case_test_wait_for_log svr_stdlog \
        'WebTransport maximum draft' 40 0.025
    then
        case_test_stop_server
        case_test_snapshot_case_logs "${name}"
        return 1
    fi

    WT_INTEROP_CLIENT_STATUS=0
    env ROLE=client TESTCASE="${WT_INTEROP_CLIENT_CASE}" \
        PROTOCOLS="${WT_INTEROP_CLIENT_PROTOCOLS}" \
        REQUESTS="${WT_INTEROP_REQUESTS}" \
        XQC_WT_DOWNLOADS="${WT_INTEROP_DIR}/client-downloads" \
        "${build_dir}/demo/wt_interop_client" -W -v 16 -a 127.0.0.1 \
        -U "https://${WT_INTEROP_HOST}:${CASE_TEST_PORT}/wt" \
        -J "${WT_INTEROP_CA}" -K 10 -l d -L clog -k ckeys.log \
        > stdlog 2>&1 || WT_INTEROP_CLIENT_STATUS="$?"

    if [[ -n "${peer_pattern}" ]]; then
        case_test_wait_for_log svr_stdlog "${peer_pattern}" 40 0.025 \
            || status=1
    fi
    kill -0 "${CASE_TEST_SERVER_PID}" 2> /dev/null || status=1
    case_test_stop_server
    case_test_snapshot_case_logs "${name}"
    return "${status}"
}

wt_interop_ready()
{
    local log

    for log in stdlog svr_stdlog; do
        [[ "$(grep -c '^WT handshake complete$' "${log}")" -eq 1 ]] \
            || return 1
        grep -q '^WT ready: draft=16 status=200 endpoint=/wt$' "${log}" \
            || return 1
    done
}

# draft-ietf-webtrans-http3-16 Section 3.3: client protocol preference.
wt_interop_handshake()
{
    local role
    local name=wt_interop_handshake

    wt_interop_prepare "${name}" || return 1
    wt_interop_run "${name}" '^WT closed: status=200 code=0$' || return 1
    [[ "${WT_INTEROP_CLIENT_STATUS}" -eq 0 ]] || return 1
    wt_interop_ready || return 1
    printf '%s' first > "${WT_INTEROP_DIR}/expected-protocol.txt"
    for role in client server; do
        cmp "${WT_INTEROP_DIR}/expected-protocol.txt" \
            "${WT_INTEROP_DIR}/${role}-downloads/negotiated_protocol.txt" \
            || return 1
    done
    grep -q '^WT INTEROP PASS: case=handshake files=0 all_fin=1$' stdlog \
        || return 1
    ! grep -q '^WT INTEROP FAIL:' stdlog svr_stdlog
}

wt_interop_protocol_rejected()
{
    local name=wt_interop_protocol_rejected

    wt_interop_prepare "${name}" || return 1
    WT_INTEROP_CLIENT_PROTOCOLS=client-only
    WT_INTEROP_SERVER_PROTOCOLS=server-only
    wt_interop_run "${name}" || return 1
    [[ "${WT_INTEROP_CLIENT_STATUS}" -eq 1 ]] || return 1
    grep -q '^WT closed: status=403 ' stdlog || return 1
    ! grep -q '^WT ready:\|^WT INTEROP PASS:' stdlog svr_stdlog || return 1
    [[ ! -e "${WT_INTEROP_DIR}/client-downloads/negotiated_protocol.txt" \
        && ! -e "${WT_INTEROP_DIR}/server-downloads/negotiated_protocol.txt" ]]
}

wt_interop_transfer_prepare()
{
    WT_INTEROP_CLIENT_CASE=transfer-unidirectional-receive
    WT_INTEROP_SERVER_CASE=transfer
    WT_INTEROP_CLIENT_PROTOCOLS=files
    WT_INTEROP_SERVER_PROTOCOLS=files
}

# quic-interop-runner/webtransport.md: GET ends at FIN, PUSH at LF + body.
wt_interop_ur()
{
    local name=wt_interop_ur
    local index=0
    local size
    local file
    local log

    wt_interop_prepare "${name}" || return 1
    wt_interop_transfer_prepare
    python3 - "${WT_INTEROP_DIR}/server-www/wt" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for index, size in enumerate((102400, 512000, 256000, 1048576, 2097152)):
    block = bytes((value + index) % 256 for value in range(256))
    (root / f"file-{index}.bin").write_bytes(block * (size // len(block)))
PY
    [[ "$?" -eq 0 ]] || return 1
    WT_INTEROP_REQUESTS=''
    for index in 0 1 2 3 4; do
        WT_INTEROP_REQUESTS+=" https://${WT_INTEROP_HOST}:${CASE_TEST_PORT}"
        WT_INTEROP_REQUESTS+="/wt/file-${index}.bin"
    done
    wt_interop_run "${name}" '^WT closed: status=200 code=0$' || return 1
    [[ "${WT_INTEROP_CLIENT_STATUS}" -eq 0 ]] || return 1
    wt_interop_ready || return 1
    index=0
    for size in 102400 512000 256000 1048576 2097152; do
        file="wt/file-${index}.bin"
        cmp "${WT_INTEROP_DIR}/server-www/${file}" \
            "${WT_INTEROP_DIR}/client-downloads/${file}" || return 1
        grep -q "^WT file received: file-${index}.bin bytes=${size} fin=1$" \
            stdlog \
            || return 1
        index=$((index + 1))
    done
    for log in stdlog svr_stdlog; do
        [[ "$(grep -c '^WT uni sent: .* fin=1$' "${log}")" -eq 5 ]] \
            || return 1
        [[ "$(sed -n 's/^WT uni sent: id=\([0-9]*\) .*/\1/p' \
            "${log}" | sort -u | wc -l)" -eq 5 ]] || return 1
    done
    grep -q '^WT INTEROP PASS: case=UR files=5 all_fin=1$' stdlog || return 1
    ! grep -q '^WT INTEROP FAIL:' stdlog svr_stdlog
}

wt_interop_missing_file()
{
    local name=wt_interop_missing_file
    local failure='session closed before completion|stream closed before FIN'

    wt_interop_prepare "${name}" || return 1
    wt_interop_transfer_prepare
    WT_INTEROP_REQUESTS+='/missing.bin'
    wt_interop_run "${name}" \
        '^WT INTEROP FAIL: open requested file error=2$' || return 1
    [[ "${WT_INTEROP_CLIENT_STATUS}" -eq 1 ]] || return 1
    wt_interop_ready || return 1
    grep -q '^WT closed: status=200 code=1$' stdlog || return 1
    failure+='|stream reset or stopped'
    grep -Eq "^WT INTEROP FAIL: (${failure}) error=-1$" \
        stdlog || return 1
    ! grep -q '^WT INTEROP PASS:' stdlog svr_stdlog || return 1
    [[ ! -e "${WT_INTEROP_DIR}/client-downloads/wt/missing.bin" ]]
}

wt_interop_tls_rejected()
{
    [[ "${WT_INTEROP_CLIENT_STATUS}" -eq 1 ]] || return 1
    grep -q 'certificate verify failed' clog || return 1
    ! grep -q '^WT ready:\|^WT INTEROP PASS:' stdlog svr_stdlog || return 1
    [[ ! -e "${WT_INTEROP_DIR}/client-downloads/negotiated_protocol.txt" \
        && ! -e "${WT_INTEROP_DIR}/server-downloads/negotiated_protocol.txt" ]]
}

wt_interop_wrong_ca()
{
    local name=wt_interop_wrong_ca

    wt_interop_prepare "${name}" || return 1
    WT_INTEROP_CA="${WT_INTEROP_DIR}/unrelated-ca.pem"
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -x509 -nodes \
        -keyout "${WT_INTEROP_DIR}/unrelated-ca.key" \
        -out "${WT_INTEROP_CA}" -subj /CN=Unrelated-CA -days 1 \
        > "${WT_INTEROP_DIR}/certificate.log" 2>&1 || return 1
    wt_interop_run "${name}" || return 1
    wt_interop_tls_rejected
}

wt_interop_wrong_hostname()
{
    local name=wt_interop_wrong_hostname

    wt_interop_prepare "${name}" || return 1
    WT_INTEROP_HOST=wrong.xquic.test
    WT_INTEROP_REQUESTS="https://${WT_INTEROP_HOST}:${CASE_TEST_PORT}/wt"
    wt_interop_run "${name}" || return 1
    wt_interop_tls_rejected
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
case_test_case "wt_interop_handshake" --id 1817 \
    --run wt_interop_handshake --timeout 15
case_test_case "wt_interop_protocol_rejected" --id 1818 \
    --run wt_interop_protocol_rejected --timeout 15
case_test_case "wt_interop_ur" --id 1819 --run wt_interop_ur --timeout 15
case_test_case "wt_interop_missing_file" --id 1820 \
    --run wt_interop_missing_file --timeout 15
case_test_case "wt_interop_wrong_ca" --id 1821 \
    --run wt_interop_wrong_ca --timeout 15
case_test_case "wt_interop_wrong_hostname" --id 1822 \
    --run wt_interop_wrong_hostname --timeout 15

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
case_test_run
