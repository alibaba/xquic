#!/bin/bash
# MoQT endpoints bound to separate WebTransport sessions on one H3 connection.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"
case_test_group "moqt.webtransport"

case_moqt_webtransport()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_webtransport"
}

case_moqt_webtransport_errors()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_webtransport" errors
}

case_test_case "moqt_webtransport" --id 1471 --run case_moqt_webtransport
case_test_case "moqt_webtransport_errors" --id 1472 \
    --run case_moqt_webtransport_errors

case_moqt_webtransport_relay()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_webtransport" relay
}

case_moqt_webtransport_relay_errors()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_webtransport" relay-errors
}

case_test_case "moqt_webtransport_relay" --id 1491 \
    --run case_moqt_webtransport_relay
case_test_case "moqt_webtransport_relay_errors" --id 1492 \
    --run case_moqt_webtransport_relay_errors

moqt_demo_start()
{
    case_test_stop_server
    local binary="$(case_test_build_dir "${ROOT_DIR}")/demo/demo_server"
    (umask 077; openssl req -newkey rsa:2048 -x509 -nodes -days 1 \
        -keyout server.key -out server.crt -subj /CN=localhost \
        -addext subjectAltName=DNS:localhost,IP:127.0.0.1) \
        > demo-certificate.log 2>&1 || return 1
    openssl x509 -in server.crt -outform DER -out server.der || return 1
    XQC_MOQT_ALLOWED_ORIGIN=http://localhost:8080,https://example.test \
        "${binary}" "${1:---moqt}" \
        -p "${CASE_TEST_PORT:-8443}" > demo-server.log 2>&1 &
    CASE_TEST_SERVER_PID="$!"
    sleep 0.2
    kill -0 "${CASE_TEST_SERVER_PID}"
}

case_moqt_webtransport_draft07()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/demo/demo_server"
    local mode
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_webtransport" \
        draft07 || return 1
    moqt_demo_start || return 1
    for mode in wt07 wt quic; do
        XQC_MOQT_PROBE_ORIGIN=https://example.test \
            XQC_MOQT_DEMO_PORT="${CASE_TEST_PORT:-8443}" \
            "${binary}" --moqt --probe "${mode}" 127.0.0.1 \
            > "demo-${mode}.log" 2>&1 || return 1
        grep -Fq 'PROBE PASS' "demo-${mode}.log" || return 1
    done
    grep -Fq 'carrier=stream' demo-server.log || return 1
    grep -Fq 'carrier=datagram' demo-server.log || return 1
    grep -Fq 'WT CLOSED status=200 error=0' demo-server.log
}

case_moqt_webtransport_draft07_errors()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/demo/demo_server"
    local mode
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_webtransport" \
        draft07-errors || return 1
    moqt_demo_start || return 1
    for mode in bad-path07 bad-protocol07 bad-origin07; do
        XQC_MOQT_DEMO_PORT="${CASE_TEST_PORT:-8443}" \
            "${binary}" --moqt --probe "${mode}" 127.0.0.1 \
            > "demo-${mode}.log" 2>&1 || return 1
        grep -Fq 'WT CLOSED status=403' "demo-${mode}.log" || return 1
        grep -Fq 'PROBE PASS' "demo-${mode}.log" || return 1
    done
    grep -Fq 'WT REJECT' demo-server.log
}

case_test_case "moqt_webtransport_draft07" --id 1493 \
    --run case_moqt_webtransport_draft07
case_test_case "moqt_webtransport_draft07_errors" --id 1494 \
    --run case_moqt_webtransport_draft07_errors

case_moqt_demo_relay_echo()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_demo_relay"
    local mode
    moqt_demo_start --moqt-relay || return 1
    for mode in quic wt07 wt mixed mixed-reverse; do
        XQC_MOQT_DEMO_PORT="${CASE_TEST_PORT:-8443}" "${binary}" "${mode}" \
            > "relay-${mode}.log" 2>&1 || return 1
        XQC_MOQT_DEMO_PORT="${CASE_TEST_PORT:-8443}" "${binary}" "${mode}" \
            direct > "relay-direct-${mode}.log" 2>&1 || return 1
    done
    grep -Fq 'RELAY FORWARD type=0x3' demo-server.log
}

case_moqt_demo_relay_errors()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_demo_relay"
    local mode
    moqt_demo_start --moqt-relay || return 1
    for mode in quic wt07 wt mixed mixed-reverse; do
        XQC_MOQT_DEMO_PORT="${CASE_TEST_PORT:-8443}" "${binary}" "${mode}" \
            errors > "relay-errors-${mode}.log" 2>&1 || return 1
    done
}

case_test_case "moqt_demo_relay_echo" --id 1495 \
    --run case_moqt_demo_relay_echo
case_test_case "moqt_demo_relay_errors" --id 1496 \
    --run case_moqt_demo_relay_errors

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
case_test_run
