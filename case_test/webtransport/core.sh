#!/bin/bash
# Native WebTransport endpoints use ephemeral loopback ports.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "webtransport.core"

case_webtransport_transfer()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" transfer
}

case_webtransport_reject_origin()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" reject-origin
}

case_webtransport_missing_reset()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" missing-reset
}

case_webtransport_misplaced_stream_type()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" misplaced-stream-type
}

case_webtransport_settings_capacity()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" settings-capacity
}

case_webtransport_missing_datagram()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" missing-datagram
}

case_webtransport_pending_datagram_reject()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" pending-datagram-reject
}

case_webtransport_session_limit()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" session-limit
}

case_webtransport_reset_credit()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" reset-credit
}

case_webtransport_connect_pseudo_headers()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" connect-pseudo-headers
}

case_webtransport_draft07_client()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" draft07-client
}

case_webtransport_draft07_server()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" draft07-server
}

case_webtransport_draft07_reject_origin()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" draft07-reject-origin
}

case_webtransport_draft07_misplaced_stream_type()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" draft07-misplaced-stream-type
}

case_webtransport_close_client()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" close-client
}

case_webtransport_close_server()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" close-server
}

case_webtransport_idle()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" idle
}

case_webtransport_exit_client()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" exit-client
}

case_webtransport_exit_server()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" exit-server
}

case_webtransport_draft07_close_client()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" draft07-close-client
}

case_webtransport_draft07_close_server()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" draft07-close-server
}

case_webtransport_draft07_idle()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" draft07-idle
}

case_webtransport_draft07_exit_client()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" draft07-exit-client
}

case_webtransport_draft07_exit_server()
{
    local binary="$(case_test_build_dir "${ROOT_DIR}")/tests/test_webtransport"
    "${binary}" draft07-exit-server
}

case_test_case "webtransport_transfer" --id native \
    --run case_webtransport_transfer
case_test_case "webtransport_reject_origin" --id native \
    --run case_webtransport_reject_origin
case_test_case "webtransport_missing_reset" --id native \
    --run case_webtransport_missing_reset
case_test_case "webtransport_misplaced_stream_type" --id native \
    --run case_webtransport_misplaced_stream_type

case_test_case "webtransport_settings_capacity" --id native \
    --run case_webtransport_settings_capacity
case_test_case "webtransport_missing_datagram" --id native \
    --run case_webtransport_missing_datagram
case_test_case "webtransport_pending_datagram_reject" --id native \
    --run case_webtransport_pending_datagram_reject
case_test_case "webtransport_session_limit" --id native \
    --run case_webtransport_session_limit
case_test_case "webtransport_reset_credit" --id native \
    --run case_webtransport_reset_credit
case_test_case "webtransport_connect_pseudo_headers" --id native \
    --run case_webtransport_connect_pseudo_headers

case_test_case "webtransport_draft07_client" --id native \
    --run case_webtransport_draft07_client
case_test_case "webtransport_draft07_server" --id native \
    --run case_webtransport_draft07_server
case_test_case "webtransport_draft07_reject_origin" --id native \
    --run case_webtransport_draft07_reject_origin
case_test_case "webtransport_draft07_misplaced_stream_type" --id native \
    --run case_webtransport_draft07_misplaced_stream_type

case_test_case "webtransport_close_client" --id native \
    --run case_webtransport_close_client
case_test_case "webtransport_close_server" --id native \
    --run case_webtransport_close_server
case_test_case "webtransport_idle" --id native \
    --run case_webtransport_idle
case_test_case "webtransport_exit_client" --id native \
    --run case_webtransport_exit_client
case_test_case "webtransport_exit_server" --id native \
    --run case_webtransport_exit_server
case_test_case "webtransport_draft07_close_client" --id native \
    --run case_webtransport_draft07_close_client
case_test_case "webtransport_draft07_close_server" --id native \
    --run case_webtransport_draft07_close_server
case_test_case "webtransport_draft07_idle" --id native \
    --run case_webtransport_draft07_idle
case_test_case "webtransport_draft07_exit_client" --id native \
    --run case_webtransport_draft07_exit_client
case_test_case "webtransport_draft07_exit_server" --id native \
    --run case_webtransport_draft07_exit_server

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
case_test_run
