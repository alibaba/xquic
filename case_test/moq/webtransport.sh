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

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
case_test_run
