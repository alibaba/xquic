#!/bin/bash
# Two publishers and two subscribers connected through a Native QUIC relay.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"
case_test_group "moqt.relay"

case_moqt_relay_routes()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_relay" routes
}

case_moqt_relay_errors()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_relay" errors
}

case_moqt_relay_history()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_relay" history
}

case_moqt_relay_history_errors()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_relay" history-errors
}

case_moqt_relay_tracks()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_relay" tracks
}

case_moqt_relay_tracks_errors()
{
    "$(case_test_build_dir "${ROOT_DIR}")/tests/test_moqt_relay" tracks-errors
}

case_test_case "moqt_relay_routes" --id 1475 --run case_moqt_relay_routes
case_test_case "moqt_relay_errors" --id 1476 --run case_moqt_relay_errors
case_test_case "moqt_relay_history" --id 1477 --run case_moqt_relay_history
case_test_case "moqt_relay_history_errors" --id 1478 \
    --run case_moqt_relay_history_errors

case_test_case "moqt_relay_tracks" --id 1479 --run case_moqt_relay_tracks
case_test_case "moqt_relay_tracks_errors" --id 1480 \
    --run case_moqt_relay_tracks_errors

if case_test_is_discovery; then
    case_test_run
    exit 0
fi
case_test_enter_work_dir
case_test_run
