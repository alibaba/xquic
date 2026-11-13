#!/bin/bash
# Native QUIC handshake cases use ephemeral loopback ports.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"
case_test_group "moqt.negotiation"

case_moqt_alpn_coexist()
{
    local build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    "$build_dir/tests/test_moqt_negotiation" legacy || return
    python3 "$ROOT_DIR/scripts/moq_scripts/moq_alpn_test.py" "$build_dir" coexist
}

case_moqt_alpn_reject()
{
    local build_dir="$(case_test_build_dir "${ROOT_DIR}")"
    "$build_dir/tests/test_moqt_negotiation" reject || return
    python3 "$ROOT_DIR/scripts/moq_scripts/moq_alpn_test.py" "$build_dir" reject
}

case_test_case "moqt_alpn_coexist" --id 1466 --run case_moqt_alpn_coexist
case_test_case "moqt_alpn_reject" --id 1467 --run case_moqt_alpn_reject

case_moqt_setup_reject()
{
    python3 "$ROOT_DIR/scripts/moq_scripts/moq_alpn_test.py" \
        "$(case_test_build_dir "${ROOT_DIR}")" setup-errors
}

case_test_case "moqt_setup_reject" --id 1441 --run case_moqt_setup_reject

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
case_test_run
