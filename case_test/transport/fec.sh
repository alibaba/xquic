#!/bin/bash
#
# FEC endpoint case-test group.

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "transport.fec"

fec_negotiate_encoder_fec_scheme()
{
    rm -rf tp_localhost test_session xqc_token
    case_test_start_server ${SERVER_BIN} -l d -e -f

    clear_log
    echo -e "negotiate_encoder_fec_schemes ...\c"
    case_test_sudo ${CLIENT_BIN} -l d -g > stdlog
    clog_res1=`grep "|xqc_negotiate_fec_schemes|set final encoder fec scheme: XOR" clog`
    slog_res1=`grep "|xqc_negotiate_fec_schemes|set final encoder fec scheme: XOR" slog`
    errlog=`grep_err_log`
    [ -z "$errlog" ] && [ -n "$clog_res1" ] && [ -n "$slog_res1" ]
}

case_test_case "negotiate_encoder_fec_scheme" \
    --id legacy \
    --run fec_negotiate_encoder_fec_scheme

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

if [[ "${CASE_TEST_GENERATE_ONLY:-0}" = "1" ]]; then
    CASE_TEST_EXCLUDE_CASES="negotiate_encoder_fec_scheme" \
        exec "${ROOT_DIR}/case_test/lib/pending_runner.sh" "transport.fec"
fi

case_test_enter_work_dir
trap case_test_stop_server EXIT

case_test_run

CASE_TEST_EXCLUDE_CASES="negotiate_encoder_fec_scheme" \
    exec "${ROOT_DIR}/case_test/lib/pending_runner.sh" "transport.fec"
