#!/bin/bash
#
# http3.qpack endpoint case-test group.


ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "http3.qpack"

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
trap 'case_test_stop_server; case_test_cleanup_udp_port' EXIT

case_test_run
