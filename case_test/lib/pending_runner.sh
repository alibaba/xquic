#!/bin/bash
#
# Runs one case-test group by extracting its owned cases from the legacy suite.

set -euo pipefail

GROUP_ID="${1:?missing case-test group id}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

exec ruby "${ROOT_DIR}/case_test/lib/legacy_owned_runner.rb" \
    "${ROOT_DIR}" "${GROUP_ID}"
