#!/bin/bash
#
# Fails clearly for case-test groups whose bodies still live in the legacy suite.

set -euo pipefail

GROUP_ID="${1:?missing case-test group id}"

echo "case_test: ${GROUP_ID} runner is not implemented yet" >&2
echo "case_test: use scripts/case_test.sh --dry-run to inspect legacy coverage" >&2
exit 2
