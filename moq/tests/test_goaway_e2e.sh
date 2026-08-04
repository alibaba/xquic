#!/bin/bash
# Focused draft-18 GOAWAY scope coverage.
# Usage: ./test_goaway_e2e.sh <build/moq/demo>

set -u

BUILD_DIR="$(cd "${1:?Usage: $0 <build/moq/demo>}" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIFECYCLE_E2E="$SCRIPT_DIR/test_draft18_control_lifecycle_e2e.sh"
PASS=0
FAIL=0

run_case()
{
    local case_name="$1"
    local description="$2"
    printf "  %-64s " "$description"
    if CASE_FILTER="$case_name" bash "$LIFECYCLE_E2E" "$BUILD_DIR"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Draft-18 GOAWAY E2E Tests ==="
echo ""
run_case control-goaway \
    "control scope rejects cutoff and preserves established request"
run_case request-goaway \
    "request scope resets only target and retains sibling request"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
