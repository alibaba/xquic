#!/bin/bash
# Multi-element namespace tuple e2e test suite
# Verifies that multi-element namespace tuples (e.g. ["example","ns"])
# survive the full encode/decode/match lifecycle.
#
# Usage: ./test_multi_ns_tuple_e2e.sh <build_dir>
# Example: ./test_multi_ns_tuple_e2e.sh ../../build/moq/demo

BUILD_DIR="$(cd "${1:?Usage: $0 <build_dir>}" && pwd)"
SERVER="$BUILD_DIR/moq_demo_server"
CLIENT="$BUILD_DIR/moq_demo_client"
PORT=$((9700 + RANDOM % 100))
PASS=0
FAIL=0
TMPDIR=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMPDIR"' EXIT

run_test() {
    local name="$1"; shift
    printf "  %-65s " "$name"
    if "$@"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        FAIL=$((FAIL + 1))
    fi
}

assert_no_match() { grep -q "$1" "$2" && return 1 || return 0; }

for f in "$SERVER" "$CLIENT"; do
    [ -x "$f" ] || { echo "FATAL: $f not found"; exit 1; }
done

BUILD_ROOT="$(cd "$BUILD_DIR/../.." && pwd)"
if [ -f "$BUILD_ROOT/server.crt" ]; then
    cp "$BUILD_ROOT/server.crt" "$TMPDIR/"
    cp "$BUILD_ROOT/server.key" "$TMPDIR/"
elif [ -f "$BUILD_DIR/server.crt" ]; then
    cp "$BUILD_DIR/server.crt" "$TMPDIR/"
    cp "$BUILD_DIR/server.key" "$TMPDIR/"
fi

echo "=== Multi-Element Namespace Tuple E2E Tests ==="
echo ""

# ============================================================
# Test 1: Both server and client use 2-element tuple ["example","ns"]
# Expected: subscribe and publish succeed end-to-end
# ============================================================
echo "--- Test 1: Matching multi-element namespace tuple ---"
PORT=$((PORT + 1))
cd "$TMPDIR"
rm -f clog slog

"$SERVER" -l d -p $PORT -V -m -n 2 > srv1.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -m > cli1.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "1a: server created video track" \
    grep -q "track create success|track_name:video" slog
run_test "1b: server created audio track" \
    grep -q "track create success|track_name:audio" slog
run_test "1c: client subscribe video success" \
    grep -q "subscribe success.*track_name:video" clog
run_test "1d: client received subscribe_ok for video" \
    grep -q "on_subscribe_ok|track_name:video" clog
run_test "1e: server received subscribe for video" \
    grep -q "on_subscribe|subscribe_id:.*track_name:video" slog
run_test "1f: no segfault in server" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv1.log
run_test "1g: no segfault in client" \
    assert_no_match "segfault\|SIGSEGV\|abort" cli1.log
run_test "1h: no protocol violation in server" \
    assert_no_match "PROTOCOL_VIOLATION\|conn_err:3" slog
run_test "1i: no protocol violation in client" \
    assert_no_match "PROTOCOL_VIOLATION\|conn_err:3" clog

echo ""

# ============================================================
# Test 2: Server uses 2-element tuple, client uses single "namespace"
# Expected: client's subscribe cannot match server's track (anti-flattening)
# ============================================================
echo "--- Test 2: Mismatched namespace tuple (anti-flattening) ---"
PORT=$((PORT + 1))
cd "$TMPDIR"
rm -f clog slog

"$SERVER" -l d -p $PORT -V -m -n 2 > srv2.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V > cli2.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "2a: server created tracks with multi-ns" \
    grep -q "track create success|track_name:video" slog
run_test "2b: client subscribe should not get ok" \
    assert_no_match "on_subscribe_ok|track_name:video" clog
run_test "2c: no segfault in server" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv2.log
run_test "2d: no segfault in client" \
    assert_no_match "segfault\|SIGSEGV\|abort" cli2.log

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
