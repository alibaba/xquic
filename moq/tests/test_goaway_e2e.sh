#!/bin/bash
# GOAWAY e2e smoke test
# Usage: ./test_goaway_e2e.sh <build_dir>
# Example: ./test_goaway_e2e.sh ../../build_boring/moq/demo

BUILD_DIR="${1:?Usage: $0 <build_dir>}"
SERVER="$BUILD_DIR/moq_demo_server"
CLIENT="$BUILD_DIR/moq_demo_client"
CERT_DIR="$(cd "$(dirname "$0")/../../certs" 2>/dev/null && pwd || echo "")"
PORT=$((9800 + RANDOM % 100))
PASS=0
FAIL=0
TMPDIR=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMPDIR"' EXIT

run_test() {
    local name="$1"; shift
    printf "  %-50s " "$name"
    if "$@"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        FAIL=$((FAIL + 1))
    fi
}

# helper: succeed when pattern is NOT found in file
assert_no_match() { grep -q "$1" "$2" && return 1 || return 0; }

# --- Setup ---
for f in "$SERVER" "$CLIENT"; do
    [ -x "$f" ] || { echo "FATAL: $f not found"; exit 1; }
done

if [ -n "$CERT_DIR" ] && [ -f "$CERT_DIR/localhost.crt" ]; then
    cp "$CERT_DIR/localhost.crt" "$TMPDIR/server.crt"
    cp "$CERT_DIR/localhost.key" "$TMPDIR/server.key"
else
    cp "$(dirname "$SERVER")/server.crt" "$TMPDIR/server.crt" 2>/dev/null || true
    cp "$(dirname "$SERVER")/server.key" "$TMPDIR/server.key" 2>/dev/null || true
fi

echo "=== GOAWAY E2E Tests ==="
echo ""

# ============================================================
# Test 1: server -n 0 (GOAWAY-only) -> client receives GOAWAY
# ============================================================
PORT=$((PORT + 1))
cd "$TMPDIR"

"$SERVER" -l d -p $PORT -V -n 0 > srv.log 2>&1 &
SRV_PID=$!
sleep 1

timeout 10 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V > cli.log 2>&1
CLI_EXIT=$?

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "1a: client exit code is 0" [ "$CLI_EXIT" -eq 0 ]
run_test "1b: client received on_goaway" grep -q "on_goaway" cli.log
run_test "1c: client entered drain" grep -q "session entering drain" clog
run_test "1d: server entered drain" grep -q "session entering drain" slog
run_test "1e: no protocol violation" assert_no_match "conn_err:3" cli.log

# ============================================================
# Test 2: client -n 0 (GOAWAY-only) -> server receives GOAWAY
# ============================================================
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -n 5 > srv2.log 2>&1 &
SRV_PID=$!
sleep 1

timeout 5 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -n 0 > cli2.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "2a: client entered drain (sent goaway)" grep -q "session_drain" clog
run_test "2b: server received goaway" grep -q "on_goaway" slog

# ============================================================
# Test 3: no crashes during the above
# ============================================================
run_test "3a: no crashes" assert_no_match "segfault\|SIGSEGV\|abort" srv.log

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
