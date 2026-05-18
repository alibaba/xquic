#!/bin/bash
# Datachannel & Catalog enable/disable switch e2e test.
# Usage: ./test_dc_catalog_switch_e2e.sh <build_dir>
# Example: ./test_dc_catalog_switch_e2e.sh ../../build_boring/moq/demo

set -u
set -o pipefail

BUILD_DIR="$(cd "${1:?Usage: $0 <build_dir>}" && pwd)"
SERVER="$BUILD_DIR/moq_demo_server"
CLIENT="$BUILD_DIR/moq_demo_client"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR=""
for _d in "$SCRIPT_DIR/../../certs" "$SCRIPT_DIR/../../../certs"; do
    [ -d "$_d" ] && { CERT_DIR="$(cd "$_d" && pwd)"; break; }
done
PORT=$((9600 + RANDOM % 100))
PASS=0
FAIL=0
TMPDIR=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMPDIR"' EXIT

run_test() {
    local name="$1"; shift
    printf "  %-60s " "$name"
    if "$@"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        FAIL=$((FAIL + 1))
    fi
}

grep_in() {
    local pat="$1" file="$2"
    [ -s "$file" ] || return 1
    grep -q -- "$pat" "$file"
}

grep_not_in() {
    local pat="$1" file="$2"
    [ -s "$file" ] && ! grep -q -- "$pat" "$file"
}

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

echo "=== Datachannel & Catalog Switch E2E Tests ==="
echo ""

# ============================================================
# Test 1: Default (both enabled) — datachannel fires
# ============================================================
PORT=$((PORT + 1))
cd "$TMPDIR" || exit 1
rm -f clog slog

"$SERVER" -l d -p $PORT -V > srv1.log 2>&1 &
SRV_PID=$!
sleep 1

timeout 10 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V > cli1.log 2>&1 || true
kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "1a: default — client on_datachannel fires" \
    grep_in "on_datachannel" cli1.log
run_test "1b: default — server subscribe_datachannel OK" \
    grep_in "xqc_moq_subscribe_datachannel\|subscribe_datachannel\|on_datachannel" slog
run_test "1c: default — no crash" \
    grep_not_in "segfault\|SIGSEGV\|Aborted" srv1.log

# ============================================================
# Test 2: -T (disable datachannel) on both sides
# ============================================================
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -T > srv2.log 2>&1 &
SRV_PID=$!
sleep 1

timeout 10 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -T > cli2.log 2>&1 || true
kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "2a: -T — client on_datachannel does NOT fire" \
    grep_not_in "on_datachannel" cli2.log
run_test "2b: -T — server subscribe_datachannel skipped" \
    grep_not_in "subscribe_datachannel" slog
run_test "2c: -T — session setup still completes" \
    grep_in "on_session_setup\|session_setup_done" cli2.log
run_test "2d: -T — no crash" \
    grep_not_in "segfault\|SIGSEGV\|Aborted" srv2.log

# ============================================================
# Test 3: -C (disable catalog) on both sides
# ============================================================
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -C > srv3.log 2>&1 &
SRV_PID=$!
sleep 1

timeout 10 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -C > cli3.log 2>&1 || true
kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "3a: -C — no catalog subscription in client log" \
    grep_not_in "subscribe_catalog\|subscribe_latest.*catalog" clog
run_test "3b: -C — datachannel still works" \
    grep_in "on_datachannel" cli3.log
run_test "3c: -C — no crash" \
    grep_not_in "segfault\|SIGSEGV\|Aborted" srv3.log

# ============================================================
# Test 4: -T -C (both disabled)
# ============================================================
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -T -C > srv4.log 2>&1 &
SRV_PID=$!
sleep 1

timeout 10 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -T -C > cli4.log 2>&1 || true
kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "4a: -T -C — no datachannel" \
    grep_not_in "on_datachannel" cli4.log
run_test "4b: -T -C — no catalog" \
    grep_not_in "subscribe_catalog" clog
run_test "4c: -T -C — session setup completes" \
    grep_in "on_session_setup\|session_setup_done" cli4.log
run_test "4d: -T -C — no crash on server" \
    grep_not_in "segfault\|SIGSEGV\|Aborted" srv4.log
run_test "4e: -T -C — no crash on client" \
    grep_not_in "segfault\|SIGSEGV\|Aborted" cli4.log

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -ne 0 ]; then
    echo ""
    echo "--- tail srv1.log ---"; tail -20 srv1.log 2>/dev/null
    echo "--- tail cli1.log ---"; tail -20 cli1.log 2>/dev/null
    echo "--- tail srv2.log ---"; tail -20 srv2.log 2>/dev/null
    echo "--- tail cli2.log ---"; tail -20 cli2.log 2>/dev/null
    echo "--- tail clog ---";    tail -30 "$TMPDIR/clog" 2>/dev/null
    echo "--- tail slog ---";    tail -30 "$TMPDIR/slog" 2>/dev/null
fi
[ "$FAIL" -eq 0 ]
