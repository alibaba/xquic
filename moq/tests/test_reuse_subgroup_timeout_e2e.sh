#!/bin/bash
# Reused video subgroup stream timeout e2e test.
# Usage: ./test_reuse_subgroup_timeout_e2e.sh <build_dir>
# Example: ./test_reuse_subgroup_timeout_e2e.sh ../../build_alias_test/moq/demo

set -u
set -o pipefail

BUILD_DIR="$(cd "${1:?Usage: $0 <build_dir>}" && pwd)"
SERVER="$BUILD_DIR/moq_demo_server"
CLIENT="$BUILD_DIR/moq_demo_client"
BUILD_ROOT="$(cd "$BUILD_DIR/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR=""
for _d in "$SCRIPT_DIR/../../certs" "$SCRIPT_DIR/../../../certs"; do
    [ -d "$_d" ] && { CERT_DIR="$(cd "$_d" && pwd)"; break; }
done
PORT=$((9900 + RANDOM % 100))
PASS=0
FAIL=0
TMPDIR=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMPDIR"' EXIT

run_test() {
    local name="$1"; shift
    printf "  %-62s " "$name"
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

for f in "$SERVER" "$CLIENT"; do
    [ -x "$f" ] || { echo "FATAL: $f not found"; exit 1; }
done

if [ -f "$BUILD_ROOT/server.crt" ] && [ -f "$BUILD_ROOT/server.key" ]; then
    cp "$BUILD_ROOT/server.crt" "$TMPDIR/server.crt"
    cp "$BUILD_ROOT/server.key" "$TMPDIR/server.key"
elif [ -n "$CERT_DIR" ] && [ -f "$CERT_DIR/localhost.crt" ]; then
    cp "$CERT_DIR/localhost.crt" "$TMPDIR/server.crt"
    cp "$CERT_DIR/localhost.key" "$TMPDIR/server.key"
else
    cp "$(dirname "$SERVER")/server.crt" "$TMPDIR/server.crt" 2>/dev/null || true
    cp "$(dirname "$SERVER")/server.key" "$TMPDIR/server.key" 2>/dev/null || true
fi

if [ ! -f "$TMPDIR/server.crt" ] || [ ! -f "$TMPDIR/server.key" ]; then
    echo "FATAL: TLS certificate/key not found"
    exit 1
fi

echo "=== Reused Video Subgroup Timeout E2E Tests ==="
echo ""

cd "$TMPDIR" || exit 1

"$SERVER" -l d -p "$PORT" -V -W -n 25 > srv.log 2>&1 &
SRV_PID=$!
sleep 1

timeout 15 "$CLIENT" -a 127.0.0.1 -p "$PORT" -l d -V -n 25 > cli.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

LOG_SERVER="$TMPDIR/slog"
LOG_CLIENT="$TMPDIR/clog"

run_test "1a: demo enabled reused video subgroup stream" \
    grep_in "moq_video_reuse_subgroup_stream|enabled:1" srv.log
run_test "1b: GOP stayed active for more than 500ms" \
    grep_in "server_send_video_frame|.*seq:20" srv.log
run_test "1c: reused active GOP did not timeout" \
    grep_not_in "video frame timeout" "$LOG_SERVER"

run_test "2a: no server crash" \
    grep_not_in "segfault\|SIGSEGV\|Aborted" srv.log
run_test "2b: no client crash" \
    grep_not_in "segfault\|SIGSEGV\|Aborted" cli.log
run_test "2c: no protocol violation on server" \
    grep_not_in "PROTOCOL_VIOLATION\|conn_err:3" "$LOG_SERVER"
run_test "2d: no protocol violation on client" \
    grep_not_in "PROTOCOL_VIOLATION\|conn_err:3" "$LOG_CLIENT"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -ne 0 ]; then
    echo ""
    echo "--- tail srv.log ---"; tail -40 srv.log 2>/dev/null
    echo "--- tail cli.log ---"; tail -40 cli.log 2>/dev/null
    echo "--- tail slog ---";    tail -60 "$LOG_SERVER" 2>/dev/null
    echo "--- tail clog ---";    tail -40 "$LOG_CLIENT" 2>/dev/null
fi
[ "$FAIL" -eq 0 ]
