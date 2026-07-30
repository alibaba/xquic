#!/bin/bash
# CATALOG param (0xA2) e2e smoke test.
# Usage: ./test_catalog_param_e2e.sh <build_dir>
# Example: ./test_catalog_param_e2e.sh ../../build_boring/moq/demo

set -u
set -o pipefail

BUILD_DIR="$(cd "${1:?Usage: $0 <build_dir>}" && pwd)"
SERVER="$BUILD_DIR/moq_demo_server"
CLIENT="$BUILD_DIR/moq_demo_client"
CERT_DIR="$(cd "$(dirname "$0")/../../certs" 2>/dev/null && pwd || echo "")"
PORT=$((9700 + RANDOM % 100))
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

grep_in_existing() {
    local pat="$1" file="$2"
    [ -s "$file" ] || return 1
    grep -q -- "$pat" "$file"
}

grep_not_in_existing() {
    local pat="$1" file="$2"
    [ -s "$file" ] && ! grep -q -- "$pat" "$file"
}

# --- Setup ---
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
elif [ -n "$CERT_DIR" ] && [ -f "$CERT_DIR/localhost.crt" ]; then
    cp "$CERT_DIR/localhost.crt" "$TMPDIR/server.crt"
    cp "$CERT_DIR/localhost.key" "$TMPDIR/server.key"
fi

echo "=== CATALOG param (0xA2) E2E Tests ==="
echo ""

# ============================================================
# Run separate publisher and subscriber sessions because the demo's -M mode
# selects publisher behavior and intentionally skips subscriptions.
# Covers both CATALOG parameter directions:
#   - PUBLISH       (client -> server): CATALOG attached via datachannel publish
#   - SUBSCRIBE_OK  (server -> client): CATALOG attached by demo on_subscribe
# ============================================================
cd "$TMPDIR" || exit 1

"$SERVER" -l d -p "$PORT" -V -o > publish-server.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 15 "$CLIENT" -a 127.0.0.1 -p "$PORT" -l d -V -M > publish-client.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true
mv clog publish-clog
mv slog publish-slog

PORT=$((PORT + 1))
"$SERVER" -l d -p "$PORT" -V > subscribe-server.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 15 "$CLIENT" -a 127.0.0.1 -p "$PORT" -l d -V > subscribe-client.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true
mv clog subscribe-clog
mv slog subscribe-slog

PUBLISH_LOG_CLIENT="$TMPDIR/publish-clog"
PUBLISH_LOG_SERVER="$TMPDIR/publish-slog"
SUBSCRIBE_LOG_CLIENT="$TMPDIR/subscribe-clog"
SUBSCRIBE_LOG_SERVER="$TMPDIR/subscribe-slog"

# -------- PUBLISH direction (client -> server) --------
# The demo client attaches CATALOG when it publishes (datachannel). The SDK
# on the server side auto-applies on xqc_moq_on_publish, and on_publish_msg
# prints the resulting selection_params.
run_test "1a: client built catalog param for PUBLISH" \
    grep_in_existing "create_datachannel_build_catalog_ok" "$PUBLISH_LOG_CLIENT"
run_test "1b: server received PUBLISH and created track" \
    grep_in_existing "on_publish_track_created" "$PUBLISH_LOG_SERVER"
run_test "1c: server decoded CATALOG selection_params" \
    grep_in_existing "catalog_single_track_decode: role:data" publish-server.log

# -------- SUBSCRIBE_OK direction (server -> client) --------
# Demo server now attaches CATALOG on its SUBSCRIBE_OK for video/audio tracks.
# The SDK on the client side auto-applies via xqc_moq_on_subscribe_ok.
run_test "1d: server attached CATALOG on SUBSCRIBE_OK" \
    grep_in_existing "subscribe_ok attach catalog param" subscribe-server.log
run_test "1e: client auto-applied CATALOG from SUBSCRIBE_OK" \
    grep_in_existing "on_subscribe_ok catalog param applied" "$SUBSCRIBE_LOG_CLIENT"
run_test "1f: client subscribe_ok track gained codec" \
    bash -c 'grep -E -q "on_subscribe_ok catalog param applied.*codec:(av01|opus)" "$0"' "$SUBSCRIBE_LOG_CLIENT"

# ============================================================
# Test 2: no crashes, no protocol violations
# ============================================================
run_test "2a: no segfault on server" \
    bash -c '! grep -E -q "segfault|SIGSEGV|Aborted" "$@"' _ publish-server.log subscribe-server.log
run_test "2b: no segfault on client" \
    bash -c '! grep -E -q "segfault|SIGSEGV|Aborted" "$@"' _ publish-client.log subscribe-client.log
run_test "2c: no PROTOCOL_VIOLATION on client" \
    bash -c '! grep -E -q "PROTOCOL_VIOLATION|conn_err:3" "$@"' _ "$PUBLISH_LOG_CLIENT" "$SUBSCRIBE_LOG_CLIENT"
run_test "2d: no PROTOCOL_VIOLATION on server" \
    bash -c '! grep -E -q "PROTOCOL_VIOLATION|conn_err:3" "$@"' _ "$PUBLISH_LOG_SERVER" "$SUBSCRIBE_LOG_SERVER"

# ============================================================
# Test 3: CATALOG param is observable in trace
# ============================================================
run_test "3a: CATALOG type (0xa2 / 162) appears in trace" \
    bash -c 'grep -E -q "type:0xa2|type:162|XQC_MOQ_PARAM_CATALOG|catalog param applied" "$@"' _ \
    "$PUBLISH_LOG_CLIENT" "$PUBLISH_LOG_SERVER" "$SUBSCRIBE_LOG_CLIENT" "$SUBSCRIBE_LOG_SERVER"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -ne 0 ]; then
    echo ""
    for log in publish-server.log publish-client.log publish-slog publish-clog \
               subscribe-server.log subscribe-client.log subscribe-slog subscribe-clog; do
        echo "--- tail $log ---"
        tail -30 "$log" 2>/dev/null
    done
fi
[ "$FAIL" -eq 0 ]
