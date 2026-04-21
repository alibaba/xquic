#!/bin/bash
# CATALOG param (0xA2) e2e smoke test.
# Usage: ./test_catalog_param_e2e.sh <build_dir>
# Example: ./test_catalog_param_e2e.sh ../../build_boring/moq/demo

set -u
set -o pipefail

BUILD_DIR="${1:?Usage: $0 <build_dir>}"
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

wait_for_listen() {
    local port="$1" tries=50
    while [ $tries -gt 0 ]; do
        # /dev/tcp is a bash builtin but may be compiled out on some distros
        # (Alpine, minimal containers). Fall back to nc / ss when missing.
        if (echo > /dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
            return 0
        elif command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 "$port" 2>/dev/null; then
            return 0
        elif command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -q ":$port\b"; then
            return 0
        fi
        tries=$((tries - 1))
        sleep 0.1
    done
    return 1
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

echo "=== CATALOG param (0xA2) E2E Tests ==="
echo ""

# ============================================================
# Run: demo client subscribes to server tracks AND publishes a datachannel.
# Covers both auto-apply directions:
#   - PUBLISH       (client -> server): CATALOG attached via datachannel publish
#   - SUBSCRIBE_OK  (server -> client): CATALOG attached by demo on_subscribe
# ============================================================
cd "$TMPDIR" || exit 1

"$SERVER" -l d -p "$PORT" -V > srv.log 2>&1 &
SRV_PID=$!

if ! wait_for_listen "$PORT"; then
    echo "FATAL: server did not listen on $PORT within 5s"
    kill $SRV_PID 2>/dev/null || true
    exit 1
fi

timeout 15 "$CLIENT" -a 127.0.0.1 -p "$PORT" -l d -V > cli.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

LOG_CLIENT="$TMPDIR/clog"
LOG_SERVER="$TMPDIR/slog"

# -------- PUBLISH direction (client -> server) --------
# The demo client attaches CATALOG when it publishes (datachannel). The SDK
# on the server side auto-applies on xqc_moq_on_publish, and on_publish_msg
# prints the resulting selection_params.
run_test "1a: client built catalog param for PUBLISH" \
    grep_in_existing "create_datachannel_build_catalog_ok" "$LOG_CLIENT"
run_test "1b: server received PUBLISH and created track" \
    grep_in_existing "on_publish_track_created" "$LOG_SERVER"
run_test "1c: server on_publish saw selection_params" \
    grep_in_existing "==>on_publish selection_params codec:" srv.log

# -------- SUBSCRIBE_OK direction (server -> client) --------
# Demo server now attaches CATALOG on its SUBSCRIBE_OK for video/audio tracks.
# The SDK on the client side auto-applies via xqc_moq_on_subscribe_ok.
run_test "1d: server attached CATALOG on SUBSCRIBE_OK" \
    grep_in_existing "subscribe_ok attach catalog param" srv.log
run_test "1e: client auto-applied CATALOG from SUBSCRIBE_OK" \
    grep_in_existing "on_subscribe_ok catalog param applied" "$LOG_CLIENT"
run_test "1f: client subscribe_ok track gained codec" \
    bash -c 'grep -E -q "on_subscribe_ok catalog param applied.*codec:(av01|opus)" "$0"' "$LOG_CLIENT"

# ============================================================
# Test 2: no crashes, no protocol violations
# ============================================================
run_test "2a: no segfault on server" \
    bash -c '! grep -q "segfault\|SIGSEGV\|Aborted" "$0"' srv.log
run_test "2b: no segfault on client" \
    bash -c '! grep -q "segfault\|SIGSEGV\|Aborted" "$0"' cli.log
run_test "2c: no PROTOCOL_VIOLATION on client" \
    grep_not_in_existing "PROTOCOL_VIOLATION\|conn_err:3" "$LOG_CLIENT"
run_test "2d: no PROTOCOL_VIOLATION on server" \
    grep_not_in_existing "PROTOCOL_VIOLATION\|conn_err:3" "$LOG_SERVER"

# ============================================================
# Test 3: CATALOG param is observable in trace
# ============================================================
run_test "3a: CATALOG type (0xa2 / 162) appears in trace" \
    bash -c 'grep -E -q "type:0xa2|type:162|XQC_MOQ_PARAM_CATALOG|catalog param applied" "$0" "$1"' \
    "$LOG_CLIENT" "$LOG_SERVER"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -ne 0 ]; then
    echo ""
    echo "--- tail srv.log ---"; tail -30 srv.log 2>/dev/null
    echo "--- tail cli.log ---"; tail -30 cli.log 2>/dev/null
    echo "--- tail slog ---";    tail -30 "$LOG_SERVER" 2>/dev/null
    echo "--- tail clog ---";    tail -30 "$LOG_CLIENT" 2>/dev/null
fi
[ "$FAIL" -eq 0 ]
