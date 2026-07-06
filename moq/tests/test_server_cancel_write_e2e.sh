#!/bin/bash
# Server-side cancel_write e2e smoke test.
# Usage: ./test_server_cancel_write_e2e.sh <build_dir>

set -euo pipefail

BUILD_DIR="$(cd "${1:?Usage: $0 <build_dir>}" && pwd)"
SERVER="$BUILD_DIR/moq_demo_server"
CLIENT="$BUILD_DIR/moq_demo_client"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR=""
for _d in "$SCRIPT_DIR/../../certs" "$SCRIPT_DIR/../../../certs"; do
    [ -d "$_d" ] && { CERT_DIR="$(cd "$_d" && pwd)"; break; }
done
FRAME_NUM=12
CLIENT_TIMEOUT=25
PASS=0
FAIL=0
TMPDIR=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMPDIR"' EXIT

run_test() {
    local name="$1"; shift
    printf "  %-66s " "$name"
    if "$@"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        FAIL=$((FAIL + 1))
    fi
}

line_has_all_in_any() {
    local files=()
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
        files+=("$1")
        shift
    done
    [ "$#" -gt 0 ] || return 1
    shift

    local f line token ok
    for f in "${files[@]}"; do
        [ -s "$f" ] || continue
        while IFS= read -r line; do
            ok=1
            for token in "$@"; do
                case "$line" in
                    *"$token"*) ;;
                    *) ok=0; break ;;
                esac
            done
            [ "$ok" -eq 1 ] && return 0
        done < "$f"
    done
    return 1
}

none_in_any() {
    local files=()
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
        files+=("$1")
        shift
    done
    [ "$#" -gt 0 ] || return 1
    shift

    local f token
    for f in "${files[@]}"; do
        [ -s "$f" ] || continue
        for token in "$@"; do
            grep -Fq -- "$token" "$f" && return 1
        done
    done
    return 0
}

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

if [ ! -f "$TMPDIR/server.crt" ] || [ ! -f "$TMPDIR/server.key" ]; then
    command -v openssl >/dev/null 2>&1 || { echo "FATAL: no test certs and openssl not found"; exit 1; }
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$TMPDIR/server.key" -out "$TMPDIR/server.crt" \
        -days 1 -subj "/CN=localhost" >/dev/null 2>&1
fi

echo "=== Server cancel_write E2E Tests ==="
echo ""

case_dir="$TMPDIR/server-cancel-write"
port=$((9900 + RANDOM % 80))
mkdir -p "$case_dir"
cp "$TMPDIR/server.crt" "$case_dir/server.crt"
cp "$TMPDIR/server.key" "$case_dir/server.key"
cd "$case_dir" || exit 1

"$SERVER" -l d -p "$port" -V -n "$FRAME_NUM" -Z 1 > srv.log 2>&1 &
SRV_PID=$!
sleep 1
if ! kill -0 "$SRV_PID" 2>/dev/null; then
    echo "FATAL: server exited before client start"
    exit 1
fi

timeout "$CLIENT_TIMEOUT" "$CLIENT" -a 127.0.0.1 -p "$port" -l d -V -n "$FRAME_NUM" > cli.log 2>&1 || true
kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

LOG_CLIENT="$case_dir/clog"
LOG_SERVER="$case_dir/slog"

run_test "server called cancel_write for audio group before 1" \
    line_has_all_in_any srv.log "$LOG_SERVER" -- \
    "demo_audio_cancel_write|" "before_group_id:1|" "ret:0|"
run_test "cancel_write closed old audio stream" \
    line_has_all_in_any srv.log "$LOG_SERVER" -- \
    "moq cancel write stream|" "track:namespace/audio|" "group_id:0|" "ret:0|"
run_test "server dropped future old audio writes" \
    line_has_all_in_any srv.log "$LOG_SERVER" -- \
    "drop audio frame by subscribe update|" "track_name:audio|" "group_id:0|"
run_test "no server crash" \
    none_in_any srv.log "$LOG_SERVER" -- "segfault" "SIGSEGV" "Aborted" "MOQ_INTERNAL_ERROR"
run_test "no client crash" \
    none_in_any cli.log "$LOG_CLIENT" -- "segfault" "SIGSEGV" "Aborted"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -ne 0 ]; then
    echo "--- tail srv.log ---"; tail -60 srv.log 2>/dev/null
    echo "--- tail cli.log ---"; tail -60 cli.log 2>/dev/null
    echo "--- tail slog ---"; tail -80 "$LOG_SERVER" 2>/dev/null
    echo "--- tail clog ---"; tail -80 "$LOG_CLIENT" 2>/dev/null
fi
[ "$FAIL" -eq 0 ]
