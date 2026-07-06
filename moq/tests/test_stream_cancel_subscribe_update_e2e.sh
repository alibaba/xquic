#!/bin/bash
# Receiver stream cancel + SUBSCRIBE_UPDATE e2e smoke test.
# Usage: ./test_stream_cancel_subscribe_update_e2e.sh <build_dir>
# Example: ./test_stream_cancel_subscribe_update_e2e.sh ../../build_moq_update/moq/demo

set -euo pipefail

BUILD_DIR="$(cd "${1:?Usage: $0 <build_dir>}" && pwd)"
SERVER="$BUILD_DIR/moq_demo_server"
CLIENT="$BUILD_DIR/moq_demo_client"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR=""
for _d in "$SCRIPT_DIR/../../certs" "$SCRIPT_DIR/../../../certs"; do
    [ -d "$_d" ] && { CERT_DIR="$(cd "$_d" && pwd)"; break; }
done
FRAME_NUM=20
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

    local f
    for f in "${files[@]}"; do
        [ -s "$f" ] || continue
        local token
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

echo "=== Stream Cancel + SUBSCRIBE_UPDATE E2E Tests ==="
echo ""

run_moq_case() {
    local label="$1"
    local next_group_id="$2"
    local mode="${3:-media}"
    local case_dir="$TMPDIR/$label"
    local port=$((9800 + RANDOM % 100))
    mkdir -p "$case_dir"
    cp "$TMPDIR/server.crt" "$case_dir/server.crt"
    cp "$TMPDIR/server.key" "$case_dir/server.key"

    echo "--- case: $label, next_group_id=$next_group_id ---"

    cd "$case_dir" || exit 1
    if [ "$mode" = "raw" ]; then
        "$SERVER" -l d -p "$port" -V -n "$FRAME_NUM" -R > srv.log 2>&1 &
    else
        "$SERVER" -l d -p "$port" -V -n "$FRAME_NUM" > srv.log 2>&1 &
    fi
    SRV_PID=$!
    sleep 1
    if ! kill -0 "$SRV_PID" 2>/dev/null; then
        echo "FATAL: server exited before client start"
        kill $SRV_PID 2>/dev/null || true
        exit 1
    fi

    if [ "$mode" = "raw" ]; then
        timeout "$CLIENT_TIMEOUT" "$CLIENT" -a 127.0.0.1 -p "$port" -l d -V \
            -n "$FRAME_NUM" -S "$next_group_id" -R > cli.log 2>&1 || true
    else
        timeout "$CLIENT_TIMEOUT" "$CLIENT" -a 127.0.0.1 -p "$port" -l d -V \
            -n "$FRAME_NUM" -S "$next_group_id" > cli.log 2>&1 || true
    fi

    kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

    LOG_CLIENT="$case_dir/clog"
    LOG_SERVER="$case_dir/slog"

    if [ "$mode" = "raw" ]; then
        run_test "$label 1a: client called raw cancel_recv and subscribe_update" \
            line_has_all_in_any cli.log "$LOG_CLIENT" -- \
            "demo_raw_audio_cancel_recv|" "next_group_id:$next_group_id|" "recv_group_id:1|" "cancel_ret:0|" "update_ret:0|"
        run_test "$label 1b: cancel_recv sent STOP_SENDING for raw audio group 1" \
            line_has_all_in_any cli.log "$LOG_CLIENT" -- \
            "moq cancel recv stream|" "track:namespace/audio|" "group_id:1|" "ret:0|"
    else
        run_test "$label 1a: client called cancel_recv and subscribe_update" \
            line_has_all_in_any cli.log "$LOG_CLIENT" -- \
            "demo_audio_cancel_recv|" "next_group_id:$next_group_id|" "cancel_ret:0|" "update_ret:0|"
        run_test "$label 1b: cancel_recv sent STOP_SENDING for audio group 0" \
            line_has_all_in_any cli.log "$LOG_CLIENT" -- \
            "moq cancel recv stream|" "track:namespace/audio|" "group_id:0|" "ret:0|"
    fi
    run_test "$label 1c: server received SUBSCRIBE_UPDATE start_group_id" \
        line_has_all_in_any srv.log "$LOG_SERVER" -- \
        "demo_on_subscribe_update|" "start_group_id:$next_group_id|" "start_object_id:0|"
    if [ "$mode" = "raw" ]; then
        run_test "$label 1d: server resumed raw audio at requested group" \
            line_has_all_in_any srv.log "$LOG_SERVER" -- \
            "write raw object success|" "track_name:audio|" "group_id:$next_group_id|" "object_id:0|"
        run_test "$label 1e: client received raw audio at requested group" \
            line_has_all_in_any cli.log "$LOG_CLIENT" -- \
            "on_raw_object:" "name:audio" "group:$next_group_id," "id:0,"
    else
        run_test "$label 1d: server dropped old audio objects after update" \
            line_has_all_in_any srv.log "$LOG_SERVER" -- \
            "drop audio frame by subscribe update|" "track_name:audio|" "group_id:0|"
    fi

    run_test "$label 2a: no server crash" \
        none_in_any srv.log "$LOG_SERVER" -- "segfault" "SIGSEGV" "Aborted"
    run_test "$label 2b: no client crash" \
        none_in_any cli.log "$LOG_CLIENT" -- "segfault" "SIGSEGV" "Aborted"
    run_test "$label 2c: no protocol violation on server" \
        none_in_any srv.log "$LOG_SERVER" -- "PROTOCOL_VIOLATION" "conn_err:3"
    run_test "$label 2d: no protocol violation on client" \
        none_in_any cli.log "$LOG_CLIENT" -- "PROTOCOL_VIOLATION" "conn_err:3"
    echo ""
}

run_moq_case "adjacent" 1
run_moq_case "skip" 5
run_moq_case "raw-skip" 5 raw

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -ne 0 ]; then
    echo ""
    for d in "$TMPDIR"/*; do
        [ -d "$d" ] || continue
        echo "--- tail $(basename "$d")/srv.log ---"; tail -40 "$d/srv.log" 2>/dev/null
        echo "--- tail $(basename "$d")/cli.log ---"; tail -40 "$d/cli.log" 2>/dev/null
        echo "--- tail $(basename "$d")/slog ---";    tail -60 "$d/slog" 2>/dev/null
        echo "--- tail $(basename "$d")/clog ---";    tail -60 "$d/clog" 2>/dev/null
    done
fi
[ "$FAIL" -eq 0 ]
