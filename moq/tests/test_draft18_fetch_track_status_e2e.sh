#!/bin/bash

BUILD_DIR="$(cd "${1:?Usage: $0 <build/moq/demo>}" && pwd)"
SERVER="$BUILD_DIR/moq_demo_server"
CLIENT="$BUILD_DIR/moq_interop_client"
TMP_ROOT=$(mktemp -d)
SERVER_PID=
LEASE_DIR=
LEASE_ROOT=${MOQ_D18_PORT_LEASE_ROOT:-${TMPDIR:-/tmp}/xquic-moq-d18-finite-port-leases-${UID:-user}}
CLIENT_TIMEOUT_SEC=${MOQ_D18_E2E_CLIENT_TIMEOUT_SEC:-30}
SERVER_TIMEOUT_SEC=${MOQ_D18_E2E_SERVER_TIMEOUT_SEC:-30}
PASS=0
FAIL=0

cleanup()
{
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    [ -z "$LEASE_DIR" ] || rmdir "$LEASE_DIR" 2>/dev/null || true
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT INT TERM

for executable in "$SERVER" "$CLIENT"; do
    [ -x "$executable" ] \
        || { echo "FATAL: missing executable: $executable"; exit 1; }
done
for command_name in openssl lsof; do
    command -v "$command_name" >/dev/null 2>&1 \
        || { echo "FATAL: missing command: $command_name"; exit 1; }
done

mkdir -p "$LEASE_ROOT" || exit 1
seed=$((($$ + $(date +%s)) % 20000))
attempt=0
PORT=
while [ "$attempt" -lt 20000 ]; do
    candidate=$((20000 + (seed + attempt) % 30000))
    candidate_lease="$LEASE_ROOT/port-$candidate"
    if mkdir "$candidate_lease" 2>/dev/null; then
        if ! lsof -nP -iUDP:"$candidate" 2>/dev/null | grep -q UDP; then
            PORT=$candidate
            LEASE_DIR=$candidate_lease
            break
        fi
        rmdir "$candidate_lease" 2>/dev/null || true
    fi
    attempt=$((attempt + 1))
done
[ -n "$PORT" ] || { echo "FATAL: no UDP port available"; exit 1; }

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TMP_ROOT/server.key" -out "$TMP_ROOT/server.crt" \
    -days 1 -subj /CN=localhost >/dev/null 2>&1

wait_for_server()
{
    local deadline=$((SECONDS + SERVER_TIMEOUT_SEC))
    while [ "$SECONDS" -lt "$deadline" ]; do
        kill -0 "$SERVER_PID" 2>/dev/null || return 1
        lsof -nP -a -p "$SERVER_PID" -iUDP:"$PORT" 2>/dev/null \
            | grep -q UDP && return 0
        sleep 0.05
    done
    return 1
}

run_client_with_deadline()
{
    "$@" &
    local child=$!
    local deadline=$((SECONDS + CLIENT_TIMEOUT_SEC))
    while kill -0 "$child" 2>/dev/null; do
        if [ "$SECONDS" -ge "$deadline" ]; then
            kill "$child" 2>/dev/null || true
            sleep 0.1
            kill -KILL "$child" 2>/dev/null || true
            wait "$child" 2>/dev/null || true
            return 124
        fi
        sleep 0.05
    done
    wait "$child"
}

dump_logs()
{
    local dir="$1"
    echo "--- server.out ---"
    tail -n 160 "$dir/server.out" 2>/dev/null || true
    echo "--- client.out ---"
    tail -n 160 "$dir/client.out" 2>/dev/null || true
    echo "--- interop_clog ---"
    tail -n 160 "$dir/interop_clog" 2>/dev/null || true
    echo "--- slog ---"
    tail -n 160 "$dir/slog" 2>/dev/null || true
}

run_case()
{
    local case_name="$1"
    local mode="$2"
    shift 2
    local dir="$TMP_ROOT/$case_name"
    mkdir -p "$dir"
    cp "$TMP_ROOT/server.key" "$dir/server.key"
    cp "$TMP_ROOT/server.crt" "$dir/server.crt"
    (
        cd "$dir" || exit 1
        exec "$SERVER" -l d -p "$PORT" -n 2 -Q "$mode"
    ) >"$dir/server.out" 2>&1 &
    SERVER_PID=$!
    if ! wait_for_server; then
        dump_logs "$dir"
        return 1
    fi
    (
        cd "$dir" || exit 1
        run_client_with_deadline "$CLIENT" \
            --relay "moqt://127.0.0.1:$PORT" --sni localhost \
            --tls-disable-verify --verbose --test "$case_name"
    ) >"$dir/client.out" 2>&1
    local status=$?
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=
    if [ "$status" -ne 0 ] \
        || ! grep -Fqx "ok 1 - $case_name" "$dir/client.out"
    then
        dump_logs "$dir"
        return 1
    fi
    local marker
    for marker in "$@"; do
        if ! grep -Fqx "$marker" "$dir/client.out" "$dir/server.out"; then
            echo "missing exact semantic marker: $marker"
            dump_logs "$dir"
            return 1
        fi
    done
    if grep -Eq \
        "PROTOCOL_VIOLATION|conn_err:-?[1-9][0-9]*|invalid draft-18 message stream placement" \
        "$dir/interop_clog" "$dir/slog" 2>/dev/null
    then
        dump_logs "$dir"
        return 1
    fi
}

report_case()
{
    local description="$1"
    shift
    printf "  %-68s " "$description"
    if run_case "$@"; then
        echo PASS
        PASS=$((PASS + 1))
    else
        echo FAIL
        FAIL=$((FAIL + 1))
    fi
}

report_case "TRACK_STATUS -> REQUEST_OK(Properties) -> peer FIN" \
    track-status-success 7 \
    "control_e2e|track_status_ok|request_id:0|properties:0201|generic_ok:1" \
    "control_e2e|finite_request_complete|case:track-status-success|request_id:0|response_received:1|peer_fin:1|closed_notified:1" \
    "control_e2e_server|track_status_response|request_id:0|result:ok|properties:0201|ret:0|fin:1|closed:1"

report_case "TRACK_STATUS -> REQUEST_ERROR -> peer FIN" \
    track-status-rejection 8 \
    "control_e2e|finite_request_error|case:track-status-rejection|request_id:0|code:0x10|retry:0" \
    "control_e2e|finite_request_complete|case:track-status-rejection|request_id:0|response_received:1|peer_fin:1|closed_notified:1" \
    "control_e2e_server|track_status_response|request_id:0|result:error|properties:none|ret:0|fin:1|closed:1"

report_case "FETCH -> FETCH_OK -> Objects/Properties/Range + FIN" \
    fetch-success 9 \
    "control_e2e|fetch_ok|request_id:0|end_of_track:1|end:6/9|properties:0201" \
    "control_e2e|fetch_header|request_id:0|fin:0" \
    "control_e2e|fetch_object|index:0|location:2/3/4|payload:7|properties:2" \
    "control_e2e|fetch_object|index:1|location:2/3/5|payload:0|properties:0" \
    "control_e2e|fetch_object|index:2|location:4/4/0|payload:7|properties:0" \
    "control_e2e|fetch_range|location:6/9|unknown:1|eos:1" \
    "control_e2e|finite_request_complete|case:fetch-success|request_id:0|response_received:1|data_fin:1|closed_notified:1" \
    "control_e2e_server|fetch_response|request_id:0|result:ok|end:6/9|fetch_ok_ret:0|fetch_header_ret:0|objects:0,0,0|range:0|fin:1|closed:1"

report_case "FETCH -> REQUEST_ERROR -> peer FIN" \
    fetch-rejection 10 \
    "control_e2e|finite_request_error|case:fetch-rejection|request_id:0|code:0x10|retry:0" \
    "control_e2e|finite_request_complete|case:fetch-rejection|request_id:0|response_received:1|peer_fin:1|closed_notified:1" \
    "control_e2e_server|fetch_response|request_id:0|result:error|end:none|fetch_ok_ret:0|fetch_header_ret:not-sent|fin:1|closed:1"

echo "draft18 fetch/track-status e2e: pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ] && [ "$PASS" -eq 4 ]
