#!/bin/bash
#
# Paired Native QUIC cases for draft-ietf-moq-transport-18 Sections 6.1
# and 10.18 namespace response-stream behavior.
#
# Usage: ./test_draft18_namespace_response_e2e.sh <build/moq/demo>

BUILD_DIR="$(cd "${1:?Usage: $0 <build/moq/demo>}" && pwd)"
SERVER="$BUILD_DIR/moq_demo_server"
CLIENT="$BUILD_DIR/moq_interop_client"
CLIENT_TIMEOUT_SEC=${MOQ_D18_E2E_CLIENT_TIMEOUT_SEC:-60}

case "$CLIENT_TIMEOUT_SEC" in
    ''|*[!0-9]*|0)
        echo "FATAL: invalid MOQ_D18_E2E_CLIENT_TIMEOUT_SEC=$CLIENT_TIMEOUT_SEC"
        exit 1
        ;;
esac
PORT=$((10900 + RANDOM % 100))
PASS=0
FAIL=0
TEST_TMPDIR=$(mktemp -d)

cleanup()
{
    kill $(jobs -p) 2>/dev/null || true
    rm -rf "$TEST_TMPDIR"
}

trap cleanup EXIT

for executable in "$SERVER" "$CLIENT"; do
    if [ ! -x "$executable" ]; then
        echo "FATAL: $executable not found"
        exit 1
    fi
done

RUNTIME_BIN_DIR="$TEST_TMPDIR/bin"
mkdir -p "$RUNTIME_BIN_DIR"
cp "$SERVER" "$RUNTIME_BIN_DIR/moq_demo_server"
cp "$CLIENT" "$RUNTIME_BIN_DIR/moq_interop_client"
SERVER="$RUNTIME_BIN_DIR/moq_demo_server"
CLIENT="$RUNTIME_BIN_DIR/moq_interop_client"

command -v openssl >/dev/null 2>&1 \
    || { echo "FATAL: openssl not found"; exit 1; }
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TEST_TMPDIR/server.key" \
    -out "$TEST_TMPDIR/server.crt" \
    -days 1 -subj "/CN=localhost" >/dev/null 2>&1

run_suite()
{
    local base_dir="$TEST_TMPDIR/base"
    local notify_dir="$TEST_TMPDIR/notifications"
    local notify_port=$((PORT + 1))
    local client_dir="$TEST_TMPDIR/client"
    mkdir -p "$base_dir" "$notify_dir" "$client_dir"
    for server_dir in "$base_dir" "$notify_dir"; do
        cp "$TEST_TMPDIR/server.key" "$server_dir/server.key"
        cp "$TEST_TMPDIR/server.crt" "$server_dir/server.crt"
    done

    (
        cd "$base_dir" || exit 1
        exec "$SERVER" -l d -p "$PORT" -n 2 -K 0
    ) >"$base_dir/server.out" 2>&1 &
    local base_pid=$!
    (
        cd "$notify_dir" || exit 1
        exec "$SERVER" -l d -p "$notify_port" -n 2 -K 4
    ) >"$notify_dir/server.out" 2>&1 &
    local notify_pid=$!

    sleep 1
    if ! kill -0 "$base_pid" 2>/dev/null \
        || ! kill -0 "$notify_pid" 2>/dev/null
    then
        cat "$base_dir/server.out" "$notify_dir/server.out"
        kill "$base_pid" "$notify_pid" 2>/dev/null || true
        wait "$base_pid" "$notify_pid" 2>/dev/null || true
        return 1
    fi

    (
        cd "$client_dir" || exit 1
        timeout "$CLIENT_TIMEOUT_SEC" "$CLIENT" \
            --relay "moqt://127.0.0.1:$PORT" \
            --sni localhost --tls-disable-verify --verbose \
            --test "subscribe-namespace-ok,subscribe-namespace-overlap,subscribe-namespace-notifications@$notify_port" \
            >client.out 2>&1
    )
    local client_status=$?

    kill "$base_pid" "$notify_pid" 2>/dev/null || true
    wait "$base_pid" "$notify_pid" 2>/dev/null || true

    if [ "$client_status" -ne 0 ] \
        || ! grep -q '^ok 1 - subscribe-namespace-ok$' "$client_dir/client.out" \
        || ! grep -q '^ok 2 - subscribe-namespace-overlap$' "$client_dir/client.out" \
        || ! grep -q '^ok 3 - subscribe-namespace-notifications$' "$client_dir/client.out"
    then
        cat "$base_dir/server.out" "$notify_dir/server.out" \
            "$client_dir/client.out"
        [ ! -f "$client_dir/interop_clog" ] \
            || tail -n 100 "$client_dir/interop_clog"
        return 1
    fi

    for protocol_log in "$client_dir/interop_clog" \
        "$base_dir/slog" "$notify_dir/slog"
    do
        if [ -f "$protocol_log" ] \
            && grep -Eq \
                "PROTOCOL_VIOLATION|conn_err:3|invalid draft-18 message stream placement" \
                "$protocol_log"
        then
            tail -n 100 "$protocol_log"
            return 1
        fi
    done
}

if run_suite; then
    printf "  %-58s PASS\n" \
        "draft18 namespace REQUEST_OK on request stream"
    printf "  %-58s PASS\n" \
        "draft18 namespace overlap REQUEST_ERROR 0x30"
    printf "  %-58s PASS\n" \
        "draft18 NAMESPACE/DONE on accepted response stream"
    PASS=3
else
    printf "  %-58s FAIL\n" \
        "draft18 namespace REQUEST_OK on request stream"
    printf "  %-58s FAIL\n" \
        "draft18 namespace overlap REQUEST_ERROR 0x30"
    printf "  %-58s FAIL\n" \
        "draft18 NAMESPACE/DONE on accepted response stream"
    FAIL=3
fi

echo "draft18 namespace response e2e: pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
