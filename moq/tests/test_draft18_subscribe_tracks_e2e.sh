#!/bin/bash
#
# Paired Native QUIC coverage for draft-ietf-moq-transport-18
# SUBSCRIBE_TRACKS discovery and PUBLISH request streams.
#
# Usage: ./test_draft18_subscribe_tracks_e2e.sh <build/moq/demo>

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
PORT=$((11100 + RANDOM % 100))
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
    local suite_dir="$TEST_TMPDIR/subscribe-tracks"
    mkdir -p "$suite_dir"
    cp "$TEST_TMPDIR/server.key" "$suite_dir/server.key"
    cp "$TEST_TMPDIR/server.crt" "$suite_dir/server.crt"

    (
        cd "$suite_dir" || exit 1
        "$SERVER" -l d -p "$PORT" -n 2 \
            >server.out 2>&1 &
        server_pid=$!
        sleep 1
        if ! kill -0 "$server_pid" 2>/dev/null; then
            cat server.out
            return 1
        fi

        timeout "$CLIENT_TIMEOUT_SEC" "$CLIENT" \
            --relay "moqt://127.0.0.1:$PORT" \
            --sni localhost --tls-disable-verify --verbose \
            --test "subscribe-tracks-publish,subscribe-tracks-overlap" \
            >client.out 2>&1
        client_status=$?

        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true

        if [ "$client_status" -ne 0 ] \
            || ! grep -q "^ok 1 - subscribe-tracks-publish$" client.out \
            || ! grep -q "^ok 2 - subscribe-tracks-overlap$" client.out
        then
            cat server.out
            cat client.out
            [ ! -f interop_clog ] || grep -E \
                "SUBSCRIBE_TRACKS|PUBLISH|REQUEST|request_|msg_type" \
                interop_clog | tail -n 100
            [ ! -f slog ] || grep -E \
                "SUBSCRIBE_TRACKS|PUBLISH|REQUEST|request_|msg_type" \
                slog | tail -n 100
            return 1
        fi

        for protocol_log in interop_clog slog; do
            if [ -f "$protocol_log" ] \
                && grep -Eq \
                    "PROTOCOL_VIOLATION|conn_err:3|invalid draft-18 message stream placement" \
                    "$protocol_log"
            then
                cat server.out
                tail -n 100 "$protocol_log"
                return 1
            fi
        done
    )
}

if run_suite; then
    printf "  %-62s PASS\n" \
        "draft18 root SUBSCRIBE_TRACKS -> PUBLISH -> REQUEST_OK"
    printf "  %-62s PASS\n" \
        "draft18 SUBSCRIBE_TRACKS overlap -> PREFIX_OVERLAP"
    PASS=2
else
    printf "  %-62s FAIL\n" \
        "draft18 root SUBSCRIBE_TRACKS -> PUBLISH -> REQUEST_OK"
    printf "  %-62s FAIL\n" \
        "draft18 SUBSCRIBE_TRACKS overlap -> PREFIX_OVERLAP"
    FAIL=2
fi

echo "draft18 subscribe tracks e2e: pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
