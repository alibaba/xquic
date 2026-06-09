#!/bin/bash
# SUBSCRIBE_NAMESPACE e2e test suite
# Tests SUBSCRIBE_NAMESPACE (0x11), SUBSCRIBE_NAMESPACE_OK (0x12),
# SUBSCRIBE_NAMESPACE_ERROR (0x13), UNSUBSCRIBE_NAMESPACE (0x14)
#
# Usage: ./test_subscribe_namespace_e2e.sh <build_dir>
# Example: ./test_subscribe_namespace_e2e.sh ../../build/moq/demo

BUILD_DIR="$(cd "${1:?Usage: $0 <build_dir>}" && pwd)"
SERVER="$BUILD_DIR/moq_demo_server"
CLIENT="$BUILD_DIR/moq_demo_client"
PORT=$((9900 + RANDOM % 100))
PASS=0
FAIL=0
TMPDIR=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMPDIR"' EXIT

run_test() {
    local name="$1"; shift
    printf "  %-65s " "$name"
    if "$@"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        FAIL=$((FAIL + 1))
    fi
}

assert_no_match() { grep -q "$1" "$2" && return 1 || return 0; }
assert_count_ge() {
    local pattern="$1" file="$2" min="$3"
    local count
    count=$(grep -c "$pattern" "$file" 2>/dev/null || echo 0)
    [ "$count" -ge "$min" ]
}

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
fi

echo "=== SUBSCRIBE_NAMESPACE E2E Tests ==="
echo ""

# ============================================================
# Test 1: Basic flow - client sends SUBSCRIBE_NAMESPACE, server replies OK
# Mode 1: single SUBSCRIBE_NAMESPACE with namespace=["namespace"]
# ============================================================
echo "--- Test 1: Basic SUBSCRIBE_NAMESPACE -> OK ---"
PORT=$((PORT + 1))
cd "$TMPDIR"
rm -f clog slog

"$SERVER" -l d -p $PORT -V -n 2 > srv1.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -N 1 > cli1.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "1a: server decoded SUBSCRIBE_NAMESPACE (0x11)" \
    grep -q "msg_type:0x11" slog
run_test "1b: server accepted namespace prefix" \
    grep -q "subscribe_namespace accepted" slog
run_test "1c: client received SUBSCRIBE_NAMESPACE_OK (0x12)" \
    grep -q "subscribe_namespace_ok" clog
run_test "1d: server sent OK with request_id=0" \
    grep -q "subscribe_namespace_ok.*request_id:0" clog
run_test "1e: no segfault in server" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv1.log
run_test "1f: no segfault in client" \
    assert_no_match "segfault\|SIGSEGV\|abort" cli1.log
run_test "1g: no protocol violation" \
    assert_no_match "PROTOCOL_VIOLATION\|conn_err:3" slog

echo ""

# ============================================================
# Test 2: Overlap rejection - two identical SUBSCRIBE_NAMESPACE
# Mode 2: sends request_id=0 then request_id=1 with same namespace
# Server should accept first, reject second with ERROR (0x13)
# ============================================================
echo "--- Test 2: Overlap rejection (identical namespace) ---"
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -n 2 > srv2.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -N 2 > cli2.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "2a: server decoded two SUBSCRIBE_NAMESPACE messages" \
    assert_count_ge "msg_type:0x11" slog 2
run_test "2b: server accepted first namespace prefix" \
    grep -q "subscribe_namespace accepted.*request_id:0" slog
run_test "2c: server detected overlap (no second accept)" \
    assert_no_match "subscribe_namespace accepted.*request_id:2" slog
run_test "2d: client received SUBSCRIBE_NAMESPACE_OK for first" \
    grep -q "subscribe_namespace_ok.*request_id:0" clog
run_test "2e: client received SUBSCRIBE_NAMESPACE_ERROR for second" \
    grep -q "subscribe_namespace_error" clog
run_test "2f: error has reason phrase 'namespace prefix overlap'" \
    grep -q "namespace prefix overlap" clog
run_test "2g: no segfault" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv2.log
run_test "2h: no protocol violation (overlap is not fatal)" \
    assert_no_match "PROTOCOL_VIOLATION\|conn_err:3" slog

echo ""

# ============================================================
# Test 3: UNSUBSCRIBE_NAMESPACE flow
# Mode 3: sends SUBSCRIBE_NAMESPACE then UNSUBSCRIBE_NAMESPACE
# ============================================================
echo "--- Test 3: SUBSCRIBE then UNSUBSCRIBE_NAMESPACE ---"
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -n 2 > srv3.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -N 3 > cli3.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "3a: server decoded SUBSCRIBE_NAMESPACE (0x11)" \
    grep -q "msg_type:0x11" slog
run_test "3b: server decoded UNSUBSCRIBE_NAMESPACE (0x14)" \
    grep -q "msg_type:0x14" slog
run_test "3c: server processed unsubscribe_namespace" \
    grep -q "unsubscribe_namespace" slog
run_test "3d: server accepted namespace before unsubscribe" \
    grep -q "subscribe_namespace accepted" slog
run_test "3e: client received OK before unsubscribe" \
    grep -q "subscribe_namespace_ok" clog
run_test "3f: no segfault" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv3.log
run_test "3g: no protocol violation" \
    assert_no_match "PROTOCOL_VIOLATION\|conn_err:3" slog

echo ""

# ============================================================
# Test 4: Multi-element namespace tuple
# Mode 4: sends SUBSCRIBE_NAMESPACE with tuple ["example.com", "live"]
# ============================================================
echo "--- Test 4: Multi-element namespace tuple ---"
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -n 2 > srv4.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -N 4 > cli4.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "4a: server decoded SUBSCRIBE_NAMESPACE (0x11)" \
    grep -q "msg_type:0x11" slog
run_test "4b: server accepted multi-element prefix (num=2)" \
    grep -q "subscribe_namespace accepted.*prefix_num:2" slog
run_test "4c: client received OK" \
    grep -q "subscribe_namespace_ok" clog
run_test "4d: no segfault" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv4.log
run_test "4e: no protocol violation" \
    assert_no_match "PROTOCOL_VIOLATION\|conn_err:3" slog

echo ""

# ============================================================
# Test 5: Two non-overlapping namespaces - both should succeed
# Mode 5: sends ["alpha"] then ["beta"] - different prefixes
# ============================================================
echo "--- Test 5: Two non-overlapping namespaces ---"
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -n 2 > srv5.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -N 5 > cli5.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "5a: server decoded two SUBSCRIBE_NAMESPACE messages" \
    assert_count_ge "msg_type:0x11" slog 2
run_test "5b: server accepted both prefixes" \
    assert_count_ge "subscribe_namespace accepted" slog 2
run_test "5c: client received two OKs" \
    assert_count_ge "subscribe_namespace_ok" clog 2
run_test "5d: no ERROR sent (no overlap)" \
    assert_no_match "subscribe_namespace_error" clog
run_test "5e: no segfault" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv5.log
run_test "5f: no protocol violation" \
    assert_no_match "PROTOCOL_VIOLATION\|conn_err:3" slog

echo ""

# ============================================================
# Test 6: Prefix overlap (parent/child namespace)
# Mode 6: sends ["example.com"] then ["example.com", "live"]
# The child is a subset of the parent prefix, so should overlap
# ============================================================
echo "--- Test 6: Prefix overlap (parent subsumes child) ---"
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -n 2 > srv6.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -N 6 > cli6.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "6a: server decoded two SUBSCRIBE_NAMESPACE messages" \
    assert_count_ge "msg_type:0x11" slog 2
run_test "6b: server accepted parent prefix (example.com)" \
    grep -q "subscribe_namespace accepted.*request_id:0" slog
run_test "6c: server rejected child (no second accept)" \
    assert_no_match "subscribe_namespace accepted.*request_id:2" slog
run_test "6d: client got ERROR for child" \
    grep -q "subscribe_namespace_error" clog
run_test "6e: error reason is 'namespace prefix overlap'" \
    grep -q "namespace prefix overlap" clog
run_test "6f: no segfault" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv6.log
run_test "6g: no protocol violation" \
    assert_no_match "PROTOCOL_VIOLATION\|conn_err:3" slog

echo ""

# ============================================================
# Test 7: Reverse overlap (child first, parent second)
# Mode 7: sends ["example.com","live"] then ["example.com"]
# Child is more specific; parent subsumes child → overlap
# ============================================================
echo "--- Test 7: Reverse overlap (child first, parent second) ---"
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -n 2 > srv7.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -N 7 > cli7.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "7a: server decoded two SUBSCRIBE_NAMESPACE messages" \
    assert_count_ge "msg_type:0x11" slog 2
run_test "7b: server accepted child prefix (example.com/live)" \
    grep -q "subscribe_namespace accepted.*request_id:0" slog
run_test "7c: server rejected parent (no second accept)" \
    assert_no_match "subscribe_namespace accepted.*request_id:2" slog
run_test "7d: client received OK for child" \
    grep -q "subscribe_namespace_ok.*request_id:0" clog
run_test "7e: client received ERROR for parent" \
    grep -q "subscribe_namespace_error" clog
run_test "7f: error reason is 'namespace prefix overlap'" \
    grep -q "namespace prefix overlap" clog
run_test "7g: no segfault" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv7.log
run_test "7h: no protocol violation" \
    assert_no_match "PROTOCOL_VIOLATION\|conn_err:3" slog

echo ""

# ============================================================
# Test 8: Unsubscribe then resubscribe same namespace
# Mode 8: subscribe → unsubscribe → resubscribe
# After unsubscribe, the prefix is removed and resubscribe should succeed
# ============================================================
echo "--- Test 8: Unsubscribe then resubscribe ---"
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -n 2 > srv8.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -N 8 > cli8.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "8a: server decoded two SUBSCRIBE_NAMESPACE messages" \
    assert_count_ge "msg_type:0x11" slog 2
run_test "8b: server decoded UNSUBSCRIBE_NAMESPACE (0x14)" \
    grep -q "msg_type:0x14" slog
run_test "8c: server accepted first subscribe (request_id=0)" \
    grep -q "subscribe_namespace accepted.*request_id:0" slog
run_test "8d: server accepted resubscribe (request_id=2)" \
    grep -q "subscribe_namespace accepted.*request_id:2" slog
run_test "8e: client received two OKs" \
    assert_count_ge "subscribe_namespace_ok" clog 2
run_test "8f: no ERROR (resubscribe should succeed)" \
    assert_no_match "subscribe_namespace_error" clog
run_test "8g: no segfault" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv8.log
run_test "8h: no protocol violation" \
    assert_no_match "PROTOCOL_VIOLATION\|conn_err:3" slog

echo ""

# ============================================================
# Test 9: Callback override (on_subscribe_namespace callback)
# Server uses -K flag to register custom callback
# When callback is set, default handler is bypassed (no auto OK/ERROR)
# ============================================================
echo "--- Test 9: Callback override ---"
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -K 1 -n 2 > srv9.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -N 9 > cli9.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "9a: server decoded SUBSCRIBE_NAMESPACE (0x11)" \
    grep -q "msg_type:0x11" slog
run_test "9b: custom callback was triggered" \
    grep -q "custom_subscribe_namespace_callback" srv9.log
run_test "9c: default handler did NOT send OK (callback overrides)" \
    assert_no_match "subscribe_namespace accepted" slog
run_test "9d: no segfault" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv9.log
run_test "9e: no protocol violation" \
    assert_no_match "PROTOCOL_VIOLATION\|conn_err:3" slog

echo ""

# ============================================================
# Test 10: Request ID reuse after overlap ERROR
# Mode 10: request_id=0 ["alpha"] -> OK
#           request_id=2 ["alpha"] -> ERROR (overlap)
#           request_id=2 ["beta"]  -> should be rejected (duplicate id)
# Bug fix: max_peer_ns_request_id must update in overlap path
# ============================================================
echo "--- Test 10: Request ID reuse after overlap ERROR ---"
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -n 2 > srv10.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -N 10 > cli10.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "10a: server accepted first subscribe (alpha)" \
    grep -q "subscribe_namespace accepted.*request_id:0" slog
run_test "10b: server detected overlap on second request" \
    grep -q "namespace prefix overlap" slog
run_test "10c: server rejected third (duplicate request_id=2)" \
    assert_no_match "subscribe_namespace accepted.*request_id:2" slog
run_test "10d: server detected duplicate request_id" \
    grep -q "duplicate subscribe_namespace request_id" slog
run_test "10e: server closed session with err:0x3" \
    grep -q "err:0x3" slog
run_test "10f: no segfault" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv10.log

echo ""

# ============================================================
# Test 11: Request ID parity error
# Mode 11: client sends odd request_id=1
# Server should close session with PROTOCOL_VIOLATION
# ============================================================
echo "--- Test 11: Request ID parity error ---"
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -n 2 > srv11.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -N 11 > cli11.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "11a: server decoded SUBSCRIBE_NAMESPACE" \
    grep -q "msg_type:0x11" slog
run_test "11b: server detected wrong parity" \
    grep -q "wrong request_id parity" slog
run_test "11c: server closed session with err:0x3" \
    grep -q "err:0x3" slog
run_test "11d: server did NOT accept the request" \
    assert_no_match "subscribe_namespace accepted" slog
run_test "11e: no segfault" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv11.log

echo ""

# ============================================================
# Test 12: Unsubscribe non-existent namespace
# Mode 12: subscribe ["alpha"] -> OK
#           unsubscribe ["nonexistent"] -> no-op
#           subscribe ["alpha","child"] -> ERROR overlap (proves alpha still there)
# ============================================================
echo "--- Test 12: Unsubscribe non-existent namespace ---"
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -n 2 > srv12.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -N 12 > cli12.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "12a: server accepted first subscribe (alpha)" \
    grep -q "subscribe_namespace accepted.*request_id:0" slog
run_test "12b: server got unsubscribe for nonexistent" \
    grep -q "unsubscribe_namespace prefix not found" slog
run_test "12c: server rejected alpha/child (overlap proves alpha still registered)" \
    grep -q "subscribe_namespace_error" clog
run_test "12d: overlap error (not other error)" \
    grep -q "namespace prefix overlap" clog
run_test "12e: no segfault" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv12.log
run_test "12f: no protocol violation" \
    assert_no_match "PROTOCOL_VIOLATION\|conn_err:3" slog

echo ""

# ============================================================
# Test 13: Unsubscribe child does not delete parent
# Mode 13: subscribe ["a"] -> OK
#           unsubscribe ["a","child"] (never subscribed) -> no-op
#           subscribe ["a","child"] -> ERROR overlap (proves parent ["a"] still there)
# ============================================================
echo "--- Test 13: Unsubscribe child does not delete parent ---"
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -n 2 > srv13.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -N 13 > cli13.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "13a: server accepted first subscribe ([a])" \
    grep -q "subscribe_namespace accepted.*request_id:0" slog
run_test "13b: unsubscribe [a,child] did not find match" \
    grep -q "unsubscribe_namespace prefix not found" slog
run_test "13c: server rejected [a,child] subscribe (overlap with [a])" \
    grep -q "subscribe_namespace_error" clog
run_test "13d: overlap error reason" \
    grep -q "namespace prefix overlap" clog
run_test "13e: no segfault" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv13.log
run_test "13f: no protocol violation" \
    assert_no_match "PROTOCOL_VIOLATION\|conn_err:3" slog

echo ""

# ============================================================
# Test 14: Server sends OK with wrong request_id
# Server -K 2: callback sends OK(request_id + 100)
# Client should detect unknown request_id -> PROTOCOL_VIOLATION
# ============================================================
echo "--- Test 14: Wrong request_id in OK response ---"
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -K 2 -n 2 > srv14.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -N 14 > cli14.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "14a: server decoded SUBSCRIBE_NAMESPACE" \
    grep -q "msg_type:0x11" slog
run_test "14b: server callback sent wrong-id OK" \
    grep -q "ns_callback_wrong_id" srv14.log
run_test "14c: client detected unknown request_id" \
    grep -q "subscribe_namespace_ok unknown request_id" clog
run_test "14d: client closed session with err:0x3" \
    grep -q "err:0x3" clog
run_test "14e: no segfault" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv14.log
run_test "14f: no segfault on client" \
    assert_no_match "segfault\|SIGSEGV\|abort" cli14.log

echo ""

# ============================================================
# Test 15: Server sends duplicate OK
# Server -K 3: callback sends OK(request_id) twice
# Client should accept first, reject second as unknown
# ============================================================
echo "--- Test 15: Duplicate OK response ---"
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -K 3 -n 2 > srv15.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -N 15 > cli15.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "15a: server decoded SUBSCRIBE_NAMESPACE" \
    grep -q "msg_type:0x11" slog
run_test "15b: server callback sent duplicate OK" \
    grep -q "ns_callback_dup_ok" srv15.log
run_test "15c: client accepted first OK" \
    grep -q "subscribe_namespace_ok.*request_id:0" clog
run_test "15d: client detected duplicate (unknown request_id)" \
    grep -q "subscribe_namespace_ok unknown request_id" clog
run_test "15e: client closed session with err:0x3" \
    grep -q "err:0x3" clog
run_test "15f: no segfault" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv15.log

echo ""

# ============================================================
# Test 16: Callback mode still enforces protocol validation
# Server -K 1 (callback override) + Client -N 11 (odd request_id)
# Protocol checks (parity) must run BEFORE callback dispatch
# ============================================================
echo "--- Test 16: Callback mode + parity error ---"
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -K 1 -n 2 > srv16.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -N 11 > cli16.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "16a: server decoded SUBSCRIBE_NAMESPACE" \
    grep -q "msg_type:0x11" slog
run_test "16b: server detected wrong parity before callback" \
    grep -q "wrong request_id parity" slog
run_test "16c: callback was NOT invoked (blocked by validation)" \
    assert_no_match "custom_subscribe_namespace_callback" srv16.log
run_test "16d: server closed session with err:0x3" \
    grep -q "err:0x3" slog
run_test "16e: no segfault" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv16.log

echo ""

# ============================================================
# Test 17: PUBLISH forwarding after SUBSCRIBE_NAMESPACE_OK
# Mode 1: client subscribes namespace ["namespace"], server has tracks
# video and audio registered. After OK, server should forward PUBLISH
# messages for matching tracks to the client.
# ============================================================
echo "--- Test 17: PUBLISH forwarding after SUBSCRIBE_NAMESPACE_OK ---"
PORT=$((PORT + 1))
rm -f clog slog

"$SERVER" -l d -p $PORT -V -n 2 > srv17.log 2>&1 &
SRV_PID=$!
sleep 2

timeout 8 "$CLIENT" -a 127.0.0.1 -p $PORT -l d -V -N 1 > cli17.log 2>&1 || true

kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null || true

run_test "17a: server decoded SUBSCRIBE_NAMESPACE (0x11)" \
    grep -q "msg_type:0x11" slog
run_test "17b: server accepted namespace prefix" \
    grep -q "subscribe_namespace accepted" slog
run_test "17c: server forwarded PUBLISH for video" \
    grep -q "forward_matching_publish|track:video" slog
run_test "17d: server forwarded PUBLISH for audio" \
    grep -q "forward_matching_publish|track:audio" slog
run_test "17e: client received PUBLISH for video track" \
    grep -q "on_publish.*track:namespace/video" clog
run_test "17f: client received PUBLISH for audio track" \
    grep -q "on_publish.*track:namespace/audio" clog
run_test "17g: client received SUBSCRIBE_NAMESPACE_OK" \
    grep -q "subscribe_namespace_ok" clog
run_test "17h: no segfault in server" \
    assert_no_match "segfault\|SIGSEGV\|abort" srv17.log
run_test "17i: no segfault in client" \
    assert_no_match "segfault\|SIGSEGV\|abort" cli17.log
run_test "17j: no protocol violation" \
    assert_no_match "PROTOCOL_VIOLATION\|conn_err:3" slog

echo ""

# ============================================================
# Summary
# ============================================================
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
