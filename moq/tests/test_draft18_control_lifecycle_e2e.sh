#!/bin/bash
#
# Paired Native QUIC coverage for the draft-18 control lifecycle.
#
# Usage: ./test_draft18_control_lifecycle_e2e.sh <build/moq/demo>

BUILD_DIR="$(cd "${1:?Usage: $0 <build/moq/demo>}" && pwd)"
SERVER="$BUILD_DIR/moq_demo_server"
CLIENT="$BUILD_DIR/moq_interop_client"
EXPLICIT_BASE_PORT=${BASE_PORT:-}
BASE_PORT=
PASS=0
FAIL=0
TEST_TMPDIR=$(mktemp -d)
SERVER_PIDS=""
CASE_FILTER=${CASE_FILTER:-}
VALID_CASES="request-update-success request-update-overlap publish-blocked publish-done control-goaway request-goaway"
CASE_CONNECTIONS=${CASE_CONNECTIONS:-1}
IMMEDIATE_DISCONNECT_ONLY=${IMMEDIATE_DISCONNECT_ONLY:-0}
LIFECYCLE_ACTION_DELAY_MS=${LIFECYCLE_ACTION_DELAY_MS:-400}
HARNESS_SELFTEST=${HARNESS_SELFTEST:-}
FORCE_BASH_WATCHDOG=${FORCE_BASH_WATCHDOG:-0}
CLIENT_TIMEOUT_SEC=${MOQ_D18_E2E_CLIENT_TIMEOUT_SEC:-60}
SERVER_TIMEOUT_SEC=${MOQ_D18_E2E_SERVER_TIMEOUT_SEC:-60}
PORT_LEASE_ONLY=${PORT_LEASE_ONLY:-0}
PORT_LEASE_HOLD_SEC=${PORT_LEASE_HOLD_SEC:-0}
PORT_LEASE_ROOT=${PORT_LEASE_ROOT:-${TMPDIR:-/tmp}/xquic-moq-d18-control-port-leases-${UID:-user}}
PORT_LEASE_DIR=
PORT_LEASE_DIRS=()
TIMEOUT_BACKEND=
LAST_TIMEOUT_CHILD_PID=
LAST_TIMEOUT_WATCHDOG_PID=
ACTIVE_TIMEOUT_CHILD_PID=
ACTIVE_TIMEOUT_WATCHDOG_PID=

track_server()
{
    SERVER_PIDS="$SERVER_PIDS $1"
}

untrack_server()
{
    local stopped_pid="$1"
    local remaining_pids=""
    local tracked_pid
    for tracked_pid in $SERVER_PIDS; do
        if [ "$tracked_pid" != "$stopped_pid" ]; then
            remaining_pids="$remaining_pids $tracked_pid"
        fi
    done
    SERVER_PIDS="$remaining_pids"
}

cleanup()
{
    local owned_pids="$SERVER_PIDS"
    local timeout_child_pid="$ACTIVE_TIMEOUT_CHILD_PID"
    local timeout_watchdog_pid="$ACTIVE_TIMEOUT_WATCHDOG_PID"
    local server_pid
    SERVER_PIDS=""
    ACTIVE_TIMEOUT_CHILD_PID=
    ACTIVE_TIMEOUT_WATCHDOG_PID=
    if [ -n "$timeout_watchdog_pid" ]; then
        kill "$timeout_watchdog_pid" 2>/dev/null || true
    fi
    if [ -n "$timeout_child_pid" ]; then
        kill "$timeout_child_pid" 2>/dev/null || true
    fi
    if [ -n "$timeout_watchdog_pid" ]; then
        wait "$timeout_watchdog_pid" 2>/dev/null || true
    fi
    if [ -n "$timeout_child_pid" ]; then
        wait "$timeout_child_pid" 2>/dev/null || true
    fi
    for server_pid in $owned_pids; do
        kill "$server_pid" 2>/dev/null || true
    done
    for server_pid in $owned_pids; do
        wait "$server_pid" 2>/dev/null || true
    done
    release_port_lease
    rm -rf "$TEST_TMPDIR"
}

release_port_lease()
{
    local lease_dir
    local owned_lease_dirs=("${PORT_LEASE_DIRS[@]}")
    PORT_LEASE_DIRS=()
    PORT_LEASE_DIR=
    for lease_dir in "${owned_lease_dirs[@]}"; do
        rmdir "$lease_dir" 2>/dev/null || true
    done
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -n "$CASE_FILTER" ]; then
    case " $VALID_CASES " in
        *" $CASE_FILTER "*) ;;
        *)
            echo "FATAL: invalid CASE_FILTER=$CASE_FILTER; expected one of: $VALID_CASES"
            exit 1
            ;;
    esac
fi
case "$CASE_CONNECTIONS" in
    ''|*[!0-9]*|0)
        echo "FATAL: invalid CASE_CONNECTIONS=$CASE_CONNECTIONS; expected a positive integer"
        exit 1
        ;;
esac
case "$CLIENT_TIMEOUT_SEC" in
    ''|*[!0-9]*|0)
        echo "FATAL: invalid MOQ_D18_E2E_CLIENT_TIMEOUT_SEC=$CLIENT_TIMEOUT_SEC"
        exit 1
        ;;
esac
case "$SERVER_TIMEOUT_SEC" in
    ''|*[!0-9]*|0)
        echo "FATAL: invalid MOQ_D18_E2E_SERVER_TIMEOUT_SEC=$SERVER_TIMEOUT_SEC"
        exit 1
        ;;
esac
if [ "$IMMEDIATE_DISCONNECT_ONLY" = 1 ]; then
    case "$LIFECYCLE_ACTION_DELAY_MS" in
        ''|*[!0-9]*|0)
            echo "FATAL: invalid LIFECYCLE_ACTION_DELAY_MS=$LIFECYCLE_ACTION_DELAY_MS"
            exit 1
            ;;
    esac
    if [ "$LIFECYCLE_ACTION_DELAY_MS" -gt 5000 ]; then
        echo "FATAL: LIFECYCLE_ACTION_DELAY_MS must not exceed 5000"
        exit 1
    fi
fi

run_with_bash_watchdog()
{
    local timeout_seconds="$1"
    shift
    local timeout_marker="$TEST_TMPDIR/timeout.$RANDOM.$RANDOM"

    "$@" &
    local child_pid=$!
    LAST_TIMEOUT_CHILD_PID="$child_pid"
    ACTIVE_TIMEOUT_CHILD_PID="$child_pid"
    (
        local watchdog_sleep_pid=
        cleanup_watchdog_sleep()
        {
            if [ -n "$watchdog_sleep_pid" ]; then
                kill "$watchdog_sleep_pid" 2>/dev/null || true
                wait "$watchdog_sleep_pid" 2>/dev/null || true
            fi
        }
        trap cleanup_watchdog_sleep EXIT
        trap 'exit 0' INT TERM
        sleep "$timeout_seconds" &
        watchdog_sleep_pid=$!
        wait "$watchdog_sleep_pid" 2>/dev/null || exit 0
        watchdog_sleep_pid=
        if kill -0 "$child_pid" 2>/dev/null; then
            : >"$timeout_marker"
            kill -TERM "$child_pid" 2>/dev/null || true
            sleep 0.1
            kill -KILL "$child_pid" 2>/dev/null || true
        fi
    ) &
    local watchdog_pid=$!
    LAST_TIMEOUT_WATCHDOG_PID="$watchdog_pid"
    ACTIVE_TIMEOUT_WATCHDOG_PID="$watchdog_pid"

    wait "$child_pid" 2>/dev/null
    local child_status=$?
    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
    ACTIVE_TIMEOUT_CHILD_PID=
    ACTIVE_TIMEOUT_WATCHDOG_PID=
    if [ -f "$timeout_marker" ]; then
        rm -f "$timeout_marker"
        return 124
    fi
    return "$child_status"
}

run_with_timeout()
{
    local timeout_seconds="$1"
    shift
    if [ "$FORCE_BASH_WATCHDOG" != 1 ] \
        && command -v timeout >/dev/null 2>&1
    then
        TIMEOUT_BACKEND=timeout
        timeout "$timeout_seconds" "$@"
        return $?
    fi
    if [ "$FORCE_BASH_WATCHDOG" != 1 ] \
        && command -v gtimeout >/dev/null 2>&1
    then
        TIMEOUT_BACKEND=gtimeout
        gtimeout "$timeout_seconds" "$@"
        return $?
    fi
    TIMEOUT_BACKEND=bash
    run_with_bash_watchdog "$timeout_seconds" "$@"
}

if [ "$HARNESS_SELFTEST" = bash-watchdog ]; then
    run_with_timeout 1 sleep 5
    timeout_status=$?
    child_clean=0
    watchdog_clean=0
    kill -0 "$LAST_TIMEOUT_CHILD_PID" 2>/dev/null || child_clean=1
    kill -0 "$LAST_TIMEOUT_WATCHDOG_PID" 2>/dev/null || watchdog_clean=1
    printf 'timeout_selftest|backend:%s|status:%s|child_clean:%s|watchdog_clean:%s\n' \
        "$TIMEOUT_BACKEND" "$timeout_status" "$child_clean" "$watchdog_clean"
    [ "$timeout_status" -eq 124 ] \
        && [ "$child_clean" -eq 1 ] \
        && [ "$watchdog_clean" -eq 1 ]
    exit $?
fi

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

for required_command in openssl lsof; do
    command -v "$required_command" >/dev/null 2>&1 \
        || { echo "FATAL: $required_command not found"; exit 1; }
done

six_udp_ports_available()
{
    local candidate="$1"
    local offset=0
    while [ "$offset" -lt 6 ]; do
        if lsof -nP -iUDP:"$((candidate + offset))" 2>/dev/null \
            | grep -q "UDP"
        then
            return 1
        fi
        offset=$((offset + 1))
    done
    return 0
}

try_lease_six_ports()
{
    local candidate="$1"
    case "$candidate" in
        ''|*[!0-9]*) return 2 ;;
    esac
    if [ "$candidate" -lt 1024 ] || [ "$candidate" -gt 65530 ]; then
        return 2
    fi

    local acquired_dirs=()
    local offset=0
    local lease_dir
    while [ "$offset" -lt 6 ]; do
        lease_dir="$PORT_LEASE_ROOT/port-$((candidate + offset))"
        if ! mkdir "$lease_dir" 2>/dev/null; then
            local acquired_dir
            for acquired_dir in "${acquired_dirs[@]}"; do
                rmdir "$acquired_dir" 2>/dev/null || true
            done
            return 1
        fi
        acquired_dirs+=("$lease_dir")
        offset=$((offset + 1))
    done
    if ! six_udp_ports_available "$candidate"; then
        local acquired_dir
        for acquired_dir in "${acquired_dirs[@]}"; do
            rmdir "$acquired_dir" 2>/dev/null || true
        done
        return 1
    fi

    BASE_PORT="$candidate"
    PORT_LEASE_DIRS=("${acquired_dirs[@]}")
    PORT_LEASE_DIR="${PORT_LEASE_DIRS[0]}"
    return 0
}

mkdir -p "$PORT_LEASE_ROOT" \
    || { echo "FATAL: cannot create port lease root: $PORT_LEASE_ROOT"; exit 1; }

if [ -n "$EXPLICIT_BASE_PORT" ]; then
    try_lease_six_ports "$EXPLICIT_BASE_PORT"
    lease_status=$?
    if [ "$lease_status" -eq 2 ]; then
        echo "FATAL: invalid BASE_PORT=$EXPLICIT_BASE_PORT; expected 1024..65530"
        exit 1
    fi
    if [ "$lease_status" -ne 0 ]; then
        echo "FATAL: cannot lease BASE_PORT=$EXPLICIT_BASE_PORT range; lease conflict or UDP port in use"
        exit 1
    fi
else
    lease_seed=$(($$ % 5000))
    lease_attempt=0
    while [ "$lease_attempt" -lt 5000 ]; do
        lease_index=$(((lease_seed + lease_attempt) % 5000))
        lease_candidate=$((11600 + lease_index * 6))
        if try_lease_six_ports "$lease_candidate"; then
            break
        fi
        lease_attempt=$((lease_attempt + 1))
    done
    if [ -z "$PORT_LEASE_DIR" ]; then
        echo "FATAL: no free coordinated six-port range available"
        exit 1
    fi
fi

if [ "$PORT_LEASE_ONLY" = 1 ]; then
    if [ -z "$PORT_LEASE_DIR" ] || [ ! -d "$PORT_LEASE_DIR" ]; then
        echo "FATAL: coordinated six-port lease is not active"
        exit 1
    fi
    printf 'port_lease|base_port:%s|count:6|lease_dir:%s\n' \
        "$BASE_PORT" "$PORT_LEASE_DIR"
    sleep "$PORT_LEASE_HOLD_SEC"
    exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TEST_TMPDIR/server.key" \
    -out "$TEST_TMPDIR/server.crt" \
    -days 1 -subj "/CN=localhost" >/dev/null 2>&1

dump_case_logs()
{
    local case_dir="$1"
    echo "--- server.out ---"
    [ ! -f "$case_dir/server.out" ] || tail -n 160 "$case_dir/server.out"
    echo "--- client.out ---"
    for client_log in "$case_dir"/client.*.out; do
        [ ! -f "$client_log" ] || tail -n 160 "$client_log"
    done
    for protocol_log in interop_clog slog; do
        if [ -f "$case_dir/$protocol_log" ]; then
            echo "--- $protocol_log (control lifecycle) ---"
            grep -E \
                "REQUEST_UPDATE|REQUEST_(OK|ERROR)|PUBLISH_(BLOCKED|DONE)|GOAWAY|request_|msg_type|PROTOCOL_VIOLATION|conn_err" \
                "$case_dir/$protocol_log" | tail -n 160 || true
        fi
    done
}

wait_for_server()
{
    local server_pid="$1"
    local port="$2"
    local deadline=$((SECONDS + SERVER_TIMEOUT_SEC))
    while [ "$SECONDS" -lt "$deadline" ]; do
        kill -0 "$server_pid" 2>/dev/null || return 1
        if lsof -nP -a -p "$server_pid" -iUDP:"$port" 2>/dev/null \
            | grep -q "UDP"
        then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

fail_server_readiness()
{
    local case_dir="$1"
    local port="$2"
    if grep -Fq "bind socket failed" "$case_dir/server.out" 2>/dev/null; then
        echo "FATAL: server failed to bind UDP port $port after lease; availability changed before bind"
    else
        echo "FATAL: server did not become ready on UDP port $port"
    fi
    release_port_lease
    dump_case_logs "$case_dir"
}

stop_server()
{
    local server_pid="$1"
    kill "$server_pid" 2>/dev/null || true
    local attempt=0
    while kill -0 "$server_pid" 2>/dev/null && [ "$attempt" -lt 50 ]; do
        attempt=$((attempt + 1))
        sleep 0.02
    done
    if kill -0 "$server_pid" 2>/dev/null; then
        kill -KILL "$server_pid" 2>/dev/null || true
    fi
    wait "$server_pid" 2>/dev/null || true
    untrack_server "$server_pid"
}

run_immediate_disconnect_probe()
{
    local case_dir="$TEST_TMPDIR/immediate-disconnect"
    local case_port="$BASE_PORT"
    mkdir -p "$case_dir"
    cp "$TEST_TMPDIR/server.key" "$case_dir/server.key"
    cp "$TEST_TMPDIR/server.crt" "$case_dir/server.crt"

    (
        cd "$case_dir" || exit 1
        export XQC_DEMO_LIFECYCLE_ACTION_DELAY_MS="$LIFECYCLE_ACTION_DELAY_MS"
        exec "$SERVER" -l d -p "$case_port" -n 2 -Q 3
    ) >"$case_dir/server.out" 2>&1 &
    local server_pid=$!
    track_server "$server_pid"
    if ! wait_for_server "$server_pid" "$case_port"; then
        stop_server "$server_pid"
        fail_server_readiness "$case_dir" "$case_port"
        exit 1
    fi

    run_with_timeout "$CLIENT_TIMEOUT_SEC" bash -c \
        'case_dir=$1; shift; cd "$case_dir" || exit 1; exec "$@"' \
        xqc-moq-client "$case_dir" "$CLIENT" \
        --relay "moqt://127.0.0.1:$case_port" \
        --sni localhost --tls-disable-verify --verbose \
        --disconnect-after-request --test publish-blocked \
        >"$case_dir/client.1.out" 2>&1
    local client_status=$?
    if [ "$client_status" -eq 124 ] \
        || ! grep -Fq \
            "control_e2e|disconnect_after_request|case:publish-blocked|request_id:0" \
            "$case_dir/client.1.out"
    then
        stop_server "$server_pid"
        dump_case_logs "$case_dir"
        return 1
    fi

    local attempt=0
    while [ "$attempt" -lt 200 ] \
        && ! grep -Fqx \
            "control_e2e_server|lifecycle_close|pending_action:1" \
            "$case_dir/server.out"
    do
        kill -0 "$server_pid" 2>/dev/null || break
        attempt=$((attempt + 1))
        sleep 0.01
    done
    if ! grep -Fqx \
        "control_e2e_server|lifecycle_close|pending_action:1" \
        "$case_dir/server.out"
    then
        stop_server "$server_pid"
        dump_case_logs "$case_dir"
        return 1
    fi

    local wait_ms=$((LIFECYCLE_ACTION_DELAY_MS + 100))
    local wait_seconds
    wait_seconds=$(printf '%d.%03d' "$((wait_ms / 1000))" "$((wait_ms % 1000))")
    sleep "$wait_seconds"
    local server_alive=0
    local stale_action=0
    kill -0 "$server_pid" 2>/dev/null && server_alive=1
    grep -Fq "control_e2e_server|send_publish_blocked" \
        "$case_dir/server.out" && stale_action=1
    stop_server "$server_pid"

    printf 'control_lifecycle_disconnect|server_alive:%s|stale_action:%s|delay_ms:%s\n' \
        "$server_alive" "$stale_action" "$LIFECYCLE_ACTION_DELAY_MS"
    [ "$server_alive" -eq 1 ] && [ "$stale_action" -eq 0 ]
}

if [ "$IMMEDIATE_DISCONNECT_ONLY" = 1 ]; then
    run_immediate_disconnect_probe
    exit $?
fi

run_case()
{
    local case_name="$1"
    local case_port="$2"
    local lifecycle_mode="$3"
    shift 3
    local case_dir="$TEST_TMPDIR/$case_name"
    mkdir -p "$case_dir"
    cp "$TEST_TMPDIR/server.key" "$case_dir/server.key"
    cp "$TEST_TMPDIR/server.crt" "$case_dir/server.crt"

    (
        cd "$case_dir" || exit 1
        exec "$SERVER" -l d -p "$case_port" -n 2 -Q "$lifecycle_mode"
    ) >"$case_dir/server.out" 2>&1 &
    local server_pid=$!
    track_server "$server_pid"
    if ! wait_for_server "$server_pid" "$case_port"; then
        stop_server "$server_pid"
        fail_server_readiness "$case_dir" "$case_port"
        exit 1
    fi

    local connection_index=1
    while [ "$connection_index" -le "$CASE_CONNECTIONS" ]; do
        local client_output="$case_dir/client.$connection_index.out"
        run_with_timeout "$CLIENT_TIMEOUT_SEC" bash -c \
            'case_dir=$1; shift; cd "$case_dir" || exit 1; exec "$@"' \
            xqc-moq-client "$case_dir" "$CLIENT" \
            --relay "moqt://127.0.0.1:$case_port" \
            --sni localhost --tls-disable-verify --verbose \
            --test "$case_name" >"$client_output" 2>&1
        local client_status=$?

        if [ "$client_status" -ne 0 ] \
            || ! grep -q "^ok 1 - $case_name$" "$client_output"
        then
            stop_server "$server_pid"
            dump_case_logs "$case_dir"
            return 1
        fi
        connection_index=$((connection_index + 1))
    done

    if [ "$CASE_CONNECTIONS" -gt 1 ]; then
        printf '\ncontrol_lifecycle_connections|case:%s|count:%s|server_pid:%s\n' \
            "$case_name" "$CASE_CONNECTIONS" "$server_pid"
    fi

    stop_server "$server_pid"

    for expected_log in "$@"; do
        if ! grep -Fqx "$expected_log" "$case_dir"/client.*.out \
            && ! grep -Fqx "$expected_log" "$case_dir/server.out"
        then
            echo "missing exact semantic log: $expected_log"
            dump_case_logs "$case_dir"
            return 1
        fi
    done

    if [ "$case_name" = "request-update-overlap" ]; then
        local rejected_state_log=
        rejected_state_log="|request_update_rejected_state|target_id:0|update_id:4|accepted_prefix:overlap/old|candidate_applied:0|"
        if ! grep -Fq "$rejected_state_log" "$case_dir/interop_clog"; then
            echo "missing structured core log: $rejected_state_log"
            dump_case_logs "$case_dir"
            return 1
        fi
    fi

    for protocol_log in interop_clog slog; do
        if [ -f "$case_dir/$protocol_log" ] \
            && grep -Eq \
                "PROTOCOL_VIOLATION|conn_err:-?[1-9][0-9]*|invalid draft-18 message stream placement" \
                "$case_dir/$protocol_log"
        then
            dump_case_logs "$case_dir"
            return 1
        fi
    done
}

run_reported_case()
{
    local description="$1"
    shift
    if [ -n "$CASE_FILTER" ] && [ "$CASE_FILTER" != "$1" ]; then
        return
    fi
    printf "  %-68s " "$description"
    if run_case "$@"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        FAIL=$((FAIL + 1))
    fi
}

dump_combined_logs()
{
    local client_dir="$TEST_TMPDIR/combined-client"
    local case_name
    [ ! -f "$client_dir/client.out" ] \
        || { echo "--- combined client.out ---"; tail -n 240 "$client_dir/client.out"; }
    [ ! -f "$client_dir/interop_clog" ] \
        || { echo "--- combined interop_clog ---"; tail -n 240 "$client_dir/interop_clog"; }
    for case_name in $VALID_CASES; do
        [ ! -f "$TEST_TMPDIR/$case_name/server.out" ] \
            || { echo "--- $case_name server.out ---"; tail -n 160 "$TEST_TMPDIR/$case_name/server.out"; }
        [ ! -f "$TEST_TMPDIR/$case_name/slog" ] \
            || { echo "--- $case_name slog ---"; tail -n 160 "$TEST_TMPDIR/$case_name/slog"; }
    done
}

run_combined_suite()
{
    local client_dir="$TEST_TMPDIR/combined-client"
    local server_pids=""
    local case_index=0
    local case_name
    mkdir -p "$client_dir"

    for case_name in $VALID_CASES; do
        local case_dir="$TEST_TMPDIR/$case_name"
        local case_port=$((BASE_PORT + case_index))
        local lifecycle_mode=$((case_index + 1))
        mkdir -p "$case_dir"
        cp "$TEST_TMPDIR/server.key" "$case_dir/server.key"
        cp "$TEST_TMPDIR/server.crt" "$case_dir/server.crt"
        (
            cd "$case_dir" || exit 1
            exec "$SERVER" -l d -p "$case_port" -n 2 \
                -Q "$lifecycle_mode"
        ) >"$case_dir/server.out" 2>&1 &
        local server_pid=$!
        track_server "$server_pid"
        server_pids="$server_pids $server_pid"
        if ! wait_for_server "$server_pid" "$case_port"; then
            local owned_pid
            for owned_pid in $server_pids; do
                stop_server "$owned_pid"
            done
            fail_server_readiness "$case_dir" "$case_port"
            return 1
        fi
        case_index=$((case_index + 1))
    done

    local test_spec=
    test_spec="request-update-success@$BASE_PORT"
    test_spec="$test_spec,request-update-overlap@$((BASE_PORT + 1))"
    test_spec="$test_spec,publish-blocked@$((BASE_PORT + 2))"
    test_spec="$test_spec,publish-done@$((BASE_PORT + 3))"
    test_spec="$test_spec,control-goaway@$((BASE_PORT + 4))"
    test_spec="$test_spec,request-goaway@$((BASE_PORT + 5))"
    run_with_timeout "$CLIENT_TIMEOUT_SEC" bash -c \
        'client_dir=$1; shift; cd "$client_dir" || exit 1; exec "$@"' \
        xqc-moq-client "$client_dir" "$CLIENT" \
        --relay "moqt://127.0.0.1:$BASE_PORT" \
        --sni localhost --tls-disable-verify --verbose \
        --test "$test_spec" >"$client_dir/client.out" 2>&1
    local client_status=$?

    local owned_pid
    for owned_pid in $server_pids; do
        stop_server "$owned_pid"
    done

    if [ "$client_status" -ne 0 ]; then
        dump_combined_logs
        return 1
    fi

    case_index=1
    for case_name in $VALID_CASES; do
        if ! grep -Fqx "ok $case_index - $case_name" \
            "$client_dir/client.out"
        then
            echo "missing TAP success for $case_name"
            dump_combined_logs
            return 1
        fi
        case_index=$((case_index + 1))
    done

    local expected_log
    for expected_log in \
        "control_e2e|request_update_received|target_id:0|update_id:2|forward:0|prefix:update/new" \
        "control_e2e|request_update_ok|target_id:0|update_id:2|forward:0|prefix:update/new" \
        "control_e2e|request_update_error|target_id:0|update_id:4|code:0x30" \
        "control_e2e|request_update_terminal|target_id:0|update_id:4|closed_notified:1|active:0" \
        "control_e2e|publish_blocked|request_id:0|full_name:blocked/base/child/audio" \
        "control_e2e|publish_done|wire_request_id:none|stream_request_id:1|status:0x2|stream_count:0|callbacks:1|fin:1" \
        "control_e2e|goaway|scope:control|cutoff:2|timeout_ms:1000" \
        "control_e2e|going_away_error|request_id:2|code:0x06|retry:0" \
        "control_e2e|established_retained|request_id:0|local:1|response_received:1|closed_notified:0|active:1|prefix:goaway/keep" \
        "control_e2e_server|control_goaway_admission|request_id:2|callback_count:0|ret:0" \
        "control_e2e|goaway|scope:request|target_id:0|timeout_ms:100" \
        "control_e2e|request_reset|request_id:0|code:0x04" \
        "control_e2e|other_request_retained|request_id:2" \
        "control_e2e|connection_close|case:request-goaway|conn_err:0"
    do
        if ! grep -Fqx "$expected_log" "$client_dir/client.out" \
            "$TEST_TMPDIR"/*/server.out
        then
            echo "missing exact semantic log: $expected_log"
            dump_combined_logs
            return 1
        fi
    done

    local rejected_state_log=
    rejected_state_log="|request_update_rejected_state|target_id:0|update_id:4|accepted_prefix:overlap/old|candidate_applied:0|"
    if ! grep -Fq "$rejected_state_log" "$client_dir/interop_clog"; then
        echo "missing structured core log: $rejected_state_log"
        dump_combined_logs
        return 1
    fi

    local protocol_log
    for protocol_log in "$client_dir/interop_clog" "$TEST_TMPDIR"/*/slog; do
        if [ -f "$protocol_log" ] \
            && grep -Eq \
                "PROTOCOL_VIOLATION|conn_err:-?[1-9][0-9]*|invalid draft-18 message stream placement" \
                "$protocol_log"
        then
            dump_combined_logs
            return 1
        fi
    done
}

if [ -z "$CASE_FILTER" ] && [ "$CASE_CONNECTIONS" -eq 1 ]; then
    if run_combined_suite; then
        printf "  %-68s PASS\n" \
            "REQUEST_UPDATE success -> REQUEST_OK -> committed FORWARD/prefix"
        printf "  %-68s PASS\n" \
            "REQUEST_UPDATE overlap -> REQUEST_ERROR -> old prefix retained"
        printf "  %-68s PASS\n" \
            "PUBLISH_BLOCKED -> reconstructed Full Track Name"
        printf "  %-68s PASS\n" \
            "PUBLISH_DONE without Request ID -> FIN -> exactly one callback"
        printf "  %-68s PASS\n" \
            "control GOAWAY rejects cutoff request and preserves established"
        printf "  %-68s PASS\n" \
            "request GOAWAY isolates target timeout reset"
        echo "draft18 control lifecycle e2e: pass=6 fail=0"
        exit 0
    fi
    echo "draft18 control lifecycle e2e: pass=0 fail=6"
    exit 1
fi

run_reported_case \
    "REQUEST_UPDATE success -> REQUEST_OK -> committed FORWARD/prefix" \
    "request-update-success" "$BASE_PORT" 1 \
    "control_e2e|request_update_received|target_id:0|update_id:2|forward:0|prefix:update/new" \
    "control_e2e|request_update_ok|target_id:0|update_id:2|forward:0|prefix:update/new"

run_reported_case \
    "REQUEST_UPDATE overlap -> REQUEST_ERROR -> old prefix retained" \
    "request-update-overlap" "$((BASE_PORT + 1))" 2 \
    "control_e2e|request_update_error|target_id:0|update_id:4|code:0x30" \
    "control_e2e|request_update_terminal|target_id:0|update_id:4|closed_notified:1|active:0"

run_reported_case \
    "PUBLISH_BLOCKED -> reconstructed Full Track Name" \
    "publish-blocked" "$((BASE_PORT + 2))" 3 \
    "control_e2e|publish_blocked|request_id:0|full_name:blocked/base/child/audio"

run_reported_case \
    "PUBLISH_DONE without Request ID -> FIN -> exactly one callback" \
    "publish-done" "$((BASE_PORT + 3))" 4 \
    "control_e2e|publish_done|wire_request_id:none|stream_request_id:1|status:0x2|stream_count:0|callbacks:1|fin:1"

run_reported_case \
    "control GOAWAY rejects cutoff request and preserves established" \
    "control-goaway" "$((BASE_PORT + 4))" 5 \
    "control_e2e|goaway|scope:control|cutoff:2|timeout_ms:1000" \
    "control_e2e|going_away_error|request_id:2|code:0x06|retry:0" \
    "control_e2e|established_retained|request_id:0|local:1|response_received:1|closed_notified:0|active:1|prefix:goaway/keep" \
    "control_e2e_server|control_goaway_admission|request_id:2|callback_count:0|ret:0"

run_reported_case \
    "request GOAWAY isolates target timeout reset" \
    "request-goaway" "$((BASE_PORT + 5))" 6 \
    "control_e2e|goaway|scope:request|target_id:0|timeout_ms:100" \
    "control_e2e|request_reset|request_id:0|code:0x04" \
    "control_e2e|other_request_retained|request_id:2" \
    "control_e2e|connection_close|case:request-goaway|conn_err:0"

echo "draft18 control lifecycle e2e: pass=$PASS fail=$FAIL"
if [ "$((PASS + FAIL))" -eq 0 ]; then
    echo "FATAL: no lifecycle cases executed"
    exit 1
fi
[ "$FAIL" -eq 0 ]
