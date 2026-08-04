#!/bin/bash
# Self-tests for the draft-18 control lifecycle shell harness.

set -u

BUILD_DIR="$(cd "${1:?Usage: $0 <build/moq/demo>}" && pwd)"
HARNESS="$(cd "$(dirname "$0")" && pwd)/test_draft18_control_lifecycle_e2e.sh"
SELFTEST_TMPDIR=$(mktemp -d)
SELFTEST_PIDS=""

untrack_selftest_pid()
{
    local finished_pid="$1"
    local remaining_pids=""
    local tracked_pid
    for tracked_pid in $SELFTEST_PIDS; do
        if [ "$tracked_pid" != "$finished_pid" ]; then
            remaining_pids="$remaining_pids $tracked_pid"
        fi
    done
    SELFTEST_PIDS="$remaining_pids"
}

cleanup()
{
    for selftest_pid in $SELFTEST_PIDS; do
        kill "$selftest_pid" 2>/dev/null || true
        wait "$selftest_pid" 2>/dev/null || true
    done
    rm -rf "$SELFTEST_TMPDIR"
}

trap cleanup EXIT

invalid_output="$SELFTEST_TMPDIR/invalid-filter.out"
invalid_tmp_root="$SELFTEST_TMPDIR/invalid-filter-tmp"
mkdir -p "$invalid_tmp_root"
if TMPDIR="$invalid_tmp_root" CASE_FILTER=typo \
    PORT_LEASE_ROOT="$SELFTEST_TMPDIR/invalid-filter-leases" \
    bash "$HARNESS" "$BUILD_DIR" >"$invalid_output" 2>&1
then
    echo "not ok - invalid CASE_FILTER unexpectedly succeeded"
    exit 1
fi
if ! grep -Fq \
    "FATAL: invalid CASE_FILTER=typo; expected one of:" \
    "$invalid_output"
then
    echo "not ok - invalid CASE_FILTER did not report legal cases"
    tail -n 80 "$invalid_output"
    exit 1
fi
if find "$invalid_tmp_root" -mindepth 1 -print 2>/dev/null | grep -q .; then
    echo "not ok - invalid CASE_FILTER leaked its temporary directory"
    exit 1
fi

echo "ok - invalid CASE_FILTER is rejected"

two_connection_output="$SELFTEST_TMPDIR/two-connections.out"
if ! CASE_FILTER=control-goaway CASE_CONNECTIONS=2 \
    PORT_LEASE_ROOT="$SELFTEST_TMPDIR/two-connection-leases" \
    bash "$HARNESS" "$BUILD_DIR" >"$two_connection_output" 2>&1
then
    echo "not ok - two connections did not complete on one server"
    tail -n 120 "$two_connection_output"
    exit 1
fi
if ! grep -Eq \
    '^control_lifecycle_connections\|case:control-goaway\|count:2\|server_pid:[0-9]+$' \
    "$two_connection_output"
then
    echo "not ok - two-connection run did not prove one shared server"
    tail -n 120 "$two_connection_output"
    exit 1
fi

echo "ok - lifecycle state resets across two connections"

disconnect_output="$SELFTEST_TMPDIR/immediate-disconnect.out"
if ! IMMEDIATE_DISCONNECT_ONLY=1 LIFECYCLE_ACTION_DELAY_MS=400 \
    PORT_LEASE_ROOT="$SELFTEST_TMPDIR/disconnect-leases" \
    bash "$HARNESS" "$BUILD_DIR" >"$disconnect_output" 2>&1
then
    echo "not ok - immediate-disconnect lifecycle probe failed"
    tail -n 120 "$disconnect_output"
    exit 1
fi
if ! grep -Fq \
    "control_lifecycle_disconnect|server_alive:1|stale_action:0|delay_ms:400" \
    "$disconnect_output"
then
    echo "not ok - immediate disconnect did not prove delayed-action cancellation"
    tail -n 120 "$disconnect_output"
    exit 1
fi

echo "ok - disconnect cancels delayed lifecycle action"

watchdog_output="$SELFTEST_TMPDIR/bash-watchdog.out"
if ! HARNESS_SELFTEST=bash-watchdog FORCE_BASH_WATCHDOG=1 \
    bash "$HARNESS" "$BUILD_DIR" >"$watchdog_output" 2>&1
then
    echo "not ok - forced Bash watchdog self-test failed"
    tail -n 120 "$watchdog_output"
    exit 1
fi
if ! grep -Fqx \
    "timeout_selftest|backend:bash|status:124|child_clean:1|watchdog_clean:1" \
    "$watchdog_output"
then
    echo "not ok - forced Bash watchdog did not return 124 and reap helpers"
    tail -n 120 "$watchdog_output"
    exit 1
fi

echo "ok - forced Bash watchdog returns 124 and reaps helpers"

run_signal_selftest()
{
    local signal_name="$1"
    local expected_status="$2"
    local signal_dir="$SELFTEST_TMPDIR/signal-$signal_name"
    local lease_root="$signal_dir/leases"
    local output="$signal_dir/harness.out"
    local harness_pid_file="$signal_dir/harness.pid"
    mkdir -p "$signal_dir"

    sleep 10 &
    local sentinel_pid=$!
    SELFTEST_PIDS="$SELFTEST_PIDS $sentinel_pid"
    python3 - "$harness_pid_file" "$output" "$HARNESS" \
        "$BUILD_DIR" "$lease_root" <<'PY' &
import os
import signal
import subprocess
import sys

pid_file, output, harness, build_dir, lease_root = sys.argv[1:]
env = os.environ.copy()
env.update({
    "PORT_LEASE_ONLY": "1",
    "PORT_LEASE_HOLD_SEC": "2",
    "PORT_LEASE_ROOT": lease_root,
})

def reset_signals():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)

with open(output, "w") as stream:
    process = subprocess.Popen(
        ["bash", harness, build_dir], env=env,
        stdout=stream, stderr=subprocess.STDOUT,
        preexec_fn=reset_signals)
    with open(pid_file, "w") as stream_pid:
        stream_pid.write(str(process.pid))
    status = process.wait()
sys.exit(status)
PY
    local driver_pid=$!
    SELFTEST_PIDS="$SELFTEST_PIDS $driver_pid"

    local attempt=0
    while [ "$attempt" -lt 200 ] && [ ! -s "$harness_pid_file" ]
    do
        kill -0 "$driver_pid" 2>/dev/null || break
        attempt=$((attempt + 1))
        sleep 0.01
    done
    if [ ! -s "$harness_pid_file" ]; then
        echo "not ok - $signal_name probe did not start the harness"
        return 1
    fi
    local harness_pid
    harness_pid=$(tr -d '[:space:]' <"$harness_pid_file")
    SELFTEST_PIDS="$SELFTEST_PIDS $harness_pid"

    attempt=0
    while [ "$attempt" -lt 200 ] \
        && ! grep -q '^port_lease|' "$output" 2>/dev/null
    do
        kill -0 "$harness_pid" 2>/dev/null || break
        attempt=$((attempt + 1))
        sleep 0.01
    done
    if ! grep -q '^port_lease|' "$output" 2>/dev/null; then
        echo "not ok - $signal_name probe did not acquire a lease"
        tail -n 80 "$output" 2>/dev/null || true
        return 1
    fi

    kill -s "$signal_name" "$harness_pid"
    wait "$driver_pid"
    local harness_status=$?
    untrack_selftest_pid "$driver_pid"
    untrack_selftest_pid "$harness_pid"
    if [ "$harness_status" -ne "$expected_status" ]; then
        echo "not ok - $signal_name returned $harness_status, expected $expected_status"
        return 1
    fi
    if kill -0 "$harness_pid" 2>/dev/null \
        || ps -o stat= -p "$harness_pid" 2>/dev/null | grep -q .
    then
        echo "not ok - $signal_name harness was not reaped"
        return 1
    fi
    if ! kill -0 "$sentinel_pid" 2>/dev/null; then
        echo "not ok - $signal_name cleanup killed an unrelated sentinel"
        return 1
    fi
    if find "$lease_root" -mindepth 1 -print 2>/dev/null | grep -q .; then
        echo "not ok - $signal_name cleanup leaked its port lease"
        return 1
    fi

    kill "$sentinel_pid" 2>/dev/null || true
    wait "$sentinel_pid" 2>/dev/null || true
    untrack_selftest_pid "$sentinel_pid"
    echo "ok - $signal_name exits $expected_status and cleans only owned state"
}

run_signal_selftest INT 130 || exit 1
run_signal_selftest TERM 143 || exit 1

run_watchdog_signal_selftest()
{
    local signal_dir="$SELFTEST_TMPDIR/signal-watchdog"
    local output="$signal_dir/harness.out"
    local harness_pid_file="$signal_dir/harness.pid"
    local fake_build_dir="$signal_dir/fake-build"
    local lease_root="$signal_dir/leases"
    mkdir -p "$fake_build_dir"
    printf '%s\n' '#!/bin/bash' \
        'port=' \
        'while getopts "p:r:c:l:n:fd:MVIGRoeUTCWmK:Q:Z:" option; do' \
        '    case "$option" in p) port="$OPTARG" ;; esac' \
        'done' \
        'exec python3 -c '\''import socket,sys,time; sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.bind(("127.0.0.1", int(sys.argv[1]))); time.sleep(30)'\'' "$port"' \
        >"$fake_build_dir/moq_demo_server"
    printf '%s\n' '#!/bin/bash' 'exec sleep 30' \
        >"$fake_build_dir/moq_interop_client"
    chmod +x "$fake_build_dir/moq_demo_server" \
        "$fake_build_dir/moq_interop_client"

    python3 - "$harness_pid_file" "$output" "$HARNESS" \
        "$fake_build_dir" "$lease_root" <<'PY' &
import os
import signal
import subprocess
import sys

pid_file, output, harness, build_dir, lease_root = sys.argv[1:]
env = os.environ.copy()
env.update({
    "BASE_PORT": "32300",
    "CASE_FILTER": "publish-done",
    "FORCE_BASH_WATCHDOG": "1",
    "PORT_LEASE_ROOT": lease_root,
})

def reset_signals():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)

with open(output, "w") as stream:
    process = subprocess.Popen(
        ["bash", harness, build_dir], env=env,
        stdout=stream, stderr=subprocess.STDOUT,
        preexec_fn=reset_signals)
    with open(pid_file, "w") as stream_pid:
        stream_pid.write(str(process.pid))
    status = process.wait()
sys.exit(status)
PY
    local driver_pid=$!
    SELFTEST_PIDS="$SELFTEST_PIDS $driver_pid"

    local attempt=0
    while [ "$attempt" -lt 200 ] && [ ! -s "$harness_pid_file" ]; do
        kill -0 "$driver_pid" 2>/dev/null || break
        attempt=$((attempt + 1))
        sleep 0.01
    done
    if [ ! -s "$harness_pid_file" ]; then
        echo "not ok - watchdog signal probe did not start the harness"
        return 1
    fi

    local harness_pid
    harness_pid=$(tr -d '[:space:]' <"$harness_pid_file")
    SELFTEST_PIDS="$SELFTEST_PIDS $harness_pid"
    local direct_pids=
    local nested_pids=
    local deep_pids=
    local helper_pids=
    attempt=0
    while [ "$attempt" -lt 200 ]; do
        direct_pids=$(ps -axo pid=,ppid= 2>/dev/null \
            | awk -v parent="$harness_pid" '$2 == parent { print $1 }' \
            | tr '\n' ' ')
        nested_pids=
        local helper_pid
        for helper_pid in $direct_pids; do
            nested_pids="$nested_pids $(ps -axo pid=,ppid= 2>/dev/null \
                | awk -v parent="$helper_pid" '$2 == parent { print $1 }' \
                | tr '\n' ' ')"
        done
        deep_pids=
        for helper_pid in $nested_pids; do
            deep_pids="$deep_pids $(ps -axo pid=,ppid= 2>/dev/null \
                | awk -v parent="$helper_pid" '$2 == parent { print $1 }' \
                | tr '\n' ' ')"
        done
        helper_pids="$direct_pids $nested_pids $deep_pids"
        set -- $helper_pids
        [ "$#" -ge 4 ] && break
        kill -0 "$harness_pid" 2>/dev/null || break
        attempt=$((attempt + 1))
        sleep 0.01
    done
    set -- $helper_pids
    if [ "$#" -lt 4 ]; then
        echo "not ok - formal watchdog signal probe did not observe the process tree"
        tail -n 80 "$output" 2>/dev/null || true
        return 1
    fi
    SELFTEST_PIDS="$SELFTEST_PIDS $helper_pids"

    kill -TERM "$harness_pid"
    attempt=0
    while kill -0 "$driver_pid" 2>/dev/null \
        && [ "$attempt" -lt 200 ]
    do
        attempt=$((attempt + 1))
        sleep 0.01
    done
    if kill -0 "$driver_pid" 2>/dev/null; then
        echo "not ok - formal run_case TERM did not exit promptly"
        return 1
    fi
    wait "$driver_pid"
    local harness_status=$?
    untrack_selftest_pid "$driver_pid"
    untrack_selftest_pid "$harness_pid"
    if [ "$harness_status" -ne 143 ]; then
        echo "not ok - active-watchdog TERM returned $harness_status, expected 143"
        return 1
    fi

    local helper_pid
    for helper_pid in $helper_pids; do
        if kill -0 "$helper_pid" 2>/dev/null \
            || ps -o stat= -p "$helper_pid" 2>/dev/null | grep -q .
        then
            echo "not ok - active-watchdog TERM leaked helper pid $helper_pid"
            return 1
        fi
        untrack_selftest_pid "$helper_pid"
    done
    echo "ok - formal run_case TERM reaps server, client, watchdog, and timer"
}

run_watchdog_signal_selftest || exit 1

concurrent_lease_root="$SELFTEST_TMPDIR/concurrent-leases"
PORT_LEASE_ONLY=1 PORT_LEASE_HOLD_SEC=1 \
    PORT_LEASE_ROOT="$concurrent_lease_root" \
    bash "$HARNESS" "$BUILD_DIR" \
    >"$SELFTEST_TMPDIR/concurrent-a.out" 2>&1 &
lease_pid_a=$!
SELFTEST_PIDS="$SELFTEST_PIDS $lease_pid_a"
PORT_LEASE_ONLY=1 PORT_LEASE_HOLD_SEC=1 \
    PORT_LEASE_ROOT="$concurrent_lease_root" \
    bash "$HARNESS" "$BUILD_DIR" \
    >"$SELFTEST_TMPDIR/concurrent-b.out" 2>&1 &
lease_pid_b=$!
SELFTEST_PIDS="$SELFTEST_PIDS $lease_pid_b"
wait "$lease_pid_a" || exit 1
untrack_selftest_pid "$lease_pid_a"
wait "$lease_pid_b" || exit 1
untrack_selftest_pid "$lease_pid_b"
lease_base_a=$(sed -n 's/^port_lease|base_port:\([0-9][0-9]*\)|.*/\1/p' \
    "$SELFTEST_TMPDIR/concurrent-a.out")
lease_base_b=$(sed -n 's/^port_lease|base_port:\([0-9][0-9]*\)|.*/\1/p' \
    "$SELFTEST_TMPDIR/concurrent-b.out")
if [ -z "$lease_base_a" ] || [ -z "$lease_base_b" ] \
    || [ "$lease_base_a" = "$lease_base_b" ]
then
    echo "not ok - concurrent harnesses did not lease distinct ranges"
    exit 1
fi
if find "$concurrent_lease_root" -mindepth 1 -print 2>/dev/null \
    | grep -q .
then
    echo "not ok - concurrent lease run leaked a lease directory"
    exit 1
fi
echo "ok - concurrent harnesses coordinate distinct lease ranges"

explicit_lease_root="$SELFTEST_TMPDIR/explicit-conflict-leases"
mkdir -p "$explicit_lease_root/port-32000"
if BASE_PORT=32000 PORT_LEASE_ONLY=1 \
    PORT_LEASE_ROOT="$explicit_lease_root" \
    bash "$HARNESS" "$BUILD_DIR" \
    >"$SELFTEST_TMPDIR/explicit-conflict.out" 2>&1
then
    echo "not ok - explicit lease conflict unexpectedly succeeded"
    exit 1
fi
if ! grep -Fq \
    "FATAL: cannot lease BASE_PORT=32000 range; lease conflict or UDP port in use" \
    "$SELFTEST_TMPDIR/explicit-conflict.out"
then
    echo "not ok - explicit lease conflict was not clear"
    exit 1
fi
echo "ok - explicit lease conflict fails clearly"

overlap_lease_root="$SELFTEST_TMPDIR/overlap-conflict-leases"
BASE_PORT=32200 PORT_LEASE_ONLY=1 PORT_LEASE_HOLD_SEC=2 \
    PORT_LEASE_ROOT="$overlap_lease_root" \
    bash "$HARNESS" "$BUILD_DIR" \
    >"$SELFTEST_TMPDIR/overlap-a.out" 2>&1 &
overlap_pid=$!
SELFTEST_PIDS="$SELFTEST_PIDS $overlap_pid"
attempt=0
while [ "$attempt" -lt 200 ] \
    && ! grep -q '^port_lease|' "$SELFTEST_TMPDIR/overlap-a.out" 2>/dev/null
do
    kill -0 "$overlap_pid" 2>/dev/null || break
    attempt=$((attempt + 1))
    sleep 0.01
done
if ! grep -q '^port_lease|' "$SELFTEST_TMPDIR/overlap-a.out" 2>/dev/null; then
    echo "not ok - overlapping lease probe did not acquire the first range"
    exit 1
fi
if BASE_PORT=32201 PORT_LEASE_ONLY=1 \
    PORT_LEASE_ROOT="$overlap_lease_root" \
    bash "$HARNESS" "$BUILD_DIR" \
    >"$SELFTEST_TMPDIR/overlap-b.out" 2>&1
then
    echo "not ok - overlapping six-port lease unexpectedly succeeded"
    exit 1
fi
kill "$overlap_pid" 2>/dev/null || true
wait "$overlap_pid" 2>/dev/null || true
untrack_selftest_pid "$overlap_pid"
if find "$overlap_lease_root" -mindepth 1 -print 2>/dev/null | grep -q .; then
    echo "not ok - overlapping lease probe leaked port locks"
    exit 1
fi
echo "ok - overlapping six-port ranges cannot be leased concurrently"

fake_build_dir="$SELFTEST_TMPDIR/fake-build"
bind_lease_root="$SELFTEST_TMPDIR/bind-failure-leases"
mkdir -p "$fake_build_dir"
printf '%s\n' '#!/bin/bash' \
    'echo "bind socket failed, errno: 48"' 'exit 1' \
    >"$fake_build_dir/moq_demo_server"
printf '%s\n' '#!/bin/bash' 'exit 1' \
    >"$fake_build_dir/moq_interop_client"
chmod +x "$fake_build_dir/moq_demo_server" \
    "$fake_build_dir/moq_interop_client"
if BASE_PORT=32100 CASE_FILTER=publish-done \
    PORT_LEASE_ROOT="$bind_lease_root" \
    bash "$HARNESS" "$fake_build_dir" \
    >"$SELFTEST_TMPDIR/bind-failure.out" 2>&1
then
    echo "not ok - server bind failure unexpectedly succeeded"
    exit 1
fi
if ! grep -Fq \
    "FATAL: server failed to bind UDP port 32103 after lease; availability changed before bind" \
    "$SELFTEST_TMPDIR/bind-failure.out"
then
    echo "not ok - readiness did not report the bind race clearly"
    tail -n 80 "$SELFTEST_TMPDIR/bind-failure.out"
    exit 1
fi
if find "$bind_lease_root" -mindepth 1 -print 2>/dev/null | grep -q .; then
    echo "not ok - bind failure leaked its coordinated lease"
    exit 1
fi
echo "ok - actual bind failure is clear and releases its lease"
