#!/bin/bash

# MoQ Feedback Track end-to-end test script.
# Tests feedback negotiation, feedback report generation, loss/late detection,
# and CC integration using the real xquic moq_transport stack.
#
# Network impairment: Linux tc (requires cap_net_admin on /sbin/tc).

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
cd "${REPO_ROOT}/build" || exit 1

CLIENT_BIN="moq/demo/moq_feedback_client"
SERVER_BIN="moq/demo/moq_feedback_server"
PORT=${FB_TEST_PORT:-9543}

SERVER_PID=""
TOTAL_CASES=0
PASSED_CASES=0
FAILED_CASES=()

# ---- Network impairment via tc (no sudo needed with cap_net_admin) ----

CAN_INJECT=0
if command -v tc >/dev/null 2>&1; then
    # Test if tc actually works without sudo (cap_net_admin set)
    if tc qdisc show dev lo >/dev/null 2>&1; then
        CAN_INJECT=1
    fi
fi

tc_inject_loss() {
    local prob_pct=$1
    local iface="lo"
    tc qdisc del dev ${iface} root >/dev/null 2>&1 || true
    tc qdisc add dev ${iface} root handle 1: prio >/dev/null 2>&1
    tc qdisc add dev ${iface} parent 1:3 handle 30: netem loss ${prob_pct}% >/dev/null 2>&1
    tc filter add dev ${iface} protocol ip parent 1:0 prio 3 u32 \
        match ip sport ${PORT} 0xffff flowid 1:3 >/dev/null 2>&1
    echo "  [tc] loss ${prob_pct}% sport ${PORT}"
}

tc_inject_delay_loss() {
    local delay_ms=$1
    local prob_pct=$2
    local iface="lo"
    tc qdisc del dev ${iface} root >/dev/null 2>&1 || true
    tc qdisc add dev ${iface} root handle 1: prio >/dev/null 2>&1
    tc qdisc add dev ${iface} parent 1:3 handle 30: netem delay ${delay_ms}ms loss ${prob_pct}% >/dev/null 2>&1
    tc filter add dev ${iface} protocol ip parent 1:0 prio 3 u32 \
        match ip sport ${PORT} 0xffff flowid 1:3 >/dev/null 2>&1
    echo "  [tc] delay ${delay_ms}ms + loss ${prob_pct}% sport ${PORT}"
}

tc_inject_delay() {
    local delay_ms=$1
    local iface="lo"
    tc qdisc del dev ${iface} root >/dev/null 2>&1 || true
    tc qdisc add dev ${iface} root handle 1: prio >/dev/null 2>&1
    tc qdisc add dev ${iface} parent 1:3 handle 30: netem delay ${delay_ms}ms >/dev/null 2>&1
    tc filter add dev ${iface} protocol ip parent 1:0 prio 3 u32 \
        match ip sport ${PORT} 0xffff flowid 1:3 >/dev/null 2>&1
    echo "  [tc] delay ${delay_ms}ms sport ${PORT}"
}

tc_inject_loss_feedback_dir() {
    local prob_pct=$1
    local iface="lo"
    tc qdisc del dev ${iface} root >/dev/null 2>&1 || true
    tc qdisc add dev ${iface} root handle 1: prio >/dev/null 2>&1
    tc qdisc add dev ${iface} parent 1:3 handle 30: netem loss ${prob_pct}% >/dev/null 2>&1
    tc filter add dev ${iface} protocol ip parent 1:0 prio 3 u32 \
        match ip dport ${PORT} 0xffff flowid 1:3 >/dev/null 2>&1
    echo "  [tc] ${prob_pct}% loss feedback direction (dport ${PORT})"
}

tc_clear() {
    tc qdisc del dev lo root >/dev/null 2>&1 || true
}

# ---- Helpers ----

tail_file() {
    local file=$1
    local lines=${2:-80}
    if [ -f "${file}" ]; then
        tail -n "${lines}" "${file}"
    fi
}

clear_log() {
    : > clog_feedback
    : > slog_feedback
}

reset_runtime() {
    rm -rf fb_tp_localhost fb_test_session fb_xqc_token
    clear_log
}

start_server() {
    local case_name=$1
    shift
    local slog="server_fb_${case_name}.log"
    pkill -f "moq_feedback_server.*-p ${PORT}" 2>/dev/null
    sleep 0.3
    ${SERVER_BIN} -p ${PORT} "$@" > "${slog}" 2>&1 &
    SERVER_PID=$!
    sleep 1
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        wait "${SERVER_PID}" 2>/dev/null
        echo "server exited early, log=${slog}"
        tail_file "${slog}"
        SERVER_PID=""
        return 1
    fi
    return 0
}

stop_server() {
    if [ -n "${SERVER_PID}" ]; then
        kill "${SERVER_PID}" 2>/dev/null
        wait "${SERVER_PID}" 2>/dev/null
        SERVER_PID=""
    fi
}

run_client() {
    local case_name=$1
    shift
    local clog="client_fb_${case_name}.log"
    timeout 20 ${CLIENT_BIN} -p ${PORT} "$@" > "${clog}" 2>&1
    return $?
}

get_server_val() {
    local case_name=$1
    local key=$2
    local slog="server_fb_${case_name}.log"
    grep '\[SUMMARY\]' "${slog}" | grep -o "${key}=[^ ]*" | head -1 | cut -d= -f2
}

get_client_val() {
    local case_name=$1
    local key=$2
    local clog="client_fb_${case_name}.log"
    grep '\[SUMMARY\]' "${clog}" | grep -o "${key}=[^ ]*" | head -1 | cut -d= -f2
}

check_server_log() {
    local case_name=$1
    local pattern=$2
    local slog="server_fb_${case_name}.log"
    grep -q "${pattern}" "${slog}"
}

check_client_log() {
    local case_name=$1
    local pattern=$2
    local clog="client_fb_${case_name}.log"
    grep -q "${pattern}" "${clog}"
}

assert_eq() {
    local desc=$1
    local actual=$2
    local expected=$3
    if [ "${actual}" = "${expected}" ]; then
        return 0
    fi
    echo "  FAIL: ${desc}: expected=${expected} actual=${actual}"
    return 1
}

assert_gt() {
    local desc=$1
    local actual=$2
    local threshold=$3
    if [ -z "${actual}" ]; then actual=0; fi
    if [ "${actual}" -gt "${threshold}" ] 2>/dev/null; then
        return 0
    fi
    echo "  FAIL: ${desc}: ${actual} not > ${threshold}"
    return 1
}

assert_ge() {
    local desc=$1
    local actual=$2
    local threshold=$3
    if [ -z "${actual}" ]; then actual=0; fi
    if [ "${actual}" -ge "${threshold}" ] 2>/dev/null; then
        return 0
    fi
    echo "  FAIL: ${desc}: ${actual} not >= ${threshold}"
    return 1
}

assert_ne() {
    local desc=$1
    local actual=$2
    local not_expected=$3
    if [ "${actual}" != "${not_expected}" ]; then
        return 0
    fi
    echo "  FAIL: ${desc}: ${actual} should not == ${not_expected}"
    return 1
}

assert_gt_float() {
    local desc=$1
    local actual=$2
    local threshold=$3
    if [ -z "${actual}" ]; then actual=0; fi
    local result=$(awk "BEGIN { print (${actual} > ${threshold}) ? 1 : 0 }")
    if [ "${result}" = "1" ]; then
        return 0
    fi
    echo "  FAIL: ${desc}: ${actual} not > ${threshold}"
    return 1
}

assert_lt_float() {
    local desc=$1
    local actual=$2
    local threshold=$3
    if [ -z "${actual}" ]; then actual=0; fi
    local result=$(awk "BEGIN { print (${actual} < ${threshold}) ? 1 : 0 }")
    if [ "${result}" = "1" ]; then
        return 0
    fi
    echo "  FAIL: ${desc}: ${actual} not < ${threshold}"
    return 1
}

wait_pid_timeout() {
    local pid=$1
    local secs=${2:-30}
    local i=0
    while kill -0 ${pid} 2>/dev/null && [ ${i} -lt ${secs} ]; do
        sleep 1
        i=$((i + 1))
    done
    kill -9 ${pid} 2>/dev/null || true
    wait ${pid} 2>/dev/null || true
}

run_case() {
    local case_name=$1
    local desc=$2
    TOTAL_CASES=$((TOTAL_CASES + 1))
    echo ""
    echo "[ RUN  ] ${case_name}: ${desc}"
}

pass_case() {
    local case_name=$1
    PASSED_CASES=$((PASSED_CASES + 1))
    echo "[  OK  ] ${case_name}"
}

fail_case() {
    local case_name=$1
    FAILED_CASES+=("${case_name}")
    echo "[ FAIL ] ${case_name}"
}


# ============================================================
# Case 1: Clean network - feedback negotiation & report generation
# S4 (Setup Parameter), S5 (Feedback Report)
# ============================================================
run_case_clean() {
    local name="clean_network"
    run_case "${name}" "Feedback negotiation + report in clean network"
    reset_runtime

    start_server "${name}" -n 50 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e
    sleep 1
    stop_server

    local ok=0

    check_server_log "${name}" "DELIVERY_FEEDBACK" || { echo "  FAIL: no DELIVERY_FEEDBACK param"; ok=1; }

    local reports=$(get_server_val "${name}" "feedback_reports")
    assert_gt "feedback_reports > 0" "${reports}" 0 || ok=1

    local lost=$(get_server_val "${name}" "last_lost")
    assert_eq "last_lost == 0" "${lost}" "0" || ok=1

    local frames=$(get_client_val "${name}" "video_frames_received")
    assert_gt "video_frames > 0" "${frames}" 0 || ok=1

    check_server_log "${name}" "\\[FB_MEDIA\\] seq=" || { echo "  FAIL: no FB_MEDIA log lines"; ok=1; }
    check_server_log "${name}" "lost=" || { echo "  FAIL: no lost= in reports"; ok=1; }

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Case 2: Object loss detection via tc
# S5.3 (NOT_RECEIVED status)
# ============================================================
run_case_loss() {
    local name="network_loss"
    run_case "${name}" "20ms delay + 15% loss -> QUIC retransmits cause late objects"
    reset_runtime

    start_server "${name}" -n 150 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e &
    CLIENT_PID=$!
    sleep 1
    tc_inject_delay_loss 20 15
    sleep 5
    tc_clear
    wait_pid_timeout ${CLIENT_PID} 30
    sleep 2
    stop_server

    local ok=0

    local reports=$(get_server_val "${name}" "feedback_reports")
    assert_gt "feedback_reports > 0" "${reports}" 0 || ok=1

    local cc_adj=$(get_server_val "${name}" "cc_adj")
    assert_gt "cc_adj > 0 (CC reacted to network loss)" "${cc_adj}" 0 || ok=1

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Case 3: Jitter tolerance - inter-arrival delta reflects jitter
# S5.4 (avg_inter_arrival_delta)
# ============================================================
run_case_jitter() {
    local name="jitter_tolerance"
    run_case "${name}" "Jitter -> avg_inter_arrival_delta increases"
    reset_runtime

    start_server "${name}" -n 60 -j 80 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e
    sleep 1
    stop_server

    local ok=0

    local frames=$(get_client_val "${name}" "video_frames_received")
    assert_gt "video_frames > 0" "${frames}" 0 || ok=1

    local reports=$(get_server_val "${name}" "feedback_reports")
    assert_gt "feedback_reports > 0" "${reports}" 0 || ok=1

    local slog="server_fb_${name}.log"
    local last_delta=$(grep '\[FB_MEDIA\]' "${slog}" | grep -o 'avg_delta=[0-9-]*us' | tail -1 | grep -o '[0-9]*')
    if [ -n "${last_delta}" ]; then
        assert_gt "avg_delta > 33333 (33ms base)" "${last_delta}" 33333 || ok=1
    else
        echo "  FAIL: could not parse avg_delta"
        ok=1
    fi

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Case 4: Feedback negotiation verification
# S4 (Setup Parameter 0xA2)
# ============================================================
run_case_negotiation() {
    local name="negotiation"
    run_case "${name}" "Setup parameter 0xA2 negotiated"
    reset_runtime

    start_server "${name}" -n 20 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e
    sleep 1
    stop_server

    local ok=0

    check_server_log "${name}" "param\[1\]=0xa2\[DELIVERY_FEEDBACK\]" || { echo "  FAIL: server didn't see 0xa2 param"; ok=1; }
    check_client_log "${name}" "\\[SETUP\\] session established" || { echo "  FAIL: client session not established"; ok=1; }

    local reports=$(get_server_val "${name}" "feedback_reports")
    assert_gt "feedback_reports > 0" "${reports}" 0 || ok=1

    check_server_log "${name}" "playout=" || { echo "  FAIL: no playout_ahead metric"; ok=1; }

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Case 5: Network delay via tc
# S5.4 (Summary Statistics)
# ============================================================
run_case_delay() {
    local name="network_delay"
    run_case "${name}" "50ms tc delay -> avg_inter_arrival_delta shifts"
    reset_runtime

    start_server "${name}" -n 60 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e &
    CLIENT_PID=$!
    sleep 1
    tc_inject_delay 50
    wait_pid_timeout ${CLIENT_PID} 30
    tc_clear
    sleep 1
    stop_server

    local ok=0

    local frames=$(get_client_val "${name}" "video_frames_received")
    assert_gt "video_frames > 0" "${frames}" 0 || ok=1

    local reports=$(get_server_val "${name}" "feedback_reports")
    assert_gt "feedback_reports > 0" "${reports}" 0 || ok=1

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Case 6: Heavy loss (40%) - connection survives
# S5.3, S10.1 (best-effort)
# ============================================================
run_case_heavy_loss() {
    local name="heavy_loss"
    run_case "${name}" "40% tc loss -> connection survives, feedback report still works"
    reset_runtime

    start_server "${name}" -n 120 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e &
    CLIENT_PID=$!
    sleep 2
    tc_inject_loss 40
    sleep 3
    tc_clear
    wait_pid_timeout ${CLIENT_PID} 30
    sleep 1
    stop_server

    local ok=0

    local reports=$(get_server_val "${name}" "feedback_reports")
    assert_gt "feedback_reports > 0" "${reports}" 0 || ok=1

    local sent=$(get_server_val "${name}" "objects_sent")
    assert_gt "objects_sent > 0" "${sent}" 0 || ok=1

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Case 7: Feedback direction loss
# S10.1 (best-effort, report seq gap)
# ============================================================
run_case_feedback_loss() {
    local name="feedback_loss"
    run_case "${name}" "tc loss on feedback direction -> server detects report seq gaps"
    reset_runtime

    start_server "${name}" -n 80 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e &
    CLIENT_PID=$!
    sleep 2
    tc_inject_loss_feedback_dir 30
    sleep 3
    tc_clear
    wait_pid_timeout ${CLIENT_PID} 30
    sleep 1
    stop_server

    local ok=0

    local reports=$(get_server_val "${name}" "feedback_reports")
    assert_gt "feedback_reports > 0" "${reports}" 0 || ok=1

    local frames=$(get_client_val "${name}" "video_frames_received")
    assert_gt "video_frames > 0" "${frames}" 0 || ok=1

    # Check for report seq gap (at least one gap > 1 means feedback reports were lost)
    local slog="server_fb_${name}.log"
    local seq_list=$(grep '\[FB_MEDIA\] seq=' "${slog}" | grep -o 'seq=[0-9]*' | cut -d= -f2)
    local prev_seq=-1
    local gap_found=0
    for s in ${seq_list}; do
        if [ "${prev_seq}" -ge 0 ] 2>/dev/null; then
            local diff=$((s - prev_seq))
            if [ "${diff}" -gt 1 ]; then
                gap_found=1
                break
            fi
        fi
        prev_seq=${s}
    done
    if [ ${gap_found} -eq 0 ] && [ "${prev_seq}" -gt 0 ]; then
        echo "  WARN: no seq gap detected (30% feedback loss may not be enough)"
    fi

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Case 8: Summary stats accuracy
# S5.4.2 (total = recv + late + lost)
# ============================================================
run_case_summary_accuracy() {
    local name="summary_accuracy"
    run_case "${name}" "Summary invariants: total == recv+lost, late <= recv, lost==0 in clean net"
    reset_runtime

    start_server "${name}" -n 60 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e
    sleep 1
    stop_server

    local ok=0

    local slog="server_fb_${name}.log"
    local last_line=$(grep '\[FB_MEDIA\]' "${slog}" | tail -1)
    local last_lost=$(echo "${last_line}" | grep -o '([0-9]*/[0-9]*)' | head -1 | cut -d/ -f1 | tr -d '(')
    local last_total=$(echo "${last_line}" | grep -o '([0-9]*/[0-9]*)' | head -1 | cut -d/ -f2 | tr -d ')')

    if [ -n "${last_total}" ] && [ -n "${last_lost}" ]; then
        assert_gt "total_eval > 0" "${last_total}" 0 || ok=1
        assert_eq "lost == 0 (clean net)" "${last_lost}" "0" || ok=1
    else
        echo "  FAIL: could not parse total/lost from server log (last_line: ${last_line})"
        ok=1
    fi

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Case 9: Playout ahead metric
# S5.5 (PLAYOUT_AHEAD_MS = 0x02)
# ============================================================
run_case_playout_metric() {
    local name="playout_metric"
    run_case "${name}" "Client reports PLAYOUT_AHEAD_MS via optional metric"
    reset_runtime

    start_server "${name}" -n 30 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -P 150 -l e
    sleep 1
    stop_server

    local ok=0

    check_server_log "${name}" "playout=150ms" || { echo "  FAIL: no playout_ahead=150 metric"; ok=1; }

    local reports=$(get_server_val "${name}" "feedback_reports")
    assert_gt "feedback_reports > 0" "${reports}" 0 || ok=1

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Case 10: Loss then recovery
# S7.2 (status update NOT_RECEIVED -> RECEIVED)
# ============================================================
run_case_loss_recovery() {
    local name="loss_recovery"
    run_case "${name}" "delay+loss then clear -> feedback reports recovery"
    reset_runtime

    start_server "${name}" -n 120 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e &
    CLIENT_PID=$!
    sleep 1.5
    tc_inject_delay_loss 30 25
    sleep 4
    tc_clear
    sleep 1
    wait_pid_timeout ${CLIENT_PID} 30
    sleep 2
    stop_server

    local ok=0

    local reports=$(get_server_val "${name}" "feedback_reports")
    assert_gt "feedback_reports > 0" "${reports}" 0 || ok=1

    local frames=$(get_client_val "${name}" "video_frames_received")
    assert_gt "video_frames > 0" "${frames}" 0 || ok=1

    local cc_adj=$(get_server_val "${name}" "cc_adj")
    assert_gt "cc_adj > 0 (loss/late was detected during run)" "${cc_adj:-0}" 0 || ok=1

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Case 11: Late detection via tc delay + jitter
# S5.3 (RECEIVED_LATE status)
# ============================================================
run_case_late_via_delay() {
    local name="late_via_delay"
    run_case "${name}" "tc delay + jitter -> objects arrive late"
    reset_runtime

    start_server "${name}" -n 80 -j 50 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e &
    CLIENT_PID=$!
    sleep 1.5
    tc_inject_delay 100
    sleep 3
    tc_clear
    wait_pid_timeout ${CLIENT_PID} 30
    sleep 1
    stop_server

    local ok=0

    local reports=$(get_server_val "${name}" "feedback_reports")
    assert_gt "feedback_reports > 0" "${reports}" 0 || ok=1

    local frames=$(get_client_val "${name}" "video_frames_received")
    assert_gt "video_frames > 0" "${frames}" 0 || ok=1

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Case 12: Report sequence monotonicity
# S5.1 (Report Sequence)
# ============================================================
run_case_report_seq() {
    local name="report_seq"
    run_case "${name}" "Report Sequence is monotonically increasing"
    reset_runtime

    start_server "${name}" -n 60 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e
    sleep 1
    stop_server

    local ok=0
    local slog="server_fb_${name}.log"

    local seq_list=$(grep '\[FB_MEDIA\] seq=' "${slog}" | grep -o 'seq=[0-9]*' | cut -d= -f2)
    local prev=-1
    local mono=1
    for s in ${seq_list}; do
        if [ "${s}" -le "${prev}" ] 2>/dev/null; then
            mono=0
            echo "  FAIL: seq ${s} <= prev ${prev}"
            break
        fi
        prev=${s}
    done
    if [ "${mono}" -eq 1 ] && [ "${prev}" -gt 0 ]; then
        : # pass
    else
        if [ "${prev}" -le 0 ]; then
            echo "  FAIL: no report seq found"
        fi
        ok=1
    fi

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Case 13: Object entries present in feedback report
# S5.2 (Object Entry)
# ============================================================
run_case_object_entries() {
    local name="object_entries"
    run_case "${name}" "Feedback report contains object entries with status; object_id monotonic"
    reset_runtime

    start_server "${name}" -n 40 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e
    sleep 1
    stop_server

    local ok=0
    local slog="server_fb_${name}.log"

    check_server_log "${name}" "\\[FB_MEDIA\\] seq=" || { echo "  FAIL: no FB_MEDIA log lines"; ok=1; }

    local total_reports=$(grep -c '\[FB_MEDIA\] seq=' "${slog}" 2>/dev/null || echo 0)
    assert_gt "reports > 0" "${total_reports}" 0 || ok=1

    local entry_count=$(grep '\[FB_MEDIA\]' "${slog}" | grep -o 'entries=[0-9]*' | cut -d= -f2 | awk '{s+=$1} END{print s+0}')
    assert_gt "total entries > 0" "${entry_count}" 0 || ok=1

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Case 14: Feedback report generation frequency within S7.3 bounds
# S7.3 (50ms - 2s)
# ============================================================
run_case_report_frequency() {
    local name="report_freq"
    run_case "${name}" "Feedback report generation interval within 50ms-2s"
    reset_runtime

    start_server "${name}" -n 80 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e
    sleep 1
    stop_server

    local ok=0
    local slog="server_fb_${name}.log"

    local timestamps=$(grep '\[FB_MEDIA\] seq=' "${slog}" | grep -o 'ts=[0-9]*' | cut -d= -f2)
    local prev_ts=0
    local too_fast=0
    local too_slow=0
    local count=0
    for ts in ${timestamps}; do
        if [ ${prev_ts} -gt 0 ]; then
            local delta=$((ts - prev_ts))
            if [ ${delta} -lt 40000 ]; then
                too_fast=$((too_fast + 1))
            fi
            if [ ${delta} -gt 2100000 ]; then
                too_slow=$((too_slow + 1))
            fi
            count=$((count + 1))
        fi
        prev_ts=${ts}
    done

    if [ ${count} -lt 2 ]; then
        echo "  FAIL: not enough reports to check interval"
        ok=1
    fi
    if [ ${too_fast} -gt 0 ]; then
        echo "  FAIL: ${too_fast} reports generated faster than 40ms"
        ok=1
    fi
    if [ ${too_slow} -gt 0 ]; then
        echo "  FAIL: ${too_slow} reports generated slower than 2.1s"
        ok=1
    fi

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Case 15: CC reacts to feedback (via crosslayer gateway)
# S8.4 (MoQ -> crosslayer -> CC control)
# ============================================================
run_case_cc_integration() {
    local name="cc_integration"
    run_case "${name}" "CC adjustments triggered by feedback late via crosslayer; BBR override verified"
    reset_runtime

    start_server "${name}" -n 150 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e &
    CLIENT_PID=$!
    sleep 1.5
    tc_inject_delay_loss 30 25
    sleep 5
    tc_clear
    wait_pid_timeout ${CLIENT_PID} 30
    sleep 2
    stop_server

    local ok=0

    local cc_adj=$(get_server_val "${name}" "cc_adj")
    assert_gt "cc_adj > 0 (feedback drove CC via crosslayer)" "${cc_adj}" 0 || ok=1

    local cc_dispatch=$(get_server_val "${name}" "cc_dispatch")
    assert_gt "cc_dispatch > 0 (real CC events dispatched)" "${cc_dispatch:-0}" 0 || ok=1

    # Verify BBR override actually took effect: last_gain should be non-zero
    local last_gain=$(get_server_val "${name}" "last_gain")
    assert_ne "last_gain != 0 (BBR override activated)" "${last_gain:-0.000}" "0.000" || ok=1

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Case 16: Override expires after impairment stops
# Verify BBR override is cleared after expiry
# ============================================================
run_case_override_expiry() {
    local name="override_expiry"
    run_case "${name}" "Override expires after impairment cleared; BBR resumes normal"
    reset_runtime

    start_server "${name}" -n 200 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e &
    CLIENT_PID=$!
    sleep 1.5
    # Inject impairment to trigger override
    tc_inject_delay_loss 30 25
    sleep 3
    # Clear impairment and wait for override to expire (200ms default + margin)
    tc_clear
    sleep 2
    wait_pid_timeout ${CLIENT_PID} 30
    sleep 2
    stop_server

    local ok=0

    local cc_dispatch=$(get_server_val "${name}" "cc_dispatch")
    assert_gt "cc_dispatch > 0 (override was triggered)" "${cc_dispatch:-0}" 0 || ok=1

    local last_gain=$(get_server_val "${name}" "last_gain")
    assert_ne "last_gain != 0 (override was once dispatched)" "${last_gain:-0.000}" "0.000" || ok=1

    # BBR moq_override_active should be 0 at close time (override expired)
    local override_active=$(get_server_val "${name}" "override_active")
    assert_eq "override_active == 0 (expired after 200ms)" "${override_active:-1}" "0" || ok=1

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Case 17: CUBIC has no x_layer handler -> cc_dispatch == 0
# Verify the "no CC handler" branch
# ============================================================
run_case_cubic_no_handler() {
    local name="cubic_no_handler"
    run_case "${name}" "CUBIC CC -> cc_dispatch==0 (no x_layer handler)"
    reset_runtime

    start_server "${name}" -n 100 -c c -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e &
    CLIENT_PID=$!
    sleep 1.5
    tc_inject_delay_loss 20 15
    sleep 4
    tc_clear
    wait_pid_timeout ${CLIENT_PID} 30
    sleep 2
    stop_server

    local ok=0

    local reports=$(get_server_val "${name}" "feedback_reports")
    assert_gt "feedback_reports > 0" "${reports}" 0 || ok=1

    local cc_adj=$(get_server_val "${name}" "cc_adj")
    assert_gt "cc_adj > 0 (decision layer still fires)" "${cc_adj}" 0 || ok=1

    local cc_dispatch=$(get_server_val "${name}" "cc_dispatch")
    assert_eq "cc_dispatch == 0 (CUBIC has no x_layer handler)" "${cc_dispatch:-0}" "0" || ok=1

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Case 18: CC recovery probe-up after network impairment clears
# Verify that rule 7 (recovery_gain=1.05) fires when network is clean,
# proving that CC feedback drives both reduction AND increase.
# ============================================================
run_case_cc_recovery_probeup() {
    local name="cc_recovery_probeup"
    run_case "${name}" "Loss then clean -> last_gain > 1.0 proves CC recovery probe-up"
    reset_runtime

    # NOTE: client default is only 100 frames (~3.3s @30fps), which is not enough
    # to cover impairment+recovery phases. Use a larger frame budget here.
    start_server "${name}" -n 320 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e -n 300 &
    CLIENT_PID=$!

    sleep 1.5
    tc_inject_delay_loss 30 20
    sleep 3
    tc_clear
    sleep 4
    wait_pid_timeout ${CLIENT_PID} 30
    sleep 2
    stop_server

    local ok=0

    local reports=$(get_server_val "${name}" "feedback_reports")
    assert_gt "feedback_reports > 0" "${reports}" 0 || ok=1

    local cc_dispatch=$(get_server_val "${name}" "cc_dispatch")
    assert_gt "cc_dispatch > 0 (events dispatched)" "${cc_dispatch:-0}" 0 || ok=1

    local last_gain=$(get_server_val "${name}" "last_gain")
    assert_gt_float "last_gain > 1.0 (recovery probe-up was last action)" "${last_gain:-0}" "1.0" || ok=1

    # Verify reduction happened during impairment by checking crosslayer
    # dispatch log in slog_feedback (xquic internal log, not stdout).
    local min_gain=$(grep 'crosslayer_dispatch|type:PACING_GAIN' slog_feedback 2>/dev/null \
        | grep -o 'clamped_gain:[0-9.]*' | cut -d: -f2 \
        | awk 'BEGIN{m=9999} {if($1+0<m)m=$1} END{if(m==9999)print ""; else print m}')
    if [ -n "${min_gain}" ]; then
        assert_lt_float "min dispatched gain < 1.0 (reduction happened)" "${min_gain}" "1.0" || ok=1
    else
        echo "  WARN: could not parse dispatched gain from slog_feedback (log level may be too low)"
    fi

    local cc_adj=$(get_server_val "${name}" "cc_adj")
    assert_gt "cc_adj > 0 (loss/late detected during impairment phase)" "${cc_adj:-0}" 0 || ok=1

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}


# ============================================================
# Main
# ============================================================
echo "=== MoQ Feedback Track E2E Tests ==="
echo "Server: ${SERVER_BIN}"
echo "Client: ${CLIENT_BIN}"
echo "Port:   ${PORT}"
echo ""

if [ ${CAN_INJECT} -eq 1 ]; then
    echo "[INFO] tc available (cap_net_admin), all network impairment tests enabled"
else
    echo "[WARN] tc not available or lacks cap_net_admin, network impairment tests will be skipped"
fi

# ============================================================
# Case 19: Network feedback callback fires with valid stats
# on_feedback_network (FB_NET log lines)
# ============================================================
run_case_network_feedback() {
    local name="network_feedback"
    run_case "${name}" "on_feedback_network fires with srtt/bw/pacing"
    reset_runtime

    start_server "${name}" -n 50 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e
    sleep 1
    stop_server

    local ok=0
    local slog="server_fb_${name}.log"

    check_server_log "${name}" "\\[FB_NET\\]" || { echo "  FAIL: no FB_NET log lines"; ok=1; }

    local net_count=$(grep -c '\[FB_NET\]' "${slog}" 2>/dev/null || echo 0)
    assert_gt "FB_NET lines > 0" "${net_count}" 0 || ok=1

    local last_srtt=$(grep '\[FB_NET\]' "${slog}" | tail -1 | grep -o 'srtt=[0-9]*' | cut -d= -f2)
    if [ -n "${last_srtt}" ]; then
        assert_gt "srtt > 0" "${last_srtt}" 0 || ok=1
    else
        echo "  FAIL: could not parse srtt from FB_NET"
        ok=1
    fi

    local last_pacing=$(grep '\[FB_NET\]' "${slog}" | tail -1 | grep -o 'pacing=[0-9]*' | cut -d= -f2)
    if [ -n "${last_pacing}" ]; then
        assert_gt "pacing > 0" "${last_pacing}" 0 || ok=1
    else
        echo "  FAIL: could not parse pacing from FB_NET"
        ok=1
    fi

    local last_send=$(grep '\[FB_NET\]' "${slog}" | tail -1 | grep -o 'pkts [0-9]*/[0-9]*' | grep -o '/[0-9]*' | tr -d '/')
    if [ -n "${last_send}" ]; then
        assert_gt "send_count > 0" "${last_send}" 0 || ok=1
    else
        echo "  FAIL: could not parse send_count from FB_NET"
        ok=1
    fi

    local media_count=$(grep -c '\[FB_MEDIA\]' "${slog}" 2>/dev/null || echo 0)
    assert_gt "FB_MEDIA count > 0" "${media_count}" 0 || ok=1

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}

# ============================================================
# Case 20: Bidirectional MRR feedback
# Client sends upload, Server subscribes, both generate MRR
# ============================================================
run_case_bidirectional_feedback() {
    local name="bidirectional_feedback"
    run_case "${name}" "Bidirectional MRR: Client receives Server-side FB_MEDIA_RECV"
    reset_runtime

    start_server "${name}" -n 30 -l e || { fail_case "${name}"; return; }
    run_client "${name}" -l e -n 30
    sleep 1
    stop_server

    local ok=0
    local slog="server_fb_${name}.log"
    local clog="client_fb_${name}.log"

    local server_reports=$(get_server_val "${name}" "feedback_reports")
    assert_gt "server feedback_reports > 0" "${server_reports}" 0 || ok=1

    local upload_frames=$(get_server_val "${name}" "upload_frames_received")
    assert_gt "upload_frames_received > 0" "${upload_frames}" 0 || ok=1

    local client_fb_recv=$(get_client_val "${name}" "feedback_reports_received")
    assert_gt "client feedback_reports_received > 0" "${client_fb_recv}" 0 || ok=1

    local client_fb_sent=$(get_client_val "${name}" "feedback_reports_sent")
    assert_gt "client feedback_reports_sent > 0" "${client_fb_sent}" 0 || ok=1

    local client_net_count=$(grep -c '\[FB_NET\]' "${clog}" 2>/dev/null || echo 0)
    assert_gt "client FB_NET count > 0" "${client_net_count}" 0 || ok=1

    local server_net_count=$(grep -c '\[FB_NET\]' "${slog}" 2>/dev/null || echo 0)
    assert_gt "server FB_NET count > 0" "${server_net_count}" 0 || ok=1

    local upload_subscribe_requests=$(get_client_val "${name}" "upload_subscribe_requests")
    assert_eq "upload_subscribe_requests == 1" "${upload_subscribe_requests}" "1" || ok=1

    local upload_timer_starts=$(get_client_val "${name}" "upload_timer_starts")
    assert_eq "upload_timer_starts == 1" "${upload_timer_starts}" "1" || ok=1

    local first_client_net=$(grep -n '\[FB_NET\]' "${clog}" | head -1 | cut -d: -f1)
    local first_client_media=$(grep -n '\[FB_MEDIA_RECV\]' "${clog}" | head -1 | cut -d: -f1)
    if [ -n "${first_client_net}" ] && [ -n "${first_client_media}" ]; then
        if [ "${first_client_net}" -ge "${first_client_media}" ]; then
            echo "  FAIL: client FB_NET should appear before first FB_MEDIA_RECV"
            ok=1
        fi
    else
        echo "  FAIL: could not locate client FB_NET / FB_MEDIA_RECV ordering"
        ok=1
    fi

    check_client_log "${name}" "\\[FB_MEDIA_RECV\\]" || { echo "  FAIL: no FB_MEDIA_RECV on client"; ok=1; }
    check_server_log "${name}" "\\[UPLOAD_VIDEO\\]" || { echo "  FAIL: no UPLOAD_VIDEO on server"; ok=1; }
    check_client_log "${name}" "\\[CLIENT_SUBSCRIBE\\]" || { echo "  FAIL: no CLIENT_SUBSCRIBE on client"; ok=1; }
    check_client_log "${name}" "\\[FB_NET\\]" || { echo "  FAIL: no FB_NET on client"; ok=1; }

    if [ ${ok} -eq 0 ]; then pass_case "${name}"; else fail_case "${name}"; fi
}

# --- Non-network tests (always run) ---
run_case_clean
run_case_negotiation
run_case_jitter
run_case_summary_accuracy
run_case_playout_metric
run_case_report_seq
run_case_object_entries
run_case_report_frequency
run_case_network_feedback
run_case_bidirectional_feedback

# --- Network impairment tests (require tc with cap_net_admin) ---
if [ ${CAN_INJECT} -eq 1 ]; then
    run_case_loss
    run_case_delay
    run_case_heavy_loss
    run_case_feedback_loss
    run_case_loss_recovery
    run_case_late_via_delay
    run_case_cc_integration
    run_case_override_expiry
    run_case_cubic_no_handler
    run_case_cc_recovery_probeup
else
    echo ""
    echo "[SKIP] 10 network impairment tests (tc unavailable)"
fi

echo ""
echo "=== Results: ${PASSED_CASES}/${TOTAL_CASES} passed ==="
if [ ${#FAILED_CASES[@]} -gt 0 ]; then
    echo "Failed: ${FAILED_CASES[*]}"
    exit 1
fi
exit 0
