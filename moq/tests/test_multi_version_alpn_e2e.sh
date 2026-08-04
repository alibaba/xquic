#!/usr/bin/env bash

set -uo pipefail

DEMO_DIR="$(cd "${1:?Usage: $0 <demo_dir>}" && pwd)"
SERVER="${DEMO_DIR}/moq_demo_server"
CLIENT="${DEMO_DIR}/moq_demo_client"
if [ -n "${MOQ_E2E_LOG_DIR:-}" ]; then
    mkdir -p -- "${MOQ_E2E_LOG_DIR}"
    TMP_DIR="$(mktemp -d "${MOQ_E2E_LOG_DIR%/}/moq-alpn-e2e.XXXXXX")"
else
    TMP_DIR="$(mktemp -d)"
fi
SERVER_DIR="${TMP_DIR}/server"
PORT=0
SERVER_PID=""
LAST_CLIENT_PID=""
CLIENT_PIDS=""
PASS=0
FAIL=0
EXPECTED_TESTS=6
SCRIPT_OK=0
CONCURRENCY_BARRIER_OK=0
CONCURRENCY_SNAPSHOT="${TMP_DIR}/concurrency_server_barrier.slog"

set_client_rc() {
    local name="$1"
    local rc="$2"
    printf '%s\n' "${rc}" >"${TMP_DIR}/${name}/exit_code"
}

client_rc() {
    local name="$1"
    local rc_file="${TMP_DIR}/${name}/exit_code"

    if [ ! -f "${rc_file}" ]; then
        echo 125
        return
    fi
    cat "${rc_file}"
}

wait_for_exit() {
    local pid="$1"
    local timeout_ms="${2:-12000}"
    local waited=0

    while kill -0 "${pid}" 2>/dev/null; do
        if [ "${waited}" -ge "${timeout_ms}" ]; then
            kill -CONT "${pid}" 2>/dev/null || true
            kill "${pid}" 2>/dev/null || true
            wait "${pid}" 2>/dev/null || true
            return 124
        fi
        sleep 0.1
        waited=$((waited + 100))
    done
    wait "${pid}"
}

wait_for_pattern() {
    local file="$1"
    local pattern="$2"
    local timeout_ms="${3:-5000}"
    local waited=0

    while [ "${waited}" -lt "${timeout_ms}" ]; do
        if [ -f "${file}" ] && grep -Eq "${pattern}" "${file}"; then
            return 0
        fi
        sleep 0.05
        waited=$((waited + 50))
    done
    return 1
}

process_is_stopped() {
    local pid="$1"
    local state

    state="$(ps -o stat= -p "${pid}" 2>/dev/null | tr -d '[:space:]')"
    case "${state}" in
        *T*) return 0 ;;
        *) return 1 ;;
    esac
}

wait_for_stopped() {
    local pid="$1"
    local timeout_ms="${2:-5000}"
    local waited=0

    while [ "${waited}" -lt "${timeout_ms}" ]; do
        if process_is_stopped "${pid}"; then
            return 0
        fi
        if ! kill -0 "${pid}" 2>/dev/null; then
            return 1
        fi
        sleep 0.05
        waited=$((waited + 50))
    done
    return 1
}

stop_server() {
    if [ -n "${SERVER_PID}" ]; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
        SERVER_PID=""
    fi
}

cleanup() {
    local pid
    for pid in ${CLIENT_PIDS}; do
        kill -CONT "${pid}" 2>/dev/null || true
        kill "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
    done
    stop_server

    if [ "${SCRIPT_OK}" -eq 1 ] \
        && [ "${KEEP_MOQ_E2E_TMP:-0}" != "1" ]
    then
        rm -rf -- "${TMP_DIR}"
    else
        echo "Preserving E2E logs at ${TMP_DIR}"
    fi
}
trap cleanup EXIT

run_test() {
    local name="$1"
    shift

    printf "  %-62s " "${name}"
    if "$@"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        FAIL=$((FAIL + 1))
    fi
}

run_client_async() {
    local name="$1"
    shift
    local client_dir="${TMP_DIR}/${name}"

    mkdir -p "${client_dir}"
    (
        cd "${client_dir}" || exit 1
        exec "${CLIENT}" -a 127.0.0.1 -p "${PORT}" -l d -n 1 -T "$@"
    ) >"${client_dir}/stdout.log" 2>&1 &
    LAST_CLIENT_PID=$!
    CLIENT_PIDS="${CLIENT_PIDS} ${LAST_CLIENT_PID}"
}

run_client() {
    local name="$1"
    shift
    local rc

    run_client_async "${name}" "$@"
    if wait_for_exit "${LAST_CLIENT_PID}" 12000; then
        rc=0
    else
        rc=$?
    fi
    set_client_rc "${name}" "${rc}"
    return "${rc}"
}

server_scid_for_client() {
    local name="$1"
    local client_log="${TMP_DIR}/${name}/clog"

    [ -f "${client_log}" ] || return 1
    sed -n "s/.*p-127\\.0\\.0\\.1-${PORT}-\\([[:xdigit:]]*\\).*/\\1/p" \
        "${client_log}" | tail -n 1
}

assert_positive_profile() {
    local name="$1"
    local profile="$2"
    local alpn="$3"
    local wire_version="$4"
    local server_scid
    local stdout_log="${TMP_DIR}/${name}/stdout.log"
    local rc

    rc="$(client_rc "${name}")"
    [ "${rc}" -eq 0 ] || return 1
    [ "${rc}" -ne 125 ] || return 1
    server_scid="$(server_scid_for_client "${name}")" || return 1
    [ -n "${server_scid}" ] || return 1

    grep -q "moq_profile_selected.*alpn:${alpn}.*profile:${profile}.*wire_version:${wire_version}" \
        "${TMP_DIR}/${name}/clog" \
        && grep -q "moq_setup_active.*profile:${profile}.*wire_version:${wire_version}" \
            "${TMP_DIR}/${name}/clog" \
        && grep -q "|scid:${server_scid}|.*moq_profile_selected.*alpn:${alpn}.*profile:${profile}.*wire_version:${wire_version}" \
            "${SERVER_DIR}/slog" \
        && grep -q "|scid:${server_scid}|.*moq_setup_active.*profile:${profile}.*wire_version:${wire_version}" \
            "${SERVER_DIR}/slog" \
        && grep -q "|scid:${server_scid}|.*on_session_setup" \
            "${SERVER_DIR}/slog" \
        && {
            if [ "${profile}" = "draft-18" ]; then
                grep -q "client_subscribe_tracks_sent|.*ret:0|" "${stdout_log}" \
                    && grep -q "client_subscribe_tracks_ok|" "${stdout_log}" \
                    && grep -q "client_publish_ok|track:video|.*ret:0|" "${stdout_log}" \
                    && grep -q "client_publish_ok|track:audio|.*ret:0|" "${stdout_log}"
            else
                grep -q "client_subscribe_ok|track:video|" "${stdout_log}" \
                    && grep -q "client_subscribe_ok|track:audio|" "${stdout_log}"
            fi
        } \
        && grep -q "client_recv_video_frame|" "${stdout_log}" \
        && grep -q "client_recv_audio_frame|" "${stdout_log}" \
        && grep -q "|scid:${server_scid}|.*write video frame success" \
            "${SERVER_DIR}/slog" \
        && grep -q "|scid:${server_scid}|.*write audio frame success" \
            "${SERVER_DIR}/slog" \
        && {
            [ "${profile}" != "draft-14" ] \
                || ! grep -q "|scid:${server_scid}|.*on subscribe" \
                    "${SERVER_DIR}/slog"
        }
}

assert_unknown_alpn_rejected() {
    local name="unknown_alpn"
    local stdout_log="${TMP_DIR}/${name}/stdout.log"
    local client_log="${TMP_DIR}/${name}/clog"
    local server_log="${TMP_DIR}/${name}/server_slog"
    local rc

    rc="$(client_rc "${name}")"
    [ "${rc}" -ne 0 ] \
        && [ "${rc}" -ne 125 ] \
        && grep -q "alpn_probe_connect_started|alpn:moq-99|" "${stdout_log}" \
        && grep -q "alpn_probe_closed|conn_err:376|handshake_finished:0|" \
            "${stdout_log}" \
        && [ -s "${client_log}" ] \
        && grep -q "xqc_process_conn_close_frame|with err:0x178" \
            "${client_log}" \
        && grep -q "select proto error" "${server_log}" \
        && grep -Eq "alert:120|NO_APPLICATION_PROTOCOL" \
            "${server_log}" \
        && ! grep -q "moq_profile_selected.*alpn:moq-99" "${client_log}" \
        && ! grep -q "moq_profile_selected.*alpn:moq-99" "${server_log}"
}

barrier_diagnostic() {
    local name="$1"
    local alpn="$2"
    local predicate="$3"
    local pid="$4"
    local started_at="$5"
    local deadline="$6"
    local marker_seen="$7"
    local state

    state="$(ps -o state= -p "${pid}" 2>/dev/null | tr -d '[:space:]')"
    [ -n "${state}" ] || state="exited"
    printf 'e2e_barrier_wait_failed|client:%s|alpn:%s|predicate:%s|pid:%s|state:%s|marker_seen:%s|elapsed_sec:%s|timeout_sec:%s|\n' \
        "${name}" "${alpn}" "${predicate}" "${pid}" "${state}" \
        "${marker_seen}" "$((SECONDS - started_at))" \
        "$((deadline - started_at))" \
        | tee -a "${TMP_DIR}/concurrency_barrier.log" >&2
}

wait_for_setup_barrier_until() {
    local name="$1"
    local pid="$2"
    local alpn="$3"
    local started_at="$4"
    local deadline="$5"
    local stdout_log="${TMP_DIR}/${name}/stdout.log"
    local marker_seen=0
    local predicate

    while [ "${SECONDS}" -lt "${deadline}" ]; do
        if [ "${marker_seen}" -eq 0 ] \
            && grep -q "e2e_setup_barrier_stopped[|]alpn:${alpn}[|]" \
                "${stdout_log}" 2>/dev/null
        then
            marker_seen=1
        fi
        if [ "${marker_seen}" -eq 1 ] && process_is_stopped "${pid}"; then
            return 0
        fi
        if ! kill -0 "${pid}" 2>/dev/null; then
            break
        fi
        sleep 0.05
    done

    if ! kill -0 "${pid}" 2>/dev/null; then
        predicate="process_alive"
    elif [ "${marker_seen}" -eq 0 ]; then
        predicate="setup_marker"
    else
        predicate="process_stopped"
    fi
    barrier_diagnostic "${name}" "${alpn}" "${predicate}" "${pid}" \
        "${started_at}" "${deadline}" "${marker_seen}"
    return 1
}

wait_for_server_barrier_until() {
    local name="$1"
    local pid="$2"
    local server_scid="$3"
    local alpn="$4"
    local profile="$5"
    local wire_version="$6"
    local started_at="$7"
    local deadline="$8"

    while [ "${SECONDS}" -lt "${deadline}" ]; do
        if grep -q "|scid:${server_scid}|.*moq_setup_active.*profile:${profile}.*wire_version:${wire_version}" \
            "${SERVER_DIR}/slog" 2>/dev/null
        then
            return 0
        fi
        if ! kill -0 "${pid}" 2>/dev/null; then
            break
        fi
        sleep 0.05
    done

    barrier_diagnostic "${name}" "${alpn}" "server_setup_active" "${pid}" \
        "${started_at}" "${deadline}" "1"
    return 1
}

assert_concurrent_profiles() {
    local v5_scid
    local v14_scid
    local v18_scid

    [ "${CONCURRENCY_BARRIER_OK}" -eq 1 ] || return 1
    [ "$(client_rc concurrent_v5)" -eq 0 ] || return 1
    [ "$(client_rc concurrent_v14)" -eq 0 ] || return 1
    [ "$(client_rc concurrent_v18)" -eq 0 ] || return 1
    v5_scid="$(server_scid_for_client concurrent_v5)" || return 1
    v14_scid="$(server_scid_for_client concurrent_v14)" || return 1
    v18_scid="$(server_scid_for_client concurrent_v18)" || return 1

    [ -n "${v5_scid}" ] \
        && [ -n "${v14_scid}" ] \
        && [ -n "${v18_scid}" ] \
        && [ "${v5_scid}" != "${v14_scid}" ] \
        && [ "${v5_scid}" != "${v18_scid}" ] \
        && [ "${v14_scid}" != "${v18_scid}" ] \
        && grep -q "|scid:${v5_scid}|.*moq_setup_active.*profile:draft-05.*wire_version:4278190085" \
            "${CONCURRENCY_SNAPSHOT}" \
        && grep -q "|scid:${v14_scid}|.*moq_setup_active.*profile:draft-14.*wire_version:4278190094" \
            "${CONCURRENCY_SNAPSHOT}" \
        && grep -q "|scid:${v18_scid}|.*moq_setup_active.*profile:draft-18.*wire_version:4278190098" \
            "${CONCURRENCY_SNAPSHOT}" \
        && ! grep -q "|scid:${v5_scid}|.*xqc_conn_immediate_close" \
            "${CONCURRENCY_SNAPSHOT}" \
        && ! grep -q "|scid:${v14_scid}|.*xqc_conn_immediate_close" \
            "${CONCURRENCY_SNAPSHOT}" \
        && ! grep -q "|scid:${v18_scid}|.*xqc_conn_immediate_close" \
            "${CONCURRENCY_SNAPSHOT}" \
        && ! grep -q "|scid:${v5_scid}|.*xqc_moq_session_destroy" \
            "${CONCURRENCY_SNAPSHOT}" \
        && ! grep -q "|scid:${v14_scid}|.*xqc_moq_session_destroy" \
            "${CONCURRENCY_SNAPSHOT}" \
        && ! grep -q "|scid:${v18_scid}|.*xqc_moq_session_destroy" \
            "${CONCURRENCY_SNAPSHOT}" \
        && assert_positive_profile concurrent_v5 draft-05 moq-05 4278190085 \
        && assert_positive_profile concurrent_v14 draft-14 moq-14 4278190094 \
        && assert_positive_profile concurrent_v18 draft-18 moqt-18 4278190098
}

start_server() {
    local attempt

    for attempt in 1 2 3 4 5; do
        PORT=$((12000 + RANDOM % 2000))
        rm -f "${SERVER_DIR}/stdout.log" "${SERVER_DIR}/slog"
        (
            cd "${SERVER_DIR}" || exit 1
            exec "${SERVER}" -l d -p "${PORT}" -n 2 -T
        ) >"${SERVER_DIR}/stdout.log" 2>&1 &
        SERVER_PID=$!

        if wait_for_pattern "${SERVER_DIR}/stdout.log" \
            "MoQ server ready on UDP port ${PORT}" 3000
        then
            return 0
        fi
        stop_server
    done
    return 1
}

for binary in "${SERVER}" "${CLIENT}"; do
    if [ ! -x "${binary}" ]; then
        echo "FATAL: executable not found: ${binary}"
        exit 1
    fi
done

mkdir -p "${SERVER_DIR}"
BUILD_ROOT="$(cd "${DEMO_DIR}/../.." && pwd)"
if [ -f "${BUILD_ROOT}/server.crt" ] && [ -f "${BUILD_ROOT}/server.key" ]; then
    cp "${BUILD_ROOT}/server.crt" "${SERVER_DIR}/"
    cp "${BUILD_ROOT}/server.key" "${SERVER_DIR}/"
else
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${SERVER_DIR}/server.key" \
        -out "${SERVER_DIR}/server.crt" \
        -subj "/CN=localhost" -days 1 >/dev/null 2>&1
fi

if ! start_server; then
    echo "FATAL: server failed to bind and become ready after 5 attempts"
    exit 1
fi

echo "=== MoQ pure-ALPN multi-version E2E ==="

for entry in \
    "legacy_v5|draft-05|moq-quic|4278190085" \
    "draft05_v5|draft-05|moq-05|4278190085" \
    "draft14_v14|draft-14|moq-14|4278190094" \
    "draft18_v18|draft-18|moqt-18|4278190098"
do
    IFS='|' read -r name profile alpn wire_version <<<"${entry}"
    run_client "${name}" -A "${alpn}" || true
    run_test "${name}: ${alpn} selects ${profile}/${wire_version}" \
        assert_positive_profile "${name}" "${profile}" "${alpn}" \
        "${wire_version}"
done

unknown_server_start=$(( $(wc -l <"${SERVER_DIR}/slog") + 1 ))
run_client unknown_alpn -Q -A moq-99 || true
tail -n +"${unknown_server_start}" "${SERVER_DIR}/slog" \
    >"${TMP_DIR}/unknown_alpn/server_slog"
run_test "unknown ALPN reaches TLS negotiation and is rejected by server" \
    assert_unknown_alpn_rejected

CONCURRENCY_TIMEOUT_SEC="${MOQ_E2E_BARRIER_TIMEOUT_SEC:-60}"
case "${CONCURRENCY_TIMEOUT_SEC}" in
    ''|*[!0-9]*)
        echo "FATAL: MOQ_E2E_BARRIER_TIMEOUT_SEC must be a positive integer"
        exit 2
        ;;
esac
if [ "${CONCURRENCY_TIMEOUT_SEC}" -le 0 ]; then
    echo "FATAL: MOQ_E2E_BARRIER_TIMEOUT_SEC must be a positive integer"
    exit 2
fi
CONCURRENCY_STARTED_AT="${SECONDS}"
CONCURRENCY_DEADLINE=$((CONCURRENCY_STARTED_AT + CONCURRENCY_TIMEOUT_SEC))

run_client_async concurrent_v5 -B -A moq-05
v5_pid="${LAST_CLIENT_PID}"
if wait_for_setup_barrier_until concurrent_v5 "${v5_pid}" moq-05 \
    "${CONCURRENCY_STARTED_AT}" "${CONCURRENCY_DEADLINE}"
then
    run_client_async concurrent_v14 -B -A moq-14
    v14_pid="${LAST_CLIENT_PID}"
    if wait_for_setup_barrier_until concurrent_v14 "${v14_pid}" moq-14 \
        "${CONCURRENCY_STARTED_AT}" "${CONCURRENCY_DEADLINE}" \
        && wait_for_setup_barrier_until concurrent_v5 "${v5_pid}" moq-05 \
            "${CONCURRENCY_STARTED_AT}" "${CONCURRENCY_DEADLINE}"
    then
        run_client_async concurrent_v18 -B -A moqt-18
        v18_pid="${LAST_CLIENT_PID}"
    fi
    if [ -n "${v18_pid:-}" ] \
        && wait_for_setup_barrier_until concurrent_v18 "${v18_pid}" moqt-18 \
            "${CONCURRENCY_STARTED_AT}" "${CONCURRENCY_DEADLINE}" \
        && wait_for_setup_barrier_until concurrent_v14 "${v14_pid}" moq-14 \
            "${CONCURRENCY_STARTED_AT}" "${CONCURRENCY_DEADLINE}" \
        && wait_for_setup_barrier_until concurrent_v5 "${v5_pid}" moq-05 \
            "${CONCURRENCY_STARTED_AT}" "${CONCURRENCY_DEADLINE}"
    then
        v5_scid="$(server_scid_for_client concurrent_v5)" || v5_scid=""
        v14_scid="$(server_scid_for_client concurrent_v14)" || v14_scid=""
        v18_scid="$(server_scid_for_client concurrent_v18)" || v18_scid=""
        if [ -n "${v5_scid}" ] \
            && [ -n "${v14_scid}" ] \
            && [ -n "${v18_scid}" ] \
            && [ "${v5_scid}" != "${v14_scid}" ] \
            && [ "${v5_scid}" != "${v18_scid}" ] \
            && [ "${v14_scid}" != "${v18_scid}" ] \
            && wait_for_server_barrier_until concurrent_v5 "${v5_pid}" \
                "${v5_scid}" moq-05 draft-05 4278190085 \
                "${CONCURRENCY_STARTED_AT}" "${CONCURRENCY_DEADLINE}" \
            && wait_for_server_barrier_until concurrent_v14 "${v14_pid}" \
                "${v14_scid}" moq-14 draft-14 4278190094 \
                "${CONCURRENCY_STARTED_AT}" "${CONCURRENCY_DEADLINE}" \
            && wait_for_server_barrier_until concurrent_v18 "${v18_pid}" \
                "${v18_scid}" moqt-18 draft-18 4278190098 \
                "${CONCURRENCY_STARTED_AT}" "${CONCURRENCY_DEADLINE}"
        then
            cp "${SERVER_DIR}/slog" "${CONCURRENCY_SNAPSHOT}"
        fi
        if [ -f "${CONCURRENCY_SNAPSHOT}" ] \
            && ! grep -q "|scid:${v5_scid}|.*xqc_conn_immediate_close" \
                "${CONCURRENCY_SNAPSHOT}" \
            && ! grep -q "|scid:${v14_scid}|.*xqc_conn_immediate_close" \
                "${CONCURRENCY_SNAPSHOT}" \
            && ! grep -q "|scid:${v18_scid}|.*xqc_conn_immediate_close" \
                "${CONCURRENCY_SNAPSHOT}"
        then
            CONCURRENCY_BARRIER_OK=1
        fi
    fi
else
    v14_pid=""
fi

kill -CONT "${v5_pid}" 2>/dev/null || true
if [ -n "${v14_pid:-}" ]; then
    kill -CONT "${v14_pid}" 2>/dev/null || true
fi
if [ -n "${v18_pid:-}" ]; then
    kill -CONT "${v18_pid}" 2>/dev/null || true
fi

if wait_for_exit "${v5_pid}" 12000; then
    set_client_rc concurrent_v5 0
else
    set_client_rc concurrent_v5 $?
fi
if [ -n "${v14_pid:-}" ]; then
    if wait_for_exit "${v14_pid}" 12000; then
        set_client_rc concurrent_v14 0
    else
        set_client_rc concurrent_v14 $?
    fi
else
    mkdir -p "${TMP_DIR}/concurrent_v14"
    set_client_rc concurrent_v14 125
fi
if [ -n "${v18_pid:-}" ]; then
    if wait_for_exit "${v18_pid}" 12000; then
        set_client_rc concurrent_v18 0
    else
        set_client_rc concurrent_v18 $?
    fi
else
    mkdir -p "${TMP_DIR}/concurrent_v18"
    set_client_rc concurrent_v18 125
fi

run_test "server snapshot proves concurrent active v5/v14/v18 media sessions" \
    assert_concurrent_profiles

echo
echo "MoQ multi-version ALPN E2E: ${PASS} passed, ${FAIL} failed"
if [ "${PASS}" -ne "${EXPECTED_TESTS}" ] || [ "${FAIL}" -ne 0 ]; then
    exit 1
fi

SCRIPT_OK=1
exit 0
