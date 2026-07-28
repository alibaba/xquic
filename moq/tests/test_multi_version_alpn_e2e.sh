#!/usr/bin/env bash

set -uo pipefail

DEMO_DIR="$(cd "${1:?Usage: $0 <demo_dir>}" && pwd)"
SERVER="${DEMO_DIR}/moq_demo_server"
CLIENT="${DEMO_DIR}/moq_demo_client"
TMP_DIR="$(mktemp -d)"
SERVER_DIR="${TMP_DIR}/server"
PORT=$((12000 + RANDOM % 2000))
SERVER_PID=""
LAST_CLIENT_PID=""
PASS=0
FAIL=0

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
            kill "${pid}" 2>/dev/null || true
            wait "${pid}" 2>/dev/null || true
            return 124
        fi
        sleep 0.1
        waited=$((waited + 100))
    done
    wait "${pid}"
}

stop_server() {
    if [ -n "${SERVER_PID}" ]; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
        SERVER_PID=""
    fi
}

cleanup() {
    stop_server
    if [ "${KEEP_MOQ_E2E_TMP:-0}" = "1" ]; then
        echo "Preserving E2E logs at ${TMP_DIR}"
    else
        rm -r -- "${TMP_DIR}"
    fi
}
trap cleanup EXIT

run_test() {
    local name="$1"
    shift
    printf "  %-58s " "${name}"
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
    local server_scid

    [ "$(client_rc "${name}")" -eq 0 ] || return 1
    server_scid="$(server_scid_for_client "${name}")" || return 1
    [ -n "${server_scid}" ] \
        && grep -q "moq_setup_active.*profile:${profile}" \
            "${TMP_DIR}/${name}/clog" \
        && grep -q "|scid:${server_scid}|.*moq_setup_active.*profile:${profile}" \
            "${SERVER_DIR}/slog" \
        && grep -q "|scid:${server_scid}|.*on_session_setup" \
            "${SERVER_DIR}/slog"
}

assert_unknown_alpn_rejected() {
    local name="unknown_alpn"
    local stdout_log="${TMP_DIR}/${name}/stdout.log"

    [ "$(client_rc "${name}")" -ne 0 ] \
        && grep -q "unsupported MoQ ALPN: moq-99" "${stdout_log}" \
        && ! grep -q "on_session_setup" "${stdout_log}"
}

assert_concurrent_profiles() {
    local v5_scid
    local v14_scid

    [ "$(client_rc concurrent_v5)" -eq 0 ] || return 1
    [ "$(client_rc concurrent_v14)" -eq 0 ] || return 1
    v5_scid="$(server_scid_for_client concurrent_v5)" || return 1
    v14_scid="$(server_scid_for_client concurrent_v14)" || return 1

    [ -n "${v5_scid}" ] \
        && [ -n "${v14_scid}" ] \
        && [ "${v5_scid}" != "${v14_scid}" ] \
        && grep -q "|scid:${v5_scid}|.*moq_setup_active.*profile:draft-05" \
            "${SERVER_DIR}/slog" \
        && grep -q "|scid:${v14_scid}|.*moq_setup_active.*profile:draft-14" \
            "${SERVER_DIR}/slog"
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

(
    cd "${SERVER_DIR}" || exit 1
    exec "${SERVER}" -l d -p "${PORT}" -n 2 -T
) >"${SERVER_DIR}/stdout.log" 2>&1 &
SERVER_PID=$!

sleep 0.5
if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "FATAL: server did not start"
    exit 1
fi

echo "=== MoQ pure-ALPN multi-version E2E ==="

for entry in \
    "legacy_v5|draft-05|moq-quic" \
    "draft05_v5|draft-05|moq-05" \
    "draft14_v14|draft-14|moq-14"
do
    IFS='|' read -r name profile alpn <<<"${entry}"
    run_client "${name}" -A "${alpn}"
    run_test "${name}: negotiated ${profile}" \
        assert_positive_profile "${name}" "${profile}"
done

run_client unknown_alpn -A moq-99
run_test "unknown ALPN is rejected before connection setup" \
    assert_unknown_alpn_rejected

run_client_async concurrent_v5 -A moq-05
v5_pid="${LAST_CLIENT_PID}"
run_client_async concurrent_v14 -A moq-14
v14_pid="${LAST_CLIENT_PID}"

if wait_for_exit "${v5_pid}" 12000; then
    set_client_rc concurrent_v5 0
else
    set_client_rc concurrent_v5 $?
fi
if wait_for_exit "${v14_pid}" 12000; then
    set_client_rc concurrent_v14 0
else
    set_client_rc concurrent_v14 $?
fi

run_test "one server concurrently keeps distinct v5/v14 profiles" \
    assert_concurrent_profiles

echo
echo "MoQ multi-version ALPN E2E: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
