#!/usr/bin/env bash
#
# End-to-end test for draft-14 SUBSCRIBE_NAMESPACE relay forwarding (control + media data).
#
# Topology:
#   client A (subscriber)  --> relay (server) <-- client B (publisher)
#
# Expected:
#   - A sends SUBSCRIBE_NAMESPACE(prefix=["namespace","xquic"])
#   - B publishes tracks under ["namespace","xquic"] and sends media frames
#   - relay forwards PUBLISH to A and forwards video/audio frames from B to A
#

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
cd "${REPO_ROOT}/build" || exit 1

MOQ_DEMO_DIR="moq/demo"
RELAY_BIN="${MOQ_DEMO_DIR}/moq_demo_relay_v14"
CLIENT_BIN="${MOQ_DEMO_DIR}/moq_demo_client"

RELAY_PORT=4434
CASE_TIMEOUT_SECONDS=40
LINEBUF_PREFIX=()
if command -v stdbuf >/dev/null 2>&1; then
    LINEBUF_PREFIX=(stdbuf -oL -eL)
fi

run_with_timeout() {
    local timeout_seconds=$1
    shift
    timeout -s INT -k 2 "${timeout_seconds}" "$@"
}

clear_log() {
    : > clog
    : > slog
    : > relay.log
}

reset_runtime() {
    rm -rf tp_localhost test_session xqc_token
    clear_log
}

build_targets() {
    cmake --build . -j 8 --target \
        xquic-static \
        moq_demo_client \
        moq_demo_relay_v14 >/dev/null
}

RELAY_PID=""
CLIENT_A_PID=""
CLIENT_B_PID=""

cleanup() {
    if [ -n "${CLIENT_A_PID}" ]; then
        kill "${CLIENT_A_PID}" 2>/dev/null || true
        wait "${CLIENT_A_PID}" 2>/dev/null || true
    fi
    if [ -n "${CLIENT_B_PID}" ]; then
        kill "${CLIENT_B_PID}" 2>/dev/null || true
        wait "${CLIENT_B_PID}" 2>/dev/null || true
    fi
    if [ -n "${RELAY_PID}" ]; then
        kill "${RELAY_PID}" 2>/dev/null || true
        wait "${RELAY_PID}" 2>/dev/null || true
    fi
    killall moq_demo_relay_v14 2>/dev/null || true
    killall moq_demo_client 2>/dev/null || true
}
trap cleanup EXIT

build_targets
reset_runtime

echo "[ RUN      ] moq_case_subscribe_namespace_relay.relay_forward_control_and_media"

${LINEBUF_PREFIX[@]} ${RELAY_BIN} -p "${RELAY_PORT}" -V > relay_case.log 2>&1 &
RELAY_PID=$!
sleep 1
if ! kill -0 "${RELAY_PID}" 2>/dev/null; then
    echo "[     FAIL ] relay did not start"
    exit 1
fi

# Start subscriber A first: it subscribes the namespace prefix and waits for media frames.
run_with_timeout "${CASE_TIMEOUT_SECONDS}" \
    ${LINEBUF_PREFIX[@]} ${CLIENT_BIN} -a 127.0.0.1 -p "${RELAY_PORT}" -V -r sub -N -W -n 1 \
    > client_a.log 2>&1 &
CLIENT_A_PID=$!

sleep 2

# Start publisher B: publishes tracks under the tuple namespace and sends media frames.
run_with_timeout "${CASE_TIMEOUT_SECONDS}" \
    ${LINEBUF_PREFIX[@]} ${CLIENT_BIN} -a 127.0.0.1 -p "${RELAY_PORT}" -V -r pub -N -M -n 6 \
    > client_b.log 2>&1 &
CLIENT_B_PID=$!

wait "${CLIENT_A_PID}" || true
wait "${CLIENT_B_PID}" || true

if ! kill -0 "${RELAY_PID}" 2>/dev/null; then
    echo "[     FAIL ] relay crashed during test"
    exit 1
fi

err_clog=$(grep "\[error\]" clog 2>/dev/null || true)
err_slog=$(grep "\[error\]" slog 2>/dev/null || true)
err_relay=$(grep "\[error\]" relay.log 2>/dev/null || true)

a_sub_ns=$(grep -E "send subscribe_namespace:" client_a.log 2>/dev/null || true)
a_publish=$(grep -E "on_publish:.*(video|audio)" client_a.log 2>/dev/null || true)
a_video=$(grep -E "^subscribe_id:.*video_len:" client_a.log 2>/dev/null || true)
a_audio=$(grep -E "on_audio_frame:" client_a.log 2>/dev/null || true)

relay_publish=$(grep -E "relay on_publish:" relay_case.log 2>/dev/null || true)
relay_forward=$(grep -E "relay forward publish:" relay_case.log 2>/dev/null || true)

if [ -n "${a_sub_ns}" ] && [ -n "${a_publish}" ] && [ -n "${a_video}" ] && [ -n "${a_audio}" ] \
   && [ -n "${relay_publish}" ] && [ -n "${relay_forward}" ] \
   && [ -z "${err_clog}" ] && [ -z "${err_slog}" ] && [ -z "${err_relay}" ]; then
    echo "[       OK ] moq_case_subscribe_namespace_relay.relay_forward_control_and_media (1 ms)"
    exit 0
fi

echo "[     FAIL ] moq_case_subscribe_namespace_relay.relay_forward_control_and_media (1 ms)"
echo "${err_clog}"
echo "${err_slog}"
echo "${err_relay}"
echo "--- client_a ---"
grep -E "send subscribe_namespace:|on_publish:|subscribe_id:|on_audio_frame:" client_a.log 2>/dev/null || true
echo "--- relay ---"
grep -E "relay on_publish:|relay forward publish:|publish_ok:" relay_case.log 2>/dev/null || true
echo "--- client_b ---"
grep -E "on_publish_ok:|send (video|audio) frame label:" client_b.log 2>/dev/null || true

exit 1
