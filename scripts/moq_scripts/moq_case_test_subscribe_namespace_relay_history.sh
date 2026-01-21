#!/usr/bin/env bash
#
# Case 2 (History replay):
#   Publisher B publishes first.
#   Subscriber A joins later and sends SUBSCRIBE_NAMESPACE(prefix).
#   Relay must immediately forward existing PUBLISH_NAMESPACE/PUBLISH + media frames.
#

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
cd "${REPO_ROOT}/build" || exit 1

MOQ_DEMO_DIR="moq/demo"
RELAY_BIN="${MOQ_DEMO_DIR}/moq_demo_relay_v14"
CLIENT_BIN="${MOQ_DEMO_DIR}/moq_demo_client"

RELAY_PORT=4435
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

reset_runtime() {
    rm -rf tp_localhost test_session xqc_token
    : > clog
    : > slog
    : > relay.log
}

build_targets() {
    cmake --build . -j 8 --target xquic-static moq_demo_client moq_demo_relay_v14 >/dev/null
}

RELAY_PID=""
PUB_PID=""
SUB_PID=""

cleanup() {
    if [ -n "${SUB_PID}" ]; then
        kill "${SUB_PID}" 2>/dev/null || true
        wait "${SUB_PID}" 2>/dev/null || true
    fi
    if [ -n "${PUB_PID}" ]; then
        kill "${PUB_PID}" 2>/dev/null || true
        wait "${PUB_PID}" 2>/dev/null || true
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

echo "[ RUN      ] moq_case_subscribe_namespace_relay.history_replay"

${LINEBUF_PREFIX[@]} ${RELAY_BIN} -p "${RELAY_PORT}" -V > relay_case.log 2>&1 &
RELAY_PID=$!
sleep 1

run_with_timeout "${CASE_TIMEOUT_SECONDS}" \
    ${LINEBUF_PREFIX[@]} ${CLIENT_BIN} -a 127.0.0.1 -p "${RELAY_PORT}" -V -r pub -N -M -T "namespace,xquic" -n 6 \
    > publisher.log 2>&1 &
PUB_PID=$!

sleep 2

run_with_timeout "${CASE_TIMEOUT_SECONDS}" \
    ${LINEBUF_PREFIX[@]} ${CLIENT_BIN} -a 127.0.0.1 -p "${RELAY_PORT}" -V -r sub -N -W -T "namespace,xquic" -n 1 \
    > subscriber.log 2>&1 &
SUB_PID=$!

wait "${SUB_PID}" || true
kill "${PUB_PID}" 2>/dev/null || true
wait "${PUB_PID}" 2>/dev/null || true

if ! kill -0 "${RELAY_PID}" 2>/dev/null; then
    echo "[     FAIL ] relay crashed during test"
    exit 1
fi

err_clog=$(grep "\[error\]" clog 2>/dev/null || true)
err_slog=$(grep "\[error\]" slog 2>/dev/null || true)
err_relay=$(grep "\[error\]" relay.log 2>/dev/null || true)

sub_send=$(grep -E "send subscribe_namespace:" subscriber.log 2>/dev/null || true)
sub_publish=$(grep -E "on_publish:.*(video|audio)" subscriber.log 2>/dev/null || true)
sub_video=$(grep -E "^subscribe_id:.*video_len:" subscriber.log 2>/dev/null || true)
sub_audio=$(grep -E "on_audio_frame:" subscriber.log 2>/dev/null || true)
relay_history=$(grep -E "relay history forward publish:" relay_case.log 2>/dev/null || true)

if [ -n "${sub_send}" ] && [ -n "${sub_publish}" ] && [ -n "${sub_video}" ] && [ -n "${sub_audio}" ] \
   && [ -n "${relay_history}" ] \
   && [ -z "${err_clog}" ] && [ -z "${err_slog}" ] && [ -z "${err_relay}" ]; then
    echo "[       OK ] moq_case_subscribe_namespace_relay.history_replay (1 ms)"
    exit 0
fi

echo "[     FAIL ] moq_case_subscribe_namespace_relay.history_replay (1 ms)"
echo "${err_clog}"
echo "${err_slog}"
echo "${err_relay}"
echo "--- subscriber ---"
grep -E "send subscribe_namespace:|on_publish:|subscribe_id:.*video_len:|on_audio_frame:" subscriber.log 2>/dev/null || true
echo "--- relay ---"
grep -E "relay on_publish:|relay history forward publish:" relay_case.log 2>/dev/null || true
exit 1

