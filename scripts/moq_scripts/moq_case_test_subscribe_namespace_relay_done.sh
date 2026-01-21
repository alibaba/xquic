#!/usr/bin/env bash
#
# Case 8 (PUBLISH_NAMESPACE_DONE):
#   Subscriber A subscribes a prefix.
#   Publisher B publishes tracks under the matching namespace.
#   When B disconnects, relay should eventually emit PUBLISH_NAMESPACE_DONE to A.
#

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
cd "${REPO_ROOT}/build" || exit 1

MOQ_DEMO_DIR="moq/demo"
RELAY_BIN="${MOQ_DEMO_DIR}/moq_demo_relay_v14"
CLIENT_BIN="${MOQ_DEMO_DIR}/moq_demo_client"

RELAY_PORT=4437
CASE_TIMEOUT_SECONDS=45
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

echo "[ RUN      ] moq_case_subscribe_namespace_relay.publish_namespace_done"

${LINEBUF_PREFIX[@]} ${RELAY_BIN} -p "${RELAY_PORT}" -V > relay_case.log 2>&1 &
RELAY_PID=$!
sleep 1

# Subscriber waits for namespace DONE and then closes (-D).
run_with_timeout "${CASE_TIMEOUT_SECONDS}" \
    ${LINEBUF_PREFIX[@]} ${CLIENT_BIN} -a 127.0.0.1 -p "${RELAY_PORT}" -V -r sub -N -D -T "namespace,xquic" -n 1 \
    > subscriber.log 2>&1 &
SUB_PID=$!

sleep 2

run_with_timeout "${CASE_TIMEOUT_SECONDS}" \
    ${LINEBUF_PREFIX[@]} ${CLIENT_BIN} -a 127.0.0.1 -p "${RELAY_PORT}" -V -r pub -N -M -T "namespace,xquic" -n 6 \
    > publisher.log 2>&1 &
PUB_PID=$!

sleep 4
kill "${PUB_PID}" 2>/dev/null || true
wait "${PUB_PID}" 2>/dev/null || true

wait "${SUB_PID}" || true

if ! kill -0 "${RELAY_PID}" 2>/dev/null; then
    echo "[     FAIL ] relay crashed during test"
    exit 1
fi

err_clog=$(grep "\[error\]" clog 2>/dev/null || true)
err_slog=$(grep "\[error\]" slog 2>/dev/null || true)
err_relay=$(grep "\[error\]" relay.log 2>/dev/null || true)

done_lines=$(grep -E "on_publish_namespace_done: namespaces:namespace/xquic" subscriber.log 2>/dev/null || true)
done_count=$(grep -c -E "on_publish_namespace_done: namespaces:" subscriber.log 2>/dev/null || true)

if [ -n "${done_lines}" ] && [ "${done_count}" -eq 1 ] \
   && [ -z "${err_clog}" ] && [ -z "${err_slog}" ] && [ -z "${err_relay}" ]; then
    echo "[       OK ] moq_case_subscribe_namespace_relay.publish_namespace_done (1 ms)"
    exit 0
fi

echo "[     FAIL ] moq_case_subscribe_namespace_relay.publish_namespace_done (1 ms)"
echo "${err_clog}"
echo "${err_slog}"
echo "${err_relay}"
echo "--- subscriber ---"
grep -E "send subscribe_namespace:|on_publish_namespace:|on_publish_namespace_done:|on_publish:" subscriber.log 2>/dev/null || true
echo "--- relay ---"
grep -E "relay on_publish:|relay on_publish_done:|relay history forward publish:" relay_case.log 2>/dev/null || true
exit 1

