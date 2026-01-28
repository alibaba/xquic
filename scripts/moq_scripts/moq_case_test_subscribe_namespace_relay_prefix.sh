#!/usr/bin/env bash
#
# Case 5 (Prefix discrimination, multi-segment tuples):
#   Subscribers:
#     A1 subscribes prefix ["namespace"]
#     A2 subscribes prefix ["namespace","xquic"]
#   Publishers:
#     B publishes namespace ["namespace","xquic"]
#     C publishes namespace ["namespace","other"]
#
# Expected:
#   - A1 receives both namespaces
#   - A2 receives only ["namespace","xquic"]
#

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
cd "${REPO_ROOT}/build" || exit 1

MOQ_DEMO_DIR="moq/demo"
RELAY_BIN="${MOQ_DEMO_DIR}/moq_demo_relay_v14"
CLIENT_BIN="${MOQ_DEMO_DIR}/moq_demo_client"

RELAY_PORT=4436
CASE_TIMEOUT_SECONDS=25
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
SUB1_PID=""
SUB2_PID=""
PUB_B_PID=""
PUB_C_PID=""

cleanup() {
    for pid in "${SUB1_PID}" "${SUB2_PID}" "${PUB_B_PID}" "${PUB_C_PID}" "${RELAY_PID}"; do
        if [ -n "${pid}" ]; then
            kill "${pid}" 2>/dev/null || true
            wait "${pid}" 2>/dev/null || true
        fi
    done
    killall moq_demo_relay_v14 2>/dev/null || true
    killall moq_demo_client 2>/dev/null || true
}
trap cleanup EXIT

build_targets
reset_runtime

echo "[ RUN      ] moq_case_subscribe_namespace_relay.prefix_discrimination"

${LINEBUF_PREFIX[@]} ${RELAY_BIN} -p "${RELAY_PORT}" -V > relay_case.log 2>&1 &
RELAY_PID=$!
sleep 1

# Keep subscribers alive; the script will terminate them via timeout.
run_with_timeout "${CASE_TIMEOUT_SECONDS}" \
    ${LINEBUF_PREFIX[@]} ${CLIENT_BIN} -a 127.0.0.1 -p "${RELAY_PORT}" -V -r sub -N -E 4 -T "namespace" -n 1 \
    > subscriber_a1.log 2>&1 &
SUB1_PID=$!

run_with_timeout "${CASE_TIMEOUT_SECONDS}" \
    ${LINEBUF_PREFIX[@]} ${CLIENT_BIN} -a 127.0.0.1 -p "${RELAY_PORT}" -V -r sub -N -E 2 -T "namespace,xquic" -n 1 \
    > subscriber_a2.log 2>&1 &
SUB2_PID=$!

sleep 2

run_with_timeout "${CASE_TIMEOUT_SECONDS}" \
    ${LINEBUF_PREFIX[@]} ${CLIENT_BIN} -a 127.0.0.1 -p "${RELAY_PORT}" -V -r pub -N -M -T "namespace,xquic" -n 6 \
    > publisher_b.log 2>&1 &
PUB_B_PID=$!

run_with_timeout "${CASE_TIMEOUT_SECONDS}" \
    ${LINEBUF_PREFIX[@]} ${CLIENT_BIN} -a 127.0.0.1 -p "${RELAY_PORT}" -V -r pub -N -M -T "namespace,other" -n 6 \
    > publisher_c.log 2>&1 &
PUB_C_PID=$!

wait "${SUB1_PID}" || true
wait "${SUB2_PID}" || true
wait "${PUB_B_PID}" || true
wait "${PUB_C_PID}" || true

if ! kill -0 "${RELAY_PID}" 2>/dev/null; then
    echo "[     FAIL ] relay crashed during test"
    exit 1
fi

err_clog=$(grep "\[error\]" clog 2>/dev/null || true)
err_slog=$(grep "\[error\]" slog 2>/dev/null || true)
err_relay=$(grep "\[error\]" relay.log 2>/dev/null || true)

a1_xquic=$(grep -E "on_publish:.*track:namespace/xquic/(video|audio)" subscriber_a1.log 2>/dev/null || true)
a1_other=$(grep -E "on_publish:.*track:namespace/other/(video|audio)" subscriber_a1.log 2>/dev/null || true)
a2_xquic=$(grep -E "on_publish:.*track:namespace/xquic/(video|audio)" subscriber_a2.log 2>/dev/null || true)
a2_other=$(grep -E "on_publish:.*track:namespace/other/(video|audio)" subscriber_a2.log 2>/dev/null || true)

if [ -n "${a1_xquic}" ] && [ -n "${a1_other}" ] && [ -n "${a2_xquic}" ] && [ -z "${a2_other}" ] \
   && [ -z "${err_clog}" ] && [ -z "${err_slog}" ] && [ -z "${err_relay}" ]; then
    echo "[       OK ] moq_case_subscribe_namespace_relay.prefix_discrimination (1 ms)"
    exit 0
fi

echo "[     FAIL ] moq_case_subscribe_namespace_relay.prefix_discrimination (1 ms)"
echo "${err_clog}"
echo "${err_slog}"
echo "${err_relay}"
echo "--- subscriber_a1 ---"
grep -E "send subscribe_namespace:|on_publish:" subscriber_a1.log 2>/dev/null || true
echo "--- subscriber_a2 ---"
grep -E "send subscribe_namespace:|on_publish:" subscriber_a2.log 2>/dev/null || true
exit 1
