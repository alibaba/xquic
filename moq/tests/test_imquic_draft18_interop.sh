#!/usr/bin/env bash

set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BUILD_DIR=${XQUIC_BUILD_DIR:-"${ROOT_DIR}/build-alpn-v2-final"}
IMQUIC_ROOT=${IMQUIC_ROOT:-}
CLIENT=${XQUIC_INTEROP_CLIENT:-"${BUILD_DIR}/moq/demo/moq_interop_client"}
RELAY=${IMQUIC_RELAY:-"${IMQUIC_ROOT}/examples/imquic-moq-relay"}
PUBLISHER=${IMQUIC_PUBLISHER:-"${IMQUIC_ROOT}/examples/imquic-moq-pub"}
LOG_PARENT=${MOQ_IMQUIC_LOG_PARENT:-"${TMPDIR:-/tmp}"}

if [[ -z "${IMQUIC_ROOT}" ]]; then
    echo "IMQUIC_ROOT must point to an imquic checkout" >&2
    exit 2
fi
if [[ ! -x "${CLIENT}" ]]; then
    echo "xquic interop client not found: ${CLIENT}" >&2
    exit 2
fi
if [[ ! -x "${RELAY}" ]]; then
    echo "imquic relay not found: ${RELAY}" >&2
    exit 2
fi
if [[ ! -x "${PUBLISHER}" ]]; then
    echo "imquic publisher not found: ${PUBLISHER}" >&2
    exit 2
fi

mkdir -p "${LOG_PARENT}"
RUN_DIR=$(mktemp -d "${LOG_PARENT%/}/xquic-imquic-d18.XXXXXX") || exit 2
CERT_FILE="${RUN_DIR}/server.crt"
KEY_FILE="${RUN_DIR}/server.key"

if [[ -n "${MOQ_IMQUIC_CERT:-}" && -n "${MOQ_IMQUIC_KEY:-}" ]]; then
    cp "${MOQ_IMQUIC_CERT}" "${CERT_FILE}"
    cp "${MOQ_IMQUIC_KEY}" "${KEY_FILE}"
else
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -subj "/CN=localhost" -keyout "${KEY_FILE}" \
        -out "${CERT_FILE}" >/dev/null 2>&1 || exit 2
fi

IMQUIC_LIB_DIR="${IMQUIC_ROOT}/src/.libs"
export DYLD_LIBRARY_PATH="${IMQUIC_LIB_DIR}${DYLD_LIBRARY_PATH:+:${DYLD_LIBRARY_PATH}}"
export DYLD_FALLBACK_LIBRARY_PATH="${IMQUIC_LIB_DIR}${DYLD_FALLBACK_LIBRARY_PATH:+:${DYLD_FALLBACK_LIBRARY_PATH}}"
export LD_LIBRARY_PATH="${IMQUIC_LIB_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

DEFAULT_CASES=(
    setup-only
    announce-only
    publish-namespace-done
    subscribe-error
    announce-subscribe
    subscribe-before-announce
    subscribe-namespace-ok
    subscribe-namespace-overlap
    subscribe-namespace-notifications
    subscribe-tracks-publish
    subscribe-tracks-overlap
    request-update-success
    request-update-overlap
    publish-blocked
    publish-done
    control-goaway
    request-goaway
    track-status-success
    track-status-rejection
    fetch-success
    fetch-rejection
)

if [[ -n "${MOQ_IMQUIC_CASES:-}" ]]; then
    IFS=',' read -r -a CASES <<<"${MOQ_IMQUIC_CASES}"
else
    CASES=("${DEFAULT_CASES[@]}")
fi

RELAY_PID=
PUBLISHER_PID=
cleanup_relay() {
    if [[ -n "${PUBLISHER_PID}" ]] \
        && kill -0 "${PUBLISHER_PID}" 2>/dev/null
    then
        kill "${PUBLISHER_PID}" 2>/dev/null || true
        wait "${PUBLISHER_PID}" 2>/dev/null || true
    fi
    PUBLISHER_PID=
    if [[ -n "${RELAY_PID}" ]] && kill -0 "${RELAY_PID}" 2>/dev/null; then
        kill "${RELAY_PID}" 2>/dev/null || true
        wait "${RELAY_PID}" 2>/dev/null || true
    fi
    RELAY_PID=
}
trap cleanup_relay EXIT INT TERM

wait_for_relay_port() {
    local relay_log=$1
    local port=
    local attempt
    for attempt in {1..100}; do
        port=$(sed -n 's/.*Bound to .*:\([0-9][0-9]*\).*/\1/p' \
            "${relay_log}" 2>/dev/null | tail -1)
        if [[ -n "${port}" ]]; then
            printf '%s\n' "${port}"
            return 0
        fi
        if ! kill -0 "${RELAY_PID}" 2>/dev/null; then
            return 1
        fi
        sleep 0.1
    done
    return 1
}

wait_for_process_pattern() {
    local pid=$1
    local log=$2
    local pattern=$3
    local attempt
    for attempt in {1..100}; do
        if grep -Fq "${pattern}" "${log}" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "${pid}" 2>/dev/null; then
            return 1
        fi
        sleep 0.1
    done
    return 1
}

PASS=0
FAIL=0
for case_name in "${CASES[@]}"; do
    case_dir="${RUN_DIR}/${case_name}"
    mkdir -p "${case_dir}"
    relay_log="${case_dir}/relay.out"
    publisher_log="${case_dir}/publisher.out"
    client_log="${case_dir}/client.out"

    "${RELAY}" -M 18 -q -b 127.0.0.1 -p 0 \
        -c "${CERT_FILE}" -k "${KEY_FILE}" -d 7 \
        >"${relay_log}" 2>&1 &
    RELAY_PID=$!

    if ! relay_port=$(wait_for_relay_port "${relay_log}"); then
        printf '  %-42s FAIL (relay did not start)\n' "${case_name}"
        FAIL=$((FAIL + 1))
        cleanup_relay
        continue
    fi

    if [[ "${case_name}" == "fetch-success" ]]; then
        "${PUBLISHER}" -M 18 -q -X -b 127.0.0.1 \
            -r 127.0.0.1 -R "${relay_port}" \
            -S localhost -n moq-test -n interop -N test-track \
            -c "${CERT_FILE}" -k "${KEY_FILE}" -d 7 \
            >"${publisher_log}" 2>&1 &
        PUBLISHER_PID=$!
        if ! wait_for_process_pattern "${PUBLISHER_PID}" "${publisher_log}" \
            "Publish '0' accepted"
        then
            printf '  %-42s FAIL (publisher did not become routable)\n' \
                "${case_name}"
            tail -n 20 "${publisher_log}" | sed 's/^/    /' || true
            FAIL=$((FAIL + 1))
            cleanup_relay
            continue
        fi
    fi

    "${CLIENT}" --relay "moqt://127.0.0.1:${relay_port}" \
        --sni localhost --tls-disable-verify --verbose \
        --test "${case_name}" >"${client_log}" 2>&1
    client_status=$?
    cleanup_relay

    if [[ ${client_status} -eq 0 ]] \
        && grep -Fqx "ok 1 - ${case_name}" "${client_log}" \
        && ! grep -q '^not ok ' "${client_log}"; then
        printf '  %-42s PASS\n' "${case_name}"
        PASS=$((PASS + 1))
    else
        printf '  %-42s FAIL\n' "${case_name}"
        grep -E '^(ok|not ok) |message:|received:' "${client_log}" \
            | sed 's/^/    /' || true
        if [[ -s "${publisher_log}" ]]; then
            grep -E 'interop_fetch_responder|error|Error|failed' \
                "${publisher_log}" | sed 's/^/    publisher: /' || true
        fi
        FAIL=$((FAIL + 1))
    fi
done

trap - EXIT INT TERM
cleanup_relay

printf 'xquic <-> imquic draft-18 control interop: pass=%d fail=%d\n' \
    "${PASS}" "${FAIL}"
printf 'evidence: %s\n' "${RUN_DIR}"

[[ ${FAIL} -eq 0 && ${PASS} -eq ${#CASES[@]} ]]
