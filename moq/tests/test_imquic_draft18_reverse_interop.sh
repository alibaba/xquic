#!/usr/bin/env bash

set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BUILD_DIR=${XQUIC_BUILD_DIR:-"${ROOT_DIR}/build-alpn-v2-final"}
IMQUIC_ROOT=${IMQUIC_ROOT:-}
SERVER=${XQUIC_INTEROP_SERVER:-"${BUILD_DIR}/moq/demo/moq_demo_server"}
SUBSCRIBER=${IMQUIC_SUBSCRIBER:-"${IMQUIC_ROOT}/examples/imquic-moq-sub"}
PUBLISHER=${IMQUIC_PUBLISHER:-"${IMQUIC_ROOT}/examples/imquic-moq-pub"}
OFFICIAL_CLIENT=${IMQUIC_INTEROP_TEST:-"${IMQUIC_ROOT}/examples/imquic-moq-interop-test"}
LOG_PARENT=${MOQ_IMQUIC_LOG_PARENT:-"${TMPDIR:-/tmp}"}
CASE_TIMEOUT=${MOQ_IMQUIC_CASE_TIMEOUT_SEC:-20}
PORT_LEASE_ROOT=${MOQ_IMQUIC_PORT_LEASE_ROOT:-"${TMPDIR:-/tmp}/xquic-imquic-d18-port-leases-${UID:-user}"}
BASE_PORT=${BASE_PORT:-$((40000 + ($$ % 10000)))}

DEFAULT_CASES=(
    namespace-events
    request-update
    publish-blocked
    publish-done
    control-goaway
    request-goaway
    track-status-ok
    track-status-error
    fetch-ok
    fetch-error
    xquic-to-imquic-subgroup
    xquic-to-imquic-datagram
    imquic-to-xquic-subgroup
    imquic-to-xquic-datagram
    imquic-to-xquic-fetch
)
if [[ -n "${MOQ_IMQUIC_REVERSE_CASES:-}" ]]; then
    IFS=',' read -r -a CASES <<<"${MOQ_IMQUIC_REVERSE_CASES}"
else
    CASES=("${DEFAULT_CASES[@]}")
fi
DEFAULT_OFFICIAL_CASES="setup-only announce-only publish-namespace-done subscribe-error announce-subscribe subscribe-before-announce"
if [[ -n "${MOQ_IMQUIC_OFFICIAL_CASES:-}" ]]; then
    OFFICIAL_CASE_LIST=${MOQ_IMQUIC_OFFICIAL_CASES//,/ }
elif [[ -n "${MOQ_IMQUIC_REVERSE_CASES:-}" ]]; then
    OFFICIAL_CASE_LIST=
else
    OFFICIAL_CASE_LIST=${DEFAULT_OFFICIAL_CASES}
fi

if [[ -z "${IMQUIC_ROOT}" ]]; then
    echo "IMQUIC_ROOT must point to an imquic checkout" >&2
    exit 2
fi
if [[ ! -x "${SERVER}" ]]; then
    echo "xquic server not found: ${SERVER}" >&2
    exit 2
fi
if [[ ! -x "${SUBSCRIBER}" ]]; then
    echo "imquic subscriber not found: ${SUBSCRIBER}" >&2
    exit 2
fi
if [[ ! -x "${PUBLISHER}" ]]; then
    echo "imquic publisher not found: ${PUBLISHER}" >&2
    exit 2
fi
if [[ -n "${OFFICIAL_CASE_LIST}" && ! -x "${OFFICIAL_CLIENT}" ]]; then
    echo "imquic official interop client not found: ${OFFICIAL_CLIENT}" >&2
    exit 2
fi
PEER_BINARIES=(
    subscriber "${SUBSCRIBER}"
    publisher "${PUBLISHER}"
)
if [[ -n "${OFFICIAL_CASE_LIST}" ]]; then
    PEER_BINARIES+=(interop-test "${OFFICIAL_CLIENT}")
fi
bash "${ROOT_DIR}/moq/tests/check_imquic_draft18_peer.sh" \
    "${IMQUIC_ROOT}" "${PEER_BINARIES[@]}" \
    || exit 2
case "${CASE_TIMEOUT}" in
    ''|*[!0-9]*|0)
        echo "MOQ_IMQUIC_CASE_TIMEOUT_SEC must be a positive integer" >&2
        exit 2
        ;;
esac

mkdir -p "${LOG_PARENT}" "${PORT_LEASE_ROOT}"
RUN_DIR=$(mktemp -d "${LOG_PARENT%/}/imquic-xquic-d18.XXXXXX") || exit 2
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

SERVER_PID=
CLIENT_PID=
LEASE_DIRS=
LEASED_PORT=

stop_pid() {
    local pid=$1
    local signal=${2:-INT}
    local deadline
    [[ -n "${pid}" ]] || return 0
    if ! kill -0 "${pid}" 2>/dev/null; then
        wait "${pid}" 2>/dev/null || true
        return 0
    fi
    kill -"${signal}" "${pid}" 2>/dev/null || true
    deadline=$(( $(date +%s) + 3 ))
    while kill -0 "${pid}" 2>/dev/null \
        && [[ $(date +%s) -lt ${deadline} ]]
    do
        sleep 0.05
    done
    if kill -0 "${pid}" 2>/dev/null; then
        kill -TERM "${pid}" 2>/dev/null || true
        sleep 0.1
    fi
    if kill -0 "${pid}" 2>/dev/null; then
        kill -KILL "${pid}" 2>/dev/null || true
    fi
    wait "${pid}" 2>/dev/null || true
}

cleanup() {
    stop_pid "${CLIENT_PID}" TERM
    stop_pid "${SERVER_PID}" INT
    local lease
    for lease in ${LEASE_DIRS}; do
        rmdir "${lease}" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

wait_for_pattern() {
    local pid=$1
    local file=$2
    local pattern=$3
    local timeout=$4
    local deadline=$(( $(date +%s) + timeout ))
    while [[ $(date +%s) -le ${deadline} ]]; do
        if grep -Fq "${pattern}" "${file}" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "${pid}" 2>/dev/null; then
            grep -Fq "${pattern}" "${file}" 2>/dev/null
            return $?
        fi
        sleep 0.05
    done
    return 1
}

wait_for_count() {
    local pid=$1
    local file=$2
    local pattern=$3
    local expected=$4
    local timeout=$5
    local deadline=$(( $(date +%s) + timeout ))
    local count
    while [[ $(date +%s) -le ${deadline} ]]; do
        count=$(grep -Fc "${pattern}" "${file}" 2>/dev/null || true)
        if [[ ${count} -ge ${expected} ]]; then
            return 0
        fi
        if ! kill -0 "${pid}" 2>/dev/null; then
            return 1
        fi
        sleep 0.05
    done
    return 1
}

lease_port() {
    local ordinal=$1
    local attempt candidate lease
    for attempt in {0..199}; do
        candidate=$((BASE_PORT + ordinal + attempt * 11))
        if [[ ${candidate} -gt 65000 ]]; then
            candidate=$((20000 + (candidate % 40000)))
        fi
        lease="${PORT_LEASE_ROOT}/${candidate}"
        if mkdir "${lease}" 2>/dev/null; then
            LEASE_DIRS="${LEASE_DIRS} ${lease}"
            LEASED_PORT=${candidate}
            return 0
        fi
    done
    return 1
}

assert_contains() {
    local file=$1
    local pattern=$2
    if ! grep -Fq "${pattern}" "${file}"; then
        echo "missing: ${pattern}" >&2
        return 1
    fi
}

assert_clean_logs() {
    local client_log=$1
    local server_log=$2
    if grep -Eq 'Error parsing MoQ message|PROTOCOL_VIOLATION|Invalid Request ID|Broken properties|Broken MoQ message' "${client_log}" \
        || grep -Eq 'decode message error|PROTOCOL_VIOLATION|conn_err:0x3' "${server_log}"
    then
        return 1
    fi
}

run_case() {
    local case_name=$1
    local ordinal=$2
    local mode=0
    local namespace_mode=0
    local terminal_pattern=
    local terminal_count=1
    local terminal_side=client
    local frame_num=0
    local server_role=
    local client_bin=${SUBSCRIBER}
    local -a client_args=()
    local -a client_patterns=()
    local -a server_patterns=()
    local -a server_extra=()

    case "${case_name}" in
        namespace-events)
            mode=2
            namespace_mode=4
            client_args=(-B -n explicit -N video)
            terminal_pattern='>> NAMESPACE_DONE'
            client_patterns=('>> NAMESPACE (' '>> NAMESPACE_DONE')
            server_patterns=('explicit publish_namespace ret:0' 'explicit publish_namespace_done ret:0')
            ;;
        request-update)
            mode=1
            client_args=(-B -n update -n old -N video -u 1 -U 1)
            terminal_pattern='>> REQUEST_OK'
            terminal_count=4
            client_patterns=('Sending a REQUEST_UPDATE for ID 0' 'Sending a REQUEST_UPDATE for ID 2')
            server_patterns=('prefix:test/namespace' 'namespace_request_update_ok|target_id:2')
            ;;
        publish-blocked)
            mode=3
            client_args=(-B -n blocked -n base -N audio)
            terminal_pattern='>> PUBLISH_SKIPPED'
            client_patterns=('>> PUBLISH_SKIPPED')
            server_patterns=('send_publish_blocked|request_id:0|full_name:blocked/base/child/audio|ret:0')
            ;;
        publish-done)
            mode=4
            client_args=(-B -n done -N audio)
            terminal_pattern='Subscription via ID 1 is done, using 0 streams: status 2 (e2e done)'
            client_patterns=('>> PUBLISH_DONE' 'Getting rid of PUBLISH' 'status 2 (e2e done)')
            server_patterns=('send_publish_done|stream_request_id:1|wire_request_id:none|status:0x2|ret:0')
            ;;
        control-goaway)
            mode=5
            client_args=(-B -n goaway -n keep -N video)
            terminal_pattern='Got a GOAWAY:'
            client_patterns=('>> GOAWAY' 'Got a GOAWAY:' 'timeout=1000ms')
            server_patterns=('send_control_goaway|cutoff:2|timeout_ms:1000|ret:0' 'control_goaway_admission|request_id:2|callback_count:0|ret:0')
            ;;
        request-goaway)
            mode=6
            client_args=(-B -n goaway -n request -N video)
            terminal_pattern='Got a GOAWAY for request 0:'
            client_patterns=("Subscription to namespace '2' accepted" 'Got a GOAWAY for request 0:' 'Got RESET_STREAM for STREAM 0: 4')
            server_patterns=('send_request_goaway|target_id:0|other_id:2|timeout_ms:100|ret:0')
            ;;
        track-status-ok)
            mode=7
            client_args=(-i -n namespace -N video)
            terminal_pattern='Track status 0 accepted'
            client_patterns=('Track status 0 accepted' "Getting rid of TRACK_STATUS '0'")
            server_patterns=('track_status_response|request_id:0|result:ok|properties:0201|ret:0|fin:1|closed:1')
            ;;
        track-status-error)
            mode=8
            client_args=(-i -n missing -N video)
            terminal_pattern='Got an error querying the track status via ID 0'
            client_patterns=('Got an error querying the track status via ID 0' "Getting rid of TRACK_STATUS '0'")
            server_patterns=('track_status_response|request_id:0|result:error|properties:none|ret:0|fin:1|closed:1')
            ;;
        fetch-ok)
            mode=9
            client_args=(-f ascending -n namespace -N video)
            terminal_pattern='Fetch 0 accepted'
            client_patterns=(
                'Fetch 0 accepted'
                'group=2, subgroup=3 (first=0), id=4, priority=7, payload=7 bytes, properties=1, delivery=FETCH_HEADER, status=NORMAL_OBJECT, eos=0'
                'group=2, subgroup=3 (first=0), id=5, priority=7, payload=0 bytes, properties=0, delivery=FETCH_HEADER, status=NORMAL_OBJECT, eos=0'
                'group=4, subgroup=4 (first=0), id=0, priority=7, payload=7 bytes, properties=0, delivery=FETCH_HEADER, status=NORMAL_OBJECT, eos=0'
                'Incoming FETCH range: reqid=0, group=6, object=9, unknown=1, eos=1'
            )
            server_patterns=('fetch_response|request_id:0|result:ok|end:6/9|fetch_ok_ret:0|fetch_header_ret:0|objects:0,0,0|range:0|fin:1|closed:1')
            ;;
        fetch-error)
            mode=10
            client_args=(-f ascending -n missing -N video)
            terminal_pattern='Got an error fetching via ID 0'
            client_patterns=('Got an error fetching via ID 0' "Getting rid of FETCH '0'")
            server_patterns=('fetch_response|request_id:0|result:error|end:none|fetch_ok_ret:0|fetch_header_ret:not-sent|fin:1|closed:1')
            ;;
        xquic-to-imquic-subgroup)
            mode=0
            frame_num=2
            server_extra=(-T)
            client_args=(-n namespace -N video)
            terminal_pattern='Incoming object:'
            terminal_count=2
            client_patterns=(
                "Subscribing to 'namespace--video'"
                'group=1, subgroup=0 (first=1), id=0'
                'group=1, subgroup=1 (first=1), id=1'
                'delivery=STREAM_HEADER_SUBGROUP, status=NORMAL_OBJECT, eos=1'
            )
            server_patterns=(
                'server_send_video_frame|subscribe_id:0|seq:0|'
                'server_send_video_frame|subscribe_id:0|seq:1|'
            )
            ;;
        xquic-to-imquic-datagram)
            mode=0
            frame_num=2
            server_extra=(-G -T)
            client_args=(-n namespace -N video)
            terminal_pattern='delivery=OBJECT_DATAGRAM'
            terminal_count=2
            client_patterns=(
                "Subscribing to 'namespace--video'"
                'group=1, subgroup=0 (first=0), id=0, priority=7'
                'group=1, subgroup=0 (first=0), id=1, priority=7'
                'delivery=OBJECT_DATAGRAM, status=NORMAL_OBJECT, eos=0'
            )
            server_patterns=(
                'server_send_object_datagram|track:video|alias:0|group:1|object:0|'
                'server_send_object_datagram|track:video|alias:0|group:1|object:1|'
            )
            ;;
        imquic-to-xquic-subgroup)
            mode=13
            server_role=sub
            server_extra=(-o -T)
            client_bin=${PUBLISHER}
            terminal_side=server
            client_args=(-X -n interop -N data -D subgroup -x)
            terminal_pattern='on_raw_object:'
            terminal_count=2
            client_patterns=("Publish '0' accepted" 'Starting to send MoQ objects')
            server_patterns=(
                'on_publish: subscribe_id:0 track:interop/data'
                'on_raw_object: track_namespace:interop track_name:data subscribe_id:0 group_id:1 subgroup_id:0 object_id:0'
                'on_raw_object: track_namespace:interop track_name:data subscribe_id:0 group_id:1 subgroup_id:0 object_id:1'
                'properties_present:1'
            )
            ;;
        imquic-to-xquic-datagram)
            mode=13
            server_role=sub
            server_extra=(-o -T)
            client_bin=${PUBLISHER}
            terminal_side=server
            client_args=(-X -n interop -N data -D datagram -x)
            terminal_pattern='on_datagram_object:'
            terminal_count=2
            client_patterns=("Publish '0' accepted" 'Starting to send MoQ objects')
            server_patterns=(
                'on_publish: subscribe_id:0 track:interop/data'
                'on_datagram_object: ns:interop name:data alias:0 group:1 id:0'
                'on_datagram_object: ns:interop name:data alias:0 group:1 id:1'
                'properties_present:1'
            )
            ;;
        imquic-to-xquic-fetch)
            mode=14
            server_role=sub
            server_extra=(-T)
            client_bin=${PUBLISHER}
            terminal_side=server
            client_args=(-n interop -N data -D subgroup)
            terminal_pattern='control_e2e_server|fetch_object|'
            terminal_count=3
            client_patterns=(
                'interop_fetch_responder|request_id:1|track:interop/data|range:1/0-5/'
                'interop_fetch_responder|accepted|request_id:1|end:4/0|ret:0'
                'interop_fetch_responder|object|index:0|group:2|subgroup:3|object:4|payload:14|properties:1|eos:0|ret:0'
                'interop_fetch_responder|object|index:1|group:2|subgroup:3|object:5|payload:0|properties:0|eos:0|ret:0'
                'interop_fetch_responder|object|index:2|group:4|subgroup:4|object:0|payload:14|properties:0|eos:1|ret:0'
            )
            server_patterns=(
                'control_e2e_server|fetch_sent|request_id:1|track:interop/data|range:1/0-5/max|ret:0'
                'control_e2e_server|fetch_ok|request_id:1|expected:1|end_of_track:1|end:4/0|properties:0'
                'control_e2e_server|fetch_header|request_id:1|fin:0'
                'control_e2e_server|fetch_object|request_id:1|index:0|group:2|subgroup:3|object:4|priority:7|payload:14|'
                'control_e2e_server|fetch_payload|index:0|value:imquic-fetch-A'
                'control_e2e_server|fetch_object|request_id:1|index:1|group:2|subgroup:3|object:5|priority:7|payload:0|'
                'control_e2e_server|fetch_object|request_id:1|index:2|group:4|subgroup:4|object:0|priority:7|payload:14|'
                'control_e2e_server|fetch_payload|index:2|value:imquic-fetch-C'
                'control_e2e_server|fetch_complete|request_id:1|error:0|objects:3'
            )
            ;;
        *)
            echo "unknown reverse interop case: ${case_name}" >&2
            return 1
            ;;
    esac

    local case_dir="${RUN_DIR}/${case_name}"
    local server_log="${case_dir}/server.out"
    local client_log="${case_dir}/client.out"
    local port
    mkdir -p "${case_dir}"
    cp "${CERT_FILE}" "${case_dir}/server.crt"
    cp "${KEY_FILE}" "${case_dir}/server.key"
    lease_port "${ordinal}" || return 1
    port=${LEASED_PORT}

    local -a server_args=(-l d -p "${port}" -n "${frame_num}" -Q "${mode}")
    if [[ -n "${server_role}" ]]; then
        server_args+=(-r "${server_role}")
    fi
    if [[ ${#server_extra[@]} -gt 0 ]]; then
        server_args+=("${server_extra[@]}")
    fi
    if [[ ${namespace_mode} -ne 0 ]]; then
        server_args+=(-K "${namespace_mode}")
    fi
    (
        cd "${case_dir}" || exit 1
        exec "${SERVER}" "${server_args[@]}"
    ) >"${server_log}" 2>&1 &
    SERVER_PID=$!
    if ! wait_for_pattern "${SERVER_PID}" "${server_log}" 'MoQ server ready' "${CASE_TIMEOUT}"; then
        stop_pid "${SERVER_PID}" INT
        SERVER_PID=
        return 1
    fi

    (
        cd "${case_dir}" || exit 1
        exec "${client_bin}" -M 18 -q -b 127.0.0.1 \
            -r 127.0.0.1 -R "${port}" \
            -S localhost -d 7 "${client_args[@]}"
    ) >"${client_log}" 2>&1 &
    CLIENT_PID=$!

    local reached=0
    local terminal_pid=${CLIENT_PID}
    local terminal_file=${client_log}
    if [[ ${terminal_side} == server ]]; then
        terminal_pid=${SERVER_PID}
        terminal_file=${server_log}
    fi
    if [[ ${terminal_count} -gt 1 ]]; then
        wait_for_count "${terminal_pid}" "${terminal_file}" "${terminal_pattern}" \
            "${terminal_count}" "${CASE_TIMEOUT}" && reached=1
    else
        wait_for_pattern "${terminal_pid}" "${terminal_file}" "${terminal_pattern}" \
            "${CASE_TIMEOUT}" && reached=1
    fi
    sleep 0.4
    stop_pid "${CLIENT_PID}" INT
    CLIENT_PID=
    stop_pid "${SERVER_PID}" INT
    SERVER_PID=

    [[ ${reached} -eq 1 ]] || return 1
    local pattern
    for pattern in "${client_patterns[@]}"; do
        assert_contains "${client_log}" "${pattern}" || return 1
    done
    for pattern in "${server_patterns[@]}"; do
        assert_contains "${server_log}" "${pattern}" || return 1
    done
    assert_clean_logs "${client_log}" "${server_log}" || return 1

    if [[ ${case_name} == publish-done ]]; then
        local callbacks
        callbacks=$(grep -Fc 'Subscription via ID 1 is done' "${client_log}" || true)
        [[ ${callbacks} -eq 1 ]] || return 1
    fi
    if [[ ${case_name} == request-goaway ]] \
        && grep -Fq 'Got RESET_STREAM for STREAM 4:' "${client_log}"
    then
        return 1
    fi
    return 0
}

run_official_case() {
    local case_name=$1
    local ordinal=$2
    local mode=0
    case "${case_name}" in
        setup-only|announce-only|publish-namespace-done)
            mode=0
            ;;
        subscribe-error)
            mode=12
            ;;
        announce-subscribe|subscribe-before-announce)
            mode=11
            ;;
        *)
            echo "unknown official interop case: ${case_name}" >&2
            return 1
            ;;
    esac

    local case_dir="${RUN_DIR}/official-${case_name}"
    local server_log="${case_dir}/server.out"
    local client_log="${case_dir}/client.out"
    local server_slog="${case_dir}/slog"
    local port
    mkdir -p "${case_dir}"
    cp "${CERT_FILE}" "${case_dir}/server.crt"
    cp "${KEY_FILE}" "${case_dir}/server.key"
    lease_port "${ordinal}" || return 1
    port=${LEASED_PORT}

    (
        cd "${case_dir}" || exit 1
        exec "${SERVER}" -l d -p "${port}" -n 1000 -Q "${mode}"
    ) >"${server_log}" 2>&1 &
    SERVER_PID=$!
    if ! wait_for_pattern "${SERVER_PID}" "${server_log}" \
        'MoQ server ready' "${CASE_TIMEOUT}"
    then
        stop_pid "${SERVER_PID}" INT
        SERVER_PID=
        return 1
    fi

    (
        cd "${case_dir}" || exit 1
		if [[ "${case_name}" == "setup-only" ]]; then
			export IMQUIC_INTEROP_HOLD_SETUP_READY=1
		fi
        exec "${OFFICIAL_CLIENT}" \
            -r "moqt://127.0.0.1:${port}" -t "${case_name}" \
            --tls-disable-verify -v
    ) >"${client_log}" 2>&1 &
    CLIENT_PID=$!
    local reached=0
	if [[ "${case_name}" == "setup-only" ]]; then
		wait_for_pattern "${CLIENT_PID}" "${client_log}" \
			'# MoQ setup ready; waiting for peer evidence' "${CASE_TIMEOUT}" \
			&& wait_for_pattern "${SERVER_PID}" "${server_slog}" \
				'moq_setup_active|profile:draft-18' "${CASE_TIMEOUT}" \
			&& reached=1
	else
		wait_for_pattern "${CLIENT_PID}" "${client_log}" \
			"ok 1 - ${case_name}" "${CASE_TIMEOUT}" && reached=1
	fi
    stop_pid "${CLIENT_PID}" INT
    CLIENT_PID=
    stop_pid "${SERVER_PID}" INT
    SERVER_PID=

    [[ ${reached} -eq 1 ]] || return 1
    grep -Fqx "ok 1 - ${case_name}" "${client_log}" || return 1
    if grep -Eq '^not ok |Error parsing MoQ message|PROTOCOL_VIOLATION|Invalid Request ID' "${client_log}" \
        || grep -Eq 'decode message error|PROTOCOL_VIOLATION|conn_err:0x3' "${server_log}"
    then
        return 1
    fi

    case "${case_name}" in
        setup-only)
            assert_contains "${server_slog}" 'moq_setup_active|profile:draft-18' || return 1
            ;;
        announce-only)
            assert_contains "${server_slog}" 'publish_namespace request accepted|request_id:0' || return 1
            ;;
        publish-namespace-done)
            assert_contains "${server_slog}" 'publish_namespace request accepted|request_id:0' || return 1
            assert_contains "${server_slog}" 'publish_namespace request ended|request_id:0' || return 1
            ;;
        subscribe-error)
            assert_contains "${server_log}" 'subscribe_response|request_id:0|result:error|code:0x10|ret:0' || return 1
            ;;
        announce-subscribe|subscribe-before-announce)
            assert_contains "${server_slog}" 'publish_namespace request accepted|request_id:0' || return 1
            assert_contains "${server_log}" 'subscribe_response|request_id:0|result:ok|namespace_ready:1|ret:0' || return 1
            ;;
    esac
    return 0
}

PASS=0
FAIL=0
ordinal=0
for case_name in "${CASES[@]}"; do
    printf '  %-32s ' "${case_name}"
    if run_case "${case_name}" "${ordinal}"; then
        echo PASS
        PASS=$((PASS + 1))
    else
        echo FAIL
        case_dir="${RUN_DIR}/${case_name}"
        grep -E 'Error parsing|PROTOCOL_VIOLATION|Invalid Request ID|Broken properties|control_e2e|Got a GOAWAY|accepted|Got an error|PUBLISH' \
            "${case_dir}/client.out" "${case_dir}/server.out" 2>/dev/null \
            | tail -40 | sed 's/^/    /' || true
        FAIL=$((FAIL + 1))
    fi
    ordinal=$((ordinal + 1))
done

CONTROL_PASS=${PASS}
CONTROL_FAIL=${FAIL}
OFFICIAL_PASS=0
OFFICIAL_FAIL=0
for case_name in ${OFFICIAL_CASE_LIST}; do
    printf '  official/%-23s ' "${case_name}"
    if run_official_case "${case_name}" "${ordinal}"; then
        echo PASS
        PASS=$((PASS + 1))
        OFFICIAL_PASS=$((OFFICIAL_PASS + 1))
    else
        echo FAIL
        case_dir="${RUN_DIR}/official-${case_name}"
        grep -E '^(ok|not ok) |Error parsing|PROTOCOL_VIOLATION|control_e2e|publish_namespace' \
            "${case_dir}/client.out" "${case_dir}/server.out" \
            "${case_dir}/slog" 2>/dev/null | tail -40 \
            | sed 's/^/    /' || true
        FAIL=$((FAIL + 1))
        OFFICIAL_FAIL=$((OFFICIAL_FAIL + 1))
    fi
    ordinal=$((ordinal + 1))
done

trap - EXIT INT TERM
cleanup
printf 'imquic -> xquic draft-18 extended controls: pass=%d fail=%d\n' \
    "${CONTROL_PASS}" "${CONTROL_FAIL}"
printf 'imquic official -> xquic draft-18 roles: pass=%d fail=%d\n' \
    "${OFFICIAL_PASS}" "${OFFICIAL_FAIL}"
printf 'imquic -> xquic draft-18 total: pass=%d fail=%d\n' \
    "${PASS}" "${FAIL}"
printf 'evidence: %s\n' "${RUN_DIR}"

EXPECTED_TOTAL=$((${#CASES[@]} + OFFICIAL_PASS + OFFICIAL_FAIL))
[[ ${FAIL} -eq 0 && ${PASS} -eq ${EXPECTED_TOTAL} ]]
