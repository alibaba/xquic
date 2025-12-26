#!/bin/bash

# Copyright (c) 2022, Alibaba Group Holding Limited

# New MOQ end-to-end test script. Test cases includes:
# 1.publish stream 2.dynamic datachannel, 3.raw object mode.

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
cd "${REPO_ROOT}/build" || exit 1

CLIENT_BIN="moq/demo/moq_demo_client"
SERVER_BIN="moq/demo/moq_demo_server"

SERVER_PID=""
CLIENT_STDLOG=""
SERVER_STDLOG=""
SERVER_BASE_ARGS=("-c" "b" "-p" "4433" "-V")
CLIENT_BASE_ARGS=("-a" "127.0.0.1" "-p" "4433" "-V")
TOTAL_CASES=0
PASSED_CASES=0
FAILED_CASES=()

clear_log() {
    : > clog
    : > slog
}

reset_runtime() {
    rm -rf tp_localhost test_session xqc_token
    clear_log
}

start_server() {
    local case_name=$1
    shift
    SERVER_STDLOG="server_${case_name}.log"
    ${SERVER_BIN} "$@" > "${SERVER_STDLOG}" 2>&1 &
    SERVER_PID=$!
    sleep 1
}

stop_server() {
    if [ -n "${SERVER_PID}" ]; then
        kill "${SERVER_PID}" 2>/dev/null
        wait "${SERVER_PID}" 2>/dev/null
        SERVER_PID=""
    fi
    killall moq_demo_server 2>/dev/null
}

run_client() {
    local case_name=$1
    shift
    CLIENT_STDLOG="client_${case_name}.log"
    ${CLIENT_BIN} "$@" > "${CLIENT_STDLOG}" 2>&1
    return $?
}

get_err_log() {
    local err_clog err_slog output=""
    err_clog=$(grep "\[error\]" clog 2>/dev/null || true)
    err_slog=$(grep "\[error\]" slog 2>/dev/null || true)
    if [ -n "${err_clog}" ]; then
        output="${err_clog}"
    fi
    if [ -n "${err_slog}" ]; then
        if [ -n "${output}" ]; then
            output="${output}"$'\n'"${err_slog}"
        else
            output="${err_slog}"
        fi
    fi
    printf "%s" "${output}"
}

# params: case_name, result
case_print_result() {
    echo "[ RUN      ] moq_case_e2e.$1"
    if [ "$2" = "pass" ]; then
        echo "[       OK ] moq_case_e2e.$1 (1 ms)"
    else
        echo "[     FAIL ] moq_case_e2e.$1 (1 ms)"
    fi
}

record_case_result() {
    local name=$1
    local status=$2
    TOTAL_CASES=$((TOTAL_CASES + 1))
    if [ "${status}" = "pass" ]; then
        PASSED_CASES=$((PASSED_CASES + 1))
    else
        FAILED_CASES+=("${name}")
    fi
}

run_publish_case() {
    local case_name="publish_basic"
    local status="fail"
    echo -e "moq publish only ...\c"
    reset_runtime
    start_server "${case_name}" "${SERVER_BASE_ARGS[@]}" -r pub -n 60
    run_client "${case_name}" "${CLIENT_BASE_ARGS[@]}" -r sub -n 60
    local cli_res errlog
    cli_res=$(grep "|on_video|" clog | grep "seq:59" 2>/dev/null || true)
    errlog=$(get_err_log)
    if [ -n "${cli_res}" ] && [ -z "${errlog}" ]; then
        echo ">>>>>>>> pass:1"
        status="pass"
    else
        echo ">>>>>>>> pass:0"
        echo "${errlog}"
        echo "${cli_res}"
    fi
    case_print_result "${case_name}" "${status}"
    record_case_result "${case_name}" "${status}"
    stop_server
}

run_publish_reply_case() {
    local case_name="publish_reply"
    local status="fail"
    echo -e "moq publish reply ok/error ...\c"

    # sub-case 1: server replies PUBLISH_OK for both video/audio
    reset_runtime
    start_server "${case_name}_ok" "${SERVER_BASE_ARGS[@]}" -r sub -n 1 -o
    run_client "${case_name}_ok" "${CLIENT_BASE_ARGS[@]}" -r pub -n 1 -M
    local cli_ok_cnt errlog_ok
    cli_ok_cnt=$(grep -c "on_publish_ok:" "client_${case_name}_ok.log" 2>/dev/null || true)
    errlog_ok=$(get_err_log)
    stop_server

    # sub-case 2: server replies PUBLISH_ERROR for both video/audio
    reset_runtime
    start_server "${case_name}_err" "${SERVER_BASE_ARGS[@]}" -r sub -n 1 -e
    run_client "${case_name}_err" "${CLIENT_BASE_ARGS[@]}" -r pub -n 1 -M
    local cli_err_cnt errlog_err
    cli_err_cnt=$(grep -c "on_publish_error:" "client_${case_name}_err.log" 2>/dev/null || true)
    errlog_err=$(get_err_log)
    stop_server

    if [ "${cli_ok_cnt}" -ge 2 ] && [ -z "${errlog_ok}" ] \
       && [ "${cli_err_cnt}" -ge 2 ] && [ -z "${errlog_err}" ]; then
        echo ">>>>>>>> pass:1"
        status="pass"
    else
        echo ">>>>>>>> pass:0"
        echo "ok_case_error_log:"
        echo "${errlog_ok}"
        echo "ok_case_on_publish_ok count: ${cli_ok_cnt}"
        echo "err_case_error_log:"
        echo "${errlog_err}"
        echo "err_case_on_publish_error count: ${cli_err_cnt}"
    fi

    case_print_result "${case_name}" "${status}"
    record_case_result "${case_name}" "${status}"
}

run_datachannel_case() {
    local case_name="datachannel_dynamic"
    local status="fail"
    echo -e "moq dynamic datachannel ...\c"
    reset_runtime
    start_server "${case_name}" "${SERVER_BASE_ARGS[@]}" -n 10 -M
    run_client "${case_name}" "${CLIENT_BASE_ARGS[@]}" -n 10 -M
    local cli_create cli_send svr_dc errlog
    cli_create=$(grep "create extra datachannel" "${CLIENT_STDLOG}" 2>/dev/null || true)
    cli_send=$(grep "send msg on extra datachannel" "${CLIENT_STDLOG}" 2>/dev/null || true)
    svr_dc=$(grep "|on_datachannel_msg_detail|" slog 2>/dev/null || true)
    errlog=$(get_err_log)
    if [ -n "${cli_create}" ] && [ -n "${cli_send}" ] && [ -n "${svr_dc}" ] && [ -z "${errlog}" ]; then
        echo ">>>>>>>> pass:1"
        status="pass"
    else
        echo ">>>>>>>> pass:0"
        echo "${errlog}"
        echo "${cli_create}"
        echo "${cli_send}"
        echo "${svr_dc}"
    fi
    case_print_result "${case_name}" "${status}"
    record_case_result "${case_name}" "${status}"
    stop_server
}

run_raw_object_case() {
    local case_name="raw_object_mode"
    local status="fail"
    echo -e "moq raw object (-R) ...\c"
    reset_runtime
    start_server "${case_name}" "${SERVER_BASE_ARGS[@]}" -n 10 -M -R
    run_client "${case_name}" "${CLIENT_BASE_ARGS[@]}" -n 10 -M -R
    local cli_raw svr_raw errlog
    cli_raw=$(grep "|write raw object success|" clog 2>/dev/null || true)
    svr_raw=$(grep "on_raw_object:" "${SERVER_STDLOG}" 2>/dev/null || true)
    errlog=$(get_err_log)
    if [ -n "${cli_raw}" ] && [ -n "${svr_raw}" ] && [ -z "${errlog}" ]; then
        echo ">>>>>>>> pass:1"
        status="pass"
    else
        echo ">>>>>>>> pass:0"
        echo "${errlog}"
        echo "${cli_raw}"
        echo "${svr_raw}"
    fi
    case_print_result "${case_name}" "${status}"
    record_case_result "${case_name}" "${status}"
    stop_server
}

run_publish_case
run_publish_reply_case
run_datachannel_case
run_raw_object_case

run_subgroup_multi_object_case() {
    local case_name="subgroup_multi_object"
    local status="fail"
    echo -e "moq subgroup multi-object on single stream ...\c"
    reset_runtime
    start_server "${case_name}" "${SERVER_BASE_ARGS[@]}" -n 10 -V -M
    run_client "${case_name}" "${CLIENT_BASE_ARGS[@]}" -n 10 -V -M
    local errlog audio_lines obj_cnt stream_cnt delta_bad
    errlog=$(get_err_log)

    audio_lines=$(grep "server_recv_subgroup" slog 2>/dev/null | \
                  grep "track_alias:2|group_id:0|subgroup_id:0|" || true)
    if [ -n "${audio_lines}" ]; then
        obj_cnt=$(echo "${audio_lines}" | awk -F'object_id:' '{print $2}' | \
                  awk -F'|' '{print $1}' | sort -u | wc -l | tr -d ' ')
        stream_cnt=$(echo "${audio_lines}" | awk -F'stream_id:' '{print $2}' | \
                     awk -F'|' '{print $1}' | sort -u | wc -l | tr -d ' ')
        # verify Object ID Delta semantics for subgroup stream:
        # for object_id > 0 we expect object_id_delta == 0 (sequential IDs with true delta)
        delta_bad=$(echo "${audio_lines}" | awk -F'|' '
        {
            id = -1; d = -1;
            for (i = 1; i <= NF; i++) {
                if ($i ~ /object_id:/) {
                    gsub(/object_id:/, "", $i);
                    id = $i;
                } else if ($i ~ /object_id_delta:/) {
                    gsub(/object_id_delta:/, "", $i);
                    d = $i;
                }
            }
            if (id > 0 && d != 0) {
                bad = 1;
            }
        }
        END {
            if (bad == 1) {
                print "bad";
            }
        }')
    else
        obj_cnt=0
        stream_cnt=0
        delta_bad=""
    fi
    if [ "${obj_cnt}" -ge 10 ] && [ "${stream_cnt}" -eq 1 ] && [ -z "${errlog}" ] && [ -z "${delta_bad}" ]; then
        echo ">>>>>>>> pass:1"
        status="pass"
    else
        echo ">>>>>>>> pass:0"
        echo "${errlog}"
        echo "audio subgroup lines:"
        echo "${audio_lines}"
        echo "distinct object_id count: ${obj_cnt}, distinct stream_id count: ${stream_cnt}"
    fi
    case_print_result "${case_name}" "${status}"
    record_case_result "${case_name}" "${status}"
    stop_server
}

run_subgroup_multi_object_case

echo
echo "moq_case_e2e summary: ${PASSED_CASES}/${TOTAL_CASES} passed"
if [ "${PASSED_CASES}" -ne "${TOTAL_CASES}" ]; then
    echo "failed cases: ${FAILED_CASES[*]}"
fi

if [ "${PASSED_CASES}" -ne "${TOTAL_CASES}" ]; then
    exit 1
fi

cd - >/dev/null || exit 0

