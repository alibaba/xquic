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
LAST_CLIENT_RC=0
LAST_SERVER_RC=0

tail_file() {
    local file=$1
    local lines=${2:-80}
    if [ -f "${file}" ]; then
        tail -n "${lines}" "${file}"
    fi
}

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
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        wait "${SERVER_PID}" 2>/dev/null
        LAST_SERVER_RC=$?
        echo
        echo "server exited early: rc=${LAST_SERVER_RC}, log=${SERVER_STDLOG}"
        tail_file "${SERVER_STDLOG}"
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
    killall moq_demo_server 2>/dev/null
}

check_server_rc() {
    local case_name=$1
    if [ -z "${SERVER_PID}" ]; then
        return 0
    fi
    if kill -0 "${SERVER_PID}" 2>/dev/null; then
        return 0
    fi
    wait "${SERVER_PID}" 2>/dev/null
    LAST_SERVER_RC=$?
    SERVER_PID=""
    if [ "${LAST_SERVER_RC}" -ne 0 ]; then
        echo "server exited non-zero: rc=${LAST_SERVER_RC}, log=server_${case_name}.log"
        tail_file "server_${case_name}.log"
        return 1
    fi
    return 0
}

run_client() {
    local case_name=$1
    shift
    CLIENT_STDLOG="client_${case_name}.log"
    ${CLIENT_BIN} "$@" > "${CLIENT_STDLOG}" 2>&1
    LAST_CLIENT_RC=$?
    return ${LAST_CLIENT_RC}
}

check_client_rc() {
    local case_name=$1
    if [ "${LAST_CLIENT_RC}" -ne 0 ]; then
        echo "client exited non-zero: rc=${LAST_CLIENT_RC}, log=client_${case_name}.log"
        tail_file "client_${case_name}.log"
        return 1
    fi
    return 0
}

extract_subscribe_ids() {
    # params: file, grep_pattern
    local file=$1
    local pattern=$2
    grep -E "${pattern}" "${file}" 2>/dev/null | \
        sed -E 's/.*subscribe_id:([0-9]+).*/\1/' | \
        sort -n
}

uniq_join_lines() {
    # join stdin unique lines into a single comma-separated string
    sort -n -u | tr '\n' ',' | sed 's/,$//'
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
    if start_server "${case_name}" "${SERVER_BASE_ARGS[@]}" -r pub -n 60; then
        run_client "${case_name}" "${CLIENT_BASE_ARGS[@]}" -r sub -n 60
    else
        CLIENT_STDLOG="client_${case_name}.log"
        LAST_CLIENT_RC=1
    fi
    local cli_res errlog
    cli_res=$(grep "|on_video|" clog | grep "seq:59" 2>/dev/null || true)
    errlog=$(get_err_log)
    if check_client_rc "${case_name}" && check_server_rc "${case_name}" \
       && [ -n "${cli_res}" ] && [ -z "${errlog}" ]; then
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
    local expected_ids=("2" "4")
    local expected_id_list
    expected_id_list="$(printf "%s\n" "${expected_ids[@]}" | uniq_join_lines)"

    # sub-case 1: server replies PUBLISH_OK for both video/audio
    reset_runtime
    local ok_started
    ok_started=1
    if start_server "${case_name}_ok" "${SERVER_BASE_ARGS[@]}" -r sub -n 1 -o; then
        run_client "${case_name}_ok" "${CLIENT_BASE_ARGS[@]}" -r pub -n 1 -M
    else
        ok_started=0
        LAST_CLIENT_RC=1
    fi
    local cli_ok_cnt errlog_ok ok_cli_ids ok_svr_ids ok_ok
    ok_ok=1
    cli_ok_cnt=$(grep -c "on_publish_ok: subscribe_id:" "client_${case_name}_ok.log" 2>/dev/null || true)
    errlog_ok=$(get_err_log)
    ok_cli_ids=$(extract_subscribe_ids "client_${case_name}_ok.log" "on_publish_ok: subscribe_id:" | uniq_join_lines)
    if [ "${ok_started}" -ne 1 ]; then ok_ok=0; fi
    if ! check_client_rc "${case_name}_ok"; then ok_ok=0; fi
    if ! check_server_rc "${case_name}_ok"; then ok_ok=0; fi
    if [ -n "${errlog_ok}" ]; then ok_ok=0; fi
    stop_server
    ok_svr_ids=$(extract_subscribe_ids "server_${case_name}_ok.log" "on_publish: subscribe_id:" | uniq_join_lines)
    for id in "${expected_ids[@]}"; do
        if [ "$(grep -cE "on_publish_ok: subscribe_id:${id}([^0-9]|$)" "client_${case_name}_ok.log" 2>/dev/null || true)" -ne 1 ]; then
            ok_ok=0
        fi
        if [ "$(grep -cE "on_publish: subscribe_id:${id}([^0-9]|$)" "server_${case_name}_ok.log" 2>/dev/null || true)" -ne 1 ]; then
            ok_ok=0
        fi
    done

    # sub-case 2: server replies PUBLISH_ERROR for both video/audio
    reset_runtime
    local err_started
    err_started=1
    if start_server "${case_name}_err" "${SERVER_BASE_ARGS[@]}" -r sub -n 1 -e; then
        run_client "${case_name}_err" "${CLIENT_BASE_ARGS[@]}" -r pub -n 1 -M
    else
        err_started=0
        LAST_CLIENT_RC=1
    fi
    local cli_err_cnt errlog_err err_cli_ids err_svr_ids err_ok
    err_ok=1
    cli_err_cnt=$(grep -c "on_publish_error: subscribe_id:" "client_${case_name}_err.log" 2>/dev/null || true)
    errlog_err=$(get_err_log)
    err_cli_ids=$(extract_subscribe_ids "client_${case_name}_err.log" "on_publish_error: subscribe_id:" | uniq_join_lines)
    if [ "${err_started}" -ne 1 ]; then err_ok=0; fi
    if ! check_client_rc "${case_name}_err"; then err_ok=0; fi
    if ! check_server_rc "${case_name}_err"; then err_ok=0; fi
    if [ -n "${errlog_err}" ]; then err_ok=0; fi
    stop_server
    err_svr_ids=$(extract_subscribe_ids "server_${case_name}_err.log" "on_publish: subscribe_id:" | uniq_join_lines)
    for id in "${expected_ids[@]}"; do
        if [ "$(grep -cE "on_publish_error: subscribe_id:${id}([^0-9]|$)" "client_${case_name}_err.log" 2>/dev/null || true)" -ne 1 ]; then
            err_ok=0
        fi
        if [ "$(grep -cE "on_publish_error: subscribe_id:${id}([^0-9]|$).*reason:demo publish error" "client_${case_name}_err.log" 2>/dev/null || true)" -ne 1 ]; then
            err_ok=0
        fi
        if [ "$(grep -cE "on_publish: subscribe_id:${id}([^0-9]|$)" "server_${case_name}_err.log" 2>/dev/null || true)" -ne 1 ]; then
            err_ok=0
        fi
    done

    if [ "${ok_ok}" -eq 1 ] && [ "${err_ok}" -eq 1 ] \
       && [ "${cli_ok_cnt}" -eq 2 ] && [ "${cli_err_cnt}" -eq 2 ] \
       && [ "${ok_cli_ids}" = "${expected_id_list}" ] \
       && [ "${ok_svr_ids}" = "${expected_id_list}" ] \
       && [ "${err_cli_ids}" = "${expected_id_list}" ] \
       && [ "${err_svr_ids}" = "${expected_id_list}" ]; then
        echo ">>>>>>>> pass:1"
        status="pass"
    else
        echo ">>>>>>>> pass:0"
        echo "ok_case_error_log:"
        echo "${errlog_ok}"
        echo "ok_case_on_publish_ok count: ${cli_ok_cnt}"
        echo "ok_case_client_subscribe_ids: ${ok_cli_ids}"
        echo "ok_case_server_subscribe_ids: ${ok_svr_ids}"
        echo "err_case_error_log:"
        echo "${errlog_err}"
        echo "err_case_on_publish_error count: ${cli_err_cnt}"
        echo "err_case_client_subscribe_ids: ${err_cli_ids}"
        echo "err_case_server_subscribe_ids: ${err_svr_ids}"
    fi

    case_print_result "${case_name}" "${status}"
    record_case_result "${case_name}" "${status}"
}

run_datachannel_case() {
    local case_name="datachannel_dynamic"
    local status="fail"
    echo -e "moq dynamic datachannel ...\c"
    reset_runtime
    if start_server "${case_name}" "${SERVER_BASE_ARGS[@]}" -n 10 -M; then
        run_client "${case_name}" "${CLIENT_BASE_ARGS[@]}" -n 10 -M
    else
        CLIENT_STDLOG="client_${case_name}.log"
        LAST_CLIENT_RC=1
    fi
    local cli_create cli_send svr_dc errlog
    cli_create=$(grep "create extra datachannel" "${CLIENT_STDLOG}" 2>/dev/null || true)
    cli_send=$(grep "send msg on extra datachannel" "${CLIENT_STDLOG}" 2>/dev/null || true)
    svr_dc=$(grep "|on_datachannel_msg_detail|" slog 2>/dev/null || true)
    errlog=$(get_err_log)
    if check_client_rc "${case_name}" && check_server_rc "${case_name}" \
       && [ -n "${cli_create}" ] && [ -n "${cli_send}" ] && [ -n "${svr_dc}" ] && [ -z "${errlog}" ]; then
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

run_datachannel_reuse_default_case() {
    local case_name="datachannel_reuse_default"
    local status="fail"
    echo -e "moq default datachannel reuse ...\c"
    reset_runtime
    if start_server "${case_name}" "${SERVER_BASE_ARGS[@]}" -r pub -n 3 -U; then
        run_client "${case_name}" "${CLIENT_BASE_ARGS[@]}" -r sub -n 3 -U
    else
        CLIENT_STDLOG="client_${case_name}.log"
        LAST_CLIENT_RC=1
    fi

    local errlog dc_lines dc_group dc_has_obj1
    errlog=$(get_err_log)
    dc_lines=$(grep "xqc_moq_send_datachannel_msg|send datachannel msg success (subgroup)" clog 2>/dev/null || true)
    dc_group=$(echo "${dc_lines}" | grep "object_id:0|" | head -n 1 | sed -E 's/.*group_id:([0-9]+).*/\1/' || true)
    if [ -n "${dc_group}" ]; then
        dc_has_obj1=$(echo "${dc_lines}" | grep "group_id:${dc_group}|" | grep "object_id:1|" || true)
    else
        dc_has_obj1=""
    fi

    if check_client_rc "${case_name}" && check_server_rc "${case_name}" \
       && [ -n "${dc_group}" ] && [ -n "${dc_has_obj1}" ] && [ -z "${errlog}" ]; then
        echo ">>>>>>>> pass:1"
        status="pass"
    else
        echo ">>>>>>>> pass:0"
        echo "${errlog}"
        echo "${dc_lines}"
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
    if start_server "${case_name}" "${SERVER_BASE_ARGS[@]}" -n 10 -M -R; then
        run_client "${case_name}" "${CLIENT_BASE_ARGS[@]}" -n 10 -M -R
    else
        CLIENT_STDLOG="client_${case_name}.log"
        LAST_CLIENT_RC=1
    fi
    local cli_raw svr_raw errlog
    cli_raw=$(grep "|write raw object success|" clog 2>/dev/null || true)
    svr_raw=$(grep "on_raw_object:" "${SERVER_STDLOG}" 2>/dev/null || true)
    errlog=$(get_err_log)
    if check_client_rc "${case_name}" && check_server_rc "${case_name}" \
       && [ -n "${cli_raw}" ] && [ -n "${svr_raw}" ] && [ -z "${errlog}" ]; then
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

run_raw_object_reuse_case() {
    local case_name="raw_object_reuse"
    local status="fail"
    echo -e "moq raw object reuse (-R -W) ...\c"
    reset_runtime
    if start_server "${case_name}" "${SERVER_BASE_ARGS[@]}" -n 10 -M -R; then
        run_client "${case_name}" "${CLIENT_BASE_ARGS[@]}" -n 10 -M -R -W
    else
        CLIENT_STDLOG="client_${case_name}.log"
        LAST_CLIENT_RC=1
    fi
    local errlog audio_lines obj_cnt stream_cnt delta_bad cli_raw svr_raw
    errlog=$(get_err_log)
    cli_raw=$(grep "|write raw object success|" clog 2>/dev/null || true)
    svr_raw=$(grep "on_raw_object:" "${SERVER_STDLOG}" 2>/dev/null || true)

    audio_lines=$(grep "server_recv_subgroup" slog 2>/dev/null | \
                  grep "track_alias:2|group_id:0|subgroup_id:0|" || true)
    if [ -n "${audio_lines}" ]; then
        obj_cnt=$(echo "${audio_lines}" | awk -F'object_id:' '{print $2}' | \
                  awk -F'|' '{print $1}' | sort -u | wc -l | tr -d ' ')
        stream_cnt=$(echo "${audio_lines}" | awk -F'stream_id:' '{print $2}' | \
                     awk -F'|' '{print $1}' | sort -u | wc -l | tr -d ' ')
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

    if check_client_rc "${case_name}" && check_server_rc "${case_name}" \
       && [ -n "${cli_raw}" ] && [ -n "${svr_raw}" ] \
       && [ "${obj_cnt}" -ge 2 ] && [ "${stream_cnt}" -eq 1 ] && [ -z "${errlog}" ] && [ -z "${delta_bad}" ]; then
        echo ">>>>>>>> pass:1"
        status="pass"
    else
        echo ">>>>>>>> pass:0"
        echo "${errlog}"
        echo "client raw object lines:"
        echo "${cli_raw}"
        echo "server raw object lines:"
        echo "${svr_raw}"
        echo "audio subgroup lines:"
        echo "${audio_lines}"
        echo "distinct object_id count: ${obj_cnt}, distinct stream_id count: ${stream_cnt}"
    fi
    case_print_result "${case_name}" "${status}"
    record_case_result "${case_name}" "${status}"
    stop_server
}

run_publish_case
run_publish_reply_case
run_datachannel_case
run_datachannel_reuse_default_case
run_raw_object_case
run_raw_object_reuse_case

run_subgroup_multi_object_case() {
    local case_name="subgroup_multi_object"
    local status="fail"
    echo -e "moq subgroup multi-object on single stream ...\c"
    reset_runtime
    if start_server "${case_name}" "${SERVER_BASE_ARGS[@]}" -n 10 -V -M; then
        run_client "${case_name}" "${CLIENT_BASE_ARGS[@]}" -n 10 -V -M
    else
        CLIENT_STDLOG="client_${case_name}.log"
        LAST_CLIENT_RC=1
    fi
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
    if check_client_rc "${case_name}" && check_server_rc "${case_name}" \
       && [ "${obj_cnt}" -ge 10 ] && [ "${stream_cnt}" -eq 1 ] && [ -z "${errlog}" ] && [ -z "${delta_bad}" ]; then
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
