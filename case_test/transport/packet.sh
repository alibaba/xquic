#!/bin/bash
#
# transport.packet endpoint case-test group.


ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "transport.packet"

case_transport_packet_illegal_packet()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1


clear_log
echo -e "illegal packet ...\c"
result=`${CLIENT_BIN} -s 1024000 -l d -t 1 -E -x 10|grep ">>>>>>>> pass" `
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "illegal_packet" "pass"
else
    case_print_result "illegal_packet" "fail"
    echo "$errlog"
fi

}

case_transport_packet_duplicate_packet()
{

clear_log
echo -e "duplicate packet ...\c"
result=`${CLIENT_BIN} -s 1024000 -l d -t 1 -E -x 9|grep ">>>>>>>> pass" `
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "duplicate_packet" "pass"
else
    case_print_result "duplicate_packet" "fail"
    echo "$errlog"
fi

}

case_transport_packet_packet_with_wrong_cid()
{

clear_log
echo -e "packet with wrong cid ...\c"
result=`${CLIENT_BIN} -s 1024000 -l d -t 1 -E -x 8|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "packet_with_wrong_cid" "pass"
else
    case_print_result "packet_with_wrong_cid" "fail"
    echo "$errlog"
fi

}

case_transport_packet_retry_packet_send()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l i -e -x 2 > /dev/null
sleep 1
rm -f test_session

clear_log
echo -e "retry packet send ...\c"
case_test_stop_server
rm -f xqc_token
case_test_start_server ${SERVER_BIN} -l d -e -x 601 > /dev/null
sleep 1
result=`${CLIENT_BIN} -s 1024 -l d -t 1 -E --conn_options CBBR|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
slog_res=`grep -a -E "<==.*xqc_conn_send_retry ok" slog`
clog_res=`grep -a -E "packet_parse_retry" clog`
#echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ] && [ -n "$slog_res" ] && [ -n "$clog_res" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "retry_packet_send" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "retry_packet_send" "fail"
    echo "$errlog"
    echo "$slog_res"
    echo "$clog_res"
fi



}

case_transport_packet_large_ack_range_with_30_percent_loss()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l e -e > /dev/null
sleep 1



packet_loss_pass=0
packet_loss_attempt=1
while [ $packet_loss_attempt -le 2 ]; do
    clear_log
    if [ $packet_loss_attempt -gt 1 ]; then
        echo -e "large_ack_range_with_30_percent_loss retry ${packet_loss_attempt} ...\c"
    fi
    ${CLIENT_BIN} -s 2048000 -l e -t 20 -E -d 300 > stdlog
    result=`grep ">>>>>>>> pass:1" stdlog`
    errlog=`grep_err_log`
    if [ -z "$errlog" ] && [ -n "$result" ]; then
        packet_loss_pass=1
        break
    fi
    if [ $packet_loss_attempt -ge 2 ] || ! case_test_should_retry_timeout_or_no_result stdlog "$errlog"; then
        break
    fi
    packet_loss_attempt=$((packet_loss_attempt + 1))
done
if [ $packet_loss_pass -eq 1 ]; then
    case_print_result "large_ack_range_with_30_percent_loss" "pass"
else
    case_print_result "large_ack_range_with_30_percent_loss" "fail"
    echo "$errlog"
fi
}

case_transport_packet_client_initial_dcid_corruption()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -x 9 > /dev/null
sleep 1




clear_log
case_test_stop_server
echo -e "client Initial dcid corruption ...\c"
sleep 1
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1
client_print_res=`${CLIENT_BIN} -s 1024000 -l d -t 1 -x 22 -E | grep ">>>>>>>> pass"`
errlog=`grep_err_log`
server_log_res=`grep -a "decrypt payload error" slog`
server_conn_cnt=`grep -a "xqc_conn_create" slog | grep -a -v "tra_parameters_set" | grep -a -v "mempool" | grep -a -v "connection_state_updated" | grep -a -v "path_assigned" | wc -l`
echo "$client_print_res"
if [ "$client_print_res" != "" ] && [ "$server_log_res" != "" ] && [ $server_conn_cnt -eq 2 ]; then
    case_print_result "client_initial_dcid_corruption" "pass"
else
    case_print_result "client_initial_dcid_corruption" "fail"
    echo "$errlog"
fi


}

case_transport_packet_client_initial_scid_corruption()
{


clear_log
case_test_stop_server
echo -e "client Initial scid corruption ...\c"
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1
client_print_res=`${CLIENT_BIN} -s 1024000 -l d -t 1 -x 23 -E | grep ">>>>>>>> pass:1"`
errlog=`grep_err_log`
server_iscid_res=`grep -a "iscid mismatch" slog`
echo "$client_print_res"
# After ISCID validation, server detects the corrupted SCID does not match
# the client's transport-parameter ISCID and closes the connection, so client
# fails the transfer (no pass:1) and server logs iscid mismatch.
if [ "$client_print_res" == "" ] && [ "$server_iscid_res" != "" ]; then
    case_print_result "client_initial_scid_corruption" "pass"
else
    case_print_result "client_initial_scid_corruption" "fail"
    echo "$errlog"
fi


}

case_transport_packet_server_initial_dcid_corruption()
{


clear_log
case_test_stop_server
echo -e "server Initial dcid corruption ...\c"
case_test_start_server ${SERVER_BIN} -l d -e -x 3 > /dev/null
sleep 1
client_print_res=`${CLIENT_BIN} -s 1024000 -l d -t 1 -E |grep ">>>>>>>> pass"`
client_log_res=`grep -a "fail to find connection" clog`
echo "$client_print_res"
if [ "$client_print_res" != "" ] && [ "$client_log_res" != "" ]; then
    case_print_result "server_initial_dcid_corruption" "pass"
else
    case_print_result "server_initial_dcid_corruption" "fail"
    echo "$errlog"
fi


}

case_transport_packet_server_initial_scid_corruption()
{


clear_log
case_test_stop_server
echo -e "server Initial scid corruption ...\c"
case_test_start_server ${SERVER_BIN} -l d -e -x 4 > /dev/null
sleep 1
client_print_res=`${CLIENT_BIN} -s 1024000 -l d -t 1 -E |grep ">>>>>>>> pass"`
client_log_res=`grep -a "decrypt data error" clog`
echo "$client_print_res"
if [ "$client_print_res" != "" ] && [ "$client_log_res" != "" ]; then
    case_print_result "server_initial_scid_corruption" "pass"
else
    case_print_result "server_initial_scid_corruption" "fail"
fi


}

case_transport_packet_server_odcid_hash()
{


clear_log
case_test_stop_server
echo -e "server odcid hash ...\c"
case_test_start_server ${SERVER_BIN} -l d -e -x 5 > /dev/null
sleep 1
result=`${CLIENT_BIN} -s 1024000 -l d -t 1 -E | grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "server_odcid_hash" "pass"
else
    case_print_result "server_odcid_hash" "fail"
    echo "$errlog"
fi

# ${SERVER_BIN} should be killed after this case, since some of the test case requires ${SERVER_BIN} without param `-E`
}

case_transport_packet_ack_timestamp_frame_case_1()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 1 --qlog_importance c > /dev/null
sleep 1

case_test_stop_server
clear_log
echo -e "ack_timestamp_frame: server enable, 0 < max_ts_per_ack < 64 and client enable, 0 < max_ts_per_ack < 64 ...\c"
case_test_start_server ${SERVER_BIN} -l d -e -x 450 > /dev/null
sleep 1
${CLIENT_BIN} -s 102400 -l d -t 1 -E -x 450 > stdlog
cli_res1=`grep -a "xqc_write_packet_receive_timestamps_into_buf|ts_info_len" clog | wc -l`
cli_res2=`grep -a "xqc_parse_timestamps_in_ack_ext|report_num:" clog | wc -l`

svr_res1=`grep -a "xqc_write_packet_receive_timestamps_into_buf|ts_info_len" slog | wc -l`
svr_res2=`grep -a "xqc_parse_timestamps_in_ack_ext|report_num:" slog | wc -l`

if [ "$cli_res1" -gt 0 ] && [ "$cli_res2" -gt 0 ] && [ "$svr_res1" -gt 0 ] && [ "$svr_res2" -gt 0 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "ack_timestamp_frame_case_1" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "ack_timestamp_frame_case_1" "fail"
fi


}

case_transport_packet_ack_timestamp_frame_case_2()
{


case_test_stop_server
clear_log
echo -e "ack_timestamp_frame: server enable, 0 < max_ts_per_ack < 64 and client disable, 0 < max_ts_per_ack < 64 ...\c"
case_test_start_server ${SERVER_BIN} -l d -e -x 450 > /dev/null
sleep 1
${CLIENT_BIN} -s 102400 -l d -t 1 -E -x 451 > stdlog
cli_res1=`grep -a "xqc_write_packet_receive_timestamps_into_buf|ts_info_len" clog | wc -l`
cli_res2=`grep -a "xqc_parse_timestamps_in_ack_ext|report_num:" clog | wc -l`

svr_res1=`grep -a "xqc_write_packet_receive_timestamps_into_buf|ts_info_len" slog | wc -l`
svr_res2=`grep -a "xqc_parse_timestamps_in_ack_ext|report_num:" slog | wc -l`

echo -e "$cli_res1 $cli_res2 $svr_res1 $svr_res2"

if [ "$cli_res1" -eq 0 ] && [ "$cli_res2" -eq 0 ] && [ "$svr_res1" -eq 0 ] && [ "$svr_res2" -eq 0 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "ack_timestamp_frame_case_2" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "ack_timestamp_frame_case_2" "fail"
fi


}

case_transport_packet_ack_timestamp_frame_case_3()
{


case_test_stop_server
clear_log
echo -e "ack_timestamp_frame: server enable, 0 < max_ts_per_ack < 64 and client enable, max_ts_per_ack >= 64 ...\c"
case_test_start_server ${SERVER_BIN} -l d -e -x 450 > /dev/null
sleep 1
${CLIENT_BIN} -s 102400 -l d -t 1 -E -x 452 > stdlog
cli_res1=`grep "conn errno" stdlog`

svr_res1=`grep -a "[error]" slog | grep -a "xqc_conn_tls_transport_params_cb" | wc -l`

if [ -n "$cli_res1" ] && [ -n "$svr_res1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "ack_timestamp_frame_case_3" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "ack_timestamp_frame_case_3" "fail"
fi


}

case_transport_packet_ack_timestamp_frame_case_4()
{


case_test_stop_server
clear_log
echo -e "ack_timestamp_frame: server enable, 0 < max_ts_per_ack < 64 and client enable, max_ts_per_ack = 0 ...\c"
case_test_start_server ${SERVER_BIN} -l d -e -x 450 > /dev/null
sleep 1
${CLIENT_BIN} -s 102400 -l d -t 1 -E -x 453 > stdlog
cli_res1=`grep -a "xqc_write_packet_receive_timestamps_into_buf|ts_info_len" clog | wc -l`
cli_res2=`grep -a "xqc_parse_timestamps_in_ack_ext|report_num:" clog | wc -l`

svr_res1=`grep -a "xqc_write_packet_receive_timestamps_into_buf|ts_info_len" slog | wc -l`
svr_res2=`grep -a "xqc_parse_timestamps_in_ack_ext|report_num:" slog | wc -l`

if [ "$cli_res1" -gt 0 ] && [ "$cli_res2" -eq 0 ] && [ "$svr_res1" -eq 0 ] && [ "$svr_res2" -gt 0 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "ack_timestamp_frame_case_4" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "ack_timestamp_frame_case_4" "fail"
fi


}

case_transport_packet_ack_timestamp_frame_case_5()
{


case_test_stop_server
clear_log
echo -e "ack_timestamp_frame: server disable, 0 < max_ts_per_ack < 64 and client enable, 0 < max_ts_per_ack < 64  ...\c"
case_test_start_server ${SERVER_BIN} -l d -e -x 451 > /dev/null
sleep 1
${CLIENT_BIN} -s 102400 -l d -t 1 -E -x 450 > stdlog
cli_res1=`grep -a "xqc_write_packet_receive_timestamps_into_buf|ts_info_len" clog | wc -l`
cli_res2=`grep -a "xqc_parse_timestamps_in_ack_ext|report_num:" clog | wc -l`

svr_res1=`grep -a "xqc_write_packet_receive_timestamps_into_buf|ts_info_len" slog | wc -l`
svr_res2=`grep -a "xqc_parse_timestamps_in_ack_ext|report_num:" slog | wc -l`

if [ "$cli_res1" -eq 0 ] && [ "$cli_res2" -eq 0 ] && [ "$svr_res1" -eq 0 ] && [ "$svr_res2" -eq 0 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "ack_timestamp_frame_case_5" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "ack_timestamp_frame_case_5" "fail"
fi


}

case_transport_packet_ack_timestamp_frame_case_6()
{


case_test_stop_server
clear_log
echo -e "ack_timestamp_frame: server enable, max_ts_per_ack > 64 and client enable, 0 < max_ts_per_ack < 64  ...\c"
case_test_start_server ${SERVER_BIN} -l d -e -x 452 > /dev/null
sleep 1
${CLIENT_BIN} -s 102400 -l d -t 1 -E -x 450 > stdlog
cli_res1=`grep -a "[error]" clog | grep -a "xqc_conn_tls_transport_params_cb" | wc -l`

svr_res1=`grep -a "[error]" slog | grep -a "xqc_process_conn_close_frame" | wc -l`


if [ "$cli_res1" -gt 0 ] && [ "$svr_res1" -gt 0 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "ack_timestamp_frame_case_6" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "ack_timestamp_frame_case_6" "fail"
fi

## ACK_ECN (0x03) frame parsing tests (issue #632)

}

case_transport_packet_ack_ecn_parse_both()
{

## ACK_ECN (0x03) frame parsing tests (issue #632)

case_test_stop_server
clear_log
echo -e "ack_ecn_parse: both endpoints send ACK_ECN, verify parsing on both sides ...\c"
case_test_start_server ${SERVER_BIN} -l d -e -x 454 > /dev/null
sleep 1
${CLIENT_BIN} -s 102400 -l d -t 1 -E -x 454 > stdlog
cli_res=`grep -a "ACK_ECN frame ECN counts consumed" clog | wc -l`
svr_res=`grep -a "ACK_ECN frame ECN counts consumed" slog | wc -l`
errlog=`grep_err_log`

if [ -z "$errlog" ] && [ "$cli_res" -gt 0 ] && [ "$svr_res" -gt 0 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "ack_ecn_parse_both" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "ack_ecn_parse_both" "fail"
fi

}

case_transport_packet_ack_ecn_parse_server_only()
{

case_test_stop_server
clear_log
echo -e "ack_ecn_parse: only server sends ACK_ECN, verify client parsing ...\c"
case_test_start_server ${SERVER_BIN} -l d -e -x 455 > /dev/null
sleep 1
${CLIENT_BIN} -s 102400 -l d -t 1 -E -x 455 > stdlog
cli_res=`grep -a "ACK_ECN frame ECN counts consumed" clog | wc -l`
svr_res=`grep -a "ACK_ECN frame ECN counts consumed" slog | wc -l`
errlog=`grep_err_log`

if [ -z "$errlog" ] && [ "$cli_res" -gt 0 ] && [ "$svr_res" -eq 0 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "ack_ecn_parse_server_only" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "ack_ecn_parse_server_only" "fail"
fi

}

# Print the frames of the first Initial packet a log says its endpoint sent.
case_transport_packet_first_initial_frames()
{
grep -a -m 1 "xqc_send_packet_with_pn|<==|.*|pkt_type:INIT|" "$1" \
    | grep -a -o "frame:[A-Z_ ]*"
}

case_transport_packet_server_hello_carries_ack()
{
# RFC 9000 Section 13.2.1: the server's first Initial, which carries the
# ServerHello, also acknowledges the client's Initial.
case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
echo -e "server hello carries ack ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
frames=`case_transport_packet_first_initial_frames slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ] \
    && [[ "$frames" == *ACK* ]] && [[ "$frames" == *CRYPTO* ]]; then
    echo ">>>>>>>> pass:1"
    case_print_result "server_hello_carries_ack" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "server_hello_carries_ack" "fail"
    echo "$result"
    echo "$frames"
    echo "$errlog"
fi
case_test_stop_server
rm -f test_session xqc_token tp_localhost
}

case_transport_packet_server_hello_ack_under_amplification_limit()
{
# With a certificate larger than three times the client's first Initial,
# the anti-amplification limit holds back most of the server's flight. The
# ACK of the client's Initial still goes out with the ServerHello, so the
# client gets it before it sends any Handshake packet.
local work_dir=`pwd`
local dir="${work_dir}/server_hello_ack_large_cert"
local san="DNS:test.xquic.com"
local i

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
rm -rf "$dir"
mkdir -p "$dir"
for i in $(seq 1 60); do
    san="${san},DNS:$(printf 'a%0249d' "$i")"
done
echo -e "server hello ack under amplification limit ...\c"
if ! openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -nodes -keyout "$dir/server.key" -out "$dir/server.crt" -days 1 \
    -subj "/CN=test.xquic.com" -addext "subjectAltName=${san}" \
    > /dev/null 2>&1
then
    echo ">>>>>>>> pass:0"
    case_print_result "server_hello_ack_under_amplification_limit" "fail"
    echo "large certificate generation failed"
    rm -rf "$dir"
    return
fi

cd "$dir" && case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
cd "$work_dir"
${CLIENT_BIN} -s 1024 -l d -t 3 -E > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
aal=`grep -a "blocked by anti amplification limit" "$dir/slog"`
frames=`case_transport_packet_first_initial_frames "$dir/slog"`
acked=`grep -a -n -m 1 "xqc_send_ctl_on_ack_received|.*|pkt_type:INIT|" clog \
    | cut -d: -f1`
first_hsk=`grep -a -n -m 1 "xqc_send_packet_with_pn|<==|.*|pkt_type:HSK|" clog \
    | cut -d: -f1`
errlog=`grep -a "\[error\]" clog "$dir/slog"`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ] && [ -n "$aal" ] \
    && [[ "$frames" == *ACK* ]] && [ -n "$acked" ] && [ -n "$first_hsk" ] \
    && [ "$acked" -lt "$first_hsk" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "server_hello_ack_under_amplification_limit" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "server_hello_ack_under_amplification_limit" "fail"
    echo "$result"
    echo "aal:${aal:0:200}"
    echo "$frames"
    echo "clog lines: Initial acked ${acked}, first Handshake ${first_hsk}"
    echo "$errlog"
fi
case_test_stop_server
rm -rf "$dir"
rm -f test_session xqc_token tp_localhost
}

case_test_case "illegal_packet" --id native --mode self-reporting --run case_transport_packet_illegal_packet
case_test_case "duplicate_packet" --id native --mode self-reporting --run case_transport_packet_duplicate_packet
case_test_case "packet_with_wrong_cid" --id native --mode self-reporting --run case_transport_packet_packet_with_wrong_cid
case_test_case "retry_packet_send" --id native --mode self-reporting --run case_transport_packet_retry_packet_send
case_test_case "large_ack_range_with_30_percent_loss" --id native --mode self-reporting --run case_transport_packet_large_ack_range_with_30_percent_loss --timeout 120
case_test_case "client_initial_dcid_corruption" --id native --mode self-reporting --run case_transport_packet_client_initial_dcid_corruption
case_test_case "client_initial_scid_corruption" --id native --mode self-reporting --run case_transport_packet_client_initial_scid_corruption
case_test_case "server_initial_dcid_corruption" --id native --mode self-reporting --run case_transport_packet_server_initial_dcid_corruption
case_test_case "server_initial_scid_corruption" --id native --mode self-reporting --run case_transport_packet_server_initial_scid_corruption
case_test_case "server_odcid_hash" --id native --mode self-reporting --run case_transport_packet_server_odcid_hash
case_test_case "ack_timestamp_frame_case_1" --id native --mode self-reporting --run case_transport_packet_ack_timestamp_frame_case_1
case_test_case "ack_timestamp_frame_case_2" --id native --mode self-reporting --run case_transport_packet_ack_timestamp_frame_case_2
case_test_case "ack_timestamp_frame_case_3" --id native --mode self-reporting --run case_transport_packet_ack_timestamp_frame_case_3
case_test_case "ack_timestamp_frame_case_4" --id native --mode self-reporting --run case_transport_packet_ack_timestamp_frame_case_4
case_test_case "ack_timestamp_frame_case_5" --id native --mode self-reporting --run case_transport_packet_ack_timestamp_frame_case_5
case_test_case "ack_timestamp_frame_case_6" --id native --mode self-reporting --run case_transport_packet_ack_timestamp_frame_case_6
case_test_case "ack_ecn_parse_both" --id native --mode self-reporting --run case_transport_packet_ack_ecn_parse_both
case_test_case "ack_ecn_parse_server_only" --id native --mode self-reporting --run case_transport_packet_ack_ecn_parse_server_only
case_test_case "server_hello_carries_ack" --id native \
    --mode self-reporting \
    --run case_transport_packet_server_hello_carries_ack
case_test_case "server_hello_ack_under_amplification_limit" --id native \
    --mode self-reporting \
    --run case_transport_packet_server_hello_ack_under_amplification_limit

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
trap 'case_test_stop_server; case_test_cleanup_udp_port' EXIT

case_test_run
