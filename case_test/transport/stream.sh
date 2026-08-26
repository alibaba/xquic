#!/bin/bash
#
# transport.stream endpoint case-test group.


ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "transport.stream"

case_transport_stream_server_inited_stream()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1



rm -f test_session tp_localhost xqc_token

case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 17 > /dev/null

clear_log
echo -e "server-inited stream ...\c"
${CLIENT_BIN} -l d -E -t 3 >> stdlog
client_refuse=`grep "ignore server initiated bidi-streams at client" clog`
client_discard=`grep "data discarded" clog`
client_check=`grep "xqc_h3_stream_close_notify" clog | grep "|stream_id:1|"`
client_std_res=`grep ">>>>>>>> pass" stdlog`
clog_res=`grep "xqc_destroy_stream" clog | grep "close_msg:finished" | grep "stream_id:1"`
if [ -n "$client_refuse" ] && [ -n "$client_discard" ] && [ -n "$client_std_res" ] && [ -n "$clog_res" ] && [ -z "$client_check" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "server_inited_stream" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "server_inited_stream" "fail"
fi



}

case_transport_stream_stream_send_pure_fin()
{



case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 99 > /dev/null
sleep 1

rm -f test_session tp_localhost xqc_token

clear_log
echo -e "stream send pure fin ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 99 -T 1 >> clog
errlog=`grep_err_log`
clog_res=`cat clog | grep "|send_state:3|recv_state:3|stream_id:0|stream_type:0|send_bytes:0|read_bytes:0|recv_bytes:0|stream_len:0|"`
slog_res=`cat slog | grep "|send_state:3|recv_state:3|stream_id:0|stream_type:0|send_bytes:0|read_bytes:0|recv_bytes:0|stream_len:0|"`
if [ -z "$errlog" ] && [ -n "$clog_res" ] && [ -n "$slog_res" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "stream_send_pure_fin" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "stream_send_pure_fin" "fail"
fi

rm -f test_session

}

case_transport_stream_stream_read_notify_fail()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 99 > /dev/null
sleep 1

rm -f test_session tp_localhost xqc_token


rm -rf test_session

case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1

clear_log
echo -e "stream read notify fail ...\c"
${CLIENT_BIN} -s 1024000 -l d -t 1 -E -x 12 >> clog
result=`grep_err_log|grep -v xqc_h3_request_on_recv|grep -v xqc_h3_stream_process_in|grep -v xqc_h3_stream_read_notify|grep -v xqc_process_read_streams|grep -v xqc_process_conn_close_frame|grep -v xqc_h3_stream_process_request`
if [ -z "$result" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "stream_read_notify_fail" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "stream_read_notify_fail" "fail"
fi


}

case_transport_stream_create_stream_fail()
{


clear_log
echo -e "create stream fail ...\c"
${CLIENT_BIN} -s 1024000 -l d -t 1 -E -x 11 >> clog
result=`grep_err_log|grep -v xqc_stream_create`
if [ -z "$result" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "create_stream_fail" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "create_stream_fail" "fail"
fi

}

case_transport_stream_fin_only()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1

grep_err_log

clear_log
echo -e "fin only ...\c"
result=`${CLIENT_BIN} -s 5120 -l d -t 1 -E -x 4 |grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "fin_only" "pass"
else
    case_print_result "fin_only" "fail"
    echo "$errlog"
fi

}

case_transport_stream_send_data_after_fin()
{

clear_log
echo -e "send data after fin ...\c"
result=`${CLIENT_BIN} -s 5120 -l d -t 1 -E -x 50 |grep ">>>>>>>> pass"`
errlog=`grep_err_log | grep -v "send data after fin sent"`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "send_data_after_fin" "pass"
else
    case_print_result "send_data_after_fin" "fail"
    echo "$errlog"
fi

}

case_transport_stream_send_header_after_fin()
{

clear_log
echo -e "send header after fin ...\c"
result=`${CLIENT_BIN} -s 5120 -l d -t 1 -E -x 51 |grep ">>>>>>>> pass"`
errlog=`grep_err_log | grep -v "send data after fin sent"`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "send_header_after_fin" "pass"
else
    case_print_result "send_header_after_fin" "fail"
    echo "$errlog"
fi

}

case_transport_stream_send_fin_after_fin()
{

clear_log
echo -e "send fin after fin ...\c"
result=`${CLIENT_BIN} -s 5120 -l d -t 1 -E -x 52 |grep ">>>>>>>> pass"`
errlog=`grep_err_log | grep -v "send data after fin sent"`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "send_fin_after_fin" "pass"
else
    case_print_result "send_fin_after_fin" "fail"
    echo "$errlog"
fi


}

case_transport_stream_reset_stream()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1

grep_err_log|grep -v xqc_process_write_streams|grep -v xqc_h3_stream_write_notify|grep -v xqc_process_conn_close_frame



clear_log
echo -e "Reset stream when sending...\c"
${CLIENT_BIN} -s 1024000 -l d -t 1 -E -x 1 >> clog
if grep "send_state:5|recv_state:5" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
    case_print_result "reset_stream" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "reset_stream" "fail"
fi
}

case_transport_stream_reset_stream_when_receiving()
{
grep_err_log|grep -v stream


clear_log
echo -e "Reset stream when receiving...\c"
${CLIENT_BIN} -s 1024000 -l d -t 1 -E -x 21 > stdlog
result=`grep "xqc_send_queue_drop_stream_frame_packets" slog`
flag=`grep "send_state:5|recv_state:5" clog`
errlog=`grep_err_log|grep -v stream`
if [ -n "$flag" ] && [ -z "$errlog" ] && [ -n "$result" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "reset_stream_when_receiving" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "reset_stream_when_receiving" "fail"
    echo "$flag"
    echo "$errlog"
fi

}

case_transport_stream_send_header_after_reset_stream()
{

clear_log
echo -e "Send header after reset stream...\c"
${CLIENT_BIN} -s 1024000 -l d -t 1 -E -x 28 > stdlog
result=`grep "xqc_conn_destroy.*err:0x0" clog`
flag=`grep "send_state:5|recv_state:5" clog`
errlog=`grep_err_log|grep -v stream`
if [ -n "$flag" ] && [ -z "$errlog" ] && [ -n "$result" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_header_after_reset_stream" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_header_after_reset_stream" "fail"
    echo "$flag"
    echo "$errlog"
fi


}

case_transport_stream_NULL_stream_callback()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l i -e > /dev/null
sleep 1

grep_err_log


clear_log
rm -f test_session
echo -e "NULL stream callback ...\c"
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l i -e -x 2 > /dev/null
sleep 1
${CLIENT_BIN} -l d -T 1 -E >> clog
if grep "stream_read_notify is NULL" slog >/dev/null; then
    echo ">>>>>>>> pass:1"
    case_print_result "NULL_stream_callback" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "NULL_stream_callback" "fail"
fi
rm -f test_session

}

case_transport_stream_send_1K_data()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1


clear_log
echo -e "send 1K data ...\c"
result=`${CLIENT_BIN} -s 1024 -l d -t 1 -E --conn_options CBBR|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "send_1K_data" "pass"
else
    case_print_result "send_1K_data" "fail"
    echo "$errlog"
fi

}

case_transport_stream_send_1M_data()
{

clear_log
echo -e "send 1M data ...\c"
result=`${CLIENT_BIN} -s 1024000 -l d -t 1 -E|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "send_1M_data" "pass"
else
    case_print_result "send_1M_data" "fail"
    echo "$errlog"
fi

}

case_transport_stream_send_10M_data()
{

clear_log
echo -e "send 10M data ...\c"
result=`${CLIENT_BIN} -s 10240000 -l e -E|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "send_10M_data" "pass"
else
    case_print_result "send_10M_data" "fail"
    echo "$errlog"
fi

}

case_transport_stream_send_10M_data_mempool_protected()
{

clear_log
echo -e "send 10M data (mempool protected) ...\c"
result=`${CLIENT_BIN}  -s 10240000 -l e -E -x 600 |grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "send_10M_data_mempool_protected" "pass"
else
    case_print_result "send_10M_data_mempool_protected" "fail"
    echo "$errlog"
fi

}

case_transport_stream_send_4K_every_time()
{

clear_log
echo -e "send 4K every time ...\c"
result=`${CLIENT_BIN} -s 10240000 -l e -E -x 49|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "send_4K_every_time" "pass"
else
    case_print_result "send_4K_every_time" "fail"
    echo "$errlog"
fi

}

case_transport_stream_stream_level_flow_control()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1

echo -e "spurious loss detect on ...\c"
echo "$result"


clear_log
echo -e "stream level flow control ...\c"
result=`${CLIENT_BIN} -s 10240000 -l e -E|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "stream_level_flow_control" "pass"
else
    case_print_result "stream_level_flow_control" "fail"
    echo "$errlog"
fi

}

case_transport_stream_connection_level_flow_control()
{

clear_log
echo -e "connection level flow control ...\c"
${CLIENT_BIN} -s 512000 -l e -E -n 10 > stdlog
sleep 1
if [[ `grep ">>>>>>>> pass:1" stdlog|wc -l` -eq 10 ]]; then
    echo ">>>>>>>> pass:1"
    case_print_result "connection_level_flow_control" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "connection_level_flow_control" "fail"
fi
}

case_transport_stream_stream_concurrency_flow_control()
{
grep_err_log

clear_log
echo -e "stream concurrency flow control ...\c"
${CLIENT_BIN} -s 1 -l e -t 1 -E -P 1025 -G > ccfc.log
if [[ `grep ">>>>>>>> pass:1" ccfc.log|wc -l` -eq 1024 ]]; then
    echo ">>>>>>>> pass:1"
    case_print_result "stream_concurrency_flow_control" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "stream_concurrency_flow_control" "fail"
fi
}

case_transport_stream_send_queue_full()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 2 > /dev/null
sleep 1
rm -f test_session tp_localhost xqc_token

case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null
sleep 1
clear_log
echo -e "send_queue_full...\c"
${CLIENT_BIN} -l d -T 1 -s 40000000 -U 1 -Q 65535 -1 > stdlog
cli_res1=`grep "\[dgram\]|retry_datagram_send_later|" stdlog`
cli_res2=`grep "|too many packets used|ctl_packets_used:" clog`
cli_res3=`grep "\[dgram\]|dgram_write|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_queue_full" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_queue_full" "fail"
fi

}

case_transport_stream_send_queue_full_batch()
{

clear_log
echo -e "send_queue_full_batch...\c"
${CLIENT_BIN} -l d -T 1 -s 40000000 -U 2 -Q 65535 -1 > stdlog
cli_res1=`grep "\[dgram\]|retry_datagram_send_multiple_later|" stdlog`
cli_res2=`grep "|too many packets used|ctl_packets_used:" clog`
cli_res3=`grep "\[dgram\]|dgram_write|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_queue_full_batch" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_queue_full_batch" "fail"
fi

}

case_transport_stream_conn_rate_throttling()
{
case_test_stop_server
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -e -M > /dev/null
sleep 1

rm -rf tp_localhost test_session xqc_token


case_test_sudo rm -rf tp_localhost test_session xqc_token clog stdlog ckeys.log
clear_log
echo -e "conn_rate_throttling ...\c"
result=`${CLIENT_BIN} -s 1024000 -l d -E --rate_limit 1000000 |grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "conn_rate_throttling" "pass"
else
    case_print_result "conn_rate_throttling" "fail"
    echo "$errlog"
fi

}

case_transport_stream_stream_rate_throttling()
{

clear_log
echo -e "stream_rate_throttling ...\c"
result=`${CLIENT_BIN} -s 1024000 -l d -E -x 109 |grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "stream_rate_throttling" "pass"
else
    case_print_result "stream_rate_throttling" "fail"
    echo "$errlog"
fi


}

case_transport_stream_reset_stream_on_send_only_stream()
{
case_test_start_server ${SERVER_BIN} -l d -e -x 1014 > /dev/null
sleep 1

case_test_stop_server


# issues #565 / #566 / #567: a frame naming a stream the peer does not own must
# close the connection with STREAM_STATE_ERROR (0x5) per RFC 9000 section 19.4,
# section 19.5 and section 19.8. Each case asserts both the server side reason
# and the error code the client actually observes in CONNECTION_CLOSE, so a
# generic failure or an unrelated close cannot satisfy it.

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1
echo -e "reset_stream_on_send_only_stream ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 705 >> clog
sleep 1
server_rejected=`grep "RESET_STREAM on send-only stream|stream_id:3|" slog`
client_close_code=`grep "xqc_parse_conn_close_frame|type:18|err_code:5|" clog`
if [ -n "$server_rejected" ] && [ -n "$client_close_code" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "reset_stream_on_send_only_stream" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "reset_stream_on_send_only_stream" "fail"
fi

}

case_transport_stream_reset_stream_on_recv_only_stream()
{

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e -x 717 > svr_stdlog
sleep 1
echo -e "reset_stream_on_recv_only_stream ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 717 > stdlog
sleep 1
result=`grep ">>>>>>>> pass:1" stdlog`
server_reset=`grep "\[recv-only-reset-test\]|stream_id:.*|ret:0|" svr_stdlog`
server_rejected=`grep "RESET_STREAM on send-only stream" slog`
client_close_code=`grep "xqc_parse_conn_close_frame|type:18|err_code:5|" clog`
if [ -n "$result" ] && [ -n "$server_reset" ] \
    && [ -z "$server_rejected" ] && [ -z "$client_close_code" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "reset_stream_on_recv_only_stream" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "reset_stream_on_recv_only_stream" "fail"
fi

}

case_transport_stream_stop_sending_on_recv_only_stream()
{

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1
echo -e "stop_sending_on_recv_only_stream ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 706 >> clog
sleep 1
server_rejected=`grep "STOP_SENDING on recv-only stream|stream_id:2|" slog`
client_close_code=`grep "xqc_parse_conn_close_frame|type:18|err_code:5|" clog`
if [ -n "$server_rejected" ] && [ -n "$client_close_code" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "stop_sending_on_recv_only_stream" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "stop_sending_on_recv_only_stream" "fail"
fi

}

case_transport_stream_stream_frame_on_send_only_stream()
{

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1
echo -e "stream_frame_on_send_only_stream ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 707 >> clog
sleep 1
server_rejected=`grep "STREAM frame on send-only stream|stream_id:3|" slog`
client_close_code=`grep "xqc_parse_conn_close_frame|type:18|err_code:5|" clog`
if [ -n "$server_rejected" ] && [ -n "$client_close_code" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "stream_frame_on_send_only_stream" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "stream_frame_on_send_only_stream" "fail"
fi

}

case_transport_stream_stream_frame_on_local_uncreated_stream()
{

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1
echo -e "stream_frame_on_local_uncreated_stream ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 708 >> clog
sleep 1
server_rejected=`grep "STREAM frame on locally initiated uncreated stream|stream_id:1|" slog`
client_close_code=`grep "xqc_parse_conn_close_frame|type:18|err_code:5|" clog`
if [ -n "$server_rejected" ] && [ -n "$client_close_code" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "stream_frame_on_local_uncreated_stream" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "stream_frame_on_local_uncreated_stream" "fail"
fi

}

case_transport_stream_max_stream_data_on_send_only_stream()
{

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1
echo -e "max_stream_data_on_send_only_stream ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 718 > stdlog
sleep 1
result=`grep ">>>>>>>> pass:1" stdlog`
server_received=`grep \
    "xqc_parse_max_stream_data_frame|type:9|"\
"stream_id:3|max_stream_data:4611686018427387903|" \
    slog`
server_applied=`grep \
    "xqc_process_max_stream_data_frame|"\
"max_stream_data=4611686018427387903|"\
"max_stream_data_old=16777216|" \
    slog`
client_close_code=`grep "xqc_parse_conn_close_frame|type:18|err_code:5|" clog`
if [ -n "$result" ] && [ -n "$server_received" ] \
    && [ -n "$server_applied" ] \
    && [ -z "$client_close_code" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "max_stream_data_on_send_only_stream" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "max_stream_data_on_send_only_stream" "fail"
fi

}

case_transport_stream_max_stream_data_on_recv_only_stream()
{

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1
echo -e "max_stream_data_on_recv_only_stream ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 719 >> clog
sleep 1
server_rejected=`grep "MAX_STREAM_DATA on recv-only stream|stream_id:2|" slog`
client_close_code=`grep "xqc_parse_conn_close_frame|type:18|err_code:5|" clog`
if [ -n "$server_rejected" ] && [ -n "$client_close_code" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "max_stream_data_on_recv_only_stream" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "max_stream_data_on_recv_only_stream" "fail"
fi

}

case_test_case "server_inited_stream" --id native --mode self-reporting --run case_transport_stream_server_inited_stream
case_test_case "stream_send_pure_fin" --id native --mode self-reporting --run case_transport_stream_stream_send_pure_fin
case_test_case "stream_read_notify_fail" --id native --mode self-reporting --run case_transport_stream_stream_read_notify_fail
case_test_case "create_stream_fail" --id native --mode self-reporting --run case_transport_stream_create_stream_fail
case_test_case "fin_only" --id native --mode self-reporting --run case_transport_stream_fin_only
case_test_case "send_data_after_fin" --id native --mode self-reporting --run case_transport_stream_send_data_after_fin
case_test_case "send_header_after_fin" --id native --mode self-reporting --run case_transport_stream_send_header_after_fin
case_test_case "send_fin_after_fin" --id native --mode self-reporting --run case_transport_stream_send_fin_after_fin
case_test_case "reset_stream" --id native --mode self-reporting --run case_transport_stream_reset_stream
case_test_case "reset_stream_when_receiving" --id native --mode self-reporting --run case_transport_stream_reset_stream_when_receiving
case_test_case "send_header_after_reset_stream" --id native --mode self-reporting --run case_transport_stream_send_header_after_reset_stream
case_test_case "NULL_stream_callback" --id native --mode self-reporting --run case_transport_stream_NULL_stream_callback
case_test_case "send_1K_data" --id native --mode self-reporting --run case_transport_stream_send_1K_data
case_test_case "send_1M_data" --id native --mode self-reporting --run case_transport_stream_send_1M_data
case_test_case "send_10M_data" --id native --mode self-reporting --run case_transport_stream_send_10M_data
case_test_case "send_10M_data_mempool_protected" --id native --mode self-reporting --run case_transport_stream_send_10M_data_mempool_protected
case_test_case "send_4K_every_time" --id native --mode self-reporting --run case_transport_stream_send_4K_every_time
case_test_case "stream_level_flow_control" --id native --mode self-reporting --run case_transport_stream_stream_level_flow_control
case_test_case "connection_level_flow_control" --id native --mode self-reporting --run case_transport_stream_connection_level_flow_control
case_test_case "stream_concurrency_flow_control" --id native --mode self-reporting --run case_transport_stream_stream_concurrency_flow_control
case_test_case "send_queue_full" --id native --mode self-reporting --run case_transport_stream_send_queue_full
case_test_case "send_queue_full_batch" --id native --mode self-reporting --run case_transport_stream_send_queue_full_batch
case_test_case "conn_rate_throttling" --id native --mode self-reporting --run case_transport_stream_conn_rate_throttling
case_test_case "stream_rate_throttling" --id native --mode self-reporting --run case_transport_stream_stream_rate_throttling
case_test_case "reset_stream_on_send_only_stream" --id native --mode self-reporting --run case_transport_stream_reset_stream_on_send_only_stream
case_test_case "reset_stream_on_recv_only_stream" --id native --mode self-reporting --run case_transport_stream_reset_stream_on_recv_only_stream
case_test_case "stop_sending_on_recv_only_stream" --id native --mode self-reporting --run case_transport_stream_stop_sending_on_recv_only_stream
case_test_case "stream_frame_on_send_only_stream" --id native --mode self-reporting --run case_transport_stream_stream_frame_on_send_only_stream
case_test_case "stream_frame_on_local_uncreated_stream" --id native --mode self-reporting --run case_transport_stream_stream_frame_on_local_uncreated_stream
case_test_case "max_stream_data_on_send_only_stream" --id native \
    --mode self-reporting \
    --run case_transport_stream_max_stream_data_on_send_only_stream
case_test_case "max_stream_data_on_recv_only_stream" --id native \
    --mode self-reporting \
    --run case_transport_stream_max_stream_data_on_recv_only_stream

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
trap 'case_test_stop_server; case_test_cleanup_udp_port' EXIT
case_test_require_sudo

case_test_run
