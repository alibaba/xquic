# Copyright (c) 2022, Alibaba Group Holding Limited

#!/bin/bash

#macOS
#export EVENT_NOKQUEUE=1

LOCAL_TEST=0
#LOCAL_TEST=1

cd ../build

CLIENT_BIN="tests/test_client"
SERVER_BIN="tests/test_server"


clear_log() {
    >clog
    >slog
}

grep_err_log() {
    grep "\[error\]" clog
    grep "\[error\]" slog
    #grep "retrans rate:" clog|grep -v "retrans rate:0.0000"
    #grep "retrans rate:" slog|grep -v "retrans rate:0.0000"
}

# params: case_name, result
case_print_result() {
    echo "[ RUN      ] xquic_case_test.$1"
    if [ "$2" = "pass" ];then
        echo "[       OK ] xquic_case_test.$1 (1 ms)"
    else
        echo "[     FAIL ] xquic_case_test.$1 (1 ms)"
    fi
}


# start test_server
rm -rf tp_localhost test_session xqc_token
killall test_server 2> /dev/null
${SERVER_BIN} -l d -e > /dev/null &
sleep 1

clear_log
echo -e "log switch off ...\c"
${CLIENT_BIN} -s 1024000 -l d -t 1 -E -x 44 >> stdlog
log_size=`wc -l clog | awk -F ' ' '{print $1}'`
if [ $log_size -eq 0 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "log_switch_off" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "log_switch_off" "fail"
fi


echo -e "server refuse ...\c"
${CLIENT_BIN} -x 46 -t 1 >> stdlog
sleep 10
result=`grep "conn close notified by refuse" slog`
if [ -n "$result" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "server_refuse" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "server_refuse" "fail"
fi


rm -f test_session tp_localhost xqc_token

killall test_server 2> /dev/null
${SERVER_BIN} -l d -e -x 17 > /dev/null &

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



killall test_server 2> /dev/null
${SERVER_BIN} -l d -e -x 99 > /dev/null &
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

clear_log
echo -e "h3 stream send pure fin ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 99 >> clog
errlog=`grep_err_log | grep -v "send data after fin sent"`
clog_res=`cat clog | grep "|send_state:3|recv_state:3|stream_id:0|stream_type:0|send_bytes:0|read_bytes:0|recv_bytes:0|stream_len:0|"`
slog_res=`cat slog | grep "|send_state:3|recv_state:3|stream_id:0|stream_type:0|send_bytes:0|read_bytes:0|recv_bytes:0|stream_len:0|"`
if [ -z "$errlog" ] && [ -n "$clog_res" ] && [ -n "$slog_res" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_stream_send_pure_fin" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_stream_send_pure_fin" "fail"
fi

rm -f test_session

clear_log
echo -e "h3_ext_bytestream send pure fin ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 310 -T 2 >> clog
errlog=`grep_err_log`
clog_res=`cat clog | grep "|send_state:3|recv_state:3|stream_id:0|stream_type:0|send_bytes:5|read_bytes:2|recv_bytes:2|stream_len:2|"`
slog_res=`cat slog | grep "|send_state:3|recv_state:3|stream_id:0|stream_type:0|send_bytes:2|read_bytes:5|recv_bytes:5|stream_len:5|"`
if [ -z "$errlog" ] && [ -n "$clog_res" ] && [ -n "$slog_res" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_bytestream_send_pure_fin" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_bytestream_send_pure_fin" "fail"
fi

rm -rf test_session

killall test_server 2> /dev/null
${SERVER_BIN} -l d -e > /dev/null &
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

clear_log
echo -e "create connection fail ...\c"
${CLIENT_BIN} -s 1024000 -l d -t 1 -E -x 7 >> clog
result=`grep_err_log|grep -v xqc_client_connect`
if [ -z "$result" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "create_connection_fail" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "create_connection_fail" "fail"
fi

clear_log
echo -e "socket recv fail ...\c"
result=`${CLIENT_BIN} -s 1024000 -l d -t 1 -E -x 6|grep ">>>>>>>> pass" `
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "socket_recv_fail" "pass"
else
    case_print_result "socket_recv_fail" "fail"
    echo "$errlog"
fi

clear_log
echo -e "socket send fail ...\c"
result=`${CLIENT_BIN} -s 1024000 -l d -t 1 -E -x 5|grep ">>>>>>>> pass" `
errlog=`grep_err_log|grep -v "write_socket error"`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "socket_send_fail" "pass"
else
    case_print_result "socket_send_fail" "fail"
    echo "$errlog"
fi

clear_log
echo -e "verify Token fail ...\c"
rm -f xqc_token
result=`${CLIENT_BIN} -s 1024000 -l d -t 1 -E|grep ">>>>>>>> pass"`
errlog=`grep_err_log|grep -v xqc_conn_check_token`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "verify_token_fail" "pass"
else
    case_print_result "verify_token_fail" "fail"
    echo "$errlog"
fi

clear_log
echo -e "verify Token success ...\c"
result=`${CLIENT_BIN} -s 1024000 -l d -t 1 -E|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "verify_token_success" "pass"
else
    case_print_result "verify_token_success" "fail"
    echo "$errlog"
fi

clear_log
echo -e "test application delay ...\c"
rm -f xqc_token
${CLIENT_BIN} -s 5120 -l d -t 1 -E -x 16 >> clog
if test "$(grep -e "|====>|.*NEW_TOKEN" clog |wc -l)" -gt 1 >/dev/null && grep ">>>>>>>> pass:1" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
    case_print_result "test_application_delay" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "test_application_delay" "fail"
fi
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


clear_log
echo -e "header header data ...\c"
${CLIENT_BIN} -s 5120 -l d -t 1 -E -x 30 >> clog
header_res=`grep "recv header" slog`
trailer_res=`grep "recv tailer header" slog`
if [ -n "$header_res" ] && [ -n "$trailer_res" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "header_header_data" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "header_header_data" "fail"
fi
grep_err_log

clear_log
echo -e "header data header ...\c"
${CLIENT_BIN} -s 5120 -l d -t 1 -E -x 31 >> clog
header_res=`grep "recv header" slog`
trailer_res=`grep "recv tailer header" slog`
if [ -n "$header_res" ] && [ -n "$trailer_res" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "header_data_header" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "header_data_header" "fail"
fi
grep_err_log


clear_log
echo -e "header data fin ...\c"
${CLIENT_BIN}  -l d -t 2 -s 100 -E -x 35 >> clog
result=`grep ">>>>>>>> pass" clog`
sres=`grep "|recv_fin|" slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$sres" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "header_data_fin" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "header_data_fin" "fail"
fi
grep_err_log


clear_log
echo -e "header data immediate fin ...\c"
${CLIENT_BIN}  -l d -t 2 -s 100 -E -x 36 >> clog
result=`grep ">>>>>>>> pass" clog`
sres=`grep "h3 fin only received" slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -z "$sres" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "header_data_immediate_fin" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "header_data_immediate_fin" "fail"
fi
grep_err_log


clear_log
echo -e "header fin ...\c"
${CLIENT_BIN}  -l d -t 2 -x 37 >> clog
sres=`grep "|recv_fin|" slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$sres" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "header_fin" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "header_fin" "fail"
fi
grep_err_log


clear_log
echo -e "header immediate fin ...\c"
${CLIENT_BIN}  -l d -t 2 -x 38 >> clog
sres=`grep "h3 fin only received" slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -z "$sres" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "header_data_immediate_fin" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "header_data_immediate_fin" "fail"
fi
grep_err_log



clear_log
echo -e "uppercase header ...\c"
${CLIENT_BIN} -s 5120 -l d -t 1 -E -x 34 >> clog
result=`grep ">>>>>>>> pass" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "uppercase_header" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "uppercase_header" "fail"
fi


clear_log
echo -e "user close connection ...\c"
${CLIENT_BIN} -s 1024000 -l d -t 1 -E -x 2 >> clog
if grep "<==.*CONNECTION_CLOSE" clog >/dev/null && grep "==>.*CONNECTION_CLOSE" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
    case_print_result "user_close_connection" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "user_close_connection" "fail"
fi
grep_err_log



clear_log
echo -e "close connection with error ...\c"
${CLIENT_BIN} -s 1024000 -l d -t 1 -E -x 3 >> stdlog
if grep "<==.*CONNECTION_CLOSE" clog >/dev/null && grep "==>.*CONNECTION_CLOSE" clog >/dev/null && grep "conn closing: 1" stdlog >/dev/null; then
    echo ">>>>>>>> pass:1"
    case_print_result "close_connection_with_error" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "close_connection_with_error" "fail"
fi
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


clear_log
${CLIENT_BIN} -s 1024000 -l e -t 1 -E -1 -V 1 > stdlog
echo -e "Cert verify ...\c"
result=`grep ">>>>>>>> pass:" stdlog`
echo "$result"
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "cert_verify" "pass"
else
    case_print_result "cert_verify" "fail"
    echo "$errlog"
fi


clear_log
echo -e "1RTT ...\c"
${CLIENT_BIN} -s 1024000 -l e -t 1 -E -1 > stdlog
result=`grep ">>>>>>>> pass:" stdlog`
echo "$result"
flag=`grep "early_data_flag:0" stdlog`
errlog=`grep_err_log`
if [ -n "$flag" ] && [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "1RTT" "pass"
else
    case_print_result "1RTT" "fail"
    echo "$flag"
    echo "$errlog"
fi


clear_log
echo -e "alp negotiation failure ...\c"
rm -f test_session
${CLIENT_BIN} -l e -t 1 -T 1 -x 43 > stdlog
alpn_res=`grep "xqc_ssl_alpn_select_cb|select proto error" slog`
if [ -n "$alpn_res" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "alp_negotiation_failure" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "alp_negotiation_failure" "fail"
fi


clear_log
echo -e "without session ticket ...\c"
rm -f test_session
${CLIENT_BIN} -s 1024000 -l e -t 1 -E > stdlog
result=`grep ">>>>>>>> pass:" stdlog`
echo "$result"
flag=`grep "early_data_flag:0" stdlog`
errlog=`grep_err_log`
if [ -n "$flag" ] && [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "without_session_ticket" "pass"
else
    case_print_result "without_session_ticket" "fail"
    echo "$flag"
    echo "$errlog"
fi


clear_log
rm -f test_session xqc_token tp_localhost
echo -e "transport ping ...\c"
${CLIENT_BIN} -s 1024 -l d -E -x 28 -T 1 >> clog
ret_ping_id=`grep "====>ping_id:" clog`
ret_no_ping_id=`grep "====>no ping_id" clog`
if [ -n "$ret_ping_id" ] && [ -n "$ret_no_ping_id" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "transport_ping" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "transport_ping" "fail"
fi


clear_log
rm -f test_session xqc_token tp_localhost
echo -e "h3 ping ...\c"
${CLIENT_BIN} -s 1024 -l d -E -x 28 >> clog
ret_ping_id=`grep "====>ping_id:" clog`
ret_no_ping_id=`grep "====>no ping_id" clog`
if [ -n "$ret_ping_id" ] && [ -n "$ret_no_ping_id" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ping" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ping" "fail"
fi


clear_log
echo -e "0RTT accept ...\c"
${CLIENT_BIN} -s 1024000 -l e -t 1 -E > stdlog
result=`grep ">>>>>>>> pass:" stdlog`
echo "$result"
flag=`grep "early_data_flag:1" stdlog`
errlog=`grep_err_log`
if [ -n "$flag" ] && [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "0RTT_accept" "pass"
else
    case_print_result "0RTT_accept" "fail"
    echo "$flag"
    echo "$errlog"
fi


clear_log
echo -e "0RTT reject. restart server ....\c"
killall test_server
${SERVER_BIN} -l i -e > /dev/null &
sleep 1
${CLIENT_BIN} -s 1024000 -l d -t 1 -E > stdlog
result=`grep ">>>>>>>> pass:" stdlog`
echo "$result"
flag=`grep "early_data_flag:2" stdlog`
errlog=`grep_err_log`
if [ -n "$flag" ] && [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "0RTT_reject" "pass"
else
    case_print_result "0RTT_reject" "fail"
    echo "$flag"
    echo "$errlog"
fi

clear_log
echo -e "transport only ...\c"
rm -f test_session
result=`${CLIENT_BIN} -s 1024000 -l d -T 1 -t 1 -E|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "transport_only" "pass"
else
    case_print_result "transport_only" "fail"
    echo "$errlog"
fi

clear_log
echo -e "transport 0RTT ...\c"
${CLIENT_BIN} -s 1024000 -l e -T 1 -t 1 -E > stdlog
result=`grep ">>>>>>>> pass:" stdlog`
echo "$result"
flag=`grep "early_data_flag:1" stdlog`
errlog=`grep_err_log`
if [ -n "$flag" ] && [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "transport_0RTT" "pass"
else
    case_print_result "transport_0RTT" "fail"
    echo "$flag"
    echo "$errlog"
fi
rm -f test_session


clear_log
echo -e "no crypto without 0RTT ...\c"
rm -f test_session
result=`${CLIENT_BIN} -s 1024000 -l d -N -t 1 -E|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "no_crypto_without_0RTT" "pass"
else
    case_print_result "no_crypto_without_0RTT" "fail"
    echo "$errlog"
fi


clear_log
echo -e "no crypto with 0RTT ...\c"
${CLIENT_BIN} -s 1024000 -l d -N -t 1 -E > stdlog
if grep "early_data_flag:1" stdlog >/dev/null && grep ">>>>>>>> pass:1" stdlog >/dev/null; then
    echo ">>>>>>>> pass:1"
    case_print_result "no_crypto_with_0RTT" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "no_crypto_with_0RTT" "fail"
fi
grep_err_log


clear_log
echo -e "no crypto with 0RTT twice ...\c"
${CLIENT_BIN} -s 1024000 -l d -N -t 1 -E > stdlog
if grep "early_data_flag:1" stdlog >/dev/null && grep ">>>>>>>> pass:1" stdlog >/dev/null; then
    echo ">>>>>>>> pass:1"
    case_print_result "no_crypto_with_0RTT_twice" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "no_crypto_with_0RTT_twice" "fail"
fi
grep_err_log


clear_log
echo -e "0RTT buffer limit before Initial ...\c"
${CLIENT_BIN} -l d -t 1 -x 39 -E >> clog
limit_log=`grep "0RTT reach buffer limit before DCID confirmed" slog`
clog_res=`grep ">>>>>>>> pass:1" clog`
errlog=`grep_err_log`
if [ -n "$limit_log" ] && [ -n "$clog_res" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "0RTT_buffer_limit_before_Initial" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "0RTT_buffer_limit_before_Initial" "fail"
fi
grep_err_log


clear_log
echo -e "empty header value ...\c"
${CLIENT_BIN} -x 47 -1 -n 10 >> stdlog
result=`grep -E "test_result_speed:.*request_cnt: 10." stdlog`
errlog=`grep_err_log`
if [ -n "$result" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "empty_header_value" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "empty_header_value" "fail"
    exit 1
fi
grep_err_log


clear_log
rm -f test_session
echo -e "NULL stream callback ...\c"
killall test_server
${SERVER_BIN} -l i -e -x 2 > /dev/null &
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

clear_log
echo -e "retry packet send ...\c"
killall test_server
rm -f xqc_token
${SERVER_BIN} -l d -e -x 601 > /dev/null &
sleep 1
result=`${CLIENT_BIN} -s 1024 -l d -t 1 -E --conn_options CBBR|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
slog_res=`grep -E "<==.*xqc_conn_send_retry ok" slog`
clog_res=`grep -E "packet_parse_retry" clog`
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



clear_log
echo -e "server cid negotiate ...\c"
killall test_server
${SERVER_BIN} -l d -e -x 1 > /dev/null &
sleep 1
${CLIENT_BIN} -s 1024000 -l d -t 1 -E >> clog
result=`grep ">>>>>>>> pass:1" clog`
dcid=`grep "====>DCID" clog | awk -F ":" '{print $2}'`
dcid_res=`grep "new:$dcid" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ] && [ -n "$dcid_res" ] && [ -n "$dcid" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "server_cid_negotiate" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "server_cid_negotiate" "fail"
    echo "$errlog"
fi

clear_log
echo -e "GET request ...\c"
result=`${CLIENT_BIN} -l d -t 1 -E -G|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
alpn_res=`grep "|selected_alpn:h3|" slog`
echo "$result"
if [ -z "$errlog" ] && [ -n "$alpn_res" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "GET_request" "pass"
else
    case_print_result "GET_request" "fail"
    echo "$errlog"
fi

clear_log
rm -f test_session xqc_token tp_localhost
echo -e "new client 29 - new server ...\c"
result=`${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 17 |grep ">>>>>>>> pass"`
alpn_res=`grep "selected_alpn:h3-29" slog`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ -n "$alpn_res" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "new_client_29_&_new_server" "pass"
else
    case_print_result "new_client_29_&_new_server" "fail"
    echo "$errlog"
fi
rm -f test_session xqc_token tp_localhost


clear_log
echo -e "set h3 settings ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 18 >> clog
if grep ">>>>>>>> pass:1" clog >/dev/null && \
    grep -e "xqc_h3_conn_send_settings.*qpack_blocked_streams:32|qpack_max_table_capacity:4096|max_field_section_size:512" clog >/dev/null && \
    grep -e "xqc_h3_conn_on_settings_entry_received.*id:7.*value:32" slog >/dev/null && \
    grep -e "xqc_h3_conn_on_settings_entry_received.*id:1.*value:4096" slog >/dev/null && \
    grep -e "xqc_h3_conn_on_settings_entry_received.*id:6.*value:512" slog >/dev/null; then
    echo ">>>>>>>> pass:1"
    case_print_result "set_h3_settings" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "set_h3_settings" "fail"
fi
grep_err_log

clear_log
echo -e "header size constraints ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 19 -n 2 >> clog
if grep -e "xqc_h3_stream_send_headers.*fields_size.*exceed.*SETTINGS_MAX_FIELD_SECTION_SIZE.*" slog >/dev/null; then
    echo ">>>>>>>> pass:1"
    case_print_result "header_size_constraints" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "header_size_constraints" "fail"
fi
grep_err_log|grep -v xqc_h3_stream_send_headers


clear_log
echo -e "no h3 init settings callback ...\c"
result=`${CLIENT_BIN} -s 1024 -l d -t 1 -E |grep ">>>>>>>> pass"`
clog_res=`grep "new_h3_local_settings" clog`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ] && [ -z "$clog_res" ]; then
    case_print_result "no_h3_init_settings_cb" "pass"
else
    case_print_result "no_h3_init_settings_cb" "fail"
    echo "$errlog"
fi

clear_log
echo -e "set h3 init settings callback ...\c"
result=`${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 502|grep ">>>>>>>> pass"`
clog_res=`grep -E "new_h3_local_settings.*qpack_dec_max_table_capacity:65536" clog`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ] && [ -n "$clog_res" ]; then
    case_print_result "set_h3_init_settings_cb" "pass"
else
    case_print_result "set_h3_init_settings_cb" "fail"
    echo "$errlog"
fi

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

clear_log
echo -e "BBR ...\c"
result=`${CLIENT_BIN} -s 10240000 -l e -E -c bbr|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "BBR" "pass"
else
    case_print_result "BBR" "fail"
    echo "$errlog"
fi

clear_log
echo -e "BBR with cwnd compensation ...\c"
result=`${CLIENT_BIN} -s 10240000 -l e -E -c bbr+|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "BBR+" "pass"
else
    case_print_result "BBR+" "fail"
    echo "$errlog"
fi

clear_log
echo -e "BBRv2 ...\c"
result=`${CLIENT_BIN} -s 10240000 -l e -E -c bbr2|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "BBRv2" "pass"
else
    case_print_result "BBRv2" "fail"
    echo "$errlog"
fi

clear_log
echo -e "BBRv2+ ...\c"
result=`${CLIENT_BIN} -s 10240000 -l e -E -c bbr2+|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "BBRv2+" "pass"
else
    case_print_result "BBRv2+" "fail"
    echo "$errlog"
fi

clear_log
echo -e "Reno with pacing ...\c"
result=`${CLIENT_BIN} -s 10240000 -l e -E -c reno -C|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "reno_with_pacing" "pass"
else
    case_print_result "reno_with_pacing" "fail"
    echo "$errlog"
fi

clear_log
echo -e "Reno without pacing ...\c"
result=`${CLIENT_BIN} -s 10240000 -l e -E -c reno|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "reno_without_pacing" "pass"
else
    case_print_result "reno_without_pacing" "fail"
    echo "$errlog"
fi


clear_log
echo -e "Cubic with pacing ...\c"
result=`${CLIENT_BIN} -s 10240000 -l e -E -c cubic -C|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "cubic_with_pacing" "pass"
else
    case_print_result "cubic_with_pacing" "fail"
    echo "$errlog"
fi

clear_log
echo -e "Cubic without pacing ...\c"
result=`${CLIENT_BIN} -s 10240000 -l e -E -c cubic|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "cubic_without_pacing" "pass"
else
    case_print_result "cubic_without_pacing" "fail"
    echo "$errlog"
fi

clear_log
echo -e "unlimited_cc...\c"
result=`${CLIENT_BIN} -s 102400 -l e -t 1 -E -c u|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "unlimited_cc" "pass"
else
    case_print_result "unlimited_cc" "fail"
    echo "$errlog"
fi

clear_log
echo -e "Copa with default parameters (delta=0.05, ai_unit=1.0) ...\c"
result=`${CLIENT_BIN} -s 10240000 -l e -t 1 -E -c P|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "copa_with_default_parameters" "pass"
else
    case_print_result "copa_with_default_parameters" "fail"
    echo "$errlog"
fi

clear_log
echo -e "Copa with customized parameters (delta=0.5, ai_unit=5.0) ...\c"
result=`${CLIENT_BIN} -s 10240000 -l e -t 1 -E -c P --copa_delta 0.5 --copa_ai_unit 5.0 |grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "copa_with_customized_parameters" "pass"
else
    case_print_result "copa_with_customized_parameters" "fail"
    echo "$errlog"
fi


clear_log
echo -e "low_delay_settings...\c"
result=`${CLIENT_BIN} -s 102400 -l e -t 1 -E -x 400|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "low_delay_settings" "pass"
else
    case_print_result "low_delay_settings" "fail"
    echo "$errlog"
fi


clear_log
result=`${CLIENT_BIN} -s 10240000 -l e -t 1 -E -x 26|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "spurious_loss_detect_on" "pass"
else
    case_print_result "spurious_loss_detect_on" "fail"
    echo "$errlog"
fi
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
grep_err_log|grep -v stream
rm -f ccfc.log

clear_log
echo -e "1% loss ...\c"
result=`${CLIENT_BIN} -s 10240000 -l e -E -d 10|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "1_percent_loss" "pass"
else
    case_print_result "1_percent_loss" "fail"
    echo "$errlog"
fi

clear_log
echo -e "3% loss ...\c"
result=`${CLIENT_BIN} -s 10240000 -l e -E -d 30|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "3_percent_loss" "pass"
else
    case_print_result "3_percent_loss" "fail"
    echo "$errlog"
fi

clear_log
result=`${CLIENT_BIN} -s 10240000 -t 5 -l e -E -d 100|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "10_percent_loss" "pass"
else
    case_print_result "10_percent_loss" "fail"
    echo "$errlog"
fi
echo -e "10% loss ...\c"
echo "$result"


killall test_server 2> /dev/null
${SERVER_BIN} -l e -e > /dev/null &
sleep 1

clear_log
echo -e "sendmmsg with 10% loss ...\c"
result=`${CLIENT_BIN} -s 10240000 -t 5 -l e -E -d 100 -x 20 -c c|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "sengmmsg_with_10_percent_loss" "pass"
else
    case_print_result "sengmmsg_with_10_percent_loss" "fail"
    echo "$errlog"
fi


clear_log
result=`${CLIENT_BIN} -s 2048000 -l e -t 5 -E -d 300|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "large_ack_range_with_30_percent_loss" "pass"
else
    case_print_result "large_ack_range_with_30_percent_loss" "fail"
    echo "$errlog"
fi
echo -e "large ack range with 30% loss ...\c"
echo "$result"


clear_log
echo -e "test client long header ...\c"
${CLIENT_BIN} -l d -x 29 >> clog
#clog_res=`grep "xqc_process_conn_close_frame|with err:" clog`
#slog_res=`grep "READ_VALUE error" slog`
slog_res=`grep -a "large nv|conn" slog`
clog_res=`grep -a "xqc_process_conn_close_frame|with err:" clog`
if [ -n "$clog_res" ] && [ -n "$slog_res" ]; then
    case_print_result "test_client_long_header" "pass"
else
    case_print_result "test_client_long_header" "fail"
fi


killall test_server 2> /dev/null
${SERVER_BIN} -l d -x 9 > /dev/null &
sleep 1


clear_log
echo -e "test server long header ...\c"
${CLIENT_BIN} -l d >> clog
#slog_res=`grep "xqc_process_conn_close_frame|with err:" slog`
#clog_res=`grep "READ_VALUE error" clog`
slog_res=`grep "large nv|conn" slog`
#clog_res=`grep "xqc_process_conn_close_frame|with err:" clog`
if [ -n "$slog_res" ]; then
    case_print_result "test_server_long_header" "pass"
else
    case_print_result "test_server_long_header" "fail"
fi


clear_log
killall test_server
echo -e "client Initial dcid corruption ...\c"
sleep 1
${SERVER_BIN} -l d -e > /dev/null &
sleep 1
client_print_res=`${CLIENT_BIN} -s 1024000 -l d -t 1 -x 22 -E | grep ">>>>>>>> pass"`
errlog=`grep_err_log`
server_log_res=`grep "decrypt payload error" slog`
server_conn_cnt=`grep "xqc_conn_create" slog | grep -v "tra_parameters_set" | grep -v "mempool" | grep -v "connection_state_updated" | grep -v "path_assigned" | wc -l`
echo "$client_print_res"
if [ "$client_print_res" != "" ] && [ "$server_log_res" != "" ] && [ $server_conn_cnt -eq 2 ]; then
    case_print_result "client_initial_dcid_corruption" "pass"
else
    case_print_result "client_initial_dcid_corruption" "fail"
    echo "$errlog"
fi


clear_log
killall test_server
echo -e "client Initial scid corruption ...\c"
${SERVER_BIN} -l d -e > /dev/null &
sleep 1
client_print_res=`${CLIENT_BIN} -s 1024000 -l d -t 1 -x 23 -E | grep ">>>>>>>> pass"`
errlog=`grep_err_log`
server_log_res=`grep "decrypt data error" slog`
server_dcid_res=`grep "dcid change" slog`
echo "$client_print_res"
if [ "$client_print_res" != "" ] && [ "$server_log_res" != NULL ] && [ "$server_dcid_res" != NULL ]; then
    case_print_result "client_initial_scid_corruption" "pass"
else
    case_print_result "client_initial_scid_corruption" "fail"
    echo "$errlog"
fi


clear_log
killall test_server
echo -e "server Initial dcid corruption ...\c"
${SERVER_BIN} -l d -e -x 3 > /dev/null &
sleep 1
client_print_res=`${CLIENT_BIN} -s 1024000 -l d -t 1 -E |grep ">>>>>>>> pass"`
client_log_res=`grep "fail to find connection" clog`
echo "$client_print_res"
if [ "$client_print_res" != "" ] && [ "$client_log_res" != "" ]; then
    case_print_result "server_initial_dcid_corruption" "pass"
else
    case_print_result "server_initial_dcid_corruption" "fail"
    echo "$errlog"
fi


clear_log
killall test_server
echo -e "server Initial scid corruption ...\c"
${SERVER_BIN} -l d -e -x 4 > /dev/null &
sleep 1
client_print_res=`${CLIENT_BIN} -s 1024000 -l d -t 1 -E |grep ">>>>>>>> pass"`
client_log_res=`grep "decrypt data error" clog`
echo "$client_print_res"
if [ "$client_print_res" != "" ] && [ "$client_log_res" != "" ]; then
    case_print_result "server_initial_scid_corruption" "pass"
else
    case_print_result "server_initial_scid_corruption" "fail"
fi


clear_log
killall test_server
echo -e "server odcid hash ...\c"
${SERVER_BIN} -l d -e -x 5 > /dev/null &
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
clear_log
killall test_server 2> /dev/null
echo -e "load balancer cid generate with encryption...\c"
${SERVER_BIN} -l d -e -S "server_id_0" -E > /dev/null &
sleep 1
${CLIENT_BIN} -s 1024000 -l d -t 1 >> clog
result=`grep "|lb cid encrypted|" slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "load_balancer_cid_generate_with_encryption" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "load_balancer_cid_generate_with_encryption" "fail"
fi

clear_log
killall test_server 2> /dev/null
echo -e "load balancer cid generate ...\c"
${SERVER_BIN} -l d -e -S "server_id_0" > /dev/null &
sleep 1
${CLIENT_BIN} -s 1024000 -l d -t 1 >> clog
result=`grep "|xqc_conn_confirm_cid|dcid change|" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "load_balancer_cid_generate" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "load_balancer_cid_generate" "fail"
fi

clear_log
echo -e "set cipher suites ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -x 27 >> clog
result=`grep "set cipher suites suc|ciphers:TLS_CHACHA20_POLY1305_SHA256" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "set_cipher_suites" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "set_cipher_suites" "fail"
fi


killall test_server 2> /dev/null
${SERVER_BIN} -l d -e -x 8 > /dev/null &
sleep 1

clear_log
rm -f test_session xqc_token tp_localhost
echo -e "server amplification limit ...\c"
${CLIENT_BIN} -s 1024 -l d -t 3 -x 25 -1 >> clog
enter_aal=`grep "amplification limit" slog`
aal=`grep "blocked by anti amplification limit" slog`
leave_aal=`grep "anti-amplification state unlock" slog`
if [ -n "$enter_aal" ] || [ -n "$aal" ] || [ -n "$leave_aal" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "server_amplification_limit" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "server_amplification_limit" "fail"
fi


killall test_server 2> /dev/null
${SERVER_BIN} -l e -e -x 10 > /dev/null &
sleep 1
clear_log
echo -e "massive requests with massive header ...\c"
${CLIENT_BIN} -l e -q 50 -n 100 -x 32 -E > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "massive_requests_with_massive_header" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "massive_requests_with_massive_header" "fail"
    echo "$result"
fi

killall test_server 2> /dev/null
${SERVER_BIN} -l d -e -b > /dev/null &
sleep 1

clear_log
echo -e "version negotiation ...\c"
${CLIENT_BIN} -l d -E -x 33 >> clog
result=`grep -e "|====>|.*VERSION_NEGOTIATION" clog`
if [ -n "$result" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "version_negotiation" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "version_negotiation" "fail"
fi


killall test_server
${SERVER_BIN} -l d -e -x 11 > /dev/null &
sleep 1

clear_log
echo -e "server refuse connection ...\c"
${CLIENT_BIN} -l d -E >> clog
svr_result=`grep "server_accept callback return error" slog`
if [ -n "$svr_result" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "server_refuse_connection" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "server_refuse_connection" "fail"
fi

killall test_server
${SERVER_BIN} -l e -e -x 12 > /dev/null &
sleep 1

clear_log
echo -e "linger close transport ...\c"
rm -f test_session xqc_token tp_localhost
result=`${CLIENT_BIN} -l e -T 1 -t 1 -E|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "linger_close_transport" "pass"
else
    case_print_result "linger_close_transport" "fail"
    echo "$errlog"
fi
rm -f test_session xqc_token tp_localhost

clear_log
echo -e "linger close h3 ...\c"
result=`${CLIENT_BIN} -l e -t 1 -E|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "linger_close_h3" "pass"
else
    case_print_result "linger_close_h3" "fail"
    echo "$errlog"
fi

killall test_server
${SERVER_BIN} -l d -e > /dev/null &
sleep 1

clear_log
echo -e "key update ...\c"
${CLIENT_BIN} -s 102400 -l d -E -x 40 >> clog
result=`grep ">>>>>>>> pass" clog`
svr_res=`grep "key phase changed to" slog`
cli_res=`grep "key phase changed to" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ] && [ "$svr_res" != "" ] && [ "$cli_res" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "key_update" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "key_update" "fail"
fi
grep_err_log

clear_log
echo -e "key update 0RTT...\c"
${CLIENT_BIN} -s 102400 -l d -E -x 40 >> clog
result=`grep ">>>>>>>> pass" clog`
svr_res=`grep "key phase changed to" slog`
cli_res=`grep "key phase changed to" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ] && [ "$svr_res" != "" ] && [ "$cli_res" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "key_update_0RTT" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "key_update_0RTT" "fail"
fi
grep_err_log


echo -e "max pkt out size...\c"
${CLIENT_BIN} -l d -x 42 -1 -E > stdlog
result=`grep ">>>>>>>> pass" stdlog`
if [ -n "$result" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "max_pkt_out_size" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "max_pkt_out_size" "fail"
fi


killall test_server
${SERVER_BIN} -l d -x 13 > /dev/null &
sleep 1
clear_log
echo -e "stateless reset...\c"
${CLIENT_BIN} -l d -x 41 -1 -t 5 > stdlog
result=`grep "|====>|receive stateless reset" clog`
cloing_notify=`grep "conn closing: 641" stdlog`
if [ -n "$result" ] && [ -n "$cloing_notify" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "stateless_reset" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "stateless_reset" "fail"
fi


clear_log
echo -e "stateless reset during hsk...\c"
${CLIENT_BIN} -l d  -t 5 -x 45 -1 -s 100 -G > stdlog
result=`grep "|====>|receive stateless reset" clog`
cloing_notify=`grep "conn closing: 641" stdlog`
svr_hsk=`grep "handshake_time:0" slog`
if [ -n "$result" ] && [ -n "$cloing_notify" ] && [ -n "$svr_hsk" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "stateless_reset_during_hsk" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "stateless_reset_during_hsk" "fail"
    exit
fi

killall test_server
${SERVER_BIN} -l d -e -M > /dev/null &
sleep 1


clear_log
echo -e "MPNS enable multipath negotiate ...\c"
sudo ${CLIENT_BIN} -s 1024000 -l d -t 1 -M -i lo > stdlog
result=` grep "enable_multipath=1" stdlog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MPNS_enable_multipath_negotiate" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MPNS_enable_multipath_negotiate" "fail"
fi
grep_err_log

clear_log
echo -e "MPNS send 1M data on multiple paths ...\c"
sudo ${CLIENT_BIN} -s 1024000 -l d -t 1 -M -i lo -i lo -E > stdlog
result=`grep ">>>>>>>> pass" stdlog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MPNS_send_1M_data_on_multiple_paths" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MPNS_send_1M_data_on_multiple_paths" "fail"
fi
grep_err_log

clear_log
echo -e "MPNS multipath 30 percent loss ...\c"
sudo ${CLIENT_BIN} -s 10240000 -t 5 -l e -E -d 300 -M -i lo -i lo > stdlog
result=`grep ">>>>>>>> pass" stdlog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    echo ">>>>>>>> pass:1"  
    case_print_result "MPNS_multipath_30_percent_loss" "pass"
else
    echo ">>>>>>>> pass:0"  
    case_print_result "MPNS_multipath_30_percent_loss" "fail"
fi
grep_err_log

clear_log
echo -e "MPNS multipath close initial path ...\c"
sudo ${CLIENT_BIN} -s 10240 -l d -t 5 -M -i lo -i lo -E -x 100 -e 10 --epoch_timeout 1000000 > stdlog
result=`grep ">>>>>>>> pass" stdlog`
svr_res=`grep "|path closed|path:0|" slog`
cli_res=`grep "|path closed|path:0|" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ "$svr_res" != "" ] && [ "$cli_res" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MPNS_multipath_close_initial_path" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MPNS_multipath_close_initial_path" "fail"
fi
grep_err_log

clear_log
echo -e "MPNS multipath 30 percent loss close initial path ...\c"
sudo ${CLIENT_BIN} -s 10240 -t 6 -l d -E -d 300 -M -i lo -i lo -x 100 -e 10 --epoch_timeout 1000000 > stdlog
result=`grep ">>>>>>>> pass" stdlog`
svr_res=`grep "|path closed|path:0|" slog`
cli_res=`grep "|path closed|path:0|" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ "$svr_res" != "" ] && [ "$cli_res" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MPNS_multipath_30_percent_loss_close_initial_path" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MPNS_multipath_30_percent_loss_close_initial_path" "fail"
fi
grep_err_log



clear_log
echo -e "MPNS multipath close new path ...\c"
sudo ${CLIENT_BIN} -s 10240 -l d -t 5 -M -A -i lo -i lo -E -x 101 -e 10 --epoch_timeout 1000000 >> clog
result=`grep ">>>>>>>> pass" clog`
svr_res=`grep "|path closed|path:1|" slog`
cli_res=`grep "|path closed|path:1|" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ "$svr_res" != "" ] && [ "$cli_res" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MPNS_multipath_close_new_path" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MPNS_multipath_close_new_path" "fail"
fi
grep_err_log

clear_log
echo -e "MPNS multipath 30 percent loss close new path ...\c"
sudo ${CLIENT_BIN} -s 10240 -t 6 -l d -E -d 300 -M -i lo -i lo -x 101 -e 10 --epoch_timeout 1000000 > stdlog
result=`grep ">>>>>>>> pass" stdlog`
svr_res=`grep "|path closed|path:1|" slog`
cli_res=`grep "|path closed|path:1|" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ "$svr_res" != "" ] && [ "$cli_res" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MPNS_multipath_30_percent_loss_close_new_path" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MPNS_multipath_30_percent_loss_close_new_path" "fail"
fi
grep_err_log

killall test_server
${SERVER_BIN} -l d -e -M > /dev/null &
sleep 1


clear_log
echo -e "send 1M data on multiple paths with multipath version 10"
sudo ${CLIENT_BIN} -s 1024000 -l d -t 1 -M -i lo -i lo -E -v 10 > stdlog
cli_result=`grep "multipath version negotiation succeed on multipath 010" clog`
if [ -n "$cli_result" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MPNS_send_data_with_multipath_10" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MPNS_send_data_with_multipath_10" "fail"
fi
rm -f test_session tp_localhost xqc_token

killall test_server
${SERVER_BIN} -l d -e -M -R 1 > /dev/null &
sleep 1

clear_log
echo -e "MPNS reinject unack packets by capacity ...\c"
sudo ${CLIENT_BIN} -s 1024000 -l d -t 1 -M -i lo -i lo -E -R 1 > stdlog
result=`grep ">>>>>>>> pass" stdlog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MPNS_reinject_unack_packets_by_capacity" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MPNS_reinject_unack_packets_by_capacity" "fail"
fi
grep_err_log


killall test_server
${SERVER_BIN} -l d -e -M -R 2 > /dev/null &
sleep 1

clear_log
echo -e "MPNS reinject unack packets by deadline ...\c"
sudo ${CLIENT_BIN} -s 1024000 -l d -t 1 -M -i lo -i lo -E -R 2 > stdlog
result=`grep ">>>>>>>> pass" stdlog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MPNS_reinject_unack_packets_by_deadline" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MPNS_reinject_unack_packets_by_deadline" "fail"
fi
grep_err_log


killall test_server
${SERVER_BIN} -l d -e -M > /dev/null &
sleep 1

clear_log
echo -e "NAT rebinding path 0 ...\c"
sudo ${CLIENT_BIN} -s 102400 -l d -t 3 -M -i lo -i lo -E -n 2 -x 103 > stdlog
result=`grep ">>>>>>>> pass:0" stdlog`
errlog=`grep_err_log`
rebind=`grep "|path:0|REBINDING|validate NAT rebinding addr|" slog`
if [ -z "$errlog" ] && [ -z "$result" ] && [ "$rebind" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "NAT_rebinding_path_0" "pass"
else
    echo ">>>>>>>> pass:0"
    echo $errlog
    echo $result
    echo $rebind
    case_print_result "NAT_rebinding_path_0" "fail"
fi
grep_err_log

clear_log
echo -e "NAT rebinding path 1 ...\c"
sudo ${CLIENT_BIN} -s 1024000 -l d -t 3 -M -i lo -i lo -E -n 2 -x 104 > stdlog
result=`grep ">>>>>>>> pass:0" stdlog`
errlog=`grep_err_log`
rebind=`grep "|path:1|REBINDING|validate NAT rebinding addr|" slog`
if [ -z "$errlog" ] && [ -z "$result" ] && [ "$rebind" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "NAT_rebinding_path_1" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "NAT_rebinding_path_1" "fail"
fi
grep_err_log

killall test_server
${SERVER_BIN} -l d -e -M -y > /dev/null &
sleep 1

clear_log
echo -e "Multipath Compensate and Accelerate ...\c"
sudo ${CLIENT_BIN} -s 102400 -l d -t 3 -M -A -i lo -i lo -E -P 2 -y > ccfc.log
errlog=`grep_err_log`
svr_res=`grep "path_status:2->1" slog`
cli_res=`grep "path_status:2->1" clog`
if [ -z "$errlog" ] && [ `grep ">>>>>>>> pass:1" ccfc.log|wc -l` -eq 2 ] && [ "$svr_res" != "" ] &&  [ "$cli_res" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "Multipath_Compensate_and_Accelerate" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "Multipath_Compensate_and_Accelerate" "fail"
fi
grep_err_log

clear_log
echo -e "Multipath Compensate but not Accelerate ...\c"
sudo ${CLIENT_BIN} -s 102400 -l d -t 3 -M -i lo -i lo -E -P 2 -y > ccfc.log
errlog=`grep_err_log`
svr_res=`grep "path_status:2->1" slog`
cli_res=`grep "path_status:2->1" clog`
if [ -z "$errlog" ] && [ `grep ">>>>>>>> pass:1" ccfc.log|wc -l` -eq 2 ] && [ "$svr_res" != "" ] &&  [ "$cli_res" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "Multipath_Compensate_and_Accelerate" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "Multipath_Compensate_and_Accelerate" "fail"
fi
grep_err_log


killall test_server
if [ -f test_session ]; then
    rm -f test_session
fi
if [ -f tp_localhost ]; then
    rm -f tp_localhost
fi
if [ -f xqc_token ]; then
    rm -f xqc_token
fi
if [ -f stdlog ]; then
    rm -f stdlog
fi

${SERVER_BIN} -l d -Q 9000 > /dev/null &
sleep 1
clear_log
echo -e "datagram frame size negotiation...\c"
${CLIENT_BIN} -l d -Q 9000 >> stdlog
cli_result=`grep "|1RTT_transport_params|max_datagram_frame_size:9000|" clog`
svr_result=`grep "|1RTT_transport_params|max_datagram_frame_size:9000|" slog`
errlog=`grep_err_log`
if [ -n "$cli_result" ] && [ -n "$svr_result" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "datagram_frame_size_negotiation" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "datagram_frame_size_negotiation" "fail"
fi

clear_log
echo -e "0RTT max_datagram_frame_size is valid...\c"
${CLIENT_BIN} -l d >> stdlog
cli_result=`grep "|0RTT_transport_params|max_datagram_frame_size:9000|" clog`
cli_result2=`grep "|1RTT_transport_params|max_datagram_frame_size:9000|" clog`
errlog=`grep_err_log`
if [ -n "$cli_result" ] && [ -n "$cli_result2" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "0rtt_max_datagram_frame_size_is_valid" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "0rtt_max_datagram_frame_size_is_valid" "fail"
fi

killall test_server
${SERVER_BIN} -l d -Q 8000 > /dev/null &
sleep 1
clear_log
echo -e "0RTT max_datagram_frame_size is invalid...\c"
${CLIENT_BIN} -l d >> stdlog
cli_result=`grep "|0RTT_transport_params|max_datagram_frame_size:9000|" clog`
cli_err=`grep "[error].*err:0xe" clog`
svr_err=`grep "[error].*err:0xe" slog`
if [ -n "$cli_result" ] && [ -n "$cli_err" ] && [ -n "$svr_err" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "0rtt_max_datagram_frame_size_is_invalid" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "0rtt_max_datagram_frame_size_is_invalid" "fail"
fi
rm -f test_session tp_localhost xqc_token

killall test_server
if [ -f test_session ]; then
    rm -f test_session
fi
if [ -f tp_localhost ]; then
    rm -f tp_localhost
fi
if [ -f xqc_token ]; then
    rm -f xqc_token
fi
stdbuf -oL ${SERVER_BIN} -l d -Q 1000 -x 200 > svr_stdlog &
sleep 1
clear_log
echo -e "datagram_get_mss(no_saved_transport_params)...\c"
${CLIENT_BIN} -l d -T 1 -x 200 -Q 1000 -s 1 -U 1 > stdlog
cli_res1=`grep "\[dgram-200\]|.*|initial_mss:0|" stdlog`
cli_res2=`grep "\[dgram-200\]|.*|updated_mss:997|" stdlog`
svr_res=`grep -a "\[dgram-200\]|.*|initial_mss:997|" svr_stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$svr_res" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "datagram_get_mss_no_saved_transport_params" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "datagram_get_mss_no_saved_transport_params" "fail"
fi

> svr_stdlog
clear_log
echo -e "datagram_get_mss(saved_transport_params)...\c"
${CLIENT_BIN} -l d -T 1 -x 200 -Q 1000 -s 1 -U 1 > stdlog
cli_res1=`grep "\[dgram-200\]|.*|initial_mss:997|" stdlog`
cli_res2=`grep "\[dgram-200\]|.*|updated_mss:997|" stdlog`
svr_res=`grep -a "\[dgram-200\]|.*|initial_mss:997|" svr_stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$svr_res" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "datagram_get_mss_saved_transport_params" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "datagram_get_mss_saved_transport_params" "fail"
fi

killall test_server
if [ -f test_session ]; then
    rm -f test_session
fi
if [ -f tp_localhost ]; then
    rm -f tp_localhost
fi
if [ -f xqc_token ]; then
    rm -f xqc_token
fi
stdbuf -oL  ${SERVER_BIN} -l d -Q 65535 -x 201 > svr_stdlog &
sleep 1
clear_log
echo -e "datagram_mss_limited_by_MTU...\c"
${CLIENT_BIN} -l d -T 1 -x 201 -Q 65535 -s 1 -U 1 > stdlog
cli_res1=`grep "\[dgram-200\]|.*|initial_mss:0|" stdlog`
cli_res2=`grep "\[dgram-200\]|.*|updated_mss:1200|" stdlog`
svr_res=`grep -a "\[dgram-200\]|.*|initial_mss:1200|" svr_stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$svr_res" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "datagram_mss_limited_by_MTU" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "datagram_mss_limited_by_MTU" "fail"
fi

killall test_server
if [ -f test_session ]; then
    rm -f test_session
fi
if [ -f tp_localhost ]; then
    rm -f tp_localhost
fi
if [ -f xqc_token ]; then
    rm -f xqc_token
fi

# timer-based dgram probe
stdbuf -oL ${SERVER_BIN} -l d -Q 65535 -x 209 -e -U 2 > svr_stdlog &
sleep 1
clear_log
echo -e "timer_based_dgram_probe...\c"
${CLIENT_BIN} -l d -T 1 -x 209 -s 1000 -U 1 -Q 65535 -x 209 > stdlog
killall test_server
cli_res1=(`grep "|recv_dgram_bytes:" stdlog | egrep -o ':[0-9]+' | egrep -o '[0-9]+'`)
svr_res=(`grep "|recv_dgram_bytes:" svr_stdlog | egrep -o ':[0-9]+' | egrep -o '[0-9]+'`)
if [ ${cli_res1[0]} -ge 3000 ] && [ ${cli_res1[1]} -ge 1000 ] \
    && [ ${svr_res[0]} -ge 2000 ] && [ ${svr_res[1]} -ge 2000 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "timer_based_dgram_probe" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "timer_based_dgram_probe" "fail"
fi

killall test_server &> /dev/null
if [ -f test_session ]; then
    rm -f test_session
fi
if [ -f tp_localhost ]; then
    rm -f tp_localhost
fi
if [ -f xqc_token ]; then
    rm -f xqc_token
fi

stdbuf -oL ${SERVER_BIN} -l d -Q 1000 -x 200 > svr_stdlog &
sleep 1
clear_log
echo -e "datagram_mss_limited_by_max_datagram_frame_size...\c"
${CLIENT_BIN} -l d -T 1 -x 200 -s 1 -U 1 -Q 1000 > stdlog
cli_res1=`grep "\[dgram-200\]|.*|initial_mss:0|" stdlog`
cli_res2=`grep "\[dgram-200\]|.*|updated_mss:997|" stdlog`
svr_res=`grep -a "\[dgram-200\]|.*|initial_mss:997|" svr_stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$svr_res" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "datagram_mss_limited_by_max_datagram_frame_size" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "datagram_mss_limited_by_max_datagram_frame_size" "fail"
fi
rm -f test_session tp_localhost xqc_token

killall test_server

${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null &
sleep 1
clear_log
#generate 0rtt data
${CLIENT_BIN} -l e -T 1 -s 1 -U 1 -Q 65535 > stdlog
clear_log
echo -e "send_0RTT_datagram_100KB...\c"
${CLIENT_BIN} -l e -T 1 -s 102400 -U 1 -Q 65535 -E > stdlog
cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_0RTT_datagram_100KB" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_0RTT_datagram_100KB" "fail"
fi

if [ $LOCAL_TEST -ne 0 ]; then
    clear_log
    echo -e "send_0RTT_datagram_1MB...\c"
    ${CLIENT_BIN} -l e -T 1 -s 1048576 -U 1 -Q 65535 -E > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_0RTT_datagram_1MB" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_0RTT_datagram_1MB" "fail"
    fi

    clear_log
    echo -e "send_0RTT_datagram_10MB...\c"
    ${CLIENT_BIN} -l e -T 1 -s 10485760 -U 1 -Q 65535 -E > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_0RTT_datagram_10MB" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_0RTT_datagram_10MB" "fail"
    fi

    clear_log
    echo -e "send_0RTT_datagram_100MB...\c"
    ${CLIENT_BIN} -l e -T 1 -s 104857600 -U 1 -Q 65535 -E > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_0RTT_datagram_100MB" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_0RTT_datagram_100MB" "fail"
    fi

fi
rm -f test_session tp_localhost xqc_token


killall test_server

${SERVER_BIN} -l e -Q 65535 -e -U 2 > /dev/null &
sleep 1
clear_log
#generate 0rtt data
${CLIENT_BIN} -l e -T 1 -s 1 -U 2 -Q 65535 > stdlog
clear_log
echo -e "send_0RTT_datagram_100KB_batch...\c"
${CLIENT_BIN} -l e -T 1 -s 102400 -U 2 -Q 65535 -E > stdlog
cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_0RTT_datagram_100KB_batch" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_0RTT_datagram_100KB_batch" "fail"
fi

if [ $LOCAL_TEST -ne 0 ]; then
    clear_log
    echo -e "send_0RTT_datagram_1MB_batch...\c"
    ${CLIENT_BIN} -l e -T 1 -s 1048576 -U 2 -Q 65535 -E > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_0RTT_datagram_1MB_batch" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_0RTT_datagram_1MB_batch" "fail"
    fi

    clear_log
    echo -e "send_0RTT_datagram_10MB_batch...\c"
    ${CLIENT_BIN} -l e -T 1 -s 10485760 -U 2 -Q 65535 -E > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_0RTT_datagram_10MB_batch" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_0RTT_datagram_10MB_batch" "fail"
    fi

    clear_log
    echo -e "send_0RTT_datagram_100MB_batch...\c"
    ${CLIENT_BIN} -l e -T 1 -s 104857600 -U 2 -Q 65535 -E > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_0RTT_datagram_100MB_batch" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_0RTT_datagram_100MB_batch" "fail"
    fi

fi
rm -f test_session tp_localhost xqc_token


killall test_server
${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null &
sleep 1
clear_log
echo -e "send_1RTT_datagram_100KB...\c"
${CLIENT_BIN} -l e -T 1 -s 102400 -U 1 -Q 65535 -E -1 > stdlog
cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_1RTT_datagram_100KB" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_1RTT_datagram_100KB" "fail"
fi

if [ $LOCAL_TEST -ne 0 ]; then
    clear_log
    echo -e "send_1RTT_datagram_1MB...\c"
    ${CLIENT_BIN} -l e -T 1 -s 1048576 -U 1 -Q 65535 -E -1 > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_1RTT_datagram_1MB" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_1RTT_datagram_1MB" "fail"
    fi

    clear_log
    echo -e "send_1RTT_datagram_10MB...\c"
    ${CLIENT_BIN} -l e -T 1 -s 10485760 -U 1 -Q 65535 -E -1 > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_1RTT_datagram_10MB" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_1RTT_datagram_10MB" "fail"
    fi

    clear_log
    echo -e "send_1RTT_datagram_100MB...\c"
    ${CLIENT_BIN} -l e -T 1 -s 104857600 -U 1 -Q 65535 -E -1 > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_1RTT_datagram_100MB" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_1RTT_datagram_100MB" "fail"
    fi
fi
rm -f test_session tp_localhost xqc_token


killall test_server
${SERVER_BIN} -l e -Q 65535 -e -U 2 > /dev/null &
sleep 1
clear_log
echo -e "send_1RTT_datagram_100KB_batch...\c"
${CLIENT_BIN} -l e -T 1 -s 102400 -U 2 -Q 65535 -E -1 > stdlog
cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_1RTT_datagram_100KB_batch" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_1RTT_datagram_100KB_batch" "fail"
fi

if [ $LOCAL_TEST -ne 0 ]; then
    clear_log
    echo -e "send_1RTT_datagram_1MB_batch...\c"
    ${CLIENT_BIN} -l e -T 1 -s 1048576 -U 2 -Q 65535 -E -1 > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_1RTT_datagram_1MB_batch" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_1RTT_datagram_1MB_batch" "fail"
    fi

    clear_log
    echo -e "send_1RTT_datagram_10MB_batch...\c"
    ${CLIENT_BIN} -l e -T 1 -s 10485760 -U 2 -Q 65535 -E -1 > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_1RTT_datagram_10MB_batch" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_1RTT_datagram_10MB_batch" "fail"
    fi

    clear_log
    echo -e "send_1RTT_datagram_100MB_batch...\c"
    ${CLIENT_BIN} -l e -T 1 -s 104857600 -U 2 -Q 65535 -E -1 > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_1RTT_datagram_100MB_batch" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_1RTT_datagram_100MB_batch" "fail"
    fi
fi
rm -f test_session tp_localhost xqc_token

killall test_server
${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null &
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

clear_log
echo -e "send_0rtt_datagram_without_saved_datagram_tp...\c"
${CLIENT_BIN} -l d -T 1 -s 999 -U 1 -Q 65535 -1 -E -x 202 > stdlog
cli_res1=`grep "\[dgram\]|retry_datagram_send_later|" stdlog`
cli_res2=`grep "|waiting_for_max_datagram_frame_size_from_peer|" clog`
cli_res3=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res4=`grep "\[dgram\]|dgram_write|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_0rtt_datagram_without_saved_datagram_tp" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_0rtt_datagram_without_saved_datagram_tp" "fail"
fi

clear_log
echo -e "send_0rtt_datagram_without_saved_datagram_tp_batch...\c"
${CLIENT_BIN} -l d -T 1 -s 999 -U 2 -Q 65535 -1 -E -x 202 > stdlog
cli_res1=`grep "\[dgram\]|retry_datagram_send_multiple_later|" stdlog`
cli_res2=`grep "|waiting_for_max_datagram_frame_size_from_peer|" clog`
cli_res3=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res4=`grep "\[dgram\]|dgram_write|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_0rtt_datagram_without_saved_datagram_tp_batch" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_0rtt_datagram_without_saved_datagram_tp_batch" "fail"
fi


clear_log
echo -e "send_too_many_0rtt_datagrams...\c"
${CLIENT_BIN} -l d -T 1 -s 40000 -U 1 -Q 65535 -E > stdlog
cli_res1=`grep "\[dgram\]|retry_datagram_send_later|" stdlog`
cli_res2=`grep "|too many 0rtt packets|" clog`
cli_res3=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res4=`grep "\[dgram\]|dgram_write|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_too_many_0rtt_datagrams" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_too_many_0rtt_datagrams" "fail"
fi

clear_log
echo -e "send_too_many_0rtt_datagrams_batch...\c"
${CLIENT_BIN} -l d -T 1 -s 40000 -U 2 -Q 65535 -E > stdlog
cli_res1=`grep "\[dgram\]|retry_datagram_send_multiple_later|" stdlog`
cli_res2=`grep "|too many 0rtt packets|" clog`
cli_res3=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res4=`grep "\[dgram\]|dgram_write|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_too_many_0rtt_datagrams_batch" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_too_many_0rtt_datagrams_batch" "fail"
fi

killall test_server
${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null &
sleep 1
clear_log
echo -e "send_0rtt_datagram_reject...\c"
${CLIENT_BIN} -l d -T 1 -s 4800 -U 1 -Q 65535 -E > stdlog
cli_res1=`grep "xqc_conn_early_data_reject" clog`
cli_res2=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_0rtt_datagram_reject" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_0rtt_datagram_reject" "fail"
fi


killall test_server
${SERVER_BIN} -l d -Q 1000 -e -U 1 -s 1 > /dev/null &
sleep 1
clear_log
echo -e "send_oversized_datagram...\c"
${CLIENT_BIN} -l d -T 1 -s 4800 -U 1 -Q 65535 -E -1 -x 203 > stdlog
cli_res1=`grep "datagram_is_too_large" clog`
cli_res2=`grep "trying_to_send_an_oversized_datagram" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_oversized_datagram" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_oversized_datagram" "fail"
fi

clear_log
echo -e "send_oversized_datagram_batch...\c"
${CLIENT_BIN} -l d -T 1 -s 4800 -U 2 -Q 65535 -E -1 -x 203 > stdlog
cli_res1=`grep "datagram_is_too_large" clog`
cli_res2=`grep "trying_to_send_an_oversized_datagram" stdlog`
cli_res3=`grep "|partially_sent_pkts_in_a_batch|cnt:1|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_oversized_datagram_batch" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_oversized_datagram_batch" "fail"
fi
rm -rf tp_localhost test_session xqc_token

killall test_server
${SERVER_BIN} -l d -Q 0 -e -U 1 -s 1 > /dev/null &
sleep 1
clear_log
echo -e "send_datagram_while_peer_does_not_support...\c"
${CLIENT_BIN} -l d -T 1 -s 4800 -U 1 -Q 65535 -E -1 -x 204 > stdlog
cli_res1=`grep "|does not support datagram|" clog`
cli_res2=`grep "\[dgram\]|send_datagram_error|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_datagram_while_peer_does_not_support" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_datagram_while_peer_does_not_support" "fail"
fi

clear_log
echo -e "send_datagram_batch_while_peer_does_not_support...\c"
${CLIENT_BIN} -l d -T 1 -s 4800 -U 2 -Q 65535 -E -1 -x 204 > stdlog
cli_res1=`grep "|does not support datagram|" clog`
cli_res2=`grep "\[dgram\]|send_datagram_multiple_error|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_datagram_batch_while_peer_does_not_support" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_datagram_batch_while_peer_does_not_support" "fail"
fi

killall test_server
${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null &
sleep 1
${CLIENT_BIN} -l d -T 1 -s 1 -U 1 -Q 65535 -E -N > stdlog
clear_log
echo -e "send_0rtt_datagram_dgram1_lost...\c"
${CLIENT_BIN} -l d -T 1 -s 4800 -U 1 -Q 65535 -E -x 205 -N > stdlog
cli_res1=`grep "\[dgram\]|dgram_lost|dgram_id:0|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_0rtt_datagram_dgram1_lost" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_0rtt_datagram_dgram1_lost" "fail"
fi

clear_log
echo -e "send_1rtt_datagram_dgram1_lost...\c"
${CLIENT_BIN} -l d -T 1 -s 4800 -U 1 -Q 65535 -E -x 205 -N -1 > stdlog
cli_res1=`grep "\[dgram\]|dgram_lost|dgram_id:0|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_1rtt_datagram_dgram1_lost" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_1rtt_datagram_dgram1_lost" "fail"
fi

clear_log
echo -e "send_0rtt_datagram_reorder...\c"
${CLIENT_BIN} -l d -T 1 -s 1800 -U 1 -Q 65535 -E -x 206 -N > stdlog
cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_0rtt_datagram_reorder" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_0rtt_datagram_reorder" "fail"
fi

clear_log
echo -e "send_1rtt_datagram_reorder...\c"
${CLIENT_BIN} -l d -T 1 -s 1800 -U 1 -Q 65535 -E -x 206 -N -1 > stdlog
cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_1rtt_datagram_reorder" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_1rtt_datagram_reorder" "fail"
fi

clear_log
echo -e "datagram_lost_callback...\c"
${CLIENT_BIN} -l d -T 1 -s 1000 -U 1 -Q 65535 -E -x 205 -N -1 > stdlog
cli_res1=`grep "\[dgram\]|dgram_lost|dgram_id:0|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "datagram_lost_callback" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "datagram_lost_callback" "fail"
fi

clear_log
echo -e "datagram_acked_callback...\c"
${CLIENT_BIN} -l d -T 1 -s 1000 -U 1 -Q 65535 -E -x 207 > stdlog
cli_res1=`grep "\[dgram\]|dgram_acked|dgram_id:0|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "datagram_acked_callback" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "datagram_acked_callback" "fail"
fi

killall test_server
if [ -f test_session ]; then
    rm -f test_session
fi
if [ -f tp_localhost ]; then
    rm -f tp_localhost
fi
if [ -f xqc_token ]; then
    rm -f xqc_token
fi
stdbuf -oL ${SERVER_BIN} -l d -Q 65535 -x 208 -e -U 1 > svr_stdlog &
sleep 1

clear_log
echo -e "1RTT_datagram_send_redundancy...\c"
${CLIENT_BIN} -l d -T 1 -s 2000 -U 1 -Q 65535 -x 208 > stdlog
cli_res1=`grep "\[dgram\]|recv_dgram_bytes:8000" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "1RTT_datagram_send_redundancy" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "1RTT_datagram_send_redundancy" "fail"
fi

if [ -f test_session ]; then
    rm -f test_session
fi

clear_log
echo -e "1RTT_datagram_send_multiple_redundancy...\c"
${CLIENT_BIN} -l d -T 1 -s 2000 -U 2 -Q 65535 -x 208 > stdlog
cli_res1=`grep "\[dgram\]|recv_dgram_bytes:8000" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "1RTT_datagram_send_multiple_redundancy" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "1RTT_datagram_send_multiple_redundancy" "fail"
fi


clear_log
echo -e "0RTT_datagram_send_redundancy...\c"
${CLIENT_BIN} -l d -T 1 -s 2000 -U 1 -Q 65535 -x 208 > stdlog
cli_res1=`grep "\[dgram\]|recv_dgram_bytes:8000" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "0RTT_datagram_send_redundancy" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "0RTT_datagram_send_redundancy" "fail"
fi

clear_log
echo -e "0RTT_datagram_send_multiple_redundancy...\c"
${CLIENT_BIN} -l d -T 1 -s 2000 -U 2 -Q 65535 -x 208 > stdlog
cli_res1=`grep "\[dgram\]|recv_dgram_bytes:8000" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "0RTT_datagram_send_multiple_redundancy" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "0RTT_datagram_send_multiple_redundancy" "fail"
fi

killall test_server
rm -rf tp_localhost test_session xqc_token
clear_log
stdbuf -oL ${SERVER_BIN} -l d -Q 65535 -x 208 -e -U 1 > svr_stdlog &
sleep 1

echo -e "stop_datagram_send_redundancy_after_negotiation...\c"
${CLIENT_BIN} -l d -T 1 -s 2000 -U 2 -Q 65535 -x 208 --close_dg_red 1 > stdlog
cli_res=`grep "|stop sending datagram redundancy." clog`
svr_res=`grep "|stop sending datagram redundancy." slog`
errlog=`grep_err_log`
if [ -n "$cli_res" ] && [ -n "$svr_res" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "stop_datagram_send_redundancy_after_negotiation" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "stop_datagram_send_redundancy_after_negotiation" "fail"
fi


killall test_server
${SERVER_BIN} -l d -e -x 208 -Q 65535 -U 1 --dgram_qos 3 > /dev/null &
sleep 1

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "No reinjection for normal datagrams...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 208 -Q 65535 -U 1 -T 1 --dgram_qos 3 > stdlog
result=`grep "\[dgram\]|recv_dgram_bytes:1024|sent_dgram_bytes:1024|" stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:0" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "No_reinjection_for_normal_datagrams" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "No_reinjection_for_normal_datagrams" "fail"
fi
grep_err_log

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "No reinjection for normal h3-ext datagrams...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 208 -Q 65535 -U 1 -T 2 --dgram_qos 3 > stdlog
result=`grep "\[h3-dgram\]|recv_dgram_bytes:1024|sent_dgram_bytes:1024|" stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:0" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "No_reinjection_for_normal_h3_ext_datagrams" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "No_reinjection_for_normal_h3_ext_datagrams" "fail"
fi
grep_err_log


# h3 ext datagram

killall test_server
if [ -f test_session ]; then
    rm -f test_session
fi
if [ -f tp_localhost ]; then
    rm -f tp_localhost
fi
if [ -f xqc_token ]; then
    rm -f xqc_token
fi
stdbuf -oL ${SERVER_BIN} -l d -Q 1000 -x 200 > svr_stdlog &
sleep 1
clear_log
echo -e "h3_ext_datagram_get_mss(no_saved_transport_params)...\c"
${CLIENT_BIN} -l d -T 2 -x 200 -Q 1000 -s 1 -U 1 > stdlog
cli_res1=`grep "\[h3-dgram-200\]|.*|initial_mss:0|" stdlog`
cli_res2=`grep "\[h3-dgram-200\]|.*|updated_mss:997|" stdlog`
svr_res=`grep -a "\[h3-dgram-200\]|.*|initial_mss:997|" svr_stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$svr_res" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_datagram_get_mss_no_saved_transport_params" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_datagram_get_mss_no_saved_transport_params" "fail"
fi

> svr_stdlog
clear_log
echo -e "h3_ext_datagram_get_mss(saved_transport_params)...\c"
${CLIENT_BIN} -l d -T 2 -x 200 -Q 1000 -s 1 -U 1 > stdlog
cli_res1=`grep "\[h3-dgram-200\]|.*|initial_mss:997|" stdlog`
cli_res2=`grep "\[h3-dgram-200\]|.*|updated_mss:997|" stdlog`
svr_res=`grep -a "\[h3-dgram-200\]|.*|initial_mss:997|" svr_stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$svr_res" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_datagram_get_mss_saved_transport_params" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_datagram_get_mss_saved_transport_params" "fail"
fi

killall test_server
if [ -f test_session ]; then
    rm -f test_session
fi
if [ -f tp_localhost ]; then
    rm -f tp_localhost
fi
if [ -f xqc_token ]; then
    rm -f xqc_token
fi
stdbuf -oL  ${SERVER_BIN} -l d -Q 65535 -x 201 > svr_stdlog &
sleep 1
clear_log
echo -e "h3_ext_datagram_mss_limited_by_MTU...\c"
${CLIENT_BIN} -l d -T 2 -x 201 -Q 65535 -s 1 -U 1 > stdlog
cli_res1=`grep "\[h3-dgram-200\]|.*|initial_mss:0|" stdlog`
cli_res2=`grep "\[h3-dgram-200\]|.*|updated_mss:1200|" stdlog`
svr_res=`grep -a "\[h3-dgram-200\]|.*|initial_mss:1200|" svr_stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$svr_res" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_datagram_mss_limited_by_MTU" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_datagram_mss_limited_by_MTU" "fail"
fi

killall test_server
if [ -f test_session ]; then
    rm -f test_session
fi
if [ -f tp_localhost ]; then
    rm -f tp_localhost
fi
if [ -f xqc_token ]; then
    rm -f xqc_token
fi
stdbuf -oL ${SERVER_BIN} -l d -Q 1000 -x 200 > svr_stdlog &
sleep 1
clear_log
echo -e "h3_ext_datagram_mss_limited_by_max_datagram_frame_size...\c"
${CLIENT_BIN} -l d -T 2 -x 200 -s 1 -U 1 -Q 1000 > stdlog
cli_res1=`grep "\[h3-dgram-200\]|.*|initial_mss:0|" stdlog`
cli_res2=`grep "\[h3-dgram-200\]|.*|updated_mss:997|" stdlog`
svr_res=`grep -a "\[h3-dgram-200\]|.*|initial_mss:997|" svr_stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$svr_res" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_datagram_mss_limited_by_max_datagram_frame_size" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_datagram_mss_limited_by_max_datagram_frame_size" "fail"
fi
rm -f test_session tp_localhost xqc_token

killall test_server

${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null &
sleep 1
clear_log
#generate 0rtt data
${CLIENT_BIN} -l e -T 2 -s 1 -U 1 -Q 65535 > stdlog
clear_log
echo -e "send_0RTT_h3_ext_datagram_100KB...\c"
${CLIENT_BIN} -l e -T 2 -s 102400 -U 1 -Q 65535 -E > stdlog
cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_0RTT_h3_ext_datagram_100KB" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_0RTT_h3_ext_datagram_100KB" "fail"
fi

if [ $LOCAL_TEST -ne 0 ]; then
    clear_log
    echo -e "send_0RTT_h3_ext_datagram_1MB...\c"
    ${CLIENT_BIN} -l e -T 2 -s 1048576 -U 1 -Q 65535 -E > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_0RTT_h3_ext_datagram_1MB" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_0RTT_h3_ext_datagram_1MB" "fail"
    fi

    clear_log
    echo -e "send_0RTT_h3_ext_datagram_10MB...\c"
    ${CLIENT_BIN} -l e -T 2 -s 10485760 -U 1 -Q 65535 -E > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_0RTT_h3_ext_datagram_10MB" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_0RTT_h3_ext_datagram_10MB" "fail"
    fi

    clear_log
    echo -e "send_0RTT_h3_ext_datagram_100MB...\c"
    ${CLIENT_BIN} -l e -T 2 -s 104857600 -U 1 -Q 65535 -E > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_0RTT_h3_ext_datagram_100MB" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_0RTT_h3_ext_datagram_100MB" "fail"
    fi

fi
rm -f test_session tp_localhost xqc_token


killall test_server

${SERVER_BIN} -l e -Q 65535 -e -U 2 > /dev/null &
sleep 1
clear_log
#generate 0rtt data
${CLIENT_BIN} -l e -T 2 -s 1 -U 2 -Q 65535 > stdlog
clear_log
echo -e "send_0RTT_h3_ext_datagram_100KB_batch...\c"
${CLIENT_BIN} -l e -T 2 -s 102400 -U 2 -Q 65535 -E > stdlog
cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_0RTT_h3_ext_datagram_100KB_batch" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_0RTT_h3_ext_datagram_100KB_batch" "fail"
fi

if [ $LOCAL_TEST -ne 0 ]; then
    clear_log
    echo -e "send_0RTT_h3_ext_datagram_1MB_batch...\c"
    ${CLIENT_BIN} -l e -T 2 -s 1048576 -U 2 -Q 65535 -E > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_0RTT_h3_ext_datagram_1MB_batch" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_0RTT_h3_ext_datagram_1MB_batch" "fail"
    fi

    clear_log
    echo -e "send_0RTT_h3_ext_datagram_10MB_batch...\c"
    ${CLIENT_BIN} -l e -T 2 -s 10485760 -U 2 -Q 65535 -E > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_0RTT_h3_ext_datagram_10MB_batch" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_0RTT_h3_ext_datagram_10MB_batch" "fail"
    fi

    clear_log
    echo -e "send_0RTT_h3_ext_datagram_100MB_batch...\c"
    ${CLIENT_BIN} -l e -T 2 -s 104857600 -U 2 -Q 65535 -E > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_0RTT_h3_ext_datagram_100MB_batch" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_0RTT_h3_ext_datagram_100MB_batch" "fail"
    fi

fi
rm -f test_session tp_localhost xqc_token


killall test_server
${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null &
sleep 1
clear_log
echo -e "send_1RTT_h3_ext_datagram_100KB...\c"
${CLIENT_BIN} -l e -T 2 -s 102400 -U 1 -Q 65535 -E -1 > stdlog
cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_1RTT_h3_ext_datagram_100KB" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_1RTT_h3_ext_datagram_100KB" "fail"
fi

if [ $LOCAL_TEST -ne 0 ]; then
    clear_log
    echo -e "send_1RTT_h3_ext_datagram_1MB...\c"
    ${CLIENT_BIN} -l e -T 2 -s 1048576 -U 1 -Q 65535 -E -1 > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_1RTT_h3_ext_datagram_1MB" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_1RTT_h3_ext_datagram_1MB" "fail"
    fi

    clear_log
    echo -e "send_1RTT_h3_ext_datagram_10MB...\c"
    ${CLIENT_BIN} -l e -T 2 -s 10485760 -U 1 -Q 65535 -E -1 > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_1RTT_h3_ext_datagram_10MB" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_1RTT_h3_ext_datagram_10MB" "fail"
    fi

    clear_log
    echo -e "send_1RTT_h3_ext_datagram_100MB...\c"
    ${CLIENT_BIN} -l e -T 2 -s 104857600 -U 1 -Q 65535 -E -1 > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_1RTT_h3_ext_datagram_100MB" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_1RTT_h3_ext_datagram_100MB" "fail"
    fi
fi
rm -f test_session tp_localhost xqc_token


killall test_server
${SERVER_BIN} -l e -Q 65535 -e -U 2 > /dev/null &
sleep 1
clear_log
echo -e "send_1RTT_h3_ext_datagram_100KB_batch...\c"
${CLIENT_BIN} -l e -T 2 -s 102400 -U 2 -Q 65535 -E -1 > stdlog
cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_1RTT_h3_ext_datagram_100KB_batch" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_1RTT_h3_ext_datagram_100KB_batch" "fail"
fi

if [ $LOCAL_TEST -ne 0 ]; then
    clear_log
    echo -e "send_1RTT_h3_ext_datagram_1MB_batch...\c"
    ${CLIENT_BIN} -l e -T 2 -s 1048576 -U 2 -Q 65535 -E -1 > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_1RTT_h3_ext_datagram_1MB_batch" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_1RTT_h3_ext_datagram_1MB_batch" "fail"
    fi

    clear_log
    echo -e "send_1RTT_h3_ext_datagram_10MB_batch...\c"
    ${CLIENT_BIN} -l e -T 2 -s 10485760 -U 2 -Q 65535 -E -1 > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_1RTT_h3_ext_datagram_10MB_batch" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_1RTT_h3_ext_datagram_10MB_batch" "fail"
    fi

    clear_log
    echo -e "send_1RTT_h3_ext_datagram_100MB_batch...\c"
    ${CLIENT_BIN} -l e -T 2 -s 104857600 -U 2 -Q 65535 -E -1 > stdlog
    cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
    errlog=`grep_err_log`
    if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "send_1RTT_h3_ext_datagram_100MB_batch" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "send_1RTT_h3_ext_datagram_100MB_batch" "fail"
    fi
fi
rm -f test_session tp_localhost xqc_token

killall test_server
${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null &
sleep 1
clear_log
echo -e "h3_ext_dgram_send_queue_full...\c"
${CLIENT_BIN} -l d -T 2 -s 40000000 -U 1 -Q 65535 -1 > stdlog
cli_res1=`grep "\[h3-dgram\]|retry_datagram_send_later|" stdlog`
cli_res2=`grep "|too many packets used|ctl_packets_used:" clog`
cli_res3=`grep "\[h3-dgram\]|dgram_write|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_dgram_send_queue_full" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_dgram_send_queue_full" "fail"
fi

clear_log
echo -e "h3_ext_dgram_send_queue_full_batch...\c"
${CLIENT_BIN} -l d -T 2 -s 40000000 -U 2 -Q 65535 -1 > stdlog
cli_res1=`grep "\[h3-dgram\]|retry_datagram_send_multiple_later|" stdlog`
cli_res2=`grep "|too many packets used|ctl_packets_used:" clog`
cli_res3=`grep "\[h3-dgram\]|dgram_write|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_dgram_send_queue_full_batch" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_dgram_send_queue_full_batch" "fail"
fi

clear_log
echo -e "send_0rtt_h3_ext_datagram_without_saved_datagram_tp...\c"
${CLIENT_BIN} -l d -T 2 -s 999 -U 1 -Q 65535 -1 -E -x 202 > stdlog
cli_res1=`grep "\[h3-dgram\]|retry_datagram_send_later|" stdlog`
cli_res2=`grep "|waiting_for_max_datagram_frame_size_from_peer|" clog`
cli_res3=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res4=`grep "\[h3-dgram\]|dgram_write|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_0rtt_h3_ext_datagram_without_saved_datagram_tp" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_0rtt_h3_ext_datagram_without_saved_datagram_tp" "fail"
fi

clear_log
echo -e "send_0rtt_h3_ext_datagram_without_saved_datagram_tp_batch...\c"
${CLIENT_BIN} -l d -T 2 -s 999 -U 2 -Q 65535 -1 -E -x 202 > stdlog
cli_res1=`grep "\[h3-dgram\]|retry_datagram_send_multiple_later|" stdlog`
cli_res2=`grep "|waiting_for_max_datagram_frame_size_from_peer|" clog`
cli_res3=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res4=`grep "\[h3-dgram\]|dgram_write|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_0rtt_h3_ext_datagram_without_saved_datagram_tp_batch" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_0rtt_h3_ext_datagram_without_saved_datagram_tp_batch" "fail"
fi


clear_log
echo -e "send_too_many_0rtt_h3_ext_datagrams...\c"
${CLIENT_BIN} -l d -T 2 -s 40000 -U 1 -Q 65535 -E > stdlog
cli_res1=`grep "\[h3-dgram\]|retry_datagram_send_later|" stdlog`
cli_res2=`grep "|too many 0rtt packets|" clog`
cli_res3=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res4=`grep "\[h3-dgram\]|dgram_write|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_too_many_0rtt_h3_ext_datagrams" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_too_many_0rtt_h3_ext_datagrams" "fail"
fi

clear_log
echo -e "send_too_many_0rtt_h3_ext_datagrams_batch...\c"
${CLIENT_BIN} -l d -T 2 -s 40000 -U 2 -Q 65535 -E > stdlog
cli_res1=`grep "\[h3-dgram\]|retry_datagram_send_multiple_later|" stdlog`
cli_res2=`grep "|too many 0rtt packets|" clog`
cli_res3=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res4=`grep "\[h3-dgram\]|dgram_write|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_too_many_0rtt_h3_ext_datagrams_batch" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_too_many_0rtt_h3_ext_datagrams_batch" "fail"
fi

killall test_server
${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null &
sleep 1
clear_log
echo -e "send_0rtt_h3_ext_datagram_reject...\c"
${CLIENT_BIN} -l d -T 2 -s 4800 -U 1 -Q 65535 -E > stdlog
cli_res1=`grep "xqc_conn_early_data_reject" clog`
cli_res2=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_0rtt_h3_ext_datagram_reject" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_0rtt_h3_ext_datagram_reject" "fail"
fi


killall test_server
${SERVER_BIN} -l d -Q 1000 -e -U 1 -s 1 > /dev/null &
sleep 1
clear_log
echo -e "send_oversized_h3_ext_datagram...\c"
${CLIENT_BIN} -l d -T 2 -s 4800 -U 1 -Q 65535 -E -1 -x 203 > stdlog
cli_res1=`grep "datagram_is_too_large" clog`
cli_res2=`grep "trying_to_send_an_oversized_datagram" stdlog`
#errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_oversized_h3_ext_datagram" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_oversized_h3_ext_datagram" "fail"
fi

clear_log
echo -e "send_oversized_h3_ext_datagram_batch...\c"
${CLIENT_BIN} -l d -T 2 -s 4800 -U 2 -Q 65535 -E -1 -x 203 > stdlog
cli_res1=`grep "datagram_is_too_large" clog`
cli_res2=`grep "trying_to_send_an_oversized_datagram" stdlog`
cli_res3=`grep "|partially_sent_pkts_in_a_batch|cnt:1|" stdlog`
#errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_oversized_h3_ext_datagram_batch" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_oversized_h3_ext_datagram_batch" "fail"
fi
rm -rf tp_localhost test_session xqc_token

killall test_server
${SERVER_BIN} -l d -Q 0 -e -U 1 -s 1 > /dev/null &
sleep 1
clear_log
echo -e "send_h3_ext_datagram_while_peer_does_not_support...\c"
${CLIENT_BIN} -l d -T 2 -s 4800 -U 1 -Q 65535 -E -1 -x 204 > stdlog
cli_res1=`grep "|does not support datagram|" clog`
cli_res2=`grep "\[h3-dgram\]|send_datagram_error|" stdlog`
#errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_h3_ext_datagram_while_peer_does_not_support" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_h3_ext_datagram_while_peer_does_not_support" "fail"
fi

clear_log
echo -e "send_h3_ext_datagram_batch_while_peer_does_not_support...\c"
${CLIENT_BIN} -l d -T 2 -s 4800 -U 2 -Q 65535 -E -1 -x 204 > stdlog
cli_res1=`grep "|does not support datagram|" clog`
cli_res2=`grep "\[h3-dgram\]|send_datagram_multiple_error|" stdlog`
#errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_h3_ext_datagram_batch_while_peer_does_not_support" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_h3_ext_datagram_batch_while_peer_does_not_support" "fail"
fi

killall test_server
${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null &
sleep 1
${CLIENT_BIN} -l d -T 2 -s 1 -U 1 -Q 65535 -E -N > stdlog
clear_log
echo -e "send_0rtt_h3_ext_datagram_dgram1_lost...\c"
${CLIENT_BIN} -l d -T 2 -s 4800 -U 1 -Q 65535 -E -x 205 -N > stdlog
cli_res1=`grep "\[h3-dgram\]|dgram_lost|dgram_id:0|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_0rtt_h3_ext_datagram_dgram1_lost" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_0rtt_h3_ext_datagram_dgram1_lost" "fail"
fi

clear_log
echo -e "send_1rtt_h3_ext_datagram_dgram1_lost...\c"
${CLIENT_BIN} -l d -T 2 -s 4800 -U 1 -Q 65535 -E -x 205 -N -1 > stdlog
cli_res1=`grep "\[h3-dgram\]|dgram_lost|dgram_id:0|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_1rtt_h3_ext_datagram_dgram1_lost" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_1rtt_h3_ext_datagram_dgram1_lost" "fail"
fi

clear_log
echo -e "send_0rtt_h3_ext_datagram_reorder...\c"
${CLIENT_BIN} -l d -T 2 -s 1800 -U 1 -Q 65535 -E -x 206 -N > stdlog
cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_0rtt_h3_ext_datagram_reorder" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_0rtt_h3_ext_datagram_reorder" "fail"
fi

clear_log
echo -e "send_1rtt_h3_ext_datagram_reorder...\c"
${CLIENT_BIN} -l d -T 2 -s 1800 -U 1 -Q 65535 -E -x 206 -N -1 > stdlog
cli_res1=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "send_1rtt_h3_ext_datagram_reorder" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "send_1rtt_h3_ext_datagram_reorder" "fail"
fi

clear_log
echo -e "h3_ext_datagram_lost_callback...\c"
${CLIENT_BIN} -l d -T 2 -s 1000 -U 1 -Q 65535 -E -x 205 -N -1 > stdlog
cli_res1=`grep "\[h3-dgram\]|dgram_lost|dgram_id:0|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_datagram_lost_callback" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_datagram_lost_callback" "fail"
fi

clear_log
echo -e "h3_ext_datagram_acked_callback...\c"
${CLIENT_BIN} -l d -T 2 -s 1000 -U 1 -Q 65535 -E -x 207 > stdlog
cli_res1=`grep "\[h3-dgram\]|dgram_acked|dgram_id:0|" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_datagram_acked_callback" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_datagram_acked_callback" "fail"
fi

rm -f test_session tp_localhost xqc_token

killall test_server

${SERVER_BIN} -l e -Q 65535 -e -U 1 -x 208 > /dev/null &
sleep 1

clear_log
echo -e "1RTT_h3_ext_datagram_send_redundancy...\c"
${CLIENT_BIN} -l d -T 2 -s 2000 -U 1 -Q 65535 -x 208 > stdlog
cli_res1=`grep "\[h3-dgram\]|recv_dgram_bytes:8000" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "1RTT_h3_ext_datagram_send_redundancy" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "1RTT_h3_ext_datagram_send_redundancy" "fail"
fi

rm -f test_session tp_localhost xqc_token

clear_log
echo -e "1RTT_h3_ext_datagram_send_multiple_redundancy...\c"
${CLIENT_BIN} -l d -T 2 -s 2000 -U 2 -Q 65535 -x 208 > stdlog
cli_res1=`grep "\[h3-dgram\]|recv_dgram_bytes:8000" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "1RTT_h3_ext_datagram_send_multiple_redundancy" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "1RTT_h3_ext_datagram_send_multiple_redundancy" "fail"
fi

clear_log
echo -e "0RTT_h3_ext_datagram_send_redundancy...\c"
${CLIENT_BIN} -l d -T 2 -s 2000 -U 1 -Q 65535 -x 208 > stdlog
cli_res1=`grep "\[h3-dgram\]|recv_dgram_bytes:8000" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "0RTT_h3_ext_datagram_send_redundancy" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "0RTT_h3_ext_datagram_send_redundancy" "fail"
fi

clear_log
echo -e "0RTT_h3_ext_datagram_send_multiple_redundancy...\c"
${CLIENT_BIN} -l d -T 2 -s 2000 -U 2 -Q 65535 -x 208 > stdlog
cli_res1=`grep "\[h3-dgram\]|recv_dgram_bytes:8000" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "0RTT_h3_ext_datagram_send_multiple_redundancy" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "0RTT_h3_ext_datagram_send_multiple_redundancy" "fail"
fi


# send h3 request / bytestream / datagram in one h3_conn (-x 300)

rm -f test_session tp_localhost xqc_token

killall test_server

${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null &
sleep 1


## 1RTT
clear_log
echo -e "h3_ext_1RTT_send_test...\c"
${CLIENT_BIN} -l e -T 2 -s 102400 -U 1 -Q 65535 -E -x 300 -1 > stdlog
cli_res1=`grep ">>>>>>>> pass:1" stdlog`
cli_res2=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res3=`grep "\[h3-dgram\]|recv_dgram_bytes:102400|sent_dgram_bytes:102400|lost_dgram_bytes:0|lost_cnt:0|" stdlog`
cli_res4=`grep "\[bytestream\]|bytes_sent:102400|bytes_rcvd:102400|recv_fin:1|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:yes|" stdlog`
cli_res6=`grep "early_data_flag:0" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ -n "$cli_res5" ] && [ -n "$cli_res6" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_1RTT_send_test" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_1RTT_send_test" "fail"
fi

## 0RTT
clear_log
echo -e "h3_ext_0RTT_accept_send_test...\c"
${CLIENT_BIN} -l e -T 2 -s 102400 -U 1 -Q 65535 -E -x 300 > stdlog
cli_res1=`grep ">>>>>>>> pass:1" stdlog`
cli_res2=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res3=`grep "\[h3-dgram\]|recv_dgram_bytes:102400|sent_dgram_bytes:102400|lost_dgram_bytes:0|lost_cnt:0|" stdlog`
cli_res4=`grep "\[bytestream\]|bytes_sent:102400|bytes_rcvd:102400|recv_fin:1|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:yes|" stdlog`
cli_res6=`grep "early_data_flag:1" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ -n "$cli_res5" ] && [ -n "$cli_res6" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_0RTT_accept_send_test" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_0RTT_accept_send_test" "fail"
fi

## 0RTT reject

killall test_server

${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null &
sleep 1

clear_log
echo -e "h3_ext_0RTT_reject_send_test...\c"
${CLIENT_BIN} -l e -T 2 -s 102400 -U 1 -Q 65535 -E -x 300 > stdlog
cli_res1=`grep ">>>>>>>> pass:1" stdlog`
cli_res2=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res3=`grep "\[h3-dgram\]|recv_dgram_bytes:102400|sent_dgram_bytes:102400|lost_dgram_bytes:0|lost_cnt:0|" stdlog`
cli_res4=`grep "\[bytestream\]|bytes_sent:102400|bytes_rcvd:102400|recv_fin:1|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:yes|" stdlog`
cli_res6=`grep "early_data_flag:2" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ -n "$cli_res5" ] && [ -n "$cli_res6" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_0RTT_reject_send_test" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_0RTT_reject_send_test" "fail"
fi

# send concurrent h3 req / open concurrent bytestreams / send datagrams in one h3_conn (-x 301)

## 1RTT
clear_log
echo -e "h3_ext_1RTT_concurrent_send_test...\c"
${CLIENT_BIN} -l e -T 2 -s 102400 -U 1 -Q 65535 -E -x 301 -P 2 -1 > stdlog
cli_res1=`grep ">>>>>>>> pass:1" stdlog | wc -l`
cli_res2=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res3=`grep "\[h3-dgram\]|recv_dgram_bytes:102400|sent_dgram_bytes:102400|lost_dgram_bytes:0|lost_cnt:0|" stdlog`
cli_res4=`grep "\[bytestream\]|bytes_sent:102400|bytes_rcvd:102400|recv_fin:1|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:yes|" stdlog | wc -l`
cli_res6=`grep "early_data_flag:0" stdlog`

errlog=`grep_err_log`
if [ "$cli_res1" == "2" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ "$cli_res5" == "2" ] && [ -n "$cli_res6" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_1RTT_concurrent_send_test" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_1RTT_concurrent_send_test" "fail"
fi

## 0RTT
clear_log
echo -e "h3_ext_0RTT_accept_concurrent_send_test...\c"
${CLIENT_BIN} -l e -T 2 -s 102400 -U 1 -Q 65535 -E -x 301 -P 2 > stdlog
cli_res1=`grep ">>>>>>>> pass:1" stdlog | wc -l`
cli_res2=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res3=`grep "\[h3-dgram\]|recv_dgram_bytes:102400|sent_dgram_bytes:102400|lost_dgram_bytes:0|lost_cnt:0|" stdlog`
cli_res4=`grep "\[bytestream\]|bytes_sent:102400|bytes_rcvd:102400|recv_fin:1|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:yes|" stdlog | wc -l`
cli_res6=`grep "early_data_flag:1" stdlog`

errlog=`grep_err_log`
if [ "$cli_res1" == "2" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ "$cli_res5" == "2" ] && [ -n "$cli_res6" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_0RTT_accept_concurrent_send_test" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_0RTT_accept_concurrent_send_test" "fail"
fi

## 0RTT reject

killall test_server

${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null &
sleep 1

clear_log
echo -e "h3_ext_0RTT_reject_concurrent_send_test...\c"
${CLIENT_BIN} -l e -T 2 -s 102400 -U 1 -Q 65535 -E -x 301 -P 2 > stdlog
cli_res1=`grep ">>>>>>>> pass:1" stdlog | wc -l`
cli_res2=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res3=`grep "\[h3-dgram\]|recv_dgram_bytes:102400|sent_dgram_bytes:102400|lost_dgram_bytes:0|lost_cnt:0|" stdlog`
cli_res4=`grep "\[bytestream\]|bytes_sent:102400|bytes_rcvd:102400|recv_fin:1|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:yes|" stdlog | wc -l`
cli_res6=`grep "early_data_flag:2" stdlog`

errlog=`grep_err_log`
if [ "$cli_res1" == "2" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ "$cli_res5" == "2" ] && [ -n "$cli_res6" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_0RTT_reject_concurrent_send_test" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_0RTT_reject_concurrent_send_test" "fail"
fi


# send bytestream with pure fin (-x 302 -x 303)

## 1RTT

clear_log
echo -e "h3_ext_1RTT_send_pure_fin1...\c"
${CLIENT_BIN} -l e -T 2 -s 102400 -U 1 -Q 65535 -E -x 302 -1 > stdlog
cli_res1=`grep ">>>>>>>> pass:1" stdlog | wc -l`
cli_res2=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res3=`grep "\[h3-dgram\]|recv_dgram_bytes:102400|sent_dgram_bytes:102400|lost_dgram_bytes:0|lost_cnt:0|" stdlog`
cli_res4=`grep "\[bytestream\]|bytes_sent:0|bytes_rcvd:0|recv_fin:1|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:no|" stdlog | wc -l`
cli_res6=`grep "early_data_flag:0" stdlog`

errlog=`grep_err_log`
if [ "$cli_res1" == "1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ "$cli_res5" == "1" ] && [ -n "$cli_res6" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_1RTT_send_pure_fin1" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_1RTT_send_pure_fin1" "fail"
fi

clear_log
echo -e "h3_ext_1RTT_send_pure_fin2...\c"
${CLIENT_BIN} -l e -T 2 -s 102400 -U 1 -Q 65535 -E -x 303 -1 > stdlog
cli_res1=`grep ">>>>>>>> pass:1" stdlog | wc -l`
cli_res2=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res3=`grep "\[h3-dgram\]|recv_dgram_bytes:102400|sent_dgram_bytes:102400|lost_dgram_bytes:0|lost_cnt:0|" stdlog`
cli_res4=`grep "\[bytestream\]|bytes_sent:0|bytes_rcvd:0|recv_fin:1|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:no|" stdlog | wc -l`
cli_res6=`grep "early_data_flag:0" stdlog`

errlog=`grep_err_log`
if [ "$cli_res1" == "1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ "$cli_res5" == "1" ] && [ -n "$cli_res6" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_1RTT_send_pure_fin2" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_1RTT_send_pure_fin2" "fail"
fi

## 0RTT

clear_log
echo -e "h3_ext_0RTT_accept_send_pure_fin1...\c"
${CLIENT_BIN} -l e -T 2 -s 102400 -U 1 -Q 65535 -E -x 302 > stdlog
cli_res1=`grep ">>>>>>>> pass:1" stdlog | wc -l`
cli_res2=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res3=`grep "\[h3-dgram\]|recv_dgram_bytes:102400|sent_dgram_bytes:102400|lost_dgram_bytes:0|lost_cnt:0|" stdlog`
cli_res4=`grep "\[bytestream\]|bytes_sent:0|bytes_rcvd:0|recv_fin:1|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:no|" stdlog | wc -l`
cli_res6=`grep "early_data_flag:1" stdlog`

errlog=`grep_err_log`
if [ "$cli_res1" == "1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ "$cli_res5" == "1" ] && [ -n "$cli_res6" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_0RTT_accept_send_pure_fin1" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_0RTT_accept_send_pure_fin1" "fail"
fi

clear_log
echo -e "h3_ext_0RTT_accept_send_pure_fin2...\c"
${CLIENT_BIN} -l e -T 2 -s 102400 -U 1 -Q 65535 -E -x 303 > stdlog
cli_res1=`grep ">>>>>>>> pass:1" stdlog | wc -l`
cli_res2=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res3=`grep "\[h3-dgram\]|recv_dgram_bytes:102400|sent_dgram_bytes:102400|lost_dgram_bytes:0|lost_cnt:0|" stdlog`
cli_res4=`grep "\[bytestream\]|bytes_sent:0|bytes_rcvd:0|recv_fin:1|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:no|" stdlog | wc -l`
cli_res6=`grep "early_data_flag:1" stdlog`

errlog=`grep_err_log`
if [ "$cli_res1" == "1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ "$cli_res5" == "1" ] && [ -n "$cli_res6" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_0RTT_accept_send_pure_fin2" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_0RTT_accept_send_pure_fin2" "fail"
fi

## 0RTT reject

killall test_server

${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null &
sleep 1

clear_log
echo -e "h3_ext_0RTT_reject_send_pure_fin1...\c"
${CLIENT_BIN} -l e -T 2 -s 102400 -U 1 -Q 65535 -E -x 302 > stdlog
cli_res1=`grep ">>>>>>>> pass:1" stdlog | wc -l`
cli_res2=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res3=`grep "\[h3-dgram\]|recv_dgram_bytes:102400|sent_dgram_bytes:102400|lost_dgram_bytes:0|lost_cnt:0|" stdlog`
cli_res4=`grep "\[bytestream\]|bytes_sent:0|bytes_rcvd:0|recv_fin:1|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:no|" stdlog | wc -l`
cli_res6=`grep "early_data_flag:2" stdlog`

errlog=`grep_err_log`
if [ "$cli_res1" == "1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ "$cli_res5" == "1" ] && [ -n "$cli_res6" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_0RTT_reject_send_pure_fin1" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_0RTT_reject_send_pure_fin1" "fail"
fi

killall test_server

${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null &
sleep 1

clear_log
echo -e "h3_ext_0RTT_reject_send_pure_fin2...\c"
${CLIENT_BIN} -l e -T 2 -s 102400 -U 1 -Q 65535 -E -x 303 > stdlog
cli_res1=`grep ">>>>>>>> pass:1" stdlog | wc -l`
cli_res2=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_res3=`grep "\[h3-dgram\]|recv_dgram_bytes:102400|sent_dgram_bytes:102400|lost_dgram_bytes:0|lost_cnt:0|" stdlog`
cli_res4=`grep "\[bytestream\]|bytes_sent:0|bytes_rcvd:0|recv_fin:1|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:no|" stdlog | wc -l`
cli_res6=`grep "early_data_flag:2" stdlog`

errlog=`grep_err_log`
if [ "$cli_res1" == "1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ "$cli_res5" == "1" ] && [ -n "$cli_res6" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_0RTT_reject_send_pure_fin2" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_0RTT_reject_send_pure_fin2" "fail"
fi

# finish bytestream during transmission (-x 304)

clear_log
echo -e "h3_ext_finish_bytestream_during_transmission...\c"
${CLIENT_BIN} -l d -T 2 -s 102400 -U 1 -Q 65535 -E -x 304 > stdlog
cli_res1=`grep ">>>>>>>> pass:1" stdlog | wc -l`
cli_res4=(`grep "\[bytestream\]|bytes_sent:" stdlog | egrep -o ':[0-9]+' | egrep -o '[0-9]+'`)
cli_res5=`grep "\[bytestream\]|same_content:yes|" stdlog | wc -l`
cli_res6=`grep "send pure fin" clog`
errlog=`grep_err_log | grep -v "send data after fin sent"`
if [ "$cli_res1" == "1" ] \
    && [ ${cli_res4[0]} -eq 102400 ] && [ ${cli_res4[1]} -eq 102400 ] \
    && [ "$cli_res5" == "1" ] && [ -n "$cli_res6" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_finish_bytestream_during_transmission" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_finish_bytestream_during_transmission" "fail"
fi

# close bytestream during transmission (-x 305)

clear_log
echo -e "h3_ext_close_bytestream_during_transmission...\c"
${CLIENT_BIN} -l d -T 2 -s 102400 -U 1 -Q 65535 -E -x 305 > stdlog
cli_res1=`grep ">>>>>>>> pass:1" stdlog | wc -l`
cli_res4=(`grep "\[bytestream\]|bytes_sent:" stdlog | egrep -o ':[0-9]+' | egrep -o '[0-9]+'`)
cli_res5=`grep "\[bytestream\]|same_content:.*|" stdlog | wc -l`
cli_res6=`grep "xqc_h3_ext_bytestream_close|success" clog`
errlog=`grep_err_log | grep -v "xqc_h3_stream_process_data|xqc_stream_recv"`
if [ "$cli_res1" == "1" ] && [ ${cli_res4[0]} -ge 102400 ] \
    && [ "$cli_res5" == "1" ] && [ -n "$cli_res6" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_close_bytestream_during_transmission" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_close_bytestream_during_transmission" "fail"
fi

# bytestream write blocked by streamlevel flowctl (-x 306)

clear_log
echo -e "h3_ext_bytestream_blocked_by_stream_flowctl...\c"
${CLIENT_BIN} -l d -T 2 -s 32000000 -U 1 -Q 65535 -E -x 306 > stdlog
cli_res2=`grep "|xqc_stream_send|exceed max_stream_data" clog`
cli_res3=`grep "|h3_ext_bytestream_write_notify|success|" clog`
cli_res4=`grep "\[bytestream\]|bytes_sent:32000000|bytes_rcvd:32000000|recv_fin:1|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:yes|" stdlog | wc -l`
errlog=`grep_err_log`
if [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ "$cli_res5" == "1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_bytestream_blocked_by_stream_flowctl" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_bytestream_blocked_by_stream_flowctl" "fail"
fi

# bytestream write blocked by 0RTT limit (-x 307)

clear_log
echo -e "h3_ext_bytestream_blocked_by_0RTT_limit...\c"
${CLIENT_BIN} -l d -T 2 -s 10000000 -U 1 -Q 65535 -E -x 307 > stdlog
cli_res2=`grep "|too many 0rtt packets|" clog`
cli_res3=`grep "|h3_ext_bytestream_write_notify|success|" clog`
cli_res4=`grep "\[bytestream\]|bytes_sent:10000000|bytes_rcvd:10000000|recv_fin:1|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:yes|" stdlog | wc -l`
errlog=`grep_err_log`
if [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ "$cli_res5" == "1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_bytestream_blocked_by_0RTT_limit" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_bytestream_blocked_by_0RTT_limit" "fail"
fi

# bytestream 0RTT write blocked by no 0RTT support (-x 308)

clear_log
echo -e "h3_ext_bytestream_blocked_by_no_0RTT_support...\c"
${CLIENT_BIN} -l d -T 2 -s 1024 -U 1 -Q 65535 -E -x 308 -1 > stdlog
cli_res2=`grep "|blocked by no 0RTT support|" clog`
cli_res3=`grep "|h3_ext_bytestream_write_notify|success|" clog`
cli_res4=`grep "\[bytestream\]|bytes_sent:1024|bytes_rcvd:1024|recv_fin:1|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:yes|" stdlog | wc -l`
errlog=`grep_err_log`
if [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ "$cli_res5" == "1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_bytestream_blocked_by_no_0RTT_support" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_bytestream_blocked_by_no_0RTT_support" "fail"
fi

# bytestream/h3_request/datagram all blocked by sndq size (-x 309)

clear_log
echo -e "h3_ext_bytestream_blocked_by_sndq_full...\c"
${CLIENT_BIN} -l e -T 2 -s 16000000 -U 1 -Q 65535 -E -x 309 > stdlog
cli_res1=`grep ">>>>>>>> pass:1" stdlog | wc -l`
cli_res2=`grep "\[dgram\]|echo_check|same_content:.*|" stdlog`
cli_res4=`grep "\[bytestream\]|bytes_sent:16000000|bytes_rcvd:16000000|recv_fin:1|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:yes|" stdlog | wc -l`
errlog=`grep_err_log`

if [ "$cli_res1" == "1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res4" ] && [ "$cli_res5" == "1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_bytestream_blocked_by_sndq_full" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_bytestream_blocked_by_sndq_full" "fail"
fi

# read / write full messages even if blocking happens

clear_log
echo -e "h3_ext_bytestream_full_message_flow_ctrl...\c"
${CLIENT_BIN} -l d -T 2 -s 32000000 -U 1 -Q 65535 -E -x 311 > stdlog
cli_res2=`grep "|xqc_stream_send|exceed max_stream_data" clog`
cli_res3=`grep "|h3_ext_bytestream_write_notify|success|" clog`
cli_res4=`grep "\[bytestream\]|bytes_sent:32001000|bytes_rcvd:32001000|recv_fin:1|snd_times:2|rcv_times:2|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:yes|" stdlog | wc -l`
errlog=`grep_err_log`
if [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ "$cli_res5" == "1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_bytestream_full_message_under_flow_ctrl" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_bytestream_full_message_under_flow_ctrl" "fail"
fi

clear_log
echo -e "h3_ext_bytestream_full_message_0RTT_blocking...\c"
${CLIENT_BIN} -l d -T 2 -s 10000000 -U 1 -Q 65535 -E -x 312 > stdlog
cli_res2=`grep "|too many 0rtt packets|" clog`
cli_res3=`grep "|h3_ext_bytestream_write_notify|success|" clog`
cli_res4=`grep "\[bytestream\]|bytes_sent:10001000|bytes_rcvd:10001000|recv_fin:1|snd_times:2|rcv_times:2|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:yes|" stdlog | wc -l`
errlog=`grep_err_log`
if [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ "$cli_res5" == "1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_bytestream_full_message_0RTT_blocking" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_bytestream_full_message_0RTT_blocking" "fail"
fi

clear_log
echo -e "h3_ext_bytestream_full_message_no_0RTT_suppport...\c"
${CLIENT_BIN} -l d -T 2 -s 1024 -U 1 -Q 65535 -E -x 313 -1 > stdlog
cli_res2=`grep "|blocked by no 0RTT support|" clog`
cli_res3=`grep "|h3_ext_bytestream_write_notify|success|" clog`
cli_res4=`grep "\[bytestream\]|bytes_sent:2024|bytes_rcvd:2024|recv_fin:1|snd_times:2|rcv_times:2|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:yes|" stdlog | wc -l`
errlog=`grep_err_log`
if [ -n "$cli_res2" ] && [ -n "$cli_res3" ] && [ -n "$cli_res4" ] && [ "$cli_res5" == "1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_bytestream_full_message_no_0RTT_suppport" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_bytestream_full_message_no_0RTT_suppport" "fail"
fi

clear_log
echo -e "h3_ext_bytestream_full_message_sndq_full...\c"
${CLIENT_BIN} -l e -T 2 -s 16000000 -U 1 -Q 65535 -E -x 314 > stdlog
cli_res1=`grep ">>>>>>>> pass:1" stdlog | wc -l`
cli_res2=`grep "\[dgram\]|echo_check|same_content:.*|" stdlog`
cli_res4=`grep "\[bytestream\]|bytes_sent:16001000|bytes_rcvd:16001000|recv_fin:1|snd_times:2|rcv_times:2|" stdlog`
cli_res5=`grep "\[bytestream\]|same_content:yes|" stdlog | wc -l`
errlog=`grep_err_log`

if [ "$cli_res1" == "1" ] && [ -n "$cli_res2" ] && [ -n "$cli_res4" ] && [ "$cli_res5" == "1" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_bytestream_full_message_sndq_full" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_bytestream_full_message_sndq_full" "fail"
fi

killall test_server

${SERVER_BIN} -l e -Q 65535 -e -U 1 -H > /dev/null &
sleep 1

clear_log
echo -e "connect to an h3_ext disabled server...\c"
${CLIENT_BIN} -l e -T 2 -s 1024 -U 1 -Q 65535 -E > stdlog
svr_log=`grep "select proto error" slog`

if [ -n "$svr_log" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "connect_to_an_h3_ext_disabled_server" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "connect_to_an_h3_ext_disabled_server" "fail"
fi

killall test_server

${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null &
sleep 1

clear_log
echo -e "h3_ext is disabled on the client...\c"
${CLIENT_BIN} -l e -T 2 -s 1024 -U 1 -Q 65535 -E -x 315 > stdlog
cli_res1=`grep "can't get application layer callback" clog`

if [ -n "$cli_res1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_ext_is_disabled_on_the_client" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_ext_is_disabled_on_the_client" "fail"
fi

rm -rf tp_localhost test_session xqc_token
killall test_server


${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null &
sleep 1
${CLIENT_BIN} -l d -T 1 -s 4800 -U 1 -Q 65535 -E &> /dev/null #generate 0rtt ticket
killall test_server
${SERVER_BIN} -l d -e -s 1 > /dev/null & #disable datagram
sleep 1
clear_log
echo -e "check_clear_0rtt_ticket_flag_in_close_notify...\c"
${CLIENT_BIN} -l d -T 1 -s 4800 -U 1 -Q 65535 -E > stdlog
cli_res2=`grep "should_clear_0rtt_ticket, conn_err:14, clear_0rtt_ticket:1" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res2" ] && [ -n "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "check_clear_0rtt_ticket_flag_in_close_notify" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "check_clear_0rtt_ticket_flag_in_close_notify" "fail"
fi

rm -rf tp_localhost test_session xqc_token
killall test_server

${SERVER_BIN} -l d -Q 65535 -e -s 1 > /dev/null &
sleep 1
${CLIENT_BIN} -l d -s 4800 -Q 65535 -E &> /dev/null #generate 0rtt ticket
killall test_server
${SERVER_BIN} -l d -e -s 1 > /dev/null & #disable datagram
sleep 1
clear_log
echo -e "check_clear_0rtt_ticket_flag_in_h3_close_notify...\c"
${CLIENT_BIN} -l d -s 4800 -Q 65535 -E > stdlog
cli_res2=`grep "should_clear_0rtt_ticket, conn_err:14, clear_0rtt_ticket:1" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res2" ] && [ -n "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "check_clear_0rtt_ticket_flag_in_h3_close_notify" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "check_clear_0rtt_ticket_flag_in_h3_close_notify" "fail"
fi

rm -rf tp_localhost test_session xqc_token
killall test_server

${SERVER_BIN} -l d -Q 65535 -e -s 1 > /dev/null &
sleep 1
${CLIENT_BIN} -l d -s 4800 -Q 65535 -E &> /dev/null #generate 0rtt ticket
killall test_server
${SERVER_BIN} -l d -e -s 1 > /dev/null & #disable datagram
sleep 1
clear_log
echo -e "check_clear_0rtt_ticket_flag_in_h3_close_notify...\c"
${CLIENT_BIN} -l d -s 4800 -Q 65535 -E > stdlog
cli_res2=`grep "should_clear_0rtt_ticket, conn_err:14, clear_0rtt_ticket:1" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res2" ] && [ -n "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "check_clear_0rtt_ticket_flag_in_h3_close_notify" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "check_clear_0rtt_ticket_flag_in_h3_close_notify" "fail"
fi

rm -rf tp_localhost test_session xqc_token
killall test_server

clear_log
echo -e "request_closing_notify...\c"
${SERVER_BIN} -l d -x 14 > /dev/null &
sleep 1
${CLIENT_BIN} -l d >> stdlog
res=`grep "request closing notify triggered" stdlog`
if [ -n "$res" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "request_closing_notify" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "request_closing_notify" "fail"
fi


killall test_server
${SERVER_BIN} -l d -e -M -R 3 -Q 65535 -U 1 > /dev/null &
sleep 1

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "SP reinject datagrams ...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -R 3 -Q 65535 -U 1 -T 1 > stdlog
result=`grep "\[dgram\]|recv_dgram_bytes:4096|sent_dgram_bytes:1024|" stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:0" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "SP_reinject_datagrams" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "SP_reinject_datagrams" "fail"
fi
grep_err_log

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "SP reinject h3-ext datagrams ...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -R 3 -Q 65535 -U 1 -T 2 > stdlog
result=`grep "\[h3-dgram\]|recv_dgram_bytes:4096|sent_dgram_bytes:1024|" stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:0" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "SP_reinject_h3_ext_datagrams" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "SP_reinject_h3_ext_datagrams" "fail"
fi
grep_err_log


rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "MP reinject datagrams ...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -R 3 -Q 65535 -U 1 -T 1 -M -i lo -i lo > stdlog
result=`grep "\[dgram\]|recv_dgram_bytes:4096|sent_dgram_bytes:1024|" stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:1" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "MP_reinject_datagrams" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MP_reinject_datagrams" "fail"
fi
grep_err_log

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "MP reinject h3-ext datagrams ...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -R 3 -Q 65535 -U 1 -T 2 -M -i lo -i lo > stdlog
result=`grep "\[h3-dgram\]|recv_dgram_bytes:4096|sent_dgram_bytes:1024|" stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:1" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "MP_reinject_h3_ext_datagrams" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MP_reinject_h3_ext_datagrams" "fail"
fi
grep_err_log


killall test_server
${SERVER_BIN} -l d -e -M -x 208 -Q 65535 -U 1 > /dev/null &
sleep 1


rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "MP datagrams redundancy...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 208 -Q 65535 -U 1 -T 1 -M -i lo -i lo > stdlog
result=`grep "\[dgram\]|recv_dgram_bytes:4096|sent_dgram_bytes:1024|" stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:1" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "MP_datagrams_redundancy" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MP_datagrams_redundancy" "fail"
fi
grep_err_log

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "MP h3-ext datagrams redundancy...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 208 -Q 65535 -U 1 -T 2 -M -i lo -i lo > stdlog
result=`grep "\[h3-dgram\]|recv_dgram_bytes:4096|sent_dgram_bytes:1024|" stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:1" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "MP_h3_ext_datagrams_redundancy" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MP_h3_ext_datagrams_redundancy" "fail"
fi
grep_err_log


killall test_server
${SERVER_BIN} -l d -e -M -x 208 -Q 65535 -U 1 --dgram_qos 3 > /dev/null &
sleep 1


rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "MP no reinjection for normal datagrams...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 208 -Q 65535 -U 1 -T 1 -M -i lo -i lo --dgram_qos 3 > stdlog
result=`grep "\[dgram\]|recv_dgram_bytes:1024|sent_dgram_bytes:1024|" stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:1" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "MP_no_reinjection_for_normal_datagrams" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MP_no_reinjection_for_normal_datagrams" "fail"
fi
grep_err_log

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "MP no reinjection for normal h3-ext datagrams...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 208 -Q 65535 -U 1 -T 2 -M -i lo -i lo --dgram_qos 3 > stdlog
result=`grep "\[h3-dgram\]|recv_dgram_bytes:1024|sent_dgram_bytes:1024|" stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:1" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "MP_no_reinjection_for_normal_h3_ext_datagrams" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MP_no_reinjection_for_normal_h3_ext_datagrams" "fail"
fi
grep_err_log


killall test_server
stdbuf -oL ${SERVER_BIN} -l d -e -M -Q 65535 -U 1 --pmtud 1 -x 200 > svr_stdlog &
sleep 1

rm -rf tp_localhost test_session xqc_token
> svr_stdlog
clear_log
echo -e "SP datagram PMTUD 1RTT...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -Q 65535 -U 1 -T 1 --pmtud 1 > stdlog
result=`grep "\[dgram\]|recv_dgram_bytes:1024|sent_dgram_bytes:1024|" stdlog`
mtu_res1=`grep "\[dgram\]|mss_callback|updated_mss:1404|" stdlog`
mtu_res2=`grep -a "\[dgram\]|1RTT|updated_mss:1404|" svr_stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:0" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] && [ -n "$mtu_res1" ] && [ -n "$mtu_res2" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "SP_datagram_PMTUD_1RTT" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "SP_datagram_PMTUD_1RTT" "fail"
fi
grep_err_log

> svr_stdlog
clear_log
echo -e "SP datagram PMTUD 0RTT...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -Q 65535 -U 1 -T 1 --pmtud 1 > stdlog
result=`grep "\[dgram\]|recv_dgram_bytes:1024|sent_dgram_bytes:1024|" stdlog`
mtu_res1=`grep "\[dgram\]|mss_callback|updated_mss:1404|" stdlog`
mtu_res2=`grep -a "\[dgram\]|1RTT|updated_mss:1404|" svr_stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:0" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] && [ -n "$mtu_res1" ] && [ -n "$mtu_res2" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "SP_datagram_PMTUD_0RTT" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "SP_datagram_PMTUD_0RTT" "fail"
fi
grep_err_log

rm -rf tp_localhost test_session xqc_token
> svr_stdlog
clear_log
echo -e "SP h3-ext datagram PMTUD 1RTT...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -Q 65535 -U 1 -T 2 --pmtud 1 > stdlog
result=`grep "\[h3-dgram\]|recv_dgram_bytes:1024|sent_dgram_bytes:1024|" stdlog`
mtu_res1=`grep "\[h3-dgram\]|callback|updated_mss:1404|" stdlog`
mtu_res2=`grep -a "\[h3-dgram\]|1RTT|updated_mss:1404|" svr_stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:0" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] && [ -n "$mtu_res1" ] && [ -n "$mtu_res2" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "SP_h3_ext_datagram_PMTUD_1RTT" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "SP_h3_ext_datagram_PMTUD_1RTT" "fail"
fi
grep_err_log

> svr_stdlog
clear_log
echo -e "SP h3-ext datagram PMTUD 0RTT...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -Q 65535 -U 1 -T 2 --pmtud 1 > stdlog
result=`grep "\[h3-dgram\]|recv_dgram_bytes:1024|sent_dgram_bytes:1024|" stdlog`
mtu_res1=`grep "\[h3-dgram\]|callback|updated_mss:1404|" stdlog`
mtu_res2=`grep -a "\[h3-dgram\]|1RTT|updated_mss:1404|" svr_stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:0" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] && [ -n "$mtu_res1" ] && [ -n "$mtu_res2" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "SP_h3_ext_datagram_PMTUD_0RTT" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "SP_h3_ext_datagram_PMTUD_0RTT" "fail"
fi
grep_err_log


rm -rf tp_localhost test_session xqc_token
> svr_stdlog
clear_log
echo -e "MP datagram PMTUD 1RTT...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -Q 65535 -U 1 -T 1 --pmtud 1 -M -i lo -i lo > stdlog
result=`grep "\[dgram\]|recv_dgram_bytes:1024|sent_dgram_bytes:1024|" stdlog`
mtu_res1=`grep "\[dgram\]|mss_callback|updated_mss:1404|" stdlog`
mtu_res2=`grep -a "\[dgram\]|1RTT|updated_mss:1404|" svr_stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:1" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] && [ -n "$mtu_res1" ] && [ -n "$mtu_res2" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "MP_datagram_PMTUD_1RTT" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MP_datagram_PMTUD_1RTT" "fail"
fi
grep_err_log

> svr_stdlog
clear_log
echo -e "MP datagram PMTUD 0RTT...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -Q 65535 -U 1 -T 1 --pmtud 1 -M -i lo -i lo > stdlog
result=`grep "\[dgram\]|recv_dgram_bytes:1024|sent_dgram_bytes:1024|" stdlog`
mtu_res1=`grep "\[dgram\]|mss_callback|updated_mss:1404|" stdlog`
mtu_res2=`grep -a "\[dgram\]|1RTT|updated_mss:1404|" svr_stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:1" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] && [ -n "$mtu_res1" ] && [ -n "$mtu_res2" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "MP_datagram_PMTUD_0RTT" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MP_datagram_PMTUD_0RTT" "fail"
fi
grep_err_log

rm -rf tp_localhost test_session xqc_token
> svr_stdlog
clear_log
echo -e "MP h3-ext datagram PMTUD 1RTT...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -Q 65535 -U 1 -T 2 --pmtud 1 -M -i lo -i lo > stdlog
result=`grep "\[h3-dgram\]|recv_dgram_bytes:1024|sent_dgram_bytes:1024|" stdlog`
mtu_res1=`grep "\[h3-dgram\]|callback|updated_mss:1404|" stdlog`
mtu_res2=`grep -a "\[h3-dgram\]|1RTT|updated_mss:1404|" svr_stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:1" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] && [ -n "$mtu_res1" ] && [ -n "$mtu_res2" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "MP_h3_ext_datagram_PMTUD_1RTT" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MP_h3_ext_datagram_PMTUD_1RTT" "fail"
fi
grep_err_log

> svr_stdlog
clear_log
echo -e "MP h3-ext datagram PMTUD 0RTT...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -Q 65535 -U 1 -T 2 --pmtud 1 -M -i lo -i lo > stdlog
result=`grep "\[h3-dgram\]|recv_dgram_bytes:1024|sent_dgram_bytes:1024|" stdlog`
mtu_res1=`grep "\[h3-dgram\]|callback|updated_mss:1404|" stdlog`
mtu_res2=`grep -a "\[h3-dgram\]|1RTT|updated_mss:1404|" svr_stdlog`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:1" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$cli_res" ] && [ -n "$mtu_res1" ] && [ -n "$mtu_res2" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "MP_h3_ext_datagram_PMTUD_0RTT" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MP_h3_ext_datagram_PMTUD_0RTT" "fail"
fi
grep_err_log


killall test_server
stdbuf -oL ${SERVER_BIN} -l d -e -M > /dev/null &
sleep 1

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "transport MP ping ...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -E -T 1 -e 1 --epoch_timeout 2000000 -t 3 --mp_ping 1 -M -i lo -i lo >> clog
ret_ping_id=`grep "====>ping_id:" clog`
ret_no_ping_id=`grep "====>no ping_id" clog`
path0_ping=`grep -E "xqc_send_packet_with_pn.*path:0.*PING" clog`
path1_ping=`grep -E "xqc_send_packet_with_pn.*path:1.*PING" clog`
if [ -n "$ret_ping_id" ] && [ -n "$ret_no_ping_id" ] && [ -n "$path0_ping" ] && [ -n "$path1_ping" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "transport_MP_ping" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "transport_MP_ping" "fail"
fi


rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "h3 MP ping ...\c"
sudo ${CLIENT_BIN} -s 1024 -l d -E -e 1 --epoch_timeout 2000000 -t 3 --mp_ping 1 -M -i lo -i lo >> clog
ret_ping_id=`grep "====>ping_id:" clog`
ret_no_ping_id=`grep "====>no ping_id" clog`
path0_ping=`grep -E "xqc_send_packet_with_pn.*path:0.*PING" clog`
path1_ping=`grep -E "xqc_send_packet_with_pn.*path:1.*PING" clog`
if [ -n "$ret_ping_id" ] && [ -n "$ret_no_ping_id" ] && [ -n "$path0_ping" ] && [ -n "$path1_ping" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_MP_ping" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_MP_ping" "fail"
fi


rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "freeze path0 ...\c"
sudo ${CLIENT_BIN} -s 1024000 -l d -E -e 4 -T 2 --epoch_timeout 2000000 -t 4 -M -i lo -i lo -x 107 > stdlog
clog_res1=`grep -E "path:0.*app_path_status:2->3" clog`
clog_res2=`grep -E "path:0.*app_path_status:3->1" clog`
slog_res1=`grep -E "path:0.*app_path_status:2->3" slog`
slog_res2=`grep -E "path:0.*app_path_status:3->1" slog`
if [ -n "$clog_res1" ] && [ -n "$clog_res2" ] && [ -n "$slog_res1" ] && [ -n "$slog_res2" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "freeze_path0" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "freeze_path0" "fail"
fi

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "freeze path1 ...\c"
sudo ${CLIENT_BIN} -s 1024000 -l d -E -e 4 -T 2 --epoch_timeout 2000000 -t 4 -M -i lo -i lo -x 108 > stdlog
clog_res1=`grep -E "path:1.*app_path_status:2->3" clog`
clog_res2=`grep -E "path:1.*app_path_status:3->1" clog`
slog_res1=`grep -E "path:1.*app_path_status:2->3" slog`
slog_res2=`grep -E "path:1.*app_path_status:3->1" slog`
if [ -n "$clog_res1" ] && [ -n "$clog_res2" ] && [ -n "$slog_res1" ] && [ -n "$slog_res2" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "freeze_path1" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "freeze_path1" "fail"
fi

killall test_server
stdbuf -oL ${SERVER_BIN} -l d -e -M > /dev/null &
sleep 1

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "probing standby paths ...\c"
sudo ${CLIENT_BIN} -s 1024000 -l d -E -e 1 --epoch_timeout 2000000 -t 4 -M -i lo -i lo -x 501 -y > stdlog
clog_res1=`grep -E "|xqc_path_standby_probe|PING|path:1|" clog`
if [ -n "$clog_res1" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "probing_standby_path" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "probing_standby_path" "fail"
fi


sudo rm -rf tp_localhost test_session xqc_token clog stdlog ckeys.log
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


sudo rm -rf tp_localhost test_session xqc_token clog slog stdlog ckeys.log
killall test_server
${SERVER_BIN} -l d -e -x 150 > /dev/null &
sleep 1

clear_log
echo -e "h3_engine_set_settings_api_h3 ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 150 >> stdlog
sleep 1
cli_pass=`grep ">>>>>>>> pass:1" stdlog`
cli_log1=`grep -e "xqc_h3_conn_send_settings.*qpack_blocked_streams:32|qpack_max_table_capacity:4096|max_field_section_size:512" clog`
cli_log2=`grep -e "qpack_enc_compat_dup:1" clog`
cli_log3=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:7.*value:32" clog`
cli_log4=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:1.*value:4096" clog`
cli_log5=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:6.*value:512" clog`
svr_log1=`grep -e "xqc_h3_conn_send_settings.*qpack_blocked_streams:32|qpack_max_table_capacity:4096|max_field_section_size:512" slog`
svr_log2=`grep -e "qpack_enc_compat_dup:1" slog`
svr_log3=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:7.*value:32" slog`
svr_log4=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:1.*value:4096" slog`
svr_log5=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:6.*value:512" slog`
err_log=`grep_err_log`

if [ -n "$cli_pass" ] && [ -n "$cli_log1" ] && [ -n "$cli_log2" ] && [ -n "$cli_log3" ] && [ -n "$cli_log4" ] && [ -n "$cli_log5" ] && \
   [ -z "$err_log" ] && [ -n "$svr_log1" ] && [ -n "$svr_log2" ] && [ -n "$svr_log3" ] && [ -n "$svr_log4" ] && [ -n "$svr_log5" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_engine_set_settings_api_h3" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_engine_set_settings_api_h3" "fail"
fi

sudo rm -rf tp_localhost test_session xqc_token clog slog stdlog ckeys.log
killall test_server
${SERVER_BIN} -l d -e -x 151 > /dev/null &
sleep 1

clear_log
echo -e "h3_engine_set_settings_api_h3_more ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 151 >> stdlog
sleep 1
cli_pass=`grep ">>>>>>>> pass:1" stdlog`
cli_log1=`grep -e "xqc_h3_conn_send_settings.*qpack_blocked_streams:32|qpack_max_table_capacity:4096|max_field_section_size:512" clog`
cli_log2=`grep -e "qpack_enc_compat_dup:1" clog`
cli_log3=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:7.*value:32" clog`
cli_log4=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:1.*value:4096" clog`
cli_log5=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:6.*value:512" clog`
svr_log1=`grep -e "xqc_h3_conn_send_settings.*qpack_blocked_streams:32|qpack_max_table_capacity:4096|max_field_section_size:512" slog`
svr_log2=`grep -e "qpack_enc_compat_dup:1" slog`
svr_log3=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:7.*value:32" slog`
svr_log4=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:1.*value:4096" slog`
svr_log5=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:6.*value:512" slog`
err_log=`grep_err_log`

if [ -n "$cli_pass" ] && [ -n "$cli_log1" ] && [ -n "$cli_log2" ] && [ -n "$cli_log3" ] && [ -n "$cli_log4" ] && [ -n "$cli_log5" ] && \
   [ -z "$err_log" ] && [ -n "$svr_log1" ] && [ -n "$svr_log2" ] && [ -n "$svr_log3" ] && [ -n "$svr_log4" ] && [ -n "$svr_log5" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_engine_set_settings_api_h3_more" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_engine_set_settings_api_h3_more" "fail"
fi

sudo rm -rf tp_localhost test_session xqc_token clog slog stdlog ckeys.log
killall test_server
${SERVER_BIN} -l d -e -x 152 > /dev/null &
sleep 1

clear_log
echo -e "h3_engine_set_settings_api_h3_29 ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 152 >> stdlog
sleep 1
cli_pass=`grep ">>>>>>>> pass:1" stdlog`
cli_log1=`grep -e "xqc_h3_conn_send_settings.*qpack_blocked_streams:32|qpack_max_table_capacity:4096|max_field_section_size:512" clog`
cli_log2=`grep -e "qpack_enc_compat_dup:1" clog`
cli_log3=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:7.*value:32" clog`
cli_log4=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:1.*value:4096" clog`
cli_log5=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:6.*value:512" clog`
svr_log1=`grep -e "xqc_h3_conn_send_settings.*qpack_blocked_streams:32|qpack_max_table_capacity:4096|max_field_section_size:512" slog`
svr_log2=`grep -e "qpack_enc_compat_dup:1" slog`
svr_log3=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:7.*value:32" slog`
svr_log4=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:1.*value:4096" slog`
svr_log5=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:6.*value:512" slog`
err_log=`grep_err_log`

if [ -n "$cli_pass" ] && [ -n "$cli_log1" ] && [ -n "$cli_log2" ] && [ -n "$cli_log3" ] && [ -n "$cli_log4" ] && [ -n "$cli_log5" ] && \
   [ -z "$err_log" ] && [ -n "$svr_log1" ] && [ -n "$svr_log2" ] && [ -n "$svr_log3" ] && [ -n "$svr_log4" ] && [ -n "$svr_log5" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_engine_set_settings_api_h3_29" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_engine_set_settings_api_h3_29" "fail"
fi

sudo rm -rf tp_localhost test_session xqc_token clog slog stdlog ckeys.log
killall test_server
${SERVER_BIN} -l d -e -x 153 > /dev/null &
sleep 1

clear_log
echo -e "h3_engine_set_settings_api_h3_29_more ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 153 >> stdlog
sleep 1
cli_pass=`grep ">>>>>>>> pass:1" stdlog`
cli_log1=`grep -e "xqc_h3_conn_send_settings.*qpack_blocked_streams:32|qpack_max_table_capacity:4096|max_field_section_size:512" clog`
cli_log2=`grep -e "qpack_enc_compat_dup:1" clog`
cli_log3=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:7.*value:32" clog`
cli_log4=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:1.*value:4096" clog`
cli_log5=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:6.*value:512" clog`
svr_log1=`grep -e "xqc_h3_conn_send_settings.*qpack_blocked_streams:32|qpack_max_table_capacity:4096|max_field_section_size:512" slog`
svr_log2=`grep -e "qpack_enc_compat_dup:1" slog`
svr_log3=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:7.*value:32" slog`
svr_log4=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:1.*value:4096" slog`
svr_log5=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:6.*value:512" slog`
err_log=`grep_err_log`

if [ -n "$cli_pass" ] && [ -n "$cli_log1" ] && [ -n "$cli_log2" ] && [ -n "$cli_log3" ] && [ -n "$cli_log4" ] && [ -n "$cli_log5" ] && \
   [ -z "$err_log" ] && [ -n "$svr_log1" ] && [ -n "$svr_log2" ] && [ -n "$svr_log3" ] && [ -n "$svr_log4" ] && [ -n "$svr_log5" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_engine_set_settings_api_h3_29_more" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_engine_set_settings_api_h3_29_more" "fail"
fi


sudo rm -rf tp_localhost test_session xqc_token clog slog stdlog ckeys.log
killall test_server
${SERVER_BIN} -l d -e -x 150 > /dev/null &
sleep 1

clear_log
echo -e "h3_engine_set_settings_api_h3_ext ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 150 -T 2 >> stdlog
sleep 1
cli_pass=`grep ">>>>>>>> pass:1" stdlog`
cli_log1=`grep -e "xqc_h3_conn_send_settings.*qpack_blocked_streams:32|qpack_max_table_capacity:4096|max_field_section_size:512" clog`
cli_log2=`grep -e "qpack_enc_compat_dup:1" clog`
cli_log3=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:7.*value:32" clog`
cli_log4=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:1.*value:4096" clog`
cli_log5=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:6.*value:512" clog`
svr_log1=`grep -e "xqc_h3_conn_send_settings.*qpack_blocked_streams:32|qpack_max_table_capacity:4096|max_field_section_size:512" slog`
svr_log2=`grep -e "qpack_enc_compat_dup:1" slog`
svr_log3=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:7.*value:32" slog`
svr_log4=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:1.*value:4096" slog`
svr_log5=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:6.*value:512" slog`
err_log=`grep_err_log`

if [ -n "$cli_pass" ] && [ -n "$cli_log1" ] && [ -n "$cli_log2" ] && [ -n "$cli_log3" ] && [ -n "$cli_log4" ] && [ -n "$cli_log5" ] && \
   [ -z "$err_log" ] && [ -n "$svr_log1" ] && [ -n "$svr_log2" ] && [ -n "$svr_log3" ] && [ -n "$svr_log4" ] && [ -n "$svr_log5" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_engine_set_settings_api_h3_ext" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_engine_set_settings_api_h3_ext" "fail"
fi


sudo rm -rf tp_localhost test_session xqc_token stdlog ckeys.log
killall test_server
${SERVER_BIN} -l d -e -x 151 > /dev/null &
sleep 1

clear_log
echo -e "h3_engine_set_settings_api_h3_ext_more ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 151 -T 2 >> stdlog
sleep 1
cli_pass=`grep ">>>>>>>> pass:1" stdlog`
cli_log1=`grep -e "xqc_h3_conn_send_settings.*qpack_blocked_streams:32|qpack_max_table_capacity:4096|max_field_section_size:512" clog`
cli_log2=`grep -e "qpack_enc_compat_dup:1" clog`
cli_log3=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:7.*value:32" clog`
cli_log4=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:1.*value:4096" clog`
cli_log5=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:6.*value:512" clog`
svr_log1=`grep -e "xqc_h3_conn_send_settings.*qpack_blocked_streams:32|qpack_max_table_capacity:4096|max_field_section_size:512" slog`
svr_log2=`grep -e "qpack_enc_compat_dup:1" slog`
svr_log3=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:7.*value:32" slog`
svr_log4=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:1.*value:4096" slog`
svr_log5=`grep -e "xqc_h3_conn_on_settings_entry_received.*id:6.*value:512" slog`
err_log=`grep_err_log`

if [ -n "$cli_pass" ] && [ -n "$cli_log1" ] && [ -n "$cli_log2" ] && [ -n "$cli_log3" ] && [ -n "$cli_log4" ] && [ -n "$cli_log5" ] && \
   [ -z "$err_log" ] && [ -n "$svr_log1" ] && [ -n "$svr_log2" ] && [ -n "$svr_log3" ] && [ -n "$svr_log4" ] && [ -n "$svr_log5" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_engine_set_settings_api_h3_ext_more" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_engine_set_settings_api_h3_ext_more" "fail"
fi

sudo rm -rf tp_localhost test_session xqc_token
killall test_server 2> /dev/null
${SERVER_BIN} -l d -e -f > /dev/null &
sleep 1

clear_log
echo -e "negotiate_encoder_fec_schemes ...\c"
sudo ${CLIENT_BIN} -l d -g > stdlog
clog_res1=`grep "|xqc_negotiate_fec_schemes|set final encoder fec scheme: XOR" clog`
slog_res1=`grep "|xqc_negotiate_fec_schemes|set final encoder fec scheme: XOR" slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$clog_res1" ] && [ -n "$slog_res1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "negotiate_encoder_fec_scheme" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "negotiate_encoder_fec_scheme" "fail"
fi


clear_log
echo -e "negotiate_decoder_fec_schemes ...\c"
sudo ${CLIENT_BIN} -l d -g > stdlog
clog_res2=`grep "|xqc_negotiate_fec_schemes|set final decoder fec scheme: XOR" clog`
slog_res2=`grep "|xqc_negotiate_fec_schemes|set final decoder fec scheme: XOR" slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$clog_res2" ] && [ -n "$slog_res2" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "negotiate_decoder_fec_scheme" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "negotiate_decoder_fec_scheme" "fail"
fi


clear_log
killall test_server 2> /dev/null
stdbuf -oL ${SERVER_BIN} -l d -e -f -x 1 -M > /dev/null &
sleep 1

rm -rf tp_localhost test_session xqc_token
echo -e "check fec recovery function of stream using XOR ...\c"
sudo ${CLIENT_BIN} -s 5120000 -l e -E -d 30 -g -M -i lo -i lo > stdlog
slog_res1=`grep '|process packet of block .\{1,3\} successfully' slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$slog_res1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "fec_recovered_function_of_stream_xor" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "fec_recovered_function_of_stream_xor" "fail"
fi

clear_log
killall test_server 2> /dev/null
stdbuf -oL ${SERVER_BIN} -l d -e -f -x 1 -M > /dev/null &
sleep 1

rm -rf tp_localhost test_session xqc_token
echo -e "check fec recovery function of stream using RSC ...\c"
sudo ${CLIENT_BIN} -s 5120000 -l e -E -d 30 -g -M -i lo -i lo --fec_encoder 8 --fec_decoder 8 > stdlog
slog_res1=`grep '|process packet of block .\{1,3\} successfully' slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$slog_res1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "fec_recovered_function_of_stream_rsc" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "fec_recovered_function_of_stream_rsc" "fail"
fi

clear_log
killall test_server 2> /dev/null
stdbuf -oL ${SERVER_BIN} -l d -e -f -x 1 -M > /dev/null &
sleep 1

rm -rf tp_localhost test_session xqc_token
echo -e "check fec recovery function of stream using PM ...\c"
sudo ${CLIENT_BIN} -s 5120000 -l e -E -d 30 -g -M -i lo -i lo --fec_encoder 12 --fec_decoder 12 > stdlog
slog_res1=`grep '|process packet of block .\{1,3\} successfully' slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$slog_res1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "fec_recovered_function_of_stream_pm" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "fec_recovered_function_of_stream_pm" "fail"
fi

rm -rf tp_localhost test_session xqc_token
echo -e "check fec recovery when send repair packets ahead ...\c"
sudo ${CLIENT_BIN} -s 5120000 -l d -E -d 30 -g -M -i lo -i lo --fec_encoder 12 --fec_decoder 12 --fec_timeout 20 > stdlog
clog_res=`grep '|send repair packets ahead finished' clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$clog_res" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "fec_send_repair_ahead" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "fec_send_repair_ahead" "fail"
    echo "$errlog"
    echo "$clog_res"
fi



killall test_server 2> /dev/null
${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 --dgram_qos 3 -f > /dev/null &
sleep 1

rm -rf tp_localhost test_session xqc_token

clear_log
echo -e "check fec recovery function of datagram with XOR fec scheme ...\c"
sudo ${CLIENT_BIN} -l d -T 1 -s 3000 -U 1 -Q 65535 -E -x 205 -N -1 -t 1 --dgram_qos 3 -g > stdlog
slog_res1=`grep '|process packet of block 0 successfully' slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$slog_res1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "fec_recovered_function_of_datagram_xor" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "fec_recovered_function_of_datagram_xor" "fail"
fi

clear_log
echo -e "check fec recovery function of datagram with RSC fec scheme ...\c"
sudo ${CLIENT_BIN} -l d -T 1 -s 3000 -U 1 -Q 65535 -E -x 205 -N -1 -t 1 --dgram_qos 3 -g --fec_encoder 8 --fec_decoder 8  > stdlog
slog_res1=`grep '|process packet of block 0 successfully' slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$slog_res1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "fec_recovered_function_of_datagram_rsc" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "fec_recovered_function_of_datagram_rsc" "fail"
fi

clear_log
echo -e "check fec recovery function of datagram with Packet Mask scheme ...\c"
sudo ${CLIENT_BIN} -l d -T 1 -s 3000 -U 1 -Q 65535 -E -x 205 -N -1 -t 1 --dgram_qos 3 -g --fec_encoder 12 --fec_decoder 12  > stdlog
slog_res1=`grep '|process packet of block 0 successfully' slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$slog_res1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "fec_recovered_function_of_datagram_pm" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "fec_recovered_function_of_datagram_pm" "fail"
fi

clear_log
echo -e "check fec recovery function of datagram with XOR(encoder) and RSC(decoder) fec schemes ...\c"
sudo ${CLIENT_BIN} -l d -T 1 -s 3000 -U 1 -Q 65535 -E -x 205 -N -1 -t 1 --dgram_qos 3 -g --fec_encoder 8 --fec_decoder 11 > stdlog
slog_res1=`grep '|process packet of block 0 successfully' slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$slog_res1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "fec_recovered_function_of_datagram_xor_and_rsc" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "fec_recovered_function_of_datagram_xor_and_rsc" "fail"
fi


clear_log
echo -e "check fec recovery function of datagram with XOR(decoder) and RSC(encoder) fec schemes ...\c"
sudo ${CLIENT_BIN} -l d -T 1 -s 3000 -U 1 -Q 65535 -E -x 205 -N -1 -t 1 --dgram_qos 3 -g --fec_encoder 11 --fec_decoder 8 > stdlog
slog_res1=`grep '|process packet of block 0 successfully' slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$slog_res1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "fec_recovered_function_of_datagram_rsc_and_xor" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "fec_recovered_function_of_datagram_rsc_and_xor" "fail"
fi


clear_log
rm -rf tp_localhost test_session xqc_token
echo -e "qlog disable ...\c"
killall test_server
${SERVER_BIN} -l d -e -x 1 --qlog_disable > /dev/null &
sleep 1
${CLIENT_BIN} -s 10240 -l d -t 1 -E --qlog_disable > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
svr_qlog_res1=`grep "\[packet_received\]" slog`
svr_qlog_res2=`grep "\[packet_sent\]" slog`
cli_qlog_res1=`grep "\[packet_received\]" clog`
cli_qlog_res2=`grep "\[packet_sent\]" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ] && [ -z "$svr_qlog_res1" ] && [ -z "$svr_qlog_res2" ] \
    && [ -z "$cli_qlog_res1" ] && [ -z "$cli_qlog_res2" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "qlog_disable" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "qlog_disable" "fail"
    echo "$errlog"
fi


clear_log
echo -e "qlog importance selected 1  ...\c"
killall test_server
${SERVER_BIN} -l d -e -x 1 --qlog_importance s > /dev/null &
sleep 1
${CLIENT_BIN} -s 10240 -l d -t 1 -E --qlog_importance s > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
svr_qlog_res1=`grep "\[packet_received\]" slog`
svr_qlog_res2=`grep "\[connection_started\]" slog`
cli_qlog_res1=`grep "\[packet_received\]" clog`
cli_qlog_res2=`grep "\[connection_started\]" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ] && [ -n "$svr_qlog_res1" ] && [ -n "$svr_qlog_res2" ] \
    && [ -n "$cli_qlog_res1" ] && [ -n "$cli_qlog_res2" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "qlog_importance_selected_1" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "qlog_importance_selected_1" "fail"
    echo "$errlog"
fi


clear_log
echo -e "qlog importance selected 2  ...\c"
killall test_server
${SERVER_BIN} -l i -e -x 1 --qlog_importance s > /dev/null &
sleep 1
${CLIENT_BIN} -s 10240 -l i -t 1 -E --qlog_importance s > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
svr_qlog_res1=`grep "\[packet_received\]" slog`
svr_qlog_res2=`grep "\[connection_started\]" slog`
cli_qlog_res1=`grep "\[packet_received\]" clog`
cli_qlog_res2=`grep "\[connection_started\]" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ] && [ -z "$svr_qlog_res1" ] && [ -n "$svr_qlog_res2" ] \
    && [ -z "$cli_qlog_res1" ] && [ -n "$cli_qlog_res2" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "qlog_importance_selected_2" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "qlog_importance_selected_2" "fail"
    echo "$errlog"
fi


clear_log
echo -e "qlog importance removed  ...\c"
killall test_server
${SERVER_BIN} -l d -e -x 1 --qlog_importance r > /dev/null &
sleep 1
${CLIENT_BIN} -s 10240 -l d -t 1 -E --qlog_importance r > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
svr_qlog_res1=`grep "\[packet_sent" slog`
svr_qlog_res2=`grep "\[connection_" slog`
svr_qlog_res3=`grep "\[datagram" slog`
svr_qlog_res4=`grep "\[qpack_" slog`
cli_qlog_res1=`grep "\[packet_sent" clog`
cli_qlog_res2=`grep "\[connection_" clog`
cli_qlog_res3=`grep "\[datagram" clog`
cli_qlog_res4=`grep "\[qpack_" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ] && [ -n "$svr_qlog_res1" ] && [ -n "$svr_qlog_res2" ] \
    && [ -n "$svr_qlog_res3" ] && [ -n "$svr_qlog_res4" ] && [ -n "$cli_qlog_res1" ] && [ -n "$cli_qlog_res2" ] \
    && [ -n "$cli_qlog_res3" ] && [ -n "$cli_qlog_res4" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "qlog_importance_removed" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "qlog_importance_removed" "fail"
    echo "$errlog"
fi


clear_log
echo -e "qlog importance extra  ...\c"
killall test_server
${SERVER_BIN} -l d -e -x 1 --qlog_importance e > /dev/null &
sleep 1
${CLIENT_BIN} -s 10240 -l d -t 1 -E --qlog_importance e > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
svr_qlog_res1=`grep "\[packet_sent" slog`
svr_qlog_res2=`grep "\[connection_" slog`
svr_qlog_res3=`grep "\[datagram" slog`
svr_qlog_res4=`grep "\[qpack_" slog`
cli_qlog_res1=`grep "\[packet_sent" clog`
cli_qlog_res2=`grep "\[connection_" clog`
cli_qlog_res3=`grep "\[datagram" clog`
cli_qlog_res4=`grep "\[qpack_" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ] && [ -n "$svr_qlog_res1" ] && [ -n "$svr_qlog_res2" ] \
    && [ -n "$svr_qlog_res3" ] && [ -z "$svr_qlog_res4" ] && [ -n "$cli_qlog_res1" ] && [ -n "$cli_qlog_res2" ] \
    && [ -n "$cli_qlog_res3" ] && [ -z "$cli_qlog_res4" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "qlog_importance_extra" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "qlog_importance_extra" "fail"
    echo "$errlog"
fi


clear_log
echo -e "qlog importance base  ...\c"
killall test_server
${SERVER_BIN} -l d -e -x 1 --qlog_importance b > /dev/null &
sleep 1
${CLIENT_BIN} -s 10240 -l d -t 1 -E --qlog_importance b > stdlog
svr_qlog_res1=`grep "\[packet_sent" slog`
svr_qlog_res2=`grep "\[connection_" slog`
svr_qlog_res3=`grep "\[datagram" slog`
svr_qlog_res4=`grep "\[qpack_" slog`
cli_qlog_res1=`grep "\[packet_sent" clog`
cli_qlog_res2=`grep "\[connection_" clog`
cli_qlog_res3=`grep "\[datagram" clog`
cli_qlog_res4=`grep "\[qpack_" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$svr_qlog_res1" ] && [ -n "$svr_qlog_res2" ] \
    && [ -z "$svr_qlog_res3" ] && [ -z "$svr_qlog_res4" ] && [ -n "$cli_qlog_res1" ] && [ -n "$cli_qlog_res2" ] \
    && [ -z "$cli_qlog_res3" ] && [ -z "$cli_qlog_res4" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "qlog_importance_base" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "qlog_importance_base" "fail"
    echo "$errlog"
fi


clear_log
echo -e "qlog importance core  ...\c"
killall test_server
${SERVER_BIN} -l d -e -x 1 --qlog_importance c > /dev/null &
sleep 1
${CLIENT_BIN} -s 10240 -l d -t 1 -E --qlog_importance c > /dev/null
svr_qlog_res1=`grep "\[packet_sent" slog`
svr_qlog_res2=`grep "\[connection_" slog`
svr_qlog_res3=`grep "\[datagram" slog`
svr_qlog_res4=`grep "\[qpack_" slog`
cli_qlog_res1=`grep "\[packet_sent" clog`
cli_qlog_res2=`grep "\[connection_" clog`
cli_qlog_res3=`grep "\[datagram" clog`
cli_qlog_res4=`grep "\[qpack_" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ] && [ -n "$svr_qlog_res1" ] && [ -z "$svr_qlog_res2" ] \
    && [ -z "$svr_qlog_res3" ] && [ -z "$svr_qlog_res4" ] && [ -n "$cli_qlog_res1" ] && [ -z "$cli_qlog_res2" ] \
    && [ -z "$cli_qlog_res3" ] && [ -z "$cli_qlog_res4" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "qlog_importance_core" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "qlog_importance_core" "fail"
    echo "$errlog"
fi

killall test_server
clear_log
echo -e "ack_timestamp_frame: server enable, 0 < max_ts_per_ack < 64 and client enable, 0 < max_ts_per_ack < 64 ...\c"
${SERVER_BIN} -l d -e -x 450 > /dev/null &
sleep 1
${CLIENT_BIN} -s 102400 -l d -t 1 -E -x 450 > stdlog
cli_res1=`grep "xqc_write_packet_receive_timestamps_into_buf|ts_info_len" clog | wc -l`
cli_res2=`grep "xqc_parse_timestamps_in_ack_ext|report_num:" clog | wc -l`

svr_res1=`grep "xqc_write_packet_receive_timestamps_into_buf|ts_info_len" slog | wc -l`
svr_res2=`grep "xqc_parse_timestamps_in_ack_ext|report_num:" slog | wc -l`

if [ "$cli_res1" -gt 0 ] && [ "$cli_res2" -gt 0 ] && [ "$svr_res1" -gt 0 ] && [ "$svr_res2" -gt 0 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "ack_timestamp_frame_case_1" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "ack_timestamp_frame_case_1" "fail"
fi


killall test_server
clear_log
echo -e "ack_timestamp_frame: server enable, 0 < max_ts_per_ack < 64 and client disable, 0 < max_ts_per_ack < 64 ...\c"
${SERVER_BIN} -l d -e -x 450 > /dev/null &
sleep 1
${CLIENT_BIN} -s 102400 -l d -t 1 -E -x 451 > stdlog
cli_res1=`grep "xqc_write_packet_receive_timestamps_into_buf|ts_info_len" clog | wc -l`
cli_res2=`grep "xqc_parse_timestamps_in_ack_ext|report_num:" clog | wc -l`

svr_res1=`grep "xqc_write_packet_receive_timestamps_into_buf|ts_info_len" slog | wc -l`
svr_res2=`grep "xqc_parse_timestamps_in_ack_ext|report_num:" slog | wc -l`

echo -e "$cli_res1 $cli_res2 $svr_res1 $svr_res2"

if [ "$cli_res1" -eq 0 ] && [ "$cli_res2" -eq 0 ] && [ "$svr_res1" -eq 0 ] && [ "$svr_res2" -eq 0 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "ack_timestamp_frame_case_2" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "ack_timestamp_frame_case_2" "fail"
fi


killall test_server
clear_log
echo -e "ack_timestamp_frame: server enable, 0 < max_ts_per_ack < 64 and client enable, max_ts_per_ack >= 64 ...\c"
${SERVER_BIN} -l d -e -x 450 > /dev/null &
sleep 1
${CLIENT_BIN} -s 102400 -l d -t 1 -E -x 452 > stdlog
cli_res1=`grep "conn errno" stdlog`

svr_res1=`grep "[error]" slog | grep "xqc_conn_tls_transport_params_cb" | wc -l`

if [ -n "$cli_res1" ] && [ -n "$svr_res1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "ack_timestamp_frame_case_3" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "ack_timestamp_frame_case_3" "fail"
fi


killall test_server
clear_log
echo -e "ack_timestamp_frame: server enable, 0 < max_ts_per_ack < 64 and client enable, max_ts_per_ack = 0 ...\c"
${SERVER_BIN} -l d -e -x 450 > /dev/null &
sleep 1
${CLIENT_BIN} -s 102400 -l d -t 1 -E -x 453 > stdlog
cli_res1=`grep "xqc_write_packet_receive_timestamps_into_buf|ts_info_len" clog | wc -l`
cli_res2=`grep "xqc_parse_timestamps_in_ack_ext|report_num:" clog | wc -l`

svr_res1=`grep "xqc_write_packet_receive_timestamps_into_buf|ts_info_len" slog | wc -l`
svr_res2=`grep "xqc_parse_timestamps_in_ack_ext|report_num:" slog | wc -l`

if [ "$cli_res1" -gt 0 ] && [ "$cli_res2" -eq 0 ] && [ "$svr_res1" -eq 0 ] && [ "$svr_res2" -gt 0 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "ack_timestamp_frame_case_4" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "ack_timestamp_frame_case_4" "fail"
fi


killall test_server
clear_log
echo -e "ack_timestamp_frame: server disable, 0 < max_ts_per_ack < 64 and client enable, 0 < max_ts_per_ack < 64  ...\c"
${SERVER_BIN} -l d -e -x 451 > /dev/null &
sleep 1
${CLIENT_BIN} -s 102400 -l d -t 1 -E -x 450 > stdlog
cli_res1=`grep "xqc_write_packet_receive_timestamps_into_buf|ts_info_len" clog | wc -l`
cli_res2=`grep "xqc_parse_timestamps_in_ack_ext|report_num:" clog | wc -l`

svr_res1=`grep "xqc_write_packet_receive_timestamps_into_buf|ts_info_len" slog | wc -l`
svr_res2=`grep "xqc_parse_timestamps_in_ack_ext|report_num:" slog | wc -l`

if [ "$cli_res1" -eq 0 ] && [ "$cli_res2" -eq 0 ] && [ "$svr_res1" -eq 0 ] && [ "$svr_res2" -eq 0 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "ack_timestamp_frame_case_5" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "ack_timestamp_frame_case_5" "fail"
fi


killall test_server
clear_log
echo -e "ack_timestamp_frame: server enable, max_ts_per_ack > 64 and client enable, 0 < max_ts_per_ack < 64  ...\c"
${SERVER_BIN} -l d -e -x 452 > /dev/null &
sleep 1
${CLIENT_BIN} -s 102400 -l d -t 1 -E -x 450 > stdlog
cli_res1=`grep "[error]" clog | grep "xqc_conn_tls_transport_params_cb" | wc -l`

svr_res1=`grep "[error]" slog | grep "xqc_process_conn_close_frame" | wc -l`


if [ "$cli_res1" -gt 0 ] && [ "$svr_res1" -gt 0 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "ack_timestamp_frame_case_6" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "ack_timestamp_frame_case_6" "fail"
fi

cd -
