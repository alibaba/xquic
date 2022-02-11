# Copyright (c) 2022, Alibaba Group Holding Limited

#!/bin/bash

#macOS
#export EVENT_NOKQUEUE=1

cd ../build

# start test_server
killall test_server 2> /dev/null
./test_server -l d -e > /dev/null &
sleep 1

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
function case_print_result() {
    echo "[ RUN      ] xquic_case_test.$1"
    if [ "$2" = "pass" ];then
        echo "[       OK ] xquic_case_test.$1 (1 ms)"
    else
        echo "[     FAIL ] xquic_case_test.$1 (1 ms)"
    fi
}


clear_log
echo -e "stream read notify fail ...\c"
./test_client -s 1024000 -l d -t 1 -E -x 12 >> clog
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
./test_client -s 1024000 -l d -t 1 -E -x 11 >> clog
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
result=`./test_client -s 1024000 -l d -t 1 -E -x 10|grep ">>>>>>>> pass" `
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
result=`./test_client -s 1024000 -l d -t 1 -E -x 9|grep ">>>>>>>> pass" `
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
result=`./test_client -s 1024000 -l d -t 1 -E -x 8|grep ">>>>>>>> pass"`
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
./test_client -s 1024000 -l d -t 1 -E -x 7 >> clog
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
result=`./test_client -s 1024000 -l d -t 1 -E -x 6|grep ">>>>>>>> pass" `
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
result=`./test_client -s 1024000 -l d -t 1 -E -x 5|grep ">>>>>>>> pass" `
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
result=`./test_client -s 1024000 -l d -t 1 -E|grep ">>>>>>>> pass"`
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
result=`./test_client -s 1024000 -l d -t 1 -E|grep ">>>>>>>> pass"`
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
./test_client -s 5120 -l d -t 1 -E -x 16 >> clog
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
result=`./test_client -s 5120 -l d -t 1 -E -x 4 |grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "fin_only" "pass"
else
    case_print_result "fin_only" "fail"
    echo "$errlog"
fi

clear_log
echo -e "header header data ...\c"
./test_client -s 5120 -l d -t 1 -E -x 30 >> clog
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
./test_client -s 5120 -l d -t 1 -E -x 31 >> clog
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
./test_client  -l d -t 2 -s 100 -E -x 35 >> clog
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
./test_client  -l d -t 2 -s 100 -E -x 36 >> clog
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
./test_client  -l d -t 2 -x 37 >> clog
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
./test_client  -l d -t 2 -x 38 >> clog
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
./test_client -s 5120 -l d -t 1 -E -x 34 >> clog
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
./test_client -s 1024000 -l d -t 1 -E -x 2 >> clog
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
./test_client -s 1024000 -l d -t 1 -E -x 3 >> clog
if grep "<==.*CONNECTION_CLOSE" clog >/dev/null && grep "==>.*CONNECTION_CLOSE" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
    case_print_result "close_connection_with_error" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "close_connection_with_error" "fail"
fi
grep_err_log|grep -v xqc_process_write_streams|grep -v xqc_h3_stream_write_notify|grep -v xqc_process_conn_close_frame


clear_log
echo -e "Reset stream when sending...\c"
./test_client -s 1024000 -l d -t 1 -E -x 1 >> clog
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
./test_client -s 1024000 -l d -t 1 -E -x 21 > stdlog
result=`grep "xqc_send_ctl_drop_stream_frame_packets" slog`
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
./test_client -s 1024000 -l d -t 1 -E -x 28 > stdlog
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
./test_client -s 1024000 -l e -t 1 -E -1 -V 1 > stdlog
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
./test_client -s 1024000 -l e -t 1 -E -1 > stdlog
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
echo -e "without session ticket ...\c"
rm -f test_session
./test_client -s 1024000 -l e -t 1 -E > stdlog
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
./test_client -s 1024 -l d -E -x 28 -T >> clog
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
./test_client -s 1024 -l d -E -x 28 >> clog
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
./test_client -s 1024000 -l e -t 1 -E > stdlog
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
./test_server -l i -e > /dev/null &
sleep 1
./test_client -s 1024000 -l d -t 1 -E > stdlog
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
result=`./test_client -s 1024000 -l d -T -t 1 -E|grep ">>>>>>>> pass"`
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
./test_client -s 1024000 -l e -T -t 1 -E > stdlog
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
result=`./test_client -s 1024000 -l d -N -t 1 -E|grep ">>>>>>>> pass"`
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
./test_client -s 1024000 -l d -N -t 1 -E >> clog
if grep "early_data_flag:1" clog >/dev/null && grep ">>>>>>>> pass:1" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
    case_print_result "no_crypto_with_0RTT" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "no_crypto_with_0RTT" "fail"
fi
grep_err_log


clear_log
echo -e "no crypto with 0RTT twice ...\c"
./test_client -s 1024000 -l d -N -t 1 -E >> clog
if grep "early_data_flag:1" clog >/dev/null && grep ">>>>>>>> pass:1" clog >/dev/null; then
    echo ">>>>>>>> pass:1"
    case_print_result "no_crypto_with_0RTT_twice" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "no_crypto_with_0RTT_twice" "fail"
fi
grep_err_log


clear_log
echo -e "0RTT buffer limit before Initial ...\c"
./test_client -l d -t 1 -x 39 -E >> clog
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
rm -f test_session
echo -e "NULL stream callback ...\c"
killall test_server
./test_server -l i -e -x 2 > /dev/null &
sleep 1
./test_client -l d -T -E >> clog
if grep "stream_read_notify is NULL" slog >/dev/null; then
    echo ">>>>>>>> pass:1"
    case_print_result "NULL_stream_callback" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "NULL_stream_callback" "fail"
fi
rm -f test_session


clear_log
echo -e "server cid negotiate ...\c"
killall test_server
./test_server -l d -e -x 1 > /dev/null &
sleep 1
./test_client -s 1024000 -l d -t 1 -E >> clog
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
result=`./test_client -l d -t 1 -E -G|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
alpn_res=`grep "|select alpn|h3|" slog`
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
result=`./test_client -s 1024 -l d -t 1 -E -x 17 |grep ">>>>>>>> pass"`
alpn_res=`grep "select alpn|h3-29|" slog`
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
./test_client -s 1024 -l d -t 1 -E -x 18 >> clog
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
./test_client -s 1024 -l d -t 1 -E -x 19 -n 2 >> clog
if grep -e "xqc_h3_stream_send_headers.*fields_size.*exceed.*SETTINGS_MAX_FIELD_SECTION_SIZE.*" slog >/dev/null; then
    echo ">>>>>>>> pass:1"
    case_print_result "header_size_constraints" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "header_size_constraints" "fail"
fi
grep_err_log|grep -v xqc_h3_stream_send_headers


clear_log
echo -e "send 1K data ...\c"
result=`./test_client -s 1024 -l d -t 1 -E|grep ">>>>>>>> pass"`
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
result=`./test_client -s 1024000 -l d -t 1 -E|grep ">>>>>>>> pass"`
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
result=`./test_client -s 10240000 -l e -E|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "send_10M_data" "pass"
else
    case_print_result "send_10M_data" "fail"
    echo "$errlog"
fi

clear_log
echo -e "BBR ...\c"
result=`./test_client -s 10240000 -l e -E -c bbr|grep ">>>>>>>> pass"`
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
result=`./test_client -s 10240000 -l e -E -c bbr+|grep ">>>>>>>> pass"`
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
result=`./test_client -s 10240000 -l e -E -c bbr2|grep ">>>>>>>> pass"`
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
result=`./test_client -s 10240000 -l e -E -c bbr2+|grep ">>>>>>>> pass"`
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
result=`./test_client -s 10240000 -l e -E -c reno -C|grep ">>>>>>>> pass"`
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
result=`./test_client -s 10240000 -l e -E -c reno|grep ">>>>>>>> pass"`
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
result=`./test_client -s 10240000 -l e -E -c cubic -C|grep ">>>>>>>> pass"`
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
result=`./test_client -s 10240000 -l e -E -c cubic|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "cubic_without_pacing" "pass"
else
    case_print_result "cubic_without_pacing" "fail"
    echo "$errlog"
fi


clear_log
result=`./test_client -s 10240000 -l e -t 1 -E -x 26|grep ">>>>>>>> pass"`
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
result=`./test_client -s 10240000 -l e -E|grep ">>>>>>>> pass"`
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
./test_client -s 512000 -l e -E -n 10 >> clog
if [[ `grep ">>>>>>>> pass:1" clog|wc -l` -eq 10 ]]; then
    echo ">>>>>>>> pass:1"
    case_print_result "connection_level_flow_control" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "connection_level_flow_control" "fail"
fi
grep_err_log

clear_log
echo -e "stream concurrency flow control ...\c"
./test_client -s 1 -l e -t 1 -E -P 1025 -G > ccfc.log
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
result=`./test_client -s 10240000 -l e -E -d 10|grep ">>>>>>>> pass"`
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
result=`./test_client -s 10240000 -l e -E -d 30|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "3_percent_loss" "pass"
else
    case_print_result "3_percent_loss" "fail"
    echo "$errlog"
fi

clear_log
result=`./test_client -s 10240000 -t 5 -l e -E -d 100|grep ">>>>>>>> pass"`
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
./test_server -l e -e > /dev/null &
sleep 1

clear_log
echo -e "sendmmsg with 10% loss ...\c"
result=`./test_client -s 10240000 -t 5 -l e -E -d 100 -x 20 -c c|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "sengmmsg_with_10_percent_loss" "pass"
else
    case_print_result "sengmmsg_with_10_percent_loss" "fail"
    echo "$errlog"
fi


clear_log
result=`./test_client -s 2048000 -l e -t 5 -E -d 300|grep ">>>>>>>> pass"`
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
./test_client -l d -x 29 >> clog
#clog_res=`grep "xqc_process_conn_close_frame|with err:" clog`
#slog_res=`grep "READ_VALUE error" slog`
slog_res=`grep "large nv|conn" slog`
clog_res=`grep "xqc_process_conn_close_frame|with err:" clog`
if [ -n "$clog_res" ] && [ -n "$slog_res" ]; then
    case_print_result "test_client_long_header" "pass"
else
    case_print_result "test_client_long_header" "fail"
fi


killall test_server 2> /dev/null
./test_server -l d -x 9 > /dev/null &
sleep 1


clear_log
echo -e "test server long header ...\c"
./test_client -l d >> clog
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
./test_server -l d -e > /dev/null &
sleep 1
client_print_res=`./test_client -s 1024000 -l d -t 1 -x 22 -E | grep ">>>>>>>> pass"`
errlog=`grep_err_log`
server_log_res=`grep "decrypt payload error" slog`
server_conn_cnt=`grep "xqc_conn_create" slog | grep -v "tra_parameters_set" | wc -l`
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
./test_server -l d -e > /dev/null &
sleep 1
client_print_res=`./test_client -s 1024000 -l d -t 1 -x 23 -E | grep ">>>>>>>> pass"`
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
./test_server -l d -e -x 3 > /dev/null &
sleep 1
client_print_res=`./test_client -s 1024000 -l d -t 1 -E |grep ">>>>>>>> pass"`
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
./test_server -l d -e -x 4 > /dev/null &
sleep 1
client_print_res=`./test_client -s 1024000 -l d -t 1 -E |grep ">>>>>>>> pass"`
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
./test_server -l d -e -x 5 > /dev/null &
sleep 1
result=`./test_client -s 1024000 -l d -t 1 -E | grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "server_odcid_hash" "pass"
else
    case_print_result "server_odcid_hash" "fail"
    echo "$errlog"
fi


clear_log
killall test_server 2> /dev/null
echo -e "load balancer cid generate ...\c"
./test_server -l d -e -S "server_id_0" > /dev/null &
sleep 1
./test_client -s 1024000 -l d -t 1 >> clog
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
./test_client -s 1024 -l d -t 1 -x 27 >> clog
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
./test_server -l d -e -x 8 > /dev/null &
sleep 1

clear_log
rm -f test_session xqc_token tp_localhost
echo -e "server amplification limit ...\c"
./test_client -s 1024 -l d -t 3 -x 25 -1 >> clog
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
./test_server -l e -e -x 10 > /dev/null &
sleep 1
clear_log
echo -e "massive requests with massive header ...\c"
./test_client -l e -q 50 -n 100 -x 32 -E >> clog
result=`grep ">>>>>>>> pass:1" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "massive_requests_with_massive_header" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "massive_requests_with_massive_header" "fail"
fi

killall test_server 2> /dev/null
./test_server -l d -e -b > /dev/null &
sleep 1

clear_log
echo -e "version negotiation ...\c"
./test_client -l d -E -x 33 >> clog
result=`grep -e "|====>|.*VERSION_NEGOTIATION" clog`
if [ -n "$result" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "version_negotiation" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "version_negotiation" "fail"
fi


killall test_server
./test_server -l d -e -x 11 > /dev/null &
sleep 1

clear_log
echo -e "server refuse connection ...\c"
./test_client -l d -E >> clog
svr_result=`grep "server_accept callback return error" slog`
if [ -n "$svr_result" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "server_refuse_connection" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "server_refuse_connection" "fail"
fi

killall test_server
./test_server -l e -e -x 12 > /dev/null &
sleep 1

clear_log
echo -e "linger close transport ...\c"
rm -f test_session xqc_token tp_localhost
result=`./test_client -l e -T -t 1 -E|grep ">>>>>>>> pass"`
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
result=`./test_client -l e -t 1 -E|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "linger_close_h3" "pass"
else
    case_print_result "linger_close_h3" "fail"
    echo "$errlog"
fi

killall test_server
./test_server -l d -e > /dev/null &
sleep 1

clear_log
echo -e "key update ...\c"
./test_client -s 102400 -l d -E -x 40 >> clog
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
./test_client -s 102400 -l d -E -x 40 >> clog
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

killall test_server

cd -
