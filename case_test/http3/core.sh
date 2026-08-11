#!/bin/bash
#
# http3.core endpoint case-test group.


ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "http3.core"

case_http3_core_h3_stream_send_pure_fin()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 99 > /dev/null
sleep 1

rm -f test_session tp_localhost xqc_token


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

}

case_http3_core_header_header_data()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1



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
}

case_http3_core_header_data_header()
{
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
}

case_http3_core_header_data_fin()
{
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
}

case_http3_core_header_data_immediate_fin()
{
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
}

case_http3_core_header_fin()
{
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
}

case_http3_core_uppercase_header()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1

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



}

case_http3_core_forbidden_header_e2e()
{



clear_log
echo -e "forbidden_header_e2e ...\c"
${CLIENT_BIN} -s 5120 -l d -t 1 -E -x 55 >> clog
forbidden_ok=`grep "forbidden_header_rejected:1" clog`
echo_ok=`grep ">>>>>>>> pass:1" clog`
if [ -n "$forbidden_ok" ] && [ -n "$echo_ok" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "forbidden_header_e2e" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "forbidden_header_e2e" "fail"
fi


}

case_http3_core_h3_ping()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1



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


}

case_http3_core_empty_header_value()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l i -e > /dev/null
sleep 1

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
}

case_http3_core_GET_request()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 709 > svr_stdlog
sleep 1

rm -rf tp_localhost test_session xqc_token
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1

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

}

case_http3_core_set_h3_settings()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1

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
}

case_http3_core_header_size_constraints()
{
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
}

case_http3_core_no_h3_init_settings_cb()
{
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

}

case_http3_core_set_h3_init_settings_cb()
{

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

}

case_http3_core_test_client_long_header()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l e -e > /dev/null
sleep 1

echo -e "large ack range with 30% loss ...\c"
echo "$result"


clear_log
echo -e "test client long header ...\c"
${CLIENT_BIN} -l d -x 29 >> clog
slog_res=`grep -a "large nv|conn" slog`
stream_reset=`grep -a "xqc_parse_reset_stream_frame|" clog \
    | grep "err_code:270"`
if [ -n "$stream_reset" ] && [ -n "$slog_res" ]; then
    case_print_result "test_client_long_header" "pass"
else
    case_print_result "test_client_long_header" "fail"
fi


}

case_http3_core_test_server_long_header()
{


case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -x 9 > /dev/null
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


}

case_http3_core_massive_requests_with_massive_header()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 8 > /dev/null
sleep 1



case_test_stop_server
case_test_start_server ${SERVER_BIN} -l e -e -x 10 > /dev/null
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

}

case_http3_core_h3_MP_ping()
{
case_test_stop_server
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -e -M > /dev/null
sleep 1

rm -rf tp_localhost test_session xqc_token


rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "h3 MP ping ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -E -e 1 --epoch_timeout 2000000 -t 3 --mp_ping 1 -M -i lo -i lo >> clog
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
}

case_http3_core_h3_engine_set_settings_api_h3()
{
case_test_stop_server
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -e -M > /dev/null
sleep 1

rm -rf tp_localhost test_session xqc_token


case_test_sudo rm -rf tp_localhost test_session xqc_token clog slog stdlog ckeys.log
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 150 > /dev/null
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

}

case_http3_core_h3_engine_set_settings_api_h3_more()
{

case_test_sudo rm -rf tp_localhost test_session xqc_token clog slog stdlog ckeys.log
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 151 > /dev/null
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

}

case_http3_core_h3_engine_set_settings_api_h3_29()
{

case_test_sudo rm -rf tp_localhost test_session xqc_token clog slog stdlog ckeys.log
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 152 > /dev/null
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

}

case_http3_core_h3_engine_set_settings_api_h3_29_more()
{

case_test_sudo rm -rf tp_localhost test_session xqc_token clog slog stdlog ckeys.log
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 153 > /dev/null
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


}

case_http3_core_h3_engine_set_settings_api_h3_ext()
{


case_test_sudo rm -rf tp_localhost test_session xqc_token clog slog stdlog ckeys.log
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 150 > /dev/null
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


}

case_http3_core_h3_engine_set_settings_api_h3_ext_more()
{


case_test_sudo rm -rf tp_localhost test_session xqc_token stdlog ckeys.log
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 151 > /dev/null
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

}

case_http3_core_h3_reserved_uni_stream_survives()
{
case_test_start_server ${SERVER_BIN} -l d -e -x 702 > /dev/null
sleep 1
# client uses stale session ticket from test 701
rm -f test_session xqc_token tp_localhost

## RFC 9114 Section 6.2 unidirectional stream handling

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1
echo -e "HTTP/3 reserved unidirectional stream remains usable ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 1000 > stdlog
sent=`grep "\\[h3-uni-stream-test\\]|type:0x21|ret:0|" stdlog`
received=`grep "|remote|stream_id:.*|stream_type:33|" slog`
result=`grep ">>>>>>>> pass:1" stdlog`
conn_err_zero=`grep -E "conn_err:0[^0-9]" stdlog`
if [ -n "$sent" ] && [ -n "$received" ] && [ -n "$result" ] \
    && [ -n "$conn_err_zero" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_reserved_uni_stream_survives" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_reserved_uni_stream_survives" "fail"
fi

}

case_http3_core_h3_client_push_stream_creation_error()
{

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1
echo -e "HTTP/3 client push stream gets stream creation error ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 1001 > stdlog
sent=`grep "\\[h3-uni-stream-test\\]|type:0x1|ret:0|" stdlog`
received=`grep "|remote|stream_id:.*|stream_type:1|" slog`
server_err=`grep "err:0x103" slog`
client_err=`grep -E "(conn errno:259|conn_err:259)" stdlog`
if [ -n "$sent" ] && [ -n "$received" ] && [ -n "$server_err" ] \
    && [ -n "$client_err" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_client_push_stream_creation_error" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_client_push_stream_creation_error" "fail"
fi
}

case_http3_core_h3_reserved_request_frame_accepted()
{
case_test_stop_server


## RFC 9114 Sections 7.2.5 and 9 request-stream frame handling

clear_log
rm -f test_session xqc_token tp_localhost h3_request_frame_server.log
case_test_start_server ${SERVER_BIN} -l d -e -x 1002 > h3_request_frame_server.log
sleep 1
echo -e "HTTP/3 reserved request frame remains usable ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 1002 > stdlog
sent=`grep "\\[h3-request-frame-test\\]|type:0x21|ret:0|" stdlog`
received=`grep "parse frame type success|frame_type:21|" slog`
server_ok=`grep "\\[h3-request-frame-test\\]|reserved-frame|conn_err:0|" \
    h3_request_frame_server.log`
client_ok=`grep "conn errno:256" stdlog`
if [ -n "$sent" ] && [ -n "$received" ] && [ -n "$server_ok" ] \
    && [ -n "$client_ok" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_reserved_request_frame_accepted" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_reserved_request_frame_accepted" "fail"
fi

}

case_http3_core_h3_client_push_promise_rejected()
{

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost h3_request_frame_server.log
case_test_start_server ${SERVER_BIN} -l d -e -x 1003 > h3_request_frame_server.log
sleep 1
echo -e "HTTP/3 client PUSH_PROMISE gets frame unexpected ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 1003 > stdlog
sent=`grep "\\[h3-request-frame-test\\]|type:0x5|ret:0|" stdlog`
server_err=`grep "\\[h3-request-frame-test\\]|push-promise|conn_err:261|" \
    h3_request_frame_server.log`
wire_err=`grep "err:0x105" slog`
client_err=`grep -E "(conn errno:261|conn_err:261)" stdlog`
application_type=`grep "conn_err_type:2" stdlog`
if [ -n "$sent" ] && [ -n "$server_err" ] && [ -n "$wire_err" ] \
    && [ -n "$client_err" ] && [ -n "$application_type" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_client_push_promise_rejected" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_client_push_promise_rejected" "fail"
fi
}

case_http3_core_h3_max_push_id_increase_accepted()
{
case_test_stop_server
rm -f h3_request_frame_server.log


## RFC 9114 Section 7.2.7 MAX_PUSH_ID handling

clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e -x 1005 > /dev/null
sleep 1
echo -e "HTTP/3 increasing MAX_PUSH_ID values are accepted ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 1005 > stdlog
sent=`grep "\\[h3-max-push-id-test\\]|first:1|second:3|write:0,0|send:0|" \
    stdlog`
first_received=`grep "|H3_MAX_PUSH_ID|max_push_id:1|" slog`
second_received=`grep "|H3_MAX_PUSH_ID|max_push_id:3|" slog`
result=`grep ">>>>>>>> pass:1" stdlog`
conn_err_zero=`grep -E "conn_err:0[^0-9]" stdlog`
if [ -n "$sent" ] && [ -n "$first_received" ] \
    && [ -n "$second_received" ] && [ -n "$result" ] \
    && [ -n "$conn_err_zero" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_max_push_id_increase_accepted" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_max_push_id_increase_accepted" "fail"
fi

}

case_http3_core_h3_max_push_id_decrease_rejected()
{

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e -x 1006 > /dev/null
sleep 1
echo -e "HTTP/3 decreasing MAX_PUSH_ID gets H3_ID_ERROR ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 1006 > stdlog
sent=`grep "\\[h3-max-push-id-test\\]|first:3|second:1|write:0,0|send:0|" \
    stdlog`
server_err=`grep "err:0x108" slog`
client_err=`grep -E "(conn errno:264|conn_err:264)" stdlog`
if [ -n "$sent" ] && [ -n "$server_err" ] && [ -n "$client_err" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_max_push_id_decrease_rejected" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_max_push_id_decrease_rejected" "fail"
fi

}

case_http3_core_h3_max_push_id_wrong_role_rejected()
{

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -e -x 1004 > svr_stdlog
sleep 1
echo -e "HTTP/3 server MAX_PUSH_ID gets H3_FRAME_UNEXPECTED ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 1004 > stdlog
sent=`grep "\\[h3-max-push-id-test\\]|server_send:1|write:0|send:0|" svr_stdlog`
client_err_log=`grep "err:0x105" clog`
server_err=`grep -E "(conn errno:261|conn_err:261)" svr_stdlog`
if [ -n "$sent" ] && [ -n "$client_err_log" ] && [ -n "$server_err" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_max_push_id_wrong_role_rejected" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_max_push_id_wrong_role_rejected" "fail"
fi

}

case_http3_core_h3_non_minimal_max_push_id_accepted()
{

case_test_stop_server


## RFC 9114 Section 7.1 single-varint frame payload lengths

clear_log
rm -f test_session xqc_token tp_localhost h3_frame_length_server.log
case_test_start_server ${SERVER_BIN} -l d -e -x 1007 > h3_frame_length_server.log
sleep 1
echo -e "HTTP/3 non-minimal MAX_PUSH_ID length is accepted ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 1007 > stdlog
sent=`grep "\\[h3-frame-length-test\\]|declared:2|actual:2|write:0|send:0|" \
    stdlog`
received=`grep "|H3_MAX_PUSH_ID|max_push_id:1|" slog`
server_ok=`grep "\\[h3-frame-length-test\\]|case:1007|conn_err:0|" \
    h3_frame_length_server.log`
result=`grep ">>>>>>>> pass:1" stdlog`
if [ -n "$sent" ] && [ -n "$received" ] && [ -n "$server_ok" ] \
    && [ -n "$result" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_non_minimal_max_push_id_accepted" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_non_minimal_max_push_id_accepted" "fail"
fi

}

case_http3_core_h3_overlong_max_push_id_rejected()
{

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost h3_frame_length_server.log
case_test_start_server ${SERVER_BIN} -l d -e -x 1008 > h3_frame_length_server.log
sleep 1
echo -e "HTTP/3 overlong MAX_PUSH_ID gets H3_FRAME_ERROR ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 1008 > stdlog
sent=`grep "\\[h3-frame-length-test\\]|declared:5|actual:2|write:0|send:0|" \
    stdlog`
server_err=`grep "\\[h3-frame-length-test\\]|case:1008|conn_err:262|" \
    h3_frame_length_server.log`
wire_err=`grep "err:0x106" slog`
client_err=`grep -E "(conn errno:262|conn_err:262)" stdlog`
applied=`grep "|H3_MAX_PUSH_ID|max_push_id:1|" slog`
if [ -n "$sent" ] && [ -n "$server_err" ] && [ -n "$wire_err" ] \
    && [ -n "$client_err" ] && [ -z "$applied" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_overlong_max_push_id_rejected" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_overlong_max_push_id_rejected" "fail"
fi

}

case_http3_core_h3_reserved_control_frame_accepted()
{

case_test_stop_server
rm -f h3_frame_length_server.log


## RFC 9114 Sections 7.2.3 and 9 control-frame handling

clear_log
rm -f test_session xqc_token tp_localhost h3_control_frame_server.log
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -e -x 1009 > h3_control_frame_server.log
sleep 1
echo -e "HTTP/3 reserved control frame remains usable ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 1009 > stdlog
sent=`grep "\\[h3-control-frame-test\\]|type:0x21|write:0|send:0|" \
    h3_control_frame_server.log`
received=`grep "ignore unknown frame|type:21|" clog`
client_ok=`grep "\\[h3-control-frame-test\\]|case:1009|conn_err:0|" stdlog`
server_ok=`grep "\\[h3-control-frame-test\\]|case:1009|conn_err:0|" \
    h3_control_frame_server.log`
result=`grep ">>>>>>>> pass:1" stdlog`
if [ -n "$sent" ] && [ -n "$received" ] && [ -n "$client_ok" ] \
    && [ -n "$server_ok" ] && [ -n "$result" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_reserved_control_frame_accepted" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_reserved_control_frame_accepted" "fail"
fi

}

case_http3_core_h3_cancel_push_unset_rejected()
{

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost h3_control_frame_server.log
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -e -x 1010 > h3_control_frame_server.log
sleep 1
echo -e "HTTP/3 CANCEL_PUSH above unset maximum gets H3_ID_ERROR ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 1010 > stdlog
sent=`grep "\\[h3-control-frame-test\\]|type:0x3|write:0|send:0|" \
    h3_control_frame_server.log`
wire_err=`grep "err:0x108" clog`
client_err=`grep "\\[h3-control-frame-test\\]|case:1010|conn_err:264|" \
    stdlog`
server_err=`grep "\\[h3-control-frame-test\\]|case:1010|conn_err:264|" \
    h3_control_frame_server.log`
application_type=`grep "conn_err_type:2" stdlog`
if [ -n "$sent" ] && [ -n "$wire_err" ] && [ -n "$client_err" ] \
    && [ -n "$server_err" ] && [ -n "$application_type" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_cancel_push_unset_rejected" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_cancel_push_unset_rejected" "fail"
fi

}

case_http3_core_h3_field_section_within_limit_succeeds()
{

case_test_stop_server
rm -f h3_control_frame_server.log


## RFC 9114 Sections 4.1.2 and 10.5.1 field-section limits

clear_log
rm -f test_session xqc_token tp_localhost h3_field_section_server.log
case_test_start_server ${SERVER_BIN} -l d -e -x 1011 > h3_field_section_server.log
sleep 1
echo -e "HTTP/3 fields within limit keep all request streams usable ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -P 2 -n 2 -x 1011 > stdlog
server_limit=`grep "\\[h3-field-section-test\\]|server_limit:512|" \
    h3_field_section_server.log`
received_count=`grep -c "\\[h3-field-section-test\\]|request_received|" \
    h3_field_section_server.log`
success_count=`grep -c ">>>>>>>> pass:1" stdlog`
server_ok=`grep "\\[h3-field-section-test\\]|server_conn_close|case:1011|"\
"conn_err:0|" h3_field_section_server.log`
client_ok=`grep "\\[h3-field-section-test\\]|client_conn_close|case:1011|"\
"conn_err:0|" stdlog`
if [ -n "$server_limit" ] && [ "$received_count" -eq 2 ] \
    && [ "$success_count" -eq 2 ] && [ -n "$server_ok" ] \
    && [ -n "$client_ok" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_field_section_within_limit_succeeds" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_field_section_within_limit_succeeds" "fail"
fi

}

case_http3_core_h3_field_section_over_limit_is_stream_error()
{

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost h3_field_section_server.log
case_test_start_server ${SERVER_BIN} -l d -e -x 1012 > h3_field_section_server.log
sleep 1
echo -e "HTTP/3 oversized fields reset one stream only ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -P 2 -n 2 -x 1012 > stdlog
oversized=`grep "\\[h3-field-section-test\\]|oversized_request_sent|" stdlog`
stream_reset=`grep "\\[h3-field-section-test\\]|server_stream_close|"\
".*|stream_err:270|" h3_field_section_server.log`
peer_error=`grep "\\[h3-field-section-test\\]|client_stream_closing|"\
".*|err:270|" stdlog`
received_count=`grep -c "\\[h3-field-section-test\\]|request_received|" \
    h3_field_section_server.log`
success_count=`grep -c ">>>>>>>> pass:1" stdlog`
server_ok=`grep "\\[h3-field-section-test\\]|server_conn_close|case:1012|"\
"conn_err:0|" h3_field_section_server.log`
client_ok=`grep "\\[h3-field-section-test\\]|client_conn_close|case:1012|"\
"conn_err:0|" stdlog`
if [ -n "$oversized" ] && [ -n "$stream_reset" ] \
    && [ -n "$peer_error" ] && [ "$received_count" -eq 1 ] \
    && [ "$success_count" -eq 1 ] && [ -n "$server_ok" ] \
    && [ -n "$client_ok" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_field_section_over_limit_is_stream_error" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_field_section_over_limit_is_stream_error" "fail"
fi

}

case_http3_core_h3_lowercase_response_field_name_accepted()
{

case_test_stop_server
rm -f h3_field_section_server.log


## RFC 9114 Sections 4.2 and 4.1.2 field-name validation

clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e -x 1013 > /dev/null
sleep 1
echo -e "HTTP/3 lowercase response field name is accepted ...\c"
${CLIENT_BIN} -G -l d -t 1 -x 1013 >> clog
lowercase_ok=`grep "lowercase_header_received:1" clog`
stream_ok=`grep "lowercase_header_request_succeeded:1" clog`
if [ -n "$lowercase_ok" ] && [ -n "$stream_ok" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_lowercase_response_field_name_accepted" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_lowercase_response_field_name_accepted" "fail"
fi

}

case_http3_core_h3_uppercase_response_field_name_rejected()
{

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e -x 1014 > /dev/null
sleep 1
echo -e "HTTP/3 uppercase response field name resets only stream ...\c"
${CLIENT_BIN} -G -l d -n 2 -t 2 -x 1014 >> clog
stream_error_ok=`grep "uppercase_header_stream_error:1" clog`
connection_reuse_ok=`grep "post_error_request_succeeded:1" clog`
transport_error=`grep "conn_err:1" clog`
if [ -n "$stream_error_ok" ] && [ -n "$connection_reuse_ok" ] \
    && [ -z "$transport_error" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "h3_uppercase_response_field_name_rejected" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "h3_uppercase_response_field_name_rejected" "fail"
fi

}

case_test_case "h3_stream_send_pure_fin" --id legacy --mode self-reporting --run case_http3_core_h3_stream_send_pure_fin
case_test_case "header_header_data" --id legacy --mode self-reporting --run case_http3_core_header_header_data
case_test_case "header_data_header" --id legacy --mode self-reporting --run case_http3_core_header_data_header
case_test_case "header_data_fin" --id legacy --mode self-reporting --run case_http3_core_header_data_fin
case_test_case "header_data_immediate_fin" --id legacy --mode self-reporting --run case_http3_core_header_data_immediate_fin
case_test_case "header_fin" --id legacy --mode self-reporting --run case_http3_core_header_fin
case_test_case "uppercase_header" --id legacy --mode self-reporting --run case_http3_core_uppercase_header
case_test_case "forbidden_header_e2e" --id legacy --mode self-reporting --run case_http3_core_forbidden_header_e2e
case_test_case "h3_ping" --id legacy --mode self-reporting --run case_http3_core_h3_ping
case_test_case "empty_header_value" --id legacy --mode self-reporting --run case_http3_core_empty_header_value
case_test_case "GET_request" --id legacy --mode self-reporting --run case_http3_core_GET_request
case_test_case "set_h3_settings" --id legacy --mode self-reporting --run case_http3_core_set_h3_settings
case_test_case "header_size_constraints" --id legacy --mode self-reporting --run case_http3_core_header_size_constraints
case_test_case "no_h3_init_settings_cb" --id legacy --mode self-reporting --run case_http3_core_no_h3_init_settings_cb
case_test_case "set_h3_init_settings_cb" --id legacy --mode self-reporting --run case_http3_core_set_h3_init_settings_cb
case_test_case "test_client_long_header" --id legacy --mode self-reporting --run case_http3_core_test_client_long_header
case_test_case "test_server_long_header" --id legacy --mode self-reporting --run case_http3_core_test_server_long_header
case_test_case "massive_requests_with_massive_header" --id legacy --mode self-reporting --run case_http3_core_massive_requests_with_massive_header
case_test_case "h3_MP_ping" --id legacy --mode self-reporting --run case_http3_core_h3_MP_ping
case_test_case "h3_engine_set_settings_api_h3" --id legacy --mode self-reporting --run case_http3_core_h3_engine_set_settings_api_h3
case_test_case "h3_engine_set_settings_api_h3_more" --id legacy --mode self-reporting --run case_http3_core_h3_engine_set_settings_api_h3_more
case_test_case "h3_engine_set_settings_api_h3_29" --id legacy --mode self-reporting --run case_http3_core_h3_engine_set_settings_api_h3_29
case_test_case "h3_engine_set_settings_api_h3_29_more" --id legacy --mode self-reporting --run case_http3_core_h3_engine_set_settings_api_h3_29_more
case_test_case "h3_engine_set_settings_api_h3_ext" --id legacy --mode self-reporting --run case_http3_core_h3_engine_set_settings_api_h3_ext
case_test_case "h3_engine_set_settings_api_h3_ext_more" --id legacy --mode self-reporting --run case_http3_core_h3_engine_set_settings_api_h3_ext_more
case_test_case "h3_reserved_uni_stream_survives" --id legacy --mode self-reporting --run case_http3_core_h3_reserved_uni_stream_survives
case_test_case "h3_client_push_stream_creation_error" --id legacy --mode self-reporting --run case_http3_core_h3_client_push_stream_creation_error
case_test_case "h3_reserved_request_frame_accepted" --id legacy --mode self-reporting --run case_http3_core_h3_reserved_request_frame_accepted
case_test_case "h3_client_push_promise_rejected" --id legacy --mode self-reporting --run case_http3_core_h3_client_push_promise_rejected
case_test_case "h3_max_push_id_increase_accepted" --id legacy --mode self-reporting --run case_http3_core_h3_max_push_id_increase_accepted
case_test_case "h3_max_push_id_decrease_rejected" --id legacy --mode self-reporting --run case_http3_core_h3_max_push_id_decrease_rejected
case_test_case "h3_max_push_id_wrong_role_rejected" --id legacy --mode self-reporting --run case_http3_core_h3_max_push_id_wrong_role_rejected
case_test_case "h3_non_minimal_max_push_id_accepted" --id legacy --mode self-reporting --run case_http3_core_h3_non_minimal_max_push_id_accepted
case_test_case "h3_overlong_max_push_id_rejected" --id legacy --mode self-reporting --run case_http3_core_h3_overlong_max_push_id_rejected
case_test_case "h3_reserved_control_frame_accepted" --id legacy --mode self-reporting --run case_http3_core_h3_reserved_control_frame_accepted
case_test_case "h3_cancel_push_unset_rejected" --id legacy --mode self-reporting --run case_http3_core_h3_cancel_push_unset_rejected
case_test_case "h3_field_section_within_limit_succeeds" --id legacy --mode self-reporting --run case_http3_core_h3_field_section_within_limit_succeeds
case_test_case "h3_field_section_over_limit_is_stream_error" --id legacy --mode self-reporting --run case_http3_core_h3_field_section_over_limit_is_stream_error
case_test_case "h3_lowercase_response_field_name_accepted" --id legacy --mode self-reporting --run case_http3_core_h3_lowercase_response_field_name_accepted
case_test_case "h3_uppercase_response_field_name_rejected" --id legacy --mode self-reporting --run case_http3_core_h3_uppercase_response_field_name_rejected

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
trap case_test_stop_server EXIT
case_test_require_sudo

case_test_run
