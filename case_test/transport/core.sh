#!/bin/bash
#
# transport.core endpoint case-test group.


ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "transport.core"

case_transport_core_log_switch_off()
{
# start test_server
rm -rf tp_localhost test_session xqc_token
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
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


}

case_transport_core_server_refuse()
{


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

}

case_transport_core_create_connection_fail()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1


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

}

case_transport_core_socket_recv_fail()
{

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

}

case_transport_core_socket_send_fail()
{

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

}

case_transport_core_verify_token_fail()
{

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

}

case_transport_core_verify_token_success()
{

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

}

case_transport_core_test_application_delay()
{

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
}

case_transport_core_user_close_connection()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1



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
}

case_transport_core_close_connection_with_error()
{
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
}

case_transport_core_transport_ping()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1



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


}

case_transport_core_transport_only()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l i -e > /dev/null
sleep 1

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

}

case_transport_core_transport_0RTT()
{

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


}

case_transport_core_server_cid_negotiate()
{
case_test_start_server ${SERVER_BIN} -l d -e -x 601 > /dev/null
sleep 1
#echo "$result"



clear_log
echo -e "server cid negotiate ...\c"
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 1 > /dev/null
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

}

case_transport_core_active_cid_limit_accept()
{

clear_log
echo -e "active_connection_id_limit accepts in-limit NEW_CONNECTION_ID ...\c"
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 1 > /dev/null
sleep 1
${CLIENT_BIN} -s 1024 -l d -t 1 -E > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
conn_err_zero=`grep -E "conn_err:0[^0-9]" stdlog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ] && [ -n "$conn_err_zero" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "active_cid_limit_accept" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "active_cid_limit_accept" "fail"
    echo "$errlog"
fi

}

case_transport_core_active_cid_limit_exceeded()
{

clear_log
echo -e "active_connection_id_limit rejects extra NEW_CONNECTION_ID ...\c"
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 704 > svr_stdlog
sleep 1
${CLIENT_BIN} -s 1024 -l d -t 2 -E > stdlog 2>&1
forced_cid=`grep "\[active-cid-limit-test\]" svr_stdlog`
conn_id_limit_err=`grep -E "(conn errno:9|conn_err:9)" stdlog`
frame_encoding_err=`grep -E "(conn errno:7|conn_err:7)" stdlog`
transport_type=`grep "conn_err_type:1" stdlog`
if [ -n "$forced_cid" ] && [ -n "$conn_id_limit_err" ] \
    && [ -z "$frame_encoding_err" ] && [ -n "$transport_type" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "active_cid_limit_exceeded" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "active_cid_limit_exceeded" "fail"
    echo "$forced_cid"
    echo "$conn_id_limit_err"
    echo "$frame_encoding_err"
fi

}

case_transport_core_active_cid_limit_minimum_accept()
{

clear_log
rm -rf tp_localhost test_session xqc_token
echo -e "active_connection_id_limit accepts minimum value ...\c"
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 710 > svr_stdlog
sleep 1
${CLIENT_BIN} -s 1024 -l d -t 1 -E > stdlog 2>&1
advertised=`grep "\[active-cid-limit-min-test\] advertised_limit:2" svr_stdlog`
result=`grep ">>>>>>>> pass:1" stdlog`
tp_err=`grep -E "(conn errno:8|conn_err:8[^0-9])" stdlog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$advertised" ] && [ -z "$tp_err" ] \
    && [ "$result" == ">>>>>>>> pass:1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "active_cid_limit_minimum_accept" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "active_cid_limit_minimum_accept" "fail"
    echo "$advertised"
    echo "$errlog"
fi

}

case_transport_core_active_cid_limit_below_minimum()
{

clear_log
rm -rf tp_localhost test_session xqc_token
echo -e "active_connection_id_limit rejects value below minimum ...\c"
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 709 > svr_stdlog
sleep 1
${CLIENT_BIN} -s 1024 -l d -t 2 -E > stdlog 2>&1
advertised=`grep "\[active-cid-limit-min-test\] advertised_limit:1" svr_stdlog`
tp_err=`grep -E "(conn errno:8|conn_err:8[^0-9])" stdlog`
transport_type=`grep "conn_err_type:1" stdlog`
req_ok=`grep ">>>>>>>> pass:1" stdlog`
cid_limit_err=`grep -E "(conn errno:9|conn_err:9[^0-9])" stdlog`
if [ -n "$advertised" ] && [ -n "$tp_err" ] && [ -n "$transport_type" ] \
    && [ -z "$req_ok" ] && [ -z "$cid_limit_err" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "active_cid_limit_below_minimum" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "active_cid_limit_below_minimum" "fail"
    echo "$advertised"
    echo "$tp_err"
    echo "$cid_limit_err"
fi

rm -rf tp_localhost test_session xqc_token
}

case_transport_core_max_ack_delay_valid_boundary()
{

clear_log
rm -rf tp_localhost test_session xqc_token
echo -e "max_ack_delay accepts the largest valid value ...\c"
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 714 > svr_stdlog
sleep 1
${CLIENT_BIN} -s 1024 -l d -t 1 -E > stdlog 2>&1
advertised=`grep "advertised_max_ack_delay:16383" svr_stdlog`
result=`grep ">>>>>>>> pass:1" stdlog`
tp_err=`grep -E "(conn errno:8|conn_err:8[^0-9])" stdlog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$advertised" ] && [ -z "$tp_err" ] \
    && [ "$result" == ">>>>>>>> pass:1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "max_ack_delay_valid_boundary" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "max_ack_delay_valid_boundary" "fail"
    echo "$advertised"
    echo "$errlog"
fi

}

case_transport_core_max_ack_delay_invalid_boundary()
{

clear_log
rm -rf tp_localhost test_session xqc_token
echo -e "max_ack_delay rejects the first invalid value ...\c"
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 713 > svr_stdlog
sleep 1
${CLIENT_BIN} -s 1024 -l d -t 2 -E > stdlog 2>&1
advertised=`grep "advertised_max_ack_delay:16384" svr_stdlog`
tp_err=`grep -E "(conn errno:8|conn_err:8[^0-9])" stdlog`
transport_type=`grep "conn_err_type:1" stdlog`
req_ok=`grep ">>>>>>>> pass:1" stdlog`
if [ -n "$advertised" ] && [ -n "$tp_err" ] && [ -n "$transport_type" ] \
    && [ -z "$req_ok" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "max_ack_delay_invalid_boundary" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "max_ack_delay_invalid_boundary" "fail"
    echo "$advertised"
    echo "$tp_err"
    echo "$transport_type"
fi

rm -rf tp_localhost test_session xqc_token
}

case_transport_core_new_client_29_new_server()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1


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


}

case_transport_core_load_balancer_cid_generate_with_encryption()
{
case_test_start_server ${SERVER_BIN} -l d -e -x 5 > /dev/null
sleep 1

# ${SERVER_BIN} should be killed after this case, since some of the test case requires ${SERVER_BIN} without param `-E`
clear_log
case_test_stop_server
echo -e "load balancer cid generate with encryption...\c"
case_test_start_server ${SERVER_BIN} -l d -e -S "server_id_0" -E > /dev/null
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

}

case_transport_core_load_balancer_cid_generate()
{

clear_log
case_test_stop_server
echo -e "load balancer cid generate ...\c"
case_test_start_server ${SERVER_BIN} -l d -e -S "server_id_0" > /dev/null
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

}

case_transport_core_server_amplification_limit()
{
case_test_start_server ${SERVER_BIN} -l d -e -S "server_id_0" > /dev/null
sleep 1



case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 8 > /dev/null
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


}

case_transport_core_version_negotiation()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l e -e -x 10 > /dev/null
sleep 1

case_test_stop_server
# Case 33: server only advertises draft-29 so the V1 client hits the
# abort path instead of the downgrade-protection discard.
case_test_start_server ${SERVER_BIN} -l d -e -x 33 > /dev/null
sleep 1

clear_log
echo -e "version negotiation ...\c"
${CLIENT_BIN} -l d -E -x 33 >> clog 2>&1

# Wire-level: VN packet was received and parsed by the client.
# (The event-log callback is skipped because the abort error is non-tolerant,
# so we match the unconditional debug log from xqc_packet_parse_version_negotiation.)
result=`grep "packet parse|version negotiation" clog`
if [ -n "$result" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "version_negotiation" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "version_negotiation" "fail"
fi

# RFC 9000 §6.2 mandates the client MUST abandon the connection attempt on
# a valid VN. Verify xqc_packet_parse_version_negotiation took the abort
# branch instead of the legacy silent-version-switch behaviour.
}

case_transport_core_version_negotiation_abort_path()
{

# RFC 9000 §6.2 mandates the client MUST abandon the connection attempt on
# a valid VN. Verify xqc_packet_parse_version_negotiation took the abort
# branch instead of the legacy silent-version-switch behaviour.
abort_log=`grep "version negotiation: aborting connection attempt" clog`
if [ -n "$abort_log" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "version_negotiation_abort_path" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "version_negotiation_abort_path" "fail"
fi

# The abort must be surfaced to the upper layer through conn_close_notify
# with a non-zero errno: either TRA_VERSION_NEGOTIATION_ERROR (0x53 = 83)
# from the transport conn_err, or XQC_EVERSION_NEGOTIATION (643) when the
# error is propagated through xqc_conn_get_errno on a transport-only path.
}

case_transport_core_version_negotiation_close_errno()
{

# The abort must be surfaced to the upper layer through conn_close_notify
# with a non-zero errno: either TRA_VERSION_NEGOTIATION_ERROR (0x53 = 83)
# from the transport conn_err, or XQC_EVERSION_NEGOTIATION (643) when the
# error is propagated through xqc_conn_get_errno on a transport-only path.
errno_log=`grep -E "conn errno:(83|643)" clog`
if [ -n "$errno_log" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "version_negotiation_close_errno" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "version_negotiation_close_errno" "fail"
fi


}

case_transport_core_server_refuse_connection()
{


case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 11 > /dev/null
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

}

case_transport_core_linger_close_transport()
{

case_test_stop_server
case_test_start_server ${SERVER_BIN} -l e -e -x 12 > /dev/null
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

}

case_transport_core_linger_close_h3()
{
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

}

case_transport_core_stateless_reset()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1



case_test_stop_server
# Start the server without -x 13. The previous "idle_time_out = 1000"
# trick relied on a small max_idle_timeout transport parameter to force
# the server to discard its connection state quickly; after RFC 9000
# Section 10.1 negotiation (PR #758) the client now takes the minimum
# of both advertised values, so a 1 s server-side TP would also kill
# the client well before the wake-up packet that the test relies on.
# Restart the server mid-test instead: it cleans up its connection
# state silently, then the new instance generates the stateless reset
# from the same default reset_token_key.
case_test_start_server ${SERVER_BIN} -l d > /dev/null
sleep 1
clear_log
echo -e "stateless reset...\c"
${CLIENT_BIN} -l d -x 41 -1 -t 8 > stdlog &
CLIENT_PID=$!
# Allow the handshake to finish, the two tracked short-header packets
# to be sent, and the 3 s outbound black-hole inside the client to
# begin before the server is recycled.
sleep 2
case_test_stop_server
sleep 0.2
case_test_start_server ${SERVER_BIN} -l d > /dev/null
wait $CLIENT_PID
result=`grep "|====>|receive stateless reset" clog`
cloing_notify=`grep "conn closing: 641" stdlog`
if [ -n "$result" ] && [ -n "$cloing_notify" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "stateless_reset" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "stateless_reset" "fail"
fi


}

case_transport_core_stateless_reset_during_hsk()
{


clear_log
echo -e "stateless reset during hsk...\c"
${CLIENT_BIN} -l d  -t 12 -x 45 -1 -s 100 -G > stdlog &
CLIENT_PID=$!
# Same pattern as above. The client opens the black-hole on the first
# Handshake-level or short-header outbound packet, so 2 s gives Initial
# exchange plus the start of the 10 s drop window before we recycle
# the server.
sleep 2
case_test_stop_server
sleep 0.2
case_test_start_server ${SERVER_BIN} -l d > /dev/null
wait $CLIENT_PID
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

}

case_transport_core__0rtt_forbidden_remembered_params_normal()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -Q 8000 > /dev/null
sleep 1
rm -f test_session tp_localhost xqc_token

# issue #672: RFC 9000 7.4.1 forbidden remembered transport params must not be used in 0-RTT
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1
clear_log
echo -e "0RTT forbidden remembered params (normal) ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E > stdlog
clear_log
${CLIENT_BIN} -s 1024 -l d -t 1 -E > stdlog
cli_restore=`grep "|0RTT_transport_params|" clog`
cli_pto=`grep "max_ack_delay:25|" clog`
flag=`grep "early_data_flag:1" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_restore" ] && [ -n "$cli_pto" ] && [ -n "$flag" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "0rtt_forbidden_remembered_params_normal" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "0rtt_forbidden_remembered_params_normal" "fail"
fi

}

case_transport_core__0rtt_forbidden_remembered_params_stale_not_used()
{

clear_log
echo -e "0RTT forbidden remembered params (stale max_ack_delay not used) ...\c"
case_test_replace_in_file 'max_ack_delay=[0-9]*' 'max_ack_delay=100' tp_localhost
${CLIENT_BIN} -s 1024 -l d -t 1 -E > stdlog
cli_restore=`grep "|0RTT_transport_params|" clog`
cli_stale=`grep "max_ack_delay:100|" clog`
flag=`grep "early_data_flag:1" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_restore" ] && [ -z "$cli_stale" ] && [ -n "$flag" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "0rtt_forbidden_remembered_params_stale_not_used" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "0rtt_forbidden_remembered_params_stale_not_used" "fail"
fi
rm -f test_session tp_localhost xqc_token

}

case_transport_core_check_clear_0rtt_ticket_flag_in_close_notify()
{
case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null
sleep 1


rm -rf tp_localhost test_session xqc_token
case_test_stop_server


case_test_start_server ${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null
sleep 1
${CLIENT_BIN} -l d -T 1 -s 4800 -U 1 -Q 65535 -E &> /dev/null #generate 0rtt ticket
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -s 1 > /dev/null #disable datagram
sleep 1
clear_log
echo -e "check_clear_0rtt_ticket_flag_in_close_notify...\c"
${CLIENT_BIN} -l d -T 1 -s 4800 -U 1 -Q 65535 -E > stdlog
cli_res2=`grep "conn_err:85, clear_0rtt_ticket:1" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res2" ] && [ -n "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "check_clear_0rtt_ticket_flag_in_close_notify" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "check_clear_0rtt_ticket_flag_in_close_notify" "fail"
fi

rm -rf tp_localhost test_session xqc_token
}

case_transport_core_check_clear_0rtt_ticket_flag_in_h3_close_notify()
{

rm -rf tp_localhost test_session xqc_token
case_test_stop_server

case_test_start_server ${SERVER_BIN} -l d -Q 65535 -e -s 1 > /dev/null
sleep 1
${CLIENT_BIN} -l d -s 4800 -Q 65535 -E &> /dev/null #generate 0rtt ticket
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -s 1 > /dev/null #disable datagram
sleep 1
clear_log
echo -e "check_clear_0rtt_ticket_flag_in_h3_close_notify...\c"
${CLIENT_BIN} -l d -s 4800 -Q 65535 -E > stdlog
cli_res2=`grep "conn_err:85, clear_0rtt_ticket:1" stdlog`
errlog=`grep_err_log`
if [ -n "$cli_res2" ] && [ -n "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "check_clear_0rtt_ticket_flag_in_h3_close_notify" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "check_clear_0rtt_ticket_flag_in_h3_close_notify" "fail"
fi

rm -rf tp_localhost test_session xqc_token
}

case_transport_core_request_closing_notify()
{
case_test_stop_server
sleep 1

rm -rf tp_localhost test_session xqc_token
case_test_stop_server

clear_log
echo -e "request_closing_notify...\c"
case_test_start_server ${SERVER_BIN} -l d -x 14 > /dev/null
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


}

case_transport_core_transport_MP_ping()
{
case_test_stop_server
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -e -M -Q 65535 -U 1 --pmtud 1 -x 200 > svr_stdlog
sleep 1

rm -rf tp_localhost test_session xqc_token
grep_err_log


case_test_stop_server
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -e -M > /dev/null
sleep 1

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "transport MP ping ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -E -T 1 -e 1 --epoch_timeout 2000000 -t 3 --mp_ping 1 -M -i lo -i lo >> clog
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
}

case_transport_core__0RTT_param_reduction()
{
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1

## RFC 9000 Section 7.4.1: 0-RTT transport parameter validation

# test 701: server reduces max_streams_bidi after first connection,
# client detects reduction on 0-RTT resumption, reports its local cleanup
# reason (0x54 = conn_err:84), and sends TRANSPORT_PARAMETER_ERROR (0x08)
case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
echo -e "0RTT param reduction detection ...\c"
case_test_start_server ${SERVER_BIN} -l d -e -x 701 > /dev/null
sleep 1
# first connection: establish session ticket with normal params
${CLIENT_BIN} -s 1024 -l d -t 1 -E > stdlog
# second connection: 0-RTT with reduced max_streams_bidi on server
${CLIENT_BIN} -s 1024 -l d -t 1 -E > stdlog
conn_err=`grep "conn_err:84" stdlog`
peer_err=`grep "[error].*err:0x8" slog`
if [ -n "$conn_err" ] && [ -n "$peer_err" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "0RTT_param_reduction" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "0RTT_param_reduction" "fail"
fi

# test 702: server restarts with reduced params, 0-RTT is rejected
# (ticket invalid), so validation is skipped and connection succeeds
}

case_transport_core__0RTT_rejected_param_reduction()
{

# test 702: server restarts with reduced params, 0-RTT is rejected
# (ticket invalid), so validation is skipped and connection succeeds
case_test_stop_server
clear_log
echo -e "0RTT rejected with param reduction ...\c"
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1
# First connection: establish a ticket with normal remembered params.
${CLIENT_BIN} -s 1024 -l d -t 1 -E > /dev/null
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 702 > /dev/null
sleep 1
${CLIENT_BIN} -s 1024 -l d -t 1 -E > stdlog
result=`grep ">>>>>>>> pass:" stdlog`
echo "$result"
flag=`grep "early_data_flag:2" stdlog`
conn_err_zero=`grep -E "conn_err:0[^0-9]" stdlog`
if [ -n "$flag" ] && [ -n "$conn_err_zero" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "0RTT_rejected_param_reduction" "pass"
else
    case_print_result "0RTT_rejected_param_reduction" "fail"
fi
rm -f test_session xqc_token tp_localhost

## RFC 9114 Section 6.2 unidirectional stream handling

}

case_test_case "log_switch_off" --id native --mode self-reporting --run case_transport_core_log_switch_off
case_test_case "server_refuse" --id native --mode self-reporting --run case_transport_core_server_refuse
case_test_case "create_connection_fail" --id native --mode self-reporting --run case_transport_core_create_connection_fail
case_test_case "socket_recv_fail" --id native --mode self-reporting --run case_transport_core_socket_recv_fail
case_test_case "socket_send_fail" --id native --mode self-reporting --run case_transport_core_socket_send_fail
case_test_case "verify_token_fail" --id native --mode self-reporting --run case_transport_core_verify_token_fail
case_test_case "verify_token_success" --id native --mode self-reporting --run case_transport_core_verify_token_success
case_test_case "test_application_delay" --id native --mode self-reporting --run case_transport_core_test_application_delay
case_test_case "user_close_connection" --id native --mode self-reporting --run case_transport_core_user_close_connection
case_test_case "close_connection_with_error" --id native --mode self-reporting --run case_transport_core_close_connection_with_error
case_test_case "transport_ping" --id native --mode self-reporting --run case_transport_core_transport_ping
case_test_case "transport_only" --id native --mode self-reporting --run case_transport_core_transport_only
case_test_case "transport_0RTT" --id native --mode self-reporting --run case_transport_core_transport_0RTT
case_test_case "server_cid_negotiate" --id native --mode self-reporting --run case_transport_core_server_cid_negotiate
case_test_case "active_cid_limit_accept" --id native --mode self-reporting --run case_transport_core_active_cid_limit_accept
case_test_case "active_cid_limit_exceeded" --id native --mode self-reporting --run case_transport_core_active_cid_limit_exceeded
case_test_case "active_cid_limit_minimum_accept" --id native --mode self-reporting --run case_transport_core_active_cid_limit_minimum_accept
case_test_case "active_cid_limit_below_minimum" --id native --mode self-reporting --run case_transport_core_active_cid_limit_below_minimum
case_test_case "max_ack_delay_valid_boundary" --id native --mode self-reporting --run case_transport_core_max_ack_delay_valid_boundary
case_test_case "max_ack_delay_invalid_boundary" --id native --mode self-reporting --run case_transport_core_max_ack_delay_invalid_boundary
case_test_case "new_client_29_&_new_server" --id native --mode self-reporting --run case_transport_core_new_client_29_new_server
case_test_case "load_balancer_cid_generate_with_encryption" --id native --mode self-reporting --run case_transport_core_load_balancer_cid_generate_with_encryption
case_test_case "load_balancer_cid_generate" --id native --mode self-reporting --run case_transport_core_load_balancer_cid_generate
case_test_case "server_amplification_limit" --id native --mode self-reporting --run case_transport_core_server_amplification_limit
case_test_case "version_negotiation" --id native --mode self-reporting --run case_transport_core_version_negotiation
case_test_case "version_negotiation_abort_path" --id native --mode self-reporting --run case_transport_core_version_negotiation_abort_path
case_test_case "version_negotiation_close_errno" --id native --mode self-reporting --run case_transport_core_version_negotiation_close_errno
case_test_case "server_refuse_connection" --id native --mode self-reporting --run case_transport_core_server_refuse_connection
case_test_case "linger_close_transport" --id native --mode self-reporting --run case_transport_core_linger_close_transport
case_test_case "linger_close_h3" --id native --mode self-reporting --run case_transport_core_linger_close_h3
case_test_case "stateless_reset" --id native --mode self-reporting --run case_transport_core_stateless_reset
case_test_case "stateless_reset_during_hsk" --id native --mode self-reporting --run case_transport_core_stateless_reset_during_hsk
case_test_case "0rtt_forbidden_remembered_params_normal" --id native --mode self-reporting --run case_transport_core__0rtt_forbidden_remembered_params_normal
case_test_case "0rtt_forbidden_remembered_params_stale_not_used" --id native --mode self-reporting --run case_transport_core__0rtt_forbidden_remembered_params_stale_not_used
case_test_case "check_clear_0rtt_ticket_flag_in_close_notify" --id native --mode self-reporting --run case_transport_core_check_clear_0rtt_ticket_flag_in_close_notify
case_test_case "check_clear_0rtt_ticket_flag_in_h3_close_notify" --id native --mode self-reporting --run case_transport_core_check_clear_0rtt_ticket_flag_in_h3_close_notify
case_test_case "request_closing_notify" --id native --mode self-reporting --run case_transport_core_request_closing_notify
case_test_case "transport_MP_ping" --id native --mode self-reporting --run case_transport_core_transport_MP_ping
case_test_case "0RTT_param_reduction" --id native --mode self-reporting --run case_transport_core__0RTT_param_reduction
case_test_case "0RTT_rejected_param_reduction" --id native --mode self-reporting --run case_transport_core__0RTT_rejected_param_reduction

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
trap 'case_test_stop_server; case_test_cleanup_udp_port' EXIT
case_test_require_sudo

case_test_run
