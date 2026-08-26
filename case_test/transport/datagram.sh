#!/bin/bash
#
# transport.datagram endpoint case-test group.


ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "transport.datagram"

case_transport_datagram_datagram_frame_size_negotiation()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -M -y > /dev/null
sleep 1

grep_err_log


case_test_stop_server
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

case_test_start_server ${SERVER_BIN} -l d -Q 65536 > /dev/null
sleep 1
clear_log
echo -e "datagram frame size negotiation...\c"
${CLIENT_BIN} -l d -Q 65536 >> stdlog
cli_result=`grep "|1RTT_transport_params|max_datagram_frame_size:65536|" clog`
svr_result=`grep "|1RTT_transport_params|max_datagram_frame_size:65536|" slog`
errlog=`grep_err_log`
if [ -n "$cli_result" ] && [ -n "$svr_result" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "datagram_frame_size_negotiation" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "datagram_frame_size_negotiation" "fail"
fi

}

case_transport_datagram__0rtt_max_datagram_frame_size_is_valid()
{

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

}

case_transport_datagram__0rtt_max_datagram_frame_size_is_invalid()
{

case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -Q 8000 > /dev/null
sleep 1
clear_log
echo -e "0RTT max_datagram_frame_size is invalid...\c"
${CLIENT_BIN} -l d >> stdlog
cli_result=`grep "|0RTT_transport_params|max_datagram_frame_size:9000|" clog`
cli_err=`grep "[error].*err:0x55" clog`
svr_err=`grep "[error].*err:0xa" slog`
if [ -n "$cli_result" ] && [ -n "$cli_err" ] && [ -n "$svr_err" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "0rtt_max_datagram_frame_size_is_invalid" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "0rtt_max_datagram_frame_size_is_invalid" "fail"
fi
rm -f test_session tp_localhost xqc_token

# issue #672: RFC 9000 7.4.1 forbidden remembered transport params must not be used in 0-RTT
}

case_transport_datagram_datagram_get_mss_no_saved_transport_params()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1
rm -f test_session tp_localhost xqc_token

case_test_stop_server
if [ -f test_session ]; then
    rm -f test_session
fi
if [ -f tp_localhost ]; then
    rm -f tp_localhost
fi
if [ -f xqc_token ]; then
    rm -f xqc_token
fi
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -Q 1000 -x 200 > svr_stdlog
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

}

case_transport_datagram_datagram_get_mss_saved_transport_params()
{

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

}

case_transport_datagram_datagram_mss_limited_by_MTU()
{

case_test_stop_server
if [ -f test_session ]; then
    rm -f test_session
fi
if [ -f tp_localhost ]; then
    rm -f tp_localhost
fi
if [ -f xqc_token ]; then
    rm -f xqc_token
fi
case_test_start_server stdbuf -oL  ${SERVER_BIN} -l d -Q 65535 -x 201 > svr_stdlog
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

}

case_transport_datagram_timer_based_dgram_probe()
{

case_test_stop_server
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
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -Q 65535 -x 209 -e -U 2 > svr_stdlog
sleep 1
clear_log
echo -e "timer_based_dgram_probe...\c"
${CLIENT_BIN} -l d -T 1 -x 209 -s 1000 -U 1 -Q 65535 -x 209 > stdlog
case_test_stop_server
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

}

case_transport_datagram_datagram_mss_limited_by_max_datagram_frame_size()
{

case_test_stop_server
if [ -f test_session ]; then
    rm -f test_session
fi
if [ -f tp_localhost ]; then
    rm -f tp_localhost
fi
if [ -f xqc_token ]; then
    rm -f xqc_token
fi

case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -Q 1000 -x 200 > svr_stdlog
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

}

case_transport_datagram_send_0RTT_datagram_100KB()
{
rm -f test_session tp_localhost xqc_token

case_test_stop_server

case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null
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

}

case_transport_datagram_send_0RTT_datagram_100KB_batch()
{
case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null
sleep 1

rm -f test_session tp_localhost xqc_token


case_test_stop_server

case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 2 > /dev/null
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

}

case_transport_datagram_send_1RTT_datagram_100KB()
{
case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 2 > /dev/null
sleep 1

rm -f test_session tp_localhost xqc_token


case_test_stop_server
case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null
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

}

case_transport_datagram_send_1RTT_datagram_100KB_batch()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null
sleep 1
rm -f test_session tp_localhost xqc_token


case_test_stop_server
case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 2 > /dev/null
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

}

case_transport_datagram_send_0rtt_datagram_without_saved_datagram_tp()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null
sleep 1

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

}

case_transport_datagram_send_0rtt_datagram_without_saved_datagram_tp_batch()
{

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


}

case_transport_datagram_send_too_many_0rtt_datagrams()
{


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

}

case_transport_datagram_send_too_many_0rtt_datagrams_batch()
{

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

}

case_transport_datagram_send_0rtt_datagram_reject()
{

case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null
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


}

case_transport_datagram_send_oversized_datagram()
{


case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -Q 1000 -e -U 1 -s 1 > /dev/null
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

}

case_transport_datagram_send_oversized_datagram_batch()
{

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

}

case_transport_datagram_send_datagram_while_peer_does_not_support()
{
rm -rf tp_localhost test_session xqc_token

case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -Q 0 -e -U 1 -s 1 > /dev/null
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

}

case_transport_datagram_send_datagram_batch_while_peer_does_not_support()
{

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

}

case_transport_datagram_send_0rtt_datagram_dgram1_lost()
{

case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null
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

}

case_transport_datagram_send_1rtt_datagram_dgram1_lost()
{

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

}

case_transport_datagram_send_0rtt_datagram_reorder()
{

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

}

case_transport_datagram_send_1rtt_datagram_reorder()
{

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

}

case_transport_datagram_datagram_lost_callback()
{

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

}

case_transport_datagram_datagram_acked_callback()
{

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

}

case_transport_datagram__1RTT_datagram_send_redundancy()
{

case_test_stop_server
if [ -f test_session ]; then
    rm -f test_session
fi
if [ -f tp_localhost ]; then
    rm -f tp_localhost
fi
if [ -f xqc_token ]; then
    rm -f xqc_token
fi
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -Q 65535 -x 208 -e -U 1 > svr_stdlog
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

}

case_transport_datagram__1RTT_datagram_send_multiple_redundancy()
{

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


}

case_transport_datagram__0RTT_datagram_send_redundancy()
{


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

}

case_transport_datagram__0RTT_datagram_send_multiple_redundancy()
{

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

}

case_transport_datagram_stop_datagram_send_redundancy_after_negotiation()
{

case_test_stop_server
rm -rf tp_localhost test_session xqc_token
clear_log
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -Q 65535 -x 208 -e -U 1 > svr_stdlog
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


}

case_transport_datagram_send_0RTT_h3_ext_datagram_100KB()
{
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -Q 1000 -x 200 > svr_stdlog
sleep 1
rm -f test_session tp_localhost xqc_token

case_test_stop_server

case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null
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

}

case_transport_datagram_send_0RTT_h3_ext_datagram_100KB_batch()
{
case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null
sleep 1

rm -f test_session tp_localhost xqc_token


case_test_stop_server

case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 2 > /dev/null
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

}

case_transport_datagram_send_1RTT_h3_ext_datagram_100KB()
{
case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 2 > /dev/null
sleep 1

rm -f test_session tp_localhost xqc_token


case_test_stop_server
case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null
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

}

case_transport_datagram_send_1RTT_h3_ext_datagram_100KB_batch()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null
sleep 1
rm -f test_session tp_localhost xqc_token


case_test_stop_server
case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 2 > /dev/null
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

}

case_transport_datagram_send_0rtt_h3_ext_datagram_without_saved_datagram_tp()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null
sleep 1

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

}

case_transport_datagram_send_0rtt_h3_ext_datagram_without_saved_datagram_tp_batch()
{

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


}

case_transport_datagram_send_too_many_0rtt_h3_ext_datagrams()
{


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

}

case_transport_datagram_send_too_many_0rtt_h3_ext_datagrams_batch()
{

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

}

case_transport_datagram_send_0rtt_h3_ext_datagram_reject()
{

case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null
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


}

case_transport_datagram_send_oversized_h3_ext_datagram()
{


case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -Q 1000 -e -U 1 -s 1 > /dev/null
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

}

case_transport_datagram_send_oversized_h3_ext_datagram_batch()
{

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

}

case_transport_datagram_send_h3_ext_datagram_while_peer_does_not_support()
{
rm -rf tp_localhost test_session xqc_token

case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -Q 0 -e -U 1 -s 1 > /dev/null
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

}

case_transport_datagram_send_h3_ext_datagram_batch_while_peer_does_not_support()
{

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

}

case_transport_datagram_send_0rtt_h3_ext_datagram_dgram1_lost()
{

case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null
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

}

case_transport_datagram_send_1rtt_h3_ext_datagram_dgram1_lost()
{

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

}

case_transport_datagram_send_0rtt_h3_ext_datagram_reorder()
{

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

}

case_transport_datagram_send_1rtt_h3_ext_datagram_reorder()
{

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

}

case_transport_datagram__1RTT_h3_ext_datagram_send_redundancy()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null
sleep 1

rm -f test_session tp_localhost xqc_token

case_test_stop_server

case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 -x 208 > /dev/null
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

}

case_transport_datagram__1RTT_h3_ext_datagram_send_multiple_redundancy()
{

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

}

case_transport_datagram__0RTT_h3_ext_datagram_send_redundancy()
{

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

}

case_transport_datagram__0RTT_h3_ext_datagram_send_multiple_redundancy()
{

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

}

case_transport_datagram_SP_reinject_datagrams()
{
case_test_start_server ${SERVER_BIN} -l d -x 14 > /dev/null
sleep 1


case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -M -R 3 -Q 65535 -U 1 > /dev/null
sleep 1

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "SP reinject datagrams ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -R 3 -Q 65535 -U 1 -T 1 > stdlog
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
}

case_transport_datagram_SP_reinject_h3_ext_datagrams()
{
grep_err_log

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "SP reinject h3-ext datagrams ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -R 3 -Q 65535 -U 1 -T 2 > stdlog
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
}

case_transport_datagram_PMTUD_force_enable_peer_omits_option()
{
case_test_stop_server
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -e -Q 65535 -U 1 -x 711 > /dev/null
sleep 1

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "PMTUD force enable with peer option omitted...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 711 -Q 65535 -U 1 -T 1 > stdlog
sleep 1
result=`grep "\[dgram\]|recv_dgram_bytes:1024|sent_dgram_bytes:1024|" stdlog`
probe_res=`grep "\[dgram\]|mss_callback|updated_mss:1404|" stdlog`
cli_res=`grep -E "xqc_conn_destroy.*enable_pmtud:1" clog`
svr_res=`grep -E "xqc_conn_destroy.*enable_pmtud:0" slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$probe_res" ] \
    && [ -n "$cli_res" ] && [ -n "$svr_res" ]
then
    echo ">>>>>>>> pass:1"
    case_print_result "PMTUD_force_enable_peer_omits_option" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "PMTUD_force_enable_peer_omits_option" "fail"
fi
grep_err_log
}

case_transport_datagram_PMTUD_negotiated_mode_peer_omits_option()
{
case_test_stop_server
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -e -Q 65535 -U 1 -x 712 > /dev/null
sleep 1

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "PMTUD negotiated mode with peer option omitted...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 712 -Q 65535 -U 1 -T 1 > stdlog
sleep 1
result=`grep "\[dgram\]|recv_dgram_bytes:1024|sent_dgram_bytes:1024|" stdlog`
probe_res=`grep "\[dgram\]|mss_callback|updated_mss:1404|" stdlog`
cli_res=`grep -E "xqc_conn_destroy.*enable_pmtud:0" clog`
svr_res=`grep -E "xqc_conn_destroy.*enable_pmtud:0" slog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -z "$probe_res" ] \
    && [ -n "$cli_res" ] && [ -n "$svr_res" ]
then
    echo ">>>>>>>> pass:1"
    case_print_result "PMTUD_negotiated_mode_peer_omits_option" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "PMTUD_negotiated_mode_peer_omits_option" "fail"
fi
grep_err_log
}

case_transport_datagram_SP_datagram_PMTUD_1RTT()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -M -x 208 -Q 65535 -U 1 --dgram_qos 3 > /dev/null
sleep 1


rm -rf tp_localhost test_session xqc_token
grep_err_log


case_test_stop_server
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -e -M -Q 65535 -U 1 --pmtud 1 -x 200 > svr_stdlog
sleep 1

rm -rf tp_localhost test_session xqc_token
> svr_stdlog
clear_log
echo -e "SP datagram PMTUD 1RTT...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -Q 65535 -U 1 -T 1 --pmtud 1 > stdlog
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
}

case_transport_datagram_SP_datagram_PMTUD_0RTT()
{
grep_err_log

> svr_stdlog
clear_log
echo -e "SP datagram PMTUD 0RTT...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -Q 65535 -U 1 -T 1 --pmtud 1 > stdlog
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
}

case_transport_datagram_SP_h3_ext_datagram_PMTUD_1RTT()
{
grep_err_log

rm -rf tp_localhost test_session xqc_token
> svr_stdlog
clear_log
echo -e "SP h3-ext datagram PMTUD 1RTT...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -Q 65535 -U 1 -T 2 --pmtud 1 > stdlog
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
}

case_transport_datagram_SP_h3_ext_datagram_PMTUD_0RTT()
{
grep_err_log

> svr_stdlog
clear_log
echo -e "SP h3-ext datagram PMTUD 0RTT...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -Q 65535 -U 1 -T 2 --pmtud 1 > stdlog
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
}

case_test_case "datagram_frame_size_negotiation" --id native --mode self-reporting --run case_transport_datagram_datagram_frame_size_negotiation
case_test_case "0rtt_max_datagram_frame_size_is_valid" --id native --mode self-reporting --run case_transport_datagram__0rtt_max_datagram_frame_size_is_valid
case_test_case "0rtt_max_datagram_frame_size_is_invalid" --id native --mode self-reporting --run case_transport_datagram__0rtt_max_datagram_frame_size_is_invalid
case_test_case "datagram_get_mss_no_saved_transport_params" --id native --mode self-reporting --run case_transport_datagram_datagram_get_mss_no_saved_transport_params
case_test_case "datagram_get_mss_saved_transport_params" --id native --mode self-reporting --run case_transport_datagram_datagram_get_mss_saved_transport_params
case_test_case "datagram_mss_limited_by_MTU" --id native --mode self-reporting --run case_transport_datagram_datagram_mss_limited_by_MTU
case_test_case "timer_based_dgram_probe" --id native --mode self-reporting --run case_transport_datagram_timer_based_dgram_probe
case_test_case "datagram_mss_limited_by_max_datagram_frame_size" --id native --mode self-reporting --run case_transport_datagram_datagram_mss_limited_by_max_datagram_frame_size
case_test_case "send_0RTT_datagram_100KB" --id native --mode self-reporting --run case_transport_datagram_send_0RTT_datagram_100KB
case_test_case "send_0RTT_datagram_100KB_batch" --id native --mode self-reporting --run case_transport_datagram_send_0RTT_datagram_100KB_batch
case_test_case "send_1RTT_datagram_100KB" --id native --mode self-reporting --run case_transport_datagram_send_1RTT_datagram_100KB
case_test_case "send_1RTT_datagram_100KB_batch" --id native --mode self-reporting --run case_transport_datagram_send_1RTT_datagram_100KB_batch
case_test_case "send_0rtt_datagram_without_saved_datagram_tp" --id native --mode self-reporting --run case_transport_datagram_send_0rtt_datagram_without_saved_datagram_tp
case_test_case "send_0rtt_datagram_without_saved_datagram_tp_batch" --id native --mode self-reporting --run case_transport_datagram_send_0rtt_datagram_without_saved_datagram_tp_batch
case_test_case "send_too_many_0rtt_datagrams" --id native --mode self-reporting --run case_transport_datagram_send_too_many_0rtt_datagrams
case_test_case "send_too_many_0rtt_datagrams_batch" --id native --mode self-reporting --run case_transport_datagram_send_too_many_0rtt_datagrams_batch
case_test_case "send_0rtt_datagram_reject" --id native --mode self-reporting --run case_transport_datagram_send_0rtt_datagram_reject
case_test_case "send_oversized_datagram" --id native --mode self-reporting --run case_transport_datagram_send_oversized_datagram
case_test_case "send_oversized_datagram_batch" --id native --mode self-reporting --run case_transport_datagram_send_oversized_datagram_batch
case_test_case "send_datagram_while_peer_does_not_support" --id native --mode self-reporting --run case_transport_datagram_send_datagram_while_peer_does_not_support
case_test_case "send_datagram_batch_while_peer_does_not_support" --id native --mode self-reporting --run case_transport_datagram_send_datagram_batch_while_peer_does_not_support
case_test_case "send_0rtt_datagram_dgram1_lost" --id native --mode self-reporting --run case_transport_datagram_send_0rtt_datagram_dgram1_lost
case_test_case "send_1rtt_datagram_dgram1_lost" --id native --mode self-reporting --run case_transport_datagram_send_1rtt_datagram_dgram1_lost
case_test_case "send_0rtt_datagram_reorder" --id native --mode self-reporting --run case_transport_datagram_send_0rtt_datagram_reorder
case_test_case "send_1rtt_datagram_reorder" --id native --mode self-reporting --run case_transport_datagram_send_1rtt_datagram_reorder
case_test_case "datagram_lost_callback" --id native --mode self-reporting --run case_transport_datagram_datagram_lost_callback
case_test_case "datagram_acked_callback" --id native --mode self-reporting --run case_transport_datagram_datagram_acked_callback
case_test_case "1RTT_datagram_send_redundancy" --id native --mode self-reporting --run case_transport_datagram__1RTT_datagram_send_redundancy
case_test_case "1RTT_datagram_send_multiple_redundancy" --id native --mode self-reporting --run case_transport_datagram__1RTT_datagram_send_multiple_redundancy
case_test_case "0RTT_datagram_send_redundancy" --id native --mode self-reporting --run case_transport_datagram__0RTT_datagram_send_redundancy
case_test_case "0RTT_datagram_send_multiple_redundancy" --id native --mode self-reporting --run case_transport_datagram__0RTT_datagram_send_multiple_redundancy
case_test_case "stop_datagram_send_redundancy_after_negotiation" --id native --mode self-reporting --run case_transport_datagram_stop_datagram_send_redundancy_after_negotiation
case_test_case "send_0RTT_h3_ext_datagram_100KB" --id native --mode self-reporting --run case_transport_datagram_send_0RTT_h3_ext_datagram_100KB
case_test_case "send_0RTT_h3_ext_datagram_100KB_batch" --id native --mode self-reporting --run case_transport_datagram_send_0RTT_h3_ext_datagram_100KB_batch
case_test_case "send_1RTT_h3_ext_datagram_100KB" --id native --mode self-reporting --run case_transport_datagram_send_1RTT_h3_ext_datagram_100KB
case_test_case "send_1RTT_h3_ext_datagram_100KB_batch" --id native --mode self-reporting --run case_transport_datagram_send_1RTT_h3_ext_datagram_100KB_batch
case_test_case "send_0rtt_h3_ext_datagram_without_saved_datagram_tp" --id native --mode self-reporting --run case_transport_datagram_send_0rtt_h3_ext_datagram_without_saved_datagram_tp
case_test_case "send_0rtt_h3_ext_datagram_without_saved_datagram_tp_batch" --id native --mode self-reporting --run case_transport_datagram_send_0rtt_h3_ext_datagram_without_saved_datagram_tp_batch
case_test_case "send_too_many_0rtt_h3_ext_datagrams" --id native --mode self-reporting --run case_transport_datagram_send_too_many_0rtt_h3_ext_datagrams
case_test_case "send_too_many_0rtt_h3_ext_datagrams_batch" --id native --mode self-reporting --run case_transport_datagram_send_too_many_0rtt_h3_ext_datagrams_batch
case_test_case "send_0rtt_h3_ext_datagram_reject" --id native --mode self-reporting --run case_transport_datagram_send_0rtt_h3_ext_datagram_reject
case_test_case "send_oversized_h3_ext_datagram" --id native --mode self-reporting --run case_transport_datagram_send_oversized_h3_ext_datagram
case_test_case "send_oversized_h3_ext_datagram_batch" --id native --mode self-reporting --run case_transport_datagram_send_oversized_h3_ext_datagram_batch
case_test_case "send_h3_ext_datagram_while_peer_does_not_support" --id native --mode self-reporting --run case_transport_datagram_send_h3_ext_datagram_while_peer_does_not_support
case_test_case "send_h3_ext_datagram_batch_while_peer_does_not_support" --id native --mode self-reporting --run case_transport_datagram_send_h3_ext_datagram_batch_while_peer_does_not_support
case_test_case "send_0rtt_h3_ext_datagram_dgram1_lost" --id native --mode self-reporting --run case_transport_datagram_send_0rtt_h3_ext_datagram_dgram1_lost
case_test_case "send_1rtt_h3_ext_datagram_dgram1_lost" --id native --mode self-reporting --run case_transport_datagram_send_1rtt_h3_ext_datagram_dgram1_lost
case_test_case "send_0rtt_h3_ext_datagram_reorder" --id native --mode self-reporting --run case_transport_datagram_send_0rtt_h3_ext_datagram_reorder
case_test_case "send_1rtt_h3_ext_datagram_reorder" --id native --mode self-reporting --run case_transport_datagram_send_1rtt_h3_ext_datagram_reorder
case_test_case "1RTT_h3_ext_datagram_send_redundancy" --id native --mode self-reporting --run case_transport_datagram__1RTT_h3_ext_datagram_send_redundancy
case_test_case "1RTT_h3_ext_datagram_send_multiple_redundancy" --id native --mode self-reporting --run case_transport_datagram__1RTT_h3_ext_datagram_send_multiple_redundancy
case_test_case "0RTT_h3_ext_datagram_send_redundancy" --id native --mode self-reporting --run case_transport_datagram__0RTT_h3_ext_datagram_send_redundancy
case_test_case "0RTT_h3_ext_datagram_send_multiple_redundancy" --id native --mode self-reporting --run case_transport_datagram__0RTT_h3_ext_datagram_send_multiple_redundancy
case_test_case "SP_reinject_datagrams" --id native --mode self-reporting --run case_transport_datagram_SP_reinject_datagrams
case_test_case "SP_reinject_h3_ext_datagrams" --id native --mode self-reporting --run case_transport_datagram_SP_reinject_h3_ext_datagrams
case_test_case "PMTUD_force_enable_peer_omits_option" --id native --mode self-reporting --run case_transport_datagram_PMTUD_force_enable_peer_omits_option
case_test_case "PMTUD_negotiated_mode_peer_omits_option" --id native --mode self-reporting --run case_transport_datagram_PMTUD_negotiated_mode_peer_omits_option
case_test_case "SP_datagram_PMTUD_1RTT" --id native --mode self-reporting --run case_transport_datagram_SP_datagram_PMTUD_1RTT
case_test_case "SP_datagram_PMTUD_0RTT" --id native --mode self-reporting --run case_transport_datagram_SP_datagram_PMTUD_0RTT
case_test_case "SP_h3_ext_datagram_PMTUD_1RTT" --id native --mode self-reporting --run case_transport_datagram_SP_h3_ext_datagram_PMTUD_1RTT
case_test_case "SP_h3_ext_datagram_PMTUD_0RTT" --id native --mode self-reporting --run case_transport_datagram_SP_h3_ext_datagram_PMTUD_0RTT

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
trap 'case_test_stop_server; case_test_cleanup_udp_port' EXIT
case_test_require_sudo

case_test_run
