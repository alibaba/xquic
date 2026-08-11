#!/bin/bash
#
# http3.ext endpoint case-test group.


ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "http3.ext"

case_http3_ext_h3_ext_bytestream_send_pure_fin()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 99 > /dev/null
sleep 1

rm -f test_session tp_localhost xqc_token


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

}

case_http3_ext_h3_ext_datagram_get_mss_no_saved_transport_params()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 208 -Q 65535 -U 1 --dgram_qos 3 > /dev/null
sleep 1

rm -rf tp_localhost test_session xqc_token
grep_err_log


# h3 ext datagram

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

}

case_http3_ext_h3_ext_datagram_get_mss_saved_transport_params()
{

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

}

case_http3_ext_h3_ext_datagram_mss_limited_by_MTU()
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

}

case_http3_ext_h3_ext_datagram_mss_limited_by_max_datagram_frame_size()
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

}

case_http3_ext_h3_ext_dgram_send_queue_full()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 2 > /dev/null
sleep 1
rm -f test_session tp_localhost xqc_token

case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null
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

}

case_http3_ext_h3_ext_dgram_send_queue_full_batch()
{

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

}

case_http3_ext_h3_ext_datagram_lost_callback()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 > /dev/null
sleep 1

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

}

case_http3_ext_h3_ext_datagram_acked_callback()
{

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

}

case_http3_ext_h3_ext_1RTT_send_test()
{
case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 -x 208 > /dev/null
sleep 1



# send h3 request / bytestream / datagram in one h3_conn (-x 300)

rm -f test_session tp_localhost xqc_token

case_test_stop_server

case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null
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
}

case_http3_ext_h3_ext_0RTT_accept_send_test()
{

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

}

case_http3_ext_h3_ext_0RTT_reject_send_test()
{

## 0RTT reject

case_test_stop_server

case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null
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
}

case_http3_ext_h3_ext_1RTT_concurrent_send_test()
{

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
}

case_http3_ext_h3_ext_0RTT_accept_concurrent_send_test()
{

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

}

case_http3_ext_h3_ext_0RTT_reject_concurrent_send_test()
{

## 0RTT reject

case_test_stop_server

case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null
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

}

case_http3_ext_h3_ext_1RTT_send_pure_fin1()
{


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

}

case_http3_ext_h3_ext_1RTT_send_pure_fin2()
{

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

}

case_http3_ext_h3_ext_0RTT_accept_send_pure_fin1()
{

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

}

case_http3_ext_h3_ext_0RTT_accept_send_pure_fin2()
{

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

}

case_http3_ext_h3_ext_0RTT_reject_send_pure_fin1()
{

## 0RTT reject

case_test_stop_server

case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null
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

}

case_http3_ext_h3_ext_0RTT_reject_send_pure_fin2()
{

case_test_stop_server

case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null
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

}

case_http3_ext_h3_ext_finish_bytestream_during_transmission()
{

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

}

case_http3_ext_h3_ext_close_bytestream_during_transmission()
{

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

}

case_http3_ext_h3_ext_bytestream_blocked_by_stream_flowctl()
{

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

}

case_http3_ext_h3_ext_bytestream_blocked_by_0RTT_limit()
{

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

}

case_http3_ext_h3_ext_bytestream_blocked_by_no_0RTT_support()
{

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

}

case_http3_ext_h3_ext_bytestream_blocked_by_sndq_full()
{

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

}

case_http3_ext_h3_ext_bytestream_full_message_under_flow_ctrl()
{

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

}

case_http3_ext_h3_ext_bytestream_full_message_0RTT_blocking()
{

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

}

case_http3_ext_h3_ext_bytestream_full_message_no_0RTT_suppport()
{

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

}

case_http3_ext_h3_ext_bytestream_full_message_sndq_full()
{

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

}

case_http3_ext_connect_to_an_h3_ext_disabled_server()
{

case_test_stop_server

case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 -H > /dev/null
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

}

case_http3_ext_h3_ext_is_disabled_on_the_client()
{

case_test_stop_server

case_test_start_server ${SERVER_BIN} -l e -Q 65535 -e -U 1 > /dev/null
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
}

case_test_case "h3_ext_bytestream_send_pure_fin" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_bytestream_send_pure_fin
case_test_case "h3_ext_datagram_get_mss_no_saved_transport_params" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_datagram_get_mss_no_saved_transport_params
case_test_case "h3_ext_datagram_get_mss_saved_transport_params" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_datagram_get_mss_saved_transport_params
case_test_case "h3_ext_datagram_mss_limited_by_MTU" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_datagram_mss_limited_by_MTU
case_test_case "h3_ext_datagram_mss_limited_by_max_datagram_frame_size" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_datagram_mss_limited_by_max_datagram_frame_size
case_test_case "h3_ext_dgram_send_queue_full" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_dgram_send_queue_full
case_test_case "h3_ext_dgram_send_queue_full_batch" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_dgram_send_queue_full_batch
case_test_case "h3_ext_datagram_lost_callback" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_datagram_lost_callback
case_test_case "h3_ext_datagram_acked_callback" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_datagram_acked_callback
case_test_case "h3_ext_1RTT_send_test" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_1RTT_send_test
case_test_case "h3_ext_0RTT_accept_send_test" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_0RTT_accept_send_test
case_test_case "h3_ext_0RTT_reject_send_test" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_0RTT_reject_send_test
case_test_case "h3_ext_1RTT_concurrent_send_test" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_1RTT_concurrent_send_test
case_test_case "h3_ext_0RTT_accept_concurrent_send_test" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_0RTT_accept_concurrent_send_test
case_test_case "h3_ext_0RTT_reject_concurrent_send_test" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_0RTT_reject_concurrent_send_test
case_test_case "h3_ext_1RTT_send_pure_fin1" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_1RTT_send_pure_fin1
case_test_case "h3_ext_1RTT_send_pure_fin2" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_1RTT_send_pure_fin2
case_test_case "h3_ext_0RTT_accept_send_pure_fin1" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_0RTT_accept_send_pure_fin1
case_test_case "h3_ext_0RTT_accept_send_pure_fin2" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_0RTT_accept_send_pure_fin2
case_test_case "h3_ext_0RTT_reject_send_pure_fin1" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_0RTT_reject_send_pure_fin1
case_test_case "h3_ext_0RTT_reject_send_pure_fin2" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_0RTT_reject_send_pure_fin2
case_test_case "h3_ext_finish_bytestream_during_transmission" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_finish_bytestream_during_transmission
case_test_case "h3_ext_close_bytestream_during_transmission" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_close_bytestream_during_transmission
case_test_case "h3_ext_bytestream_blocked_by_stream_flowctl" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_bytestream_blocked_by_stream_flowctl
case_test_case "h3_ext_bytestream_blocked_by_0RTT_limit" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_bytestream_blocked_by_0RTT_limit
case_test_case "h3_ext_bytestream_blocked_by_no_0RTT_support" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_bytestream_blocked_by_no_0RTT_support
case_test_case "h3_ext_bytestream_blocked_by_sndq_full" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_bytestream_blocked_by_sndq_full
case_test_case "h3_ext_bytestream_full_message_under_flow_ctrl" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_bytestream_full_message_under_flow_ctrl
case_test_case "h3_ext_bytestream_full_message_0RTT_blocking" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_bytestream_full_message_0RTT_blocking
case_test_case "h3_ext_bytestream_full_message_no_0RTT_suppport" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_bytestream_full_message_no_0RTT_suppport
case_test_case "h3_ext_bytestream_full_message_sndq_full" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_bytestream_full_message_sndq_full
case_test_case "connect_to_an_h3_ext_disabled_server" --id legacy --mode self-reporting --run case_http3_ext_connect_to_an_h3_ext_disabled_server
case_test_case "h3_ext_is_disabled_on_the_client" --id legacy --mode self-reporting --run case_http3_ext_h3_ext_is_disabled_on_the_client

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
trap case_test_stop_server EXIT

case_test_run
