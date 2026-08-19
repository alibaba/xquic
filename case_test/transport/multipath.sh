#!/bin/bash
#
# transport.multipath endpoint case-test group.


ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "transport.multipath"

case_test_group_setup()
{
    case_test_start_server ${SERVER_BIN} -l d -e -M > /dev/null
    sleep 1
}

case_transport_multipath_MPNS_enable_multipath_negotiate()
{
case_test_start_server ${SERVER_BIN} -l d > /dev/null

case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -M > /dev/null
sleep 1


clear_log
echo -e "MPNS enable multipath negotiate ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024000 -l d -t 1 -M -i lo > stdlog
result=` grep "enable_multipath=1" stdlog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MPNS_enable_multipath_negotiate" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MPNS_enable_multipath_negotiate" "fail"
fi
}

case_transport_multipath_MPNS_send_1M_data_on_multiple_paths()
{
grep_err_log

clear_log
echo -e "MPNS send 1M data on multiple paths ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024000 -l d -t 1 -M -i lo -i lo -E > stdlog
result=`grep ">>>>>>>> pass" stdlog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MPNS_send_1M_data_on_multiple_paths" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MPNS_send_1M_data_on_multiple_paths" "fail"
fi
}

case_transport_multipath_MPNS_multipath_30_percent_loss()
{
grep_err_log

echo -e "MPNS multipath 30 percent loss ...\c"
mpns_loss_pass=0
mpns_loss_attempt=1
while [ $mpns_loss_attempt -le 2 ]; do
    clear_log
    if [ $mpns_loss_attempt -gt 1 ]; then
        echo -e " retry ${mpns_loss_attempt} ...\c"
    fi
    case_test_sudo ${CLIENT_BIN} -s 5242880 -t 20 -l e -E -d 300 -M -i lo -i lo > stdlog
    result=`grep ">>>>>>>> pass:1" stdlog`
    errlog=`grep_err_log`
    if [ -z "$errlog" ] && [ -n "$result" ]; then
        mpns_loss_pass=1
        break
    fi
    if [ $mpns_loss_attempt -ge 2 ] || ! case_test_should_retry_timeout_or_no_result stdlog "$errlog"; then
        break
    fi
    mpns_loss_attempt=$((mpns_loss_attempt + 1))
done
if [ $mpns_loss_pass -eq 1 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MPNS_multipath_30_percent_loss" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MPNS_multipath_30_percent_loss" "fail"
fi
}

case_transport_multipath_MPNS_multipath_close_initial_path()
{
grep_err_log

clear_log
echo -e "MPNS multipath close initial path ...\c"
case_test_sudo ${CLIENT_BIN} -s 10240 -l d -t 5 -M -i lo -i lo -E -x 100 -e 10 --epoch_timeout 1000000 > stdlog
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
}

case_transport_multipath_MPNS_multipath_30_percent_loss_close_initial_path()
{
grep_err_log

echo -e "MPNS multipath 30 percent loss close initial path ...\c"
mpns_loss_close_initial_pass=0
mpns_loss_close_initial_attempt=1
while [ $mpns_loss_close_initial_attempt -le 2 ]; do
    clear_log
    if [ $mpns_loss_close_initial_attempt -gt 1 ]; then
        echo -e " retry ${mpns_loss_close_initial_attempt} ...\c"
    fi
    case_test_sudo ${CLIENT_BIN} -s 10240 -t 25 -l d -E -d 300 -M -A -i lo -i lo -x 100 -e 10 --epoch_timeout 2000000 > stdlog
    result_fail=`grep ">>>>>>>> pass:0" stdlog`
    result_pass=`grep ">>>>>>>> pass:1" stdlog`
    errlog=`grep_err_log`
    for wait_idx in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        svr_res=`grep "|path closed|path:0|" slog`
        cli_res=`grep "|path closed|path:0|" clog`
        if [ -n "$svr_res" ] && [ -n "$cli_res" ]; then
            break
        fi
        sleep 0.2
    done
    if [ -z "$errlog" ] && [ -z "$result_fail" ] && [ -n "$result_pass" ] && [ "$svr_res" != "" ] && [ "$cli_res" != "" ]; then
        mpns_loss_close_initial_pass=1
        break
    fi
    if [ $mpns_loss_close_initial_attempt -ge 2 ]; then
        break
    fi
    if [ -z "$errlog" ] && [ -z "$result_fail" ] && [ -n "$result_pass" ]; then
        mpns_loss_close_initial_attempt=$((mpns_loss_close_initial_attempt + 1))
        continue
    fi
    if ! case_test_should_retry_timeout_or_no_result stdlog "$errlog"; then
        break
    fi
    mpns_loss_close_initial_attempt=$((mpns_loss_close_initial_attempt + 1))
done
if [ $mpns_loss_close_initial_pass -eq 1 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MPNS_multipath_30_percent_loss_close_initial_path" "pass"
else
    [ -n "$result_pass" ] && result_pass_hit=1 || result_pass_hit=0
    [ -n "$result_fail" ] && result_fail_hit=1 || result_fail_hit=0
    [ -n "$svr_res" ] && svr_closed_hit=1 || svr_closed_hit=0
    [ -n "$cli_res" ] && cli_closed_hit=1 || cli_closed_hit=0
    [ -n "$errlog" ] && errlog_hit=1 || errlog_hit=0
    echo ">>>>>>>> pass:0"
    echo "[mpns-loss-close-initial]|result_pass:${result_pass_hit}|result_fail:${result_fail_hit}|svr_closed:${svr_closed_hit}|cli_closed:${cli_closed_hit}|errlog:${errlog_hit}|"
    case_print_result "MPNS_multipath_30_percent_loss_close_initial_path" "fail"
fi
}

case_transport_multipath_MPNS_multipath_close_new_path()
{
grep_err_log



clear_log
echo -e "MPNS multipath close new path ...\c"
case_test_sudo ${CLIENT_BIN} -s 10240 -l d -t 5 -M -A -i lo -i lo -E -x 101 -e 10 --epoch_timeout 1000000 >> clog
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
}

case_transport_multipath_MPNS_multipath_30_percent_loss_close_new_path()
{
grep_err_log

echo -e "MPNS multipath 30 percent loss close new path ...\c"
mpns_loss_close_new_pass=0
mpns_loss_close_new_attempt=1
while [ $mpns_loss_close_new_attempt -le 2 ]; do
    clear_log
    if [ $mpns_loss_close_new_attempt -gt 1 ]; then
        echo -e " retry ${mpns_loss_close_new_attempt} ...\c"
    fi
    case_test_sudo ${CLIENT_BIN} -s 10240 -t 20 -l d -E -d 300 -M -i lo -i lo -x 101 -e 10 --epoch_timeout 1000000 > stdlog
    result_fail=`grep ">>>>>>>> pass:0" stdlog`
    result_pass=`grep ">>>>>>>> pass:1" stdlog`
    svr_res=`grep "|path closed|path:1|" slog`
    cli_res=`grep "|path closed|path:1|" clog`
    errlog=`grep_err_log`
    if [ -z "$errlog" ] && [ -z "$result_fail" ] && [ -n "$result_pass" ] && [ "$svr_res" != "" ] && [ "$cli_res" != "" ]; then
        mpns_loss_close_new_pass=1
        break
    fi
    if [ $mpns_loss_close_new_attempt -ge 2 ] || ! case_test_should_retry_timeout_or_no_result stdlog "$errlog"; then
        break
    fi
    mpns_loss_close_new_attempt=$((mpns_loss_close_new_attempt + 1))
done
if [ $mpns_loss_close_new_pass -eq 1 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MPNS_multipath_30_percent_loss_close_new_path" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MPNS_multipath_30_percent_loss_close_new_path" "fail"
fi
}

case_transport_multipath_MPNS_send_data_with_multipath_10()
{
grep_err_log

case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -M > /dev/null
sleep 1


clear_log
echo -e "send 1M data on multiple paths with multipath version 10"
case_test_sudo ${CLIENT_BIN} -s 1024000 -l d -t 1 -M -i lo -i lo -E -v 10 > stdlog
cli_result=`grep "multipath version negotiation succeed on multipath 010" clog`
if [ -n "$cli_result" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MPNS_send_data_with_multipath_10" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MPNS_send_data_with_multipath_10" "fail"
fi
rm -f test_session tp_localhost xqc_token

}

case_transport_multipath_MPNS_reinject_unack_packets_by_capacity()
{
rm -f test_session tp_localhost xqc_token

case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -M -R 1 > /dev/null
sleep 1

clear_log
echo -e "MPNS reinject unack packets by capacity ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024000 -l d -t 1 -M -i lo -i lo -E -R 1 > stdlog
result=`grep ">>>>>>>> pass" stdlog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MPNS_reinject_unack_packets_by_capacity" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MPNS_reinject_unack_packets_by_capacity" "fail"
fi
}

case_transport_multipath_MPNS_reinject_unack_packets_by_deadline()
{
grep_err_log


case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -M -R 2 > /dev/null
sleep 1

clear_log
echo -e "MPNS reinject unack packets by deadline ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024000 -l d -t 1 -M -i lo -i lo -E -R 2 > stdlog
result=`grep ">>>>>>>> pass" stdlog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MPNS_reinject_unack_packets_by_deadline" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MPNS_reinject_unack_packets_by_deadline" "fail"
fi
}

case_transport_multipath_NAT_rebinding_path_0()
{
grep_err_log


case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -M > /dev/null
sleep 1

echo -e "NAT rebinding path 0 ...\c"
nat_rebinding_path0_pass=0
nat_rebinding_path0_attempt=1
while [ $nat_rebinding_path0_attempt -le 2 ]; do
    clear_log
    if [ $nat_rebinding_path0_attempt -gt 1 ]; then
        echo -e " retry ${nat_rebinding_path0_attempt} ...\c"
    fi
    case_test_sudo ${CLIENT_BIN} -s 102400 -l d -t 8 -M -i lo -i lo -E -n 2 -x 103 > stdlog
    result=`grep ">>>>>>>> pass:0" stdlog`
    errlog=`grep_err_log | grep -v "no match path challenge data" || true`
    for wait_idx in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        rebind=`grep "|path:0|REBINDING|validate NAT rebinding addr|" slog`
        if [ -n "$rebind" ]; then
            break
        fi
        sleep 0.2
    done
    if [ -z "$errlog" ] && [ -z "$result" ] && [ "$rebind" != "" ]; then
        nat_rebinding_path0_pass=1
        break
    fi
    if [ $nat_rebinding_path0_attempt -ge 2 ]; then
        break
    fi
    if [ -n "$errlog" ] || [ -n "$result" ]; then
        break
    fi
    nat_rebinding_path0_attempt=$((nat_rebinding_path0_attempt + 1))
done
if [ $nat_rebinding_path0_pass -eq 1 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "NAT_rebinding_path_0" "pass"
else
    [ -n "$errlog" ] && errlog_hit=1 || errlog_hit=0
    [ -n "$result" ] && result_fail_hit=1 || result_fail_hit=0
    [ -n "$rebind" ] && rebind_hit=1 || rebind_hit=0
    echo ">>>>>>>> pass:0"
    echo "[nat-rebinding-path0]|result_fail:${result_fail_hit}|rebind:${rebind_hit}|errlog:${errlog_hit}|"
    echo $errlog
    echo $result
    echo $rebind
    case_print_result "NAT_rebinding_path_0" "fail"
fi
}

case_transport_multipath_NAT_rebinding_path_1()
{
grep_err_log

clear_log
echo -e "NAT rebinding path 1 ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024000 -l d -t 3 -M -i lo -i lo -E -n 2 -x 104 > stdlog
result=`grep ">>>>>>>> pass:0" stdlog`
errlog=`grep_err_log | grep -v "no match path challenge data" || true`
rebind=`grep "|path:1|REBINDING|validate NAT rebinding addr|" slog`
if [ -z "$errlog" ] && [ -z "$result" ] && [ "$rebind" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "NAT_rebinding_path_1" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "NAT_rebinding_path_1" "fail"
fi
}

case_transport_multipath_Multipath_Compensate_and_Accelerate()
{
grep_err_log

case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -M -y > /dev/null
sleep 1

clear_log
echo -e "Multipath Compensate and Accelerate ...\c"
case_test_sudo ${CLIENT_BIN} -s 102400 -l d -t 3 -M -A -i lo -i lo -E -P 2 -y > ccfc.log
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
}

case_transport_multipath_No_reinjection_for_normal_datagrams()
{
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -Q 65535 -x 208 -e -U 1 > svr_stdlog
sleep 1



case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 208 -Q 65535 -U 1 --dgram_qos 3 > /dev/null
sleep 1

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "No reinjection for normal datagrams...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 208 -Q 65535 -U 1 -T 1 --dgram_qos 3 > stdlog
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
}

case_transport_multipath_No_reinjection_for_normal_h3_ext_datagrams()
{
grep_err_log

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "No reinjection for normal h3-ext datagrams...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 208 -Q 65535 -U 1 -T 2 --dgram_qos 3 > stdlog
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
}

case_transport_multipath_MP_reinject_datagrams()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -M -R 3 -Q 65535 -U 1 > /dev/null
sleep 1

rm -rf tp_localhost test_session xqc_token
grep_err_log


rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "MP reinject datagrams ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -R 3 -Q 65535 -U 1 -T 1 -M -i lo -i lo > stdlog
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
}

case_transport_multipath_MP_reinject_h3_ext_datagrams()
{
grep_err_log

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "MP reinject h3-ext datagrams ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -R 3 -Q 65535 -U 1 -T 2 -M -i lo -i lo > stdlog
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
}

case_transport_multipath_MP_datagrams_redundancy()
{
grep_err_log


case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -M -x 208 -Q 65535 -U 1 > /dev/null
sleep 1


rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "MP datagrams redundancy...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 208 -Q 65535 -U 1 -T 1 -M -i lo -i lo > stdlog
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
}

case_transport_multipath_MP_h3_ext_datagrams_redundancy()
{
grep_err_log

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "MP h3-ext datagrams redundancy...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 208 -Q 65535 -U 1 -T 2 -M -i lo -i lo > stdlog
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
}

case_transport_multipath_MP_no_reinjection_for_normal_datagrams()
{
grep_err_log


case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -M -x 208 -Q 65535 -U 1 --dgram_qos 3 > /dev/null
sleep 1


rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "MP no reinjection for normal datagrams...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 208 -Q 65535 -U 1 -T 1 -M -i lo -i lo --dgram_qos 3 > stdlog
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
}

case_transport_multipath_MP_no_reinjection_for_normal_h3_ext_datagrams()
{
grep_err_log

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "MP no reinjection for normal h3-ext datagrams...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 208 -Q 65535 -U 1 -T 2 -M -i lo -i lo --dgram_qos 3 > stdlog
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
}

case_transport_multipath_MP_datagram_PMTUD_1RTT()
{
case_test_stop_server
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -e -M -Q 65535 -U 1 --pmtud 1 -x 200 > svr_stdlog
sleep 1

rm -rf tp_localhost test_session xqc_token
grep_err_log


rm -rf tp_localhost test_session xqc_token
> svr_stdlog
clear_log
echo -e "MP datagram PMTUD 1RTT...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -Q 65535 -U 1 -T 1 --pmtud 1 -M -i lo -i lo > stdlog
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
}

case_transport_multipath_MP_datagram_PMTUD_0RTT()
{
grep_err_log

> svr_stdlog
clear_log
echo -e "MP datagram PMTUD 0RTT...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -Q 65535 -U 1 -T 1 --pmtud 1 -M -i lo -i lo > stdlog
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
}

case_transport_multipath_MP_h3_ext_datagram_PMTUD_1RTT()
{
grep_err_log

rm -rf tp_localhost test_session xqc_token
> svr_stdlog
clear_log
echo -e "MP h3-ext datagram PMTUD 1RTT...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -Q 65535 -U 1 -T 2 --pmtud 1 -M -i lo -i lo > stdlog
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
}

case_transport_multipath_MP_h3_ext_datagram_PMTUD_0RTT()
{
grep_err_log

> svr_stdlog
clear_log
echo -e "MP h3-ext datagram PMTUD 0RTT...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -Q 65535 -U 1 -T 2 --pmtud 1 -M -i lo -i lo > stdlog
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
}

case_transport_multipath_freeze_path0()
{
case_test_stop_server
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -e -M > /dev/null
sleep 1

rm -rf tp_localhost test_session xqc_token


rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "freeze path0 ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024000 -l d -E -e 4 -T 2 --epoch_timeout 2000000 -t 4 -M -i lo -i lo -x 107 > stdlog
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
}

case_transport_multipath_freeze_path1()
{

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "freeze path1 ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024000 -l d -E -e 4 -T 2 --epoch_timeout 2000000 -t 4 -M -i lo -i lo -x 108 > stdlog
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

}

case_transport_multipath_probing_standby_path()
{

case_test_stop_server
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -e -M > /dev/null
sleep 1

rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "probing standby paths ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024000 -l d -E -e 1 --epoch_timeout 2000000 -t 4 -M -i lo -i lo -x 501 -y > stdlog
clog_res1=`grep "xqc_path_standby_probe" clog | grep "PING" | grep "path:1"`
if [ -n "$clog_res1" ] ; then
    echo ">>>>>>>> pass:1"
    case_print_result "probing_standby_path" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "probing_standby_path" "fail"
fi


}

case_test_case "MPNS_enable_multipath_negotiate" --id native --mode self-reporting --run case_transport_multipath_MPNS_enable_multipath_negotiate
case_test_case "MPNS_send_1M_data_on_multiple_paths" --id native --mode self-reporting --run case_transport_multipath_MPNS_send_1M_data_on_multiple_paths
case_test_case "MPNS_multipath_30_percent_loss" --id native --mode self-reporting --run case_transport_multipath_MPNS_multipath_30_percent_loss --timeout 120
case_test_case "MPNS_multipath_close_initial_path" --id native --mode self-reporting --run case_transport_multipath_MPNS_multipath_close_initial_path
case_test_case "MPNS_multipath_30_percent_loss_close_initial_path" --id native --mode self-reporting --run case_transport_multipath_MPNS_multipath_30_percent_loss_close_initial_path --timeout 120
case_test_case "MPNS_multipath_close_new_path" --id native --mode self-reporting --run case_transport_multipath_MPNS_multipath_close_new_path
case_test_case "MPNS_multipath_30_percent_loss_close_new_path" --id native --mode self-reporting --run case_transport_multipath_MPNS_multipath_30_percent_loss_close_new_path --timeout 120
case_test_case "MPNS_send_data_with_multipath_10" --id native --mode self-reporting --run case_transport_multipath_MPNS_send_data_with_multipath_10
case_test_case "MPNS_reinject_unack_packets_by_capacity" --id native --mode self-reporting --run case_transport_multipath_MPNS_reinject_unack_packets_by_capacity
case_test_case "MPNS_reinject_unack_packets_by_deadline" --id native --mode self-reporting --run case_transport_multipath_MPNS_reinject_unack_packets_by_deadline
case_test_case "NAT_rebinding_path_0" --id native --mode self-reporting --run case_transport_multipath_NAT_rebinding_path_0 --timeout 60
case_test_case "NAT_rebinding_path_1" --id native --mode self-reporting --run case_transport_multipath_NAT_rebinding_path_1
case_test_case "Multipath_Compensate_and_Accelerate" --id native --mode self-reporting --run case_transport_multipath_Multipath_Compensate_and_Accelerate
case_test_case "No_reinjection_for_normal_datagrams" --id native --mode self-reporting --run case_transport_multipath_No_reinjection_for_normal_datagrams
case_test_case "No_reinjection_for_normal_h3_ext_datagrams" --id native --mode self-reporting --run case_transport_multipath_No_reinjection_for_normal_h3_ext_datagrams
case_test_case "MP_reinject_datagrams" --id native --mode self-reporting --run case_transport_multipath_MP_reinject_datagrams
case_test_case "MP_reinject_h3_ext_datagrams" --id native --mode self-reporting --run case_transport_multipath_MP_reinject_h3_ext_datagrams
case_test_case "MP_datagrams_redundancy" --id native --mode self-reporting --run case_transport_multipath_MP_datagrams_redundancy
case_test_case "MP_h3_ext_datagrams_redundancy" --id native --mode self-reporting --run case_transport_multipath_MP_h3_ext_datagrams_redundancy
case_test_case "MP_no_reinjection_for_normal_datagrams" --id native --mode self-reporting --run case_transport_multipath_MP_no_reinjection_for_normal_datagrams
case_test_case "MP_no_reinjection_for_normal_h3_ext_datagrams" --id native --mode self-reporting --run case_transport_multipath_MP_no_reinjection_for_normal_h3_ext_datagrams
case_test_case "MP_datagram_PMTUD_1RTT" --id native --mode self-reporting --run case_transport_multipath_MP_datagram_PMTUD_1RTT
case_test_case "MP_datagram_PMTUD_0RTT" --id native --mode self-reporting --run case_transport_multipath_MP_datagram_PMTUD_0RTT
case_test_case "MP_h3_ext_datagram_PMTUD_1RTT" --id native --mode self-reporting --run case_transport_multipath_MP_h3_ext_datagram_PMTUD_1RTT
case_test_case "MP_h3_ext_datagram_PMTUD_0RTT" --id native --mode self-reporting --run case_transport_multipath_MP_h3_ext_datagram_PMTUD_0RTT
case_test_case "freeze_path0" --id native --mode self-reporting --run case_transport_multipath_freeze_path0
case_test_case "freeze_path1" --id native --mode self-reporting --run case_transport_multipath_freeze_path1
case_test_case "probing_standby_path" --id native --mode self-reporting --run case_transport_multipath_probing_standby_path

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
trap 'case_test_stop_server; case_test_cleanup_udp_port' EXIT
case_test_require_sudo

case_test_run
