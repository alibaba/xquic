#!/bin/bash
#
# congestion.core endpoint case-test group.


ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "congestion.core"

case_congestion_core_BBR()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1


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

}

case_congestion_core_BBR_()
{

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

}

case_congestion_core_BBRv2()
{

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

}

case_congestion_core_BBRv2_()
{

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

}

case_congestion_core_reno_with_pacing()
{

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

}

case_congestion_core_reno_without_pacing()
{

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


}

case_congestion_core_cubic_with_pacing()
{


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

}

case_congestion_core_cubic_without_pacing()
{

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

}

case_congestion_core_unlimited_cc()
{

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

}

case_congestion_core_copa_with_default_parameters()
{

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

}

case_congestion_core_copa_with_customized_parameters()
{

clear_log
echo -e "Copa with customized parameters (delta=0.5, ai_unit=5.0) ...\c"
result=`${CLIENT_BIN} -s 1024000 -l e -t 1 -E -c P --copa_delta 0.5 --copa_ai_unit 5.0 |grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "copa_with_customized_parameters" "pass"
else
    case_print_result "copa_with_customized_parameters" "fail"
    echo "$errlog"
fi


}

case_congestion_core_low_delay_settings()
{


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


}

case_congestion_core_spurious_loss_detect_on()
{


clear_log
result=`${CLIENT_BIN} -s 10240000 -l e -t 1 -E -x 26|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "spurious_loss_detect_on" "pass"
else
    case_print_result "spurious_loss_detect_on" "fail"
    echo "$errlog"
fi
}

case_congestion_core__1_percent_loss()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1

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

}

case_congestion_core__3_percent_loss()
{

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

}

case_congestion_core__10_percent_loss()
{

clear_log
result=`${CLIENT_BIN} -s 10240000 -t 5 -l e -E -d 100|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "10_percent_loss" "pass"
else
    case_print_result "10_percent_loss" "fail"
    echo "$errlog"
fi
}

case_congestion_core_sengmmsg_with_10_percent_loss()
{
echo -e "10% loss ...\c"
echo "$result"


case_test_stop_server
case_test_start_server ${SERVER_BIN} -l e -e > /dev/null
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


}

case_congestion_core_max_pkt_out_size()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1

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


}

# Recovery: a lost PMTUD probe is not a congestion signal (case IDs 804/805)
# RFC 9000 Section 14.4: the loss of a PMTU probe SHOULD NOT trigger a
# congestion control reaction. The client path drops every datagram above
# 1300 bytes, which only PMTUD probes exceed.
case_congestion_core_lost_pmtud_probe_no_congestion_event()
{
# 804 happy path: the probes are lost, the transfer completes, and no packet
# is marked lost, so no congestion event starts.
case_test_stop_server
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e --pmtud 1 > /dev/null
sleep 1
clear_log
echo -e "lost PMTUD probes start no congestion event ...\c"
${CLIENT_BIN} -s 1024000 -l d -t 1 -E --pmtud 1 -x 804 > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
probe_lost=`grep "|PMTUD probe lost|" clog`
marked=`grep "|mark lost|" clog`
cc_event=`grep "|OnLostDetection|" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$probe_lost" ] \
    && [ -z "$marked" ] && [ -z "$cc_event" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "lost_pmtud_probe_no_congestion_event" "pass"
else
    echo ">>>>>>>> pass:0 (result:${result:+y} probe_lost:${probe_lost:+y}" \
        "marked:${marked:+y} cc_event:${cc_event:+y} errlog:${errlog:+y})"
    case_print_result "lost_pmtud_probe_no_congestion_event" "fail"
fi
grep_err_log
}

case_congestion_core_lost_data_packet_congestion_event()
{
# 805 abnormal path: the same path also drops one ordinary full-size packet.
# That packet is still marked lost and starts a congestion event, next to
# the probes that do not.
case_test_stop_server
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e --pmtud 1 > /dev/null
sleep 1
clear_log
echo -e "a lost data packet still starts a congestion event ...\c"
${CLIENT_BIN} -s 1024000 -l d -t 1 -E --pmtud 1 -x 805 > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
probe_lost=`grep "|PMTUD probe lost|" clog`
marked=`grep "|mark lost|" clog`
cc_event=`grep "|OnLostDetection|" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$probe_lost" ] \
    && [ -n "$marked" ] && [ -n "$cc_event" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "lost_data_packet_congestion_event" "pass"
else
    echo ">>>>>>>> pass:0 (result:${result:+y} probe_lost:${probe_lost:+y}" \
        "marked:${marked:+y} cc_event:${cc_event:+y} errlog:${errlog:+y})"
    case_print_result "lost_data_packet_congestion_event" "fail"
fi
grep_err_log
}

case_test_group_setup()
{
    case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
}

case_test_case "BBR" --id native --mode self-reporting --run case_congestion_core_BBR
case_test_case "BBR+" --id native --mode self-reporting --run case_congestion_core_BBR_
case_test_case "BBRv2" --id native --mode self-reporting --run case_congestion_core_BBRv2
case_test_case "BBRv2+" --id native --mode self-reporting --run case_congestion_core_BBRv2_
case_test_case "reno_with_pacing" --id native --mode self-reporting --run case_congestion_core_reno_with_pacing
case_test_case "reno_without_pacing" --id native --mode self-reporting --run case_congestion_core_reno_without_pacing
case_test_case "cubic_with_pacing" --id native --mode self-reporting --run case_congestion_core_cubic_with_pacing
case_test_case "cubic_without_pacing" --id native --mode self-reporting --run case_congestion_core_cubic_without_pacing
case_test_case "unlimited_cc" --id native --mode self-reporting --run case_congestion_core_unlimited_cc
case_test_case "copa_with_default_parameters" --id native --mode self-reporting --run case_congestion_core_copa_with_default_parameters
case_test_case "copa_with_customized_parameters" --id native --mode self-reporting --run case_congestion_core_copa_with_customized_parameters
case_test_case "low_delay_settings" --id native --mode self-reporting --run case_congestion_core_low_delay_settings
case_test_case "spurious_loss_detect_on" --id native --mode self-reporting --run case_congestion_core_spurious_loss_detect_on
case_test_case "1_percent_loss" --id native --mode self-reporting --run case_congestion_core__1_percent_loss
case_test_case "3_percent_loss" --id native --mode self-reporting --run case_congestion_core__3_percent_loss
case_test_case "10_percent_loss" --id native --mode self-reporting --run case_congestion_core__10_percent_loss
case_test_case "sengmmsg_with_10_percent_loss" --id native --mode self-reporting --run case_congestion_core_sengmmsg_with_10_percent_loss
case_test_case "max_pkt_out_size" --id native --mode self-reporting --run case_congestion_core_max_pkt_out_size
case_test_case "lost_pmtud_probe_no_congestion_event" --id 804 --mode self-reporting --run case_congestion_core_lost_pmtud_probe_no_congestion_event
case_test_case "lost_data_packet_congestion_event" --id 805 --mode self-reporting --run case_congestion_core_lost_data_packet_congestion_event

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
trap 'case_test_stop_server; case_test_cleanup_udp_port' EXIT

case_test_run
