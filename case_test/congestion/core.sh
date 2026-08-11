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
result=`${CLIENT_BIN} -s 10240000 -l e -t 1 -E -c P --copa_delta 0.5 --copa_ai_unit 5.0 |grep ">>>>>>>> pass"`
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

case_test_case "BBR" --id legacy --mode self-reporting --run case_congestion_core_BBR
case_test_case "BBR+" --id legacy --mode self-reporting --run case_congestion_core_BBR_
case_test_case "BBRv2" --id legacy --mode self-reporting --run case_congestion_core_BBRv2
case_test_case "BBRv2+" --id legacy --mode self-reporting --run case_congestion_core_BBRv2_
case_test_case "reno_with_pacing" --id legacy --mode self-reporting --run case_congestion_core_reno_with_pacing
case_test_case "reno_without_pacing" --id legacy --mode self-reporting --run case_congestion_core_reno_without_pacing
case_test_case "cubic_with_pacing" --id legacy --mode self-reporting --run case_congestion_core_cubic_with_pacing
case_test_case "cubic_without_pacing" --id legacy --mode self-reporting --run case_congestion_core_cubic_without_pacing
case_test_case "unlimited_cc" --id legacy --mode self-reporting --run case_congestion_core_unlimited_cc
case_test_case "copa_with_default_parameters" --id legacy --mode self-reporting --run case_congestion_core_copa_with_default_parameters
case_test_case "copa_with_customized_parameters" --id legacy --mode self-reporting --run case_congestion_core_copa_with_customized_parameters
case_test_case "low_delay_settings" --id legacy --mode self-reporting --run case_congestion_core_low_delay_settings
case_test_case "spurious_loss_detect_on" --id legacy --mode self-reporting --run case_congestion_core_spurious_loss_detect_on
case_test_case "1_percent_loss" --id legacy --mode self-reporting --run case_congestion_core__1_percent_loss
case_test_case "3_percent_loss" --id legacy --mode self-reporting --run case_congestion_core__3_percent_loss
case_test_case "10_percent_loss" --id legacy --mode self-reporting --run case_congestion_core__10_percent_loss
case_test_case "sengmmsg_with_10_percent_loss" --id legacy --mode self-reporting --run case_congestion_core_sengmmsg_with_10_percent_loss
case_test_case "max_pkt_out_size" --id legacy --mode self-reporting --run case_congestion_core_max_pkt_out_size

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
trap case_test_stop_server EXIT

case_test_run
