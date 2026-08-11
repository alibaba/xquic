#!/bin/bash
#
# observability.qlog endpoint case-test group.


ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "observability.qlog"

case_observability_qlog_qlog_disable()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 --dgram_qos 3 -f > /dev/null
sleep 1

rm -rf tp_localhost test_session xqc_token



clear_log
rm -rf tp_localhost test_session xqc_token
echo -e "qlog disable ...\c"
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 1 --qlog_disable > /dev/null
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


}

case_observability_qlog_qlog_importance_selected_1()
{


clear_log
echo -e "qlog importance selected 1  ...\c"
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 1 --qlog_importance s > /dev/null
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


}

case_observability_qlog_qlog_importance_selected_2()
{


clear_log
echo -e "qlog importance selected 2  ...\c"
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l i -e -x 1 --qlog_importance s > /dev/null
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


}

case_observability_qlog_qlog_importance_removed()
{


clear_log
echo -e "qlog importance removed  ...\c"
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 1 --qlog_importance r > /dev/null
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


}

case_observability_qlog_qlog_importance_extra()
{


clear_log
echo -e "qlog importance extra  ...\c"
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 1 --qlog_importance e > /dev/null
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


}

case_observability_qlog_qlog_importance_base()
{


clear_log
echo -e "qlog importance base  ...\c"
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 1 --qlog_importance b > /dev/null
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


}

case_observability_qlog_qlog_importance_core()
{


clear_log
echo -e "qlog importance core  ...\c"
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e -x 1 --qlog_importance c > /dev/null
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

}

case_test_case "qlog_disable" --id legacy --mode self-reporting --run case_observability_qlog_qlog_disable
case_test_case "qlog_importance_selected_1" --id legacy --mode self-reporting --run case_observability_qlog_qlog_importance_selected_1
case_test_case "qlog_importance_selected_2" --id legacy --mode self-reporting --run case_observability_qlog_qlog_importance_selected_2
case_test_case "qlog_importance_removed" --id legacy --mode self-reporting --run case_observability_qlog_qlog_importance_removed
case_test_case "qlog_importance_extra" --id legacy --mode self-reporting --run case_observability_qlog_qlog_importance_extra
case_test_case "qlog_importance_base" --id legacy --mode self-reporting --run case_observability_qlog_qlog_importance_base
case_test_case "qlog_importance_core" --id legacy --mode self-reporting --run case_observability_qlog_qlog_importance_core

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
trap case_test_stop_server EXIT

case_test_run
