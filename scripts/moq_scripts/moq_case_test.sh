# Copyright (c) 2022, Alibaba Group Holding Limited

#!/bin/bash

#macOS
#export EVENT_NOKQUEUE=1

LOCAL_TEST=0
#LOCAL_TEST=1

cd ../build

CLIENT_BIN="moq/demo/moq_demo_client"
SERVER_BIN="moq/demo/moq_demo_server"


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


# start moq_demo_server
rm -rf tp_localhost test_session xqc_token
killall moq_demo_server 2> /dev/null
${SERVER_BIN} -r pub -n 100 -c b > /dev/null &
sleep 1


clear_log
echo -e "moq subscribe ...\c"
${CLIENT_BIN} -r sub > stdlog
cli_res=`grep "|on_video|" clog |grep "seq:99"`
errlog=`grep_err_log`
if [ -n "$cli_res" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "moq_subscribe" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "moq_subscribe" "fail"
    echo "$errlog"
    echo "$cli_res"
fi


killall moq_demo_server 2> /dev/null
${SERVER_BIN} -n 100 -c b > /dev/null &
sleep 1
clear_log
echo -e "moq subscribe and publish ...\c"
${CLIENT_BIN} -n 100 > stdlog
cli_res=`grep "|on_video|" clog |grep "seq:99"`
svr_res=`grep "|on_video|" slog |grep "seq:99"`
errlog=`grep_err_log`
if [ -n "$cli_res" ] && [ -n "$svr_res" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "moq_subpub" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "moq_subpub" "fail"
    echo "$errlog"
    echo "$cli_res"
    echo "$svr_res"
fi


killall moq_demo_server 2> /dev/null
moq/demo/moq_demo_audio_server -c b -p 8443 > /dev/null &
sleep 1
clear_log
echo -e "moq audio server ...\c"
${CLIENT_BIN} -n 100 > stdlog
cli_res=`grep "|on_audio|" clog |grep "seq:99"`
svr_res=`grep "|on_audio|" slog |grep "seq:99"`
errlog=`grep_err_log`
if [ -n "$cli_res" ] && [ -n "$svr_res" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "moq_audio_server" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "moq_audio_server" "fail"
    echo "$errlog"
    echo "$cli_res"
    echo "$svr_res"
fi
killall moq_demo_audio_server 2> /dev/null


clear_log
killall moq_demo_server 2> /dev/null
${SERVER_BIN} -r pub -n 100 -f -d 10 > /dev/null &
sleep 1
echo -e "moq test fec negotiation ...\c"
${CLIENT_BIN} -r sub -f > stdlog
cli_res=`grep "|xqc_negotiate_fec_schemes|set final encoder fec scheme: Packet-Mask|fec_level: FEC_STREAM_LEVEL|" clog`
svr_res=`grep "|xqc_negotiate_fec_schemes|set final encoder fec scheme: Packet-Mask|fec_level: FEC_STREAM_LEVEL|" slog`
errlog=`grep_err_log`
if [ -n "$cli_res" ] && [ -n "$svr_res" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "moq_fec" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "moq_fec" "fail"
    echo "$errlog"
    echo "$cli_res"
    echo "$svr_res"
fi

echo -e "check fec recovery effect on moq requests using Packet-Mask scheme ...\c"
${CLIENT_BIN} -r sub -f > stdlog
cli_res=`grep "|process packet of block .\{1,3\} successfully" clog`
errlog=`grep_err_log`
cconn_res=`grep "xqc_conn_destroy" clog`
sconn_res=`grep "xqc_conn_destroy" slog`
if [ -z "$errlog" ] && [ -n "$cli_res" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "fec_recovered_function_of_stream_pm" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "fec_recovered_function_of_stream_pm" "fail"
    echo "$errlog"
    echo "$cli_res"
    echo "$cconn_res"
    echo "$sconn_res"
fi


killall moq_demo_server 2> /dev/null

cd -