#!/bin/bash
#
# tls.handshake endpoint case-test group.

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "tls.handshake"

case_tls_handshake_cert_verify()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1



clear_log
${CLIENT_BIN} -s 1024000 -l e -t 1 -E -1 -V 1 > stdlog
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


}

case_tls_handshake__1RTT()
{


clear_log
echo -e "1RTT ...\c"
${CLIENT_BIN} -s 1024000 -l e -t 1 -E -1 > stdlog
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


}

case_tls_handshake_alpn_negotiation_success()
{


clear_log
echo -e "alpn negotiation success ...\c"
rm -f test_session
${CLIENT_BIN} -s 1024 -l e -t 1 -T 1 > stdlog
alpn_ok=`grep "alpn:transport" stdlog`
conn_err_zero=`grep -E "conn_err:0[^0-9]" stdlog`
errlog=`grep_err_log`
if [ -n "$alpn_ok" ] && [ -n "$conn_err_zero" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "alpn_negotiation_success" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "alpn_negotiation_success" "fail"
fi

}

case_tls_handshake_alpn_negotiation_failure_0x178()
{

clear_log
echo -e "alpn negotiation failure (0x178) ...\c"
rm -f test_session
${CLIENT_BIN} -l e -t 1 -T 1 -x 43 > stdlog
alpn_res=`grep "xqc_ssl_alpn_select_cb|select proto error" slog`
conn_err_178=`grep "conn_err:376" stdlog`
if [ -n "$alpn_res" ] && [ -n "$conn_err_178" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "alpn_negotiation_failure_0x178" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "alpn_negotiation_failure_0x178" "fail"
fi


}

case_tls_handshake_without_session_ticket()
{


clear_log
echo -e "without session ticket ...\c"
rm -f test_session
${CLIENT_BIN} -s 1024000 -l e -t 1 -E > stdlog
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


}

case_tls_handshake__0RTT_accept()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1



clear_log
echo -e "0RTT accept ...\c"
${CLIENT_BIN} -s 1024000 -l e -t 1 -E > stdlog
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


}

case_tls_handshake__0RTT_reject()
{


clear_log
echo -e "0RTT reject. restart server ....\c"
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l i -e > /dev/null
sleep 1
${CLIENT_BIN} -s 1024000 -l d -t 1 -E > stdlog
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

}

case_tls_handshake_no_crypto_without_0RTT()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l i -e > /dev/null
sleep 1

rm -f test_session


clear_log
echo -e "no crypto without 0RTT ...\c"
rm -f test_session
result=`${CLIENT_BIN} -s 1024000 -l d -N -t 1 -E|grep ">>>>>>>> pass"`
errlog=`grep_err_log`
echo "$result"
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
    case_print_result "no_crypto_without_0RTT" "pass"
else
    case_print_result "no_crypto_without_0RTT" "fail"
    echo "$errlog"
fi


}

case_tls_handshake_no_crypto_with_0RTT()
{


clear_log
echo -e "no crypto with 0RTT ...\c"
${CLIENT_BIN} -s 1024000 -l d -N -t 1 -E > stdlog
if grep "early_data_flag:1" stdlog >/dev/null && grep ">>>>>>>> pass:1" stdlog >/dev/null; then
    echo ">>>>>>>> pass:1"
    case_print_result "no_crypto_with_0RTT" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "no_crypto_with_0RTT" "fail"
fi
}

case_tls_handshake_no_crypto_with_0RTT_twice()
{
grep_err_log


clear_log
echo -e "no crypto with 0RTT twice ...\c"
${CLIENT_BIN} -s 1024000 -l d -N -t 1 -E > stdlog
if grep "early_data_flag:1" stdlog >/dev/null && grep ">>>>>>>> pass:1" stdlog >/dev/null; then
    echo ">>>>>>>> pass:1"
    case_print_result "no_crypto_with_0RTT_twice" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "no_crypto_with_0RTT_twice" "fail"
fi
}

case_tls_handshake__0RTT_buffer_limit_before_Initial()
{
grep_err_log


clear_log
echo -e "0RTT buffer limit before Initial ...\c"
${CLIENT_BIN} -l d -t 1 -x 39 -E >> clog
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
}

case_tls_handshake_set_cipher_suites()
{
case_test_start_server ${SERVER_BIN} -l d -e -S "server_id_0" > /dev/null
sleep 1

clear_log
echo -e "set cipher suites ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -x 27 >> clog
result=`grep "set cipher suites suc|ciphers:TLS_CHACHA20_POLY1305_SHA256" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "set_cipher_suites" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "set_cipher_suites" "fail"
fi


}

case_tls_handshake_key_update()
{
case_test_stop_server
case_test_start_server ${SERVER_BIN} -l e -e -x 12 > /dev/null
sleep 1


case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1

clear_log
echo -e "key update ...\c"
${CLIENT_BIN} -s 102400 -l d -E -x 40 >> clog
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
}

case_tls_handshake_key_update_0RTT()
{
grep_err_log

clear_log
echo -e "key update 0RTT...\c"
${CLIENT_BIN} -s 102400 -l d -E -x 40 >> clog
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
}

case_tls_handshake_initial_salt_v1_key_derivation()
{
case_test_start_server ${SERVER_BIN} -l d -e -x 455 > /dev/null
sleep 1


case_test_stop_server
> svr_stdlog
case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -e -x 48 > svr_stdlog
sleep 1

rm -f test_session tp_localhost xqc_token

clear_log
echo -e "initial salt v1 key derivation ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 48 > stdlog
result=`grep ">>>>>>>> pass" stdlog`
salt_cli=`grep "\[initial-salt-test\] handshake ok, conn_err:0" stdlog`
salt_svr=`grep -a "\[initial-salt-test\] server handshake ok, conn_err:0" svr_stdlog`
errlog=`grep "derive initial secret error" clog slog`
if [ "$result" == ">>>>>>>> pass:1" ] && [ -n "$salt_cli" ] && [ -n "$salt_svr" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "initial_salt_v1_key_derivation" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "initial_salt_v1_key_derivation" "fail"
fi

}

case_tls_handshake_crypto_error_cert_verify()
{

case_test_stop_server
clear_log
echo -e "crypto_error: cert verify triggers dynamic CRYPTO_ERROR (0x112=274) ...\c"
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1
${CLIENT_BIN} -l d -t 1 -E -x 703 > stdlog
result=`grep "conn_err:274" stdlog | wc -l`
if [ "$result" -gt 0 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "crypto_error_cert_verify" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "crypto_error_cert_verify" "fail"
fi


}

case_tls_handshake_crypto_error_not_fixed_enum()
{


case_test_stop_server
clear_log
echo -e "crypto_error: removed 0x1FF enum not used (conn_err:511 absent) ...\c"
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1
${CLIENT_BIN} -l d -t 1 -E -x 703 > stdlog
result=`grep "conn_err:511" stdlog | wc -l`
if [ "$result" -eq 0 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "crypto_error_not_fixed_enum" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "crypto_error_not_fixed_enum" "fail"
fi

## RFC 9000 Section 7.4.1: 0-RTT transport parameter validation

# test 701: server reduces max_streams_bidi after first connection,
# client detects reduction on 0-RTT resumption, reports its local cleanup
# reason (0x54 = conn_err:84), and sends TRANSPORT_PARAMETER_ERROR (0x08)
}

case_test_case "cert_verify" --id legacy --mode self-reporting --run case_tls_handshake_cert_verify
case_test_case "1RTT" --id legacy --mode self-reporting --run case_tls_handshake__1RTT
case_test_case "alpn_negotiation_success" --id legacy --mode self-reporting --run case_tls_handshake_alpn_negotiation_success
case_test_case "alpn_negotiation_failure_0x178" --id legacy --mode self-reporting --run case_tls_handshake_alpn_negotiation_failure_0x178
case_test_case "without_session_ticket" --id legacy --mode self-reporting --run case_tls_handshake_without_session_ticket
case_test_case "0RTT_accept" --id legacy --mode self-reporting --run case_tls_handshake__0RTT_accept
case_test_case "0RTT_reject" --id legacy --mode self-reporting --run case_tls_handshake__0RTT_reject
case_test_case "no_crypto_without_0RTT" --id legacy --mode self-reporting --run case_tls_handshake_no_crypto_without_0RTT
case_test_case "no_crypto_with_0RTT" --id legacy --mode self-reporting --run case_tls_handshake_no_crypto_with_0RTT
case_test_case "no_crypto_with_0RTT_twice" --id legacy --mode self-reporting --run case_tls_handshake_no_crypto_with_0RTT_twice
case_test_case "0RTT_buffer_limit_before_Initial" --id legacy --mode self-reporting --run case_tls_handshake__0RTT_buffer_limit_before_Initial
case_test_case "set_cipher_suites" --id legacy --mode self-reporting --run case_tls_handshake_set_cipher_suites
case_test_case "key_update" --id legacy --mode self-reporting --run case_tls_handshake_key_update
case_test_case "key_update_0RTT" --id legacy --mode self-reporting --run case_tls_handshake_key_update_0RTT
case_test_case "initial_salt_v1_key_derivation" --id legacy --mode self-reporting --run case_tls_handshake_initial_salt_v1_key_derivation
case_test_case "crypto_error_cert_verify" --id legacy --mode self-reporting --run case_tls_handshake_crypto_error_cert_verify
case_test_case "crypto_error_not_fixed_enum" --id legacy --mode self-reporting --run case_tls_handshake_crypto_error_not_fixed_enum

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
trap case_test_stop_server EXIT

case_test_run
