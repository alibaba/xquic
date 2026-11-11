#!/bin/bash
#
# tls.handshake endpoint case-test group.


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

case_test_stop_server
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
clear_log
echo -e "alpn negotiation failure (0x178) ...\c"
rm -f test_session
${CLIENT_BIN} -l e -t 1 -T 1 -x 43 > stdlog
alpn_res=`grep -a "xqc_ssl_alpn_select_cb|select proto error" slog`
alert_res=`grep -a -E "(alert:120|NO_APPLICATION_PROTOCOL|no_application_protocol)" slog`
conn_err_178=`grep -a -E "(conn_err:376([^0-9]|$)|err:0x178([^0-9a-fA-F]|$))" stdlog clog slog`
transport_type=`grep "conn_err_type:1" stdlog`
if [ -n "$alpn_res" ] && [ -n "$alert_res" ] \
    && [ -n "$conn_err_178" ] && [ -n "$transport_type" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "alpn_negotiation_failure_0x178" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "alpn_negotiation_failure_0x178" "fail"
    echo "expected ALPN failure evidence:"
    echo "  server select proto error: ${alpn_res:-missing}"
    echo "  TLS alert 120/no_application_protocol: ${alert_res:-missing}"
    echo "  conn_err 0x178/376: ${conn_err_178:-missing}"
    echo "  transport error type: ${transport_type:-missing}"
    grep -a -E "(select proto error|alert:|NO_APPLICATION_PROTOCOL|no_application_protocol|conn_err:|err:0x)" stdlog clog slog 2>/dev/null || true
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



rm -f test_session xqc_token tp_localhost
${CLIENT_BIN} -s 1024000 -l e -t 1 -E -1 > /dev/null

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
limit_log=`grep -a "0RTT reach buffer limit before DCID confirmed" slog`
clog_res=`grep -a ">>>>>>>> pass:1" clog`
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
result=`grep -a "set cipher suites suc|ciphers:TLS_CHACHA20_POLY1305_SHA256" clog`
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
result=`grep -a ">>>>>>>> pass" clog`
svr_res=`grep -a "key phase changed to" slog`
cli_res=`grep -a "key phase changed to" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ] && [ "$svr_res" != "" ] && [ "$cli_res" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "key_update" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "key_update" "fail"
fi
}

case_tls_handshake_key_update_old_key_retention()
{
    case_test_stop_server
    case_test_start_server ${SERVER_BIN} -l d -e > /dev/null

    clear_log
    echo -e "key update old key retention ...\c"
    ${CLIENT_BIN} -s 102400 -l d -t 8 -E -x 904 >> clog
    held=`grep -a "hold-old-key-packet" clog`
    cached=`grep -a "cached-old-key-packet" clog`
    retained=`grep -a "RESULT|retained" clog`
    dropped=`grep -a "RESULT|dropped" clog`
    if [ "$held" != "" ] && [ "$cached" != "" ] \
        && [ "$retained" != "" ] && [ -z "$dropped" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "key_update_old_key_retention" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "key_update_old_key_retention" "fail"
    fi
}

case_tls_handshake_key_update_0RTT()
{
grep_err_log

echo -e "key update 0RTT...\c"
key_update_0rtt_pass=0
key_update_0rtt_attempt=1
while [ $key_update_0rtt_attempt -le 2 ]; do
    clear_log
    if [ $key_update_0rtt_attempt -gt 1 ]; then
        echo -e " retry ${key_update_0rtt_attempt} ...\c"
    fi
    ${CLIENT_BIN} -s 102400 -l d -E -x 40 >> clog
    # The peer logs its key phase change while draining the last packets, which
    # under parallel load can land just after the client exits; poll briefly so a
    # late log line is not mistaken for a missing key update.
    for wait_idx in $(seq 1 25); do
        svr_res=`grep -a "key phase changed to" slog`
        cli_res=`grep -a "key phase changed to" clog`
        if [ -n "$svr_res" ] && [ -n "$cli_res" ]; then
            break
        fi
        sleep 0.2
    done
    result=`grep -a ">>>>>>>> pass" clog`
    errlog=`grep_err_log`
    if [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ] && [ "$svr_res" != "" ] && [ "$cli_res" != "" ]; then
        key_update_0rtt_pass=1
        break
    fi
    if [ $key_update_0rtt_attempt -ge 2 ]; then
        break
    fi
    # A client pass:0 is a stream echo failure, not proof of a deterministic
    # key-update failure. Retry every error-free first attempt so transient
    # response loss and late peer processing do not bypass this case's budget.
    if [ -n "$errlog" ]; then
        break
    fi
    key_update_0rtt_attempt=$((key_update_0rtt_attempt + 1))
done
if [ $key_update_0rtt_pass -eq 1 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "key_update_0RTT" "pass"
else
    [ "$result" == ">>>>>>>> pass:1" ] && result_hit=1 || result_hit=0
    [ -n "$svr_res" ] && svr_key_phase_hit=1 || svr_key_phase_hit=0
    [ -n "$cli_res" ] && cli_key_phase_hit=1 || cli_key_phase_hit=0
    [ -n "$errlog" ] && errlog_hit=1 || errlog_hit=0
    echo ">>>>>>>> pass:0"
    echo "[key-update-0rtt]|attempt:${key_update_0rtt_attempt}|client_pass:${result_hit}|svr_key_phase:${svr_key_phase_hit}|cli_key_phase:${cli_key_phase_hit}|errlog:${errlog_hit}|"
    if [ -n "$errlog" ]; then
        echo "[key-update-0rtt][errlog]"
        printf '%s\n' "$errlog" | tail -n 10
    fi
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
errlog=`grep -a "derive initial secret error" clog slog`
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

case_tls_handshake_aead_confidentiality_boundary_updates_keys()
{

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost aead_confidentiality_server.log
case_test_start_server ${SERVER_BIN} -l d -e -x 902 > aead_confidentiality_server.log
sleep 1
echo -e "AEAD confidentiality: last permitted packet updates keys ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 902 > stdlog
injected=`grep "\[aead-confidentiality-test\]|case:902|" stdlog`
updated=`grep -a "|key phase changed to" clog`
received=`grep "\[aead-confidentiality-test\]|request_received|case:902|" \
    aead_confidentiality_server.log`
success=`grep ">>>>>>>> pass:1" stdlog`
limit_error=`grep -a "|AEAD confidentiality limit reached|" clog`
if [ -n "$injected" ] && [ -n "$updated" ] && [ -n "$received" ] \
    && [ -n "$success" ] && [ -z "$limit_error" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "aead_confidentiality_boundary_updates_keys" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "aead_confidentiality_boundary_updates_keys" "fail"
fi

}

case_tls_handshake_aead_confidentiality_exhaustion_stops_sender()
{

case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost aead_confidentiality_server.log
case_test_start_server ${SERVER_BIN} -l d -e -x 903 > aead_confidentiality_server.log
sleep 1
echo -e "AEAD confidentiality: exhausted keys reject next packet ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 903 > stdlog
injected=`grep "\[aead-confidentiality-test\]|case:903|" stdlog`
limit_error=`grep -a "|AEAD confidentiality limit reached|" clog`
wire_error=`grep -a "|err:0xf" clog`
received=`grep "\[aead-confidentiality-test\]|request_received|case:903|" \
    aead_confidentiality_server.log`
if [ -n "$injected" ] && [ -n "$limit_error" ] && [ -n "$wire_error" ] \
    && [ -z "$received" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "aead_confidentiality_exhaustion_stops_sender" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "aead_confidentiality_exhaustion_stops_sender" "fail"
fi

case_test_stop_server
rm -f aead_confidentiality_server.log

}

# RFC 9369: a connection in QUIC version 2, the Initial secrets and the keys
# derived with its salt and labels.
case_tls_handshake_quic_v2_handshake()
{
case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e -x 913 > /dev/null
sleep 1
echo -e "QUIC version 2 handshake ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 913 > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
v2_selected=`grep -a "|version selected|v:6b3343cf|" slog`
errlog=`grep_err_log`
if [ -n "$result" ] && [ -n "$v2_selected" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "quic_v2_handshake" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "quic_v2_handshake" "fail"
fi
}

# RFC 9000 Section 6: a server without QUIC version 2 answers its Initial
# with a Version Negotiation packet, and the client abandons the attempt.
case_tls_handshake_quic_v2_unsupported()
{
case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
sleep 1
echo -e "QUIC version 2 to a server without it ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 914 > stdlog
unsupported=`grep -a "|version not supported|v:1798521807|" slog`
vn=`grep -a "packet parse|version negotiation" clog`
aborted=`grep -a "version negotiation: aborting connection attempt" clog`
result=`grep ">>>>>>>> pass:1" stdlog`
if [ -n "$unsupported" ] && [ -n "$vn" ] && [ -n "$aborted" ] \
    && [ -z "$result" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "quic_v2_unsupported" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "quic_v2_unsupported" "fail"
fi
}

# RFC 9369 Sections 3.2 and 3.3.3: a Retry in QUIC version 2, with its
# packet type and Retry Integrity Tag.
case_tls_handshake_quic_v2_retry()
{
case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e -x 915 > /dev/null
sleep 1
echo -e "QUIC version 2 Retry ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 915 > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
retry_sent=`grep -a -E "<==.*xqc_conn_send_retry ok" slog`
retry_recvd=`grep -a "packet parse|retry" clog`
v2_selected=`grep -a "|version selected|v:6b3343cf|" slog`
errlog=`grep_err_log`
if [ -n "$result" ] && [ -n "$retry_sent" ] && [ -n "$retry_recvd" ] \
    && [ -n "$v2_selected" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "quic_v2_retry" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "quic_v2_retry" "fail"
fi
}

# RFC 9369 Section 4 and RFC 9368 Section 4: in a QUIC version 2
# connection, each endpoint sends its Version Information and validates the
# peer's.
case_tls_handshake_quic_v2_version_information()
{
case_test_stop_server
clear_log
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e -x 918 > /dev/null
sleep 1
echo -e "QUIC version 2 Version Information ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 918 > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
svr_vi=`grep -a "|version information|chosen:6b3343cf|available:1|" slog`
cli_vi=`grep -a "|version information|chosen:6b3343cf|available:3|" clog`
errlog=`grep_err_log`
if [ -n "$result" ] && [ -n "$svr_vi" ] && [ -n "$cli_vi" ] \
    && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "quic_v2_version_information" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "quic_v2_version_information" "fail"
fi
}

# RFC 9369 Section 5: a QUIC version 2 connection resumes the session of an
# earlier version 2 connection, with 0-RTT, and its token is valid.
case_tls_handshake_quic_v2_resumption()
{
case_test_stop_server
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e -x 919 > /dev/null
sleep 1
${CLIENT_BIN} -s 1024 -l e -t 1 -E -1 -x 919 > /dev/null
clear_log
echo -e "QUIC version 2 resumption ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 919 > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
flag=`grep "early_data_flag:1" stdlog`
token_err=`grep -a "|token decrypt error|" slog`
errlog=`grep_err_log`
if [ -n "$result" ] && [ -n "$flag" ] && [ -z "$token_err" ] \
    && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "quic_v2_resumption" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "quic_v2_resumption" "fail"
fi
}

# RFC 9369 Section 5: the server accepts neither the session ticket nor the
# token of a connection in another QUIC version. A version 1 connection
# after a version 2 one, then a version 2 connection after that version 1
# one, make full handshakes: 0-RTT is rejected and the token is not valid.
case_tls_handshake_quic_v2_resumption_other_version()
{
case_test_stop_server
rm -f test_session xqc_token tp_localhost
case_test_start_server ${SERVER_BIN} -l d -e -x 920 > /dev/null
sleep 1
${CLIENT_BIN} -s 1024 -l e -t 1 -E -1 -x 920 > /dev/null
clear_log
echo -e "QUIC version 2 resumption in another version ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E > stdlog
v1_result=`grep ">>>>>>>> pass:1" stdlog`
v1_flag=`grep "early_data_flag:2" stdlog`
v1_token=`grep -a "|token decrypt error|" slog`
v1_err=`grep_err_log | grep -v "|EVP_DecryptFinal_ex failed|"`
clear_log
${CLIENT_BIN} -s 1024 -l d -t 1 -E -x 920 > stdlog
v2_result=`grep ">>>>>>>> pass:1" stdlog`
v2_flag=`grep "early_data_flag:2" stdlog`
v2_token=`grep -a "|token decrypt error|" slog`
v2_err=`grep_err_log | grep -v "|EVP_DecryptFinal_ex failed|"`
if [ -n "$v1_result" ] && [ -n "$v1_flag" ] && [ -n "$v1_token" ] \
    && [ -z "$v1_err" ] && [ -n "$v2_result" ] && [ -n "$v2_flag" ] \
    && [ -n "$v2_token" ] && [ -z "$v2_err" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "quic_v2_resumption_other_version" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "quic_v2_resumption_other_version" "fail"
fi
}

case_tls_handshake_key_update_stale_deadline()
{
    # RFC 9001 Sections 6.1 and 6.5: a second key update started while the
    # first update's old-key discard deadline is pending keeps the keys it
    # retires.
    case_test_stop_server
    case_test_start_server ${SERVER_BIN} -l d -e -x 905 > /dev/null

    clear_log
    echo -e "key update keeps retired keys past an earlier deadline ...\c"
    ${CLIENT_BIN} -s 102400 -l d -t 5 -E -x 905 >> clog
    result=`grep -a ">>>>>>>> pass" clog`
    copied=`grep -a "\[key-update-stale-deadline\]|copy-old-key-packet|" clog`
    forced=`grep -a "\[key-update-stale-deadline\]|second-update|" clog`
    retained=`grep -a "\[key-update-stale-deadline\]|RESULT|retained|" clog`
    errlog=`grep_err_log`
    if [ -n "$copied" ] && [ -n "$forced" ] && [ -n "$retained" ] \
        && [ -z "$errlog" ] && [ "$result" == ">>>>>>>> pass:1" ]; then
        echo ">>>>>>>> pass:1"
        case_print_result "key_update_stale_deadline" "pass"
    else
        echo ">>>>>>>> pass:0"
        case_print_result "key_update_stale_deadline" "fail"
        grep -a "\[key-update-stale-deadline\]" clog
        echo "$errlog"
    fi

    case_test_stop_server
}

reset_0rtt_saved_tp_matches()
{
    local expected="$1"
    test -s tp_localhost || return 1
    grep -q '^initial_max_data=' tp_localhost || return 1
    if [[ "${expected}" = 1 ]]; then
        grep -qx 'reset_stream_at=1' tp_localhost
    else
        ! grep -q '^reset_stream_at=' tp_localhost
    fi
}

reset_0rtt_check_connection()
{
    local phase="$1" cached="$2" current="$3" early="$4" reused="$5"
    local ready=1 packets_ok=1
    [[ "${phase}" = warmup ]] && ready=0

    if [[ "${ready}" = 1 ]] && ! grep -Eq \
        'xqc_send_ctl_on_packet_sent.*pkt_type:0RTT\|frame:.*STREAM' clog; then
        echo "${phase}: no STREAM packet was sent in 0-RTT"
        packets_ok=0
    fi
    if [[ "${early}" = 2 ]]; then
        if ! grep -Fq 'xqc_conn_early_data_reject|reject|' clog \
            || ! grep -Eq \
                'xqc_send_ctl_on_packet_sent.*pkt_type:SHORT_HEADER\|frame:.*STREAM' clog; then
            echo "${phase}: missing 0-RTT rejection or 1-RTT stream replay"
            packets_ok=0
        fi
    fi

    if [[ "${packets_ok}" = 1 ]] \
        && grep -Fxq '>>>>>>>> pass:1' "${phase}.log" \
        && grep -Fq "early_data_flag:${early}, conn_err:0," "${phase}.log" \
        && grep -Fxq "[reset-0rtt]|cached:${cached}|early_ready:${ready}|" \
            "${phase}.log" \
        && grep -Fxq "[reset-0rtt]|negotiated:${current}|session_reused:${reused}|" \
            "${phase}.log" \
        && grep -Fq 'save_tp_cb use server domain as the key.' "${phase}.log" \
        && grep -Fq 'save_session_cb use server domain as the key.' \
            "${phase}.log" \
        && reset_0rtt_saved_tp_matches "${current}"; then
        return 0
    fi

    echo "${phase}: expected cached=${cached} current=${current} early=${early} reused=${reused}"
    grep -E 'reset-0rtt|early_data_flag:|>>>>>>>> pass:|save.*tp' "${phase}.log"
    cat tp_localhost
    return 1
}

case_tls_reset_0rtt_transition()
{
    local id="$1" saved="$2" current="$3" early="$4"
    local failed=0

    # reliable-stream-reset-09 Section 3; RFC 9000 Section 7.4.1.
    # Keep one server/TLS context so rejection cannot come from lost keys.
    case_test_stop_server
    clear_log
    rm -f test_session xqc_token tp_localhost
    case_test_start_server ${SERVER_BIN} -l d -e -x "${id}" > server.log

    ${CLIENT_BIN} -s 4096 -l d -t 1 -E -x "${id}" > warmup.log || failed=1
    reset_0rtt_check_connection warmup 0 "${saved}" 0 0 || failed=1
    test -s test_session || failed=1
    cp tp_localhost warmup.tp
    cp clog warmup.clog
    cp slog warmup.slog

    if ! case_test_wait_for_log server.log \
        "server_ready:${current}|" 100 0.1; then
        echo 'server did not finish the warmup connection'
        cat server.log
        case_test_stop_server
        return 1
    fi

    clear_log
    ${CLIENT_BIN} -s 4096 -l d -t 1 -E -x "${id}" > resume.log || failed=1
    reset_0rtt_check_connection resume "${saved}" "${current}" \
        "${early}" 1 || failed=1
    cp tp_localhost resume.tp
    cp clog resume.clog
    cp slog resume.slog

    # The newly issued ticket and saved parameters must describe this server.
    clear_log
    ${CLIENT_BIN} -s 4096 -l d -t 1 -E -x "${id}" > refreshed.log || failed=1
    reset_0rtt_check_connection refreshed "${current}" "${current}" \
        1 1 || failed=1
    cp tp_localhost refreshed.tp
    cp clog refreshed.clog
    cp slog refreshed.slog
    case_test_stop_server

    grep -Fxq "[reset-0rtt]|server_advertised:${current}|early_data:${early}|" \
        server.log || failed=1
    grep -Fxq "[reset-0rtt]|server_advertised:${current}|early_data:1|" \
        server.log || failed=1
    return "${failed}"
}

case_tls_reset_0rtt_downgrade()
{
    case_tls_reset_0rtt_transition 909 1 0 2
}

case_tls_reset_0rtt_upgrade()
{
    case_tls_reset_0rtt_transition 910 0 1 2
}

case_tls_reset_0rtt_disabled()
{
    case_tls_reset_0rtt_transition 911 0 0 1
}

case_tls_reset_0rtt_enabled()
{
    case_tls_reset_0rtt_transition 912 1 1 1
}

case_test_case "reset_0RTT_downgrade" --id 909 --run case_tls_reset_0rtt_downgrade
case_test_case "reset_0RTT_upgrade" --id 910 --run case_tls_reset_0rtt_upgrade
case_test_case "reset_0RTT_disabled" --id 911 --run case_tls_reset_0rtt_disabled
case_test_case "reset_0RTT_enabled" --id 912 --run case_tls_reset_0rtt_enabled

case_test_case "cert_verify" --id native --mode self-reporting --run case_tls_handshake_cert_verify
case_test_case "1RTT" --id native --mode self-reporting --run case_tls_handshake__1RTT
case_test_case "alpn_negotiation_success" --id native --mode self-reporting --run case_tls_handshake_alpn_negotiation_success
case_test_case "alpn_negotiation_failure_0x178" --id native --mode self-reporting --run case_tls_handshake_alpn_negotiation_failure_0x178
case_test_case "without_session_ticket" --id native --mode self-reporting --run case_tls_handshake_without_session_ticket
case_test_case "0RTT_accept" --id native --mode self-reporting --run case_tls_handshake__0RTT_accept
case_test_case "0RTT_reject" --id native --mode self-reporting --run case_tls_handshake__0RTT_reject
case_test_case "no_crypto_without_0RTT" --id native --mode self-reporting --run case_tls_handshake_no_crypto_without_0RTT
case_test_case "no_crypto_with_0RTT" --id native --mode self-reporting --run case_tls_handshake_no_crypto_with_0RTT
case_test_case "no_crypto_with_0RTT_twice" --id native --mode self-reporting --run case_tls_handshake_no_crypto_with_0RTT_twice
case_test_case "0RTT_buffer_limit_before_Initial" --id native --mode self-reporting --run case_tls_handshake__0RTT_buffer_limit_before_Initial
case_test_case "set_cipher_suites" --id native --mode self-reporting --run case_tls_handshake_set_cipher_suites
case_test_case "key_update" --id native --mode self-reporting --run case_tls_handshake_key_update
case_test_case "key_update_old_key_retention" --id 904 --mode self-reporting --run case_tls_handshake_key_update_old_key_retention
case_test_case "key_update_0RTT" --id native --mode self-reporting --run case_tls_handshake_key_update_0RTT
case_test_case "initial_salt_v1_key_derivation" --id native --mode self-reporting --run case_tls_handshake_initial_salt_v1_key_derivation
case_test_case "crypto_error_cert_verify" --id native --mode self-reporting --run case_tls_handshake_crypto_error_cert_verify
case_test_case "crypto_error_not_fixed_enum" --id native --mode self-reporting --run case_tls_handshake_crypto_error_not_fixed_enum
case_test_case "aead_confidentiality_boundary_updates_keys" --id native --mode self-reporting --run case_tls_handshake_aead_confidentiality_boundary_updates_keys
case_test_case "aead_confidentiality_exhaustion_stops_sender" --id native --mode self-reporting --run case_tls_handshake_aead_confidentiality_exhaustion_stops_sender
case_test_case "key_update_stale_deadline" --id 905 --mode self-reporting --run case_tls_handshake_key_update_stale_deadline
case_test_case "quic_v2_handshake" --id 913 --mode self-reporting \
    --run case_tls_handshake_quic_v2_handshake
case_test_case "quic_v2_unsupported" --id 914 --mode self-reporting \
    --run case_tls_handshake_quic_v2_unsupported
case_test_case "quic_v2_retry" --id 915 --mode self-reporting \
    --run case_tls_handshake_quic_v2_retry
case_test_case "quic_v2_version_information" --id 918 \
    --mode self-reporting --run case_tls_handshake_quic_v2_version_information
case_test_case "quic_v2_resumption" --id 919 --mode self-reporting \
    --run case_tls_handshake_quic_v2_resumption
case_test_case "quic_v2_resumption_other_version" --id 920 \
    --mode self-reporting \
    --run case_tls_handshake_quic_v2_resumption_other_version

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
trap 'case_test_stop_server; case_test_cleanup_udp_port' EXIT

case_test_run
