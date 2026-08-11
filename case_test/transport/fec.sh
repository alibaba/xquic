#!/bin/bash
#
# FEC endpoint case-test group.


ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "transport.fec"

fec_start_default_server()
{
    rm -rf tp_localhost test_session xqc_token
    case_test_start_server ${SERVER_BIN} -l d -e -f
}

fec_start_stream_recovery_server()
{
    rm -rf tp_localhost test_session xqc_token
    case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -e -f -x 1 -M
}

fec_start_frame_type_server()
{
    rm -rf tp_localhost test_session xqc_token
    case_test_start_server stdbuf -oL ${SERVER_BIN} -l d -e -f -x 700 -M
}

fec_start_datagram_server()
{
    rm -rf tp_localhost test_session xqc_token
    case_test_start_server ${SERVER_BIN} -l d -Q 65535 -e -U 1 -s 1 --dgram_qos 3 -f
}

fec_negotiate_encoder_fec_scheme()
{
    fec_start_default_server

    clear_log
    echo -e "negotiate_encoder_fec_schemes ...\c"
    case_test_sudo ${CLIENT_BIN} -l d -g > stdlog
    clog_res1=`grep "|xqc_negotiate_fec_schemes|set final encoder fec scheme: XOR" clog`
    slog_res1=`grep "|xqc_negotiate_fec_schemes|set final encoder fec scheme: XOR" slog`
    errlog=`grep_err_log`
    [ -z "$errlog" ] && [ -n "$clog_res1" ] && [ -n "$slog_res1" ]
}

fec_negotiate_decoder_fec_scheme()
{
    fec_start_default_server

    clear_log
    echo -e "negotiate_decoder_fec_schemes ...\c"
    case_test_sudo ${CLIENT_BIN} -l d -g > stdlog
    clog_res2=`grep "|xqc_negotiate_fec_schemes|set final decoder fec scheme: XOR" clog`
    slog_res2=`grep "|xqc_negotiate_fec_schemes|set final decoder fec scheme: XOR" slog`
    errlog=`grep_err_log`
    [ -z "$errlog" ] && [ -n "$clog_res2" ] && [ -n "$slog_res2" ]
}

fec_recovered_function_of_stream_xor()
{
    fec_start_stream_recovery_server

    clear_log
    echo -e "check fec recovery function of stream using XOR ...\c"
    case_test_sudo ${CLIENT_BIN} -s 5120000 -l e -E -d 30 -g -M -i lo -i lo > stdlog
    slog_res1=`grep '|process packet of block .\{1,3\} successfully' slog`
    errlog=`grep_err_log`
    [ -z "$errlog" ] && [ -n "$slog_res1" ]
}

fec_recovered_function_of_stream_rsc()
{
    fec_start_stream_recovery_server

    clear_log
    echo -e "check fec recovery function of stream using RSC ...\c"
    case_test_sudo ${CLIENT_BIN} -s 5120000 -l e -E -d 30 -g -M -i lo -i lo --fec_encoder 8 --fec_decoder 8 > stdlog
    slog_res1=`grep '|process packet of block .\{1,3\} successfully' slog`
    errlog=`grep_err_log`
    [ -z "$errlog" ] && [ -n "$slog_res1" ]
}

fec_recovered_function_of_stream_pm()
{
    fec_start_stream_recovery_server

    clear_log
    echo -e "check fec recovery function of stream using PM ...\c"
    case_test_sudo ${CLIENT_BIN} -s 5120000 -l e -E -d 30 -g -M -i lo -i lo --fec_encoder 12 --fec_decoder 12 > stdlog
    slog_res1=`grep '|process packet of block .\{1,3\} successfully' slog`
    errlog=`grep_err_log`
    [ -z "$errlog" ] && [ -n "$slog_res1" ]
}

fec_send_repair_ahead()
{
    fec_start_stream_recovery_server

    clear_log
    echo -e "check fec recovery when send repair packets ahead ...\c"
    case_test_sudo ${CLIENT_BIN} -s 5120000 -l d -E -d 30 -g -M -i lo -i lo --fec_encoder 12 --fec_decoder 12 --fec_timeout 20 > stdlog
    clog_res=`grep '|send repair packets ahead finished' clog`
    errlog=`grep_err_log`
    [ -z "$errlog" ] && [ -n "$clog_res" ]
}

frame_type_bit_repair_sent()
{
    fec_start_frame_type_server

    clear_log
    echo -e "frame_type_bit repair symbol sent (bit 32 non-zero) ...\c"
    case_test_sudo ${CLIENT_BIN} -s 5120000 -l d -E -d 30 -g -x 700 -M -i lo -i lo > stdlog
    clog_repair=`grep 'frame:.*FEC_REPAIR' clog`
    echo_result=`grep ">>>>>>>> pass" stdlog`
    errlog=`grep_err_log`
    [ -z "$errlog" ] && [ -n "$clog_repair" ] && [ "$echo_result" == ">>>>>>>> pass:1" ]
}

frame_type_bit_repair_received()
{
    fec_start_frame_type_server

    clear_log
    echo -e "frame_type_bit repair symbol received (bit 32 non-zero) ...\c"
    case_test_sudo ${CLIENT_BIN} -s 5120000 -l d -E -d 30 -g -x 700 -M -i lo -i lo > stdlog
    slog_repair=`grep 'frame:.*FEC_REPAIR' slog`
    echo_result=`grep ">>>>>>>> pass" stdlog`
    errlog=`grep_err_log`
    [ -z "$errlog" ] && [ -n "$slog_repair" ] && [ "$echo_result" == ">>>>>>>> pass:1" ]
}

fec_recovered_function_of_datagram_xor()
{
    fec_start_datagram_server

    clear_log
    echo -e "check fec recovery function of datagram with XOR fec scheme ...\c"
    case_test_sudo ${CLIENT_BIN} -l d -T 1 -s 3000 -U 1 -Q 65535 -E -x 205 -N -1 -t 1 --dgram_qos 3 -g > stdlog
    slog_res1=`grep '|process packet of block 0 successfully' slog`
    errlog=`grep_err_log`
    [ -z "$errlog" ] && [ -n "$slog_res1" ]
}

fec_recovered_function_of_datagram_rsc()
{
    fec_start_datagram_server

    clear_log
    echo -e "check fec recovery function of datagram with RSC fec scheme ...\c"
    case_test_sudo ${CLIENT_BIN} -l d -T 1 -s 3000 -U 1 -Q 65535 -E -x 205 -N -1 -t 1 --dgram_qos 3 -g --fec_encoder 8 --fec_decoder 8 > stdlog
    slog_res1=`grep '|process packet of block 0 successfully' slog`
    errlog=`grep_err_log`
    [ -z "$errlog" ] && [ -n "$slog_res1" ]
}

fec_recovered_function_of_datagram_pm()
{
    fec_start_datagram_server

    clear_log
    echo -e "check fec recovery function of datagram with Packet Mask scheme ...\c"
    case_test_sudo ${CLIENT_BIN} -l d -T 1 -s 3000 -U 1 -Q 65535 -E -x 205 -N -1 -t 1 --dgram_qos 3 -g --fec_encoder 12 --fec_decoder 12 > stdlog
    slog_res1=`grep '|process packet of block 0 successfully' slog`
    errlog=`grep_err_log`
    [ -z "$errlog" ] && [ -n "$slog_res1" ]
}

fec_recovered_function_of_datagram_xor_and_rsc()
{
    fec_start_datagram_server

    clear_log
    echo -e "check fec recovery function of datagram with XOR(encoder) and RSC(decoder) fec schemes ...\c"
    case_test_sudo ${CLIENT_BIN} -l d -T 1 -s 3000 -U 1 -Q 65535 -E -x 205 -N -1 -t 1 --dgram_qos 3 -g --fec_encoder 8 --fec_decoder 11 > stdlog
    slog_res1=`grep '|process packet of block 0 successfully' slog`
    errlog=`grep_err_log`
    [ -z "$errlog" ] && [ -n "$slog_res1" ]
}

fec_recovered_function_of_datagram_rsc_and_xor()
{
    fec_start_datagram_server

    clear_log
    echo -e "check fec recovery function of datagram with XOR(decoder) and RSC(encoder) fec schemes ...\c"
    case_test_sudo ${CLIENT_BIN} -l d -T 1 -s 3000 -U 1 -Q 65535 -E -x 205 -N -1 -t 1 --dgram_qos 3 -g --fec_encoder 11 --fec_decoder 8 > stdlog
    slog_res1=`grep '|process packet of block 0 successfully' slog`
    errlog=`grep_err_log`
    [ -z "$errlog" ] && [ -n "$slog_res1" ]
}

case_test_case "negotiate_encoder_fec_scheme" --id legacy --run fec_negotiate_encoder_fec_scheme
case_test_case "negotiate_decoder_fec_scheme" --id legacy --run fec_negotiate_decoder_fec_scheme
case_test_case "fec_recovered_function_of_stream_xor" --id legacy --run fec_recovered_function_of_stream_xor
case_test_case "fec_recovered_function_of_stream_rsc" --id legacy --run fec_recovered_function_of_stream_rsc
case_test_case "fec_recovered_function_of_stream_pm" --id legacy --run fec_recovered_function_of_stream_pm
case_test_case "fec_send_repair_ahead" --id legacy --run fec_send_repair_ahead
case_test_case "frame_type_bit_repair_sent" --id legacy --run frame_type_bit_repair_sent
case_test_case "frame_type_bit_repair_received" --id legacy --run frame_type_bit_repair_received
case_test_case "fec_recovered_function_of_datagram_xor" --id legacy --run fec_recovered_function_of_datagram_xor
case_test_case "fec_recovered_function_of_datagram_rsc" --id legacy --run fec_recovered_function_of_datagram_rsc
case_test_case "fec_recovered_function_of_datagram_pm" --id legacy --run fec_recovered_function_of_datagram_pm
case_test_case "fec_recovered_function_of_datagram_xor_and_rsc" --id legacy --run fec_recovered_function_of_datagram_xor_and_rsc
case_test_case "fec_recovered_function_of_datagram_rsc_and_xor" --id legacy --run fec_recovered_function_of_datagram_rsc_and_xor

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

if [[ "${CASE_TEST_GENERATE_ONLY:-0}" = "1" ]]; then
    exit 0
fi

case_test_enter_work_dir
trap case_test_stop_server EXIT
case_test_require_sudo

case_test_run
