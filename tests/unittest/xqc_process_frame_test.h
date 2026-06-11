/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_PROCESS_FRAME_TEST_H_INCLUDED_
#define _XQC_PROCESS_FRAME_TEST_H_INCLUDED_

void xqc_test_process_frame();

void xqc_test_parse_padding_frame();

void xqc_test_large_ack_frame();

void xqc_test_stream_frame_offset_overflow();

void xqc_test_crypto_frame_in_0rtt_rejected();

void xqc_test_crypto_frame_in_initial_accepted();

void xqc_test_crypto_frame_in_handshake_accepted();

void xqc_test_crypto_frame_in_short_header_accepted();

void xqc_test_crypto_frame_dispatched_via_xqc_process_frame();

void xqc_test_crypto_in_0rtt_emits_connection_close();

void xqc_test_ack_ecn_normal_parse();

void xqc_test_ack_plain_regression();

void xqc_test_ack_ecn_truncated();

void xqc_test_ack_ecn_followed_by_ping();

void xqc_test_new_conn_id_zero_len_cid(void);

void xqc_test_stream_frame_on_send_only_stream(void);

#endif /* _XQC_PROCESS_FRAME_TEST_H_INCLUDED_ */
