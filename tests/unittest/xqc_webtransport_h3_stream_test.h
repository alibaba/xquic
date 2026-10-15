/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_H3_STREAM_TEST_H
#define XQC_WEBTRANSPORT_H3_STREAM_TEST_H
void xqc_test_wt_h3_reset_flow_accounting(void);
void xqc_test_wt_h3_reset_credit(void);
void xqc_test_wt_h3_reset_after_short_read(void);
void xqc_test_wt_draft07_reset_dispatch(void);
void xqc_test_wt_draft07_stream_rules(void);

void xqc_test_wt_h3_stream_demux(void);
void xqc_test_wt_h3_server_bidi(void);
void xqc_test_wt_h3_stream_passthrough(void);
void xqc_test_wt_h3_stream_prefix_errors(void);
void xqc_test_wt_h3_stream_backpressure(void);
void xqc_test_wt_h3_stream_buffer_limit(void);
void xqc_test_wt_pending_session_admission(void);
void xqc_test_wt_pending_eviction_resume(void);
void xqc_test_wt_pending_fragmented_prefix(void);
void xqc_test_wt_h3_stream_reliable_reset(void);
void xqc_test_wt_h3_stream_conn_close_cleanup(void);
void xqc_test_wt_h3_stream_reset_after_detach(void);
void xqc_test_wt_h3_stream_goaway(void);
void xqc_test_wt_h3_stream_stop_sending(void);
void xqc_test_wt_h3_stream_recv_reset_error(void);
void xqc_test_wt_h3_stream_closed_session(void);
void xqc_test_wt_h3_stream_frame_position(void);

void xqc_test_wt_callback_close_iteration(void);
void xqc_test_wt_transport_mss_notify(void);
void xqc_test_wt_demo_echo_backpressure(void);
void xqc_test_wt_demo_datagram_retry(void);
#endif
