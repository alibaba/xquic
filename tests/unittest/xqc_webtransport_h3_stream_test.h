/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_H3_STREAM_TEST_H
#define XQC_WEBTRANSPORT_H3_STREAM_TEST_H

void xqc_test_wt_h3_stream_demux(void);
void xqc_test_wt_h3_stream_passthrough(void);
void xqc_test_wt_h3_stream_prefix_errors(void);
void xqc_test_wt_h3_stream_backpressure(void);
void xqc_test_wt_h3_stream_buffer_limit(void);
void xqc_test_wt_h3_stream_reliable_reset(void);
void xqc_test_wt_h3_stream_reset_after_detach(void);
void xqc_test_wt_h3_stream_goaway(void);
void xqc_test_wt_h3_stream_stop_sending(void);

#endif
