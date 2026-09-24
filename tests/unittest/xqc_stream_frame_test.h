/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_STREAM_FRAME_TEST_H_INCLUDED_
#define _XQC_STREAM_FRAME_TEST_H_INCLUDED_

void  xqc_test_stream_frame();
void  xqc_test_stream_frame_buffered_limit();

void  xqc_test_stop_sending_drops_queued_stream_packets();
void  xqc_test_stop_sending_spares_other_streams();

void  xqc_test_stream_frame_coalesce_contiguous();
void  xqc_test_stream_frame_coalesce_bounds();
void  xqc_test_stream_frame_coalesce_through_handler();
void  xqc_test_stream_frame_coalesce_reordered();
void  xqc_test_stream_frame_coalesce_fin_only();
void  xqc_test_stream_frame_coalesce_smaller_joins();
void  xqc_test_stream_frame_coalesce_back_to_front();
void  xqc_test_stream_recv_credit_held();
void  xqc_test_stream_recv_credit_released();
void  xqc_test_stream_reset_extends_conn_credit();
void  xqc_test_stream_reset_small_keeps_conn_credit();

#endif /* _XQC_STREAM_FRAME_TEST_H_INCLUDED_ */
