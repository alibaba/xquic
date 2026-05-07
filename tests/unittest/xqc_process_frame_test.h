/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_PROCESS_FRAME_TEST_H_INCLUDED_
#define _XQC_PROCESS_FRAME_TEST_H_INCLUDED_

void xqc_test_process_frame();

void xqc_test_handshake_app_conn_close_is_converted();

void xqc_test_1rtt_only_flow_control_frames_are_buffered();

void xqc_test_parse_padding_frame();

void xqc_test_large_ack_frame();

#endif /* _XQC_PROCESS_FRAME_TEST_H_INCLUDED_ */
