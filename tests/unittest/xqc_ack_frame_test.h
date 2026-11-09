/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_ACK_FRAME_TEST_H_INCLUDED_
#define _XQC_ACK_FRAME_TEST_H_INCLUDED_

void xqc_test_ack_frame_golden(void);
void xqc_test_ack_frame_next_frame(void);
void xqc_test_ack_frame_negative_pn(void);
void xqc_test_ack_frame_truncated(void);
void xqc_test_ack_frame_range_count(void);
void xqc_test_ack_frame_fuzz(void);

#endif /* _XQC_ACK_FRAME_TEST_H_INCLUDED_ */
