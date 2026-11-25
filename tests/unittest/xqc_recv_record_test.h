/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_RECV_RECORD_TEST_H_INCLUDED_
#define _XQC_RECV_RECORD_TEST_H_INCLUDED_

void xqc_test_recv_record ();
void xqc_test_recv_timestamps_range_flag();

/*
 * RFC 9000 Section 18.2: the delayed ACK timer leaves room for a timer
 * that fires late within the advertised max_ack_delay.
 */
void xqc_test_ack_timer_within_max_ack_delay(void);
void xqc_test_ack_timer_small_max_ack_delay(void);

#endif /* _XQC_RECV_RECORD_TEST_H_INCLUDED_ */
