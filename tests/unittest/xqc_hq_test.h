/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#ifndef XQC_HQ_TEST_H
#define XQC_HQ_TEST_H

void xqc_test_hq_request_fin(void);
void xqc_test_hq_request_transport_fin(void);
void xqc_test_hq_request_delayed_fin(void);
void xqc_test_hq_request_fragmented(void);
void xqc_test_hq_request_small_buffer(void);
void xqc_test_hq_request_no_buffer(void);
void xqc_test_hq_request_recv_reset(void);

#endif
