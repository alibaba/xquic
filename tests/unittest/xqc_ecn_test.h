/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_ECN_TEST_H
#define XQC_ECN_TEST_H

/* RFC 9000 Sections 13.4 and 19.3.2, RFC 9002 Section 7.1: ECN */
void xqc_test_ecn_recv_counts(void);
void xqc_test_ecn_ack_frame_counts(void);
void xqc_test_ecn_ack_mp_frame_counts(void);
void xqc_test_ecn_marking(void);
void xqc_test_ecn_write_socket(void);
void xqc_test_ecn_validation(void);
void xqc_test_ecn_validation_on_ack(void);
void xqc_test_ecn_ce_congestion_event(void);

#endif /* XQC_ECN_TEST_H */
