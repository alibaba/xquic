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

/* write_mmsg_ecn, lost testing packets, ACK_EXTENDED ECN Counts */
void xqc_test_ecn_write_mmsg(void);
void xqc_test_ecn_burst_flags(void);
void xqc_test_ecn_testing_lost(void);
void xqc_test_ecn_ack_ext_negotiation(void);
void xqc_test_ecn_ack_ext_frame_counts(void);

#endif /* XQC_ECN_TEST_H */
