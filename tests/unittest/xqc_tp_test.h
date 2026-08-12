/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_TP_TEST_H_
#define _XQC_TP_TEST_H_

void xqc_test_transport_params();
void xqc_test_max_ack_delay_default_when_absent(void);
void xqc_test_max_ack_delay_valid_boundary(void);
void xqc_test_max_ack_delay_invalid_boundary(void);
void xqc_test_max_udp_payload_size_valid_boundary(void);
void xqc_test_max_udp_payload_size_invalid_boundary(void);
void xqc_test_tp_cid_overflow();
void xqc_test_active_cid_limit_minimum();
void xqc_test_check_transport_params_cids();

#endif
