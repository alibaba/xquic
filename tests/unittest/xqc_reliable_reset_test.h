#ifndef XQC_RELIABLE_RESET_TEST_H
#define XQC_RELIABLE_RESET_TEST_H

void xqc_test_reliable_reset_transport_params(void);
void xqc_test_reliable_reset_receive_order(void);
void xqc_test_reliable_reset_receive_errors(void);
void xqc_test_reliable_reset_ack_order(void);
void xqc_test_reliable_reset_stop_sending(void);
void xqc_test_reliable_reset_send_errors(void);

void xqc_test_reliable_reset_close(void);
void xqc_test_reliable_reset_late_ack(void);
void xqc_test_reliable_reset_retry(void);
void xqc_test_reliable_reset_zero_validation(void);

void xqc_test_reliable_reset_direction_error(void);
void xqc_test_reliable_reset_zero_fin(void);
void xqc_test_reliable_reset_zero_close(void);
void xqc_test_reliable_reset_peer_reset_send(void);
void xqc_test_reliable_reset_peer_reset_terminal(void);
void xqc_test_reliable_reset_peer_reset_pending(void);

#endif
