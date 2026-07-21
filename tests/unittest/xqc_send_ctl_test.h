/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_SEND_CTL_TEST_H
#define XQC_SEND_CTL_TEST_H

/*
 * Regression tests for issue #599 (RFC 9002 6.2.1):
 * xqc_send_ctl_calc_pto must use peer-reported max_ack_delay
 * (remote_settings), not local_settings.
 */
void xqc_test_pto_uses_remote_max_ack_delay(void);
void xqc_test_pto_remote_default_when_unset(void);

/*
 * Regression test for issue #724 (RFC 9002 5.3):
 * xqc_send_ctl_update_rtt must cap ack_delay by max_ack_delay
 * before subtracting it from latest_rtt, using the default 25ms
 * cap until the handshake is confirmed.
 */
void xqc_test_send_ctl_update_rtt_ack_delay_cap(void);

/*
 * Regression tests for issue #739 (RFC 9002 5.2):
 * After persistent congestion is detected the RTT estimator on the
 * affected path must be reset, and the next RTT sample must re-seed
 * the estimator via the first-sample branch of update_rtt.
 *
 * - resets_rtt: persistent congestion clears min_rtt/srtt/rttvar
 *   and first_rtt_sample_time, and resets cwnd.
 * - rtt_reseeds_from_new_sample: after reset, the very next sample
 *   becomes the new srtt/min_rtt directly (not smoothed with the
 *   stale srtt that triggered the reset).
 * - single_loss_does_not_reset_rtt: ordinary loss that fails the
 *   persistent-congestion predicate must leave RTT state untouched.
 * - no_rtt_sample_early_return: when no RTT sample has been taken
 *   yet, detect_lost returns before the persistent-congestion check
 *   and must not mutate RTT state.
 */
void xqc_test_send_ctl_persistent_congestion_resets_rtt(void);
void xqc_test_send_ctl_persistent_congestion_rtt_reseeds_from_new_sample(void);
void xqc_test_send_ctl_single_loss_does_not_reset_rtt(void);
void xqc_test_send_ctl_persistent_congestion_no_rtt_sample_early_return(void);

/*
 * Regression test for issue #823 / #756 BUG1 (RFC 9001 §6.1):
 * Key update initiator must NOT consider update confirmed until an ACK
 * is received for a packet sent with the new key phase.
 */
void xqc_test_key_update_initiator_confirmation(void);

/*
 * Regression test for issue #756 BUG2 (RFC 9001 §6.2):
 * Responder detects a second peer key update before sending the ACK
 * required for the first peer-initiated update.
 */
void xqc_test_consecutive_key_update_detection(void);

/*
 * Regression test for issue #756 BUG3 (RFC 9001 §6.4):
 * Old-key packet with pkt_num higher than any new-key packet must be
 * detected as KEY_UPDATE_ERROR during the 3*PTO old-key retention window.
 */
void xqc_test_old_key_high_pktnum_detection(void);

#endif
