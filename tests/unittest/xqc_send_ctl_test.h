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
 * Regression test for issue #722 (RFC 9002 in-flight definition):
 * pure PADDING packets must count toward bytes_in_flight even though
 * they are not ack-eliciting.
 */
void xqc_test_send_ctl_inflight_padding(void);

#endif
