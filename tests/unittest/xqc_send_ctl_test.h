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

#endif
