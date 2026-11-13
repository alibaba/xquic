/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_CUBIC_TEST_H_INCLUDED_
#define _XQC_CUBIC_TEST_H_INCLUDED_

void xqc_test_cubic ();
void xqc_test_cubic_loss_ssthresh ();
void xqc_test_cubic_loss_ssthresh_min_clamp ();
void xqc_test_cubic_init_cwnd ();
void xqc_test_cubic_persistent_congestion_reset ();
void xqc_test_cubic_reordered_ack_in_recovery ();
void xqc_test_cubic_slow_start_cwnd_limited ();
void xqc_test_cubic_slow_start_app_limited ();
void xqc_test_cubic_epoch_skips_app_limited_time ();

#endif /* _XQC_CUBIC_TEST_H_INCLUDED_ */
