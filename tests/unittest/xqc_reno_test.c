/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_reno_test.h"
#include "src/congestion_control/xqc_new_reno.h"
#include <stdio.h>
#include <CUnit/CUnit.h>
#include "src/common/xqc_time.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_packet_out.h"

void
print_reno(xqc_new_reno_t *reno)
{
#ifdef DEBUG_PRINT
    printf("cwnd:%u, ssthresh:%u, recovery_start_time:%llu\n",
           reno->reno_congestion_window, reno->reno_ssthresh, reno->reno_recovery_start_time);
#endif
}

void
xqc_test_reno()
{
#ifndef XQC_ENABLE_RENO
    return;
#endif
    xqc_msec_t now = xqc_monotonic_timestamp();

    xqc_new_reno_t reno;
    xqc_msec_t delay = 100;
    xqc_cc_params_t params = {.init_cwnd = 10};
    xqc_reno_cb.xqc_cong_ctl_init(&reno, NULL, params);
    print_reno(&reno);

    /* slow start */
    for (int i = 0; i < 10; ++i) {
        xqc_packet_out_t po;
        po.po_sent_time = now;
        po.po_used_size = 1000;
        xqc_reno_cb.xqc_cong_ctl_on_ack(&reno, &po, now + delay);
        now += 1000000;
        print_reno(&reno);
    }

    /* lost */
    xqc_reno_cb.xqc_cong_ctl_on_lost(&reno, now);
    print_reno(&reno);

    /* congestion avoid */
    for (int i = 0; i < 10; ++i) {
        xqc_packet_out_t po;
        po.po_sent_time = now;
        po.po_used_size = 1000;
        xqc_reno_cb.xqc_cong_ctl_on_ack(&reno, &po, now + delay);
        now += 1000000;
        print_reno(&reno);
    }

    xqc_reno_cb.xqc_cong_ctl_reset_cwnd(&reno);
    print_reno(&reno);

}

/*
 * Mirror of the RFC 9002 Section 7.2 formula evaluated in
 * src/congestion_control/xqc_new_reno.c. Kept in the test so that
 * the assertions below pin the formula independently of any
 * compile-time MSS the production macro happens to use.
 */
static uint32_t
xqc_test_reno_expected_iw(uint32_t mss)
{
    uint32_t ten_mss = 10 * mss;
    uint32_t two_mss = 2 * mss;
    uint32_t cap = two_mss > 14720 ? two_mss : 14720;
    return ten_mss < cap ? ten_mss : cap;
}

void
xqc_test_reno_init_cwnd()
{
#ifndef XQC_ENABLE_RENO
    return;
#endif
    xqc_new_reno_t reno;
    xqc_cc_params_t params = {.init_cwnd = 10};

    xqc_reno_cb.xqc_cong_ctl_init(&reno, NULL, params);

    /*
     * Regression guard for issue #727: the live initial window must
     * match the RFC 9002 Section 7.2 formula evaluated against the
     * compile-time XQC_MSS. With the stock MSS the value is 14360.
     */
    CU_ASSERT_EQUAL(reno.reno_congestion_window,
                    xqc_test_reno_expected_iw(XQC_MSS));

    /*
     * Lock the formula against canonical MSS values so a deployment
     * built with a larger maximum datagram size (for example jumbo
     * frames at MSS=9000) cannot silently drift above the 18000-byte
     * cap the RFC permits in that case.
     */
    CU_ASSERT_EQUAL(xqc_test_reno_expected_iw(1200), 12000);
    CU_ASSERT_EQUAL(xqc_test_reno_expected_iw(1436), 14360);
    CU_ASSERT_EQUAL(xqc_test_reno_expected_iw(1500), 14720);
    CU_ASSERT_EQUAL(xqc_test_reno_expected_iw(9000), 18000);
}