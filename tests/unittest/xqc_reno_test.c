/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_reno_test.h"
#include "src/congestion_control/xqc_new_reno.h"
#include <stdio.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include "src/common/xqc_time.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_packet_out.h"

/*
 * Mirror the private constants of xqc_new_reno.c so the assertions
 * below stay readable without exposing them in the public header.
 * Kept in lockstep with XQC_RENO_MIN_INIT_WIN / XQC_RENO_MAX_INIT_WIN
 * in the production file; if those diverge, update here in the same
 * commit.
 */
#define XQC_RENO_TEST_MSS               XQC_MSS
#define XQC_RENO_TEST_MIN_INIT_WIN_PKTS 4
#define XQC_RENO_TEST_MAX_INIT_WIN_PKTS 100

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

/*
 * Regression guard for issue #763. Prior to the fix xqc_reno_init
 * ignored cc_params.init_cwnd entirely, leaving NewReno deployments
 * silently pinned to the RFC 9002 default while Cubic/BBR/Copa
 * honored the override. The customize_on path must now accept
 * values in [4, 100] packets and fall back to the default outside
 * that range. customize_on=0 must continue to ignore init_cwnd so
 * callers that zero-fill xqc_cc_params_t stay on the default.
 */
void
xqc_test_reno_init_cwnd_override()
{
#ifndef XQC_ENABLE_RENO
    return;
#endif
    xqc_new_reno_t  reno;
    xqc_cc_params_t params;
    uint32_t        default_iw = xqc_test_reno_expected_iw(XQC_RENO_TEST_MSS);

    /*
     * Case 1: zero-filled params (customize_on == 0). The init_cwnd
     * field must not be read; the default IW must hold. This is the
     * regression path for callers that never opt into customization.
     */
    memset(&params, 0, sizeof(params));
    xqc_reno_cb.xqc_cong_ctl_init(&reno, NULL, params);
    CU_ASSERT_EQUAL(reno.reno_congestion_window, default_iw);

    /*
     * Case 2: customize_on == 0 with a non-zero init_cwnd. Even
     * though the field is populated the override path must not
     * fire, mirroring Cubic's behavior.
     */
    memset(&params, 0, sizeof(params));
    params.customize_on = 0;
    params.init_cwnd = 20;
    xqc_reno_cb.xqc_cong_ctl_init(&reno, NULL, params);
    CU_ASSERT_EQUAL(reno.reno_congestion_window, default_iw);

    /*
     * Case 3: customize_on with a value inside the [4, 100] packet
     * range. init_cwnd is documented in packets; xqc_reno_init
     * scales by XQC_kMaxDatagramSize internally.
     */
    memset(&params, 0, sizeof(params));
    params.customize_on = 1;
    params.init_cwnd = 20;
    xqc_reno_cb.xqc_cong_ctl_init(&reno, NULL, params);
    CU_ASSERT_EQUAL(reno.reno_congestion_window, 20 * XQC_RENO_TEST_MSS);

    /* Case 4: exact lower bound (4 packets) is accepted. */
    memset(&params, 0, sizeof(params));
    params.customize_on = 1;
    params.init_cwnd = XQC_RENO_TEST_MIN_INIT_WIN_PKTS;
    xqc_reno_cb.xqc_cong_ctl_init(&reno, NULL, params);
    CU_ASSERT_EQUAL(reno.reno_congestion_window,
                    XQC_RENO_TEST_MIN_INIT_WIN_PKTS * XQC_RENO_TEST_MSS);

    /* Case 5: exact upper bound (100 packets) is accepted. */
    memset(&params, 0, sizeof(params));
    params.customize_on = 1;
    params.init_cwnd = XQC_RENO_TEST_MAX_INIT_WIN_PKTS;
    xqc_reno_cb.xqc_cong_ctl_init(&reno, NULL, params);
    CU_ASSERT_EQUAL(reno.reno_congestion_window,
                    XQC_RENO_TEST_MAX_INIT_WIN_PKTS * XQC_RENO_TEST_MSS);

    /*
     * Case 6: just below the floor falls back rather than being
     * clamped. The contract surfaces misconfiguration instead of
     * silently rewriting it.
     */
    memset(&params, 0, sizeof(params));
    params.customize_on = 1;
    params.init_cwnd = XQC_RENO_TEST_MIN_INIT_WIN_PKTS - 1;
    xqc_reno_cb.xqc_cong_ctl_init(&reno, NULL, params);
    CU_ASSERT_EQUAL(reno.reno_congestion_window, default_iw);

    /* Case 7: just above the cap falls back. */
    memset(&params, 0, sizeof(params));
    params.customize_on = 1;
    params.init_cwnd = XQC_RENO_TEST_MAX_INIT_WIN_PKTS + 1;
    xqc_reno_cb.xqc_cong_ctl_init(&reno, NULL, params);
    CU_ASSERT_EQUAL(reno.reno_congestion_window, default_iw);

    /*
     * Case 8: customize_on with init_cwnd == 0. The packet count
     * resolves to 0 bytes which is below the floor; the default
     * must hold so a partially-initialized params struct cannot
     * stall the connection.
     */
    memset(&params, 0, sizeof(params));
    params.customize_on = 1;
    params.init_cwnd = 0;
    xqc_reno_cb.xqc_cong_ctl_init(&reno, NULL, params);
    CU_ASSERT_EQUAL(reno.reno_congestion_window, default_iw);
}