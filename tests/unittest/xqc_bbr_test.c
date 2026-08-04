/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_bbr_test.h"
#include "src/congestion_control/xqc_bbr.h"
#include "src/congestion_control/xqc_sample.h"
#include "src/transport/xqc_packet.h"
#include <CUnit/CUnit.h>
#include <string.h>

#define XQC_BBR_TEST_MIN_INIT_WIN_PKTS 4
#define XQC_BBR_TEST_MAX_INIT_WIN_PKTS 100

static uint32_t
xqc_test_bbr_expected_iw(uint32_t mss)
{
    uint32_t ten_mss = 10 * mss;
    uint32_t two_mss = 2 * mss;
    uint32_t limit = two_mss > 14720 ? two_mss : 14720;

    return ten_mss < limit ? ten_mss : limit;
}

static void
xqc_test_bbr_init(xqc_bbr_t *bbr, xqc_cc_params_t params)
{
    xqc_sample_t sampler;

    memset(&sampler, 0, sizeof(sampler));
    xqc_bbr_cb.xqc_cong_ctl_init_bbr(bbr, &sampler, params);
}

/*
 * RFC 9002 Section 7.2 RECOMMENDS an initial congestion window of
 * min(10 * max_datagram_size, max(2 * max_datagram_size, 14720)).
 */
void
xqc_test_bbr_init_cwnd()
{
    xqc_bbr_t       bbr;
    xqc_cc_params_t params;
    uint32_t        expected_iw = xqc_test_bbr_expected_iw(XQC_MSS);

    memset(&params, 0, sizeof(params));
    xqc_test_bbr_init(&bbr, params);

    CU_ASSERT_EQUAL(bbr.initial_congestion_window, expected_iw);
    CU_ASSERT_EQUAL(bbr.congestion_window, expected_iw);
    CU_ASSERT_EQUAL(xqc_bbr_cb.xqc_cong_ctl_get_cwnd(&bbr), expected_iw);

    CU_ASSERT_EQUAL(xqc_test_bbr_expected_iw(1200), 12000);
    CU_ASSERT_EQUAL(xqc_test_bbr_expected_iw(1436), 14360);
    CU_ASSERT_EQUAL(xqc_test_bbr_expected_iw(1500), 14720);
    CU_ASSERT_EQUAL(xqc_test_bbr_expected_iw(9000), 18000);
}

/*
 * The explicit override remains valid within [4, 100] packets. Invalid
 * boundary values fall back to the RFC 9002 default.
 */
void
xqc_test_bbr_init_cwnd_override()
{
    xqc_bbr_t       bbr;
    xqc_cc_params_t params;
    uint32_t        expected_iw = xqc_test_bbr_expected_iw(XQC_MSS);

    memset(&params, 0, sizeof(params));
    params.customize_on = 1;
    params.init_cwnd = 20;
    xqc_test_bbr_init(&bbr, params);
    CU_ASSERT_EQUAL(bbr.initial_congestion_window, 20 * XQC_MSS);
    CU_ASSERT_EQUAL(bbr.congestion_window, 20 * XQC_MSS);

    memset(&params, 0, sizeof(params));
    params.customize_on = 1;
    params.init_cwnd = XQC_BBR_TEST_MIN_INIT_WIN_PKTS;
    xqc_test_bbr_init(&bbr, params);
    CU_ASSERT_EQUAL(bbr.initial_congestion_window,
                    XQC_BBR_TEST_MIN_INIT_WIN_PKTS * XQC_MSS);

    memset(&params, 0, sizeof(params));
    params.customize_on = 1;
    params.init_cwnd = XQC_BBR_TEST_MAX_INIT_WIN_PKTS;
    xqc_test_bbr_init(&bbr, params);
    CU_ASSERT_EQUAL(bbr.initial_congestion_window,
                    XQC_BBR_TEST_MAX_INIT_WIN_PKTS * XQC_MSS);

    memset(&params, 0, sizeof(params));
    params.customize_on = 1;
    params.init_cwnd = XQC_BBR_TEST_MIN_INIT_WIN_PKTS - 1;
    xqc_test_bbr_init(&bbr, params);
    CU_ASSERT_EQUAL(bbr.initial_congestion_window, expected_iw);
    CU_ASSERT_EQUAL(bbr.congestion_window, expected_iw);

    memset(&params, 0, sizeof(params));
    params.customize_on = 1;
    params.init_cwnd = XQC_BBR_TEST_MAX_INIT_WIN_PKTS + 1;
    xqc_test_bbr_init(&bbr, params);
    CU_ASSERT_EQUAL(bbr.initial_congestion_window, expected_iw);
    CU_ASSERT_EQUAL(bbr.congestion_window, expected_iw);

    memset(&params, 0, sizeof(params));
    params.customize_on = 1;
    params.init_cwnd = 0;
    xqc_test_bbr_init(&bbr, params);
    CU_ASSERT_EQUAL(bbr.initial_congestion_window, expected_iw);
    CU_ASSERT_EQUAL(bbr.congestion_window, expected_iw);
}
