/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_cubic_test.h"
#include "src/congestion_control/xqc_cubic.h"
#include "src/transport/xqc_packet.h"
#include <CUnit/CUnit.h>
#include <stdio.h>
#include <string.h>
#include "src/common/xqc_time.h"

/*
 * Mirror the private constants of xqc_cubic.c so the assertions
 * below stay readable without exposing them in the public header.
 * If xqc_cubic.c ever diverges from these numbers, the assertions
 * here are expected to be updated in the same commit.
 */
#define XQC_CUBIC_TEST_MSS              XQC_MSS
#define XQC_CUBIC_TEST_DEFAULT_INIT_WIN (10 * XQC_CUBIC_TEST_MSS)
#define XQC_CUBIC_TEST_MAX_INIT_WIN     (100 * XQC_CUBIC_TEST_MSS)

void
print_cubic(xqc_cubic_t *cubic)
{

#ifdef DEBUG_PRINT
    printf("cwnd:%llu, tcp_cwnd:%llu, last_max_cwnd:%llu, ssthresh:%llu, epoch_start:%llu, bic_origin_point:%llu\n",
           cubic->cwnd, cubic->tcp_cwnd, cubic->last_max_cwnd, cubic->ssthresh, cubic->epoch_start, cubic->bic_origin_point);
#endif
}

void
xqc_test_cubic()
{
    xqc_msec_t now = xqc_monotonic_timestamp();

    xqc_cubic_t cubic;
    xqc_msec_t delay = 100;
    xqc_cc_params_t params = {.init_cwnd = 10};
    xqc_cubic_cb.xqc_cong_ctl_init(&cubic, NULL, params);

    print_cubic(&cubic);

    /* slow start */
    for (int i = 0; i < 10; ++i) {
        xqc_packet_out_t po;
        po.po_sent_time = now;
        po.po_used_size = 1000;
        xqc_cubic_cb.xqc_cong_ctl_on_ack(&cubic, &po, now + delay);
        now += 1000000;
        print_cubic(&cubic);
    }

    /* lost */
    xqc_cubic_cb.xqc_cong_ctl_on_lost(&cubic, now);
    print_cubic(&cubic);

    /* congestion avoid */
    for (int i = 0; i < 10; ++i) {
        xqc_packet_out_t po;
        po.po_sent_time = now;
        po.po_used_size = 1000;
        xqc_cubic_cb.xqc_cong_ctl_on_ack(&cubic, &po, now + delay);
        now += 1000000;
        print_cubic(&cubic);
    }

    xqc_cubic_cb.xqc_cong_ctl_reset_cwnd(&cubic);
    print_cubic(&cubic);

}

/*
 * Regression guard for issue #728. CUBIC's default initial congestion
 * window must match RFC 9002 Section 7.2 (10 * MSS with XQC_MSS = 1436),
 * and the customize_on path must clamp caller-supplied values into
 * [XQC_CUBIC_MIN_WIN/MSS, XQC_CUBIC_MAX_INIT_WIN/MSS], falling back to
 * the default outside that range.
 */
void
xqc_test_cubic_init_cwnd()
{
    xqc_cubic_t     cubic;
    xqc_cc_params_t params;

    /* Case 1: no customization, default IW. */
    memset(&params, 0, sizeof(params));
    xqc_cubic_cb.xqc_cong_ctl_init(&cubic, NULL, params);
    CU_ASSERT_EQUAL(cubic.init_cwnd, XQC_CUBIC_TEST_DEFAULT_INIT_WIN);
    CU_ASSERT_EQUAL(cubic.cwnd, XQC_CUBIC_TEST_DEFAULT_INIT_WIN);
    CU_ASSERT_EQUAL(cubic.tcp_cwnd, XQC_CUBIC_TEST_DEFAULT_INIT_WIN);
    CU_ASSERT_EQUAL(cubic.last_max_cwnd, XQC_CUBIC_TEST_DEFAULT_INIT_WIN);

    /*
     * Case 2: customize_on with a value inside the [4, 100] packet
     * range. The init_cwnd field is documented in packets and the
     * CCA scales by MSS internally.
     */
    memset(&params, 0, sizeof(params));
    params.customize_on = 1;
    params.init_cwnd = 20;
    xqc_cubic_cb.xqc_cong_ctl_init(&cubic, NULL, params);
    CU_ASSERT_EQUAL(cubic.init_cwnd, 20 * XQC_CUBIC_TEST_MSS);
    CU_ASSERT_EQUAL(cubic.cwnd, 20 * XQC_CUBIC_TEST_MSS);

    /* Case 3: customize_on above the 100-packet cap falls back. */
    memset(&params, 0, sizeof(params));
    params.customize_on = 1;
    params.init_cwnd = 200;
    xqc_cubic_cb.xqc_cong_ctl_init(&cubic, NULL, params);
    CU_ASSERT_EQUAL(cubic.init_cwnd, XQC_CUBIC_TEST_DEFAULT_INIT_WIN);
    CU_ASSERT_EQUAL(cubic.cwnd, XQC_CUBIC_TEST_DEFAULT_INIT_WIN);

    /* Case 4: customize_on below the 4-packet floor falls back. */
    memset(&params, 0, sizeof(params));
    params.customize_on = 1;
    params.init_cwnd = 1;
    xqc_cubic_cb.xqc_cong_ctl_init(&cubic, NULL, params);
    CU_ASSERT_EQUAL(cubic.init_cwnd, XQC_CUBIC_TEST_DEFAULT_INIT_WIN);
    CU_ASSERT_EQUAL(cubic.cwnd, XQC_CUBIC_TEST_DEFAULT_INIT_WIN);

    /* Case 5: customize_on exactly at the cap is accepted. */
    memset(&params, 0, sizeof(params));
    params.customize_on = 1;
    params.init_cwnd = 100;
    xqc_cubic_cb.xqc_cong_ctl_init(&cubic, NULL, params);
    CU_ASSERT_EQUAL(cubic.init_cwnd, XQC_CUBIC_TEST_MAX_INIT_WIN);
    CU_ASSERT_EQUAL(cubic.cwnd, XQC_CUBIC_TEST_MAX_INIT_WIN);
}
