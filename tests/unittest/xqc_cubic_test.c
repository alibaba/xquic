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
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_multipath.h"
#include "xqc_common_test.h"

/*
 * Mirror the private constants of xqc_cubic.c so the assertions
 * below stay readable without exposing them in the public header.
 * If xqc_cubic.c ever diverges from these numbers, the assertions
 * here are expected to be updated in the same commit.
 */
#define XQC_CUBIC_TEST_MSS              XQC_MSS
#define XQC_CUBIC_TEST_DEFAULT_INIT_WIN (10 * XQC_CUBIC_TEST_MSS)
#define XQC_CUBIC_TEST_MIN_WIN          (4 * XQC_CUBIC_TEST_MSS)
#define XQC_CUBIC_TEST_MAX_INIT_WIN     (100 * XQC_CUBIC_TEST_MSS)
#define XQC_CUBIC_TEST_BETA             718
#define XQC_CUBIC_TEST_BETA_SCALE       1024

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

void
xqc_test_cubic_loss_ssthresh()
{
    xqc_cubic_t     cubic;
    xqc_cc_params_t params = {0};
    uint64_t        expected_ssthresh;

    xqc_cubic_cb.xqc_cong_ctl_init(&cubic, NULL, params);
    expected_ssthresh = cubic.cwnd * XQC_CUBIC_TEST_BETA
                        / XQC_CUBIC_TEST_BETA_SCALE;
    xqc_cubic_cb.xqc_cong_ctl_on_lost(&cubic, 1);

    CU_ASSERT_EQUAL(cubic.ssthresh, expected_ssthresh);
    CU_ASSERT_EQUAL(cubic.cwnd, expected_ssthresh);
    CU_ASSERT_EQUAL(cubic.tcp_cwnd, expected_ssthresh);
}

void
xqc_test_cubic_loss_ssthresh_min_clamp()
{
    xqc_cubic_t     cubic;
    xqc_cc_params_t params = {0};
    uint64_t        expected_ssthresh;

    xqc_cubic_cb.xqc_cong_ctl_init(&cubic, NULL, params);
    cubic.cwnd = 5 * XQC_CUBIC_TEST_MSS;
    expected_ssthresh = cubic.cwnd * XQC_CUBIC_TEST_BETA
                        / XQC_CUBIC_TEST_BETA_SCALE;
    xqc_cubic_cb.xqc_cong_ctl_on_lost(&cubic, 1);

    CU_ASSERT_EQUAL(cubic.ssthresh, expected_ssthresh);
    CU_ASSERT_EQUAL(cubic.cwnd, XQC_CUBIC_TEST_MIN_WIN);
    CU_ASSERT_EQUAL(cubic.tcp_cwnd, XQC_CUBIC_TEST_MIN_WIN);
    CU_ASSERT_TRUE(cubic.cwnd > cubic.ssthresh);
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


void
xqc_test_cubic_persistent_congestion_reset()
{
    xqc_cubic_t       cubic;
    xqc_cc_params_t   params;
    xqc_packet_out_t  po;
    xqc_usec_t        lost_sent_time;
    xqc_usec_t        recovery_start;
    uint64_t          cwnd;

    memset(&params, 0, sizeof(params));
    memset(&po, 0, sizeof(po));
    xqc_cubic_cb.xqc_cong_ctl_init(&cubic, NULL, params);

    lost_sent_time = xqc_monotonic_timestamp() + 1;
    xqc_cubic_cb.xqc_cong_ctl_on_lost(&cubic, lost_sent_time);
    CU_ASSERT_FATAL(cubic.congestion_recovery_start_time != 0);

    recovery_start = cubic.congestion_recovery_start_time;
    xqc_cubic_cb.xqc_cong_ctl_reset_cwnd(&cubic);

    CU_ASSERT_EQUAL(cubic.congestion_recovery_start_time, 0);
    CU_ASSERT_EQUAL(cubic.cwnd, cubic.min_cwnd);

    cwnd = cubic.cwnd;
    po.po_sent_time = recovery_start;
    po.po_used_size = 1000;
    xqc_cubic_cb.xqc_cong_ctl_on_ack(&cubic, &po, recovery_start + 1);

    CU_ASSERT(cubic.cwnd > cwnd);
}


void
xqc_test_cubic_reordered_ack_in_recovery()
{
    xqc_cubic_t       cubic;
    xqc_cc_params_t   params;
    xqc_packet_out_t  po;
    xqc_usec_t        lost_sent_time;
    uint64_t          cwnd;

    memset(&params, 0, sizeof(params));
    memset(&po, 0, sizeof(po));
    xqc_cubic_cb.xqc_cong_ctl_init(&cubic, NULL, params);

    lost_sent_time = xqc_monotonic_timestamp() + 1;
    xqc_cubic_cb.xqc_cong_ctl_on_lost(&cubic, lost_sent_time);
    CU_ASSERT_FATAL(cubic.congestion_recovery_start_time != 0);

    cwnd = cubic.cwnd;
    po.po_sent_time = cubic.congestion_recovery_start_time;
    po.po_used_size = 1000;
    xqc_cubic_cb.xqc_cong_ctl_on_ack(
        &cubic, &po, cubic.congestion_recovery_start_time + 1);

    CU_ASSERT_EQUAL(cubic.cwnd, cwnd);
}


/*
 * RFC 9002 Section 7.8, RFC 9438 Sections 4.2 and 5.8: CUBIC grows its
 * window only while the sender uses it, and the time the sender does not
 * is left out of t. A connection's path drives the CUBIC instance, as
 * xqc_send_ctl_is_cwnd_limited() decides from its send state.
 */
static void
xqc_test_cubic_set_cwnd_limited(xqc_send_ctl_t *send_ctl, xqc_bool_t limited)
{
    send_ctl->ctl_is_cwnd_limited = limited;
    send_ctl->ctl_max_bytes_in_flight = limited ? 0x7fffffff : 0;
}

static void
xqc_test_cubic_ack(xqc_cubic_t *cubic, xqc_usec_t sent_time, xqc_usec_t now)
{
    xqc_packet_out_t po;

    memset(&po, 0, sizeof(po));
    po.po_sent_time = sent_time;
    po.po_used_size = 1000;
    xqc_cubic_cb.xqc_cong_ctl_on_ack(cubic, &po, now);
}

static void
xqc_test_cubic_slow_start_case(xqc_bool_t cwnd_limited, uint64_t growth)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_cubic_t *cubic = send_ctl->ctl_cong;
    CU_ASSERT_FATAL(send_ctl->ctl_cong_callback == &xqc_cubic_cb);

    uint64_t cwnd = cubic->cwnd;
    xqc_test_cubic_set_cwnd_limited(send_ctl, cwnd_limited);
    xqc_test_cubic_ack(cubic, 1, 1001);
    CU_ASSERT_EQUAL(cubic->cwnd, cwnd + growth);

    xqc_engine_destroy(conn->engine);
}

/* slow start with the window in use: + acked bytes */
void
xqc_test_cubic_slow_start_cwnd_limited()
{
    xqc_test_cubic_slow_start_case(XQC_TRUE, 1000);
}

/* slow start with nothing ever in flight: no growth */
void
xqc_test_cubic_slow_start_app_limited()
{
    xqc_test_cubic_slow_start_case(XQC_FALSE, 0);
}

/*
 * Congestion avoidance: an epoch starts with an ACK at E. One sender does
 * not use its window from an ACK at E + 1 ms until one at E + 100.009 s,
 * the other acknowledges at E + 1 ms with its window in use. Without those
 * 100.008 s both are 1 ms into the epoch and end with the same window.
 */
static uint64_t
xqc_test_cubic_epoch_case(xqc_bool_t idle)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_cubic_t *cubic = send_ctl->ctl_cong;
    xqc_usec_t rs, e;
    uint64_t cwnd, ret;

    xqc_cubic_cb.xqc_cong_ctl_on_lost(cubic, 1);
    rs = cubic->congestion_recovery_start_time;
    CU_ASSERT_FATAL(rs != 0);
    e = rs + 1000;

    xqc_test_cubic_set_cwnd_limited(send_ctl, XQC_TRUE);
    xqc_test_cubic_ack(cubic, rs + 1, e);
    CU_ASSERT_FATAL(cubic->epoch_start == e);

    if (idle) {
        xqc_test_cubic_set_cwnd_limited(send_ctl, XQC_FALSE);
        cwnd = cubic->cwnd;
        xqc_test_cubic_ack(cubic, rs + 1, e + 1000);
        xqc_test_cubic_ack(cubic, rs + 1, e + 100000000);
        CU_ASSERT_EQUAL(cubic->cwnd, cwnd);
        xqc_test_cubic_set_cwnd_limited(send_ctl, XQC_TRUE);
        xqc_test_cubic_ack(cubic, rs + 1, e + 100009000);
        CU_ASSERT_EQUAL(cubic->epoch_start, e + 100008000);

    } else {
        xqc_test_cubic_ack(cubic, rs + 1, e + 1000);
    }

    ret = cubic->cwnd;
    xqc_engine_destroy(conn->engine);
    return ret;
}

void
xqc_test_cubic_epoch_skips_app_limited_time()
{
    CU_ASSERT_EQUAL(xqc_test_cubic_epoch_case(XQC_TRUE),
                    xqc_test_cubic_epoch_case(XQC_FALSE));
}
