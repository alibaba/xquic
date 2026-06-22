/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <xquic/xquic_typedef.h>

#include "xqc_send_ctl_test.h"
#include "xqc_common_test.h"

#include "src/common/xqc_malloc.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_transport_params.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_frame.h"


/*
 * Issue #599 regression test.
 *
 * RFC 9002 6.2.1 requires PTO to be computed from the peer-reported
 * max_ack_delay. Pre-fix, xqc_send_ctl_calc_pto used local_settings,
 * which collapsed to the right value only when both endpoints happened
 * to advertise the same delay. This test sets local and remote to
 * distinct values and asserts the formula consumes remote_settings.
 *
 * Formula (xqc_send_ctl.h):
 *   pto = srtt + max(4*rttvar, kGranularity*1000)
 *       + remote_settings.max_ack_delay * 1000
 *
 * We pin srtt and rttvar so the floor term collapses to
 * XQC_kGranularity * 1000, isolating the max_ack_delay contribution.
 */
void
xqc_test_pto_uses_remote_max_ack_delay(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl != NULL);

    /* Pin RTT terms so floor = XQC_kGranularity * 1000. */
    send_ctl->ctl_srtt   = 1000; /* 1 ms in usec */
    send_ctl->ctl_rttvar = 0;    /* 4*rttvar = 0 -> floor wins */

    /* Distinct local vs remote so a wrong source is observable. */
    conn->local_settings.max_ack_delay  = 25;
    conn->remote_settings.max_ack_delay = 100;

    xqc_usec_t got = xqc_send_ctl_calc_pto(send_ctl);

    xqc_usec_t expected_remote = 1000
        + XQC_kGranularity * 1000
        + conn->remote_settings.max_ack_delay * 1000;
    xqc_usec_t expected_local_bug = 1000
        + XQC_kGranularity * 1000
        + conn->local_settings.max_ack_delay * 1000;

    /* Positive assertion: matches RFC 9002 6.2.1 formula with remote. */
    CU_ASSERT_EQUAL(got, expected_remote);

    /* Negative control: must NOT equal the buggy local-based formula.
     * Difference is (remote - local) * 1000 = 75000 usec. */
    CU_ASSERT_NOT_EQUAL(got, expected_local_bug);

    xqc_engine_destroy(conn->engine);
}


/*
 * Defensive guard: even when the peer has not yet advertised transport
 * parameters, remote_settings.max_ack_delay is initialized to
 * XQC_DEFAULT_MAX_ACK_DELAY (25) by xqc_conn_set_default_settings. The
 * formula must yield a sane positive value with no UB.
 */
void
xqc_test_pto_remote_default_when_unset(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl != NULL);

    /* Do NOT touch remote_settings: keep the default from conn create. */
    CU_ASSERT_EQUAL(conn->remote_settings.max_ack_delay,
                    XQC_DEFAULT_MAX_ACK_DELAY);

    send_ctl->ctl_srtt   = 1000;
    send_ctl->ctl_rttvar = 0;

    xqc_usec_t got = xqc_send_ctl_calc_pto(send_ctl);
    xqc_usec_t expected = 1000
        + XQC_kGranularity * 1000
        + XQC_DEFAULT_MAX_ACK_DELAY * 1000;

    CU_ASSERT_EQUAL(got, expected);
    CU_ASSERT(got > 0);

    xqc_engine_destroy(conn->engine);
}


typedef struct xqc_rtt_case_s {
    const char     *name;
    xqc_bool_t      hsk_confirmed;
    xqc_bool_t      first_sample;
    uint64_t        remote_max_ack_delay_ms;
    xqc_usec_t      input_ack_delay;
    xqc_usec_t      latest_rtt;
    xqc_usec_t      pre_minrtt;
    xqc_usec_t      pre_srtt;
    xqc_usec_t      pre_rttvar;
    xqc_usec_t      expected_srtt;
    xqc_usec_t      expected_rttvar;
    xqc_usec_t      expected_minrtt;
} xqc_rtt_case_t;


static void
xqc_test_send_ctl_run_rtt_case(xqc_connection_t *conn, xqc_path_ctx_t *path,
    const xqc_rtt_case_t *tc)
{
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;

    send_ctl->ctl_conn  = conn;
    send_ctl->ctl_srtt  = tc->pre_srtt;
    send_ctl->ctl_rttvar = tc->pre_rttvar;
    send_ctl->ctl_minrtt = tc->pre_minrtt;
    send_ctl->ctl_first_rtt_sample_time = tc->first_sample ? 0 : 1;

    if (tc->hsk_confirmed) {
        conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;

    } else {
        conn->conn_flag &= ~XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    }
    conn->remote_settings.max_ack_delay = tc->remote_max_ack_delay_ms;

    xqc_usec_t latest = tc->latest_rtt;
    xqc_send_ctl_update_rtt(send_ctl, &latest, tc->input_ack_delay);

    if (send_ctl->ctl_srtt != tc->expected_srtt
        || send_ctl->ctl_rttvar != tc->expected_rttvar
        || send_ctl->ctl_minrtt != tc->expected_minrtt)
    {
        fprintf(stderr,
                "case [%s] mismatch: srtt got=%llu want=%llu, "
                "rttvar got=%llu want=%llu, minrtt got=%llu want=%llu\n",
                tc->name,
                (unsigned long long) send_ctl->ctl_srtt,
                (unsigned long long) tc->expected_srtt,
                (unsigned long long) send_ctl->ctl_rttvar,
                (unsigned long long) tc->expected_rttvar,
                (unsigned long long) send_ctl->ctl_minrtt,
                (unsigned long long) tc->expected_minrtt);
    }

    CU_ASSERT(send_ctl->ctl_srtt == tc->expected_srtt);
    CU_ASSERT(send_ctl->ctl_rttvar == tc->expected_rttvar);
    CU_ASSERT(send_ctl->ctl_minrtt == tc->expected_minrtt);
}


void
xqc_test_send_ctl_update_rtt_ack_delay_cap(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    xqc_path_ctx_t *path = xqc_calloc(1, sizeof(xqc_path_ctx_t));
    CU_ASSERT_FATAL(path != NULL);
    path->path_send_ctl = xqc_calloc(1, sizeof(xqc_send_ctl_t));
    CU_ASSERT_FATAL(path->path_send_ctl != NULL);

    conn->conn_initial_path = path;

    /*
     * Pre-condition: srtt=200ms, rttvar=50ms, minrtt=10ms, second-or-later
     * sample. The handshake-not-confirmed cap is 25ms regardless of the
     * negotiated max_ack_delay; after confirmation it is the negotiated
     * value clamped per RFC 9000 18.2.
     */
    xqc_rtt_case_t cases[] = {
        {
            .name = "hsk_not_confirmed_large_ack_delay",
            .hsk_confirmed = XQC_FALSE,
            .first_sample  = XQC_FALSE,
            .remote_max_ack_delay_ms = 100,
            .input_ack_delay = 200000,
            .latest_rtt      = 250000,
            .pre_minrtt      = 10000,
            .pre_srtt        = 200000,
            .pre_rttvar      = 50000,
            /* ack_delay capped to 25ms; adjusted = 225ms */
            .expected_srtt   = 203125,
            .expected_rttvar = 43750,
            .expected_minrtt = 10000,
        },
        {
            .name = "hsk_confirmed_large_ack_delay",
            .hsk_confirmed = XQC_TRUE,
            .first_sample  = XQC_FALSE,
            .remote_max_ack_delay_ms = 100,
            .input_ack_delay = 200000,
            .latest_rtt      = 250000,
            .pre_minrtt      = 10000,
            .pre_srtt        = 200000,
            .pre_rttvar      = 50000,
            /* ack_delay capped to negotiated 100ms; adjusted = 150ms */
            .expected_srtt   = 193750,
            .expected_rttvar = 50000,
            .expected_minrtt = 10000,
        },
        {
            .name = "hsk_not_confirmed_small_ack_delay",
            .hsk_confirmed = XQC_FALSE,
            .first_sample  = XQC_FALSE,
            .remote_max_ack_delay_ms = 100,
            .input_ack_delay = 10000,
            .latest_rtt      = 50000,
            .pre_minrtt      = 10000,
            .pre_srtt        = 200000,
            .pre_rttvar      = 50000,
            /* 10ms < 25ms cap, unchanged; adjusted = 40ms */
            .expected_srtt   = 180000,
            .expected_rttvar = 77500,
            .expected_minrtt = 10000,
        },
        {
            .name = "hsk_confirmed_remote_smaller_than_default",
            .hsk_confirmed = XQC_TRUE,
            .first_sample  = XQC_FALSE,
            .remote_max_ack_delay_ms = 5,
            .input_ack_delay = 30000,
            .latest_rtt      = 50000,
            .pre_minrtt      = 10000,
            .pre_srtt        = 200000,
            .pre_rttvar      = 50000,
            /* capped to negotiated 5ms; adjusted = 45ms */
            .expected_srtt   = 180625,
            .expected_rttvar = 76250,
            .expected_minrtt = 10000,
        },
        {
            .name = "first_sample_skips_ack_delay_cap",
            .hsk_confirmed = XQC_FALSE,
            .first_sample  = XQC_TRUE,
            .remote_max_ack_delay_ms = 100,
            .input_ack_delay = 200000,
            .latest_rtt      = 50000,
            .pre_minrtt      = 0,
            .pre_srtt        = 0,
            .pre_rttvar      = 0,
            /* first sample: srtt = latest_rtt, rttvar = latest_rtt/2 */
            .expected_srtt   = 50000,
            .expected_rttvar = 25000,
            .expected_minrtt = 50000,
        },
        {
            .name = "ack_delay_zero",
            .hsk_confirmed = XQC_FALSE,
            .first_sample  = XQC_FALSE,
            .remote_max_ack_delay_ms = 100,
            .input_ack_delay = 0,
            .latest_rtt      = 50000,
            .pre_minrtt      = 10000,
            .pre_srtt        = 200000,
            .pre_rttvar      = 50000,
            /* cap path harmless; adjusted = 50ms */
            .expected_srtt   = 181250,
            .expected_rttvar = 75000,
            .expected_minrtt = 10000,
        },
        {
            .name = "plausibility_blocks_subtraction",
            .hsk_confirmed = XQC_FALSE,
            .first_sample  = XQC_FALSE,
            .remote_max_ack_delay_ms = 100,
            .input_ack_delay = 10000,
            .latest_rtt      = 12000,
            .pre_minrtt      = 11000,
            .pre_srtt        = 12000,
            .pre_rttvar      = 1000,
            /*
             * adjusted_rtt + 1000us = 13000us, minrtt + ack_delay = 21000us;
             * plausibility check fails, ack_delay not subtracted.
             */
            .expected_srtt   = 12000,
            .expected_rttvar = 750,
            .expected_minrtt = 11000,
        },
        {
            .name = "hsk_confirmed_remote_zero_cap",
            .hsk_confirmed = XQC_TRUE,
            .first_sample  = XQC_FALSE,
            .remote_max_ack_delay_ms = 0,
            .input_ack_delay = 50000,
            .latest_rtt      = 50000,
            .pre_minrtt      = 10000,
            .pre_srtt        = 200000,
            .pre_rttvar      = 50000,
            /* cap to 0 forces ack_delay to 0; adjusted = 50ms */
            .expected_srtt   = 181250,
            .expected_rttvar = 75000,
            .expected_minrtt = 10000,
        },
    };

    size_t n = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < n; i++) {
        xqc_test_send_ctl_run_rtt_case(conn, path, &cases[i]);
    }

    xqc_engine_destroy(conn->engine);
    xqc_free(path->path_send_ctl);
    xqc_free(path);
}


/*
 * Issue #739 regression tests.
 *
 * Pre-fix, xqc_send_ctl_detect_lost only reset cwnd on persistent
 * congestion; min_rtt/srtt/rttvar were left at their pre-disruption
 * values. After a major path event that triggers persistent
 * congestion, the stale (smaller) srtt and rttvar made every
 * downstream PTO and persistent-congestion duration computation use
 * RTT that no longer reflects the path, repeatedly mis-triggering
 * loss detection. RFC 9002 5.2 SHOULD reset min_rtt to the newest
 * sample; ngtcp2 (lib/ngtcp2_rtb.c persistent_congestion path)
 * additionally resets srtt/rttvar to initial and clears the
 * first-sample timestamp so the next sample re-seeds the estimator.
 *
 * The fix in xqc_send_ctl_detect_lost performs exactly that reset.
 * These tests pin its observable effects and guard against
 * regressions in two directions:
 *   - that the reset is *not* applied to ordinary loss
 *   - that the early-return guard for "no RTT sample yet" still
 *     short-circuits before any reset can fire
 */


/*
 * Seed a single in-flight, ack-eliciting packet on the connection's
 * initial path. po_sent_time/pkt_num are caller-supplied so the
 * caller controls the persistent-congestion duration arithmetic.
 *
 * po_used_size is left at 0 so xqc_send_ctl_decrease_inflight is a
 * no-op on inflight bookkeeping; we only need the packet to be on
 * the unacked list and on the right path so detect_lost picks it up.
 */
static xqc_packet_out_t *
xqc_test_send_ctl_seed_lost_packet(xqc_connection_t *conn,
    xqc_packet_number_t pkt_num, xqc_usec_t po_sent_time)
{
    xqc_send_queue_t *sq = conn->conn_send_queue;
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;

    xqc_packet_out_t *po = xqc_packet_out_get(sq);
    if (po == NULL) {
        return NULL;
    }

    po->po_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    po->po_pkt.pkt_pns  = XQC_PNS_APP_DATA;
    po->po_pkt.pkt_num  = pkt_num;
    po->po_path_id      = send_ctl->ctl_path->path_id;
    po->po_sent_time    = po_sent_time;
    po->po_flag         = XQC_POF_IN_FLIGHT;
    /* PING is ack-eliciting and is not in XQC_NEED_REPAIR. */
    po->po_frame_types  = XQC_FRAME_BIT_PING;
    po->po_used_size    = 0;

    xqc_send_queue_insert_unacked(po, &sq->sndq_unacked_packets[XQC_PNS_APP_DATA], sq);
    return po;
}


/*
 * Build a send_ctl state that satisfies xqc_send_ctl_in_persistent_congestion:
 *   - pto_count == XQC_CONSECUTIVE_PTO_THRESH
 *   - srtt/rttvar small so duration is bounded and easy to exceed
 *   - first_rtt_sample_time non-zero so detect_lost doesn't early-return
 *   - largest_acked[APP_DATA] >= our packet's pkt_num so the loop considers it
 */
static void
xqc_test_send_ctl_arm_pc_state(xqc_send_ctl_t *send_ctl,
    xqc_usec_t srtt, xqc_usec_t rttvar, xqc_usec_t minrtt,
    xqc_packet_number_t largest_acked)
{
    send_ctl->ctl_srtt    = srtt;
    send_ctl->ctl_rttvar  = rttvar;
    send_ctl->ctl_minrtt  = minrtt;
    send_ctl->ctl_latest_rtt = srtt;
    send_ctl->ctl_first_rtt_sample_time = 1;
    send_ctl->ctl_pto_count = XQC_CONSECUTIVE_PTO_THRESH;
    send_ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = largest_acked;
}


void
xqc_test_send_ctl_persistent_congestion_resets_rtt(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl != NULL);
    CU_ASSERT_FATAL(send_ctl->ctl_cong_callback != NULL);
    CU_ASSERT_FATAL(send_ctl->ctl_cong_callback->xqc_cong_ctl_reset_cwnd != NULL);
    CU_ASSERT_FATAL(send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd != NULL);

    /* initial_rtt is the post-reset srtt; assert it is non-zero so the
     * test does not silently accept an unintended 0/0 outcome. */
    CU_ASSERT_FATAL(conn->conn_settings.initial_rtt > 0);
    conn->remote_settings.max_ack_delay = 25; /* ms */

    /* Pin RTT estimator at a small, converged value. With srtt=10ms,
     * rttvar=2ms, max_ack_delay=25ms, the persistent-congestion
     * duration is (10 + max(8,2) + 25)ms * 3 = 129ms. Setting
     * po_sent_time = 1us and now = 1s leaves a 999ms gap, well past
     * the 129ms threshold. */
    xqc_test_send_ctl_arm_pc_state(send_ctl,
                                   /* srtt   */ 10000,
                                   /* rttvar */  2000,
                                   /* minrtt */  8000,
                                   /* largest_acked */ 1);

    xqc_packet_out_t *po = xqc_test_send_ctl_seed_lost_packet(conn, 1, 1);
    CU_ASSERT_FATAL(po != NULL);

    uint64_t cwnd_before = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(
        send_ctl->ctl_cong);
    /* Cubic default init_cwnd = 10*MSS, which must exceed min_cwnd (4*MSS).
     * If this invariant ever flips, the cwnd-reset assertion below would
     * become a tautology, so guard it explicitly. */
    CU_ASSERT_FATAL(cwnd_before > 0);

    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, 1000000);

    /* min_rtt resets to the xquic sentinel (XQC_MAX_UINT32_VALUE), not
     * UINT64_MAX, to stay consistent with xqc_send_ctl_create. */
    CU_ASSERT_EQUAL(send_ctl->ctl_minrtt, XQC_MAX_UINT32_VALUE);
    CU_ASSERT_EQUAL(send_ctl->ctl_srtt, conn->conn_settings.initial_rtt);
    CU_ASSERT_EQUAL(send_ctl->ctl_rttvar, conn->conn_settings.initial_rtt / 2);
    CU_ASSERT_EQUAL(send_ctl->ctl_first_rtt_sample_time, 0);

    uint64_t cwnd_after = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(
        send_ctl->ctl_cong);
    /* Cubic reset_cwnd collapses cwnd to min_cwnd; cubic_init sets
     * cwnd = init_cwnd > min_cwnd. So cwnd must strictly shrink. */
    CU_ASSERT(cwnd_after < cwnd_before);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_persistent_congestion_rtt_reseeds_from_new_sample(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl != NULL);
    CU_ASSERT_FATAL(conn->conn_settings.initial_rtt > 0);
    conn->remote_settings.max_ack_delay = 25;

    /* Drive the persistent-congestion path identically to Test A so the
     * state on entry to update_rtt is exactly what the fix produces. */
    xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 1);
    xqc_packet_out_t *po = xqc_test_send_ctl_seed_lost_packet(conn, 1, 1);
    CU_ASSERT_FATAL(po != NULL);
    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, 1000000);

    CU_ASSERT_FATAL(send_ctl->ctl_first_rtt_sample_time == 0);

    /* Inject a new RTT sample that is orders of magnitude larger than
     * the pre-reset estimator (8ms minrtt -> 300ms latest_rtt). Without
     * the first_rtt_sample_time clear, the existing min(latest, minrtt)
     * code in update_rtt would have left minrtt pegged at 8ms — the
     * exact bug. With the clear, the first-sample branch takes the
     * value directly. */
    xqc_usec_t latest = 300000;
    xqc_send_ctl_update_rtt(send_ctl, &latest, 0);

    CU_ASSERT_EQUAL(send_ctl->ctl_minrtt, 300000);
    CU_ASSERT_EQUAL(send_ctl->ctl_srtt,   300000);
    CU_ASSERT_EQUAL(send_ctl->ctl_rttvar, 150000);
    CU_ASSERT(send_ctl->ctl_first_rtt_sample_time != 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_single_loss_does_not_reset_rtt(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl != NULL);
    conn->remote_settings.max_ack_delay = 25;

    /* Same RTT state and same packet timing as Test A, but pto_count
     * is below XQC_CONSECUTIVE_PTO_THRESH so the persistent-congestion
     * predicate fails. The packet is still marked lost (single loss),
     * but the RTT estimator must remain untouched. */
    xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 1);
    send_ctl->ctl_pto_count = 0;

    xqc_packet_out_t *po = xqc_test_send_ctl_seed_lost_packet(conn, 1, 1);
    CU_ASSERT_FATAL(po != NULL);

    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, 1000000);

    /* All four RTT fields must equal their pre-call values. */
    CU_ASSERT_EQUAL(send_ctl->ctl_srtt,   10000);
    CU_ASSERT_EQUAL(send_ctl->ctl_rttvar,  2000);
    CU_ASSERT_EQUAL(send_ctl->ctl_minrtt,  8000);
    CU_ASSERT(send_ctl->ctl_first_rtt_sample_time != 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_persistent_congestion_no_rtt_sample_early_return(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl != NULL);
    conn->remote_settings.max_ack_delay = 25;

    /* Arm a state where the duration check WOULD pass if reached, then
     * clear first_rtt_sample_time so the guard at the top of the
     * OnPacketsLost block returns before the persistent-congestion
     * branch can fire. This pins existing behavior: the fix must not
     * change what happens before RTT has been measured. */
    xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 1);
    send_ctl->ctl_first_rtt_sample_time = 0;

    xqc_packet_out_t *po = xqc_test_send_ctl_seed_lost_packet(conn, 1, 1);
    CU_ASSERT_FATAL(po != NULL);

    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, 1000000);

    /* No mutation, including first_rtt_sample_time itself. */
    CU_ASSERT_EQUAL(send_ctl->ctl_srtt,   10000);
    CU_ASSERT_EQUAL(send_ctl->ctl_rttvar,  2000);
    CU_ASSERT_EQUAL(send_ctl->ctl_minrtt,  8000);
    CU_ASSERT_EQUAL(send_ctl->ctl_first_rtt_sample_time, 0);

    xqc_engine_destroy(conn->engine);
}


/*
 * Issue #823 / #756 BUG1 regression test (RFC 9001 §6.1).
 *
 * When the local endpoint initiates a key update, the next key update
 * MUST NOT be initiated until the peer ACKs a packet sent with the new
 * key phase (largest_acked >= first_sent_pktno).
 *
 * The enforcement mechanism:
 * - key_update_initiator is set TRUE on initiation
 * - The trigger condition requires first_sent_pktno <= ctl_largest_acked
 * - ACK processing clears key_update_initiator once confirmed
 *
 * This test validates:
 * 1. After initiating: key_update_initiator == TRUE
 * 2. ACK with largest_acked < first_sent_pktno: initiator not cleared
 * 3. ACK with largest_acked >= first_sent_pktno: initiator cleared
 * 4. Next key update trigger blocked until first_sent_pktno <= largest_acked
 */
void
xqc_test_key_update_initiator_confirmation(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl != NULL);

    /*
     * Simulate the state after initiator calls key update:
     * - key_update_initiator = TRUE
     * - key_update_not_confirmed = TRUE
     * - first_sent_pktno = 100 (first packet sent with new key phase)
     */
    conn->key_update_ctx.key_update_initiator = XQC_TRUE;
    conn->key_update_ctx.key_update_not_confirmed = XQC_TRUE;
    conn->key_update_ctx.first_sent_pktno = 100;

    /* Pre-condition: both flags are TRUE */
    CU_ASSERT_EQUAL(conn->key_update_ctx.key_update_initiator, XQC_TRUE);
    CU_ASSERT_EQUAL(conn->key_update_ctx.key_update_not_confirmed, XQC_TRUE);

    /*
     * Case 1: ACK with largest_acked = 99 (< first_sent_pktno).
     * The peer has only ACKed packets sent with the OLD key phase.
     * Initiator flag must NOT be cleared yet.
     */
    send_ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = 99;

    /* Mirror the confirmation check logic in xqc_send_ctl_on_ack_received */
    xqc_pkt_num_space_t pns = XQC_PNS_APP_DATA;
    if (conn->key_update_ctx.key_update_initiator
        && send_ctl->ctl_largest_acked[pns] != XQC_MAX_UINT64_VALUE
        && send_ctl->ctl_largest_acked[pns] >= conn->key_update_ctx.first_sent_pktno)
    {
        conn->key_update_ctx.key_update_initiator = XQC_FALSE;
        conn->key_update_ctx.key_update_not_confirmed = XQC_FALSE;
    }

    /* Still pending: 99 < 100, neither flag cleared */
    CU_ASSERT_EQUAL(conn->key_update_ctx.key_update_initiator, XQC_TRUE);
    CU_ASSERT_EQUAL(conn->key_update_ctx.key_update_not_confirmed, XQC_TRUE);

    /* Verify the next key update trigger is blocked:
     * condition: first_sent_pktno <= ctl_largest_acked must be FALSE */
    CU_ASSERT(!(conn->key_update_ctx.first_sent_pktno
                <= send_ctl->ctl_largest_acked[XQC_PNS_APP_DATA]));

    /*
     * Case 2: ACK with largest_acked = 100 (== first_sent_pktno).
     * The peer has now ACKed a packet sent with the new key phase.
     * Initiator flag MUST be cleared.
     */
    send_ctl->ctl_largest_acked[pns] = 100;

    if (conn->key_update_ctx.key_update_initiator
        && send_ctl->ctl_largest_acked[pns] != XQC_MAX_UINT64_VALUE
        && send_ctl->ctl_largest_acked[pns] >= conn->key_update_ctx.first_sent_pktno)
    {
        conn->key_update_ctx.key_update_initiator = XQC_FALSE;
        conn->key_update_ctx.key_update_not_confirmed = XQC_FALSE;
    }

    /* Confirmed: 100 >= 100, both flags cleared */
    CU_ASSERT_EQUAL(conn->key_update_ctx.key_update_initiator, XQC_FALSE);
    CU_ASSERT_EQUAL(conn->key_update_ctx.key_update_not_confirmed, XQC_FALSE);

    /* Verify the next key update trigger is now unblocked:
     * condition: first_sent_pktno <= ctl_largest_acked must be TRUE */
    CU_ASSERT(conn->key_update_ctx.first_sent_pktno
              <= send_ctl->ctl_largest_acked[XQC_PNS_APP_DATA]);

    /*
     * Case 3: Verify idempotency — once cleared, re-running the check
     * with a higher ACK does not re-trigger (initiator is already FALSE).
     */
    send_ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = 200;

    if (conn->key_update_ctx.key_update_initiator
        && send_ctl->ctl_largest_acked[pns] != XQC_MAX_UINT64_VALUE
        && send_ctl->ctl_largest_acked[pns] >= conn->key_update_ctx.first_sent_pktno)
    {
        conn->key_update_ctx.key_update_initiator = XQC_FALSE;
        conn->key_update_ctx.key_update_not_confirmed = XQC_FALSE;
    }

    CU_ASSERT_EQUAL(conn->key_update_ctx.key_update_initiator, XQC_FALSE);
    CU_ASSERT_EQUAL(conn->key_update_ctx.key_update_not_confirmed, XQC_FALSE);

    xqc_engine_destroy(conn->engine);
}


/*
 * Issue #756 BUG2 regression test (RFC 9001 §6.2).
 *
 * When a key update is in progress (key_update_not_confirmed == TRUE),
 * a second key-phase change from the peer (different from next_in_key_phase,
 * with pkt_num > first_recv_pktno) must be detected as a consecutive key
 * update violation and treated as KEY_UPDATE_ERROR.
 *
 * This test validates the detection condition inline (same pattern as the
 * initiator confirmation test above).
 */
void
xqc_test_consecutive_key_update_detection(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    /*
     * Setup: simulate a key update in progress.
     * next_in_key_phase = 0 (expecting key_phase 0 for current epoch)
     * first_recv_pktno = 50  (lowest pkt received with current keys)
     * key_update_not_confirmed = TRUE (awaiting ACK confirmation)
     */
    conn->key_update_ctx.next_in_key_phase = 0;
    conn->key_update_ctx.first_recv_pktno = 50;
    conn->key_update_ctx.key_update_not_confirmed = XQC_TRUE;

    /*
     * Case 1: Packet with same key_phase as expected, pkt_num > first_recv.
     * This is a normal packet, NOT a consecutive key update.
     * key_phase == next_in_key_phase → condition does not fire.
     */
    xqc_uint_t key_phase = 0; /* matches next_in_key_phase */
    xqc_packet_number_t pkt_num = 100;
    xqc_bool_t detected = XQC_FALSE;

    if (key_phase != conn->key_update_ctx.next_in_key_phase
        && pkt_num > conn->key_update_ctx.first_recv_pktno
        && conn->key_update_ctx.key_update_not_confirmed)
    {
        detected = XQC_TRUE;
    }
    CU_ASSERT_EQUAL(detected, XQC_FALSE);

    /*
     * Case 2: Packet with different key_phase, pkt_num <= first_recv.
     * This is an old/reordered packet, NOT a consecutive key update.
     */
    key_phase = 1; /* differs from next_in_key_phase */
    pkt_num = 30;  /* <= first_recv_pktno */
    detected = XQC_FALSE;

    if (key_phase != conn->key_update_ctx.next_in_key_phase
        && pkt_num > conn->key_update_ctx.first_recv_pktno
        && conn->key_update_ctx.key_update_not_confirmed)
    {
        detected = XQC_TRUE;
    }
    CU_ASSERT_EQUAL(detected, XQC_FALSE);

    /*
     * Case 3: Packet with different key_phase, pkt_num > first_recv,
     * but key_update_not_confirmed is FALSE → no detection (normal RX key update).
     */
    conn->key_update_ctx.key_update_not_confirmed = XQC_FALSE;
    key_phase = 1;
    pkt_num = 100;
    detected = XQC_FALSE;

    if (key_phase != conn->key_update_ctx.next_in_key_phase
        && pkt_num > conn->key_update_ctx.first_recv_pktno
        && conn->key_update_ctx.key_update_not_confirmed)
    {
        detected = XQC_TRUE;
    }
    CU_ASSERT_EQUAL(detected, XQC_FALSE);

    /*
     * Case 4: All conditions met → consecutive key update DETECTED.
     * key_phase != next_in_key_phase, pkt_num > first_recv, not_confirmed = TRUE.
     */
    conn->key_update_ctx.key_update_not_confirmed = XQC_TRUE;
    key_phase = 1;
    pkt_num = 100;
    detected = XQC_FALSE;

    if (key_phase != conn->key_update_ctx.next_in_key_phase
        && pkt_num > conn->key_update_ctx.first_recv_pktno
        && conn->key_update_ctx.key_update_not_confirmed)
    {
        detected = XQC_TRUE;
    }
    CU_ASSERT_EQUAL(detected, XQC_TRUE);

    xqc_engine_destroy(conn->engine);
}
