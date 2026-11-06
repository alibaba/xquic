/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <xquic/xquic_typedef.h>

#include "xqc_send_ctl_test.h"
#include "xqc_common_test.h"
#include "xqc_alloc_wrap.h"

#include "src/common/xqc_malloc.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_transport_params.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_frame.h"
#include "src/congestion_control/xqc_cubic.h"


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


#ifdef XQC_TEST_ALLOC_WRAP

/*
 * xqc_pn_ctl_create() allocates a ring of sent ACKs for each packet number
 * space. Each of its allocations fails in turn (xqc_alloc_wrap.h): the
 * creation fails, and once the engine is destroyed, nothing allocated since
 * the engine was created is left. The sweep ends with a run in which
 * nothing fails and the packet number control is created.
 */
void
xqc_test_pn_ctl_create_alloc_failures(void)
{
    long n;

    /* the first connection makes the allocations made once per process */
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_engine_destroy(conn->engine);

    for (n = 1; n < 100000; n++) {
        xqc_test_alloc_live = 0;
        xqc_test_alloc_tracking = 1;
        conn = test_engine_connect();
        CU_ASSERT_FATAL(conn != NULL);

        xqc_test_alloc_failed = 0;
        xqc_test_alloc_fail_at = n;
        xqc_test_alloc_count = 0;
        xqc_pn_ctl_t *pn_ctl = xqc_pn_ctl_create(conn);
        xqc_test_alloc_count = -1;
        CU_ASSERT((pn_ctl == NULL) == xqc_test_alloc_failed);
        if (pn_ctl != NULL) {
            xqc_pn_ctl_destroy(pn_ctl);
        }

        xqc_engine_destroy(conn->engine);
        xqc_test_alloc_tracking = 0;
        CU_ASSERT(xqc_test_alloc_live == 0);

        if (!xqc_test_alloc_failed) {
            /* nothing failed: the packet number control was created */
            break;
        }
    }
    CU_ASSERT(n > 1);
}

#else

void
xqc_test_pn_ctl_create_alloc_failures(void)
{
    /* needs the linker's --wrap (see tests/CMakeLists.txt) */
}

#endif


static xqc_path_ctx_t *
xqc_test_path_validation_create_path(xqc_connection_t *conn)
{
    xqc_path_ctx_t *path = xqc_calloc(1, sizeof(xqc_path_ctx_t));
    if (path == NULL) {
        return NULL;
    }

    path->parent_conn = conn;
    path->path_id = 1;
    path->app_path_status = XQC_APP_PATH_STATUS_AVAILABLE;
    path->path_send_ctl = xqc_send_ctl_create(path);
    if (path->path_send_ctl == NULL) {
        xqc_free(path);
        return NULL;
    }

    return path;
}


static void
xqc_test_path_validation_destroy_path(xqc_path_ctx_t *path)
{
    xqc_send_ctl_destroy(path->path_send_ctl);
    xqc_free(path);
}


void
xqc_test_path_validation_timeout_current_pto_dominates(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    conn->enable_multipath = XQC_TRUE;
    conn->remote_settings.max_ack_delay = 25;
    conn->conn_settings.initial_rtt = 100000;

    xqc_send_ctl_t *current = conn->conn_initial_path->path_send_ctl;
    current->ctl_srtt = 400000;
    current->ctl_rttvar = 50000;

    xqc_path_ctx_t *path = xqc_test_path_validation_create_path(conn);
    CU_ASSERT_FATAL(path != NULL);

    xqc_usec_t current_pto = 400000 + 4 * 50000 + 25 * 1000;
    xqc_usec_t new_path_pto = 100000 + 4 * 50000 + 25 * 1000;
    CU_ASSERT(current_pto > new_path_pto);

    xqc_usec_t before = xqc_monotonic_timestamp();
    xqc_int_t ret = xqc_path_init(path, conn);
    xqc_usec_t after = xqc_monotonic_timestamp();
    CU_ASSERT_EQUAL(ret, XQC_OK);

    xqc_timer_t *timer = &path->path_send_ctl->path_timer_manager
                          .timer[XQC_TIMER_PATH_IDLE];
    xqc_usec_t expected = 3 * current_pto;
    CU_ASSERT(timer->timer_is_set);
    CU_ASSERT(timer->expire_time >= before + expected);
    CU_ASSERT(timer->expire_time <= after + expected);
    CU_ASSERT_EQUAL(path->path_state, XQC_PATH_STATE_VALIDATING);

    xqc_test_path_validation_destroy_path(path);
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_path_validation_timeout_new_path_pto_dominates(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    conn->enable_multipath = XQC_TRUE;
    conn->remote_settings.max_ack_delay = 25;
    conn->conn_settings.initial_rtt = 400000;

    xqc_send_ctl_t *current = conn->conn_initial_path->path_send_ctl;
    current->ctl_srtt = 10000;
    current->ctl_rttvar = 0;

    xqc_path_ctx_t *path = xqc_test_path_validation_create_path(conn);
    CU_ASSERT_FATAL(path != NULL);

    xqc_usec_t current_pto = 10000 + XQC_kGranularity * 1000
                             + 25 * 1000;
    xqc_usec_t new_path_pto = 400000 + 4 * 200000 + 25 * 1000;
    CU_ASSERT(new_path_pto > current_pto);

    xqc_usec_t before = xqc_monotonic_timestamp();
    xqc_int_t ret = xqc_path_init(path, conn);
    xqc_usec_t after = xqc_monotonic_timestamp();
    CU_ASSERT_EQUAL(ret, XQC_OK);

    xqc_timer_t *timer = &path->path_send_ctl->path_timer_manager
                          .timer[XQC_TIMER_PATH_IDLE];
    xqc_usec_t expected = 3 * new_path_pto;
    CU_ASSERT(timer->timer_is_set);
    CU_ASSERT(timer->expire_time >= before + expected);
    CU_ASSERT(timer->expire_time <= after + expected);

    xqc_test_path_validation_destroy_path(path);
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_path_validation_timer_not_extended_by_packet(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    conn->enable_multipath = XQC_TRUE;
    xqc_path_ctx_t *path = conn->conn_initial_path;
    CU_ASSERT_FATAL(xqc_conn_find_path_by_scid(conn, &path->path_scid)
                    == path);

    path->path_state = XQC_PATH_STATE_VALIDATING;
    xqc_timer_t *timer = &path->path_send_ctl->path_timer_manager
                          .timer[XQC_TIMER_PATH_IDLE];
    timer->timer_is_set = XQC_TRUE;
    timer->expire_time = 123456789;

    xqc_conn_process_packet_recved_path(conn, &path->path_scid, 1200,
                                        200000000);
    CU_ASSERT_EQUAL(timer->expire_time, 123456789);

    xqc_usec_t before = xqc_monotonic_timestamp();
    xqc_path_validate(path);
    xqc_usec_t after = xqc_monotonic_timestamp();
    xqc_usec_t idle = xqc_path_get_idle_timeout(path) * 1000;
    CU_ASSERT_EQUAL(path->path_state, XQC_PATH_STATE_ACTIVE);
    CU_ASSERT(timer->expire_time >= before + idle);
    CU_ASSERT(timer->expire_time <= after + idle);

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
xqc_test_send_ctl_update_rtt_subtracts_at_min_rtt(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_rtt_case_t tc = {
        .name = "subtracts_at_min_rtt",
        .hsk_confirmed = XQC_FALSE,
        .first_sample  = XQC_FALSE,
        .remote_max_ack_delay_ms = 100,
        .input_ack_delay = 10000,
        .latest_rtt      = 20000,
        .pre_minrtt      = 10000,
        .pre_srtt        = 20000,
        .pre_rttvar      = 1000,
        .expected_srtt   = 18750,
        .expected_rttvar = 3250,
        .expected_minrtt = 10000,
    };

    xqc_test_send_ctl_run_rtt_case(conn, conn->conn_initial_path, &tc);
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_update_rtt_rejects_below_min_rtt(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_rtt_case_t tc = {
        .name = "rejects_below_min_rtt",
        .hsk_confirmed = XQC_FALSE,
        .first_sample  = XQC_FALSE,
        .remote_max_ack_delay_ms = 100,
        .input_ack_delay = 10000,
        .latest_rtt      = 19999,
        .pre_minrtt      = 10000,
        .pre_srtt        = 20000,
        .pre_rttvar      = 1000,
        .expected_srtt   = 19999,
        .expected_rttvar = 750,
        .expected_minrtt = 10000,
    };

    xqc_test_send_ctl_run_rtt_case(conn, conn->conn_initial_path, &tc);
    xqc_engine_destroy(conn->engine);
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
             * latest_rtt = 12000us is below minrtt + ack_delay = 21000us,
             * so ack_delay is not subtracted.
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


void
xqc_test_send_ctl_granularity_marks_at_boundary(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl != NULL);

    send_ctl->ctl_srtt = 0;
    send_ctl->ctl_latest_rtt = 0;
    send_ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = 100;
    send_ctl->ctl_reordering_packet_threshold = XQC_kPacketThreshold;

    xqc_packet_out_t *po = xqc_test_send_ctl_seed_lost_packet(conn, 99, 1);
    CU_ASSERT_FATAL(po != NULL);

    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, 1001);

    CU_ASSERT_EQUAL(conn->detected_loss_cnt, 1);
    CU_ASSERT_EQUAL(send_ctl->sampler.loss, 1);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_granularity_defers_before_boundary(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl != NULL);

    send_ctl->ctl_srtt = 0;
    send_ctl->ctl_latest_rtt = 0;
    send_ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = 100;
    send_ctl->ctl_reordering_packet_threshold = XQC_kPacketThreshold;

    xqc_packet_out_t *po = xqc_test_send_ctl_seed_lost_packet(conn, 99, 1);
    CU_ASSERT_FATAL(po != NULL);

    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, 1000);

    CU_ASSERT_EQUAL(conn->detected_loss_cnt, 0);
    CU_ASSERT_EQUAL(send_ctl->sampler.loss, 0);
    CU_ASSERT_EQUAL(send_ctl->ctl_loss_time[XQC_PNS_APP_DATA], 1001);

    xqc_engine_destroy(conn->engine);
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


typedef struct xqc_test_send_ctl_log_s {
    char    line[XQC_MAX_LOG_LEN];
    int     lines;
} xqc_test_send_ctl_log_t;


/* keep the statistics lines of the lost packets */
static void
xqc_test_send_ctl_log_write(xqc_log_level_t lvl, const void *buf,
    size_t size, void *user_data)
{
    xqc_test_send_ctl_log_t  *capture = user_data;
    char                      line[XQC_MAX_LOG_LEN];

    size = xqc_min(size, sizeof(line) - 1);
    memcpy(line, buf, size);
    line[size] = '\0';

    if (strstr(line, "|lost interval:") != NULL) {
        memcpy(capture->line, line, size + 1);
        capture->lines++;
    }
}


/*
 * Loss detection logs a statistics line at most once per record interval;
 * its last fields are the detection time and the time of that record.
 */
void
xqc_test_send_ctl_lost_interval_log(void)
{
    xqc_connection_t         *conn = test_engine_connect();
    xqc_test_send_ctl_log_t   capture = {0};
    xqc_log_callbacks_t       callbacks = {0};
    xqc_log_callbacks_t      *log_callbacks;
    void                     *log_user_data;
    char                      expected[64];
    int                       lines;

    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_send_queue_t *sq = conn->conn_send_queue;
    CU_ASSERT_FATAL(send_ctl != NULL);
    conn->remote_settings.max_ack_delay = 25;

    callbacks.xqc_log_write_err = xqc_test_send_ctl_log_write;
    log_callbacks = conn->log->log_callbacks;
    log_user_data = conn->log->user_data;
    conn->log->log_level = XQC_LOG_DEBUG;
    conn->log->log_callbacks = &callbacks;
    conn->log->user_data = &capture;

    /* an RTT sample, but no persistent congestion, which would clear it */
    xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 2);
    send_ctl->ctl_pto_count = 0;

    /* a congestion window that stays above 32 bits after the loss */
    CU_ASSERT_FATAL(send_ctl->ctl_cong_callback == &xqc_cubic_cb);
    ((xqc_cubic_t *) send_ctl->ctl_cong)->cwnd = 0x300000000ULL;

    CU_ASSERT_FATAL(xqc_test_send_ctl_seed_lost_packet(conn, 1, 1) != NULL);
    xqc_send_ctl_detect_lost(send_ctl, sq, XQC_PNS_APP_DATA, 1000000);
    CU_ASSERT(send_ctl->ctl_info.last_lost_time == 1000000);

    uint64_t cwnd = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(
        send_ctl->ctl_cong);
    CU_ASSERT(cwnd > 0xffffffffULL);
    snprintf(expected, sizeof(expected), "|cwnd:%llu|bw:0|",
             (unsigned long long) cwnd);
#if !defined(XQC_DISABLE_LOG) && !defined(XQC_ONLY_ERROR_LOG)
    CU_ASSERT(capture.lines == 1);
    CU_ASSERT_PTR_NOT_NULL(strstr(capture.line, expected));
    CU_ASSERT_PTR_NOT_NULL(strstr(capture.line,
                                  "|now:1000000|last_lost_time:1000000|"));
#else
    /* the statistics line is compiled out */
    CU_ASSERT(capture.lines == 0);
#endif

    /* a loss within the record interval is not recorded, and adds no line */
    lines = capture.lines;
    CU_ASSERT_FATAL(xqc_test_send_ctl_seed_lost_packet(conn, 2, 2) != NULL);
    xqc_send_ctl_detect_lost(send_ctl, sq, XQC_PNS_APP_DATA, 1000001);
    CU_ASSERT(xqc_list_empty(&sq->sndq_unacked_packets[XQC_PNS_APP_DATA]));
    CU_ASSERT(send_ctl->ctl_info.last_lost_time == 1000000);
    CU_ASSERT(capture.lines == lines);

    conn->log->log_callbacks = log_callbacks;
    conn->log->user_data = log_user_data;
    xqc_engine_destroy(conn->engine);
}


/*
 * RFC 9000 14.4: the loss of a PMTU probe "SHOULD NOT trigger a congestion
 * control reaction" (also RFC 8899 3, item 7). Both tests arm the
 * persistent-congestion state, so a probe counted as a loss would also
 * collapse cwnd and reset the RTT estimator.
 */
static void
xqc_test_send_ctl_lost_packet_cc(xqc_bool_t pmtud_probe)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_send_queue_t *sq = conn->conn_send_queue;
    CU_ASSERT_FATAL(send_ctl != NULL);
    CU_ASSERT_FATAL(send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd != NULL);
    conn->remote_settings.max_ack_delay = 25;

    xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 1);

    xqc_packet_out_t *po = xqc_test_send_ctl_seed_lost_packet(conn, 1, 1);
    CU_ASSERT_FATAL(po != NULL);
    if (pmtud_probe) {
        po->po_flag |= XQC_POF_PMTUD_PROBING;
    }

    uint64_t cwnd_before = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(
        send_ctl->ctl_cong);
    uint64_t lost_before = send_ctl->ctl_lost_pkts_number;
    uint64_t detected_before = conn->detected_loss_cnt;

    xqc_send_ctl_detect_lost(send_ctl, sq, XQC_PNS_APP_DATA, 1000000);

    uint64_t cwnd_after = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(
        send_ctl->ctl_cong);

    /* Either way the packet leaves the unacked list. */
    CU_ASSERT(xqc_list_empty(&sq->sndq_unacked_packets[XQC_PNS_APP_DATA]));

    if (pmtud_probe) {
        CU_ASSERT_EQUAL(cwnd_after, cwnd_before);
        CU_ASSERT_EQUAL(send_ctl->sampler.loss, 0);
        CU_ASSERT_EQUAL(send_ctl->ctl_lost_pkts_number, lost_before);
        CU_ASSERT_EQUAL(conn->detected_loss_cnt, detected_before);
        CU_ASSERT_EQUAL(send_ctl->ctl_srtt, 10000);
        CU_ASSERT_EQUAL(send_ctl->ctl_minrtt, 8000);

    } else {
        CU_ASSERT(cwnd_after < cwnd_before);
        CU_ASSERT_EQUAL(send_ctl->sampler.loss, 1);
        CU_ASSERT_EQUAL(send_ctl->ctl_lost_pkts_number, lost_before + 1);
        CU_ASSERT_EQUAL(conn->detected_loss_cnt, detected_before + 1);
    }

    xqc_engine_destroy(conn->engine);
}



/*
 * Every ack-eliciting packet sent on a path restarts its PTO timer
 * (RFC 9002 Section 6.2.1), so a path that stops delivering while packets
 * keep being sent on it more often than once per PTO never gets a PTO, and
 * ctl_pto_count stays 0. The effective PTO count counts the expiries those
 * sends hid, from the last progress on the path to its last send.
 *
 * With srtt = 10 ms, rttvar = 1.25 ms and the peer's max_ack_delay = 25 ms,
 * the first Application Data PTO is 10 + max(4 * 1.25, 1) + 25 = 40 ms.
 */
static xqc_usec_t
xqc_test_effective_pto_setup(xqc_connection_t *conn)
{
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;

    conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    conn->conn_settings.pto_backoff_factor = 2.0;
    conn->remote_settings.max_ack_delay = 25;
    send_ctl->ctl_srtt = 10000;
    send_ctl->ctl_rttvar = 1250;
    send_ctl->ctl_minrtt = 10000;
    send_ctl->ctl_latest_rtt = 10000;
    send_ctl->ctl_first_rtt_sample_time = 1;

    return xqc_send_ctl_get_pto_duration(send_ctl, XQC_PNS_APP_DATA, 0);
}


/*
 * Send an Application Data packet on the initial path through the sending
 * accounting of xqc_send_ctl_on_packet_sent(): a 100-byte PING, or with
 * probe, a 1450-byte PMTUD probe (PING and PADDING).
 */
static xqc_packet_out_t *
xqc_test_effective_pto_send_packet(xqc_connection_t *conn,
    xqc_packet_number_t pkt_num, xqc_usec_t sent_time, xqc_bool_t probe)
{
    xqc_send_queue_t *sq = conn->conn_send_queue;
    xqc_path_ctx_t *path = conn->conn_initial_path;

    xqc_packet_out_t *po = xqc_packet_out_get(sq);
    if (po == NULL) {
        return NULL;
    }

    po->po_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    po->po_pkt.pkt_pns  = XQC_PNS_APP_DATA;
    po->po_pkt.pkt_num  = pkt_num;
    po->po_path_id      = path->path_id;
    po->po_sent_time    = sent_time;
    po->po_frame_types  = XQC_FRAME_BIT_PING;
    po->po_used_size    = 100;
    if (probe) {
        po->po_frame_types |= XQC_FRAME_BIT_PADDING;
        po->po_flag |= XQC_POF_PMTUD_PROBING;
        po->po_used_size = 1450;
    }

    xqc_send_queue_insert_unacked(po,
        &sq->sndq_unacked_packets[XQC_PNS_APP_DATA], sq);
    xqc_send_ctl_on_packet_sent(path->path_send_ctl, path->path_pn_ctl, po,
                                sent_time);

    return po;
}


static xqc_packet_out_t *
xqc_test_effective_pto_send(xqc_connection_t *conn,
    xqc_packet_number_t pkt_num, xqc_usec_t sent_time)
{
    return xqc_test_effective_pto_send_packet(conn, pkt_num, sent_time,
                                              XQC_FALSE);
}


static xqc_packet_out_t *
xqc_test_effective_pto_send_probe(xqc_connection_t *conn,
    xqc_packet_number_t pkt_num, xqc_usec_t sent_time)
{
    return xqc_test_effective_pto_send_packet(conn, pkt_num, sent_time,
                                              XQC_TRUE);
}


/*
 * Happy path: a path keeps getting a packet every half PTO and none is
 * acknowledged. Over 3 PTOs of sends it hides two PTO expiries, which is the
 * minrtt/backup threshold (pto_cnt_thr = 2), so it falls to the LOW class
 * although ctl_pto_count is still 0. The first ACK that acknowledges a
 * packet sent on it restores it.
 */
void
xqc_test_effective_pto_count_silent_path(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_path_ctx_t *path = conn->conn_initial_path;
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    xqc_usec_t pto = xqc_test_effective_pto_setup(conn);
    CU_ASSERT_FATAL(pto == 40000);
    CU_ASSERT_FATAL(conn->conn_settings.scheduler_params.pto_cnt_thr == 2);
    path->app_path_status = XQC_APP_PATH_STATUS_AVAILABLE;

    /* Healthy and idle: not LOW. */
    CU_ASSERT(xqc_path_get_perf_class(path) != XQC_PATH_CLASS_AVAILABLE_LOW);

    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_usec_t first = now - 4 * pto;
    for (int i = 0; i < 7; i++) {
        CU_ASSERT_FATAL(xqc_test_effective_pto_send(conn, 10 + i,
                                                    first + i * pto / 2)
                        != NULL);
    }

    /* The last send came 3 PTOs after the first one: expiries at 1 and 3. */
    CU_ASSERT_EQUAL(send_ctl->ctl_pto_count, 0);
    CU_ASSERT_EQUAL(send_ctl->ctl_progress_time, first);
    CU_ASSERT_EQUAL(xqc_send_ctl_get_effective_pto_count(send_ctl), 2);
    CU_ASSERT_EQUAL(xqc_path_get_perf_class(path),
                    XQC_PATH_CLASS_AVAILABLE_LOW);

    /* The peer acknowledges the last packet sent on the path. */
    xqc_ack_info_t ack_info;
    memset(&ack_info, 0, sizeof(ack_info));
    ack_info.pns = XQC_PNS_APP_DATA;
    ack_info.path_id = path->path_id;
    ack_info.n_ranges = 1;
    ack_info.ranges[0].low = 16;
    ack_info.ranges[0].high = 16;
    ack_info.largest_acked = 16;

    now = xqc_monotonic_timestamp();
    CU_ASSERT_EQUAL(xqc_send_ctl_on_ack_received(send_ctl, path->path_pn_ctl,
                        conn->conn_send_queue, &ack_info, now, XQC_TRUE),
                    XQC_OK);
    CU_ASSERT_EQUAL(send_ctl->ctl_progress_time, now);
    CU_ASSERT_EQUAL(xqc_send_ctl_get_effective_pto_count(send_ctl), 0);
    CU_ASSERT(xqc_path_get_perf_class(path) != XQC_PATH_CLASS_AVAILABLE_LOW);

    xqc_engine_destroy(conn->engine);
}


/* the initial path of a connection set up by xqc_test_effective_pto_setup() */
static xqc_path_ctx_t *
xqc_test_effective_pto_path(xqc_connection_t *conn)
{
    xqc_path_ctx_t *path = conn->conn_initial_path;

    CU_ASSERT_FATAL(path != NULL);
    CU_ASSERT_FATAL(xqc_test_effective_pto_setup(conn) == 40000);
    CU_ASSERT_FATAL(conn->conn_settings.scheduler_params.pto_cnt_thr == 2);
    path->app_path_status = XQC_APP_PATH_STATUS_AVAILABLE;
    return path;
}


/*
 * Abnormal path: PMTUD probes alone. The loss of a probe can mean that the
 * path MTU is smaller than the probe (RFC 9000 Section 14.4), and sending
 * one does not arm the PTO timer, so two 1450-byte probes sent 500 ms
 * apart, 12.5 PTOs, and never acknowledged hide no expiry: the path keeps
 * its class.
 */
void
xqc_test_effective_pto_count_pmtud_only(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    xqc_path_ctx_t *path = xqc_test_effective_pto_path(conn);
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    xqc_timer_t *timer =
        &send_ctl->path_timer_manager.timer[XQC_TIMER_LOSS_DETECTION];
    xqc_path_perf_class_t perf_class = xqc_path_get_perf_class(path);
    uint32_t inflight = send_ctl->ctl_bytes_in_flight;
    uint8_t timer_is_set = timer->timer_is_set;
    xqc_usec_t expire_time = timer->expire_time;
    CU_ASSERT(perf_class != XQC_PATH_CLASS_AVAILABLE_LOW);

    xqc_usec_t first = xqc_monotonic_timestamp() - 600000;
    CU_ASSERT_FATAL(xqc_test_effective_pto_send_probe(conn, 10, first)
                    != NULL);
    CU_ASSERT_FATAL(xqc_test_effective_pto_send_probe(conn, 11,
                                                      first + 500000)
                    != NULL);

    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, inflight + 2900);
    CU_ASSERT_EQUAL(send_ctl->ctl_pto_count, 0);
    CU_ASSERT_EQUAL(timer->timer_is_set, timer_is_set);
    CU_ASSERT_EQUAL(timer->expire_time, expire_time);
    CU_ASSERT_EQUAL(xqc_send_ctl_get_effective_pto_count(send_ctl), 0);
    CU_ASSERT_EQUAL(xqc_path_get_perf_class(path), perf_class);

    xqc_engine_destroy(conn->engine);
}


/*
 * PMTUD probes among ordinary packets: only the ordinary packets count.
 *
 * - A probe sent 4 PTOs before the first ordinary packet does not start
 *   the count, and one sent 2 PTOs after the last does not extend it:
 *   ordinary packets every half PTO for 1.5 PTOs hide one expiry.
 * - Ordinary packets every half PTO for 3 PTOs, with a probe between each
 *   two, still hide two expiries: the path falls to the LOW class.
 * - Once the ordinary packets are acknowledged, a probe left in flight and
 *   one sent two PTO periods later hide nothing.
 */
void
xqc_test_effective_pto_count_pmtud_interleaved(void)
{
    xqc_connection_t *conn;
    xqc_path_ctx_t *path;
    xqc_send_ctl_t *send_ctl;
    xqc_usec_t pto, t0, ack_time;
    xqc_ack_info_t ack_info;
    int i;

    /* probes before and after 1.5 PTOs of ordinary packets */
    conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    path = xqc_test_effective_pto_path(conn);
    send_ctl = path->path_send_ctl;
    pto = 40000;
    t0 = xqc_monotonic_timestamp() - 10 * pto;

    CU_ASSERT_FATAL(xqc_test_effective_pto_send_probe(conn, 10, t0) != NULL);
    for (i = 0; i < 4; i++) {
        CU_ASSERT_FATAL(xqc_test_effective_pto_send(conn, 11 + i,
                                                    t0 + 4 * pto
                                                    + i * pto / 2)
                        != NULL);
    }
    CU_ASSERT_FATAL(xqc_test_effective_pto_send_probe(conn, 15,
                                                      t0 + 7 * pto + pto / 2)
                    != NULL);

    CU_ASSERT_EQUAL(send_ctl->ctl_progress_time, t0 + 4 * pto);
    CU_ASSERT_EQUAL(xqc_send_ctl_get_effective_pto_count(send_ctl), 1);
    CU_ASSERT(xqc_path_get_perf_class(path) != XQC_PATH_CLASS_AVAILABLE_LOW);
    xqc_engine_destroy(conn->engine);

    /* 3 PTOs of ordinary packets with probes between them */
    conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    path = xqc_test_effective_pto_path(conn);
    send_ctl = path->path_send_ctl;
    t0 = xqc_monotonic_timestamp() - 10 * pto;

    for (i = 0; i < 7; i++) {
        CU_ASSERT_FATAL(xqc_test_effective_pto_send(conn, 10 + 2 * i,
                                                    t0 + i * pto / 2)
                        != NULL);
        if (i < 6) {
            CU_ASSERT_FATAL(xqc_test_effective_pto_send_probe(conn,
                                11 + 2 * i, t0 + i * pto / 2 + pto / 4)
                            != NULL);
        }
    }

    CU_ASSERT_EQUAL(send_ctl->ctl_pto_count, 0);
    CU_ASSERT_EQUAL(send_ctl->ctl_progress_time, t0);
    CU_ASSERT_EQUAL(xqc_send_ctl_get_effective_pto_count(send_ctl), 2);
    CU_ASSERT_EQUAL(xqc_path_get_perf_class(path),
                    XQC_PATH_CLASS_AVAILABLE_LOW);
    xqc_engine_destroy(conn->engine);

    /* a probe left in flight once the ordinary packet is acknowledged */
    conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    path = xqc_test_effective_pto_path(conn);
    send_ctl = path->path_send_ctl;
    t0 = xqc_monotonic_timestamp() - 10 * pto;

    CU_ASSERT_FATAL(xqc_test_effective_pto_send(conn, 10, t0) != NULL);
    CU_ASSERT_FATAL(xqc_test_effective_pto_send_probe(conn, 11, t0 + pto / 2)
                    != NULL);

    memset(&ack_info, 0, sizeof(ack_info));
    ack_info.pns = XQC_PNS_APP_DATA;
    ack_info.path_id = path->path_id;
    ack_info.n_ranges = 1;
    ack_info.ranges[0].low = 10;
    ack_info.ranges[0].high = 10;
    ack_info.largest_acked = 10;
    ack_time = t0 + pto;
    CU_ASSERT_EQUAL(xqc_send_ctl_on_ack_received(send_ctl, path->path_pn_ctl,
                        conn->conn_send_queue, &ack_info, ack_time, XQC_TRUE),
                    XQC_OK);
    CU_ASSERT_EQUAL(send_ctl->ctl_progress_time, ack_time);
    CU_ASSERT(send_ctl->ctl_bytes_in_flight > 0);

    CU_ASSERT_FATAL(xqc_test_effective_pto_send_probe(conn, 12,
        ack_time
        + xqc_send_ctl_get_pto_duration(send_ctl, XQC_PNS_APP_DATA, 0)
        + xqc_send_ctl_get_pto_duration(send_ctl, XQC_PNS_APP_DATA, 1))
                    != NULL);
    CU_ASSERT_EQUAL(xqc_send_ctl_get_effective_pto_count(send_ctl), 0);
    CU_ASSERT(xqc_path_get_perf_class(path) != XQC_PATH_CLASS_AVAILABLE_LOW);
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_lost_pmtud_probe_no_cc_reaction(void)
{
    xqc_test_send_ctl_lost_packet_cc(XQC_TRUE);
}


void
xqc_test_send_ctl_lost_packet_cc_reaction(void)
{
    xqc_test_send_ctl_lost_packet_cc(XQC_FALSE);
}


/*
 * The effective PTO count with the last ack-eliciting send other than a
 * PMTUD probe at last_sent.
 */
static unsigned
xqc_test_effective_pto_at(xqc_send_ctl_t *send_ctl, xqc_usec_t last_sent)
{
    send_ctl->ctl_progress_last_sent = last_sent;
    return xqc_send_ctl_get_effective_pto_count(send_ctl);
}


/*
 * Boundaries and guards: the expiries follow the configured backoff, with
 * the timer's cap, the real ctl_pto_count still wins when it is larger, the
 * count is capped, and a path without bytes in flight, or a connection
 * whose handshake is not confirmed, only reports ctl_pto_count.
 */
void
xqc_test_effective_pto_count_bounds(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_usec_t pto = xqc_test_effective_pto_setup(conn);
    CU_ASSERT_FATAL(pto == 40000);

    xqc_usec_t since = 1000000;
    send_ctl->ctl_progress_time = since;
    send_ctl->ctl_progress_bytes_inflight = 100;

    /* Backoff 2: expiries 1, 3 and 7 PTOs after the last progress. */
    CU_ASSERT_EQUAL(xqc_test_effective_pto_at(send_ctl, since + pto - 1), 0);
    CU_ASSERT_EQUAL(xqc_test_effective_pto_at(send_ctl, since + pto), 1);
    CU_ASSERT_EQUAL(xqc_test_effective_pto_at(send_ctl, since + 3 * pto - 1),
                    1);
    CU_ASSERT_EQUAL(xqc_test_effective_pto_at(send_ctl, since + 3 * pto), 2);
    CU_ASSERT_EQUAL(xqc_test_effective_pto_at(send_ctl, since + 7 * pto), 3);
    CU_ASSERT_EQUAL(xqc_test_effective_pto_at(send_ctl, since + 100000 * pto),
                    XQC_EFFECTIVE_PTO_COUNT_MAX);

    /* Backoff 1.5: expiries 1, 2.5 and 4.75 PTOs after the last progress. */
    conn->conn_settings.pto_backoff_factor = 1.5;
    CU_ASSERT_EQUAL(
        xqc_test_effective_pto_at(send_ctl, since + 5 * pto / 2 - 1), 1);
    CU_ASSERT_EQUAL(xqc_test_effective_pto_at(send_ctl, since + 5 * pto / 2),
                    2);
    CU_ASSERT_EQUAL(xqc_test_effective_pto_at(send_ctl, since + 19 * pto / 4),
                    3);

    /* Backoff 3: 11 expiries after (3^11 - 1) / 2 PTOs, then the 12th
     * period is capped at 2^16 PTOs, as the timer caps it. */
    conn->conn_settings.pto_backoff_factor = 3.0;
    xqc_usec_t eleven = (177147 - 1) / 2 * pto;
    CU_ASSERT_EQUAL(xqc_test_effective_pto_at(send_ctl, since + eleven), 11);
    CU_ASSERT_EQUAL(
        xqc_test_effective_pto_at(send_ctl, since + eleven + 65536 * pto - 1),
        11);
    CU_ASSERT_EQUAL(
        xqc_test_effective_pto_at(send_ctl, since + eleven + 65536 * pto), 12);
    conn->conn_settings.pto_backoff_factor = 2.0;

    /* An ACK that acknowledged a packet sent on the path restarts it. */
    send_ctl->ctl_progress_time = since + 3 * pto;
    CU_ASSERT_EQUAL(xqc_test_effective_pto_at(send_ctl, since + 4 * pto - 1),
                    0);
    CU_ASSERT_EQUAL(xqc_test_effective_pto_at(send_ctl, since + 4 * pto), 1);

    /* The real count wins when it is larger. */
    send_ctl->ctl_pto_count = 5;
    CU_ASSERT_EQUAL(xqc_test_effective_pto_at(send_ctl, since + 4 * pto), 5);

    /* An idle path is not unresponsive. */
    send_ctl->ctl_pto_count = 1;
    send_ctl->ctl_progress_bytes_inflight = 0;
    CU_ASSERT_EQUAL(xqc_test_effective_pto_at(send_ctl, since + 100000 * pto),
                    1);

    /* Any PTO, even one at the top of the xqc_usec_t range, where the
     * last progress plus one PTO wraps: one millisecond after the last
     * progress, no expiry has been hidden. */
    xqc_usec_t srtt = send_ctl->ctl_srtt;
    send_ctl->ctl_pto_count = 0;
    send_ctl->ctl_progress_bytes_inflight = 100;
    send_ctl->ctl_srtt = XQC_MAX_UINT64_VALUE - (1 << 20);
    send_ctl->ctl_progress_time = 1 << 21;
    CU_ASSERT_FATAL(send_ctl->ctl_progress_time
                    + xqc_send_ctl_get_pto_duration(send_ctl,
                                                    XQC_PNS_APP_DATA, 0)
                    < send_ctl->ctl_progress_time);
    CU_ASSERT_EQUAL(xqc_test_effective_pto_at(send_ctl, (1 << 21) + 1000), 0);
    send_ctl->ctl_srtt = srtt;
    send_ctl->ctl_progress_time = since;

    /* Before the handshake is confirmed, only the PTO timer counts. */
    send_ctl->ctl_pto_count = 0;
    send_ctl->ctl_progress_bytes_inflight = 100;
    conn->conn_flag &= ~XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    CU_ASSERT_EQUAL(xqc_test_effective_pto_at(send_ctl, since + 100000 * pto),
                    0);

    send_ctl->ctl_progress_bytes_inflight = 0;
    xqc_engine_destroy(conn->engine);
}


static xqc_usec_t
xqc_test_pto_frozen_timestamp(void)
{
    return 1000000;
}


/*
 * The PTO period that the loss detection timer arms after pto_count PTOs,
 * with ack-eliciting packets of pns alone in flight, or with nothing in
 * flight when pns is XQC_PNS_N; 0 when it arms none, as for Application
 * Data before the handshake is confirmed.
 */
static xqc_usec_t
xqc_test_timer_pto_period(xqc_send_ctl_t *send_ctl, xqc_pkt_num_space_t pns,
    unsigned pto_count)
{
    xqc_timestamp_pt saved_clock = xqc_monotonic_timestamp;
    unsigned saved_count = send_ctl->ctl_pto_count;
    unsigned saved_bytes = send_ctl->ctl_bytes_in_flight;
    uint32_t saved_inflight[XQC_PNS_N];
    xqc_usec_t saved_sent[XQC_PNS_N];
    xqc_pkt_num_space_t pns_ret;

    memcpy(saved_inflight, send_ctl->ctl_bytes_ack_eliciting_inflight,
           sizeof(saved_inflight));
    memcpy(saved_sent, send_ctl->ctl_time_of_last_sent_ack_eliciting_packet,
           sizeof(saved_sent));

    /* the last ack-eliciting packets were sent, or the clock reads, 1 s */
    xqc_usec_t now = xqc_test_pto_frozen_timestamp();
    xqc_monotonic_timestamp = xqc_test_pto_frozen_timestamp;
    send_ctl->ctl_pto_count = pto_count;
    send_ctl->ctl_bytes_in_flight = pns < XQC_PNS_N ? 100 : 0;
    for (int i = 0; i < XQC_PNS_N; i++) {
        send_ctl->ctl_bytes_ack_eliciting_inflight[i] = i == pns ? 100 : 0;
        send_ctl->ctl_time_of_last_sent_ack_eliciting_packet[i] = now;
    }

    xqc_usec_t timeout =
        xqc_send_ctl_get_pto_time_and_space(send_ctl, now, &pns_ret);

    xqc_monotonic_timestamp = saved_clock;
    send_ctl->ctl_pto_count = saved_count;
    send_ctl->ctl_bytes_in_flight = saved_bytes;
    memcpy(send_ctl->ctl_bytes_ack_eliciting_inflight, saved_inflight,
           sizeof(saved_inflight));
    memcpy(send_ctl->ctl_time_of_last_sent_ack_eliciting_packet, saved_sent,
           sizeof(saved_sent));

    if (timeout == XQC_MAX_UINT64_VALUE) {
        return 0;
    }
    if (pns < XQC_PNS_N) {
        CU_ASSERT_EQUAL(pns_ret, pns);
    }
    return timeout - now;
}


/*
 * The hidden expiries are those of the PTO timer itself, with the
 * connection's PTO settings. With control_pto_value, the timer's period is
 * srtt + srtt / 4 + max_ack_delay: 150 ms with srtt = rttvar = 100 ms, not
 * the 525 ms of srtt + 4 * rttvar + max_ack_delay. Sends without progress
 * for 450 ms hide its expiries at 150 and 450 ms, and demote the path.
 */
void
xqc_test_effective_pto_count_control_pto_value(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_path_ctx_t *path = conn->conn_initial_path;
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    xqc_test_effective_pto_setup(conn);
    conn->conn_settings.control_pto_value = 1;
    send_ctl->ctl_srtt = 100000;
    send_ctl->ctl_rttvar = 100000;
    path->app_path_status = XQC_APP_PATH_STATUS_AVAILABLE;

    CU_ASSERT_EQUAL(
        xqc_test_timer_pto_period(send_ctl, XQC_PNS_APP_DATA, 0), 150000);
    CU_ASSERT_EQUAL(
        xqc_test_timer_pto_period(send_ctl, XQC_PNS_APP_DATA, 1), 300000);

    /* A send every 50 ms, none acknowledged. */
    static const unsigned expected[] = {0, 0, 0, 1, 1, 1, 1, 1, 1, 2};
    xqc_usec_t first = xqc_monotonic_timestamp() - 1000000;
    for (int i = 0; i < 10; i++) {
        CU_ASSERT_FATAL(xqc_test_effective_pto_send(conn, 10 + i,
                                                    first + i * 50000)
                        != NULL);
        CU_ASSERT_EQUAL(xqc_send_ctl_get_effective_pto_count(send_ctl),
                        expected[i]);
    }

    CU_ASSERT_EQUAL(send_ctl->ctl_pto_count, 0);
    CU_ASSERT_EQUAL(xqc_path_get_perf_class(path),
                    XQC_PATH_CLASS_AVAILABLE_LOW);

    xqc_engine_destroy(conn->engine);
}


/*
 * Before the path's first RTT sample, the timer's period is
 * initial_pto_duration + max_ack_delay when initial_pto_duration is set:
 * 2025 ms with 2 s, not the 325 ms of srtt + 4 * rttvar + max_ack_delay
 * with the initial srtt = 100 ms and rttvar = 50 ms. Sends without
 * progress for 975 ms hide no expiry, so the path keeps its class; the
 * expiries at 2025 and 6075 ms count.
 */
void
xqc_test_effective_pto_count_initial_pto_duration(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_path_ctx_t *path = conn->conn_initial_path;
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    xqc_test_effective_pto_setup(conn);
    conn->conn_settings.initial_pto_duration = 2000000;
    send_ctl->ctl_srtt = 100000;
    send_ctl->ctl_rttvar = 50000;
    send_ctl->ctl_first_rtt_sample_time = 0;
    path->app_path_status = XQC_APP_PATH_STATUS_AVAILABLE;

    CU_ASSERT_EQUAL(
        xqc_test_timer_pto_period(send_ctl, XQC_PNS_APP_DATA, 0), 2025000);
    CU_ASSERT_EQUAL(
        xqc_test_timer_pto_period(send_ctl, XQC_PNS_APP_DATA, 1), 4050000);

    /* A send every 75 ms for 975 ms, none acknowledged. */
    xqc_usec_t first = xqc_monotonic_timestamp() - 7000000;
    xqc_packet_number_t pn = 10;
    for (int i = 0; i <= 13; i++) {
        CU_ASSERT_FATAL(xqc_test_effective_pto_send(conn, pn++,
                                                    first + i * 75000)
                        != NULL);
    }

    CU_ASSERT_EQUAL(xqc_send_ctl_get_effective_pto_count(send_ctl), 0);
    CU_ASSERT(xqc_path_get_perf_class(path) != XQC_PATH_CLASS_AVAILABLE_LOW);

    static const struct {
        xqc_usec_t  sent;
        unsigned    count;
    } later[] = {
        {2025000 - 1, 0}, {2025000, 1}, {6075000 - 1, 1}, {6075000, 2},
    };
    for (size_t i = 0; i < sizeof(later) / sizeof(later[0]); i++) {
        CU_ASSERT_FATAL(xqc_test_effective_pto_send(conn, pn++,
                                                    first + later[i].sent)
                        != NULL);
        CU_ASSERT_EQUAL(xqc_send_ctl_get_effective_pto_count(send_ctl),
                        later[i].count);
    }

    CU_ASSERT_EQUAL(send_ctl->ctl_pto_count, 0);
    CU_ASSERT_EQUAL(xqc_path_get_perf_class(path),
                    XQC_PATH_CLASS_AVAILABLE_LOW);

    xqc_engine_destroy(conn->engine);
}


/*
 * The PTO timer and the effective PTO count follow one PTO period policy:
 * for each control_pto_value, with or without an RTT sample on the path,
 * with or without initial_pto_duration, and before or after the handshake
 * is confirmed, the timer arms the Application Data periods of the table
 * after 0 and 1 PTOs, the same without max_ack_delay for Handshake packets
 * or with nothing in flight, and sends without progress count the
 * Application Data expiries exactly. Before the handshake is confirmed,
 * the timer arms no Application Data PTO, and only ctl_pto_count counts.
 */
void
xqc_test_effective_pto_count_timer_policy(void)
{
    /* srtt = rttvar = 100 ms, the peer's max_ack_delay = 25 ms, backoff 2 */
    static const struct {
        uint8_t     control_pto_value;
        xqc_bool_t  rtt_sample;
        xqc_usec_t  initial_pto_duration;
        xqc_usec_t  pto;
    } cases[] = {
        /* srtt + max(4 * rttvar, 1 ms) + max_ack_delay */
        {0,   XQC_TRUE,  0,       525000},
        {0,   XQC_FALSE, 0,       525000},
        {0,   XQC_TRUE,  2000000, 525000},
        /* srtt + srtt / 4 + max_ack_delay */
        {1,   XQC_TRUE,  0,       150000},
        {2,   XQC_TRUE,  0,       150000},
        {255, XQC_TRUE,  0,       150000},
        {1,   XQC_FALSE, 0,       150000},
        {1,   XQC_TRUE,  2000000, 150000},
        /* no RTT sample yet: initial_pto_duration + max_ack_delay */
        {0,   XQC_FALSE, 2000000, 2025000},
        {1,   XQC_FALSE, 2000000, 2025000},
        {2,   XQC_FALSE, 2000000, 2025000},
    };
    size_t n = sizeof(cases) / sizeof(cases[0]);

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_test_effective_pto_setup(conn);
    send_ctl->ctl_srtt = 100000;
    send_ctl->ctl_rttvar = 100000;

    xqc_usec_t since = 1000000;
    for (size_t i = 0; i < n; i++) {
        for (int confirmed = 0; confirmed <= 1; confirmed++) {
            xqc_usec_t pto = cases[i].pto;

            conn->conn_settings.control_pto_value =
                cases[i].control_pto_value;
            conn->conn_settings.initial_pto_duration =
                cases[i].initial_pto_duration;
            send_ctl->ctl_first_rtt_sample_time = cases[i].rtt_sample;
            if (confirmed) {
                conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;

            } else {
                conn->conn_flag &= ~XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
            }

            /* the timer: pto, then 2 * pto, for Application Data, and the
             * same without max_ack_delay for Handshake or with nothing in
             * flight */
            CU_ASSERT_EQUAL(
                xqc_test_timer_pto_period(send_ctl, XQC_PNS_APP_DATA, 0),
                confirmed ? pto : 0);
            CU_ASSERT_EQUAL(
                xqc_test_timer_pto_period(send_ctl, XQC_PNS_APP_DATA, 1),
                confirmed ? 2 * pto : 0);
            CU_ASSERT_EQUAL(xqc_test_timer_pto_period(send_ctl, XQC_PNS_HSK, 0),
                            pto - 25000);
            CU_ASSERT_EQUAL(xqc_test_timer_pto_period(send_ctl, XQC_PNS_HSK, 1),
                            2 * (pto - 25000));
            if (!confirmed) {
                CU_ASSERT_EQUAL(
                    xqc_test_timer_pto_period(send_ctl, XQC_PNS_N, 0),
                    pto - 25000);
            }

            /* the effective count: expiries at pto and 3 * pto */
            send_ctl->ctl_pto_count = 0;
            send_ctl->ctl_progress_time = since;
            send_ctl->ctl_progress_bytes_inflight = 100;
            CU_ASSERT_EQUAL(
                xqc_test_effective_pto_at(send_ctl, since + pto - 1), 0);
            CU_ASSERT_EQUAL(xqc_test_effective_pto_at(send_ctl, since + pto),
                            confirmed ? 1 : 0);
            CU_ASSERT_EQUAL(
                xqc_test_effective_pto_at(send_ctl, since + 3 * pto - 1),
                confirmed ? 1 : 0);
            CU_ASSERT_EQUAL(
                xqc_test_effective_pto_at(send_ctl, since + 3 * pto),
                confirmed ? 2 : 0);
            send_ctl->ctl_progress_bytes_inflight = 0;
        }
    }

    xqc_engine_destroy(conn->engine);
}
