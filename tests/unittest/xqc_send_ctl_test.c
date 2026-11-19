/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <xquic/xquic_typedef.h>

#include "xqc_send_ctl_test.h"
#include "xqc_common_test.h"
#include "xqc_alloc_wrap.h"

#include "src/common/xqc_malloc.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_transport_params.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_stream.h"
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
 * RFC 9000 Section 14.2: packets that are not PMTU probes SHOULD fit within
 * the maximum datagram size. Once the path MTU went down, a lost packet built
 * at the old size is resent in packets of the new size, and a PTO probes
 * with packets that fit.
 */
#define XQC_TEST_SPLIT_OLD_SIZE     1400
#define XQC_TEST_SPLIT_NEW_SIZE     1200
#define XQC_TEST_SPLIT_DATA_LEN     1350
#define XQC_TEST_SPLIT_NOW          10000000

/* the byte of the test data at a stream offset */
static unsigned char
xqc_test_split_byte(uint64_t offset)
{
    return (unsigned char) (offset * 31 + 7);
}

/* a client connection that builds its packets at the old size */
static xqc_connection_t *
xqc_test_split_conn(void)
{
    xqc_connection_t *conn = test_engine_connect();

    if (conn == NULL) {
        return NULL;
    }

    conn->conn_err = 0;
    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT
                       | XQC_CONN_FLAG_TLS_HSK_COMPLETED;
    conn->pkt_out_size = XQC_TEST_SPLIT_OLD_SIZE;
    conn->conn_initial_path->curr_pkt_out_size = XQC_TEST_SPLIT_OLD_SIZE;
    return conn;
}

/*
 * len bytes of test data written to stream from its offset 0, and queued:
 * the flag keeps xqc_stream_send() from running the send logic.
 */
static void
xqc_test_split_write(xqc_stream_t *stream, size_t len, uint8_t fin)
{
    unsigned char data[XQC_TEST_SPLIT_DATA_LEN];

    CU_ASSERT_FATAL(len <= sizeof(data));
    for (size_t i = 0; i < len; i++) {
        data[i] = xqc_test_split_byte(i);
    }
    stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
    CU_ASSERT_FATAL(xqc_stream_send(stream, data, len, fin) == (ssize_t) len);
}

/* the packet queued with the data of stream */
static xqc_packet_out_t *
xqc_test_split_queued(xqc_connection_t *conn, xqc_stream_t *stream)
{
    xqc_list_head_t *pos;

    xqc_list_for_each(pos, &conn->conn_send_queue->sndq_send_packets) {
        xqc_packet_out_t *po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if ((po->po_frame_types & XQC_FRAME_BIT_STREAM)
            && po->po_stream_frames[0].ps_stream_id == stream->stream_id)
        {
            return po;
        }
    }
    return NULL;
}

/* po goes out on the initial path as packet number pn */
static void
xqc_test_split_send(xqc_connection_t *conn, xqc_packet_out_t *po,
    xqc_packet_number_t pn)
{
    xqc_path_ctx_t *path = conn->conn_initial_path;

    xqc_send_queue_remove_send(&po->po_list);
    po->po_pkt.pkt_num = pn;
    po->po_pkt.pkt_pns = XQC_PNS_APP_DATA;
    po->po_path_id = path->path_id;
    po->po_sent_time = pn;
    xqc_send_queue_insert_unacked(po,
        &conn->conn_send_queue->sndq_unacked_packets[XQC_PNS_APP_DATA],
        conn->conn_send_queue);
    xqc_send_ctl_on_packet_sent(path->path_send_ctl, path->path_pn_ctl, po,
                                po->po_sent_time);
}

/* po and its copies acknowledged */
static void
xqc_test_split_ack(xqc_connection_t *conn, xqc_packet_out_t *po)
{
    xqc_send_ctl_on_packet_acked(conn->conn_initial_path->path_send_ctl, po,
                                 XQC_TEST_SPLIT_NOW, 0);
    xqc_send_queue_maybe_remove_unacked(po, conn->conn_send_queue, NULL);
}

/* the path MTU goes down: the connection builds packets of the new size */
static void
xqc_test_split_shrink(xqc_connection_t *conn)
{
    conn->conn_initial_path->curr_pkt_out_size = XQC_TEST_SPLIT_NEW_SIZE;
    xqc_conn_try_to_update_mss(conn);
    CU_ASSERT_EQUAL(conn->pkt_out_size, XQC_TEST_SPLIT_NEW_SIZE);
}

/* ACKs up to largest_acked: the packets sent long before are lost */
static void
xqc_test_split_detect_lost(xqc_connection_t *conn,
    xqc_packet_number_t largest_acked)
{
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;

    send_ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = largest_acked;
    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, XQC_TEST_SPLIT_NOW);
}

/* the data of a STREAM frame of po (RFC 9000 Section 19.8) */
static const unsigned char *
xqc_test_split_frame_data(const xqc_packet_out_t *po,
    const xqc_po_stream_frame_t *frame)
{
    const unsigned char *p = po->po_buf + frame->ps_type_offset;
    unsigned char type = *p++;

    p += xqc_vint_len(*p >> 6);
    if (type & 0x04) {
        p += xqc_vint_len(*p >> 6);
    }
    if (type & 0x02) {
        p += xqc_vint_len(*p >> 6);
    }
    return p;
}

/*
 * The lost list resends the len bytes of test data of stream, in order,
 * each packet of the current size with a STREAM frame of its own that holds
 * a stream reference, and the FIN in the last one when fin. Returns the
 * number of those packets.
 */
static int
xqc_test_split_check_pieces(xqc_connection_t *conn, xqc_stream_t *stream,
    size_t len, uint8_t fin)
{
    xqc_list_head_t *pos;
    uint64_t next = 0;
    int count = 0;

    xqc_list_for_each(pos, &conn->conn_send_queue->sndq_lost_packets) {
        xqc_packet_out_t *po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        xqc_po_stream_frame_t *frame = &po->po_stream_frames[0];
        const unsigned char *data;

        if (!(po->po_frame_types & XQC_FRAME_BIT_STREAM)
            || frame->ps_stream_id != stream->stream_id)
        {
            continue;
        }

        CU_ASSERT(po->po_used_size <= conn->pkt_out_size);
        CU_ASSERT_PTR_NULL(po->po_origin);
        CU_ASSERT(po->po_flag & XQC_POF_STREAM_UNACK);
        CU_ASSERT_EQUAL(po->po_stream_frames_idx, 1);
        CU_ASSERT_EQUAL(frame->ps_offset, next);
        data = xqc_test_split_frame_data(po, frame);
        for (unsigned int i = 0; i < frame->ps_length; i++) {
            CU_ASSERT_EQUAL(data[i], xqc_test_split_byte(next + i));
        }
        next += frame->ps_length;
        CU_ASSERT_EQUAL(frame->ps_has_fin, fin && next == len);
        count++;
    }

    CU_ASSERT_EQUAL(next, len);
    return count;
}

/* the packets of the lost list go out and are acknowledged */
static void
xqc_test_split_ack_lost_list(xqc_connection_t *conn, xqc_packet_number_t pn)
{
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next,
                           &conn->conn_send_queue->sndq_lost_packets)
    {
        xqc_packet_out_t *po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        xqc_test_split_send(conn, po, pn++);
        xqc_test_split_ack(conn, po);
    }
}

/* a PTO probe copy of po goes out as packet number pn, sent at sent_time */
static xqc_packet_out_t *
xqc_test_split_probe_copy(xqc_connection_t *conn, xqc_packet_out_t *po,
    xqc_packet_number_t pn, xqc_usec_t sent_time)
{
    xqc_send_queue_t *sq = conn->conn_send_queue;
    xqc_packet_out_t *copy;

    xqc_send_ctl_decrease_inflight(conn, po);
    xqc_send_queue_copy_to_probe(po, sq, conn->conn_initial_path);
    CU_ASSERT_FATAL(!xqc_list_empty(&sq->sndq_pto_probe_packets));
    copy = xqc_list_entry(sq->sndq_pto_probe_packets.next, xqc_packet_out_t,
                          po_list);
    xqc_test_split_send(conn, copy, pn);
    copy->po_sent_time = sent_time;
    return copy;
}

/*
 * A lost STREAM packet that no longer fits, a PTO probe copy of the packet
 * first sent: its data goes into packets that fit, which take the stream
 * references, and the packets of the old size are dropped. A late ACK of the
 * first one gives back no reference again, and the FIN is acknowledged with
 * the new packet that carries it.
 */
void
xqc_test_send_ctl_split_lost_stream_packet(void)
{
    xqc_connection_t *conn = xqc_test_split_conn();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_queue_t *sq = conn->conn_send_queue;
    xqc_stream_t *stream = xqc_create_stream_with_conn(conn,
        XQC_UNDEFINE_STREAM_ID, XQC_CLI_BID, NULL, NULL);
    CU_ASSERT_FATAL(stream != NULL);

    xqc_test_split_write(stream, XQC_TEST_SPLIT_DATA_LEN, 1);
    xqc_packet_out_t *po = xqc_test_split_queued(conn, stream);
    CU_ASSERT_FATAL(po != NULL);
    xqc_test_split_send(conn, po, 1);
    xqc_packet_out_t *copy = xqc_test_split_probe_copy(conn, po, 2, 2);
    CU_ASSERT_EQUAL(stream->stream_unacked_pkt, 1);
    CU_ASSERT_EQUAL(stream->stream_state_send, XQC_SEND_STREAM_ST_DATA_SENT);

    xqc_test_split_shrink(conn);
    CU_ASSERT_FATAL(xqc_packet_out_exceeds_mss(conn, copy));
    xqc_test_split_detect_lost(conn, 10);

    int pieces = xqc_test_split_check_pieces(conn, stream,
                                             XQC_TEST_SPLIT_DATA_LEN, 1);
    CU_ASSERT(pieces >= 2);
    CU_ASSERT_EQUAL(stream->stream_unacked_pkt, pieces);
    CU_ASSERT(po->po_flag & XQC_POF_SPLIT);
    CU_ASSERT(copy->po_flag & XQC_POF_RETRANSED);
    CU_ASSERT_EQUAL(conn->detected_loss_cnt, 1);
    CU_ASSERT_EQUAL(stream->stream_stats.first_fin_ack_time, 0);
    CU_ASSERT_EQUAL(conn->conn_err, 0);

    /* a late ACK of the packet first sent */
    xqc_send_ctl_on_packet_acked(conn->conn_initial_path->path_send_ctl, po,
                                 XQC_TEST_SPLIT_NOW, 0);
    CU_ASSERT_EQUAL(stream->stream_unacked_pkt, pieces);
    CU_ASSERT_EQUAL(stream->stream_state_send, XQC_SEND_STREAM_ST_DATA_SENT);
    CU_ASSERT_EQUAL(stream->stream_stats.first_fin_ack_time, 0);

    /* the next loss detection drops them */
    xqc_test_split_detect_lost(conn, 10);
    CU_ASSERT(xqc_list_empty(&sq->sndq_unacked_packets[XQC_PNS_APP_DATA]));

    xqc_test_split_ack_lost_list(conn, 20);
    CU_ASSERT_EQUAL(stream->stream_unacked_pkt, 0);
    CU_ASSERT_EQUAL(stream->stream_state_send, XQC_SEND_STREAM_ST_DATA_RECVD);
    CU_ASSERT(stream->stream_stats.first_fin_ack_time != 0);

    xqc_engine_destroy(conn->engine);
}

/*
 * A lost packet that still fits is copied as before, and so is one with a
 * DATAGRAM frame, which cannot be cut out.
 */
void
xqc_test_send_ctl_split_lost_packet_copied(void)
{
    xqc_connection_t *conn = xqc_test_split_conn();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_queue_t *sq = conn->conn_send_queue;
    xqc_stream_t *stream = xqc_create_stream_with_conn(conn,
        XQC_UNDEFINE_STREAM_ID, XQC_CLI_BID, NULL, NULL);
    CU_ASSERT_FATAL(stream != NULL);

    /* a packet of the new size */
    xqc_test_split_write(stream, XQC_TEST_SPLIT_NEW_SIZE - 100, 0);
    xqc_packet_out_t *fits = xqc_test_split_queued(conn, stream);
    CU_ASSERT_FATAL(fits != NULL);
    xqc_test_split_send(conn, fits, 1);

    /* an oversized packet with a DATAGRAM frame */
    xqc_packet_out_t *dgram = xqc_packet_out_get(sq);
    CU_ASSERT_FATAL(dgram != NULL);
    dgram->po_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    dgram->po_frame_types = XQC_FRAME_BIT_DATAGRAM | XQC_FRAME_BIT_MAX_DATA;
    dgram->po_used_size = XQC_TEST_SPLIT_OLD_SIZE;
    xqc_send_queue_insert_send(dgram, &sq->sndq_send_packets, sq);
    xqc_test_split_send(conn, dgram, 2);

    xqc_test_split_shrink(conn);
    CU_ASSERT_FALSE(xqc_packet_out_exceeds_mss(conn, fits));
    CU_ASSERT_EQUAL(xqc_send_queue_split_lost(sq, fits), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_send_queue_split_lost(sq, dgram), -XQC_EPARAM);

    xqc_test_split_detect_lost(conn, 10);
    CU_ASSERT_EQUAL(conn->detected_loss_cnt, 2);
    CU_ASSERT_FALSE(fits->po_flag & XQC_POF_SPLIT);
    CU_ASSERT_FALSE(dgram->po_flag & XQC_POF_SPLIT);
    CU_ASSERT_EQUAL(fits->po_origin_ref_cnt, 1);
    CU_ASSERT_EQUAL(dgram->po_origin_ref_cnt, 1);
    CU_ASSERT_EQUAL(stream->stream_unacked_pkt, 1);

    int copies = 0;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &sq->sndq_lost_packets) {
        xqc_packet_out_t *copy = xqc_list_entry(pos, xqc_packet_out_t,
                                                po_list);
        CU_ASSERT(copy->po_origin == fits || copy->po_origin == dgram);
        CU_ASSERT_EQUAL(copy->po_used_size, copy->po_origin->po_used_size);
        copies++;
    }
    CU_ASSERT_EQUAL(copies, 2);
    CU_ASSERT_EQUAL(conn->conn_err, 0);

    xqc_engine_destroy(conn->engine);
}

/*
 * The other frames of a lost packet that no longer fits go into one more
 * packet, without the STREAM frames and the padding: a MAX_DATA sent with
 * stream data, and a MAX_STREAMS padded to the old size.
 */
void
xqc_test_send_ctl_split_keeps_other_frames(void)
{
    xqc_connection_t *conn = xqc_test_split_conn();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_queue_t *sq = conn->conn_send_queue;
    xqc_stream_t *stream = xqc_create_stream_with_conn(conn,
        XQC_UNDEFINE_STREAM_ID, XQC_CLI_BID, NULL, NULL);
    CU_ASSERT_FATAL(stream != NULL);

    xqc_test_split_write(stream, XQC_TEST_SPLIT_DATA_LEN - 20, 0);
    xqc_packet_out_t *mixed = xqc_test_split_queued(conn, stream);
    CU_ASSERT_FATAL(mixed != NULL);
    unsigned int header_len = mixed->po_stream_frames[0].ps_type_offset;
    unsigned int max_data_len = xqc_gen_max_data_frame(mixed, 1 << 20);
    mixed->po_used_size += max_data_len;
    xqc_test_split_send(conn, mixed, 1);

    xqc_packet_out_t *padded = xqc_write_new_packet(conn,
                                                    XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT_FATAL(padded != NULL);
    unsigned int max_streams_len = xqc_gen_max_streams_frame(padded, 100, 1);
    CU_ASSERT_FATAL(max_streams_len > 0);
    padded->po_used_size += max_streams_len;
    xqc_gen_padding_frame_with_len(conn, padded,
        XQC_TEST_SPLIT_OLD_SIZE - padded->po_used_size,
        XQC_TEST_SPLIT_OLD_SIZE);
    xqc_test_split_send(conn, padded, 2);

    xqc_test_split_shrink(conn);
    xqc_test_split_detect_lost(conn, 10);
    CU_ASSERT(mixed->po_flag & XQC_POF_SPLIT);
    CU_ASSERT(padded->po_flag & XQC_POF_SPLIT);
    CU_ASSERT_EQUAL(stream->stream_unacked_pkt,
                    xqc_test_split_check_pieces(conn, stream,
                        XQC_TEST_SPLIT_DATA_LEN - 20, 0));

    int max_data = 0, max_streams = 0;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &sq->sndq_lost_packets) {
        xqc_packet_out_t *po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (po->po_frame_types & XQC_FRAME_BIT_STREAM) {
            continue;
        }

        CU_ASSERT_PTR_NULL(po->po_origin);
        CU_ASSERT_FALSE(po->po_flag & XQC_POF_STREAM_UNACK);
        CU_ASSERT_EQUAL(po->po_buf_size, XQC_TEST_SPLIT_NEW_SIZE);
        CU_ASSERT_EQUAL(po->po_stream_frames_idx, 0);
        if (po->po_frame_types == XQC_FRAME_BIT_MAX_DATA) {
            CU_ASSERT_EQUAL(po->po_used_size, header_len + max_data_len);
            CU_ASSERT_EQUAL(po->po_buf[header_len], 0x10);
            max_data++;

        } else if (po->po_frame_types == XQC_FRAME_BIT_MAX_STREAMS) {
            CU_ASSERT_EQUAL(po->po_used_size, header_len + max_streams_len);
            CU_ASSERT_PTR_NULL(po->po_padding);
            max_streams++;

        } else {
            CU_FAIL("unexpected frames resent");
        }
    }
    CU_ASSERT_EQUAL(max_data, 1);
    CU_ASSERT_EQUAL(max_streams, 1);
    CU_ASSERT_EQUAL(conn->conn_err, 0);

    xqc_engine_destroy(conn->engine);
}

/*
 * draft-ietf-quic-reliable-stream-reset-09 Section 5.3: a reliable reset
 * completes once the data below the reliable size is acknowledged. When a
 * lost packet is split, its other copies are dropped, and their data is not
 * taken as acknowledged, which only the new packets can be.
 */
void
xqc_test_send_ctl_split_copy_not_acked(void)
{
    xqc_connection_t *conn = xqc_test_split_conn();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_queue_t *sq = conn->conn_send_queue;
    xqc_path_ctx_t *path = conn->conn_initial_path;
    conn->local_settings.reset_stream_at = XQC_TRUE;
    conn->remote_settings.reset_stream_at = XQC_TRUE;
    xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
        XQC_STREAM_UNI, NULL);
    CU_ASSERT_FATAL(stream != NULL);
    stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
    CU_ASSERT(xqc_stream_set_reliable_size(stream, XQC_TEST_SPLIT_DATA_LEN)
              == XQC_OK);

    xqc_test_split_write(stream, XQC_TEST_SPLIT_DATA_LEN, 0);
    xqc_packet_out_t *po = xqc_test_split_queued(conn, stream);
    CU_ASSERT_FATAL(po != NULL);
    xqc_test_split_send(conn, po, 1);

    /* two PTO probes sent copies of it at the old size, the second one
     * recently */
    xqc_packet_out_t *copy = xqc_test_split_probe_copy(conn, po, 2, 2);
    xqc_packet_out_t *recent = xqc_test_split_probe_copy(conn, po, 20,
        XQC_TEST_SPLIT_NOW - 1000);
    CU_ASSERT_PTR_EQUAL(copy->po_origin, po);
    CU_ASSERT_PTR_EQUAL(recent->po_origin, po);
    CU_ASSERT_EQUAL(stream->stream_unacked_pkt, 1);

    /* RESET_STREAM_AT, acknowledged */
    CU_ASSERT(xqc_stream_reset(stream, 9) == XQC_OK);
    xqc_list_head_t *pos;
    xqc_packet_out_t *reset = NULL;
    xqc_list_for_each(pos, &sq->sndq_send_packets) {
        xqc_packet_out_t *p = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (p->po_frame_types & XQC_FRAME_BIT_RESET_STREAM_AT) {
            reset = p;
        }
    }
    CU_ASSERT_FATAL(reset != NULL);
    xqc_test_split_send(conn, reset, 3);
    xqc_test_split_ack(conn, reset);
    CU_ASSERT(stream->reset_at.send_reset_acked);
    CU_ASSERT_EQUAL(stream->stream_state_send, XQC_SEND_STREAM_ST_DATA_SENT);

    /* the path MTU goes down; the first copy is lost and split, and the
     * recent one, still in flight, is dropped */
    xqc_test_split_shrink(conn);
    xqc_test_split_detect_lost(conn, 10);
    CU_ASSERT(po->po_flag & XQC_POF_SPLIT);
    int pieces = xqc_test_split_check_pieces(conn, stream,
                                             XQC_TEST_SPLIT_DATA_LEN, 0);
    CU_ASSERT(pieces >= 2);
    CU_ASSERT_EQUAL(path->path_send_ctl->ctl_bytes_ack_eliciting_inflight[
                        XQC_PNS_APP_DATA], 0);
    CU_ASSERT_EQUAL(stream->stream_unacked_pkt, pieces);
    CU_ASSERT_EQUAL(stream->stream_acked_offset, 0);
    CU_ASSERT_EQUAL(stream->stream_state_send, XQC_SEND_STREAM_ST_DATA_SENT);

    /* the next loss detection drops the lost packet and its first copy */
    xqc_test_split_detect_lost(conn, 10);
    CU_ASSERT(xqc_list_empty(&sq->sndq_unacked_packets[XQC_PNS_APP_DATA]));
    CU_ASSERT_EQUAL(stream->stream_acked_offset, 0);
    CU_ASSERT_EQUAL(stream->stream_state_send, XQC_SEND_STREAM_ST_DATA_SENT);

    /* the new packets acknowledged complete the reset */
    xqc_test_split_ack_lost_list(conn, 20);
    CU_ASSERT_EQUAL(stream->stream_acked_offset, XQC_TEST_SPLIT_DATA_LEN);
    CU_ASSERT_EQUAL(stream->stream_state_send, XQC_SEND_STREAM_ST_DATA_RECVD);
    CU_ASSERT_EQUAL(conn->conn_err, 0);

    xqc_engine_destroy(conn->engine);
}

/*
 * A PTO probes with a packet that fits: a copy of one built before the path
 * MTU went down would be lost as well. Without any, it sends PINGs.
 */
static void
xqc_test_send_ctl_pto_probe(xqc_bool_t with_fitting_packet)
{
    xqc_connection_t *conn = xqc_test_split_conn();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_queue_t *sq = conn->conn_send_queue;
    xqc_stream_t *big = xqc_create_stream_with_conn(conn,
        XQC_UNDEFINE_STREAM_ID, XQC_CLI_BID, NULL, NULL);
    xqc_stream_t *small = xqc_create_stream_with_conn(conn,
        XQC_UNDEFINE_STREAM_ID, XQC_CLI_BID, NULL, NULL);
    CU_ASSERT_FATAL(big != NULL && small != NULL);

    xqc_test_split_write(big, XQC_TEST_SPLIT_DATA_LEN, 0);
    xqc_packet_out_t *oversized = xqc_test_split_queued(conn, big);
    CU_ASSERT_FATAL(oversized != NULL);
    xqc_test_split_send(conn, oversized, 1);

    xqc_packet_out_t *fits = NULL;
    if (with_fitting_packet) {
        xqc_test_split_write(small, 100, 0);
        fits = xqc_test_split_queued(conn, small);
        CU_ASSERT_FATAL(fits != NULL);
        xqc_test_split_send(conn, fits, 2);
    }

    xqc_test_split_shrink(conn);
    xqc_path_send_one_or_two_ack_elicit_pkts(conn->conn_initial_path,
                                             XQC_PNS_APP_DATA);

    int probes = 0;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &sq->sndq_pto_probe_packets) {
        xqc_packet_out_t *po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        CU_ASSERT(po->po_used_size <= xqc_conn_get_mss(conn));
        if (with_fitting_packet) {
            CU_ASSERT_PTR_EQUAL(po->po_origin, fits);

        } else {
            CU_ASSERT_PTR_NULL(po->po_origin);
            CU_ASSERT_EQUAL(po->po_frame_types, XQC_FRAME_BIT_PING);
        }
        probes++;
    }
    CU_ASSERT_EQUAL(probes, XQC_CONN_PTO_PKT_CNT_MAX);
    CU_ASSERT(oversized->po_flag & XQC_POF_IN_FLIGHT);
    CU_ASSERT_FALSE(oversized->po_flag & XQC_POF_TLP);
    CU_ASSERT_EQUAL(oversized->po_origin_ref_cnt, 0);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_send_ctl_pto_pings_when_none_fits(void)
{
    xqc_test_send_ctl_pto_probe(XQC_FALSE);
}

void
xqc_test_send_ctl_pto_probes_packet_that_fits(void)
{
    xqc_test_send_ctl_pto_probe(XQC_TRUE);
}

/*
 * The packet size of the connection follows its smallest open path, down
 * too, and PMTUD searches again from there; without an open path it stays.
 */
void
xqc_test_send_ctl_mss_follows_smallest_path(void)
{
    xqc_connection_t *conn = xqc_test_split_conn();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_path_ctx_t *path = conn->conn_initial_path;

    conn->max_pkt_out_size = XQC_TEST_SPLIT_OLD_SIZE;
    conn->probing_pkt_out_size = XQC_TEST_SPLIT_OLD_SIZE;
    conn->probing_cnt = 2;
    conn->conn_flag &= ~XQC_CONN_FLAG_PMTUD_PROBING;
    path->path_max_pkt_out_size = XQC_MAX_PACKET_OUT_SIZE;

    xqc_test_split_shrink(conn);
    CU_ASSERT_EQUAL(conn->max_pkt_out_size, XQC_MAX_PACKET_OUT_SIZE);
    CU_ASSERT_EQUAL(conn->probing_pkt_out_size, XQC_MAX_PACKET_OUT_SIZE);
    CU_ASSERT_EQUAL(conn->probing_cnt, 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_PMTUD_PROBING) != 0);

    /* a closing path does not count */
    xqc_set_path_state(path, XQC_PATH_STATE_CLOSING);
    path->curr_pkt_out_size = XQC_PACKET_OUT_SIZE - 100;
    xqc_conn_try_to_update_mss(conn);
    CU_ASSERT_EQUAL(conn->pkt_out_size, XQC_TEST_SPLIT_NEW_SIZE);

    xqc_engine_destroy(conn->engine);
}
