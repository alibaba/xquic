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
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_in.h"


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
 * RFC 9002 Sections 7.6.1 and 7.6.2 require two lost ack-eliciting
 * transmissions, with no intervening ACK, after a prior RTT sample.
 */
static xqc_packet_out_t *xqc_test_send_ctl_send_packet(xqc_connection_t *conn,
    xqc_pkt_num_space_t pns, xqc_packet_number_t pkt_num,
    xqc_usec_t sent_time, xqc_frame_type_bit_t frames);
static xqc_packet_out_t *xqc_test_send_ctl_seed_lost_packet(
    xqc_connection_t *conn, xqc_packet_number_t pkt_num,
    xqc_usec_t sent_time);
static void xqc_test_send_ctl_arm_pc_state(xqc_send_ctl_t *send_ctl,
    xqc_usec_t srtt, xqc_usec_t rttvar, xqc_usec_t minrtt,
    xqc_packet_number_t largest_acked);
static void xqc_test_send_ctl_ack(xqc_connection_t *conn,
    xqc_pkt_num_space_t pns, xqc_packet_number_t largest,
    xqc_packet_number_t earlier, xqc_usec_t now);
static void xqc_test_send_ctl_assert_pc(xqc_send_ctl_t *send_ctl,
    xqc_bool_t expected);


static xqc_packet_out_t *
xqc_test_send_ctl_send_packet(xqc_connection_t *conn,
    xqc_pkt_num_space_t pns, xqc_packet_number_t pkt_num,
    xqc_usec_t sent_time, xqc_frame_type_bit_t frames)
{
    xqc_send_queue_t *sq = conn->conn_send_queue;
    xqc_path_ctx_t *path = conn->conn_initial_path;
    xqc_pkt_type_t type = XQC_PTYPE_SHORT_HEADER;

    if (pns == XQC_PNS_INIT) {
        type = XQC_PTYPE_INIT;

    } else if (pns == XQC_PNS_HSK) {
        type = XQC_PTYPE_HSK;
    }

    xqc_packet_out_t *po = xqc_packet_out_get_and_insert_send(sq, type);
    if (po == NULL) {
        return NULL;
    }

    po->po_pkt.pkt_pns = pns;
    po->po_pkt.pkt_num = pkt_num;
    po->po_path_id = path->path_id;
    po->po_sent_time = sent_time;
    po->po_frame_types = frames;
    po->po_used_size = 1200;
    po->po_enc_size = 1200;
    xqc_send_ctl_on_packet_sent(path->path_send_ctl,
                                xqc_get_pn_ctl(conn, path), po, sent_time);
    xqc_send_queue_remove_send(&po->po_list);
    if (XQC_IS_ACK_ELICITING(frames)) {
        xqc_send_queue_insert_unacked(po, &sq->sndq_unacked_packets[pns], sq);

    } else {
        xqc_send_queue_insert_free(po, &sq->sndq_free_packets, sq);
    }
    return po;
}


static xqc_packet_out_t *
xqc_test_send_ctl_seed_lost_packet(xqc_connection_t *conn,
    xqc_packet_number_t pkt_num, xqc_usec_t sent_time)
{
    return xqc_test_send_ctl_send_packet(conn, XQC_PNS_APP_DATA, pkt_num,
                                         sent_time, XQC_FRAME_BIT_PING);
}


static void
xqc_test_send_ctl_arm_pc_state(xqc_send_ctl_t *send_ctl,
    xqc_usec_t srtt, xqc_usec_t rttvar, xqc_usec_t minrtt,
    xqc_packet_number_t largest_acked)
{
    send_ctl->ctl_srtt = srtt;
    send_ctl->ctl_rttvar = rttvar;
    send_ctl->ctl_minrtt = minrtt;
    send_ctl->ctl_latest_rtt = srtt;
    send_ctl->ctl_first_rtt_sample_time = 1;
    send_ctl->ctl_pto_count = 0;
    /* Direct loss passes model a previously received ACK above the losses. */
    send_ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = largest_acked
        ? largest_acked + 1 : XQC_MAX_UINT64_VALUE;
    send_ctl->ctl_conn->remote_settings.max_ack_delay = 25;
    send_ctl->ctl_conn->conn_settings.disable_pn_skipping = 1;
}


static void
xqc_test_send_ctl_ack(xqc_connection_t *conn, xqc_pkt_num_space_t pns,
    xqc_packet_number_t largest, xqc_packet_number_t earlier, xqc_usec_t now)
{
    xqc_path_ctx_t *path = conn->conn_initial_path;
    xqc_ack_info_t ack = {0};

    ack.pns = pns;
    ack.n_ranges = 1;
    ack.ranges[0].low = largest;
    ack.ranges[0].high = largest;
    if (earlier != XQC_MAX_UINT64_VALUE) {
        ack.n_ranges = 2;
        ack.ranges[1].low = earlier;
        ack.ranges[1].high = earlier;
    }

    /* A cross-path ACK leaves the pinned RTT estimate unchanged. */
    CU_ASSERT_EQUAL(xqc_send_ctl_on_ack_received(path->path_send_ctl,
        xqc_get_pn_ctl(conn, path), conn->conn_send_queue, &ack, now,
        XQC_FALSE), XQC_OK);
}


static void
xqc_test_send_ctl_assert_pc(xqc_send_ctl_t *send_ctl, xqc_bool_t expected)
{
    if (expected) {
        CU_ASSERT_EQUAL(send_ctl->ctl_first_rtt_sample_time, 0);
        CU_ASSERT_EQUAL(send_ctl->ctl_minrtt, XQC_MAX_UINT32_VALUE);
        CU_ASSERT_EQUAL(send_ctl->ctl_srtt,
                        send_ctl->ctl_conn->conn_settings.initial_rtt);
        CU_ASSERT_EQUAL(send_ctl->ctl_rttvar,
                        send_ctl->ctl_conn->conn_settings.initial_rtt / 2);

    } else {
        CU_ASSERT_NOT_EQUAL(send_ctl->ctl_first_rtt_sample_time, 0);
        CU_ASSERT_EQUAL(send_ctl->ctl_srtt, 10000);
        CU_ASSERT_EQUAL(send_ctl->ctl_rttvar, 2000);
        CU_ASSERT_EQUAL(send_ctl->ctl_minrtt, 8000);
    }
}


void
xqc_test_send_ctl_granularity_marks_at_boundary(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    uint32_t inflight_before = send_ctl->ctl_bytes_in_flight;

    send_ctl->ctl_srtt = 0;
    send_ctl->ctl_latest_rtt = 0;
    send_ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = 100;
    send_ctl->ctl_reordering_packet_threshold = XQC_kPacketThreshold;
    CU_ASSERT_PTR_NOT_NULL_FATAL(
        xqc_test_send_ctl_seed_lost_packet(conn, 99, 1));

    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, 1001);
    CU_ASSERT_EQUAL(conn->detected_loss_cnt, 1);
    CU_ASSERT_EQUAL(send_ctl->sampler.loss, 1);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, inflight_before);
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_granularity_defers_before_boundary(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    uint32_t inflight_before = send_ctl->ctl_bytes_in_flight;

    send_ctl->ctl_srtt = 0;
    send_ctl->ctl_latest_rtt = 0;
    send_ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = 100;
    send_ctl->ctl_reordering_packet_threshold = XQC_kPacketThreshold;
    CU_ASSERT_PTR_NOT_NULL_FATAL(
        xqc_test_send_ctl_seed_lost_packet(conn, 99, 1));

    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, 1000);
    CU_ASSERT_EQUAL(conn->detected_loss_cnt, 0);
    CU_ASSERT_EQUAL(send_ctl->sampler.loss, 0);
    CU_ASSERT_EQUAL(send_ctl->ctl_loss_time[XQC_PNS_APP_DATA], 1001);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, inflight_before + 1200);
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_persistent_congestion_resets_rtt(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    uint32_t inflight_before = send_ctl->ctl_bytes_in_flight;
    CU_ASSERT_PTR_NOT_NULL_FATAL(
        send_ctl->ctl_cong_callback->xqc_cong_ctl_reset_cwnd);
    CU_ASSERT_FATAL(conn->conn_settings.initial_rtt > 0);

    xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(
        xqc_test_send_ctl_seed_lost_packet(conn, 1, 1000000));
    CU_ASSERT_PTR_NOT_NULL_FATAL(
        xqc_test_send_ctl_seed_lost_packet(conn, 2, 1200000));
    uint64_t cwnd_before = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(
        send_ctl->ctl_cong);

    CU_ASSERT_PTR_NOT_NULL_FATAL(
        xqc_test_send_ctl_seed_lost_packet(conn, 3, 1390000));
    xqc_test_send_ctl_ack(conn, XQC_PNS_APP_DATA, 3,
                          XQC_MAX_UINT64_VALUE, 1400000);
    xqc_test_send_ctl_assert_pc(send_ctl, XQC_TRUE);
    CU_ASSERT_EQUAL(conn->detected_loss_cnt, 2);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, inflight_before);
    CU_ASSERT(send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(
        send_ctl->ctl_cong) < cwnd_before);
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_persistent_congestion_rtt_reseeds_from_new_sample(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;

    xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(
        xqc_test_send_ctl_seed_lost_packet(conn, 1, 1000000));
    CU_ASSERT_PTR_NOT_NULL_FATAL(
        xqc_test_send_ctl_seed_lost_packet(conn, 2, 1200000));
    CU_ASSERT_PTR_NOT_NULL_FATAL(
        xqc_test_send_ctl_seed_lost_packet(conn, 3, 1390000));
    xqc_test_send_ctl_ack(conn, XQC_PNS_APP_DATA, 3,
                          XQC_MAX_UINT64_VALUE, 1400000);
    CU_ASSERT_EQUAL(send_ctl->ctl_first_rtt_sample_time, 0);

    /* RFC 9002 Section 5.2: the next RTT sample seeds the estimator. */
    xqc_usec_t latest = 300000;
    xqc_send_ctl_update_rtt(send_ctl, &latest, 0);
    CU_ASSERT_EQUAL(send_ctl->ctl_minrtt, 300000);
    CU_ASSERT_EQUAL(send_ctl->ctl_srtt, 300000);
    CU_ASSERT_EQUAL(send_ctl->ctl_rttvar, 150000);
    CU_ASSERT_NOT_EQUAL(send_ctl->ctl_first_rtt_sample_time, 0);
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_single_loss_does_not_reset_rtt(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    uint32_t inflight_before = send_ctl->ctl_bytes_in_flight;

    xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 1);
    send_ctl->ctl_pto_count = 10;
    CU_ASSERT_PTR_NOT_NULL_FATAL(
        xqc_test_send_ctl_seed_lost_packet(conn, 1, 1000000));
    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, 2000000);
    xqc_test_send_ctl_assert_pc(send_ctl, XQC_FALSE);
    CU_ASSERT_EQUAL(conn->detected_loss_cnt, 1);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, inflight_before);
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_persistent_congestion_no_rtt_sample_early_return(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;

    xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 2);
    send_ctl->ctl_first_rtt_sample_time = 0;
    CU_ASSERT_PTR_NOT_NULL_FATAL(
        xqc_test_send_ctl_seed_lost_packet(conn, 1, 1000000));
    CU_ASSERT_PTR_NOT_NULL_FATAL(
        xqc_test_send_ctl_seed_lost_packet(conn, 2, 1200000));
    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, 1400000);
    CU_ASSERT_EQUAL(send_ctl->ctl_first_rtt_sample_time, 0);
    CU_ASSERT_EQUAL(send_ctl->ctl_srtt, 10000);
    CU_ASSERT_EQUAL(send_ctl->ctl_rttvar, 2000);
    CU_ASSERT_EQUAL(send_ctl->ctl_minrtt, 8000);
    CU_ASSERT_EQUAL(conn->detected_loss_cnt, 2);
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_persistent_congestion_duration_boundary(void)
{
    /* RFC 9002 Section 7.6.1: (10 + 8 + 25) ms * 3 = 129 ms. */
    for (xqc_usec_t span = 128999; span <= 129001; span++) {
        xqc_connection_t *conn = test_engine_connect();
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
        uint32_t inflight_before = send_ctl->ctl_bytes_in_flight;
        xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 0);

        CU_ASSERT_PTR_NOT_NULL_FATAL(
            xqc_test_send_ctl_seed_lost_packet(conn, 1, 1000000));
        CU_ASSERT_PTR_NOT_NULL_FATAL(
            xqc_test_send_ctl_seed_lost_packet(conn, 7, 1000000 + span));
        CU_ASSERT_PTR_NOT_NULL_FATAL(
            xqc_test_send_ctl_seed_lost_packet(conn, 8, 1390000));
        CU_ASSERT_EQUAL(send_ctl->ctl_pto_count, 0);
        xqc_test_send_ctl_ack(conn, XQC_PNS_APP_DATA, 8,
                              XQC_MAX_UINT64_VALUE, 1400000);
        xqc_test_send_ctl_assert_pc(send_ctl, span > 129000);
        CU_ASSERT_EQUAL(conn->detected_loss_cnt, 2);
        CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, inflight_before);
        xqc_engine_destroy(conn->engine);
    }
}


void
xqc_test_send_ctl_persistent_congestion_prior_rtt_required(void)
{
    for (int prior_sample = 0; prior_sample < 2; prior_sample++) {
        xqc_connection_t *conn = test_engine_connect();
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
        xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 2);
        send_ctl->ctl_first_rtt_sample_time = prior_sample ? 1000000 : 0;
        CU_ASSERT_PTR_NOT_NULL_FATAL(
            xqc_test_send_ctl_seed_lost_packet(conn, 1, 1000000));
        CU_ASSERT_PTR_NOT_NULL_FATAL(
            xqc_test_send_ctl_seed_lost_packet(conn, 2, 1200000));
        if (!prior_sample) {
            send_ctl->ctl_first_rtt_sample_time = 1300000;
        }
        send_ctl->ctl_pto_count = 10;
        xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                                 XQC_PNS_APP_DATA, 2000000);
        xqc_test_send_ctl_assert_pc(send_ctl, XQC_FALSE);
        CU_ASSERT_EQUAL(conn->detected_loss_cnt, 2);
        xqc_engine_destroy(conn->engine);
    }
}


void
xqc_test_send_ctl_persistent_congestion_ack_interrupts(void)
{
    for (int mode = 0; mode < 5; mode++) {
        xqc_connection_t *conn = test_engine_connect();
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
        xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 0);
        xqc_pkt_num_space_t middle_pns = mode == 3
                                        ? XQC_PNS_HSK : XQC_PNS_APP_DATA;
        xqc_frame_type_bit_t middle_frame = mode >= 2
                                            ? XQC_FRAME_BIT_ACK
                                            : XQC_FRAME_BIT_PING;
        CU_ASSERT_PTR_NOT_NULL_FATAL(
            xqc_test_send_ctl_seed_lost_packet(conn, 1, 1000000));
        CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_send_packet(conn,
            middle_pns, 2, 1100000, middle_frame));
        CU_ASSERT_PTR_NOT_NULL_FATAL(
            xqc_test_send_ctl_seed_lost_packet(conn, 3, 1200000));
        CU_ASSERT_PTR_NOT_NULL_FATAL(
            xqc_test_send_ctl_seed_lost_packet(conn, 4, 1390000));

        if (mode == 1) {
            /* Reordered ACK, after the higher packet number was ACKed. */
            send_ctl->ctl_srtt = 1000000;
            send_ctl->ctl_latest_rtt = 1000000;
            send_ctl->ctl_reordering_packet_threshold = 100;
            xqc_test_send_ctl_ack(conn, XQC_PNS_APP_DATA, 4,
                                  XQC_MAX_UINT64_VALUE, 1400000);
            CU_ASSERT_EQUAL(conn->detected_loss_cnt, 0);
            send_ctl->ctl_srtt = 10000;
            send_ctl->ctl_latest_rtt = 10000;
            xqc_test_send_ctl_ack(conn, XQC_PNS_APP_DATA, 2,
                                  XQC_MAX_UINT64_VALUE, 1500000);

        } else if (mode >= 2 && mode <= 3) {
            /* ACK-only packets are already recycled, so has_acked is 0. */
            xqc_test_send_ctl_ack(conn, middle_pns, 2,
                                  XQC_MAX_UINT64_VALUE, 1400000);
        }

        send_ctl->ctl_pto_count = 10;
        xqc_test_send_ctl_ack(conn, XQC_PNS_APP_DATA, 4,
                              mode == 0 ? 2 : XQC_MAX_UINT64_VALUE, 1500000);
        /* An unacknowledged ACK-only packet does not split the interval. */
        xqc_test_send_ctl_assert_pc(send_ctl, mode == 4);
        xqc_engine_destroy(conn->engine);
    }
}


void
xqc_test_send_ctl_persistent_congestion_ack_eliciting_endpoints(void)
{
    for (int endpoint = 0; endpoint < 2; endpoint++) {
        xqc_connection_t *conn = test_engine_connect();
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
        xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 2);
        send_ctl->ctl_pto_count = 10;
        CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_send_packet(conn,
            XQC_PNS_APP_DATA, 1, 1000000,
            endpoint == 0 ? XQC_FRAME_BIT_PADDING : XQC_FRAME_BIT_PING));
        CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_send_packet(conn,
            XQC_PNS_APP_DATA, 2, 1200000,
            endpoint == 1 ? XQC_FRAME_BIT_ACK : XQC_FRAME_BIT_PING));
        xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                                 XQC_PNS_APP_DATA, 2000000);
        xqc_test_send_ctl_assert_pc(send_ctl, XQC_FALSE);
        CU_ASSERT_EQUAL(conn->detected_loss_cnt, 1);
        xqc_engine_destroy(conn->engine);
    }
}


void
xqc_test_send_ctl_persistent_congestion_across_loss_batches(void)
{
    for (int interrupted = 0; interrupted < 2; interrupted++) {
        xqc_connection_t *conn = test_engine_connect();
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
        uint32_t inflight_before = send_ctl->ctl_bytes_in_flight;
        xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 1);
        CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_send_packet(conn,
            XQC_PNS_APP_DATA, 1, 1000000, XQC_FRAME_BIT_DATAGRAM));
        xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                                 XQC_PNS_APP_DATA, 1050000);
        CU_ASSERT_EQUAL(conn->detected_loss_cnt, 1);
        CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, inflight_before);
        xqc_test_send_ctl_assert_pc(send_ctl, XQC_FALSE);

        if (interrupted) {
            CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_send_packet(conn,
                XQC_PNS_APP_DATA, 2, 1100000, XQC_FRAME_BIT_ACK));
            xqc_test_send_ctl_ack(conn, XQC_PNS_APP_DATA, 2,
                                  XQC_MAX_UINT64_VALUE, 1150000);
        }

        CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_send_packet(conn,
            XQC_PNS_APP_DATA, 3, 1200000, XQC_FRAME_BIT_DATAGRAM));
        CU_ASSERT_PTR_NOT_NULL_FATAL(
            xqc_test_send_ctl_seed_lost_packet(conn, 4, 1390000));
        xqc_test_send_ctl_ack(conn, XQC_PNS_APP_DATA, 4,
                              XQC_MAX_UINT64_VALUE, 1400000);
        xqc_test_send_ctl_assert_pc(send_ctl, !interrupted);
        CU_ASSERT_EQUAL(conn->detected_loss_cnt, 2);
        CU_ASSERT_EQUAL(send_ctl->ctl_lost_dgram_cnt, 2);
        CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, inflight_before);
        xqc_engine_destroy(conn->engine);
    }
}


void
xqc_test_send_ctl_persistent_congestion_pending_other_space(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    uint32_t inflight_before = send_ctl->ctl_bytes_in_flight;
    xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_send_packet(conn,
        XQC_PNS_HSK, 1, 1000000, XQC_FRAME_BIT_PING));
    CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_send_packet(conn,
        XQC_PNS_APP_DATA, 1, 1100000, XQC_FRAME_BIT_DATAGRAM));
    CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_send_packet(conn,
        XQC_PNS_HSK, 2, 1200000, XQC_FRAME_BIT_PING));
    send_ctl->ctl_pto_count = 10;
    send_ctl->ctl_largest_acked[XQC_PNS_HSK] = 3;

    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_HSK, 1400000);
    xqc_test_send_ctl_assert_pc(send_ctl, XQC_FALSE);
    CU_ASSERT_EQUAL(conn->detected_loss_cnt, 2);

    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, 1400000);
    xqc_test_send_ctl_assert_pc(send_ctl, XQC_TRUE);
    CU_ASSERT_EQUAL(conn->detected_loss_cnt, 3);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, inflight_before);
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_persistent_congestion_history_wrap(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    uint32_t inflight_before = send_ctl->ctl_bytes_in_flight;
    xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_send_packet(conn,
        XQC_PNS_HSK, 1, 1000000, XQC_FRAME_BIT_PING));

    for (size_t i = 1; i < XQC_PERSISTENT_CONGESTION_MAX_PACKETS; i++) {
        CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_send_packet(conn,
            XQC_PNS_INIT, i, 1000000 + i, XQC_FRAME_BIT_ACK));
    }
    CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_send_packet(conn,
        XQC_PNS_APP_DATA, 1, 1200000, XQC_FRAME_BIT_DATAGRAM));
    CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_send_packet(conn,
        XQC_PNS_HSK, 2, 1400000, XQC_FRAME_BIT_PING));

    /* Losing an evicted packet must not mark its reused slot as lost. */
    send_ctl->ctl_largest_acked[XQC_PNS_HSK] = 3;
    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_HSK, 1500000);
    xqc_test_send_ctl_assert_pc(send_ctl, XQC_FALSE);
    CU_ASSERT_EQUAL(conn->detected_loss_cnt, 2);

    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, 1500000);
    xqc_test_send_ctl_assert_pc(send_ctl, XQC_TRUE);
    CU_ASSERT_EQUAL(conn->detected_loss_cnt, 3);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, inflight_before);
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_persistent_congestion_history_reset(void)
{
    for (int reset_path = 0; reset_path < 2; reset_path++) {
        xqc_connection_t *conn = test_engine_connect();
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
        uint32_t inflight_before = send_ctl->ctl_bytes_in_flight;
        xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 1);
        CU_ASSERT_PTR_NOT_NULL_FATAL(
            xqc_test_send_ctl_seed_lost_packet(conn, 1, 1000000));
        xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                                 XQC_PNS_APP_DATA, 1050000);
        if (reset_path) {
            xqc_send_ctl_reset(send_ctl);
            inflight_before = send_ctl->ctl_bytes_in_flight;

        } else {
            xqc_send_ctl_on_pns_discard(send_ctl, XQC_PNS_HSK);
        }
        xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 2);
        CU_ASSERT_PTR_NOT_NULL_FATAL(
            xqc_test_send_ctl_seed_lost_packet(conn, 2, 1200000));
        xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                                 XQC_PNS_APP_DATA, 1250000);
        xqc_test_send_ctl_assert_pc(send_ctl, XQC_FALSE);

        CU_ASSERT_PTR_NOT_NULL_FATAL(
            xqc_test_send_ctl_seed_lost_packet(conn, 3, 1400000));
        send_ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = 4;
        xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                                 XQC_PNS_APP_DATA, 1450000);
        xqc_test_send_ctl_assert_pc(send_ctl, XQC_TRUE);
        CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, inflight_before);
        xqc_engine_destroy(conn->engine);
    }
}


void
xqc_test_send_ctl_persistent_congestion_recycled_probe(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_send_queue_t *sq = conn->conn_send_queue;
    uint32_t inflight_before = send_ctl->ctl_bytes_in_flight;
    xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(
        xqc_test_send_ctl_seed_lost_packet(conn, 1, 1000000));

    /* Rebinding probes are recorded directly, then recycled by the sender. */
    xqc_packet_out_t *probe = xqc_packet_out_get_and_insert_send(sq,
        XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT_PTR_NOT_NULL_FATAL(probe);
    probe->po_pkt.pkt_num = 2;
    probe->po_path_id = send_ctl->ctl_path->path_id;
    probe->po_sent_time = 1100000;
    probe->po_frame_types = XQC_FRAME_BIT_PATH_CHALLENGE;
    xqc_send_ctl_pc_on_sent(send_ctl, probe);
    xqc_send_queue_remove_send(&probe->po_list);
    xqc_send_queue_insert_free(probe, &sq->sndq_free_packets, sq);
    xqc_test_send_ctl_ack(conn, XQC_PNS_APP_DATA, 2,
                          XQC_MAX_UINT64_VALUE, 1150000);

    CU_ASSERT_PTR_NOT_NULL_FATAL(
        xqc_test_send_ctl_seed_lost_packet(conn, 3, 1200000));
    CU_ASSERT_PTR_NOT_NULL_FATAL(
        xqc_test_send_ctl_seed_lost_packet(conn, 4, 1390000));
    xqc_test_send_ctl_ack(conn, XQC_PNS_APP_DATA, 4,
                          XQC_MAX_UINT64_VALUE, 1400000);
    xqc_test_send_ctl_assert_pc(send_ctl, XQC_FALSE);
    CU_ASSERT_EQUAL(conn->detected_loss_cnt, 2);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, inflight_before);
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_send_ctl_persistent_congestion_ack_range_limit(void)
{
    for (unsigned ranges = 63; ranges <= 65; ranges++) {
        xqc_connection_t *conn = test_engine_connect();
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        xqc_path_ctx_t *path = conn->conn_initial_path;
        xqc_send_ctl_t *send_ctl = path->path_send_ctl;
        uint32_t inflight_before = send_ctl->ctl_bytes_in_flight;
        xqc_packet_number_t largest = ranges == 65 ? 130 : 128;
        xqc_test_send_ctl_arm_pc_state(send_ctl, 10000, 2000, 8000, 0);

        CU_ASSERT_PTR_NOT_NULL_FATAL(
            xqc_test_send_ctl_seed_lost_packet(conn, 1, 1000000));
        CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_send_packet(conn,
            XQC_PNS_APP_DATA, 2, 1100000, XQC_FRAME_BIT_ACK));
        CU_ASSERT_PTR_NOT_NULL_FATAL(
            xqc_test_send_ctl_seed_lost_packet(conn, 3, 1200000));
        for (xqc_packet_number_t num = 4; num <= largest; num += 2) {
            CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_send_packet(conn,
                XQC_PNS_APP_DATA, num, 1300000 + num,
                num == largest ? XQC_FRAME_BIT_PING : XQC_FRAME_BIT_ACK));
        }

        /*
         * RFC 9000 Section 19.3.1: singleton even-numbered ACK ranges.
         * Encode largest_acked and ACK Range Count as two-byte varints;
         * zero gaps and range lengths acknowledge every other packet.
         * The 65th range acknowledges PN 2, inside the loss interval.
         */
        unsigned char wire[256] = {0x02, 0x40, 0, 0, 0x40, 0, 0};
        wire[2] = (unsigned char) largest;
        wire[5] = (unsigned char) (ranges - 1);
        size_t wire_len = 7 + 2 * (ranges - 1);
        xqc_packet_in_t packet_in = {0};
        xqc_ack_info_t ack = {0};
        packet_in.pos = wire;
        packet_in.last = wire + wire_len;
        packet_in.pi_pkt.pkt_pns = XQC_PNS_APP_DATA;
        CU_ASSERT_EQUAL_FATAL(xqc_parse_ack_frame(&packet_in, conn, &ack),
                              XQC_OK);
        CU_ASSERT_PTR_EQUAL(packet_in.pos, packet_in.last);
        CU_ASSERT_EQUAL(ack.n_ranges, ranges > 64 ? 64 : ranges);
        CU_ASSERT_EQUAL(ack.ranges[ack.n_ranges - 1].low,
                        ranges == 64 ? 2 : 4);
        CU_ASSERT_EQUAL(xqc_send_ctl_on_ack_received(send_ctl,
            xqc_get_pn_ctl(conn, path), conn->conn_send_queue, &ack, 1400000,
            XQC_FALSE), XQC_OK);
        xqc_test_send_ctl_assert_pc(send_ctl, ranges == 63);
        CU_ASSERT_EQUAL(conn->detected_loss_cnt, 2);
        CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, inflight_before);

        if (ranges >= 64) {
            /* A fresh, fully observed suffix can still establish loss. */
            CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_seed_lost_packet(
                conn, largest + 1, 1600000));
            CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_seed_lost_packet(
                conn, largest + 2, 1800000));
            CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_test_send_ctl_seed_lost_packet(
                conn, largest + 3, 1990000));
            xqc_test_send_ctl_ack(conn, XQC_PNS_APP_DATA, largest + 3,
                                  XQC_MAX_UINT64_VALUE, 2000000);
            xqc_test_send_ctl_assert_pc(send_ctl, XQC_TRUE);
            CU_ASSERT_EQUAL(conn->detected_loss_cnt, 4);
            CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, inflight_before);
        }
        xqc_engine_destroy(conn->engine);
    }
}
