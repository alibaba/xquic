/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <xquic/xquic_typedef.h>

#include "xqc_send_ctl_test.h"
#include "xqc_common_test.h"

#include "src/common/xqc_malloc.h"
#include "src/transport/xqc_send_ctl.h"
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
 * Issue #722 regression test.
 *
 * RFC 9002 defines an in-flight packet as one that carries any frame
 * besides ACK or CONNECTION_CLOSE. Before the fix,
 * xqc_send_ctl_increase_inflight gated the bytes_in_flight accounting
 * on XQC_IS_ACK_ELICITING, which excludes PADDING, so a packet that
 * carried nothing but PADDING (PMTUD probes, Initial padding, anti-
 * amplification fill) never reached the counter. The decrement path
 * was symmetrically wrong, so the per-packet XQC_POF_IN_FLIGHT flag
 * never flipped and the counters merely stayed balanced -- always
 * understated. After the fix bytes_in_flight follows
 * XQC_CAN_IN_FLIGHT, while bytes_ack_eliciting_inflight remains
 * gated on XQC_IS_ACK_ELICITING.
 *
 * We construct minimal xqc_packet_out_t objects on the stack and
 * drive the two counters directly; the goal is to lock the
 * branching logic, not to exercise the surrounding scheduler.
 */
static void
xqc_test_inflight_init_packet(xqc_packet_out_t *po, uint64_t types,
    uint64_t path_id)
{
    memset(po, 0, sizeof(*po));
    po->po_frame_types  = types;
    po->po_used_size    = 1200;
    po->po_path_id      = path_id;
    po->po_pkt.pkt_pns  = XQC_PNS_APP_DATA;
}

void
xqc_test_send_ctl_inflight_padding(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_initial_path != NULL);

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl != NULL);

    uint64_t path_id = conn->conn_initial_path->path_id;

    /* Baseline */
    send_ctl->ctl_bytes_in_flight = 0;
    send_ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_APP_DATA] = 0;

    /* Case 1: pure PADDING packet must enter bytes_in_flight but
     * leave bytes_ack_eliciting_inflight untouched. */
    xqc_packet_out_t padding_only;
    xqc_test_inflight_init_packet(&padding_only,
                                  XQC_FRAME_BIT_PADDING, path_id);
    xqc_send_ctl_increase_inflight(conn, &padding_only);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, 1200);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_APP_DATA], 0);
    CU_ASSERT((padding_only.po_flag & XQC_POF_IN_FLIGHT) != 0);

    /* Case 2: pure ACK packet must NOT be counted (XQC_CAN_IN_FLIGHT
     * excludes ACK). */
    xqc_packet_out_t ack_only;
    xqc_test_inflight_init_packet(&ack_only,
                                  XQC_FRAME_BIT_ACK, path_id);
    xqc_send_ctl_increase_inflight(conn, &ack_only);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, 1200);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_APP_DATA], 0);
    CU_ASSERT((ack_only.po_flag & XQC_POF_IN_FLIGHT) == 0);

    /* Case 3: pure CONNECTION_CLOSE must NOT be counted. */
    xqc_packet_out_t cc_only;
    xqc_test_inflight_init_packet(&cc_only,
                                  XQC_FRAME_BIT_CONNECTION_CLOSE, path_id);
    xqc_send_ctl_increase_inflight(conn, &cc_only);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, 1200);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_APP_DATA], 0);

    /* Case 4: STREAM packet bumps both counters (ack-eliciting). */
    xqc_packet_out_t stream_pkt;
    xqc_test_inflight_init_packet(&stream_pkt,
                                  XQC_FRAME_BIT_STREAM, path_id);
    xqc_send_ctl_increase_inflight(conn, &stream_pkt);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, 2400);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_APP_DATA], 1200);

    /* Case 5: PADDING + ACK in the same packet -- PADDING keeps
     * XQC_CAN_IN_FLIGHT true so bytes_in_flight increases, but the
     * packet is not ack-eliciting (PADDING and ACK are both in the
     * XQC_IS_ACK_ELICITING exclusion list). */
    xqc_packet_out_t padding_plus_ack;
    xqc_test_inflight_init_packet(&padding_plus_ack,
                                  XQC_FRAME_BIT_PADDING | XQC_FRAME_BIT_ACK,
                                  path_id);
    xqc_send_ctl_increase_inflight(conn, &padding_plus_ack);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, 3600);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_APP_DATA], 1200);

    /* Case 6: a second increase_inflight on the same packet is a
     * no-op -- the XQC_POF_IN_FLIGHT flag must guard against double
     * counting. */
    xqc_send_ctl_increase_inflight(conn, &padding_only);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, 3600);

    /* Case 7: decrease_inflight on the PADDING-only packet must
     * subtract from bytes_in_flight without touching the
     * ack_eliciting counter -- symmetric with case 1. */
    xqc_send_ctl_decrease_inflight(conn, &padding_only);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, 2400);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_APP_DATA], 1200);
    CU_ASSERT((padding_only.po_flag & XQC_POF_IN_FLIGHT) == 0);

    /* Case 8: decrease the PADDING+ACK packet -- bytes_in_flight only. */
    xqc_send_ctl_decrease_inflight(conn, &padding_plus_ack);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, 1200);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_APP_DATA], 1200);

    /* Case 9: decrease the STREAM packet -- both counters go back to zero. */
    xqc_send_ctl_decrease_inflight(conn, &stream_pkt);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, 0);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_APP_DATA], 0);

    /* Case 10: a second decrease on the same packet must not
     * underflow either counter. xqc_uint32_bounded_subtract clamps
     * at zero but the XQC_POF_IN_FLIGHT guard should short-circuit
     * the call first. */
    xqc_send_ctl_decrease_inflight(conn, &stream_pkt);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_in_flight, 0);
    CU_ASSERT_EQUAL(send_ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_APP_DATA], 0);

    xqc_engine_destroy(conn->engine);
}
