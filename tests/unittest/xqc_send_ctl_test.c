/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>

#include "xqc_send_ctl_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_transport_params.h"


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
