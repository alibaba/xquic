/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <stdint.h>
#include "xquic/xquic.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_client.h"
#include "src/transport/xqc_defs.h"
#include "src/transport/xqc_stream.h"
#include "xquic/xquic_typedef.h"
#include "src/common/xqc_str.h"
#include "src/common/xqc_list.h"
#include "src/congestion_control/xqc_new_reno.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_engine.h"

void
xqc_test_conn_create()
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT(engine != NULL);

    const xqc_cid_t *cid = test_cid_connect(engine);
    CU_ASSERT_NOT_EQUAL(cid, NULL);

    xqc_engine_destroy(engine);
}

/* -------------------------------------------------------------------------
 * Idle-timeout negotiation tests for issue #559.
 *
 * Coverage matrix (post-handshake unless noted):
 *   1. local=30000, remote=5000   -> 5000   (min wins)
 *   2. local=5000,  remote=30000  -> 5000   (min wins, swapped)
 *   3. local=0,     remote=30000  -> 30000  (0 means "no limit", take peer)
 *   4. local=30000, remote=0      -> 30000  (peer disabled, keep local)
 *   5. local=0,     remote=0      -> XQC_CONN_DEFAULT_IDLE_TIMEOUT (safety fallback)
 *   6. local=30000, remote=5000, pre-handshake, client -> 30000 (remote not authoritative yet)
 *   7. pre-handshake server                              -> conn_settings.init_idle_time_out
 *   8. local=10000, remote=10000  -> 10000 (equal values)
 *   9. local=UINT64_MAX, remote=1 -> 1     (no overflow in min)
 *
 * The connection object is reused across cases by mutating the relevant
 * fields directly; xqc_conn_get_idle_timeout() only reads conn_type,
 * conn_flag, conn_settings.init_idle_time_out, local_settings.max_idle_timeout
 * and remote_settings.max_idle_timeout, so this is safe.
 * ------------------------------------------------------------------------- */

static void
xqc_idle_to_set(xqc_connection_t *conn, xqc_conn_type_t role,
    xqc_msec_t local_to, xqc_msec_t remote_to,
    int handshake_done, xqc_msec_t init_to)
{
    conn->conn_type = role;
    conn->local_settings.max_idle_timeout = local_to;
    conn->remote_settings.max_idle_timeout = remote_to;
    conn->conn_settings.init_idle_time_out = init_to;

    if (handshake_done) {
        conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED;
    } else {
        conn->conn_flag &= ~XQC_CONN_FLAG_HANDSHAKE_COMPLETED;
    }
}

void
xqc_test_conn_idle_timeout()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    xqc_msec_t got;

    /* Case 1: post-handshake client, local > remote -> remote wins */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_CLIENT, 30000, 5000, 1, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 5000);

    /* Case 2: post-handshake client, local < remote -> local wins */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_CLIENT, 5000, 30000, 1, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 5000);

    /* Case 3: post-handshake client, local=0 -> take remote */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_CLIENT, 0, 30000, 1, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 30000);

    /* Case 4: post-handshake client, remote=0 -> keep local */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_CLIENT, 30000, 0, 1, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 30000);

    /* Case 5: post-handshake client, both 0 -> safety fallback to default */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_CLIENT, 0, 0, 1, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == XQC_CONN_DEFAULT_IDLE_TIMEOUT);

    /* Case 6: pre-handshake client -> stays on local, remote ignored */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_CLIENT, 30000, 5000, 0, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 30000);

    /* Case 7a: pre-handshake server with init_idle_time_out configured -> uses init */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_SERVER, 30000, 5000, 0, 7000);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 7000);

    /* Case 7b: pre-handshake server with init_idle_time_out=0 -> uses XQC_CONN_INITIAL_IDLE_TIMEOUT */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_SERVER, 30000, 5000, 0, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == XQC_CONN_INITIAL_IDLE_TIMEOUT);

    /* Case 8: post-handshake client, equal values -> that value */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_CLIENT, 10000, 10000, 1, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 10000);

    /* Case 9: post-handshake client, very large local vs tiny remote -> remote (no overflow) */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_CLIENT, (xqc_msec_t)UINT64_MAX, 1, 1, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 1);

    /* Case 10: post-handshake server, mirror of Case 1 to confirm role does
     * not affect post-handshake path */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_SERVER, 30000, 5000, 1, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 5000);

    xqc_engine_destroy(conn->engine);
}


/*
 * Regression guard for issue #681. xqc_conn_early_data_reject must
 * walk every 0-RTT-flagged stream on conn_all_streams. The pre-fix
 * loop returned XQC_OK as soon as it hit a stream already in
 * RESET_SENT / RESET_RECVD, leaving any subsequent 0-RTT streams in
 * their pre-reject state. Three streams are primed so the middle
 * one short-circuits the loop in the broken version, and the
 * assertions on the third stream catch the regression.
 */
void
xqc_test_conn_early_data_reject()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    /* The loop being exercised lives in the client branch. */
    CU_ASSERT(conn->conn_type != XQC_CONN_TYPE_SERVER);

    xqc_stream_t *s1 = xqc_create_stream_with_conn(conn, XQC_UNDEFINE_STREAM_ID,
                                                   XQC_CLI_BID, NULL, NULL);
    xqc_stream_t *s2 = xqc_create_stream_with_conn(conn, XQC_UNDEFINE_STREAM_ID,
                                                   XQC_CLI_BID, NULL, NULL);
    xqc_stream_t *s3 = xqc_create_stream_with_conn(conn, XQC_UNDEFINE_STREAM_ID,
                                                   XQC_CLI_BID, NULL, NULL);
    CU_ASSERT_FATAL(s1 != NULL && s2 != NULL && s3 != NULL);

    /*
     * Prime each stream with a non-zero send_offset / unacked_pkt so
     * the post-call zeroing is observable, and force the middle one
     * past the RESET threshold to drive the issue path.
     */
    s1->stream_flag |= XQC_STREAM_FLAG_HAS_0RTT;
    s1->stream_send_offset = 100;
    s1->stream_unacked_pkt = 2;

    s2->stream_flag |= XQC_STREAM_FLAG_HAS_0RTT;
    s2->stream_send_offset = 200;
    s2->stream_unacked_pkt = 3;
    s2->stream_state_send = XQC_SEND_STREAM_ST_RESET_SENT;

    s3->stream_flag |= XQC_STREAM_FLAG_HAS_0RTT;
    s3->stream_send_offset = 300;
    s3->stream_unacked_pkt = 4;

    xqc_int_t ret = xqc_conn_early_data_reject(conn);
    CU_ASSERT(ret == XQC_OK);

    /* Live stream: re-initialised for 1-RTT retransmission. */
    CU_ASSERT_EQUAL(s1->stream_send_offset, 0);
    CU_ASSERT_EQUAL(s1->stream_unacked_pkt, 0);
    CU_ASSERT_EQUAL(s1->stream_state_send, XQC_SEND_STREAM_ST_READY);
    CU_ASSERT_EQUAL(s1->stream_state_recv, XQC_RECV_STREAM_ST_RECV);

    /*
     * Already-reset stream: offsets cleared, terminal state preserved
     * (RFC 9000 §3.4 forbids resurrecting a reset stream), buffered
     * 0-RTT writes discarded.
     */
    CU_ASSERT_EQUAL(s2->stream_send_offset, 0);
    CU_ASSERT_EQUAL(s2->stream_unacked_pkt, 0);
    CU_ASSERT_EQUAL(s2->stream_state_send, XQC_SEND_STREAM_ST_RESET_SENT);
    CU_ASSERT(xqc_list_empty(&s2->stream_write_buff_list.write_buff_list));

    /*
     * Regression guard for issue #681: with the pre-fix early return
     * this stream would still hold offset 300 / unacked 4 / READY-send
     * untouched. The fix MUST iterate past the reset stream above.
     */
    CU_ASSERT_EQUAL(s3->stream_send_offset, 0);
    CU_ASSERT_EQUAL(s3->stream_unacked_pkt, 0);
    CU_ASSERT_EQUAL(s3->stream_state_send, XQC_SEND_STREAM_ST_READY);
    CU_ASSERT_EQUAL(s3->stream_state_recv, XQC_RECV_STREAM_ST_RECV);

    /*
     * A stream without the 0-RTT flag must not be touched by the
     * function regardless of its position in the list.
     */
    xqc_stream_t *s4 = xqc_create_stream_with_conn(conn, XQC_UNDEFINE_STREAM_ID,
                                                   XQC_CLI_BID, NULL, NULL);
    CU_ASSERT_FATAL(s4 != NULL);
    s4->stream_send_offset = 400;
    s4->stream_unacked_pkt = 5;

    ret = xqc_conn_early_data_reject(conn);
    CU_ASSERT(ret == XQC_OK);

    CU_ASSERT_EQUAL(s4->stream_send_offset, 400);
    CU_ASSERT_EQUAL(s4->stream_unacked_pkt, 5);

    xqc_destroy_stream(s1);
    xqc_destroy_stream(s2);
    xqc_destroy_stream(s3);
    xqc_destroy_stream(s4);
}
