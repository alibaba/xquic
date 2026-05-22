/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <stdint.h>
#include "xquic/xquic.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_client.h"
#include "src/transport/xqc_defs.h"
#include "src/transport/xqc_timer.h"
#include "xquic/xquic_typedef.h"
#include "src/common/xqc_str.h"
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

/* -------------------------------------------------------------------------
 * Regression guard for issue #645. xqc_conn_try_to_enable_pmtud() used to
 * AND-gate the local enable_pmtud bit with conn->remote_settings.enable_pmtud,
 * which is decoded from an xquic-private transport parameter. Peers that do
 * not speak that parameter (ngtcp2, Cloudflare quiche, Google QUIC, ...)
 * leave the field at zero, which silently disabled xquic's own probing
 * against every non-xquic peer. The fix drops the peer side of the gate;
 * PMTUD is now driven solely by the local opt-in bit, matching RFC 9000
 * Section 14 (PMTUD is a sender-only concern).
 *
 * Coverage matrix (role bit is 0x1 on client, 0x2 on server):
 *   1. local=0x1, remote=0x0, client -> enabled (the #645 regression case)
 *   2. local=0x2, remote=0x0, server -> enabled (server-side mirror)
 *   3. local=0x0, remote=0x3, client -> disabled (local opt-out wins)
 *   4. local=0x2, remote=0x3, client -> disabled (cross-role bit only)
 *   5. local=0x3, remote=0x0, client -> enabled  (joint bits cover client)
 *   6. local=0x3, remote=0x0, server -> enabled  (joint bits cover server)
 *
 * The fields touched by xqc_conn_try_to_enable_pmtud are conn_type,
 * local_settings.enable_pmtud, conn->enable_pmtud, conn->enable_multipath
 * and the conn_timer_manager PMTUD_PROBING slot, so mutating those
 * directly between cases is safe.
 * ------------------------------------------------------------------------- */

static void
xqc_pmtud_case_set(xqc_connection_t *conn, xqc_conn_type_t role,
    uint64_t local_bits, uint64_t remote_bits)
{
    conn->conn_type = role;
    conn->local_settings.enable_pmtud = local_bits;
    conn->remote_settings.enable_pmtud = remote_bits;
    conn->enable_pmtud = 0;
    xqc_timer_unset(&conn->conn_timer_manager, XQC_TIMER_PMTUD_PROBING);
}

void
xqc_test_conn_pmtud_unilateral()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    /*
     * test_engine_connect() always builds a client connection, so the
     * server cases below override conn_type directly. enable_multipath
     * is left at its initialised value; the function only branches on
     * it to choose the PMTUD probing start delay.
     */

    /* Case 1: client opts in, peer silent -> PMTUD enabled. This is the
     * exact configuration that issue #645 reproduces in the wild. */
    xqc_pmtud_case_set(conn, XQC_CONN_TYPE_CLIENT, 0x1, 0x0);
    xqc_conn_try_to_enable_pmtud(conn);
    CU_ASSERT(conn->enable_pmtud == 1);

    /* Case 2: server opts in, peer silent -> PMTUD enabled. */
    xqc_pmtud_case_set(conn, XQC_CONN_TYPE_SERVER, 0x2, 0x0);
    xqc_conn_try_to_enable_pmtud(conn);
    CU_ASSERT(conn->enable_pmtud == 1);

    /* Case 3: local opt-out wins regardless of what the peer advertises. */
    xqc_pmtud_case_set(conn, XQC_CONN_TYPE_CLIENT, 0x0, 0x3);
    xqc_conn_try_to_enable_pmtud(conn);
    CU_ASSERT(conn->enable_pmtud == 0);

    /* Case 4: client looks at bit 0x1 only; the local 0x2 covers the
     * server role and must not enable PMTUD on a client. */
    xqc_pmtud_case_set(conn, XQC_CONN_TYPE_CLIENT, 0x2, 0x3);
    xqc_conn_try_to_enable_pmtud(conn);
    CU_ASSERT(conn->enable_pmtud == 0);

    /* Case 5: joint bits 0x3 cover the client role. */
    xqc_pmtud_case_set(conn, XQC_CONN_TYPE_CLIENT, 0x3, 0x0);
    xqc_conn_try_to_enable_pmtud(conn);
    CU_ASSERT(conn->enable_pmtud == 1);

    /* Case 6: joint bits 0x3 cover the server role too. */
    xqc_pmtud_case_set(conn, XQC_CONN_TYPE_SERVER, 0x3, 0x0);
    xqc_conn_try_to_enable_pmtud(conn);
    CU_ASSERT(conn->enable_pmtud == 1);

    xqc_engine_destroy(conn->engine);
}
