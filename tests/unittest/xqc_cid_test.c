/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_cid_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_send_ctl.h"

#define XQC_TEST_CID_1 "xquictestconnid1"
#define XQC_TEST_CID_2 "xquictestconnid2"

void
xqc_test_cid_basic()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_cid_t test_scid, test_dcid;

    ret = xqc_generate_cid(conn->engine, NULL, &test_scid, 1);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_cid_set_insert_cid(&conn->scid_set, &test_scid, XQC_CID_UNUSED, conn->remote_settings.active_connection_id_limit, 0);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_cid_in_cid_set(&conn->scid_set, &test_scid, 0) != NULL);

    ret = xqc_get_unused_cid(&conn->scid_set, &test_scid, 0);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_cid_set_delete_cid(&conn->scid_set, &test_scid, 0);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_cid_in_cid_set(&conn->scid_set, &test_scid, 0) == NULL);


    ret = xqc_generate_cid(conn->engine, NULL, &test_dcid, 1);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_cid_set_insert_cid(&conn->dcid_set, &test_dcid, XQC_CID_UNUSED, conn->local_settings.active_connection_id_limit, 0);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_cid_in_cid_set(&conn->dcid_set, &test_dcid, 0) != NULL);

    ret = xqc_get_unused_cid(&conn->dcid_set, &test_dcid, 0);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_cid_set_delete_cid(&conn->dcid_set, &test_dcid, 0);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_cid_in_cid_set(&conn->dcid_set, &test_dcid, 0) == NULL);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_new_cid()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_cid_t test_scid;

    /* New Conn ID */
    ret = xqc_write_new_conn_id_frame_to_packet(conn, 0);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_cid_set_get_unused_cnt(&conn->scid_set, 0) == 1);

    ret = xqc_get_unused_cid(&conn->scid_set, &test_scid, 0);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_cid_set_get_unused_cnt(&conn->scid_set, 0) == 0);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_retire_cid()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_cid_t test_dcid;

    /* Retire Conn ID */
    ret = xqc_write_retire_conn_id_frame_to_packet(conn, 0);
    CU_ASSERT(ret == -XQC_ECONN_NO_AVAIL_CID);

    ret = xqc_generate_cid(conn->engine, NULL, &test_dcid, 1);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_cid_set_insert_cid(&conn->dcid_set, &test_dcid, XQC_CID_UNUSED, conn->local_settings.active_connection_id_limit, 0);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_write_retire_conn_id_frame_to_packet(conn, 0);
    CU_ASSERT(ret == XQC_OK);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_recv_retire_cid()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_cid_t test_scid, test_dcid;

    ret = xqc_write_new_conn_id_frame_to_packet(conn, 0);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_get_unused_cid(&conn->scid_set, &test_scid, 0);
    CU_ASSERT(ret == XQC_OK);

    xqc_cid_t ori_cid;
    xqc_cid_copy(&ori_cid, &conn->scid_set.user_scid);

    /* Recv Retire_CID Frame */
    char XQC_RETIRE_CID_FRAME[] = {0x19,       /* type */
                                   0x00,       /* Sequence Number */};
    xqc_packet_in_t packet_in;
    memset(&packet_in, 0, sizeof(xqc_packet_in_t));
    packet_in.pos = XQC_RETIRE_CID_FRAME;
    packet_in.last = packet_in.pos + sizeof(XQC_RETIRE_CID_FRAME);

    ret = xqc_process_frames(conn, &packet_in);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(packet_in.pi_frame_types == XQC_FRAME_BIT_RETIRE_CONNECTION_ID);

    /* ori_scid retired */
    xqc_cid_inner_t *ori_inner_cid = xqc_cid_in_cid_set(&conn->scid_set, &ori_cid, 0);
    CU_ASSERT(ori_inner_cid != NULL);
    CU_ASSERT(ori_inner_cid->state == XQC_CID_RETIRED);

    /* user_scid updated */
    CU_ASSERT(xqc_cid_is_equal(&conn->scid_set.user_scid, &test_scid) == XQC_OK);

    /* retired timer */
    CU_ASSERT(xqc_timer_is_set(&conn->conn_timer_manager, XQC_TIMER_RETIRE_CID));

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_retire_cid_with_odcid_in_set()
{
    /*
     * interop: xquic & quic-go
     * if odcid in scid_set, and then retire user_scid, the user_scid will switch to odcid.
     * so don't insert odcid into scid_set, especially when the length of odcid is different.
     */

    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    /* generate odcid with different cid_len:20 */
    xqc_cid_t test_odcid;
    conn->engine->config->cid_len = XQC_MAX_CID_LEN;

    ret = xqc_generate_cid(conn->engine, NULL, &test_odcid, 0);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_cid_set_insert_cid(&conn->scid_set, &test_odcid, XQC_CID_USED, conn->remote_settings.active_connection_id_limit, 0);
    CU_ASSERT(ret == XQC_OK);

    /* generate new cid with default cid_len:8 */
    xqc_cid_t test_scid;
    conn->engine->config->cid_len = XQC_DEFAULT_CID_LEN;
    conn->remote_settings.active_connection_id_limit = XQC_CONN_ACTIVE_CID_LIMIT;

    ret = xqc_write_new_conn_id_frame_to_packet(conn, 0);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_get_unused_cid(&conn->scid_set, &test_scid, 0);
    CU_ASSERT(ret == XQC_OK);

    /* retire user_scid */
    char XQC_RETIRE_CID_FRAME[] = {0x19,       /* type */
                                   0x00,       /* Sequence Number */};
    xqc_packet_in_t packet_in;
    memset(&packet_in, 0, sizeof(xqc_packet_in_t));
    packet_in.pos = XQC_RETIRE_CID_FRAME;
    packet_in.last = packet_in.pos + sizeof(XQC_RETIRE_CID_FRAME);

    ret = xqc_process_frames(conn, &packet_in);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(packet_in.pi_frame_types == XQC_FRAME_BIT_RETIRE_CONNECTION_ID);

    /* user_scid updated to odcid */
    CU_ASSERT(xqc_cid_is_equal(&conn->scid_set.user_scid, &test_scid) != XQC_OK);
    CU_ASSERT(xqc_cid_is_equal(&conn->scid_set.user_scid, &test_odcid) == XQC_OK);
    /* cid_len changed */
    CU_ASSERT(conn->scid_set.user_scid.cid_len == XQC_MAX_CID_LEN);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_cid()
{
    xqc_test_cid_basic();
    xqc_test_new_cid();
    xqc_test_retire_cid();
    xqc_test_recv_retire_cid();
    xqc_test_retire_cid_with_odcid_in_set();
}

/*
 * Helper: snapshot the current active CID count (UNUSED + USED) of cid_set
 * on the initial path. test_engine_connect() pre-populates the cid_set with
 * the initial SCID/DCID needed for the handshake, so any test that wants to
 * verify "boundary at limit" must base its limit on this baseline rather
 * than assuming the set is empty.
 */
static uint64_t
xqc_test_cid_active_count(xqc_cid_set_t *cid_set)
{
    int64_t unused = xqc_cid_set_get_unused_cnt(cid_set, XQC_INITIAL_PATH_ID);
    int64_t used   = xqc_cid_set_get_used_cnt(cid_set, XQC_INITIAL_PATH_ID);
    if (unused < 0) {
        unused = 0;
    }
    if (used < 0) {
        used = 0;
    }
    return (uint64_t)(unused + used);
}

/*
 * Helper: insert one fresh UNUSED CID into cid_set with the given limit and
 * a unique seq number. Returns the value of xqc_cid_set_insert_cid (so callers
 * can assert XQC_OK or -XQC_EACTIVE_CID_LIMIT depending on the boundary case).
 */
static xqc_int_t
xqc_test_cid_insert_one(xqc_connection_t *conn, xqc_cid_set_t *cid_set,
    xqc_cid_state_t state, uint64_t limit, uint64_t seq_num)
{
    xqc_cid_t cid;
    xqc_int_t ret;

    ret = xqc_generate_cid(conn->engine, NULL, &cid, seq_num);
    if (ret != XQC_OK) {
        return ret;
    }
    return xqc_cid_set_insert_cid(cid_set, &cid, state, limit,
                                  XQC_INITIAL_PATH_ID);
}

/*
 * Issue #585 — off-by-one regression test for xqc_cid_set_insert_cid.
 *
 * RFC 9000 Section 5.1.1: "An endpoint MUST NOT provide more connection IDs
 * than the peer's active_connection_id_limit." Active count = UNUSED + USED;
 * RETIRED CIDs are no longer active.
 *
 * Coverage matrix (all cases compute "limit" relative to the baseline active
 * count produced by test_engine_connect(), so the test is robust against
 * future changes to the handshake fixture):
 *   #1 scid: count == limit-1, insert succeeds       -> XQC_OK
 *   #2 scid: count == limit,   insert MUST be denied -> -XQC_EACTIVE_CID_LIMIT
 *   #3 dcid: count == limit-1, insert succeeds       -> XQC_OK
 *   #4 dcid: count == limit,   insert MUST be denied -> -XQC_EACTIVE_CID_LIMIT
 *   #5 mixed UNUSED + USED summing to limit -> next insert denied
 *   #6 RETIRED CIDs are excluded from active count   -> insert succeeds
 *   #7 limit == baseline + 1: second insert past baseline MUST be denied
 *
 * Pre-fix behavior (count > limit) allowed (limit + 1) active CIDs, so cases
 * #2/#4/#5/#7 would incorrectly return XQC_OK. Post-fix (count >= limit), all
 * four are denied.
 */
void
xqc_test_cid_active_limit()
{
    xqc_int_t           ret;
    xqc_connection_t   *conn;

    /* ---- Cases #1 & #2: SCID side ---- */
    {
        conn = test_engine_connect();
        CU_ASSERT_FATAL(conn != NULL);

        uint64_t base  = xqc_test_cid_active_count(&conn->scid_set);
        uint64_t limit = base + 2;  /* room for exactly 2 more inserts */

        /* the (base + 1)-th insert (== limit-1 -> limit) must succeed */
        ret = xqc_test_cid_insert_one(conn, &conn->scid_set,
                                      XQC_CID_UNUSED, limit, 1001);
        CU_ASSERT(ret == XQC_OK);

        /* the (base + 2)-th insert (== limit) -- last allowed one */
        ret = xqc_test_cid_insert_one(conn, &conn->scid_set,
                                      XQC_CID_UNUSED, limit, 1002);
        CU_ASSERT(ret == XQC_OK);

        /* the (base + 3)-th insert pushes count past limit -> MUST be denied */
        ret = xqc_test_cid_insert_one(conn, &conn->scid_set,
                                      XQC_CID_UNUSED, limit, 1003);
        CU_ASSERT(ret == -XQC_EACTIVE_CID_LIMIT);

        xqc_engine_destroy(conn->engine);
    }

    /* ---- Cases #3 & #4: DCID side ---- */
    {
        conn = test_engine_connect();
        CU_ASSERT_FATAL(conn != NULL);

        uint64_t base  = xqc_test_cid_active_count(&conn->dcid_set);
        uint64_t limit = base + 2;

        ret = xqc_test_cid_insert_one(conn, &conn->dcid_set,
                                      XQC_CID_UNUSED, limit, 2001);
        CU_ASSERT(ret == XQC_OK);

        ret = xqc_test_cid_insert_one(conn, &conn->dcid_set,
                                      XQC_CID_UNUSED, limit, 2002);
        CU_ASSERT(ret == XQC_OK);

        ret = xqc_test_cid_insert_one(conn, &conn->dcid_set,
                                      XQC_CID_UNUSED, limit, 2003);
        CU_ASSERT(ret == -XQC_EACTIVE_CID_LIMIT);

        xqc_engine_destroy(conn->engine);
    }

    /* ---- Case #5: mixed UNUSED + USED summing to limit ---- */
    {
        conn = test_engine_connect();
        CU_ASSERT_FATAL(conn != NULL);

        uint64_t base  = xqc_test_cid_active_count(&conn->dcid_set);
        uint64_t limit = base + 2;

        /* one UNUSED, one USED -> total active grows by 2 -> equals limit */
        ret = xqc_test_cid_insert_one(conn, &conn->dcid_set,
                                      XQC_CID_UNUSED, limit, 3001);
        CU_ASSERT(ret == XQC_OK);

        ret = xqc_test_cid_insert_one(conn, &conn->dcid_set,
                                      XQC_CID_USED, limit, 3002);
        CU_ASSERT(ret == XQC_OK);

        /* unused_cnt + used_cnt == limit -> next insert MUST be denied */
        ret = xqc_test_cid_insert_one(conn, &conn->dcid_set,
                                      XQC_CID_UNUSED, limit, 3003);
        CU_ASSERT(ret == -XQC_EACTIVE_CID_LIMIT);

        xqc_engine_destroy(conn->engine);
    }

    /* ---- Case #6: RETIRED CIDs are excluded from the active count ---- */
    {
        conn = test_engine_connect();
        CU_ASSERT_FATAL(conn != NULL);

        uint64_t base  = xqc_test_cid_active_count(&conn->scid_set);
        uint64_t limit = base + 2;

        /* fill up to the limit with two fresh UNUSED CIDs */
        ret = xqc_test_cid_insert_one(conn, &conn->scid_set,
                                      XQC_CID_UNUSED, limit, 4001);
        CU_ASSERT(ret == XQC_OK);
        ret = xqc_test_cid_insert_one(conn, &conn->scid_set,
                                      XQC_CID_UNUSED, limit, 4002);
        CU_ASSERT(ret == XQC_OK);

        /* sanity: at limit, next insert is denied */
        ret = xqc_test_cid_insert_one(conn, &conn->scid_set,
                                      XQC_CID_UNUSED, limit, 4003);
        CU_ASSERT(ret == -XQC_EACTIVE_CID_LIMIT);

        /* retire one of our inserted UNUSED CIDs via state transition */
        xqc_cid_inner_t *inner = xqc_get_inner_cid_by_seq(&conn->scid_set, 4001,
                                                          XQC_INITIAL_PATH_ID);
        CU_ASSERT_FATAL(inner != NULL);
        ret = xqc_cid_switch_to_next_state(&conn->scid_set, inner,
                                           XQC_CID_RETIRED,
                                           XQC_INITIAL_PATH_ID);
        CU_ASSERT(ret == XQC_OK);

        /* active count drops by 1 (RETIRED is excluded) -> insert succeeds */
        ret = xqc_test_cid_insert_one(conn, &conn->scid_set,
                                      XQC_CID_UNUSED, limit, 4004);
        CU_ASSERT(ret == XQC_OK);

        xqc_engine_destroy(conn->engine);
    }

    /* ---- Case #7: tight limit (baseline + 1), second insert MUST be denied ---- */
    {
        conn = test_engine_connect();
        CU_ASSERT_FATAL(conn != NULL);

        uint64_t base  = xqc_test_cid_active_count(&conn->scid_set);
        uint64_t limit = base + 1;  /* room for exactly 1 more insert */

        ret = xqc_test_cid_insert_one(conn, &conn->scid_set,
                                      XQC_CID_UNUSED, limit, 5001);
        CU_ASSERT(ret == XQC_OK);

        ret = xqc_test_cid_insert_one(conn, &conn->scid_set,
                                      XQC_CID_UNUSED, limit, 5002);
        CU_ASSERT(ret == -XQC_EACTIVE_CID_LIMIT);

        xqc_engine_destroy(conn->engine);
    }
}