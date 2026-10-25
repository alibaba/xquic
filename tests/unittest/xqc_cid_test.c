/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_cid_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_utils.h"

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
 * Helper: snapshot the current "countable" CID count of cid_set on the
 * initial path.  Per RFC 9000 §5.1.1, handshake (original) CIDs are excluded
 * from the active_connection_id_limit.  This helper returns the count that
 * is actually compared against the limit, i.e. (UNUSED + USED - original).
 */
static uint64_t
xqc_test_cid_active_count(xqc_cid_set_t *cid_set)
{
    int64_t unused = xqc_cid_set_get_unused_cnt(cid_set, XQC_INITIAL_PATH_ID);
    int64_t used   = xqc_cid_set_get_used_cnt(cid_set, XQC_INITIAL_PATH_ID);
    xqc_cid_set_inner_t *inner = xqc_get_path_cid_set(cid_set, XQC_INITIAL_PATH_ID);
    uint64_t original = inner ? inner->original_cid_cnt : 0;
    if (unused < 0) {
        unused = 0;
    }
    if (used < 0) {
        used = 0;
    }
    uint64_t active = (uint64_t)(unused + used);
    return (active > original) ? (active - original) : 0;
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

/*
 * Issue #820 — RFC 9000 §18.2: active_connection_id_limit is "the maximum
 * number of connection IDs from the peer that an endpoint is willing to store.
 * This value includes the connection ID received during the handshake."
 *
 * Only the client's self-generated initial DCID is NOT from the peer and is
 * excluded from the count (original_cid_cnt = 1).  The server's SCID from
 * the Initial response IS from the peer and must count toward the limit.
 * The initial SCID (in scid_set) IS sent to the peer during the handshake
 * and must also count toward the peer's limit.
 *
 * Reproduces the nginx interop scenario: with active_connection_id_limit = 8,
 * the dcid_set has 1 self-generated CID (excluded) + 1 peer handshake CID
 * (counted) = countable 1.  So 7 more NEW_CONNECTION_IDs can be accepted
 * (1 + 7 = 8 == limit), and the 8th is rejected.
 */
void
xqc_test_cid_handshake_exclusion()
{
    xqc_int_t           ret;
    xqc_connection_t   *conn;
    uint64_t            i;

    conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    /*
     * After test_engine_connect, dcid_set has 1 USED CID (the client's
     * self-generated initial DCID), marked as original.  original_cid_cnt
     * = 1, so countable = (unused + used) - 1.
     *
     * scid_set also has 1 USED CID (the initial SCID), but it is NOT
     * marked as original — it IS sent to the peer during the handshake
     * and counts toward remote_settings.active_connection_id_limit.
     */

    /* verify scid_set: initial SCID is NOT original (sent to peer, counts toward limit) */
    {
        xqc_cid_set_inner_t *s = xqc_get_path_cid_set(&conn->scid_set,
                                                       XQC_INITIAL_PATH_ID);
        CU_ASSERT_FATAL(s != NULL);
        CU_ASSERT(s->original_cid_cnt == 0);
    }

    /*
     * Simulate the server SCID arrival (peer handshake CID).
     * Unlike the client's self-generated DCID, this CID IS from the
     * peer and must NOT be marked as original — it counts toward the
     * limit per RFC 9000 §18.2.
     */
    xqc_cid_t server_scid;
    ret = xqc_generate_cid(conn->engine, NULL, &server_scid, 0);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_cid_set_insert_cid(&conn->dcid_set, &server_scid, XQC_CID_USED,
                                 conn->local_settings.active_connection_id_limit,
                                 XQC_INITIAL_PATH_ID);
    CU_ASSERT(ret == XQC_OK);
    /* Do NOT mark server_scid as original — it is from the peer */

    /* verify: 2 used CIDs total, but only 1 original (self-generated) */
    CU_ASSERT(xqc_cid_set_get_used_cnt(&conn->dcid_set, XQC_INITIAL_PATH_ID) == 2);
    CU_ASSERT(xqc_cid_set_get_unused_cnt(&conn->dcid_set, XQC_INITIAL_PATH_ID) == 0);
    {
        xqc_cid_set_inner_t *s = xqc_get_path_cid_set(&conn->dcid_set,
                                                       XQC_INITIAL_PATH_ID);
        CU_ASSERT_FATAL(s != NULL);
        CU_ASSERT(s->original_cid_cnt == 1);  /* only client's self-generated */
    }

    /*
     * Per RFC 9000 §18.2, active_connection_id_limit = 8 applies to
     * peer-supplied CIDs.  Currently countable = (0 + 2) - 1 = 1
     * (1 self-generated excluded, 1 peer handshake included).
     * So (8 - 1) = 7 more NEW_CONNECTION_IDs can be accepted.
     */
    uint64_t limit = conn->local_settings.active_connection_id_limit;  /* 8 */
    CU_ASSERT(limit == 8);

    /* 7 NEW_CONNECTION_IDs fill the remaining slots: countable = 1 + 7 = 8 */
    for (i = 1; i <= 7; i++) {
        ret = xqc_test_cid_insert_one(conn, &conn->dcid_set,
                                      XQC_CID_UNUSED, limit, 100 + i);
        CU_ASSERT(ret == XQC_OK);
    }

    /* 8th is rejected: countable = 1 (peer handshake) + 7 (NCID) = 8 >= 8 */
    ret = xqc_test_cid_insert_one(conn, &conn->dcid_set,
                                  XQC_CID_UNUSED, limit, 108);
    CU_ASSERT(ret == -XQC_EACTIVE_CID_LIMIT);

    /*
     * Verify that retiring the self-generated CID does NOT free a slot
     * (it was already excluded from the count).
     */
    xqc_cid_inner_t *orig = xqc_cid_in_cid_set(&conn->dcid_set,
                                                &conn->dcid_set.current_dcid,
                                                XQC_INITIAL_PATH_ID);
    /* if not found via current_dcid, find the original directly */
    if (orig == NULL) {
        /* fallback: find any original CID */
        xqc_list_head_t *pos;
        xqc_cid_set_inner_t *inner_set = xqc_get_path_cid_set(&conn->dcid_set,
                                                               XQC_INITIAL_PATH_ID);
        xqc_list_for_each(pos, &inner_set->cid_list) {
            xqc_cid_inner_t *tmp = xqc_list_entry(pos, xqc_cid_inner_t, list);
            if (tmp->is_original) {
                orig = tmp;
                break;
            }
        }
    }
    CU_ASSERT_FATAL(orig != NULL);
    ret = xqc_cid_switch_to_next_state(&conn->dcid_set, orig,
                                       XQC_CID_RETIRED, XQC_INITIAL_PATH_ID);
    CU_ASSERT(ret == XQC_OK);

    /* original_cid_cnt decreased, but countable unchanged since it was
     * already excluded.  Still at limit. */
    ret = xqc_test_cid_insert_one(conn, &conn->dcid_set,
                                  XQC_CID_UNUSED, limit, 109);
    CU_ASSERT(ret == -XQC_EACTIVE_CID_LIMIT);

    /* retire a peer NCID CID to free a slot */
    xqc_cid_inner_t *ncid = xqc_get_inner_cid_by_seq(&conn->dcid_set, 101,
                                                      XQC_INITIAL_PATH_ID);
    CU_ASSERT_FATAL(ncid != NULL);
    ret = xqc_cid_switch_to_next_state(&conn->dcid_set, ncid,
                                       XQC_CID_RETIRED, XQC_INITIAL_PATH_ID);
    CU_ASSERT(ret == XQC_OK);

    /* countable = (1 peer handshake + 6 NCID) - 0 original = 7 < 8, succeeds */
    ret = xqc_test_cid_insert_one(conn, &conn->dcid_set,
                                  XQC_CID_UNUSED, limit, 110);
    CU_ASSERT(ret == XQC_OK);

    xqc_engine_destroy(conn->engine);
}

/*
 * Test mark_original idempotency: calling xqc_cid_set_mark_original twice
 * on the same CID must not inflate original_cid_cnt.
 */
void
xqc_test_cid_mark_original_idempotent()
{
    xqc_int_t         ret;
    xqc_connection_t *conn;

    conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    /* test_engine_connect already marks initial DCID as original (cnt=1) */
    xqc_cid_set_inner_t *inner_set = xqc_get_path_cid_set(&conn->dcid_set,
                                                           XQC_INITIAL_PATH_ID);
    CU_ASSERT_FATAL(inner_set != NULL);
    uint64_t cnt_before = inner_set->original_cid_cnt;

    /* call mark_original again on the same CID — must be a no-op */
    xqc_cid_set_mark_original(&conn->dcid_set,
                              &conn->dcid_set.current_dcid,
                              XQC_INITIAL_PATH_ID);
    CU_ASSERT(inner_set->original_cid_cnt == cnt_before);

    /* call a third time for good measure */
    xqc_cid_set_mark_original(&conn->dcid_set,
                              &conn->dcid_set.current_dcid,
                              XQC_INITIAL_PATH_ID);
    CU_ASSERT(inner_set->original_cid_cnt == cnt_before);

    xqc_engine_destroy(conn->engine);
}

/*
 * Test that xqc_cid_set_delete_cid correctly decrements original_cid_cnt
 * when an original CID is deleted (rather than state-transitioned).
 */
void
xqc_test_cid_delete_original()
{
    xqc_int_t         ret;
    xqc_connection_t *conn;

    conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    /* insert a new CID and mark it as original */
    xqc_cid_t extra_cid;
    ret = xqc_generate_cid(conn->engine, NULL, &extra_cid, 0);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_cid_set_insert_cid(&conn->dcid_set, &extra_cid, XQC_CID_USED,
                                 conn->local_settings.active_connection_id_limit,
                                 XQC_INITIAL_PATH_ID);
    CU_ASSERT(ret == XQC_OK);
    xqc_cid_set_mark_original(&conn->dcid_set, &extra_cid, XQC_INITIAL_PATH_ID);

    xqc_cid_set_inner_t *inner_set = xqc_get_path_cid_set(&conn->dcid_set,
                                                           XQC_INITIAL_PATH_ID);
    CU_ASSERT_FATAL(inner_set != NULL);
    uint64_t cnt_before = inner_set->original_cid_cnt;
    CU_ASSERT(cnt_before >= 2);

    /* delete the extra original CID — original_cid_cnt must decrease */
    ret = xqc_cid_set_delete_cid(&conn->dcid_set, &extra_cid,
                                 XQC_INITIAL_PATH_ID);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(inner_set->original_cid_cnt == cnt_before - 1);

    /* delete a non-original CID — original_cid_cnt must NOT change */
    xqc_cid_t normal_cid;
    ret = xqc_generate_cid(conn->engine, NULL, &normal_cid, 200);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_cid_set_insert_cid(&conn->dcid_set, &normal_cid, XQC_CID_UNUSED,
                                 conn->local_settings.active_connection_id_limit,
                                 XQC_INITIAL_PATH_ID);
    CU_ASSERT(ret == XQC_OK);

    uint64_t cnt_after_insert = inner_set->original_cid_cnt;
    ret = xqc_cid_set_delete_cid(&conn->dcid_set, &normal_cid,
                                 XQC_INITIAL_PATH_ID);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(inner_set->original_cid_cnt == cnt_after_insert);

    xqc_engine_destroy(conn->engine);
}


static xqc_engine_t *
xqc_test_create_hash_engine(void)
{
    xqc_engine_t *engine = test_create_engine();

    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    return engine;
}


void
xqc_test_conns_hash_remove_owned_entry()
{
    xqc_engine_t      *engine = xqc_test_create_hash_engine();
    xqc_connection_t   conn_a;
    xqc_connection_t   conn_b;
    unsigned char      cid[] = {0x43, 0x49, 0x44, 0x2d,
                                0x6f, 0x77, 0x6e, 0x65};

    if (engine == NULL) {
        return;
    }

    xqc_memzero(&conn_a, sizeof(conn_a));
    xqc_memzero(&conn_b, sizeof(conn_b));
    conn_a.log = engine->log;
    conn_b.log = engine->log;

    CU_ASSERT(xqc_insert_conns_hash(engine->conns_hash_dcid, &conn_a,
                                    cid, sizeof(cid)) == XQC_OK);
    CU_ASSERT(xqc_insert_conns_hash(engine->conns_hash_dcid, &conn_b,
                                    cid, sizeof(cid)) == XQC_OK);
    CU_ASSERT(xqc_find_conns_hash(engine->conns_hash_dcid, &conn_a,
                                  cid, sizeof(cid)) == &conn_b);

    CU_ASSERT(xqc_remove_conns_hash(engine->conns_hash_dcid, &conn_a,
                                    cid, sizeof(cid)) == XQC_OK);
    CU_ASSERT(xqc_find_conns_hash(engine->conns_hash_dcid, &conn_b,
                                  cid, sizeof(cid)) == &conn_b);

    CU_ASSERT(xqc_remove_conns_hash(engine->conns_hash_dcid, &conn_b,
                                    cid, sizeof(cid)) == XQC_OK);
    CU_ASSERT(xqc_find_conns_hash(engine->conns_hash_dcid, &conn_b,
                                  cid, sizeof(cid)) == NULL);
    xqc_engine_destroy(engine);
}


void
xqc_test_conns_hash_reject_non_owner()
{
    xqc_engine_t      *engine = xqc_test_create_hash_engine();
    xqc_connection_t   conn_a;
    xqc_connection_t   conn_b;
    xqc_connection_t   conn_c;
    unsigned char      cid[] = {0x43, 0x49, 0x44, 0x2d,
                                0x6f, 0x77, 0x6e, 0x65};

    if (engine == NULL) {
        return;
    }

    xqc_memzero(&conn_a, sizeof(conn_a));
    xqc_memzero(&conn_b, sizeof(conn_b));
    xqc_memzero(&conn_c, sizeof(conn_c));
    conn_a.log = engine->log;
    conn_b.log = engine->log;
    conn_c.log = engine->log;

    CU_ASSERT(xqc_insert_conns_hash(engine->conns_hash_dcid, &conn_a,
                                    cid, sizeof(cid)) == XQC_OK);
    CU_ASSERT(xqc_insert_conns_hash(engine->conns_hash_dcid, &conn_b,
                                    cid, sizeof(cid)) == XQC_OK);
    CU_ASSERT(xqc_remove_conns_hash(engine->conns_hash_dcid, &conn_c,
                                    cid, sizeof(cid)) == -XQC_ECONN_NFOUND);
    CU_ASSERT(xqc_find_conns_hash(engine->conns_hash_dcid, &conn_c,
                                  cid, sizeof(cid)) == &conn_b);

    CU_ASSERT(xqc_remove_conns_hash(engine->conns_hash_dcid, &conn_b,
                                    cid, sizeof(cid)) == XQC_OK);
    CU_ASSERT(xqc_remove_conns_hash(engine->conns_hash_dcid, &conn_a,
                                    cid, sizeof(cid)) == XQC_OK);
    xqc_engine_destroy(engine);
}


void
xqc_test_new_conn_id_insert_failure_hash_rollback()
{
    xqc_int_t         ret;
    xqc_connection_t *conn;
    unsigned char     frame_buf[64];
    unsigned char    *p = frame_buf;
    unsigned char     cid[] = {'h', 'a', 's', 'h', 'r', 'b', '0', '1'};
    unsigned char     sr_token[XQC_STATELESS_RESET_TOKENLEN];
    xqc_cid_t         rejected_cid;
    xqc_cid_t         peer_cid;

    conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    /*
     * Insert one peer-supplied CID so the countable active number is not 0.
     * The initial DCID from test_engine_connect() is locally generated and
     * marked original, so it does not count into active_connection_id_limit.
     */
    ret = xqc_generate_cid(conn->engine, NULL, &peer_cid, 1);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_cid_set_insert_cid(&conn->dcid_set, &peer_cid, XQC_CID_USED,
                                 conn->local_settings.active_connection_id_limit,
                                 XQC_INITIAL_PATH_ID);
    CU_ASSERT(ret == XQC_OK);

    /* Clamp the limit to the current active count so the next insert fails. */
    conn->local_settings.active_connection_id_limit =
        xqc_test_cid_active_count(&conn->dcid_set);
    CU_ASSERT(conn->local_settings.active_connection_id_limit > 0);

    for (size_t i = 0; i < XQC_STATELESS_RESET_TOKENLEN; i++) {
        sr_token[i] = (unsigned char)(0xa0 + i);
    }

    memset(&rejected_cid, 0, sizeof(rejected_cid));
    rejected_cid.cid_seq_num = 8;
    rejected_cid.cid_len = sizeof(cid);
    memcpy(rejected_cid.cid_buf, cid, sizeof(cid));
    memcpy(rejected_cid.sr_token, sr_token, sizeof(sr_token));

    *p++ = 0x18;  /* NEW_CONNECTION_ID */
    *p++ = 0x08;  /* sequence number */
    *p++ = 0x00;  /* retire prior to */
    *p++ = sizeof(cid);
    memcpy(p, cid, sizeof(cid));
    p += sizeof(cid);
    memcpy(p, sr_token, sizeof(sr_token));
    p += sizeof(sr_token);

    CU_ASSERT(xqc_find_conns_hash(conn->engine->conns_hash_dcid, conn,
                                  cid, sizeof(cid)) == NULL);
    CU_ASSERT(xqc_find_conns_hash(conn->engine->conns_hash_sr_token, conn,
                                  sr_token, XQC_STATELESS_RESET_TOKENLEN) == NULL);

    xqc_packet_in_t packet_in;
    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    packet_in.pos = frame_buf;
    packet_in.last = p;

    ret = xqc_process_frames(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_CONNECTION_ID_LIMIT_ERROR);

    /* The rejected CID must not linger in dcid_set or engine hash tables. */
    CU_ASSERT(xqc_cid_in_cid_set(&conn->dcid_set, &rejected_cid,
                                 XQC_INITIAL_PATH_ID) == NULL);
    CU_ASSERT(xqc_find_conns_hash(conn->engine->conns_hash_dcid, conn,
                                  cid, sizeof(cid)) == NULL);
    CU_ASSERT(xqc_find_conns_hash(conn->engine->conns_hash_sr_token, conn,
                                  sr_token, XQC_STATELESS_RESET_TOKENLEN) == NULL);

    xqc_engine_destroy(conn->engine);
}


/*
 * Verify the two-phase retirement cleanup of an expired SCID:
 *   Phase 1 (timer N):   the expired RETIRED CID transitions to REMOVED;
 *                        the node is still physically present.
 *   Phase 2 (timer N+1): the REMOVED CID is purged from scid_set and
 *                        engine->conns_hash.
 */
void
xqc_test_retired_scid_cleanup()
{
    xqc_int_t ret;
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    ret = xqc_write_new_conn_id_frame_to_packet(conn, 0);
    CU_ASSERT(ret == XQC_OK);

    xqc_cid_inner_t *inner_cid = NULL;
    xqc_cid_t retired_cid;
    xqc_cid_set_inner_t *inner_set = xqc_get_path_cid_set(&conn->scid_set,
                                                           XQC_INITIAL_PATH_ID);
    CU_ASSERT_FATAL(inner_set != NULL);

    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &inner_set->cid_list) {
        xqc_cid_inner_t *tmp = xqc_list_entry(pos, xqc_cid_inner_t, list);
        if (tmp->state == XQC_CID_UNUSED) {
            inner_cid = tmp;
            break;
        }
    }
    CU_ASSERT_FATAL(inner_cid != NULL);
    xqc_cid_copy(&retired_cid, &inner_cid->cid);
    CU_ASSERT(xqc_find_conns_hash(conn->engine->conns_hash, conn,
                                  retired_cid.cid_buf, retired_cid.cid_len) == conn);

    ret = xqc_cid_switch_to_next_state(&conn->scid_set, inner_cid,
                                       XQC_CID_RETIRED, XQC_INITIAL_PATH_ID);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(inner_set->retired_cnt == 1);
    CU_ASSERT(xqc_cid_in_cid_set(&conn->scid_set, &retired_cid,
                                 XQC_INITIAL_PATH_ID) != NULL);

    xqc_usec_t now = xqc_monotonic_timestamp();
    inner_cid->retired_ts = now - 1;
    xqc_timer_set(&conn->conn_timer_manager, XQC_TIMER_RETIRE_CID, now - 1, 0);
    xqc_conn_timer_expire(conn, now);

    /* Phase 1: state machine marks REMOVED and decrements retired_cnt;
     * the node is still physically present in scid_set and conns_hash. */
    xqc_cid_inner_t *removed_inner = xqc_cid_in_cid_set(&conn->scid_set, &retired_cid,
                                                          XQC_INITIAL_PATH_ID);
    CU_ASSERT(removed_inner != NULL);
    CU_ASSERT(removed_inner->state == XQC_CID_REMOVED);
    CU_ASSERT(inner_set->retired_cnt == 0);
    CU_ASSERT(xqc_find_conns_hash(conn->engine->conns_hash, conn,
                                   retired_cid.cid_buf, retired_cid.cid_len) == conn);

    /* Phase 2: fire timer again; the REMOVED branch purges the node. */
    now = xqc_monotonic_timestamp();
    xqc_timer_set(&conn->conn_timer_manager, XQC_TIMER_RETIRE_CID, now - 1, 0);
    xqc_conn_timer_expire(conn, now);

    CU_ASSERT(xqc_cid_in_cid_set(&conn->scid_set, &retired_cid,
                                 XQC_INITIAL_PATH_ID) == NULL);
    CU_ASSERT(xqc_find_conns_hash(conn->engine->conns_hash, conn,
                                  retired_cid.cid_buf, retired_cid.cid_len) == NULL);
    CU_ASSERT(inner_set->retired_cnt == 0);

    xqc_engine_destroy(conn->engine);
}


/*
 * Verify the two-phase RETIRED CID cleanup:
 *   Phase 1 (timer N):   expired RETIRED CIDs are transitioned to REMOVED;
 *                         non-expired ones stay RETIRED and re-arm the timer.
 *   Phase 2 (timer N+1): REMOVED CIDs from phase 1 are physically purged
 *                         from scid_set and conns_hash.
 */
void
xqc_test_retired_scid_batch_cleanup()
{
    xqc_int_t ret;
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    /* Create two additional SCIDs so both end up UNUSED in scid_set + conns_hash.
     * Raise the remote limit first to allow multiple NEW_CONNECTION_ID frames. */
    conn->remote_settings.active_connection_id_limit = XQC_CONN_ACTIVE_CID_LIMIT;
    ret = xqc_write_new_conn_id_frame_to_packet(conn, 0);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_write_new_conn_id_frame_to_packet(conn, 0);
    CU_ASSERT(ret == XQC_OK);

    xqc_cid_set_inner_t *inner_set = xqc_get_path_cid_set(&conn->scid_set,
                                                           XQC_INITIAL_PATH_ID);
    CU_ASSERT_FATAL(inner_set != NULL);

    /* Collect the two UNUSED CIDs */
    xqc_cid_inner_t *cid1 = NULL, *cid2 = NULL;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &inner_set->cid_list) {
        xqc_cid_inner_t *tmp = xqc_list_entry(pos, xqc_cid_inner_t, list);
        if (tmp->state == XQC_CID_UNUSED) {
            if (cid1 == NULL) {
                cid1 = tmp;
            } else {
                cid2 = tmp;
                break;
            }
        }
    }
    CU_ASSERT_FATAL(cid1 != NULL);
    CU_ASSERT_FATAL(cid2 != NULL);

    xqc_cid_t scid1, scid2;
    xqc_cid_copy(&scid1, &cid1->cid);
    xqc_cid_copy(&scid2, &cid2->cid);

    /* Retire both */
    ret = xqc_cid_switch_to_next_state(&conn->scid_set, cid1,
                                       XQC_CID_RETIRED, XQC_INITIAL_PATH_ID);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_cid_switch_to_next_state(&conn->scid_set, cid2,
                                       XQC_CID_RETIRED, XQC_INITIAL_PATH_ID);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(inner_set->retired_cnt == 2);

    xqc_usec_t now = xqc_monotonic_timestamp();
    cid1->retired_ts = now - 1;                  /* already expired        */
    cid2->retired_ts = now + 10000000000ULL;     /* expires far in future  */

    /* Phase 1: timer transitions expired CIDs to REMOVED; non-expired stay RETIRED. */
    xqc_timer_set(&conn->conn_timer_manager, XQC_TIMER_RETIRE_CID, now - 1, 0);
    xqc_conn_timer_expire(conn, now);

    /* cid1 (expired): transitioned to REMOVED, still physically in scid_set and hash */
    xqc_cid_inner_t *cid1_removed = xqc_cid_in_cid_set(&conn->scid_set, &scid1,
                                                         XQC_INITIAL_PATH_ID);
    CU_ASSERT(cid1_removed != NULL);
    CU_ASSERT(cid1_removed->state == XQC_CID_REMOVED);
    CU_ASSERT(xqc_find_conns_hash(conn->engine->conns_hash, conn,
                                  scid1.cid_buf, scid1.cid_len) != NULL);

    /* cid2 (not yet expired): still RETIRED, present in both */
    CU_ASSERT(xqc_cid_in_cid_set(&conn->scid_set, &scid2, XQC_INITIAL_PATH_ID) != NULL);
    CU_ASSERT(xqc_find_conns_hash(conn->engine->conns_hash, conn,
                                  scid2.cid_buf, scid2.cid_len) != NULL);

    /* retired_cnt: cid1 decremented (now REMOVED), cid2 still RETIRED */
    CU_ASSERT(inner_set->retired_cnt == 1);

    /* Timer must be re-armed to handle cid2 when it eventually expires */
    CU_ASSERT(xqc_timer_is_set(&conn->conn_timer_manager, XQC_TIMER_RETIRE_CID));

    /* Phase 2: fire timer again; the REMOVED branch purges cid1. */
    now = xqc_monotonic_timestamp();
    xqc_timer_set(&conn->conn_timer_manager, XQC_TIMER_RETIRE_CID, now - 1, 0);
    xqc_conn_timer_expire(conn, now);

    /* cid1: now completely gone */
    CU_ASSERT(xqc_cid_in_cid_set(&conn->scid_set, &scid1, XQC_INITIAL_PATH_ID) == NULL);
    CU_ASSERT(xqc_find_conns_hash(conn->engine->conns_hash, conn,
                                  scid1.cid_buf, scid1.cid_len) == NULL);

    /* cid2: still RETIRED (not yet expired), timer still re-armed */
    CU_ASSERT(xqc_cid_in_cid_set(&conn->scid_set, &scid2, XQC_INITIAL_PATH_ID) != NULL);
    CU_ASSERT(inner_set->retired_cnt == 1);
    CU_ASSERT(xqc_timer_is_set(&conn->conn_timer_manager, XQC_TIMER_RETIRE_CID));

    xqc_engine_destroy(conn->engine);
}


/*
 * Verify the REMOVED-state safety-net branch in xqc_timer_retire_cid_timeout.
 *
 * Simulate the pre-fix scenario: a CID is driven into XQC_CID_REMOVED by the
 * old state machine path (UNUSED -> RETIRED -> REMOVED) but is NOT physically
 * freed.  When the timer fires, the REMOVED branch must purge the node from
 * both scid_set and conns_hash.
 */
void
xqc_test_removed_scid_safety_net()
{
    xqc_int_t ret;
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    ret = xqc_write_new_conn_id_frame_to_packet(conn, 0);
    CU_ASSERT(ret == XQC_OK);

    xqc_cid_set_inner_t *inner_set = xqc_get_path_cid_set(&conn->scid_set,
                                                           XQC_INITIAL_PATH_ID);
    CU_ASSERT_FATAL(inner_set != NULL);

    xqc_cid_inner_t *inner_cid = NULL;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &inner_set->cid_list) {
        xqc_cid_inner_t *tmp = xqc_list_entry(pos, xqc_cid_inner_t, list);
        if (tmp->state == XQC_CID_UNUSED) {
            inner_cid = tmp;
            break;
        }
    }
    CU_ASSERT_FATAL(inner_cid != NULL);

    xqc_cid_t removed_cid;
    xqc_cid_copy(&removed_cid, &inner_cid->cid);

    /* Reproduce old behavior: drive the CID all the way to REMOVED via the
     * state machine, but intentionally skip physical cleanup. */
    ret = xqc_cid_switch_to_next_state(&conn->scid_set, inner_cid,
                                       XQC_CID_RETIRED, XQC_INITIAL_PATH_ID);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_cid_switch_to_next_state(&conn->scid_set, inner_cid,
                                       XQC_CID_REMOVED, XQC_INITIAL_PATH_ID);
    CU_ASSERT(ret == XQC_OK);

    /* State is REMOVED; retired_cnt already decremented by state machine */
    CU_ASSERT(inner_cid->state == XQC_CID_REMOVED);
    CU_ASSERT(inner_set->retired_cnt == 0);

    /* Node is still physically present in scid_set and conns_hash (the bug) */
    CU_ASSERT(xqc_cid_in_cid_set(&conn->scid_set, &removed_cid,
                                  XQC_INITIAL_PATH_ID) != NULL);
    CU_ASSERT(xqc_find_conns_hash(conn->engine->conns_hash, conn,
                                  removed_cid.cid_buf, removed_cid.cid_len) == conn);

    /* Fire the timer; the safety-net REMOVED branch should purge it */
    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_timer_set(&conn->conn_timer_manager, XQC_TIMER_RETIRE_CID, now - 1, 0);
    xqc_conn_timer_expire(conn, now);

    /* Node must now be physically gone from both structures */
    CU_ASSERT(xqc_cid_in_cid_set(&conn->scid_set, &removed_cid,
                                  XQC_INITIAL_PATH_ID) == NULL);
    CU_ASSERT(xqc_find_conns_hash(conn->engine->conns_hash, conn,
                                  removed_cid.cid_buf, removed_cid.cid_len) == NULL);

    xqc_engine_destroy(conn->engine);
}


static xqc_bool_t
xqc_test_cid_set_listed(xqc_list_head_t *list, xqc_cid_set_inner_t *inner_set)
{
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, list) {
        if (xqc_list_entry(pos, xqc_cid_set_inner_t, next) == inner_set) {
            return XQC_TRUE;
        }
    }
    return XQC_FALSE;
}

/*
 * The CIDs of an abandoned path ID leave cid_set_list, which the lookups
 * made for every received packet search first, but stay findable: a
 * long-lived connection would otherwise compare every incoming CID against
 * the CIDs of every path it has ever closed.
 */
void
xqc_test_cid_abandoned_set_off_list(void)
{
    xqc_int_t ret;
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    xqc_cid_t cid1, cid2;
    CU_ASSERT(xqc_cid_set_add_path(&conn->scid_set, 1) == XQC_OK);
    CU_ASSERT(xqc_cid_set_add_path(&conn->scid_set, 2) == XQC_OK);
    ret = xqc_generate_cid(conn->engine, NULL, &cid1, 1);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_generate_cid(conn->engine, NULL, &cid2, 1);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_cid_set_insert_cid(&conn->scid_set, &cid1, XQC_CID_UNUSED, 8, 1) == XQC_OK);
    CU_ASSERT(xqc_cid_set_insert_cid(&conn->scid_set, &cid2, XQC_CID_UNUSED, 8, 2) == XQC_OK);
    xqc_cid_set_update_state(&conn->scid_set, 1, XQC_CID_SET_USED);
    xqc_cid_set_update_state(&conn->scid_set, 2, XQC_CID_SET_USED);

    xqc_cid_set_inner_t *set1 = xqc_get_path_cid_set(&conn->scid_set, 1);
    CU_ASSERT_FATAL(set1 != NULL);
    CU_ASSERT(xqc_test_cid_set_listed(&conn->scid_set.cid_set_list, set1));
    uint32_t used = conn->scid_set.set_cnt[XQC_CID_SET_USED];
    uint32_t abandoned = conn->scid_set.set_cnt[XQC_CID_SET_ABANDONED];

    xqc_cid_set_update_state(&conn->scid_set, 1, XQC_CID_SET_ABANDONED);

    CU_ASSERT(!xqc_test_cid_set_listed(&conn->scid_set.cid_set_list, set1));
    CU_ASSERT(set1->set_state == XQC_CID_SET_ABANDONED);
    CU_ASSERT(conn->scid_set.set_cnt[XQC_CID_SET_USED] == used - 1);
    CU_ASSERT(conn->scid_set.set_cnt[XQC_CID_SET_ABANDONED] == abandoned + 1);
    CU_ASSERT_PTR_EQUAL(xqc_get_path_cid_set(&conn->scid_set, 1), set1);

    xqc_cid_t probe = cid1;
    probe.path_id = 0;
    xqc_cid_inner_t *found = xqc_cid_set_search_cid(&conn->scid_set, &probe);
    CU_ASSERT(found != NULL);
    CU_ASSERT(probe.path_id == 1);
    CU_ASSERT(xqc_cid_in_cid_set(&conn->scid_set, &cid1, 1) != NULL);
    probe = cid2;
    CU_ASSERT(xqc_cid_set_search_cid(&conn->scid_set, &probe) != NULL);
    CU_ASSERT(probe.path_id == 2);

    xqc_engine_destroy(conn->engine);
}

/*
 * A set that leaves ABANDONED goes back to cid_set_list, where the walks
 * that look for USED or UNUSED sets find it. xqc_path_create() moves the
 * sets of the path ID it creates to USED, whatever their state.
 */
void
xqc_test_cid_abandoned_set_back_on_list(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    xqc_cid_set_t *scid_set = &conn->scid_set;
    CU_ASSERT(xqc_cid_set_add_path(scid_set, 1) == XQC_OK);
    xqc_cid_set_update_state(scid_set, 1, XQC_CID_SET_USED);

    xqc_cid_set_inner_t *set1 = xqc_get_path_cid_set(scid_set, 1);
    CU_ASSERT_FATAL(set1 != NULL);
    uint32_t used = scid_set->set_cnt[XQC_CID_SET_USED];
    uint32_t abandoned = scid_set->set_cnt[XQC_CID_SET_ABANDONED];

    xqc_cid_set_update_state(scid_set, 1, XQC_CID_SET_ABANDONED);
    CU_ASSERT(xqc_test_cid_set_listed(&scid_set->abandoned_set_list, set1));

    /* a set already ABANDONED is left where it is and counted once */
    xqc_cid_set_update_state(scid_set, 1, XQC_CID_SET_ABANDONED);
    CU_ASSERT(xqc_test_cid_set_listed(&scid_set->abandoned_set_list, set1));
    CU_ASSERT(!xqc_test_cid_set_listed(&scid_set->cid_set_list, set1));
    CU_ASSERT(scid_set->set_cnt[XQC_CID_SET_USED] == used - 1);
    CU_ASSERT(scid_set->set_cnt[XQC_CID_SET_ABANDONED] == abandoned + 1);

    xqc_cid_set_update_state(scid_set, 1, XQC_CID_SET_USED);

    CU_ASSERT(xqc_test_cid_set_listed(&scid_set->cid_set_list, set1));
    CU_ASSERT(!xqc_test_cid_set_listed(&scid_set->abandoned_set_list, set1));
    CU_ASSERT(set1->set_state == XQC_CID_SET_USED);
    CU_ASSERT(scid_set->set_cnt[XQC_CID_SET_USED] == used);
    CU_ASSERT(scid_set->set_cnt[XQC_CID_SET_ABANDONED] == abandoned);
    CU_ASSERT_PTR_EQUAL(xqc_get_path_cid_set(scid_set, 1), set1);

    xqc_engine_destroy(conn->engine);
}
