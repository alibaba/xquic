/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

/*
 * Closing a path with PATH_ABANDON (draft-ietf-quic-multipath-10 Section
 * 3.3, RFC 10069 Section 3.4), on the draft-10 wire.
 */

#include "xqc_path_close_test.h"
#include <CUnit/CUnit.h>
#include <string.h>
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_timer.h"
#include "xqc_common_test.h"

/* path IDs up to this one are allowed on both sides */
#define XQC_TEST_MAX_PATH_ID    4
/* the active_connection_id_limit of the test connection ID sets */
#define XQC_TEST_CID_LIMIT      8

extern xqc_bool_t xqc_conn_should_close(xqc_connection_t *conn,
    xqc_path_ctx_t *path);

/* the PATH_ABANDON frames queued for sending */
typedef struct {
    int         count;
    /* bit n set: one names path ID n (the tests use path IDs below 64) */
    uint64_t    path_ids;
    /* the fields of the last one */
    uint64_t    path_id;
    uint64_t    error_code;
} xqc_test_abandons_t;


static xqc_connection_t *
xqc_test_path_close_conn(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    conn->enable_multipath = XQC_CONN_MP_ENABLED;
    conn->conn_settings.multipath_version = XQC_MULTIPATH_10;
    conn->local_max_path_id = XQC_TEST_MAX_PATH_ID;
    conn->remote_max_path_id = XQC_TEST_MAX_PATH_ID;
    conn->curr_max_path_id = XQC_TEST_MAX_PATH_ID;
    CU_ASSERT_FATAL(xqc_conn_add_path_cid_sets(conn, XQC_INITIAL_PATH_ID + 1,
                                               XQC_TEST_MAX_PATH_ID)
                    == XQC_OK);
    return conn;
}


/*
 * Give path_id one connection ID of each side, as MP_NEW_CONNECTION_ID
 * frames do. *scid, if given, gets ours: the peer's packets on the path
 * carry it.
 */
static void
xqc_test_path_close_add_cids(xqc_connection_t *conn, uint64_t path_id,
    xqc_cid_t *scid)
{
    xqc_cid_t ours, peers;

    xqc_memzero(&ours, sizeof(ours));
    xqc_memzero(&peers, sizeof(peers));
    ours.cid_len = XQC_DEFAULT_CID_LEN;
    peers.cid_len = XQC_DEFAULT_CID_LEN;
    memset(ours.cid_buf, 0x50 + (int) path_id, XQC_DEFAULT_CID_LEN);
    memset(peers.cid_buf, 0x60 + (int) path_id, XQC_DEFAULT_CID_LEN);

    CU_ASSERT_FATAL(xqc_cid_set_insert_cid(&conn->scid_set, &ours,
                                           XQC_CID_UNUSED, XQC_TEST_CID_LIMIT,
                                           path_id)
                    == XQC_OK);
    CU_ASSERT_FATAL(xqc_cid_set_insert_cid(&conn->dcid_set, &peers,
                                           XQC_CID_UNUSED, XQC_TEST_CID_LIMIT,
                                           path_id)
                    == XQC_OK);
    if (scid != NULL) {
        *scid = ours;
    }
}


static xqc_path_ctx_t *
xqc_test_path_close_active_path(xqc_connection_t *conn, uint64_t path_id)
{
    xqc_path_ctx_t *path;

    xqc_test_path_close_add_cids(conn, path_id, NULL);
    path = xqc_conn_create_path_inner(conn, NULL, NULL,
                                      XQC_APP_PATH_STATUS_AVAILABLE, path_id);
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);
    xqc_path_validate(path);
    CU_ASSERT_FATAL(path->path_state == XQC_PATH_STATE_ACTIVE);
    return path;
}


/* process frames received in a 1-RTT packet on path recv_path_id */
static xqc_int_t
xqc_test_path_close_recv(xqc_connection_t *conn, unsigned char *frames,
    unsigned char *end, uint64_t recv_path_id)
{
    xqc_packet_in_t packet_in;

    xqc_memzero(&packet_in, sizeof(packet_in));
    packet_in.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    packet_in.pi_path_id = recv_path_id;
    packet_in.pos = frames;
    packet_in.last = end;
    return xqc_process_frames(conn, &packet_in);
}


static xqc_int_t
xqc_test_path_close_recv_abandon(xqc_connection_t *conn, uint64_t path_id)
{
    unsigned char  frame[32];
    unsigned char *p = frame;

    p = xqc_put_varint(p, XQC_TRANS_FRAME_TYPE_MP_ABANDON);
    p = xqc_put_varint(p, path_id);
    p = xqc_put_varint(p, XQC_PATH_ABANDON_APPLICATION);
    p = xqc_put_varint(p, 0);  /* Reason Phrase Length */
    return xqc_test_path_close_recv(conn, frame, p, XQC_INITIAL_PATH_ID);
}


static xqc_bool_t
xqc_test_path_close_sets_abandoned(xqc_connection_t *conn, uint64_t path_id)
{
    xqc_cid_set_inner_t *scid_set = xqc_get_path_cid_set(&conn->scid_set,
                                                         path_id);
    xqc_cid_set_inner_t *dcid_set = xqc_get_path_cid_set(&conn->dcid_set,
                                                         path_id);

    return scid_set != NULL && scid_set->set_state == XQC_CID_SET_ABANDONED
        && dcid_set != NULL && dcid_set->set_state == XQC_CID_SET_ABANDONED;
}


/*
 * xqc_conn_close_path() as an application calls it from a callback: the
 * engine is running and does not process the connection again, which would
 * try to send 1-RTT packets that the test connection has no keys for.
 */
static xqc_int_t
xqc_test_path_close_by_app(xqc_connection_t *conn, uint64_t path_id)
{
    xqc_engine_t *engine = conn->engine;
    xqc_int_t     ret;

    engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
    ret = xqc_conn_close_path(engine, &conn->scid_set.user_scid, path_id);
    engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
    return ret;
}


static xqc_test_abandons_t
xqc_test_path_close_queued_abandons(xqc_connection_t *conn)
{
    xqc_test_abandons_t  abandons = {0};
    xqc_list_head_t     *queues[] = {
        &conn->conn_send_queue->sndq_send_packets_high_pri,
        &conn->conn_send_queue->sndq_send_packets,
    };
    xqc_list_head_t     *pos;
    xqc_packet_out_t    *po;
    xqc_packet_in_t      pi;

    for (size_t i = 0; i < sizeof(queues) / sizeof(queues[0]); i++) {
        xqc_list_for_each(pos, queues[i]) {
            po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (!(po->po_frame_types & XQC_FRAME_BIT_PATH_ABANDON)) {
                continue;
            }

            /* the writer puts it first in a packet of its own */
            xqc_memzero(&pi, sizeof(pi));
            pi.pos = po->po_payload;
            pi.last = po->po_buf + po->po_used_size;
            CU_ASSERT(xqc_parse_path_abandon_frame(&pi, &abandons.path_id,
                                                   &abandons.error_code)
                      == XQC_OK);
            CU_ASSERT_FATAL(abandons.path_id < 64);
            abandons.path_ids |= 1ULL << abandons.path_id;
            abandons.count++;
        }
    }

    return abandons;
}


/*
 * RFC 10069 Section 3.4: a PATH_ABANDON for a path ID that has no path, as
 * when the peer's PATH_CHALLENGE never arrived, is answered with PATH_ABANDON
 * too, once. A path ID above the peer's limit is named in no frame
 * (Section 4), so it gets no answer, but it stays abandoned.
 */
void
xqc_test_path_abandon_reply_without_path(void)
{
    xqc_connection_t     *conn = xqc_test_path_close_conn();
    xqc_test_abandons_t   abandons;

    CU_ASSERT(xqc_conn_find_path_by_path_id(conn, 2) == NULL);
    CU_ASSERT(xqc_test_path_close_recv_abandon(conn, 2) == XQC_OK);
    abandons = xqc_test_path_close_queued_abandons(conn);
    CU_ASSERT(abandons.count == 1);
    CU_ASSERT(abandons.path_id == 2);
    CU_ASSERT(abandons.error_code == XQC_PATH_ABANDON_NO_ERROR);
    CU_ASSERT(xqc_test_path_close_sets_abandoned(conn, 2));

    /* the peer repeats its PATH_ABANDON */
    CU_ASSERT(xqc_test_path_close_recv_abandon(conn, 2) == XQC_OK);
    CU_ASSERT(xqc_test_path_close_queued_abandons(conn).count == 1);

    conn->remote_max_path_id = XQC_TEST_MAX_PATH_ID - 1;
    CU_ASSERT(xqc_test_path_close_recv_abandon(conn, XQC_TEST_MAX_PATH_ID)
              == XQC_OK);
    CU_ASSERT(xqc_test_path_close_queued_abandons(conn).count == 1);
    CU_ASSERT(xqc_test_path_close_sets_abandoned(conn, XQC_TEST_MAX_PATH_ID));
    CU_ASSERT(conn->conn_err == 0);

    xqc_engine_destroy(conn->engine);
}


/*
 * RFC 10069 Section 4.2.1: a path that the application closes is abandoned
 * with APPLICATION_ABANDON_PATH, once. The only active path is not closed.
 */
void
xqc_test_path_abandon_code_application(void)
{
    xqc_connection_t     *conn = xqc_test_path_close_conn();
    xqc_path_ctx_t       *path = xqc_test_path_close_active_path(conn, 1);
    xqc_test_abandons_t   abandons;

    CU_ASSERT(xqc_test_path_close_by_app(conn, 1) == XQC_OK);
    CU_ASSERT(path->path_state == XQC_PATH_STATE_CLOSING);
    abandons = xqc_test_path_close_queued_abandons(conn);
    CU_ASSERT(abandons.count == 1);
    CU_ASSERT(abandons.path_id == 1);
    CU_ASSERT(abandons.error_code == XQC_PATH_ABANDON_APPLICATION);

    /* closing it again sends nothing more */
    CU_ASSERT(xqc_test_path_close_by_app(conn, 1) == XQC_OK);
    CU_ASSERT(xqc_test_path_close_queued_abandons(conn).count == 1);

    CU_ASSERT(xqc_test_path_close_by_app(conn, XQC_INITIAL_PATH_ID)
              == -XQC_EMP_NO_ACTIVE_PATH);
    CU_ASSERT(conn->conn_initial_path->path_state == XQC_PATH_STATE_ACTIVE);
    CU_ASSERT(xqc_test_path_close_queued_abandons(conn).count == 1);

    xqc_engine_destroy(conn->engine);
}


/*
 * RFC 10069 Section 3.4: the PATH_ABANDON that answers the peer's carries
 * NO_ERROR and is sent once. The peer's PATH_ABANDON for the only active
 * path closes the connection instead.
 */
void
xqc_test_path_abandon_code_reply(void)
{
    xqc_connection_t     *conn = xqc_test_path_close_conn();
    xqc_path_ctx_t       *path = xqc_test_path_close_active_path(conn, 1);
    xqc_test_abandons_t   abandons;

    CU_ASSERT(xqc_test_path_close_recv_abandon(conn, 1) == XQC_OK);
    CU_ASSERT(path->path_state == XQC_PATH_STATE_CLOSING);
    abandons = xqc_test_path_close_queued_abandons(conn);
    CU_ASSERT(abandons.count == 1);
    CU_ASSERT(abandons.path_id == 1);
    CU_ASSERT(abandons.error_code == XQC_PATH_ABANDON_NO_ERROR);

    /* the peer repeats its PATH_ABANDON */
    CU_ASSERT(xqc_test_path_close_recv_abandon(conn, 1) == XQC_OK);
    CU_ASSERT(xqc_test_path_close_queued_abandons(conn).count == 1);
    CU_ASSERT(conn->conn_state < XQC_CONN_STATE_CLOSING);

    CU_ASSERT(xqc_test_path_close_recv_abandon(conn, XQC_INITIAL_PATH_ID)
              == XQC_OK);
    CU_ASSERT(conn->conn_state >= XQC_CONN_STATE_CLOSING);
    abandons = xqc_test_path_close_queued_abandons(conn);
    CU_ASSERT((abandons.path_ids & (1ULL << XQC_INITIAL_PATH_ID)) == 0);

    xqc_engine_destroy(conn->engine);
}


/*
 * RFC 10069 Sections 3.4 and 4.2.1: a path that misses its validation
 * deadline, or whose socket fails, is abandoned with PATH_UNSTABLE_OR_POOR.
 * A socket error on the only active path closes the connection instead.
 */
void
xqc_test_path_abandon_code_broken_path(void)
{
    xqc_connection_t     *conn = xqc_test_path_close_conn();
    xqc_path_ctx_t       *validating, *active;
    xqc_timer_manager_t  *timers;
    xqc_test_abandons_t   abandons;

    xqc_test_path_close_add_cids(conn, 1, NULL);
    validating = xqc_conn_create_path_inner(conn, NULL, NULL,
                                            XQC_APP_PATH_STATUS_AVAILABLE, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(validating);
    CU_ASSERT(validating->path_state == XQC_PATH_STATE_VALIDATING);
    timers = &validating->path_send_ctl->path_timer_manager;
    CU_ASSERT_FATAL(xqc_timer_is_set(timers, XQC_TIMER_PATH_IDLE));

    xqc_timer_expire(timers, timers->timer[XQC_TIMER_PATH_IDLE].expire_time);
    abandons = xqc_test_path_close_queued_abandons(conn);
    CU_ASSERT(abandons.count == 1);
    CU_ASSERT(abandons.path_id == 1);
    CU_ASSERT(abandons.error_code == XQC_PATH_ABANDON_UNSTABLE_OR_POOR);

    active = xqc_test_path_close_active_path(conn, 2);
    CU_ASSERT(xqc_conn_should_close(conn, active) == XQC_FALSE);
    CU_ASSERT(active->path_state == XQC_PATH_STATE_CLOSING);
    abandons = xqc_test_path_close_queued_abandons(conn);
    CU_ASSERT(abandons.count == 2);
    CU_ASSERT(abandons.path_id == 2);
    CU_ASSERT(abandons.error_code == XQC_PATH_ABANDON_UNSTABLE_OR_POOR);

    CU_ASSERT(xqc_conn_should_close(conn, conn->conn_initial_path)
              == XQC_TRUE);
    CU_ASSERT(conn->conn_initial_path->path_state == XQC_PATH_STATE_ACTIVE);
    CU_ASSERT(xqc_test_path_close_queued_abandons(conn).count == 2);

    xqc_engine_destroy(conn->engine);
}
