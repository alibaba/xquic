/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

/*
 * Path status (draft-ietf-quic-multipath-10 Sections 3.2 and 7.3-7.4, RFC
 * 10069 Sections 3.3 and 4.3), on the draft-10 wire.
 */

#include "xqc_path_status_test.h"
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
#include "xqc_common_test.h"

/* path IDs up to this one are allowed on both sides */
#define XQC_TEST_MAX_PATH_ID    4
/* the active_connection_id_limit of the test connection ID sets */
#define XQC_TEST_CID_LIMIT      8

static const uint64_t xqc_test_status_frame_type[XQC_APP_PATH_STATUS_MAX] = {
    [XQC_APP_PATH_STATUS_STANDBY]   = XQC_TRANS_FRAME_TYPE_MP_STANDBY,
    [XQC_APP_PATH_STATUS_AVAILABLE] = XQC_TRANS_FRAME_TYPE_MP_AVAILABLE,
    [XQC_APP_PATH_STATUS_FROZEN]    = XQC_TRANS_FRAME_TYPE_MP_FROZEN,
};

/* the status frames queued for sending in packets of their own */
typedef struct {
    int         count;
    /* the fields of the last one */
    uint64_t    path_id;
    uint64_t    seq;
    uint64_t    status;
} xqc_test_statuses_t;


static xqc_connection_t *
xqc_test_path_status_conn(void)
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


/* a path that this side opens on path_id, still being validated */
static xqc_path_ctx_t *
xqc_test_path_status_new_path(xqc_connection_t *conn, uint64_t path_id)
{
    xqc_cid_t       ours, peers;
    xqc_path_ctx_t *path;

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

    path = xqc_conn_create_path_inner(conn, NULL, NULL,
                                      XQC_APP_PATH_STATUS_AVAILABLE, path_id);
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);
    CU_ASSERT_FATAL(path->path_state == XQC_PATH_STATE_VALIDATING);
    return path;
}


/* frames that the peer sent in a packet received on path 0 */
static xqc_int_t
xqc_test_path_status_recv_frames(xqc_connection_t *conn,
    unsigned char *frames, unsigned char *end)
{
    xqc_packet_in_t  packet_in;

    xqc_memzero(&packet_in, sizeof(packet_in));
    packet_in.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    packet_in.pi_path_id = XQC_INITIAL_PATH_ID;
    packet_in.pos = frames;
    packet_in.last = end;
    return xqc_process_frames(conn, &packet_in);
}


static xqc_int_t
xqc_test_path_status_recv(xqc_connection_t *conn, uint64_t path_id,
    uint64_t seq, xqc_app_path_status_t status)
{
    unsigned char    frame[32];
    unsigned char   *p = frame;

    p = xqc_put_varint(p, xqc_test_status_frame_type[status]);
    p = xqc_put_varint(p, path_id);
    p = xqc_put_varint(p, seq);
    return xqc_test_path_status_recv_frames(conn, frame, p);
}


static xqc_int_t
xqc_test_path_status_recv_abandon(xqc_connection_t *conn, uint64_t path_id)
{
    unsigned char    frame[32];
    unsigned char   *p = frame;

    p = xqc_put_varint(p, XQC_TRANS_FRAME_TYPE_MP_ABANDON);
    p = xqc_put_varint(p, path_id);
    p = xqc_put_varint(p, 0);  /* Error Code */
    p = xqc_put_varint(p, 0);  /* Reason Phrase Length */
    return xqc_test_path_status_recv_frames(conn, frame, p);
}


static xqc_int_t
xqc_test_path_status_mark(xqc_connection_t *conn, uint64_t path_id,
    xqc_app_path_status_t status)
{
    const xqc_cid_t *cid = &conn->scid_set.user_scid;

    switch (status) {
    case XQC_APP_PATH_STATUS_STANDBY:
        return xqc_conn_mark_path_standby(conn->engine, cid, path_id);
    case XQC_APP_PATH_STATUS_AVAILABLE:
        return xqc_conn_mark_path_available(conn->engine, cid, path_id);
    case XQC_APP_PATH_STATUS_FROZEN:
        return xqc_conn_mark_path_frozen(conn->engine, cid, path_id);
    default:
        CU_FAIL("no API marks this status");
        return -XQC_EPARAM;
    }
}


/* the status frames in packets of their own on the lists */
static xqc_test_statuses_t
xqc_test_path_status_listed(xqc_list_head_t **lists, size_t n_lists)
{
    const xqc_frame_type_bit_t status_bits = XQC_FRAME_BIT_PATH_STANDBY
                                             | XQC_FRAME_BIT_PATH_AVAILABLE
                                             | XQC_FRAME_BIT_PATH_FROZEN;
    xqc_test_statuses_t  statuses = {0};
    xqc_list_head_t     *pos;
    xqc_packet_out_t    *po;
    xqc_packet_in_t      pi;

    for (size_t i = 0; i < n_lists; i++) {
        xqc_list_for_each(pos, lists[i]) {
            po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (!(po->po_frame_types & status_bits)
                || (po->po_frame_types & XQC_FRAME_BIT_PATH_CHALLENGE))
            {
                continue;
            }

            xqc_memzero(&pi, sizeof(pi));
            pi.pos = po->po_payload;
            pi.last = po->po_buf + po->po_used_size;
            CU_ASSERT(xqc_parse_path_status_frame(&pi, &statuses.path_id,
                                                  &statuses.seq,
                                                  &statuses.status)
                      == XQC_OK);
            statuses.count++;
        }
    }

    return statuses;
}


static xqc_test_statuses_t
xqc_test_path_status_queued(xqc_connection_t *conn)
{
    xqc_list_head_t *queues[] = {
        &conn->conn_send_queue->sndq_send_packets_high_pri,
        &conn->conn_send_queue->sndq_send_packets,
    };

    return xqc_test_path_status_listed(queues,
                                       sizeof(queues) / sizeof(queues[0]));
}


/*
 * RFC 10069 Section 4.3: a status frame is ignored only if one with an equal
 * or higher Path Status Sequence Number was received before for the path
 * ID. The peer may number its first one 0, and each path ID has its own
 * sequence.
 */
void
xqc_test_path_status_first_seq_zero(void)
{
    xqc_connection_t  *conn = xqc_test_path_status_conn();
    xqc_path_ctx_t    *path0 = conn->conn_initial_path;
    xqc_path_ctx_t    *path1 = xqc_test_path_status_new_path(conn, 1);

    xqc_path_validate(path1);

    CU_ASSERT(xqc_test_path_status_recv(conn, 0, 0,
                                        XQC_APP_PATH_STATUS_STANDBY)
              == XQC_OK);
    CU_ASSERT(path0->peer_status.status == XQC_APP_PATH_STATUS_STANDBY);
    CU_ASSERT(path0->app_path_status == XQC_APP_PATH_STATUS_STANDBY);

    /* the same number again, then an older one: both ignored */
    CU_ASSERT(xqc_test_path_status_recv(conn, 0, 0,
                                        XQC_APP_PATH_STATUS_AVAILABLE)
              == XQC_OK);
    CU_ASSERT(path0->app_path_status == XQC_APP_PATH_STATUS_STANDBY);
    CU_ASSERT(xqc_test_path_status_recv(conn, 0, 5,
                                        XQC_APP_PATH_STATUS_AVAILABLE)
              == XQC_OK);
    CU_ASSERT(path0->app_path_status == XQC_APP_PATH_STATUS_AVAILABLE);
    CU_ASSERT(xqc_test_path_status_recv(conn, 0, 3,
                                        XQC_APP_PATH_STATUS_STANDBY)
              == XQC_OK);
    CU_ASSERT(path0->app_path_status == XQC_APP_PATH_STATUS_AVAILABLE);
    CU_ASSERT(path0->peer_status.largest_seq == 5);

    /* path ID 1 counts on its own */
    CU_ASSERT(xqc_test_path_status_recv(conn, 1, 0,
                                        XQC_APP_PATH_STATUS_STANDBY)
              == XQC_OK);
    CU_ASSERT(path1->app_path_status == XQC_APP_PATH_STATUS_STANDBY);
    CU_ASSERT(path0->app_path_status == XQC_APP_PATH_STATUS_AVAILABLE);
    CU_ASSERT(conn->conn_err == 0);

    xqc_engine_destroy(conn->engine);
}


/*
 * The queued status packets go out on the path, one after the other, long
 * ago: they are in flight, unacknowledged.
 */
static void
xqc_test_path_status_send_queued(xqc_connection_t *conn, xqc_path_ctx_t *path,
    xqc_packet_number_t *pkt_num)
{
    xqc_send_queue_t    *send_queue = conn->conn_send_queue;
    xqc_list_head_t     *pos, *next;
    xqc_packet_out_t    *po;

    xqc_list_for_each_safe(pos, next,
                           &send_queue->sndq_send_packets_high_pri)
    {
        po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (!(po->po_frame_types & XQC_FRAME_BITS_PATH_STATUS)) {
            continue;
        }

        xqc_send_queue_remove_send(&po->po_list);
        po->po_path_id = path->path_id;
        po->po_pkt.pkt_num = (*pkt_num)++;
        po->po_sent_time = 1;
        xqc_send_ctl_increase_inflight(conn, po);
        xqc_send_queue_insert_unacked(po,
            &send_queue->sndq_unacked_packets[XQC_PNS_APP_DATA], send_queue);
    }
}


/*
 * RFC 10069 Section 4.3: a lost status frame is sent again only if it has
 * the last status sent for the path. Of two status packets that were sent
 * on path 0 and are found lost, the one with the superseded status is not
 * repaired; neither is one for a path that the peer abandoned since
 * (draft-10 Section 7.2).
 */
void
xqc_test_path_status_lost_superseded(void)
{
    xqc_connection_t     *conn = xqc_test_path_status_conn();
    xqc_path_ctx_t       *path0 = conn->conn_initial_path;
    xqc_path_ctx_t       *path1 = xqc_test_path_status_new_path(conn, 1);
    xqc_send_ctl_t       *send_ctl = path0->path_send_ctl;
    xqc_list_head_t      *lost[] = {
        &conn->conn_send_queue->sndq_lost_packets,
    };
    xqc_packet_number_t   pkt_num = 1;
    xqc_test_statuses_t   repaired;

    xqc_path_validate(path1);
    CU_ASSERT(xqc_test_path_status_mark(conn, 0, XQC_APP_PATH_STATUS_STANDBY)
              == XQC_OK);
    CU_ASSERT(xqc_test_path_status_mark(conn, 0,
                                        XQC_APP_PATH_STATUS_AVAILABLE)
              == XQC_OK);
    CU_ASSERT(xqc_test_path_status_mark(conn, 1, XQC_APP_PATH_STATUS_STANDBY)
              == XQC_OK);
    CU_ASSERT(xqc_test_path_status_queued(conn).count == 3);
    xqc_test_path_status_send_queued(conn, path0, &pkt_num);
    CU_ASSERT(xqc_test_path_status_queued(conn).count == 0);

    CU_ASSERT(xqc_test_path_status_recv_abandon(conn, 1) == XQC_OK);
    CU_ASSERT(path1->path_state == XQC_PATH_STATE_CLOSING);

    /* a later packet is acknowledged: the three are lost */
    send_ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = pkt_num + 1;
    xqc_send_ctl_detect_lost(send_ctl, conn->conn_send_queue,
                             XQC_PNS_APP_DATA, xqc_monotonic_timestamp());

    repaired = xqc_test_path_status_listed(lost, 1);
    CU_ASSERT(repaired.count == 1);
    CU_ASSERT(repaired.path_id == 0);
    CU_ASSERT(repaired.seq == 2);
    CU_ASSERT(repaired.status == XQC_APP_PATH_STATUS_AVAILABLE);

    xqc_engine_destroy(conn->engine);
}


/*
 * RFC 10069 Section 3.3: each side indicates its preference independently.
 * The peer's status does not replace the one this side indicates, which is
 * sent whenever it changes; the path is used with the stricter of the two.
 */
void
xqc_test_path_status_local_and_peer_apart(void)
{
    xqc_connection_t     *conn = xqc_test_path_status_conn();
    xqc_path_ctx_t       *path = conn->conn_initial_path;
    xqc_test_statuses_t   sent;

    CU_ASSERT(xqc_test_path_status_mark(conn, 0, XQC_APP_PATH_STATUS_STANDBY)
              == XQC_OK);
    sent = xqc_test_path_status_queued(conn);
    CU_ASSERT(sent.count == 1);
    CU_ASSERT(sent.path_id == 0);
    CU_ASSERT(sent.seq == 1);
    CU_ASSERT(sent.status == XQC_APP_PATH_STATUS_STANDBY);
    CU_ASSERT(path->app_path_status == XQC_APP_PATH_STATUS_STANDBY);

    /* the peer's AVAILABLE leaves the path a standby one here */
    CU_ASSERT(xqc_test_path_status_recv(conn, 0, 1,
                                        XQC_APP_PATH_STATUS_AVAILABLE)
              == XQC_OK);
    CU_ASSERT(path->peer_status.status == XQC_APP_PATH_STATUS_AVAILABLE);
    CU_ASSERT(path->local_status.wanted == XQC_APP_PATH_STATUS_STANDBY);
    CU_ASSERT(path->app_path_status == XQC_APP_PATH_STATUS_STANDBY);

    /* the peer is told the change */
    CU_ASSERT(xqc_test_path_status_mark(conn, 0,
                                        XQC_APP_PATH_STATUS_AVAILABLE)
              == XQC_OK);
    sent = xqc_test_path_status_queued(conn);
    CU_ASSERT(sent.count == 2);
    CU_ASSERT(sent.seq == 2);
    CU_ASSERT(sent.status == XQC_APP_PATH_STATUS_AVAILABLE);
    CU_ASSERT(path->app_path_status == XQC_APP_PATH_STATUS_AVAILABLE);

    /* the peer's STANDBY is followed, and this side's is not changed */
    CU_ASSERT(xqc_test_path_status_recv(conn, 0, 2,
                                        XQC_APP_PATH_STATUS_STANDBY)
              == XQC_OK);
    CU_ASSERT(path->app_path_status == XQC_APP_PATH_STATUS_STANDBY);
    CU_ASSERT(path->local_status.wanted == XQC_APP_PATH_STATUS_AVAILABLE);
    CU_ASSERT(xqc_test_path_status_queued(conn).count == 2);

    /* marking what the peer was told already sends nothing */
    CU_ASSERT(xqc_test_path_status_mark(conn, 0,
                                        XQC_APP_PATH_STATUS_AVAILABLE)
              == XQC_OK);
    CU_ASSERT(xqc_test_path_status_queued(conn).count == 2);

    /* the only active path is not frozen */
    CU_ASSERT(xqc_test_path_status_mark(conn, 0, XQC_APP_PATH_STATUS_FROZEN)
              == -XQC_EMP_NO_ACTIVE_PATH);
    CU_ASSERT(path->local_status.wanted == XQC_APP_PATH_STATUS_AVAILABLE);
    CU_ASSERT(xqc_test_path_status_queued(conn).count == 2);

    xqc_engine_destroy(conn->engine);
}


/*
 * RFC 10069 Section 3.3: a status indicated on either side while the path
 * is validated is kept apart from the other side's and applied once the path
 * is validated, whatever the order they come in; the status this side
 * indicates is sent then. draft-10 Section 7.2: no frame names the path ID
 * of an abandoned path, so a status marked then is not sent.
 */
void
xqc_test_path_status_before_validation(void)
{
    xqc_connection_t     *conn = xqc_test_path_status_conn();
    xqc_path_ctx_t       *path1 = xqc_test_path_status_new_path(conn, 1);
    xqc_path_ctx_t       *path2 = xqc_test_path_status_new_path(conn, 2);
    xqc_test_statuses_t   sent;

    /* this side first, then the peer */
    CU_ASSERT(xqc_test_path_status_mark(conn, 1, XQC_APP_PATH_STATUS_STANDBY)
              == XQC_OK);
    CU_ASSERT(xqc_test_path_status_recv(conn, 1, 1,
                                        XQC_APP_PATH_STATUS_AVAILABLE)
              == XQC_OK);
    CU_ASSERT(xqc_test_path_status_queued(conn).count == 0);

    /* the peer first, then this side */
    CU_ASSERT(xqc_test_path_status_recv(conn, 2, 1,
                                        XQC_APP_PATH_STATUS_STANDBY)
              == XQC_OK);
    CU_ASSERT(xqc_test_path_status_mark(conn, 2,
                                        XQC_APP_PATH_STATUS_AVAILABLE)
              == XQC_OK);

    xqc_path_validate(path1);
    sent = xqc_test_path_status_queued(conn);
    CU_ASSERT(sent.count == 1);
    CU_ASSERT(sent.path_id == 1);
    CU_ASSERT(sent.seq == 1);
    CU_ASSERT(sent.status == XQC_APP_PATH_STATUS_STANDBY);
    CU_ASSERT(path1->app_path_status == XQC_APP_PATH_STATUS_STANDBY);
    CU_ASSERT(path1->peer_status.status == XQC_APP_PATH_STATUS_AVAILABLE);

    /* AVAILABLE is what the peer assumes already: nothing to send */
    xqc_path_validate(path2);
    CU_ASSERT(xqc_test_path_status_queued(conn).count == 1);
    CU_ASSERT(path2->app_path_status == XQC_APP_PATH_STATUS_STANDBY);
    CU_ASSERT(path2->local_status.wanted == XQC_APP_PATH_STATUS_AVAILABLE);

    CU_ASSERT(xqc_test_path_status_recv_abandon(conn, 2) == XQC_OK);
    CU_ASSERT(path2->path_state == XQC_PATH_STATE_CLOSING);
    CU_ASSERT(xqc_test_path_status_mark(conn, 2, XQC_APP_PATH_STATUS_STANDBY)
              == XQC_OK);
    CU_ASSERT(xqc_test_path_status_queued(conn).count == 1);

    xqc_engine_destroy(conn->engine);
}
