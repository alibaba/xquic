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
    p = xqc_put_varint(p, 0x3e);  /* APPLICATION_ABANDON_PATH */
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
    CU_ASSERT(abandons.error_code == 0);  /* NO_ERROR */
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
