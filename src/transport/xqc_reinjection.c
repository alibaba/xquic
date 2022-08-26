/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/transport/xqc_reinjection.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_wakeup_pq.h"
#include "src/transport/xqc_packet_out.h"

#include "src/common/xqc_common.h"
#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str_hash.h"
#include "src/common/xqc_hash.h"
#include "src/common/xqc_priority_q.h"
#include "src/common/xqc_memory_pool.h"
#include "src/common/xqc_random.h"

#include "xquic/xqc_errno.h"

xqc_bool_t
xqc_packet_can_reinject(xqc_packet_out_t *packet_out)
{
    if (!(packet_out->po_frame_types & XQC_FRAME_BIT_STREAM)) {
        return XQC_FALSE;
    }

    if (XQC_SPECIFY_PATH(packet_out->po_frame_types)) {
        return XQC_FALSE;
    }

    if (XQC_MP_PKT_REINJECTED(packet_out)) {
        return XQC_FALSE;
    }

    /* DO NOT reinject non-inflight packets (those were old copies of retx pkts) */
    if (!(packet_out->po_flag & XQC_POF_IN_FLIGHT)) {
        return XQC_FALSE;
    }

    return XQC_TRUE;
}


void
xqc_associate_packet_with_reinjection(xqc_packet_out_t *reinj_origin,
    xqc_packet_out_t *reinj_replica)
{
    if (reinj_origin) {
        reinj_origin->po_flag |= XQC_POF_REINJECTED_ORIGIN;
    }

    if (reinj_replica) {
        reinj_replica->po_flag |= XQC_POF_REINJECTED_REPLICA;
        reinj_replica->po_origin = reinj_origin->po_origin ? reinj_origin->po_origin : reinj_origin;
        reinj_replica->po_origin->po_origin_ref_cnt++;

    }
}

void
xqc_disassociate_packet_with_reinjection(xqc_packet_out_t *reinj_origin,
    xqc_packet_out_t *reinj_replica)
{
    if (reinj_origin) {
        reinj_origin->po_flag &= ~XQC_POF_REINJECTED_ORIGIN;
    }

    if (reinj_replica) {
        reinj_replica->po_flag &= ~XQC_POF_REINJECTED_REPLICA;
        if (reinj_replica->po_origin) {
            reinj_replica->po_origin->po_origin_ref_cnt--;
            reinj_replica->po_origin = NULL;
        }
    }
}


static void
xqc_packet_out_replicate(xqc_packet_out_t *dst, xqc_packet_out_t *src)
{
    unsigned char *po_buf = dst->po_buf;
    xqc_memcpy(dst, src, sizeof(xqc_packet_out_t));

    /* pointers should carefully assigned in xqc_packet_out_replicate */
    dst->po_buf = po_buf;
    xqc_memcpy(dst->po_buf, src->po_buf, src->po_used_size);
    if (src->po_ppktno) {
        dst->po_ppktno = dst->po_buf + (src->po_ppktno - src->po_buf);
    }
    if (src->po_payload) {
        dst->po_payload = dst->po_buf + (src->po_payload - src->po_buf);
    }

    dst->po_origin = NULL;
    dst->po_flag &= ~XQC_POF_IN_FLIGHT;
    dst->po_user_data = src->po_user_data;
}

ssize_t
xqc_conn_try_reinject_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    xqc_path_ctx_t *path = conn->scheduler_callback->xqc_scheduler_get_path(conn->scheduler, conn, packet_out, 1, 1);
    if (path == NULL) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|MP|REINJ|fail to schedule a path|reinject|");
        return -XQC_EMP_SCHEDULE_PATH;
    }

    xqc_send_queue_t *send_queue = conn->conn_send_queue;
    xqc_packet_out_t *po_copy = xqc_packet_out_get(send_queue);
    if (!po_copy) {
        XQC_CONN_ERR(conn, XQC_EMALLOC);
        return -XQC_EMALLOC;
    }

    xqc_packet_out_replicate(po_copy, packet_out);

    xqc_associate_packet_with_reinjection(packet_out, po_copy);
    po_copy->po_reinj_origin = packet_out;

    xqc_send_queue_insert_send(&po_copy->po_list, &send_queue->sndq_send_packets, send_queue);
    xqc_move_packet_to_scheduled_path(path, po_copy, XQC_SEND_TYPE_NORMAL);

    xqc_log(conn->log, XQC_LOG_DEBUG, "|MP|REINJ|scheduled|"
            "path:%ui|stream_id:%ui|stream_offset:%ui|"
            "pkt_type:%s|origin_pkt_path:%ui|origin_pkt_num:%ui|",
            po_copy->po_path_id, po_copy->po_stream_id, po_copy->po_stream_offset,
            xqc_frame_type_2_str(packet_out->po_frame_types),
            packet_out->po_path_id, packet_out->po_pkt.pkt_num);

    return XQC_OK;
}
