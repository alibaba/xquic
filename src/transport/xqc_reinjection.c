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

void
xqc_associate_packet_with_reinjection(xqc_packet_out_t *reinj_origin,
    xqc_packet_out_t *reinj_replica)
{
    if (reinj_origin) {
        reinj_origin->po_flag |= XQC_POF_REINJECTED_ORIGIN;
        reinj_origin->po_path_flag |= XQC_PATH_SPECIFIED_BY_REINJ;
        if (reinj_origin->po_origin) {
            reinj_origin->po_origin->po_flag |= XQC_POF_REINJECTED_ORIGIN;
            reinj_origin->po_origin->po_path_flag |= XQC_PATH_SPECIFIED_BY_REINJ;
        }
    }

    if (reinj_replica) {
        reinj_replica->po_flag |= XQC_POF_REINJECTED_REPLICA;
        reinj_replica->po_origin = reinj_origin->po_origin ? reinj_origin->po_origin : reinj_origin;
        reinj_replica->po_origin->po_origin_ref_cnt++;
        reinj_replica->po_path_flag |= XQC_PATH_SPECIFIED_BY_REINJ;
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
    dst->po_flag &= ~XQC_POF_IN_UNACK_LIST;
    dst->po_flag &= ~XQC_POF_IN_PATH_BUF_LIST;
    dst->po_user_data = src->po_user_data;
    dst->po_sched_cwnd_blk_ts = 0;
    dst->po_send_cwnd_blk_ts = 0;
    dst->po_send_pacing_blk_ts = 0;
}

xqc_int_t
xqc_conn_try_reinject_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    xqc_path_ctx_t *path = conn->scheduler_callback->xqc_scheduler_get_path(conn->scheduler, conn, packet_out, 1, 1, NULL);
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
    xqc_packet_out_remove_ack_frame(po_copy);

    /* update path_flag */
    if (po_copy->po_path_flag & XQC_PATH_SPECIFIED_BY_PTO) {
        po_copy->po_path_flag &= ~XQC_PATH_SPECIFIED_BY_PTO;
    }

    po_copy->po_flag &= ~XQC_POF_RETRANSED;
    po_copy->po_flag &= ~XQC_POF_SPURIOUS_LOSS;

    xqc_associate_packet_with_reinjection(packet_out, po_copy);

    xqc_send_queue_insert_send(po_copy, &send_queue->sndq_send_packets, send_queue);
    xqc_path_send_buffer_append(path, po_copy, &path->path_reinj_tmp_buf);

    xqc_log(conn->log, XQC_LOG_DEBUG, "|MP|REINJ|scheduled|"
            "path:%ui|stream_id:%ui|stream_offset:%ui|"
            "pkt_type:%s|origin_pkt_path:%ui|origin_pkt_num:%ui|",
            po_copy->po_path_id, po_copy->po_stream_id, po_copy->po_stream_offset,
            xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types),
            packet_out->po_path_id, packet_out->po_pkt.pkt_num);

    return XQC_OK;
}


void 
xqc_conn_reinject_unack_packets(xqc_connection_t *conn, xqc_reinjection_mode_t mode)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *packet_out;

    xqc_list_for_each_safe(pos, next, &conn->conn_send_queue->sndq_unacked_packets[XQC_PNS_APP_DATA]) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (conn->reinj_callback
            && conn->reinj_callback->xqc_reinj_ctl_can_reinject
            && conn->reinj_callback->xqc_reinj_ctl_can_reinject(conn->reinj_ctl, packet_out, mode))
        {
                    
            if (xqc_conn_try_reinject_packet(conn, packet_out) != XQC_OK) {
                continue;
            }

            xqc_log(conn->log, XQC_LOG_DEBUG, "|MP|REINJ|reinject unacked packets|"
                    "pkt_num:%ui|size:%ud|pkt_type:%s|frame:%s|mode:%d|",
                    packet_out->po_pkt.pkt_num, packet_out->po_used_size,
                    xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                    xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types),
                    mode);
        }
    }

    xqc_path_ctx_t *path;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        xqc_list_splice_tail_init(&path->path_reinj_tmp_buf,
                                  &path->path_schedule_buf[XQC_SEND_TYPE_NORMAL]);
    }
}