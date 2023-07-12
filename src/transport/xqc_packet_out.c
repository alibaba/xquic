/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_conn.h"
#include "src/common/xqc_memory_pool.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_datagram.h"
#include "src/transport/xqc_reinjection.h"
#include "src/transport/xqc_packet_out.h"


xqc_packet_out_t *
xqc_packet_out_create(size_t po_buf_size)
{
    xqc_packet_out_t *packet_out;
    packet_out = xqc_calloc(1, sizeof(xqc_packet_out_t));
    if (!packet_out) {
        goto error;
    }

    packet_out->po_buf = xqc_malloc(XQC_PACKET_OUT_BUF_CAP);
    if (!packet_out->po_buf) {
        goto error;
    }

    packet_out->po_buf_cap = XQC_PACKET_OUT_BUF_CAP;
    packet_out->po_buf_size = po_buf_size;

    return packet_out;

error:
    if (packet_out) {
        xqc_free(packet_out->po_buf);
        xqc_free(packet_out);
    }
    return NULL;
}


 xqc_bool_t 
 xqc_packet_out_on_specific_path(xqc_connection_t *conn, 
    xqc_packet_out_t *po, xqc_path_ctx_t **path)
{
    xqc_bool_t ret = XQC_FALSE;
    if (po->po_path_flag) {
        *path = xqc_conn_find_path_by_path_id(conn, po->po_path_id);

        /* no packets can be sent on a closing/closed path */
        if ((*path == NULL) || ((*path)->path_state >= XQC_PATH_STATE_CLOSING)) {
            
            po->po_path_flag &= ~(XQC_PATH_SPECIFIED_BY_ACK | XQC_PATH_SPECIFIED_BY_PTO);

            if (po->po_path_flag & XQC_PATH_SPECIFIED_BY_REINJ) {
                if (po->po_flag & XQC_POF_REINJECTED_REPLICA) {
                    /* replicated packets should be removed */
                    xqc_disassociate_packet_with_reinjection(po->po_origin, po);

                } else {
                    /* the origin packet can be rescheduled */
                    po->po_path_flag &= ~XQC_PATH_SPECIFIED_BY_REINJ;
                } 
            }

            /* if the packet can not be rescheduled, we remove it. */
            if (po->po_path_flag) {
                xqc_send_queue_remove_send(&po->po_list);
                xqc_send_queue_insert_free(po, &conn->conn_send_queue->sndq_free_packets, conn->conn_send_queue);
                ret = XQC_TRUE;
            }
            *path = NULL;

        } else {
            ret = XQC_TRUE;
        }
    }
    return ret;
}

xqc_bool_t 
xqc_packet_out_can_attach_ack(xqc_packet_out_t *po, 
    xqc_path_ctx_t *path, xqc_pkt_type_t pkt_type)
{
    if (po->po_pkt.pkt_type != pkt_type) {
        return XQC_FALSE;
    }

    if (po->po_frame_types & (XQC_FRAME_BIT_ACK | XQC_FRAME_BIT_ACK_MP)) {
        return XQC_FALSE;
    }

    if (path->path_flag && path->path_id != po->po_path_id) {
        return XQC_FALSE;
    }

    return XQC_TRUE;
}

xqc_bool_t 
xqc_packet_out_can_pto_probe(xqc_packet_out_t *po, uint64_t path_id)
{
    if ((po->po_path_flag & (XQC_PATH_SPECIFIED_BY_PCPR | XQC_PATH_SPECIFIED_BY_REINJ | XQC_PATH_SPECIFIED_BY_PTMUD))
        && path_id != po->po_path_id)
    {
        return XQC_FALSE;
    }
    return XQC_TRUE;
}

void 
xqc_packet_out_remove_ack_frame(xqc_packet_out_t *po)
{
    if (po->po_frame_types & XQC_FRAME_BIT_ACK 
        || po->po_frame_types & XQC_FRAME_BIT_ACK_MP)
    {
        po->po_used_size = po->po_ack_offset;
        po->po_frame_types &= ~(XQC_FRAME_BIT_ACK | XQC_FRAME_BIT_ACK_MP);
        po->po_path_flag &= ~(XQC_PATH_SPECIFIED_BY_ACK);
    }
}

void
xqc_packet_out_copy(xqc_packet_out_t *dst, xqc_packet_out_t *src)
{
    unsigned char *po_buf = dst->po_buf;
    size_t cap = dst->po_buf_cap;
    unsigned int size = dst->po_buf_size;
    xqc_memcpy(dst, src, sizeof(xqc_packet_out_t));
    dst->po_origin_ref_cnt = 0;

    xqc_packet_out_t *origin = src->po_origin == NULL ? src : src->po_origin;

    /* pointers should carefully assigned in xqc_packet_out_copy */
    dst->po_buf = po_buf;
    xqc_memcpy(dst->po_buf, src->po_buf, src->po_used_size);
    if (src->po_ppktno) {
        dst->po_ppktno = dst->po_buf + (src->po_ppktno - src->po_buf);
    }
    if (src->po_payload) {
        dst->po_payload = dst->po_buf + (src->po_payload - src->po_buf);
    }
    if (src->po_padding) {
        dst->po_padding = dst->po_buf + (src->po_padding - src->po_buf);
    }
    dst->po_origin = origin;
    origin->po_origin_ref_cnt++;
    dst->po_user_data = src->po_user_data;

    dst->po_path_id = src->po_path_id;

    dst->po_flag &= ~XQC_POF_IN_UNACK_LIST;
    dst->po_flag &= ~XQC_POF_IN_PATH_BUF_LIST;
}


xqc_packet_out_t *
xqc_packet_out_get(xqc_send_queue_t *send_queue)
{
    xqc_packet_out_t *packet_out;
    unsigned int buf_size;
    size_t buf_cap;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_free_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        xqc_send_queue_remove_free(pos, send_queue);

        unsigned char *tmp = packet_out->po_buf;
        buf_size = send_queue->sndq_conn->pkt_out_size;
        buf_cap = packet_out->po_buf_cap;
        memset(packet_out, 0, sizeof(xqc_packet_out_t));
        packet_out->po_buf = tmp;
        packet_out->po_buf_size = buf_size;
        packet_out->po_buf_cap = buf_cap;
        return packet_out;
    }

    packet_out = xqc_packet_out_create(send_queue->sndq_conn->pkt_out_size);
    if (!packet_out) {
        return NULL;
    }

    return packet_out;
}

xqc_packet_out_t *
xqc_packet_out_get_and_insert_send(xqc_send_queue_t *send_queue, enum xqc_pkt_type pkt_type)
{
    xqc_packet_out_t *packet_out;
    packet_out = xqc_packet_out_get(send_queue);
    if (!packet_out) {
        return NULL;
    }

    packet_out->po_pkt.pkt_type = pkt_type;
    packet_out->po_pkt.pkt_pns = xqc_packet_type_to_pns(pkt_type);

    /* generate packet number when send */
    packet_out->po_pkt.pkt_num = 0;

    xqc_send_queue_insert_send(packet_out, &send_queue->sndq_send_packets, send_queue);

    return packet_out;
}

void
xqc_packet_out_destroy(xqc_packet_out_t *packet_out)
{
    xqc_free(packet_out->po_buf);
    xqc_free(packet_out);
}

void
xqc_maybe_recycle_packet_out(xqc_packet_out_t *packet_out, xqc_connection_t *conn)
{
    /* recycle packetout if no frame in it */
    if (packet_out->po_frame_types == 0) {
        xqc_list_del_init(&packet_out->po_list);
        xqc_send_queue_insert_free(packet_out, &conn->conn_send_queue->sndq_free_packets, conn->conn_send_queue);
    }
}

int
xqc_write_packet_header(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    if (packet_out->po_used_size > 0) {
        return XQC_OK;
    }

    int ret = XQC_OK;

    xqc_pkt_type_t pkt_type = packet_out->po_pkt.pkt_type;

    if (pkt_type == XQC_PTYPE_SHORT_HEADER && packet_out->po_used_size == 0) {
        ret = xqc_gen_short_packet_header(packet_out,
                                          conn->dcid_set.current_dcid.cid_buf, conn->dcid_set.current_dcid.cid_len,
                                          XQC_PKTNO_BITS, packet_out->po_pkt.pkt_num,
                                          conn->key_update_ctx.cur_out_key_phase);

    } else if (pkt_type != XQC_PTYPE_SHORT_HEADER && packet_out->po_used_size == 0) {
        ret = xqc_gen_long_packet_header(packet_out,
                                         conn->dcid_set.current_dcid.cid_buf, conn->dcid_set.current_dcid.cid_len,
                                         conn->scid_set.user_scid.cid_buf, conn->scid_set.user_scid.cid_len,
                                         conn->conn_token, conn->conn_token_len,
                                         conn->version, XQC_PKTNO_BITS);
    }

    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|gen header error|%d|", ret);
        return ret;
    }
    packet_out->po_used_size += ret;

    return XQC_OK;
}


xqc_packet_out_t *
xqc_write_new_packet(xqc_connection_t *conn, xqc_pkt_type_t pkt_type)
{
    int ret;
    xqc_packet_out_t *packet_out;

    if (pkt_type == XQC_PTYPE_NUM) {
        pkt_type = xqc_state_to_pkt_type(conn);
    }

    packet_out = xqc_packet_out_get_and_insert_send(conn->conn_send_queue, pkt_type);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_packet_out_get_and_insert_send error|");
        return NULL;
    }

    packet_out->po_path_id = XQC_INITIAL_PATH_ID;

    if (packet_out->po_used_size == 0) {
        ret = xqc_write_packet_header(conn, packet_out);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_packet_header error|");
            goto error;
        }
    }

    return packet_out;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return NULL;
}

xqc_packet_out_t *
xqc_write_packet(xqc_connection_t *conn, xqc_pkt_type_t pkt_type, unsigned need)
{
    int ret;
    xqc_packet_out_t *packet_out;

    if (pkt_type == XQC_PTYPE_NUM) {
        pkt_type = xqc_state_to_pkt_type(conn);
    }

    packet_out = xqc_send_queue_get_packet_out(conn->conn_send_queue, need, pkt_type);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_send_queue_get_packet_out error|");
        return NULL;
    }

    packet_out->po_path_id = XQC_INITIAL_PATH_ID;

    if (packet_out->po_used_size == 0) {
        ret = xqc_write_packet_header(conn, packet_out);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_packet_header error|");
            goto error;
        }
    }

    return packet_out;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return NULL;
}

xqc_packet_out_t *
xqc_write_packet_for_stream(xqc_connection_t *conn, xqc_pkt_type_t pkt_type, unsigned need, xqc_stream_t *stream)
{
    int ret;
    xqc_packet_out_t *packet_out;

    if (pkt_type == XQC_PTYPE_NUM) {
        pkt_type = xqc_state_to_pkt_type(conn);
    }

    packet_out = xqc_send_queue_get_packet_out_for_stream(conn->conn_send_queue, need, pkt_type, stream);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_send_queue_get_packet_out_for_stream error|");
        return NULL;
    }

    packet_out->po_path_id = XQC_INITIAL_PATH_ID;

    if (packet_out->po_used_size == 0) {
        ret = xqc_write_packet_header(conn, packet_out);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_packet_header error|");
            goto error;
        }
    }

    return packet_out;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return NULL;
}

int
xqc_write_ack_to_one_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_pkt_num_space_t pns)
{
    ssize_t ret;
    int has_gap;
    xqc_packet_number_t largest_ack;
    xqc_usec_t now = xqc_monotonic_timestamp();

    xqc_path_ctx_t *path = conn->conn_initial_path;
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, path);

    ret = xqc_gen_ack_frame(conn, packet_out, now, conn->local_settings.ack_delay_exponent,
                            &pn_ctl->ctl_recv_record[pns], path->path_send_ctl->ctl_largest_recv_time[pns],
                            &has_gap, &largest_ack);
    if (ret < 0) {
        goto error;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|ack_size:%ui|path:%ui|path_largest_recv:%ui|frame_largest_recv:%ui|", 
                ret, path->path_id, path->path_send_ctl->ctl_largest_received[pns], xqc_recv_record_largest(&pn_ctl->ctl_recv_record[pns]));

    packet_out->po_ack_offset = packet_out->po_used_size;
    packet_out->po_used_size += ret;
    packet_out->po_largest_ack = largest_ack;

    packet_out->po_path_flag = XQC_PATH_SPECIFIED_BY_ACK;
    packet_out->po_path_id = path->path_id;

    path->path_send_ctl->ctl_ack_eliciting_pkt[pns] = 0;
    if (has_gap) {
        conn->conn_flag |= XQC_CONN_FLAG_ACK_HAS_GAP;

    } else {
        conn->conn_flag &= ~XQC_CONN_FLAG_ACK_HAS_GAP;
    }
    conn->conn_flag &= ~(XQC_CONN_FLAG_SHOULD_ACK_INIT << pns);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

int
xqc_write_ack_to_packets(xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_pkt_num_space_t pns;
    xqc_packet_out_t *packet_out;
    xqc_pkt_type_t pkt_type;
    xqc_list_head_t *pos, *next;

    int ret;

    for (pns = 0; pns < XQC_PNS_N; ++pns) {
        if (!(conn->conn_flag & (XQC_CONN_FLAG_SHOULD_ACK_INIT << pns))) {
            continue;
        }

        if (pns == XQC_PNS_HSK) {
            pkt_type = XQC_PTYPE_HSK;

        } else if (pns == XQC_PNS_INIT) {
            pkt_type = XQC_PTYPE_INIT;

        } else {
            pkt_type = XQC_PTYPE_SHORT_HEADER;
        }

path_buffer:
        xqc_list_for_each_safe(pos, next, &conn->conn_initial_path->path_schedule_buf[XQC_SEND_TYPE_NORMAL]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (xqc_packet_out_can_attach_ack(packet_out, conn->conn_initial_path, pkt_type)) {
                ret = xqc_write_ack_to_one_packet(conn, packet_out, pns);
                if (ret == -XQC_ENOBUF) {
                    xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_write_ack_to_one_packet try conn buffer|");
                    goto write_new;

                } else if (ret == XQC_OK) {
                    goto done;

                } else {
                    return ret;
                }
            } 
            goto write_new;
        }

conn_buffer:
        xqc_list_for_each_safe(pos, next, &conn->conn_send_queue->sndq_send_packets) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (xqc_packet_out_can_attach_ack(packet_out, conn->conn_initial_path, pkt_type)) {
                ret = xqc_write_ack_to_one_packet(conn, packet_out, pns);
                if (ret == -XQC_ENOBUF) {
                    xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_write_ack_to_one_packet try new packet|");
                    goto write_new;

                } else if (ret == XQC_OK) {
                    goto done;

                } else {
                    return ret;
                }
            }
            goto write_new;
        }

write_new:
        packet_out = xqc_write_new_packet(conn, pkt_type);
        if (packet_out == NULL) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
            return -XQC_EWRITE_PKT;
        }

        ret = xqc_write_ack_to_one_packet(conn, packet_out, pns);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_ack_to_one_packet error|ret:%d|", ret);
            return ret;
        }

pure_ack:
        /* send ack packet first */
        xqc_send_queue_move_to_high_pri(&packet_out->po_list, conn->conn_send_queue);
done:
        xqc_log(conn->log, XQC_LOG_DEBUG, "|pns:%d|", pns);
    }
    return XQC_OK;
}

int
xqc_write_ping_to_packet(xqc_connection_t *conn, void *po_user_data, xqc_bool_t notify)
{
    ssize_t ret;
    xqc_packet_out_t *packet_out;

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_NUM);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    ret = xqc_gen_ping_frame(packet_out);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_ping_frame error|");
        goto error;
    }

    packet_out->po_user_data = po_user_data;
    packet_out->po_used_size += ret;

    /*
     * xquic supports inner PING and user PING, user PING shall be notified
     * to upper level while inner PING shall not.  if XQC_POF_NOTIFY is not set,
     * it's an inner PING, do no callback 
     */
    if (notify) {
        packet_out->po_flag |= XQC_POF_NOTIFY;
    }

    conn->conn_flag &= ~XQC_CONN_FLAG_PING;

    xqc_send_queue_move_to_high_pri(&packet_out->po_list, conn->conn_send_queue);
    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}


int
xqc_write_pmtud_ping_to_packet(xqc_path_ctx_t *path, 
    size_t probing_size, xqc_pkt_type_t pkt_type)
{
    int ret;
    xqc_packet_out_t *packet_out;
    xqc_connection_t *conn = path->parent_conn;

    packet_out = xqc_write_new_packet(conn, pkt_type);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    packet_out->po_buf_size = probing_size;
    if (packet_out->po_buf_size > packet_out->po_buf_cap
        || packet_out->po_buf_size < packet_out->po_used_size)
    {
        xqc_log(conn->log, XQC_LOG_ERROR, "|invalid PMTUD probing size|");
        ret = -XQC_EPMTUD_PROBING_SIZE;
        goto error;
    }

    ret = xqc_gen_ping_frame(packet_out);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_ping_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;
    packet_out->po_path_id = path->path_id;
    packet_out->po_path_flag |= XQC_PATH_SPECIFIED_BY_PTMUD;
    packet_out->po_flag |= XQC_POF_PMTUD_PROBING;
    packet_out->po_max_pkt_out_size = conn->max_pkt_out_size;

    xqc_send_queue_move_to_high_pri(&packet_out->po_list, conn->conn_send_queue);
    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

int
xqc_write_conn_close_to_packet(xqc_connection_t *conn, uint64_t err_code)
{
    ssize_t ret;
    xqc_packet_out_t *packet_out;
    xqc_pkt_type_t pkt_type = XQC_PTYPE_INIT;

    /* peer may not have received the handshake packet */
    if (conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED && conn->conn_flag & XQC_CONN_FLAG_HSK_ACKED) {
        pkt_type = XQC_PTYPE_SHORT_HEADER;
    }
    packet_out = xqc_write_new_packet(conn, pkt_type);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    ret = xqc_gen_conn_close_frame(packet_out, err_code, err_code >= H3_NO_ERROR ? 1:0, 0);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_conn_close_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    xqc_send_queue_move_to_high_pri(&packet_out->po_list, conn->conn_send_queue);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

int
xqc_write_reset_stream_to_packet(xqc_connection_t *conn, xqc_stream_t *stream,
    uint64_t err_code, uint64_t final_size)
{
    ssize_t ret;
    xqc_packet_out_t *packet_out;

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_NUM);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    ret = xqc_gen_reset_stream_frame(packet_out, stream->stream_id, err_code, final_size);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_reset_stream_frame error|");
        goto error;
    }
    stream->stream_err = err_code;

    packet_out->po_used_size += ret;

    /* new packet with index 0 */
    packet_out->po_stream_frames[0].ps_stream_id = stream->stream_id;
    packet_out->po_stream_frames[0].ps_is_reset = 1;
    packet_out->po_stream_frames[0].ps_is_used = 1;
    packet_out->po_stream_frames_idx++;
    if (stream->stream_state_send < XQC_SEND_STREAM_ST_RESET_SENT) {
        xqc_stream_send_state_update(stream, XQC_SEND_STREAM_ST_RESET_SENT);
    }

    if (stream->stream_stats.app_reset_time == 0) {
        stream->stream_stats.app_reset_time = xqc_monotonic_timestamp();
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|stream_id:%ui|stream_state_send:%d|", stream->stream_id, stream->stream_state_send);
    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

int
xqc_write_stop_sending_to_packet(xqc_connection_t *conn, xqc_stream_t *stream,
    uint64_t err_code)
{
    ssize_t ret;
    xqc_packet_out_t *packet_out;

    /*
     * A STOP_SENDING frame can be sent for streams in the Recv or Size
        Known states
     */
    if (stream->stream_state_recv >= XQC_RECV_STREAM_ST_DATA_RECVD) {
        xqc_log(conn->log, XQC_LOG_WARN, "|beyond DATA_RECVD|stream_state_recv:%d|", stream->stream_state_recv);
        return XQC_OK;
    }

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    ret = xqc_gen_stop_sending_frame(packet_out, stream->stream_id, err_code);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_stop_sending_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return -XQC_EWRITE_PKT;
}

int
xqc_write_data_blocked_to_packet(xqc_connection_t *conn, uint64_t data_limit)
{
    ssize_t ret;
    xqc_packet_out_t *packet_out;

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    ret = xqc_gen_data_blocked_frame(packet_out, data_limit);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_data_blocked_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    /* we need to send this packet asap */
    xqc_send_queue_move_to_high_pri(&packet_out->po_list, conn->conn_send_queue);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return -XQC_EWRITE_PKT;
}

int
xqc_write_stream_data_blocked_to_packet(xqc_connection_t *conn, xqc_stream_id_t stream_id, uint64_t stream_data_limit)
{
    ssize_t ret;
    xqc_packet_out_t *packet_out;
    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    ret = xqc_gen_stream_data_blocked_frame(packet_out, stream_id, stream_data_limit);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_stream_data_blocked_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    /* we need to send this packet asap */
    xqc_send_queue_move_to_high_pri(&packet_out->po_list, conn->conn_send_queue);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return -XQC_EWRITE_PKT;
}

int
xqc_write_streams_blocked_to_packet(xqc_connection_t *conn, uint64_t stream_limit, int bidirectional)
{
    ssize_t ret;
    xqc_packet_out_t *packet_out;

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_NUM);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    ret = xqc_gen_streams_blocked_frame(packet_out, stream_limit, bidirectional);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_streams_blocked_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    xqc_send_queue_move_to_high_pri(&packet_out->po_list, conn->conn_send_queue);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return -XQC_EWRITE_PKT;
}

int
xqc_write_max_data_to_packet(xqc_connection_t *conn, uint64_t max_data)
{
    ssize_t ret;
    xqc_packet_out_t *packet_out;

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    ret = xqc_gen_max_data_frame(packet_out, max_data);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_max_data_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    xqc_send_queue_move_to_high_pri(&packet_out->po_list, conn->conn_send_queue);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return -XQC_EWRITE_PKT;
}

int
xqc_write_max_stream_data_to_packet(xqc_connection_t *conn, xqc_stream_id_t stream_id, uint64_t max_stream_data)
{
    ssize_t ret = XQC_OK;
    xqc_packet_out_t *packet_out;

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    ret = xqc_gen_max_stream_data_frame(packet_out, stream_id, max_stream_data);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_max_stream_data_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    xqc_send_queue_move_to_high_pri(&packet_out->po_list, conn->conn_send_queue);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return -XQC_EWRITE_PKT;
}

int
xqc_write_max_streams_to_packet(xqc_connection_t *conn, uint64_t max_stream, int bidirectional)
{
    ssize_t ret = XQC_ERROR;
    xqc_packet_out_t *packet_out;

    if (max_stream > XQC_MAX_STREAMS) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_max_streams_to_packet error|set max_stream:%ui", max_stream);
        return -XQC_EPARAM;
    }

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_NUM);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    ret = xqc_gen_max_streams_frame(packet_out, max_stream, bidirectional);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_max_streams_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    xqc_send_queue_move_to_high_pri(&packet_out->po_list, conn->conn_send_queue);

    xqc_log(conn->log, XQC_LOG_DEBUG, "|new_max_stream:%ui|", max_stream);
    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return -XQC_EWRITE_PKT;
}

int
xqc_write_new_token_to_packet(xqc_connection_t *conn)
{
    ssize_t ret = 0;
    unsigned need;
    xqc_packet_out_t *packet_out;

    unsigned char token[XQC_MAX_TOKEN_LEN];
    unsigned token_len = XQC_MAX_TOKEN_LEN;
    xqc_conn_gen_token(conn, token, &token_len);

    need = 1 /* type */
            + xqc_vint_get_2bit(token_len) /* token len */
            + token_len; /* token */

    packet_out = xqc_write_packet(conn, XQC_PTYPE_SHORT_HEADER, need);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    ret = xqc_gen_new_token_frame(packet_out, token, token_len);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_new_token_frame error|");
        goto error;
    }

    packet_out->po_used_size += ret;

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

int
xqc_write_stream_frame_to_packet(xqc_connection_t *conn,
    xqc_stream_t *stream, xqc_pkt_type_t pkt_type, uint8_t fin,
    const unsigned char *payload, size_t payload_size, size_t *send_data_written)
{
    xqc_packet_out_t *packet_out;
    int n_written;
    /* We need 25 bytes for stream frame header at most, and left bytes for stream data.
     * It's a trade-off value, bigger need bytes for higher payload rate. */
    const unsigned need = 50;
    packet_out = xqc_write_packet_for_stream(conn, pkt_type, need, stream);
    if (packet_out == NULL) {
        return -XQC_EWRITE_PKT;
    }

    n_written = xqc_gen_stream_frame(packet_out,
                                     stream->stream_id, stream->stream_send_offset, fin,
                                     payload,
                                     payload_size,
                                     send_data_written);
    if (n_written < 0) {
        xqc_maybe_recycle_packet_out(packet_out, conn);
        return n_written;
    }
    stream->stream_send_offset += *send_data_written;
    stream->stream_conn->conn_flow_ctl.fc_data_sent += *send_data_written;
    packet_out->po_used_size += n_written;
    packet_out->po_stream_id = stream->stream_id;
    packet_out->po_stream_offset = stream->stream_send_offset;

    if (stream->stream_mp_usage_schedule == 0) {
        packet_out->po_flag |= XQC_POF_NOT_SCHEDULE;
    }
    if (stream->stream_mp_usage_reinject == 0) {
        packet_out->po_flag |= XQC_POF_NOT_REINJECT;
    }

    if (fin && *send_data_written == payload_size) {
        stream->stream_flag |= XQC_STREAM_FLAG_FIN_WRITE;
        stream->stream_stats.local_fin_write_time = xqc_monotonic_timestamp();
    }

    if (!stream->stream_stats.first_write_time) {
        stream->stream_stats.first_write_time = xqc_monotonic_timestamp();
    }
    return XQC_OK;
}

int 
xqc_write_datagram_frame_to_packet(xqc_connection_t *conn, xqc_pkt_type_t pkt_type, 
    const unsigned char *data, size_t data_len, uint64_t *dgram_id, xqc_bool_t use_supplied_dgram_id,
    xqc_data_qos_level_t qos_level)
{
    xqc_packet_out_t *packet_out;
    packet_out = xqc_write_new_packet(conn, pkt_type);
    if (packet_out == NULL) {
        return -XQC_EWRITE_PKT;
    }

    int ret;
    ret = xqc_gen_datagram_frame(packet_out, data, data_len);

    if (ret < 0) {
        xqc_maybe_recycle_packet_out(packet_out, conn);
        return ret;
    }

    if (use_supplied_dgram_id) {
        packet_out->po_dgram_id = *dgram_id;

    } else {
        packet_out->po_dgram_id = conn->next_dgram_id++;
    }
    
    if (dgram_id) {
        *dgram_id = packet_out->po_dgram_id;
    }

    if (pkt_type == XQC_PTYPE_0RTT) {
        conn->zero_rtt_count++;
    }

    if (qos_level > XQC_DATA_QOS_HIGH) {
        if (qos_level == XQC_DATA_QOS_PROBING) {
            /* must reinject the packet on a different path */
            packet_out->po_flag |= XQC_POF_REINJECT_DIFF_PATH;
            packet_out->po_flag |= XQC_POF_QOS_PROBING;

        } else {
            packet_out->po_flag |= XQC_POF_NOT_REINJECT;
        }

    } else {
        packet_out->po_flag |= XQC_POF_QOS_HIGH;
    }

    return XQC_OK;
}


/* [Transport] 12.4, HANDSHAKE_DONE only send in 1-RTT packet */
int
xqc_write_handshake_done_frame_to_packet(xqc_connection_t *conn)
{
    ssize_t n_written = 0;
    xqc_packet_out_t *packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);  
    if (packet_out == NULL) {
        return -XQC_EWRITE_PKT;
    }

    n_written = xqc_gen_handshake_done_frame(packet_out);
    if (n_written < 0) {
        xqc_maybe_recycle_packet_out(packet_out, conn);
        return n_written;
    }

    packet_out->po_used_size += n_written;

    return XQC_OK;
}


xqc_int_t
xqc_write_new_conn_id_frame_to_packet(xqc_connection_t *conn, uint64_t retire_prior_to)
{
    xqc_int_t           ret = XQC_ERROR;
    xqc_packet_out_t   *packet_out = NULL;
    xqc_cid_t           new_conn_cid;
    uint8_t             sr_token[XQC_STATELESS_RESET_TOKENLEN];

    /* only reserve bits for server side */
    ++conn->scid_set.largest_scid_seq_num;
    if (XQC_OK != xqc_generate_cid(conn->engine, &conn->scid_set.user_scid, &new_conn_cid,
                                   conn->scid_set.largest_scid_seq_num))
    {
        xqc_log(conn->log, XQC_LOG_WARN, "|generate cid error|");
        return -XQC_EGENERATE_CID;
    }

    /* generate stateless reset token */
    xqc_gen_reset_token(&new_conn_cid, sr_token, XQC_STATELESS_RESET_TOKENLEN,
                        conn->engine->config->reset_token_key,
                        conn->engine->config->reset_token_keylen);

    /* insert to scid_set & add scid_unused_cnt */
    ret = xqc_cid_set_insert_cid(&conn->scid_set.cid_set, &new_conn_cid, XQC_CID_UNUSED,
                                 conn->remote_settings.active_connection_id_limit);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_cid_set_insert_cid error|limit:%ui|unused:%ui|used:%ui|",
                conn->remote_settings.active_connection_id_limit,
                conn->scid_set.cid_set.unused_cnt, conn->scid_set.cid_set.used_cnt);
        return ret;
    }

    ret = xqc_insert_conns_hash(conn->engine->conns_hash, conn,
                                new_conn_cid.cid_buf, new_conn_cid.cid_len);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|insert new_cid into conns_hash failed|");
        return ret;
    }

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    ret = xqc_gen_new_conn_id_frame(packet_out, &new_conn_cid, retire_prior_to,
                                    sr_token);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_new_conn_id_frame error|");
        goto error;
    }
    packet_out->po_used_size += ret;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|gen_new_scid|cid:%s|sr_token:%s|seq_num:%ui",
            xqc_scid_str(&new_conn_cid), xqc_sr_token_str(new_conn_cid.sr_token),
            new_conn_cid.cid_seq_num);

    xqc_send_queue_move_to_high_pri(&packet_out->po_list, conn->conn_send_queue);
    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}


xqc_int_t
xqc_write_retire_conn_id_frame_to_packet(xqc_connection_t *conn, uint64_t seq_num)
{
    xqc_int_t ret = XQC_ERROR;

	/* select new current_dcid to replace the cid to be retired */		
    if (seq_num == conn->dcid_set.current_dcid.cid_seq_num) {	
        // TODO: DCID changes	
        ret = xqc_get_unused_cid(&conn->dcid_set.cid_set, &conn->dcid_set.current_dcid);		
        if (ret != XQC_OK) {		
            xqc_log(conn->log, XQC_LOG_ERROR, "|conn don't have available dcid|");		
            return ret;		
        }
        xqc_datagram_record_mss(conn);		
    }		
    xqc_log(conn->log, XQC_LOG_DEBUG, "|get_new_dcid:%s|seq_num:%ui|",		
            xqc_dcid_str(&conn->dcid_set.current_dcid), conn->dcid_set.current_dcid.cid_seq_num);

    xqc_packet_out_t *packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    ret = xqc_gen_retire_conn_id_frame(packet_out, seq_num);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_retire_conn_id_frame error|");
        xqc_maybe_recycle_packet_out(packet_out, conn);
        return ret;
    }

    packet_out->po_used_size += ret;

    return XQC_OK;
}


xqc_int_t
xqc_write_path_challenge_frame_to_packet(xqc_connection_t *conn, xqc_path_ctx_t *path)
{
    xqc_int_t ret = XQC_ERROR;

    xqc_packet_out_t *packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    ret = xqc_gen_path_challenge_frame(packet_out, path->path_challenge_data);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_path_challenge_frame error|%d|", ret);
        goto error;
    }

    packet_out->po_used_size += ret;

    packet_out->po_path_flag |= XQC_PATH_SPECIFIED_BY_PCPR;
    packet_out->po_path_id = path->path_id;

    xqc_send_queue_move_to_high_pri(&packet_out->po_list, conn->conn_send_queue);

    xqc_log(conn->log, XQC_LOG_DEBUG, "|path:%ui|", path->path_id);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

xqc_int_t
xqc_write_path_response_frame_to_packet(xqc_connection_t *conn, xqc_path_ctx_t *path, unsigned char *path_response_data)
{
    xqc_int_t ret = XQC_ERROR;

    xqc_packet_out_t *packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    ret = xqc_gen_path_response_frame(packet_out, path_response_data);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_path_response_frame error|%d|", ret);
        goto error;
    }

    packet_out->po_used_size += ret;

    packet_out->po_path_flag |= XQC_PATH_SPECIFIED_BY_PCPR;
    packet_out->po_path_id = path->path_id;

    xqc_send_queue_move_to_high_pri(&packet_out->po_list, conn->conn_send_queue);

    xqc_log(conn->log, XQC_LOG_DEBUG, "|path:%ui|", path->path_id);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}


int
xqc_write_ack_mp_to_packets(xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_pkt_num_space_t pns;
    xqc_packet_out_t *packet_out;
    xqc_pkt_type_t pkt_type;
    xqc_list_head_t *pos, *next;

    int ret;

    xqc_path_ctx_t *path;
    xqc_list_head_t *path_pos, *path_next;

    for (pns = 0; pns < XQC_PNS_N; ++pns) {
        if (!(conn->conn_flag & (XQC_CONN_FLAG_SHOULD_ACK_INIT << pns))) {
            continue;
        }

        xqc_list_for_each_safe(path_pos, path_next, &conn->conn_paths_list) {

            path = xqc_list_entry(path_pos, xqc_path_ctx_t, path_list);
            if (path->path_state < XQC_PATH_STATE_VALIDATING) {
                continue;
            }
            xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, path);

            xqc_pktno_range_node_t *first_range = NULL;
            xqc_list_head_t *tmp_pos, *tmp_next;
            xqc_list_for_each_safe(tmp_pos, tmp_next, &pn_ctl->ctl_recv_record[pns].list_head) {
                first_range = xqc_list_entry(tmp_pos, xqc_pktno_range_node_t, list);
                break;
            }
            if (first_range == NULL) {
                continue;
            }

            if (pns == XQC_PNS_HSK) {
                pkt_type = XQC_PTYPE_HSK;

            } else if (pns == XQC_PNS_INIT) {
                pkt_type = XQC_PTYPE_INIT;

            } else {
                pkt_type = XQC_PTYPE_SHORT_HEADER;
            }

path_buffer:
            xqc_list_for_each_safe(pos, next, &path->path_schedule_buf[XQC_SEND_TYPE_NORMAL]) {
                packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
                if (xqc_packet_out_can_attach_ack(packet_out, path, pkt_type)) {
                    ret = xqc_write_ack_mp_to_one_packet(conn, path, packet_out, pns);
                    if (ret == -XQC_ENOBUF) {
                        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_write_ack_mp_to_one_packet try new packet|");
                        goto write_new;

                    } else if (ret == XQC_OK) {
                        goto done;

                    } else {
                        return ret;
                    }
                }
                goto write_new;
            }

write_new:
            /* 指定 MP_ACK 从原路径发送 */
            packet_out = xqc_write_new_packet(conn, pkt_type);
            if (packet_out == NULL) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
                return -XQC_EWRITE_PKT;
            }

            ret = xqc_write_ack_mp_to_one_packet(conn, path, packet_out, pns);
            if (ret != XQC_OK) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_ack_mp_to_one_packet error|ret:%d|", ret);
                return ret;
            }
pure_ack:
            /* send ack packet first */
            xqc_send_queue_move_to_high_pri(&packet_out->po_list, conn->conn_send_queue);
done:
            xqc_log(conn->log, XQC_LOG_DEBUG, "|path:%ui|pns:%d|", path->path_id, pns);

        }
    }
    return XQC_OK;
}

int
xqc_write_ack_mp_to_one_packet(xqc_connection_t *conn, xqc_path_ctx_t *path,
    xqc_packet_out_t *packet_out, xqc_pkt_num_space_t pns)
{
    ssize_t ret;
    int has_gap;
    xqc_packet_number_t largest_ack;
    xqc_usec_t now = xqc_monotonic_timestamp();

    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, path);

    ret = xqc_gen_ack_mp_frame(conn, path->path_id, packet_out, now,
	                           conn->local_settings.ack_delay_exponent,
                               &pn_ctl->ctl_recv_record[packet_out->po_pkt.pkt_pns],
							   path->path_send_ctl->ctl_largest_recv_time[pns],
                               &has_gap, &largest_ack);
    if (ret < 0) {
        goto error;
    }
    xqc_log(conn->log, XQC_LOG_DEBUG, "|path:%ui|ack_size:%ui|", path->path_id, ret);

    packet_out->po_ack_offset = packet_out->po_used_size;
    packet_out->po_used_size += ret;
    packet_out->po_largest_ack = largest_ack;

    packet_out->po_path_flag |= XQC_PATH_SPECIFIED_BY_ACK;
    packet_out->po_path_id = path->path_id;

    path->path_send_ctl->ctl_ack_eliciting_pkt[pns] = 0;
    if (has_gap) {
        conn->conn_flag |= XQC_CONN_FLAG_ACK_HAS_GAP;

    } else {
        conn->conn_flag &= ~XQC_CONN_FLAG_ACK_HAS_GAP;
    }
    conn->conn_flag &= ~(XQC_CONN_FLAG_SHOULD_ACK_INIT << pns);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}


xqc_int_t
xqc_write_path_abandon_frame_to_packet(xqc_connection_t *conn, xqc_path_ctx_t *path)
{
    xqc_int_t ret = XQC_ERROR;

    xqc_packet_out_t *packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    /* dcid_seq_num = path->scid.cid_seq_num */
    uint64_t dcid_seq_num = path->path_id;

    ret = xqc_gen_path_abandon_frame(packet_out, dcid_seq_num, 0);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_path_abandon_frame error|%d|", ret);
        goto error;
    }

    packet_out->po_used_size += ret;

    xqc_send_queue_move_to_high_pri(&packet_out->po_list, conn->conn_send_queue);

    xqc_log(conn->log, XQC_LOG_DEBUG, "|path:%ui|dcid_seq_num:%ui|",
            path->path_id, dcid_seq_num);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

xqc_int_t
xqc_write_path_status_frame_to_packet(xqc_connection_t *conn, xqc_path_ctx_t *path)
{
    xqc_int_t ret = XQC_ERROR;

    xqc_packet_out_t *packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    path->app_path_status_send_seq_num++;
    ret = xqc_gen_path_status_frame(packet_out, path->path_id,
                                    path->app_path_status_send_seq_num, (uint64_t)path->app_path_status);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_path_status_frame error|%d|", ret);
        goto error;
    }

    packet_out->po_used_size += ret;
    xqc_send_queue_move_to_high_pri(&packet_out->po_list, conn->conn_send_queue);

    return XQC_OK;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return ret;
}

