/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_conn.h"
#include "src/common/xqc_memory_pool.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/common/xqc_timer.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_engine.h"


xqc_packet_out_t *
xqc_packet_out_create()
{
    xqc_packet_out_t *packet_out;
    packet_out = xqc_calloc(1, sizeof(xqc_packet_out_t));
    if (!packet_out) {
        goto error;
    }

    packet_out->po_buf = xqc_malloc(XQC_PACKET_OUT_SIZE + XQC_EXTRA_SPACE + XQC_ACK_SPACE);
    if (!packet_out->po_buf) {
        goto error;
    }

    return packet_out;

error:
    if (packet_out) {
        xqc_free(packet_out->po_buf);
        xqc_free(packet_out);
    }
    return NULL;
}

void
xqc_packet_out_copy(xqc_packet_out_t *dst, xqc_packet_out_t *src)
{
    unsigned char *po_buf = dst->po_buf;
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
    dst->po_origin = origin;
    origin->po_origin_ref_cnt++;
    dst->po_user_data = src->po_user_data;
}


xqc_packet_out_t *
xqc_packet_out_get(xqc_send_ctl_t *ctl)
{
    xqc_packet_out_t *packet_out;
    unsigned int buf_size;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &ctl->ctl_free_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        xqc_send_ctl_remove_free(pos, ctl);

        unsigned char *tmp = packet_out->po_buf;
        buf_size = packet_out->po_buf_size;
        memset(packet_out, 0, sizeof(xqc_packet_out_t));
        packet_out->po_buf = tmp;
        packet_out->po_buf_size = buf_size;
        return packet_out;
    }

    packet_out = xqc_packet_out_create();
    if (!packet_out) {
        return NULL;
    }

    return packet_out;
}

xqc_packet_out_t *
xqc_packet_out_get_and_insert_send(xqc_send_ctl_t *ctl, enum xqc_pkt_type pkt_type)
{
    xqc_packet_out_t *packet_out;
    packet_out = xqc_packet_out_get(ctl);
    if (!packet_out) {
        return NULL;
    }

    packet_out->po_buf_size = XQC_PACKET_OUT_SIZE;
    packet_out->po_pkt.pkt_type = pkt_type;
    packet_out->po_pkt.pkt_pns = xqc_packet_type_to_pns(pkt_type);

    /* generate packet number when send */
    packet_out->po_pkt.pkt_num = 0;

    xqc_send_ctl_insert_send(&packet_out->po_list, &ctl->ctl_send_packets, ctl);

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
        xqc_send_ctl_insert_free(&packet_out->po_list, &conn->conn_send_ctl->ctl_free_packets, conn->conn_send_ctl);
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

    packet_out = xqc_packet_out_get_and_insert_send(conn->conn_send_ctl, pkt_type);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_packet_out_get_and_insert_send error|");
        return NULL;
    }

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

    packet_out = xqc_send_ctl_get_packet_out(conn->conn_send_ctl, need, pkt_type);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_send_ctl_get_packet_out error|");
        return NULL;
    }

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

    ret = xqc_gen_ack_frame(conn, packet_out, now, conn->local_settings.ack_delay_exponent,
                            &conn->recv_record[packet_out->po_pkt.pkt_pns], &has_gap, &largest_ack);
    if (ret < 0) {
        goto error;
    }
    xqc_log(conn->log, XQC_LOG_DEBUG, "|ack_size:%ui|", ret);

    packet_out->po_ack_offset = packet_out->po_used_size;
    packet_out->po_used_size += ret;
    packet_out->po_largest_ack = largest_ack;

    conn->ack_eliciting_pkt[pns] = 0;
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
        if (conn->conn_flag & (XQC_CONN_FLAG_SHOULD_ACK_INIT << pns)) {

            if (pns == XQC_PNS_HSK) {
                pkt_type = XQC_PTYPE_HSK;

            } else if (pns == XQC_PNS_INIT) {
                pkt_type = XQC_PTYPE_INIT;

            } else {
                pkt_type = XQC_PTYPE_SHORT_HEADER;
            }

            xqc_list_for_each_safe(pos, next, &conn->conn_send_ctl->ctl_send_packets) {
                packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
                if (packet_out->po_pkt.pkt_type == pkt_type) {
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

done:
            xqc_log(conn->log, XQC_LOG_DEBUG, "|pns:%d|", pns);

            /* send ack packet first */
            xqc_send_ctl_move_to_head(&packet_out->po_list, &conn->conn_send_ctl->ctl_send_packets);

        }
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

    xqc_send_ctl_move_to_head(&packet_out->po_list, &conn->conn_send_ctl->ctl_send_packets);
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

    xqc_send_ctl_move_to_head(&packet_out->po_list, &conn->conn_send_ctl->ctl_send_packets);

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

    xqc_send_ctl_move_to_head(&packet_out->po_list, &conn->conn_send_ctl->ctl_send_packets);

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

    xqc_send_ctl_move_to_head(&packet_out->po_list, &conn->conn_send_ctl->ctl_send_packets);

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

    xqc_send_ctl_move_to_head(&packet_out->po_list, &conn->conn_send_ctl->ctl_send_packets);

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

    xqc_send_ctl_move_to_head(&packet_out->po_list, &conn->conn_send_ctl->ctl_send_packets);

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
    packet_out = xqc_write_new_packet(conn, pkt_type);
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

    for (int i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
        if (packet_out->po_stream_frames[i].ps_is_used == 0) {
            packet_out->po_stream_frames[i].ps_is_used = 1;
            packet_out->po_stream_frames[i].ps_stream_id = stream->stream_id;
            if (fin && *send_data_written == payload_size) {
                packet_out->po_stream_frames[i].ps_has_fin = 1;
                stream->stream_flag |= XQC_STREAM_FLAG_FIN_WRITE;
                stream->stream_stats.local_fin_write_time = xqc_monotonic_timestamp();
            }
            break;
        }

        if (i == XQC_MAX_STREAM_FRAME_IN_PO - 1) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|too many stream frames in a packet|");
            return -XQC_ELIMIT;
        }
    }

    if (pkt_type == XQC_PTYPE_0RTT) {
        conn->zero_rtt_count++;
    }

    if (!stream->stream_stats.first_write_time) {
        stream->stream_stats.first_write_time = xqc_monotonic_timestamp();
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
    xqc_int_t ret = XQC_ERROR;
    xqc_packet_out_t *packet_out = NULL;

    if (conn->scid_set.cid_set.unused_cnt >= XQC_MAX_AVAILABLE_CID_COUNT) {
        xqc_log(conn->log, XQC_LOG_WARN, "|Too many generated cid|");
        return -XQC_EGENERATE_CID;
    }
    xqc_cid_t new_conn_cid;

    /* only reserve bits for server side */
    ++conn->scid_set.largest_scid_seq_num;
    if (XQC_OK != xqc_generate_cid(conn->engine, &conn->scid_set.user_scid, &new_conn_cid,
                                   conn->scid_set.largest_scid_seq_num))
    {
        xqc_log(conn->log, XQC_LOG_WARN, "|generate cid error|");
        return -XQC_EGENERATE_CID;
    }

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    ret = xqc_gen_new_conn_id_frame(packet_out, &new_conn_cid, retire_prior_to,
                                    conn->engine->config->reset_token_key,
                                    conn->engine->config->reset_token_keylen);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_new_conn_id_frame error|");
        goto error;
    }
    packet_out->po_used_size += ret;

    ret = xqc_insert_conns_hash(conn->engine->conns_hash, conn, &new_conn_cid);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|insert new_cid into conns_hash failed|");
        goto error;
    }
    
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

    xqc_log(conn->log, XQC_LOG_DEBUG, "|gen_new_scid:%s|seq_num:%ui|",
            xqc_scid_str(&new_conn_cid), new_conn_cid.cid_seq_num);

    xqc_send_ctl_move_to_head(&packet_out->po_list, &conn->conn_send_ctl->ctl_send_packets);
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
        ret = xqc_get_unused_cid(&conn->dcid_set.cid_set, &conn->dcid_set.current_dcid);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|conn don't have available dcid|");
            return ret;
        }
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



