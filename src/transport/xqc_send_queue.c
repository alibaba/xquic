#include <string.h>

#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_conn.h"
#include "src/common/xqc_memory_pool.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_reinjection.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_conn.h"

xqc_send_queue_t *
xqc_send_queue_create(xqc_connection_t *conn)
{
    xqc_send_queue_t *send_queue = xqc_pcalloc(conn->conn_pool, sizeof(xqc_send_queue_t));
    if (send_queue == NULL) {
        return NULL;
    }

    xqc_init_list_head(&send_queue->sndq_send_packets);
    xqc_init_list_head(&send_queue->sndq_send_packets_high_pri);
    for (xqc_pkt_num_space_t pns = 0; pns < XQC_PNS_N; ++pns) {
        xqc_init_list_head(&send_queue->sndq_unacked_packets[pns]);
    }

    xqc_init_list_head(&send_queue->sndq_lost_packets);
    xqc_init_list_head(&send_queue->sndq_free_packets);
    xqc_init_list_head(&send_queue->sndq_buff_1rtt_packets);
    xqc_init_list_head(&send_queue->sndq_pto_probe_packets);

    if (conn->conn_settings.sndq_packets_used_max > 0) {
        send_queue->sndq_packets_used_max = conn->conn_settings.sndq_packets_used_max;
    } else {
        send_queue->sndq_packets_used_max = XQC_SNDQ_PACKETS_USED_MAX;
    }

    send_queue->sndq_conn = conn;

    send_queue->sndq_packets_in_unacked_list = 0;

    return send_queue;
}

void
xqc_send_queue_destroy_packets_list(xqc_list_head_t *head)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *packet_out;
    xqc_list_for_each_safe(pos, next, head) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        xqc_list_del_init(pos);
        xqc_packet_out_destroy(packet_out);
    }
}

void
xqc_send_queue_destroy(xqc_send_queue_t *send_queue)
{
    xqc_send_queue_destroy_packets_list(&send_queue->sndq_send_packets);
    xqc_send_queue_destroy_packets_list(&send_queue->sndq_send_packets_high_pri);
    for (xqc_pkt_num_space_t pns = 0; pns < XQC_PNS_N; ++pns) {
        xqc_send_queue_destroy_packets_list(&send_queue->sndq_unacked_packets[pns]);
    }

    xqc_send_queue_destroy_packets_list(&send_queue->sndq_lost_packets);
    xqc_send_queue_destroy_packets_list(&send_queue->sndq_free_packets);
    xqc_send_queue_destroy_packets_list(&send_queue->sndq_buff_1rtt_packets);
    xqc_send_queue_destroy_packets_list(&send_queue->sndq_pto_probe_packets);

    send_queue->sndq_packets_used = 0;
    send_queue->sndq_packets_used_bytes = 0;
    send_queue->sndq_packets_free = 0;   
    send_queue->sndq_packets_in_unacked_list = 0;
}


void
xqc_send_queue_pre_destroy_packets_list(xqc_send_queue_t *send_queue, xqc_list_head_t *head)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *packet_out;
    xqc_list_for_each_safe(pos, next, head) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        xqc_list_del_init(pos);
        xqc_list_add_tail(pos, &send_queue->sndq_free_packets);
    }
}

void
xqc_send_queue_pre_destroy(xqc_send_queue_t *send_queue)
{
    xqc_send_queue_pre_destroy_packets_list(send_queue, &send_queue->sndq_send_packets);
    xqc_send_queue_pre_destroy_packets_list(send_queue, &send_queue->sndq_send_packets_high_pri);
    for (xqc_pkt_num_space_t pns = 0; pns < XQC_PNS_N; ++pns) {
        xqc_send_queue_pre_destroy_packets_list(send_queue, &send_queue->sndq_unacked_packets[pns]);
    }

    xqc_send_queue_pre_destroy_packets_list(send_queue, &send_queue->sndq_lost_packets);
    xqc_send_queue_pre_destroy_packets_list(send_queue, &send_queue->sndq_buff_1rtt_packets);
    xqc_send_queue_pre_destroy_packets_list(send_queue, &send_queue->sndq_pto_probe_packets);

    send_queue->sndq_packets_used = 0;
    send_queue->sndq_packets_used_bytes = 0;
    send_queue->sndq_packets_free = 0;
    send_queue->sndq_packets_in_unacked_list = 0;
}

xqc_packet_out_t *
xqc_send_queue_get_packet_out(xqc_send_queue_t *send_queue, unsigned need, xqc_pkt_type_t pkt_type)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t  *pos;

    xqc_list_for_each_reverse(pos, &send_queue->sndq_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == pkt_type 
            && xqc_get_po_remained_size(packet_out) >= need)
        {
            return packet_out;
        }
    }

    packet_out = xqc_packet_out_get_and_insert_send(send_queue, pkt_type);
    if (packet_out == NULL) {
        return NULL;
    }

    return packet_out;
}

xqc_packet_out_t *
xqc_send_queue_get_packet_out_for_stream(xqc_send_queue_t *send_queue, unsigned need, xqc_pkt_type_t pkt_type,
    xqc_stream_t *stream)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t  *pos;
    xqc_list_head_t  *list = &send_queue->sndq_send_packets;
    if (stream->stream_priority == XQC_STREAM_PRI_HIGH) {
        list = &send_queue->sndq_send_packets_high_pri;
    }

    xqc_list_for_each_reverse(pos, list) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == pkt_type
            && xqc_get_po_remained_size(packet_out) >= need
            && packet_out->po_stream_frames_idx < XQC_MAX_STREAM_FRAME_IN_PO
            && packet_out->po_stream_frames_idx > 0
            /* Avoid Head-of-Line blocking. */
            && packet_out->po_stream_frames[packet_out->po_stream_frames_idx - 1].ps_stream_id == stream->stream_id
            && !(packet_out->po_frame_types & XQC_FRAME_BIT_SID)
            && !(packet_out->po_frame_types & XQC_FRAME_BIT_REPAIR_SYMBOL))
        {
            return packet_out;
        }
        /* Only try to fill the last packet now */
        break;
    }

    packet_out = xqc_packet_out_get_and_insert_send(send_queue, pkt_type);
    if (packet_out == NULL) {
        return NULL;
    }
    
    if (stream->stream_priority == XQC_STREAM_PRI_HIGH) {
        xqc_send_queue_move_to_high_pri(&packet_out->po_list, send_queue);
    }

    if (pkt_type == XQC_PTYPE_0RTT) {
        send_queue->sndq_conn->zero_rtt_count++;
    }

    return packet_out;
}

int xqc_send_queue_out_queue_empty(xqc_send_queue_t *send_queue)
{
    int empty;
    empty = xqc_list_empty(&send_queue->sndq_send_packets)
            && xqc_list_empty(&send_queue->sndq_send_packets_high_pri)
            && xqc_list_empty(&send_queue->sndq_lost_packets)
            && xqc_list_empty(&send_queue->sndq_pto_probe_packets)
            && xqc_list_empty(&send_queue->sndq_buff_1rtt_packets);
    if (!empty) {
        return empty;
    }

    for (xqc_pkt_num_space_t pns = 0; pns < XQC_PNS_N; ++pns) {
        empty = empty && xqc_list_empty(&send_queue->sndq_unacked_packets[pns]);
    }
    if (!empty) {
        return empty;
    }

    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_list_for_each_safe(pos, next, &send_queue->sndq_conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        for (xqc_send_type_t type = 0; type < XQC_SEND_TYPE_N; type++) {
            empty = empty && xqc_list_empty(&path->path_schedule_buf[type]);
        }
    }

    return empty;
}



void
xqc_send_queue_insert_send(xqc_packet_out_t *po, xqc_list_head_t *head, xqc_send_queue_t *send_queue)
{
    xqc_list_add_tail(&po->po_list, head);
    send_queue->sndq_packets_used++;
}

void
xqc_send_queue_remove_send(xqc_list_head_t *pos)
{
    xqc_list_del_init(pos);
}

void
xqc_send_queue_insert_lost(xqc_list_head_t *pos, xqc_list_head_t *head)
{
    xqc_list_add_tail(pos, head);
}

void
xqc_send_queue_remove_lost(xqc_list_head_t *pos)
{
    xqc_list_del_init(pos);
}

void
xqc_send_queue_insert_free(xqc_packet_out_t *po, xqc_list_head_t *head, xqc_send_queue_t *send_queue)
{
    if (po->po_pr) {
        if (po->po_pr->ref_cnt <= 1) {
            xqc_conn_destroy_ping_record(po->po_pr);

        } else {
            po->po_pr->ref_cnt--;
            po->po_pr = NULL;
        }
    }
    xqc_list_add_tail(&po->po_list, head);
    send_queue->sndq_packets_free++;
    send_queue->sndq_packets_used--;
}

void
xqc_send_queue_remove_free(xqc_list_head_t *pos, xqc_send_queue_t *send_queue)
{
    xqc_list_del_init(pos);
    send_queue->sndq_packets_free--;
}

void
xqc_send_queue_insert_buff(xqc_list_head_t *pos, xqc_list_head_t *head)
{
    xqc_list_add_tail(pos, head);
}

void
xqc_send_queue_remove_buff(xqc_list_head_t *pos, xqc_send_queue_t *send_queue)
{
    xqc_list_del_init(pos);
    send_queue->sndq_packets_used--;
}

void
xqc_send_queue_insert_probe(xqc_list_head_t *pos, xqc_list_head_t *head)
{
    xqc_list_add_tail(pos, head);
}

void
xqc_send_queue_remove_probe(xqc_list_head_t *pos)
{
    xqc_list_del_init(pos);
}

void
xqc_send_queue_insert_unacked(xqc_packet_out_t *packet_out, xqc_list_head_t *head, xqc_send_queue_t *send_queue)
{
    xqc_connection_t *conn = send_queue->sndq_conn;
    xqc_list_add_tail(&packet_out->po_list, head);
    if (!(packet_out->po_flag & XQC_POF_IN_UNACK_LIST)) {
        send_queue->sndq_packets_in_unacked_list++;
        packet_out->po_flag |= XQC_POF_IN_UNACK_LIST;
        if (send_queue->sndq_packets_in_unacked_list > XQC_SNDQ_MAX_UNACK_PACKETS_LIMIT) {
            if (conn) {
                XQC_CONN_ERR(conn, XQC_ELIMIT);
                xqc_log(conn->log, XQC_LOG_ERROR,
                        "|sndq unack packets exceed|sndq_packets_in_unacked_list:%ui|",
                        send_queue->sndq_packets_in_unacked_list); 
            }
        } 
    }
}

void
xqc_send_queue_remove_unacked(xqc_packet_out_t *packet_out, xqc_send_queue_t *send_queue)
{
    xqc_list_del_init(&packet_out->po_list);
    /* @FIXED: 
     * It is possible that the packet_out is not in the unacked list (e.g. in path buffer).
     * So, sndq_packets_in_unacked_list is incorrect sometimes. 
     * Now, we use it to estimate unsent bytes. so, it's not gonna make fatal errors.
     * But, we must find a way to fix it.
     */
    if (packet_out->po_flag & XQC_POF_IN_UNACK_LIST) {
        if (send_queue->sndq_packets_in_unacked_list == 0) {
            xqc_log(send_queue->sndq_conn->log, XQC_LOG_ERROR, "|the_number_of_unacked_packets_in_sndq_will_become_negative!|");
            return;
        }
        send_queue->sndq_packets_in_unacked_list--;
        packet_out->po_flag &= ~XQC_POF_IN_UNACK_LIST;
    }
}

uint64_t 
xqc_send_queue_get_unsent_packets_num(xqc_send_queue_t *send_queue)
{
    if (send_queue->sndq_packets_in_unacked_list > send_queue->sndq_packets_used) {
        xqc_log(send_queue->sndq_conn->log, XQC_LOG_ERROR, "|more_unacked_packets_than_used_packets|");
        return 0;
    }
    return send_queue->sndq_packets_used - send_queue->sndq_packets_in_unacked_list;
}


void
xqc_send_queue_move_to_head(xqc_list_head_t *pos, xqc_list_head_t *head)
{
    xqc_list_del_init(pos);
    xqc_list_add(pos, head);
}

void
xqc_send_queue_move_to_tail(xqc_list_head_t *pos, xqc_list_head_t *head)
{
    xqc_list_del_init(pos);
    xqc_list_add_tail(pos, head);
}

void
xqc_send_queue_move_to_high_pri(xqc_list_head_t *pos, xqc_send_queue_t *send_queue)
{
    xqc_list_del_init(pos);
    xqc_list_add_tail(pos, &send_queue->sndq_send_packets_high_pri);
}


/*
 * The data of a STREAM frame of packet_out: after the frame type, the Stream
 * ID, and the Offset and Length fields when present (RFC 9000 Section 19.8).
 */
static const unsigned char *
xqc_send_queue_stream_frame_data(const xqc_packet_out_t *packet_out,
    const xqc_po_stream_frame_t *frame)
{
    const unsigned char *p = packet_out->po_buf + frame->ps_type_offset;
    unsigned char type = *p++;

    p += xqc_vint_len(*p >> 6);
    if (type & 0x04) {      /* OFF bit */
        p += xqc_vint_len(*p >> 6);
    }
    if (type & 0x02) {      /* LEN bit */
        p += xqc_vint_len(*p >> 6);
    }

    return p;
}

/*
 * The frames of the lost packet_out other than STREAM, in one packet of the
 * current size: a copy of packet_out without its STREAM and ACK frames and
 * its padding. It is no copy tied to packet_out, as packet_out and its
 * copies are dropped once split, and it holds no stream reference.
 */
static xqc_int_t
xqc_send_queue_split_rest(xqc_send_queue_t *send_queue,
    xqc_packet_out_t *packet_out)
{
    xqc_connection_t *conn = send_queue->sndq_conn;
    xqc_packet_out_t *rest;
    xqc_po_stream_frame_t *frame;
    unsigned int start, end, i, j, kept;

    rest = xqc_packet_out_get(send_queue);
    if (rest == NULL) {
        return -XQC_EMALLOC;
    }

    xqc_packet_out_copy(rest, packet_out);
    rest->po_origin->po_origin_ref_cnt--;
    rest->po_origin = NULL;
    rest->po_buf_size = conn->pkt_out_size;
    xqc_packet_out_remove_ack_frame(rest);
    if (rest->po_padding != NULL
        && rest->po_padding < rest->po_buf + rest->po_used_size)
    {
        rest->po_used_size = rest->po_padding - rest->po_buf;
    }
    rest->po_padding = NULL;

    /* cut each STREAM frame out, and move the frames after it */
    for (i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
        frame = &rest->po_stream_frames[i];
        if (!frame->ps_is_used || frame->ps_is_reset || frame->ps_is_reset_at) {
            continue;
        }

        start = frame->ps_type_offset;
        end = xqc_send_queue_stream_frame_data(rest, frame) - rest->po_buf
              + frame->ps_length;
        if (start >= rest->po_used_size) {
            continue;
        }
        end = xqc_min(end, rest->po_used_size);
        memmove(rest->po_buf + start, rest->po_buf + end,
                rest->po_used_size - end);
        rest->po_used_size -= end - start;

        for (j = 0; j < XQC_MAX_STREAM_FRAME_IN_PO; j++) {
            if (rest->po_stream_frames[j].ps_type_offset > start) {
                rest->po_stream_frames[j].ps_type_offset -= end - start;
            }
        }
    }

    /* the RESET_STREAM and RESET_STREAM_AT records stay */
    kept = 0;
    for (i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
        frame = &rest->po_stream_frames[i];
        if (frame->ps_is_used
            && (frame->ps_is_reset || frame->ps_is_reset_at))
        {
            rest->po_stream_frames[kept++] = *frame;
        }
    }
    for (i = kept; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
        xqc_memzero(&rest->po_stream_frames[i], sizeof(xqc_po_stream_frame_t));
    }
    rest->po_stream_frames_idx = kept;

    rest->po_frame_types &= ~(XQC_FRAME_BIT_STREAM | XQC_FRAME_BIT_PADDING);
    rest->po_flag &= ~(XQC_POF_IN_FLIGHT | XQC_POF_STREAM_UNACK
                       | XQC_POF_STREAM_NO_LEN | XQC_POF_RETRANSED
                       | XQC_POF_SPURIOUS_LOSS);
    rest->po_path_flag &= ~XQC_PATH_SPECIFIED_BY_PTO;

    /* counted as used, whether it is resent or freed */
    send_queue->sndq_packets_used++;
    if (!XQC_NEED_REPAIR(rest->po_frame_types)
        && !(rest->po_flag & XQC_POF_NOTIFY))
    {
        xqc_send_queue_insert_free(rest, &send_queue->sndq_free_packets,
                                   send_queue);
        return XQC_OK;
    }

    xqc_send_queue_insert_lost(&rest->po_list, &send_queue->sndq_lost_packets);
    return XQC_OK;
}

/*
 * The data of the STREAM frame of the lost packet_out, in new packets of the
 * current size, resent before new data. Each takes its stream reference.
 */
static xqc_int_t
xqc_send_queue_split_stream_frame(xqc_send_queue_t *send_queue,
    xqc_packet_out_t *packet_out, const xqc_po_stream_frame_t *frame)
{
    xqc_connection_t *conn = send_queue->sndq_conn;
    const unsigned char *data;
    xqc_packet_out_t *piece;
    uint64_t offset = frame->ps_offset;
    size_t left = frame->ps_length;
    size_t written;
    ssize_t ret;

    data = xqc_send_queue_stream_frame_data(packet_out, frame);
    do {
        piece = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
        if (piece == NULL) {
            return -XQC_EMALLOC;
        }

        ret = xqc_gen_stream_frame(piece, frame->ps_stream_id, offset,
                                   frame->ps_has_fin, data, left, &written);
        if (ret < 0) {
            xqc_maybe_recycle_packet_out(piece, conn);
            return (xqc_int_t) ret;
        }
        piece->po_used_size += ret;
        piece->po_stream_id = frame->ps_stream_id;
        piece->po_stream_offset = offset + written;
        xqc_conn_increase_unacked_stream_ref(conn, piece);

        xqc_send_queue_remove_send(&piece->po_list);
        xqc_send_queue_insert_lost(&piece->po_list,
                                   &send_queue->sndq_lost_packets);

        data += written;
        offset += written;
        left -= written;
    } while (left > 0 && written > 0);

    return left == 0 ? XQC_OK : -XQC_ENOBUF;
}

/*
 * RFC 9000 Section 14.2: packets that are not PMTU probes SHOULD fit within
 * the maximum datagram size. A copy of the lost packet_out would not, as the
 * path MTU went down after packet_out was built, and would be lost again.
 * Its information goes into new frames instead (RFC 9000 Section 13.3),
 * whose boundaries need not be those of the lost ones (Section 2.2, RFC
 * 10069 Section 5.6): its STREAM frames into new packets of the current
 * size, and its other frames into one more (xqc_send_queue_split_rest()).
 * The new packets take their stream references before packet_out gives back
 * those of its packets, which are then marked split (XQC_POF_SPLIT):
 * xqc_send_ctl_indirectly_ack_or_drop_po() drops packet_out and its copies
 * without taking their frames as acknowledged, which the new packets are
 * not. -XQC_EPARAM when a copy of packet_out fits, or when packet_out cannot
 * be split, being no 1-RTT packet or carrying a DATAGRAM or FEC frame: it is
 * copied then.
 */
xqc_int_t
xqc_send_queue_split_lost(xqc_send_queue_t *send_queue,
    xqc_packet_out_t *packet_out)
{
    xqc_connection_t *conn = send_queue->sndq_conn;
    xqc_packet_out_t *origin = packet_out->po_origin ? packet_out->po_origin
                                                     : packet_out;
    xqc_po_stream_frame_t *frame;
    xqc_int_t ret;
    int i;

    if (!xqc_packet_out_exceeds_mss(conn, packet_out)
        || packet_out->po_pkt.pkt_type != XQC_PTYPE_SHORT_HEADER
        || (packet_out->po_frame_types
            & (XQC_FRAME_BIT_DATAGRAM | XQC_FRAME_BIT_SID
               | XQC_FRAME_BIT_REPAIR_SYMBOL)))
    {
        return -XQC_EPARAM;
    }

    if ((packet_out->po_frame_types
         & ~(XQC_FRAME_BIT_STREAM | XQC_FRAME_BIT_ACK | XQC_FRAME_BIT_ACK_MP
             | XQC_FRAME_BIT_PING | XQC_FRAME_BIT_PADDING))
        || (packet_out->po_flag & XQC_POF_NOTIFY))
    {
        ret = xqc_send_queue_split_rest(send_queue, packet_out);
        if (ret != XQC_OK) {
            return ret;
        }
    }

    for (i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
        frame = &packet_out->po_stream_frames[i];
        if (!frame->ps_is_used) {
            break;
        }

        /* the data of a stream already gone is not resent either */
        if (frame->ps_is_reset || frame->ps_is_reset_at
            || xqc_find_stream_by_id(frame->ps_stream_id,
                                     conn->streams_hash) == NULL)
        {
            continue;
        }

        ret = xqc_send_queue_split_stream_frame(send_queue, packet_out, frame);
        if (ret != XQC_OK) {
            return ret;
        }
    }

    xqc_conn_release_unacked_stream_ref(conn, packet_out);
    origin->po_flag |= XQC_POF_SPLIT;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|split lost packet|pkt_num:%ui|"
            "size:%ud|mss:%ud|frame:%s|", packet_out->po_pkt.pkt_num,
            packet_out->po_used_size, xqc_conn_get_mss(conn),
            xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types));
    return XQC_OK;
}

void
xqc_send_queue_copy_to_lost(xqc_packet_out_t *packet_out, xqc_send_queue_t *send_queue, xqc_bool_t mark_retrans)
{
    xqc_connection_t *conn = send_queue->sndq_conn;
    xqc_int_t ret;

    ret = xqc_send_queue_split_lost(send_queue, packet_out);
    if (ret != -XQC_EPARAM) {
        if (ret != XQC_OK) {
            XQC_CONN_ERR(conn, ret == -XQC_EMALLOC ? XQC_EMALLOC
                                                   : TRA_INTERNAL_ERROR);
            return;
        }

        if (mark_retrans) {
            packet_out->po_flag |= XQC_POF_RETRANSED;
        }
        return;
    }

    xqc_packet_out_t *new_po = xqc_packet_out_get(send_queue);
    if (!new_po) {
        XQC_CONN_ERR(conn, XQC_EMALLOC);
        return;
    }

    xqc_packet_out_copy(new_po, packet_out);
    xqc_packet_out_remove_ack_frame(new_po);

    if (new_po->po_path_flag & XQC_PATH_SPECIFIED_BY_PTO) {
        new_po->po_path_flag &= ~XQC_PATH_SPECIFIED_BY_PTO;
    }

    xqc_send_queue_insert_lost(&new_po->po_list, &send_queue->sndq_lost_packets);
    send_queue->sndq_packets_used++;
    if (mark_retrans) {
        packet_out->po_flag |= XQC_POF_RETRANSED;
    }
    new_po->po_flag &= ~XQC_POF_RETRANSED;
    new_po->po_flag &= ~XQC_POF_SPURIOUS_LOSS;
}

void
xqc_send_queue_copy_to_probe(xqc_packet_out_t *packet_out, xqc_send_queue_t *send_queue, xqc_path_ctx_t *path)
{
    xqc_connection_t *conn = send_queue->sndq_conn;

    xqc_packet_out_t *new_po = xqc_packet_out_get(send_queue);
    if (!new_po) {
        XQC_CONN_ERR(conn, XQC_EMALLOC);
        return;
    }

    xqc_packet_out_copy(new_po, packet_out);
    xqc_packet_out_remove_ack_frame(new_po);

    new_po->po_path_flag |= XQC_PATH_SPECIFIED_BY_PTO;
    new_po->po_path_id = path->path_id;

    xqc_send_queue_insert_probe(&new_po->po_list, &send_queue->sndq_pto_probe_packets);
    send_queue->sndq_packets_used++;
    packet_out->po_flag |= XQC_POF_RETRANSED;
    new_po->po_flag &= ~XQC_POF_RETRANSED;
    new_po->po_flag &= ~XQC_POF_SPURIOUS_LOSS;
}

/* Called when conn is ready to close */
void
xqc_send_queue_drop_packets(xqc_connection_t *conn)
{
    xqc_send_queue_t *send_queue = conn->conn_send_queue;
    xqc_log(conn->log, XQC_LOG_DEBUG, "|sndq_packets_used:%ui|sndq_packets_used_bytes:%ui|sndq_packets_free:%ui|",
            send_queue->sndq_packets_used, send_queue->sndq_packets_used_bytes, send_queue->sndq_packets_free);
    xqc_send_queue_pre_destroy(send_queue);

    xqc_path_ctx_t *path = NULL;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|path:%ui|ctl_bytes_in_flight:%ui|",
                path->path_id, path->path_send_ctl->ctl_bytes_in_flight);

        path->path_send_ctl->ctl_bytes_in_flight = 0;
        for (xqc_pkt_num_space_t pns = 0; pns < XQC_PNS_N; ++pns) {
            path->path_send_ctl->ctl_bytes_ack_eliciting_inflight[pns] = 0;
        }

        xqc_path_schedule_buf_pre_destroy(send_queue, path);
    }
}

void
xqc_send_queue_drop_0rtt_packets(xqc_connection_t *conn)
{
    xqc_send_queue_t *send_queue = conn->conn_send_queue;

    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *packet_out;
    xqc_list_for_each_safe(pos, next, &send_queue->sndq_unacked_packets[XQC_PNS_APP_DATA]) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
            xqc_send_queue_remove_unacked(packet_out, send_queue);
            xqc_send_ctl_decrease_inflight(conn, packet_out);
            if (packet_out->po_origin == NULL) {
                xqc_conn_decrease_unacked_stream_ref(conn, packet_out);
            }
            xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);
        }
    }

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
            xqc_send_queue_remove_send(pos);
            xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);
        }
    }

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_lost_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
            xqc_send_queue_remove_lost(pos);
            xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);
        }
    }

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_pto_probe_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
            xqc_send_queue_remove_probe(pos);
            xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);
        }
    }

    xqc_list_head_t *pos_path, *next_path;
    xqc_path_ctx_t *path;
    xqc_list_for_each_safe(pos_path, next_path, &conn->conn_paths_list) {
        path = xqc_list_entry(pos_path, xqc_path_ctx_t, path_list);

        xqc_list_for_each_safe(pos, next, &path->path_schedule_buf[XQC_SEND_TYPE_NORMAL]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
                xqc_path_send_buffer_remove(path, packet_out);
                xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);
            }    
        }

        xqc_list_for_each_safe(pos, next, &path->path_schedule_buf[XQC_SEND_TYPE_RETRANS]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
                xqc_path_send_buffer_remove(path, packet_out);
                xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);
            }
        }

        xqc_list_for_each_safe(pos, next, &path->path_schedule_buf[XQC_SEND_TYPE_PTO_PROBE]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
                xqc_path_send_buffer_remove(path, packet_out);
                xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);
            }
        }
    }
}

void
xqc_send_queue_drop_packets_from_list_with_type(xqc_send_ctl_t *send_ctl, xqc_send_queue_t *send_queue, xqc_pkt_type_t type,
    xqc_list_head_t *list, const char *list_name, xqc_bool_t path_buffer)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *packet_out;

    xqc_list_for_each_safe(pos, next, list) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == type) {

            if (path_buffer) {
                xqc_path_send_buffer_remove(send_ctl->ctl_path, packet_out);

            } else {
                xqc_send_queue_remove_send(pos);
            }

            xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);

        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|drop pkt from %s list|inflight:%ud|cwnd:%ui|"
                "pkt_num:%ui|ptype:%d|frames:%s|len:%ud|", list_name, send_ctl->ctl_bytes_in_flight,
                send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong), packet_out->po_pkt.pkt_num, 
                packet_out->po_pkt.pkt_type, xqc_frame_type_2_str(send_ctl->ctl_conn->engine, packet_out->po_frame_types),
                packet_out->po_used_size);
        }
    }
}

void
xqc_send_queue_drop_packets_with_type(xqc_send_ctl_t *send_ctl, xqc_send_queue_t *send_queue, xqc_pkt_type_t type)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *packet_out;

    xqc_pkt_num_space_t pns = xqc_packet_type_to_pns(type);
    if (pns == XQC_PNS_N) {
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_ERROR, "|illegal packet type|type:%d|", type);
        return;
    }

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_unacked_packets[pns]) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        xqc_send_queue_remove_unacked(packet_out, send_queue);
        xqc_send_ctl_decrease_inflight(send_ctl->ctl_conn, packet_out);
        xqc_conn_decrease_unacked_stream_ref(send_ctl->ctl_conn, packet_out);
        xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);


        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|drop pkt from unacked|inflight:%ud|cwnd:%ui|"
                "pkt_num:%ui|ptype:%d|frames:%s|", send_ctl->ctl_bytes_in_flight, 
            send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong), packet_out->po_pkt.pkt_num, 
            packet_out->po_pkt.pkt_type, xqc_frame_type_2_str(send_ctl->ctl_conn->engine, packet_out->po_frame_types));
    }

    xqc_send_queue_drop_packets_from_list_with_type(send_ctl, send_queue, type, &send_queue->sndq_send_packets_high_pri, "high_pri", XQC_FALSE);
    xqc_send_queue_drop_packets_from_list_with_type(send_ctl, send_queue, type, &send_queue->sndq_send_packets, "send", XQC_FALSE);
    xqc_send_queue_drop_packets_from_list_with_type(send_ctl, send_queue, type, &send_queue->sndq_lost_packets, "lost", XQC_FALSE);
    xqc_send_queue_drop_packets_from_list_with_type(send_ctl, send_queue, type, &send_queue->sndq_pto_probe_packets, "pto_probe", XQC_FALSE);

    xqc_list_head_t *pos_path, *next_path;
    xqc_path_ctx_t *path;
    xqc_list_for_each_safe(pos_path, next_path, &send_queue->sndq_conn->conn_paths_list) {
        path = xqc_list_entry(pos_path, xqc_path_ctx_t, path_list);

        xqc_send_queue_drop_packets_from_list_with_type(send_ctl, send_queue, type, &path->path_schedule_buf[XQC_SEND_TYPE_NORMAL_HIGH_PRI], "path_high_pri", XQC_TRUE);
        xqc_send_queue_drop_packets_from_list_with_type(send_ctl, send_queue, type, &path->path_schedule_buf[XQC_SEND_TYPE_NORMAL], "path_send", XQC_TRUE);
        xqc_send_queue_drop_packets_from_list_with_type(send_ctl, send_queue, type, &path->path_schedule_buf[XQC_SEND_TYPE_RETRANS], "path_lost", XQC_TRUE);
        xqc_send_queue_drop_packets_from_list_with_type(send_ctl, send_queue, type, &path->path_schedule_buf[XQC_SEND_TYPE_PTO_PROBE], "path_pto_probe", XQC_TRUE);
    }
}

void xqc_send_queue_drop_initial_packets(xqc_connection_t *conn)
{
    /* initial packets are send on conn_initial_path */
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_send_queue_t *send_queue = conn->conn_send_queue;
    xqc_send_queue_drop_packets_with_type(send_ctl, send_queue, XQC_PTYPE_INIT);
    xqc_send_ctl_on_pns_discard(send_ctl, XQC_PNS_INIT);
    conn->max_acked_po_size = XQC_QUIC_MIN_MSS;
}


void xqc_send_queue_drop_handshake_packets(xqc_connection_t *conn)
{
    /* handshake packets are send on conn_initial_path */
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_send_queue_t *send_queue = conn->conn_send_queue;
    xqc_send_queue_drop_packets_with_type(send_ctl, send_queue, XQC_PTYPE_HSK);
    xqc_send_ctl_on_pns_discard(send_ctl, XQC_PNS_HSK);
}


int
xqc_send_ctl_stream_frame_can_drop(xqc_packet_out_t *packet_out, xqc_stream_id_t stream_id)
{
    int drop = 0;
    /* 
     * Attached ACK could lead to a situation
     * where an original packet (w/o ACK) can be removed but the corresponding 
     * replicated packet (w/ ACK) cannot be removed. This 
     * ultimately causes that the po_origin of the replicated packet (R) points to a new 
     * packet (N) to which the buffer of the original packet is reallocated. This is
     * very rare but may lead to a infinite loop or crash when the unacked list 
     * in xqc_send_ctl_detect_lost is traversed. For example, when N is next to R in the unacked list,
     * removing R may also free N via xqc_send_ctl_indirectly_ack_or_drop_po. If that
     * happens, an infinite loop that traversing the free_packets list is triggered.
     */
    uint64_t mask = ~(XQC_FRAME_BIT_STREAM | XQC_FRAME_BIT_ACK | XQC_FRAME_BIT_ACK_MP | XQC_FRAME_BIT_SID);
    if ((packet_out->po_frame_types & mask) == 0) {
        drop = 0;
        for (int i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
            if (packet_out->po_stream_frames[i].ps_is_used == 0) {
                break;
            }
            if (packet_out->po_stream_frames[i].ps_stream_id == stream_id) {
                drop = 1;

            } else {
                drop = 0;
                break;
            }
        }
    }
    return drop;
}

static xqc_bool_t xqc_enhanced_packet_can_drop(xqc_connection_t *conn,
    xqc_packet_out_t *packet, xqc_stream_id_t id);

static xqc_bool_t
xqc_enhanced_packet_can_drop(xqc_connection_t *conn,
    xqc_packet_out_t *packet, xqc_stream_id_t id)
{
    if (!xqc_send_ctl_stream_frame_can_drop(packet, id)) {
        return XQC_FALSE;
    }
    xqc_stream_t *stream = xqc_find_stream_by_id(id, conn->streams_hash);
    if (stream != NULL
        && stream->reset_at.send_state == XQC_RESET_AT_SENT)
    {
        for (int i = 0; i < packet->po_stream_frames_idx; i++) {
            xqc_po_stream_frame_t *frame = &packet->po_stream_frames[i];
            if (frame->ps_stream_id == id && frame->ps_length
                && frame->ps_offset < stream->reset_at.send_size)
            {
                return XQC_FALSE;
            }
        }
    }
    return XQC_TRUE;
}

static void
xqc_reset_stream_release_origin(xqc_connection_t *conn,
    xqc_packet_out_t *packet, xqc_stream_id_t stream_id)
{
    xqc_packet_out_t *origin = packet->po_origin;
    if (origin == NULL) {
        return;
    }

    packet->po_origin = NULL;
    if (origin->po_origin_ref_cnt == 0) {
        return;
    }
    origin->po_origin_ref_cnt--;
    if (origin->po_origin_ref_cnt != 0
        || !(origin->po_flag & XQC_POF_IN_UNACK_LIST)
        || !xqc_enhanced_packet_can_drop(conn, origin, stream_id))
    {
        return;
    }

    origin->po_flag |= XQC_POF_INFLIGHT_CANCELED;
    xqc_send_ctl_decrease_inflight(conn, origin);
    xqc_send_queue_remove_unacked(origin, conn->conn_send_queue);
    xqc_conn_decrease_unacked_stream_ref(conn, origin);
    xqc_send_queue_insert_free(origin,
        &conn->conn_send_queue->sndq_free_packets, conn->conn_send_queue);
}

void
xqc_send_queue_drop_stream_frame_packets(xqc_connection_t *conn, xqc_stream_id_t stream_id)
{
    xqc_send_queue_t *send_queue = conn->conn_send_queue;
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *packet_out;
    int drop;
    int count = 0;
    int to_drop = 0;

    /*
     * The previous code was too complicated. Now, we want to keep it as simple
     * as possible. To do so, we just drop all pkts belonging to the closed stream
     * and decrease inflight on corresponding paths carefully. This could have minor
     * impacts on congestion controllers. But, it is ok.
     */

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_unacked_packets[XQC_PNS_APP_DATA]) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        drop = xqc_enhanced_packet_can_drop(conn, packet_out, stream_id);
        if (drop) {
            if (packet_out->po_origin == NULL
                && packet_out->po_origin_ref_cnt != 0)
            {
                continue;
            }
            count++;
            packet_out->po_flag |= XQC_POF_INFLIGHT_CANCELED;
            xqc_send_ctl_decrease_inflight(conn, packet_out);
            xqc_send_queue_remove_unacked(packet_out, send_queue);
            if (packet_out->po_origin == NULL) {
                xqc_conn_decrease_unacked_stream_ref(conn, packet_out);

            } else {
                xqc_reset_stream_release_origin(conn, packet_out,
                                                stream_id);
            }
            xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);
        }
    }

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        drop = xqc_enhanced_packet_can_drop(conn, packet_out, stream_id);
        if (drop) {
            count++;
            xqc_send_queue_remove_send(pos);
            xqc_reset_stream_release_origin(conn, packet_out, stream_id);
            xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);
        }
    }

    xqc_list_for_each_safe(pos, next,
                           &send_queue->sndq_send_packets_high_pri)
    {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        drop = xqc_enhanced_packet_can_drop(conn, packet_out, stream_id);
        if (drop) {
            count++;
            xqc_send_queue_remove_send(pos);
            xqc_reset_stream_release_origin(conn, packet_out, stream_id);
            xqc_send_queue_insert_free(packet_out,
                &send_queue->sndq_free_packets, send_queue);
        }
    }

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_buff_1rtt_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        drop = xqc_enhanced_packet_can_drop(conn, packet_out, stream_id);
        if (drop) {
            count++;
            /*
             * Buffered packets still count toward sndq_packets_used.
             * Only unlink here; insert_free() decrements the count.
             * Using remove_buff() would decrement it twice.
             */
            xqc_send_queue_remove_send(pos);
            xqc_reset_stream_release_origin(conn, packet_out, stream_id);
            xqc_send_queue_insert_free(packet_out,
                &send_queue->sndq_free_packets, send_queue);
        }
    }

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_lost_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        drop = xqc_enhanced_packet_can_drop(conn, packet_out, stream_id);
        if (drop) {
            count++;
            xqc_send_queue_remove_lost(pos);
            xqc_reset_stream_release_origin(conn, packet_out, stream_id);
            xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);
        }
    }

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_pto_probe_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        drop = xqc_enhanced_packet_can_drop(conn, packet_out, stream_id);
        if (drop) {
            count++;
            xqc_send_queue_remove_probe(pos);
            xqc_reset_stream_release_origin(conn, packet_out, stream_id);
            xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);
        }
    }

    xqc_list_head_t *pos_path, *next_path;
    xqc_path_ctx_t *path;
    xqc_list_for_each_safe(pos_path, next_path, &conn->conn_paths_list) {
        path = xqc_list_entry(pos_path, xqc_path_ctx_t, path_list);

        for (int type = 0; type < XQC_SEND_TYPE_N; type++) {
            xqc_list_for_each_safe(pos, next,
                                   &path->path_schedule_buf[type])
            {
                packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
                drop = xqc_enhanced_packet_can_drop(conn, packet_out,
                                                        stream_id);
                if (drop) {
                    count++;
                    xqc_path_send_buffer_remove(path, packet_out);
                    xqc_reset_stream_release_origin(conn, packet_out,
                                                    stream_id);
                    xqc_send_queue_insert_free(packet_out,
                        &send_queue->sndq_free_packets, send_queue);
                }
            }
        }

        xqc_list_for_each_safe(pos, next, &path->path_reinj_tmp_buf) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            drop = xqc_enhanced_packet_can_drop(conn, packet_out,
                                                    stream_id);
            if (drop) {
                count++;
                xqc_path_send_buffer_remove(path, packet_out);
                xqc_reset_stream_release_origin(conn, packet_out, stream_id);
                xqc_send_queue_insert_free(packet_out,
                    &send_queue->sndq_free_packets, send_queue);
            }
        }
    }

    if (count > 0) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|stream_id:%ui|to_drop: %d|count:%d|", stream_id, to_drop, count);
    }
}
