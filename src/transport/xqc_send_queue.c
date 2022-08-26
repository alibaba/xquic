#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_conn.h"
#include "src/common/xqc_memory_pool.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_send_ctl.h"


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

    send_queue->sndq_packets_used_max = XQC_SNDQ_PACKETS_USED_MAX;

    send_queue->pkt_out_size = conn->conn_settings.max_pkt_out_size;

    send_queue->sndq_conn = conn;

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
    send_queue->sndq_packets_free = 0;
}

xqc_packet_out_t *
xqc_send_queue_get_packet_out(xqc_send_queue_t *send_queue, unsigned need, xqc_pkt_type_t pkt_type)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t  *pos;

    xqc_list_for_each_reverse(pos, &send_queue->sndq_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == pkt_type 
            && packet_out->po_buf_size - packet_out->po_used_size >= need)
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
xqc_send_queue_insert_send(xqc_list_head_t *pos, xqc_list_head_t *head, xqc_send_queue_t *send_queue)
{
    xqc_list_add_tail(pos, head);
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
xqc_send_queue_insert_free(xqc_list_head_t *pos, xqc_list_head_t *head, xqc_send_queue_t *send_queue)
{
    xqc_list_add_tail(pos, head);
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
    xqc_list_add_tail(&packet_out->po_list, head);
}

void
xqc_send_queue_remove_unacked(xqc_packet_out_t *packet_out, xqc_send_queue_t *send_queue)
{
    xqc_list_del_init(&packet_out->po_list);
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


void
xqc_send_queue_copy_to_lost(xqc_packet_out_t *packet_out, xqc_send_queue_t *send_queue)
{
    xqc_connection_t *conn = send_queue->sndq_conn;

    xqc_packet_out_t *new_po = xqc_packet_out_get(send_queue);
    if (!new_po) {
        XQC_CONN_ERR(conn, XQC_EMALLOC);
        return;
    }

    xqc_packet_out_copy(new_po, packet_out);

    int ret;

    if ((new_po->po_ack_offset > 0) && (new_po->po_frame_types & XQC_FRAME_BIT_ACK)) {
        new_po->po_frame_types &= ~XQC_FRAME_BIT_ACK;
        new_po->po_used_size = new_po->po_ack_offset;
        ret = xqc_write_ack_to_one_packet(conn, new_po, new_po->po_pkt.pkt_pns);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_WARN, "|xqc_write_ack_to_one_packet error|");
        }

    } else if ((new_po->po_ack_offset > 0) && (new_po->po_frame_types & XQC_FRAME_BIT_ACK_MP)) {
        new_po->po_frame_types &= ~XQC_FRAME_BIT_ACK_MP;
        new_po->po_used_size = new_po->po_ack_offset;
        xqc_path_ctx_t *path = xqc_conn_find_path_by_path_id(conn, new_po->po_path_id);
        if (path == NULL) {
            xqc_log(conn->log, XQC_LOG_WARN, "|xqc_conn_find_path_by_path_id error|");
        }
        ret = xqc_write_ack_mp_to_one_packet(conn, path, new_po, new_po->po_pkt.pkt_pns);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_WARN, "|xqc_write_ack_mp_to_one_packet error|");
        }
    }

    xqc_send_queue_insert_lost(&new_po->po_list, &send_queue->sndq_lost_packets);
    send_queue->sndq_packets_used++;
    packet_out->po_flag |= XQC_POF_RETRANSED;
}

void
xqc_send_queue_copy_to_probe(xqc_packet_out_t *packet_out, xqc_send_queue_t *send_queue)
{
    xqc_connection_t *conn = send_queue->sndq_conn;

    xqc_packet_out_t *new_po = xqc_packet_out_get(send_queue);
    if (!new_po) {
        XQC_CONN_ERR(conn, XQC_EMALLOC);
        return;
    }

    xqc_packet_out_copy(new_po, packet_out);

    int ret;

    if ((new_po->po_ack_offset > 0) && (new_po->po_frame_types & XQC_FRAME_BIT_ACK)) {
        new_po->po_frame_types &= ~XQC_FRAME_BIT_ACK;
        new_po->po_used_size = new_po->po_ack_offset;
        ret = xqc_write_ack_to_one_packet(conn, new_po, new_po->po_pkt.pkt_pns);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_WARN, "|xqc_write_ack_to_one_packet error|");
        }

    } else if ((new_po->po_ack_offset > 0) && (new_po->po_frame_types & XQC_FRAME_BIT_ACK_MP)) {
        new_po->po_frame_types &= ~XQC_FRAME_BIT_ACK_MP;
        new_po->po_used_size = new_po->po_ack_offset;
        xqc_path_ctx_t *path = xqc_conn_find_path_by_path_id(conn, new_po->po_path_id);
        if (path == NULL) {
            xqc_log(conn->log, XQC_LOG_WARN, "|xqc_conn_find_path_by_path_id error|");
        }
        ret = xqc_write_ack_mp_to_one_packet(conn, path, new_po, new_po->po_pkt.pkt_pns);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_WARN, "|xqc_write_ack_mp_to_one_packet error|");
        }
    }

    xqc_send_queue_insert_probe(&new_po->po_list, &send_queue->sndq_pto_probe_packets);
    send_queue->sndq_packets_used++;
    packet_out->po_flag |= XQC_POF_RETRANSED;
}


void
xqc_send_queue_drop_packets(xqc_connection_t *conn)
{
    xqc_send_queue_t *send_queue = conn->conn_send_queue;
    xqc_log(conn->log, XQC_LOG_DEBUG, "|sndq_packets_used:%ud|sndq_packets_free:%ud|",
            send_queue->sndq_packets_used, send_queue->sndq_packets_free);
    xqc_send_queue_destroy(send_queue);

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

        xqc_path_schedule_buf_destroy(path);
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
            xqc_send_queue_insert_free(pos, &send_queue->sndq_free_packets, send_queue);
            xqc_send_ctl_decrease_inflight(conn, packet_out);
            if (packet_out->po_origin == NULL) {
                xqc_conn_decrease_unacked_stream_ref(conn, packet_out);
            }
        }
    }

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
            xqc_send_queue_remove_send(pos);
            xqc_send_queue_insert_free(pos, &send_queue->sndq_free_packets, send_queue);
        }
    }

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_lost_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
            xqc_send_queue_remove_lost(pos);
            xqc_send_queue_insert_free(pos, &send_queue->sndq_free_packets, send_queue);
        }
    }

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_pto_probe_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
            xqc_send_queue_remove_probe(pos);
            xqc_send_queue_insert_free(pos, &send_queue->sndq_free_packets, send_queue);
        }
    }

    xqc_list_head_t *pos_path, *next_path;
    xqc_path_ctx_t *path;
    xqc_list_for_each_safe(pos_path, next_path, &conn->conn_paths_list) {
        path = xqc_list_entry(pos_path, xqc_path_ctx_t, path_list);

        xqc_list_for_each_safe(pos, next, &path->path_schedule_buf[XQC_SEND_TYPE_NORMAL]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
                xqc_send_queue_remove_send(pos);
                xqc_send_queue_insert_free(pos, &send_queue->sndq_free_packets, send_queue);
            }
        }

        xqc_list_for_each_safe(pos, next, &path->path_schedule_buf[XQC_SEND_TYPE_RETRANS]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
                xqc_send_queue_remove_lost(pos);
                xqc_send_queue_insert_free(pos, &send_queue->sndq_free_packets, send_queue);
            }
        }

        xqc_list_for_each_safe(pos, next, &path->path_schedule_buf[XQC_SEND_TYPE_PTO_PROBE]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
                xqc_send_queue_remove_probe(pos);
                xqc_send_queue_insert_free(pos, &send_queue->sndq_free_packets, send_queue);
            }
        }
    }
}

void
xqc_send_queue_drop_packets_from_list_with_type(xqc_send_ctl_t *send_ctl, xqc_send_queue_t *send_queue, xqc_pkt_type_t type,
    xqc_list_head_t *list, const char *list_name)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *packet_out;

    xqc_list_for_each_safe(pos, next, list) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == type) {
            xqc_send_queue_remove_send(pos);
            xqc_send_queue_insert_free(pos, &send_queue->sndq_free_packets, send_queue);

        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|drop pkt from %s list|inflight:%ud|cwnd:%ui|"
                "pkt_num:%ui|ptype:%d|frames:%s|len:%ud|", list_name, send_ctl->ctl_bytes_in_flight,
                send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong), packet_out->po_pkt.pkt_num, 
                packet_out->po_pkt.pkt_type, xqc_frame_type_2_str(packet_out->po_frame_types),
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
        xqc_send_queue_insert_free(pos, &send_queue->sndq_free_packets, send_queue);
        xqc_send_ctl_decrease_inflight(send_ctl->ctl_conn, packet_out);
        xqc_conn_decrease_unacked_stream_ref(send_ctl->ctl_conn, packet_out);

        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|drop pkt from unacked|inflight:%ui|cwnd:%ui|"
                "pkt_num:%ui|ptype:%d|frames:%s|", send_ctl->ctl_bytes_in_flight, 
            send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong), packet_out->po_pkt.pkt_num, 
            packet_out->po_pkt.pkt_type, xqc_frame_type_2_str(packet_out->po_frame_types));
    }

    xqc_send_queue_drop_packets_from_list_with_type(send_ctl, send_queue, type, &send_queue->sndq_send_packets_high_pri, "high_pri");
    xqc_send_queue_drop_packets_from_list_with_type(send_ctl, send_queue, type, &send_queue->sndq_send_packets, "send");
    xqc_send_queue_drop_packets_from_list_with_type(send_ctl, send_queue, type, &send_queue->sndq_lost_packets, "lost");
    xqc_send_queue_drop_packets_from_list_with_type(send_ctl, send_queue, type, &send_queue->sndq_pto_probe_packets, "pto_probe");

    xqc_list_head_t *pos_path, *next_path;
    xqc_path_ctx_t *path;
    xqc_list_for_each_safe(pos_path, next_path, &send_queue->sndq_conn->conn_paths_list) {
        path = xqc_list_entry(pos_path, xqc_path_ctx_t, path_list);

        xqc_send_queue_drop_packets_from_list_with_type(send_ctl, send_queue, type, &path->path_schedule_buf[XQC_SEND_TYPE_NORMAL_HIGH_PRI], "path_high_pri");
        xqc_send_queue_drop_packets_from_list_with_type(send_ctl, send_queue, type, &path->path_schedule_buf[XQC_SEND_TYPE_NORMAL], "path_send");
        xqc_send_queue_drop_packets_from_list_with_type(send_ctl, send_queue, type, &path->path_schedule_buf[XQC_SEND_TYPE_RETRANS], "path_lost");
        xqc_send_queue_drop_packets_from_list_with_type(send_ctl, send_queue, type, &path->path_schedule_buf[XQC_SEND_TYPE_PTO_PROBE], "path_pto_probe");
    }
}

void xqc_send_queue_drop_initial_packets(xqc_connection_t *conn)
{
    /* initial packets are send on conn_initial_path */
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_send_queue_t *send_queue = conn->conn_send_queue;
    xqc_send_queue_drop_packets_with_type(send_ctl, send_queue, XQC_PTYPE_INIT);
    xqc_send_ctl_on_pns_discard(send_ctl, XQC_PNS_INIT);
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
    if (packet_out->po_frame_types == XQC_FRAME_BIT_STREAM) {
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
        if (packet_out->po_frame_types == XQC_FRAME_BIT_STREAM) {
            drop = xqc_send_ctl_stream_frame_can_drop(packet_out, stream_id);
            if (drop) {
                count++;
                xqc_send_ctl_decrease_inflight(conn, packet_out);
                xqc_send_queue_remove_unacked(packet_out, send_queue);
                xqc_send_queue_insert_free(pos, &send_queue->sndq_free_packets, send_queue);
            }
        }
    }

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_frame_types == XQC_FRAME_BIT_STREAM) {
            drop = xqc_send_ctl_stream_frame_can_drop(packet_out, stream_id);
            if (drop) {
                count++;
                xqc_send_queue_remove_send(pos);
                xqc_send_queue_insert_free(pos, &send_queue->sndq_free_packets, send_queue);
            }
        }
    }

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_lost_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_frame_types == XQC_FRAME_BIT_STREAM) {
            drop = xqc_send_ctl_stream_frame_can_drop(packet_out, stream_id);
            if (drop) {
                count++;
                xqc_send_queue_remove_lost(pos);
                xqc_send_queue_insert_free(pos, &send_queue->sndq_free_packets, send_queue);
            }
        }
    }

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_pto_probe_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_frame_types == XQC_FRAME_BIT_STREAM) {
            drop = xqc_send_ctl_stream_frame_can_drop(packet_out, stream_id);
            if (drop) {
                count++;
                xqc_send_queue_remove_probe(pos);
                xqc_send_queue_insert_free(pos, &send_queue->sndq_free_packets, send_queue);
            }
        }
    }

    xqc_list_head_t *pos_path, *next_path;
    xqc_path_ctx_t *path;
    xqc_list_for_each_safe(pos_path, next_path, &conn->conn_paths_list) {
        path = xqc_list_entry(pos_path, xqc_path_ctx_t, path_list);

        xqc_list_for_each_safe(pos, next, &path->path_schedule_buf[XQC_SEND_TYPE_NORMAL]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (packet_out->po_frame_types == XQC_FRAME_BIT_STREAM) {
                drop = xqc_send_ctl_stream_frame_can_drop(packet_out, stream_id);
                if (drop) {
                    count++;
                    xqc_send_queue_remove_send(pos);
                    xqc_send_queue_insert_free(pos, &send_queue->sndq_free_packets, send_queue);
                }
            }
        }

        xqc_list_for_each_safe(pos, next, &path->path_schedule_buf[XQC_SEND_TYPE_RETRANS]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (packet_out->po_frame_types == XQC_FRAME_BIT_STREAM) {
                drop = xqc_send_ctl_stream_frame_can_drop(packet_out, stream_id);
                if (drop) {
                    count++;
                    xqc_send_queue_remove_lost(pos);
                    xqc_send_queue_insert_free(pos, &send_queue->sndq_free_packets, send_queue);
                }
            }
        }

        xqc_list_for_each_safe(pos, next, &path->path_schedule_buf[XQC_SEND_TYPE_PTO_PROBE]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (packet_out->po_frame_types == XQC_FRAME_BIT_STREAM) {
                drop = xqc_send_ctl_stream_frame_can_drop(packet_out, stream_id);
                if (drop) {
                    count++;
                    xqc_send_queue_remove_probe(pos);
                    xqc_send_queue_insert_free(pos, &send_queue->sndq_free_packets, send_queue);
                }
            }
        }
    }

    if (count > 0) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|stream_id:%ui|to_drop: %d|count:%d|", stream_id, to_drop, count);
    }
}