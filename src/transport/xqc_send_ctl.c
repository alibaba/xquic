/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/congestion_control/xqc_bbr.h"
#include "src/congestion_control/xqc_bbr2.h"
#include "src/congestion_control/xqc_cubic.h"
#include "src/congestion_control/xqc_bbr_common.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_pacing.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_stream.h"
#include "src/common/xqc_memory_pool.h"
#include "src/congestion_control/xqc_sample.h"
#include "src/transport/xqc_pacing.h"
#include "src/transport/xqc_utils.h"

int
xqc_send_ctl_indirectly_ack_po(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    xqc_path_ctx_t *path = xqc_conn_find_path_by_path_id(conn, packet_out->po_path_id);
    if (path == NULL) {
        return XQC_FALSE;
    }

    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    xqc_send_queue_t *send_queue = conn->conn_send_queue;

    if (packet_out->po_acked
        || (packet_out->po_origin && packet_out->po_origin->po_acked))
    {
        if (packet_out->po_origin && packet_out->po_origin->po_acked) {
            /* We should not do congestion control here. */
            xqc_send_ctl_on_packet_acked(send_ctl, packet_out, 0, 0);
        }
        xqc_send_queue_maybe_remove_unacked(packet_out, send_queue, path);
        return XQC_TRUE;
    }
    return XQC_FALSE;
}


xqc_send_ctl_t *
xqc_send_ctl_create(xqc_path_ctx_t *path)
{
    xqc_connection_t *conn = path->parent_conn;

    xqc_send_ctl_t *send_ctl;
    send_ctl = xqc_pcalloc(conn->conn_pool, sizeof(xqc_send_ctl_t));
    if (send_ctl == NULL) {
        return NULL;
    }

    send_ctl->ctl_path = path;
    send_ctl->ctl_conn = conn;

    send_ctl->ctl_pto_count = 0;
    send_ctl->ctl_pto_count_since_last_tra_path_status_changed = 0;
    send_ctl->ctl_minrtt = XQC_MAX_UINT32_VALUE;
    send_ctl->ctl_srtt = XQC_kInitialRtt * 1000;
    send_ctl->ctl_rttvar = XQC_kInitialRtt * 1000 / 2;
    send_ctl->ctl_max_bytes_in_flight = 0;
    send_ctl->ctl_reordering_packet_threshold = XQC_kPacketThreshold;
    send_ctl->ctl_reordering_time_threshold_shift = XQC_kTimeThresholdShift;

    for (size_t i = 0; i < XQC_PNS_N; i++) {
        xqc_sent_record_init(&send_ctl->ctl_sent_record[i]);
        send_ctl->ctl_largest_acked[i] = XQC_MAX_UINT64_VALUE;
        send_ctl->ctl_largest_received[i] = XQC_MAX_UINT64_VALUE;
        send_ctl->ctl_unack_received[i] = XQC_MAX_UINT64_VALUE;
        send_ctl->ctl_time_of_last_sent_ack_eliciting_packet[i] = 0;
        send_ctl->ctl_loss_time[i] = 0;
    }

    memset(&send_ctl->ctl_largest_acked_sent_time, 0,
           sizeof(send_ctl->ctl_largest_acked_sent_time));

    memset(&send_ctl->ctl_largest_recv_time, 0,
           sizeof(send_ctl->ctl_largest_recv_time));

    send_ctl->ctl_is_cwnd_limited = 0;
    send_ctl->ctl_delivered = 0;
    send_ctl->ctl_lost_pkts_number = 0;
    send_ctl->ctl_last_inflight_pkt_sent_time = 0;

    xqc_timer_init(&send_ctl->path_timer_manager, conn->log, send_ctl);
    xqc_timer_set(&send_ctl->path_timer_manager, XQC_TIMER_PATH_IDLE,
                  xqc_monotonic_timestamp(), xqc_path_get_idle_timeout(path) * 1000);

    if (conn->conn_settings.cong_ctrl_callback.xqc_cong_ctl_init_bbr) {
        send_ctl->ctl_cong_callback = &conn->conn_settings.cong_ctrl_callback;

    } else if (conn->conn_settings.cong_ctrl_callback.xqc_cong_ctl_init) {
        send_ctl->ctl_cong_callback = &conn->conn_settings.cong_ctrl_callback;

    } else {
        send_ctl->ctl_cong_callback = &xqc_cubic_cb;
    }
    send_ctl->ctl_cong = xqc_pcalloc(conn->conn_pool, send_ctl->ctl_cong_callback->xqc_cong_ctl_size());

    if (conn->conn_settings.cong_ctrl_callback.xqc_cong_ctl_init_bbr) {
        send_ctl->ctl_cong_callback->xqc_cong_ctl_init_bbr(send_ctl->ctl_cong,
                                                           &send_ctl->sampler, conn->conn_settings.cc_params);

    } else {
        send_ctl->ctl_cong_callback->xqc_cong_ctl_init(send_ctl->ctl_cong, send_ctl, conn->conn_settings.cc_params);
    }

    xqc_pacing_init(&send_ctl->ctl_pacing, conn->conn_settings.pacing_on, send_ctl);

    send_ctl->ctl_info.record_interval = XQC_DEFAULT_RECORD_INTERVAL;
    send_ctl->ctl_info.last_record_time = 0;
    send_ctl->ctl_info.last_rtt_time = 0;
    send_ctl->ctl_info.last_lost_time = 0;
    send_ctl->ctl_info.last_bw_time = 0;
    send_ctl->ctl_info.rtt_change_threshold = XQC_DEFAULT_RTT_CHANGE_THRESHOLD;
    send_ctl->ctl_info.bw_change_threshold = XQC_DEFAULT_BW_CHANGE_THRESHOLD;

    send_ctl->sampler.send_ctl = send_ctl;

    xqc_log_event(conn->log, REC_PARAMETERS_SET, send_ctl);
    return send_ctl;
}

void
xqc_send_ctl_destroy(xqc_send_ctl_t *send_ctl)
{
    xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|destroy|");

    /* 从上到下4个pns的遍历，全都不一样 */
    for (xqc_pkt_num_space_t pns = 0; pns < XQC_PNS_N; ++pns) {
        xqc_sent_record_release(&send_ctl->ctl_sent_record[pns]);
        send_ctl->ctl_bytes_ack_eliciting_inflight[pns] = 0;
    }

    send_ctl->ctl_bytes_in_flight = 0;
}

void
xqc_send_ctl_reset(xqc_send_ctl_t *send_ctl)
{
    xqc_connection_t *conn = send_ctl->ctl_conn;
    xqc_path_ctx_t *path = send_ctl->ctl_path;

    send_ctl->ctl_pto_count = 0;
    send_ctl->ctl_pto_count_since_last_tra_path_status_changed = 0;
    send_ctl->ctl_minrtt = XQC_MAX_UINT32_VALUE;
    send_ctl->ctl_srtt = XQC_kInitialRtt * 1000;
    send_ctl->ctl_rttvar = XQC_kInitialRtt * 1000 / 2;
    send_ctl->ctl_max_bytes_in_flight = 0;
    send_ctl->ctl_reordering_packet_threshold = XQC_kPacketThreshold;
    send_ctl->ctl_reordering_time_threshold_shift = XQC_kTimeThresholdShift;

    for (size_t i = 0; i < XQC_PNS_N; i++) {
        xqc_sent_record_init(&send_ctl->ctl_sent_record[i]);
        send_ctl->ctl_largest_acked[i] = XQC_MAX_UINT64_VALUE;
        send_ctl->ctl_largest_received[i] = XQC_MAX_UINT64_VALUE;
        send_ctl->ctl_unack_received[i] = XQC_MAX_UINT64_VALUE;
        send_ctl->ctl_time_of_last_sent_ack_eliciting_packet[i] = 0;
        send_ctl->ctl_loss_time[i] = 0;
    }

    memset(&send_ctl->ctl_largest_acked_sent_time, 0,
           sizeof(send_ctl->ctl_largest_acked_sent_time));

    memset(&send_ctl->ctl_largest_recv_time, 0,
           sizeof(send_ctl->ctl_largest_recv_time));

    send_ctl->ctl_is_cwnd_limited = 0;
    send_ctl->ctl_delivered = 0;
    send_ctl->ctl_lost_pkts_number = 0;
    send_ctl->ctl_last_inflight_pkt_sent_time = 0;

    xqc_timer_init(&send_ctl->path_timer_manager, conn->log, send_ctl);
    xqc_timer_set(&send_ctl->path_timer_manager, XQC_TIMER_PATH_IDLE,
                  xqc_monotonic_timestamp(), xqc_path_get_idle_timeout(path) * 1000);

    xqc_pacing_init(&send_ctl->ctl_pacing, conn->conn_settings.pacing_on, send_ctl);

    send_ctl->ctl_info.record_interval = XQC_DEFAULT_RECORD_INTERVAL;
    send_ctl->ctl_info.last_record_time = 0;
    send_ctl->ctl_info.last_rtt_time = 0;
    send_ctl->ctl_info.last_lost_time = 0;
    send_ctl->ctl_info.last_bw_time = 0;
    send_ctl->ctl_info.rtt_change_threshold = XQC_DEFAULT_RTT_CHANGE_THRESHOLD;
    send_ctl->ctl_info.bw_change_threshold = XQC_DEFAULT_BW_CHANGE_THRESHOLD;

    send_ctl->sampler.send_ctl = send_ctl;

    /*
     * Move all sent/unsent packets to the send queue for resending
     * Initial packets and 0-RTT packets with new packet header.
     * 
     * TODO: Refactoring packet generation: generate packet header before sent.
     * Then all we need to do is move the packets from the unack queue to the
     * send queue, and the rest of the queues will send normally.
     */

    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *packet_out;
    xqc_send_queue_t *send_queue = conn->conn_send_queue;

    for (xqc_pkt_num_space_t pns = 0; pns < XQC_PNS_N; ++pns) {
        xqc_list_for_each_safe(pos, next, &send_queue->sndq_unacked_packets[pns]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            xqc_send_queue_remove_unacked(packet_out, send_queue);
            xqc_send_queue_move_to_tail(pos, &send_queue->sndq_send_packets);
            xqc_send_ctl_decrease_inflight(conn, packet_out);
        }
    }

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_send_packets_high_pri) {
        xqc_send_queue_move_to_tail(pos, &send_queue->sndq_send_packets);
    }

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_lost_packets) {
        xqc_send_queue_move_to_tail(pos, &send_queue->sndq_send_packets);
    }

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_pto_probe_packets) {
        xqc_send_queue_move_to_tail(pos, &send_queue->sndq_send_packets);
    }

    xqc_log_event(conn->log, REC_PARAMETERS_SET, send_ctl);
}

xqc_pn_ctl_t *
xqc_pn_ctl_create(xqc_connection_t *conn)
{
    xqc_pn_ctl_t *pn_ctl;
    pn_ctl = xqc_pcalloc(conn->conn_pool, sizeof(xqc_pn_ctl_t));
    if (pn_ctl == NULL) {
        return NULL;
    }

    for (xqc_pkt_num_space_t i = XQC_PNS_INIT; i < XQC_PNS_N; i++) {
        xqc_memzero(&pn_ctl->ctl_recv_record[i], sizeof(xqc_recv_record_t));
        xqc_init_list_head(&pn_ctl->ctl_recv_record[i].list_head);
    }

    for (xqc_pkt_num_space_t i = XQC_PNS_INIT; i < XQC_PNS_N; i++) {
        if (xqc_ack_sent_record_init(&pn_ctl->ack_sent_record[i]) == XQC_ERROR) {
            return NULL;
        }
    }

    return pn_ctl;
}

void
xqc_pn_ctl_destroy(xqc_pn_ctl_t *pn_ctl)
{
    for (xqc_pkt_num_space_t pns = XQC_PNS_INIT; pns < XQC_PNS_N; pns++) {
        xqc_recv_record_destroy(&pn_ctl->ctl_recv_record[pns]);
    }

    for (xqc_pkt_num_space_t pns = XQC_PNS_INIT; pns < XQC_PNS_N; pns++) {
        xqc_ack_sent_record_destroy(&pn_ctl->ack_sent_record[pns]);
    }
}


xqc_pn_ctl_t *
xqc_get_pn_ctl(xqc_connection_t *conn, xqc_path_ctx_t *path)
{
    if (conn->enable_multipath == XQC_CONN_MULTIPATH_SINGLE_PNS) {
        return conn->conn_initial_path->path_pn_ctl;
    }

    return path->path_pn_ctl;
}

void 
xqc_send_ctl_info_circle_record(xqc_send_ctl_t *send_ctl)
{
    xqc_connection_t *conn = send_ctl->ctl_conn;
    if (conn->conn_type != XQC_CONN_TYPE_SERVER) {
        return; /* client do not need record */
    }
    if (conn->log->log_level < XQC_LOG_STATS) {
        return;
    }

    xqc_send_ctl_info_t *ctl_info = &send_ctl->ctl_info;

    xqc_usec_t now = xqc_monotonic_timestamp();
    if (ctl_info->record_interval < 10000) { /* minimum 10ms interval to avoid log flooding */
        return;
    }

    if (ctl_info->last_record_time + ctl_info->record_interval > now) { /* not yet time to record */
        return;
    }
    ctl_info->last_record_time = now;

    uint64_t cwnd = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong);

    uint64_t bw = 0;
    uint64_t pacing_rate = 0;
    int mode = 0;
    int recovery = 0;
    int slow_start = 0;
    xqc_usec_t min_rtt = 0;

    if (send_ctl->ctl_cong_callback->xqc_cong_ctl_init_bbr) {
        bw = send_ctl->ctl_cong_callback->
             xqc_cong_ctl_get_bandwidth_estimate(send_ctl->ctl_cong);
        pacing_rate = send_ctl->ctl_cong_callback->
                      xqc_cong_ctl_get_pacing_rate(send_ctl->ctl_cong);
        mode = send_ctl->ctl_cong_callback->
               xqc_cong_ctl_info_cb->mode(send_ctl->ctl_cong);
        min_rtt = send_ctl->ctl_cong_callback->
                  xqc_cong_ctl_info_cb->min_rtt(send_ctl->ctl_cong);
    }
    recovery = send_ctl->ctl_cong_callback->xqc_cong_ctl_in_recovery(send_ctl->ctl_cong);
    if (send_ctl->ctl_cong_callback->xqc_cong_ctl_in_slow_start) {
        slow_start = send_ctl->ctl_cong_callback->xqc_cong_ctl_in_slow_start(send_ctl->ctl_cong);
    }
    uint64_t srtt = send_ctl->ctl_srtt;
    xqc_conn_log(conn, XQC_LOG_STATS,
                 "|path:%ui|"
                 "|cwnd:%ui|inflight:%ud|mode:%ud|applimit:%ud|pacing_rate:%ui|bw:%ui|"
                 "srtt:%ui|latest_rtt:%ui|min_rtt:%ui|send:%ud|lost:%ud|tlp:%ud|recv:%ud|"
                 "recovery:%ud|slow_start:%ud|conn_life:%ui|acked:%ui|delivered:%ui|"
                 "is_cwnd_limited:%d|",
                 send_ctl->ctl_path->path_id,
                 cwnd, send_ctl->ctl_bytes_in_flight,
                 mode, send_ctl->ctl_app_limited, pacing_rate, bw,
                 srtt, send_ctl->ctl_latest_rtt, min_rtt,
                 send_ctl->ctl_send_count, send_ctl->ctl_lost_count,
                 send_ctl->ctl_tlp_count,
                 send_ctl->ctl_recv_count,
                 recovery, slow_start,
                 now - conn->conn_create_time,
                 send_ctl->ctl_delivered - send_ctl->ctl_prior_delivered,
                 send_ctl->ctl_delivered,
                 send_ctl->ctl_is_cwnd_limited);

}


/*
 * QUIC's congestion control is based on TCP NewReno [RFC6582].  NewReno
 * is a congestion window based congestion control.  QUIC specifies the
 * congestion window in bytes rather than packets due to finer control
 * and the ease of appropriate byte counting [RFC3465].
 *
 * QUIC hosts MUST NOT send packets if they would increase
 * bytes_in_flight (defined in Appendix B.2) beyond the available
 * congestion window, unless the packet is a probe packet sent after a
 * PTO timer expires, as described in Section 6.3.

 * Implementations MAY use other congestion control algorithms, such as
 * Cubic [RFC8312], and endpoints MAY use different algorithms from one
 * another.  The signals QUIC provides for congestion control are
 * generic and are designed to support different algorithms.
 */
int
xqc_send_ctl_can_send(xqc_send_ctl_t *send_ctl, xqc_packet_out_t *packet_out, uint32_t schedule_bytes)
{
    xqc_connection_t *conn = send_ctl->ctl_conn;

    int can = 1;
    unsigned congestion_window = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong);

    if (conn->conn_settings.so_sndbuf > 0) {
        congestion_window = xqc_min(congestion_window, conn->conn_settings.so_sndbuf);
    }

    if (send_ctl->ctl_bytes_in_flight + schedule_bytes + packet_out->po_used_size > congestion_window) {
        can = 0;
    }

    xqc_conn_log(conn, XQC_LOG_DEBUG,
                 "|path:%ui|can:%d|pkt_sz:%ud|schedule_bytes:%ud|inflight:%ud|cwnd:%ud|conn:%p|stream_id:%ui|stream_offset:%ui|",
                 send_ctl->ctl_path->path_id,
                 can, packet_out->po_used_size, schedule_bytes, send_ctl->ctl_bytes_in_flight,
                 congestion_window, conn,
                 packet_out->po_stream_id, packet_out->po_stream_offset);
    return can;
}

xqc_bool_t
xqc_send_packet_cwnd_allows(xqc_send_ctl_t *send_ctl, 
    xqc_packet_out_t *packet_out, uint32_t schedule_bytes)
{
    xqc_connection_t *conn = send_ctl->ctl_conn;

    if (XQC_CAN_IN_FLIGHT(packet_out->po_frame_types)) {
        /* packet with high priority first */
        if (!xqc_send_ctl_can_send(send_ctl, packet_out, schedule_bytes)) {
            xqc_log(conn->log, XQC_LOG_DEBUG, 
                    "|blocked by congestion control|");
            return XQC_FALSE;
        }
    }

    return XQC_TRUE;
}

xqc_bool_t
xqc_send_packet_pacer_allows(xqc_send_ctl_t *send_ctl, 
    xqc_packet_out_t *packet_out, uint32_t schedule_bytes)
{
    xqc_connection_t *conn = send_ctl->ctl_conn;

    if (XQC_CAN_IN_FLIGHT(packet_out->po_frame_types)) {

        if (xqc_pacing_is_on(&send_ctl->ctl_pacing)) {
            if (!xqc_pacing_can_write(&send_ctl->ctl_pacing, 
                    schedule_bytes + packet_out->po_used_size)) 
            {
                xqc_log(conn->log, XQC_LOG_DEBUG, "|pacing blocked|");
                return XQC_FALSE;
            }
        }
    }

    return XQC_TRUE;
}

xqc_bool_t
xqc_send_packet_check_cc(xqc_send_ctl_t *send_ctl, 
    xqc_packet_out_t *po, uint32_t schedule_bytes)
{
    return xqc_send_packet_cwnd_allows(send_ctl, po, schedule_bytes)
           && xqc_send_packet_pacer_allows(send_ctl, po, schedule_bytes);
}


void
xqc_send_queue_maybe_remove_unacked(xqc_packet_out_t *packet_out, xqc_send_queue_t *send_queue, xqc_path_ctx_t *path)
{
    /* it is origin & some pkt ref to this packet */
    if (packet_out->po_origin == NULL && packet_out->po_origin_ref_cnt != 0) {
        return;
    }

    if (path && (packet_out->po_flag & XQC_POF_IN_PATH_BUF_LIST)) {
        xqc_path_send_buffer_remove(path, packet_out);

    } else {
        xqc_send_queue_remove_unacked(packet_out, send_queue);
    }

    if (packet_out->po_origin
        && (--packet_out->po_origin->po_origin_ref_cnt) == 0)
    {
        /* po_origin could be an inflight one, thus requiring decrease inflight. */
        xqc_send_ctl_decrease_inflight(send_queue->sndq_conn, packet_out->po_origin);
        xqc_send_queue_remove_unacked(packet_out->po_origin, send_queue); /* TODO: ensure reinject packet will in path buf (not support yet) */
        xqc_send_queue_insert_free(packet_out->po_origin, &send_queue->sndq_free_packets, send_queue);
    }

    xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);
}

void
xqc_send_ctl_on_reset_stream_acked(xqc_send_ctl_t *send_ctl, xqc_packet_out_t *packet_out)
{
    if (packet_out->po_frame_types & XQC_FRAME_BIT_RESET_STREAM) {
        xqc_stream_t *stream;
        for (int i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
            if (packet_out->po_stream_frames[i].ps_is_used == 0) {
                break;
            }
            stream = xqc_find_stream_by_id(packet_out->po_stream_frames[i].ps_stream_id, send_ctl->ctl_conn->streams_hash);
            if (stream != NULL && packet_out->po_stream_frames[i].ps_is_reset) {
                if (stream->stream_state_send == XQC_SEND_STREAM_ST_RESET_SENT) {
                    xqc_stream_send_state_update(stream, XQC_SEND_STREAM_ST_RESET_RECVD);
                    xqc_stream_maybe_need_close(stream);
                }
            }
        }
    }
}

void
xqc_send_ctl_increase_inflight(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    xqc_path_ctx_t *path = xqc_conn_find_path_by_path_id(conn, packet_out->po_path_id);
    if (path == NULL) {
        xqc_log(conn->log, XQC_LOG_WARN, "|can't find path by id|%L|", packet_out->po_path_id);
        return;
    }

    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    if (!(packet_out->po_flag & XQC_POF_IN_FLIGHT) && XQC_CAN_IN_FLIGHT(packet_out->po_frame_types)) {
        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            send_ctl->ctl_bytes_in_flight += packet_out->po_used_size;
            send_ctl->ctl_bytes_ack_eliciting_inflight[packet_out->po_pkt.pkt_pns] += packet_out->po_used_size;
            packet_out->po_flag |= XQC_POF_IN_FLIGHT;
        }
    }
}

void
xqc_send_ctl_decrease_inflight(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    xqc_path_ctx_t *path = xqc_conn_find_path_by_path_id(conn, packet_out->po_path_id);
    if (path == NULL) {
        xqc_log(conn->log, XQC_LOG_WARN, "|can't find path by id|%L|", packet_out->po_path_id);
        return;
    }

    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    if (packet_out->po_flag & XQC_POF_IN_FLIGHT) {
        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            if (send_ctl->ctl_bytes_ack_eliciting_inflight[packet_out->po_pkt.pkt_pns] < packet_out->po_used_size) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|ctl_bytes_in_flight too small|");
                send_ctl->ctl_bytes_ack_eliciting_inflight[packet_out->po_pkt.pkt_pns] = 0;
                send_ctl->ctl_bytes_in_flight = 0;

            } else {
                send_ctl->ctl_bytes_ack_eliciting_inflight[packet_out->po_pkt.pkt_pns] -= packet_out->po_used_size;
                send_ctl->ctl_bytes_in_flight -= packet_out->po_used_size;
            }
            packet_out->po_flag &= ~XQC_POF_IN_FLIGHT;
        }
    }
}

void
xqc_send_ctl_on_pns_discard(xqc_send_ctl_t *send_ctl, xqc_pkt_num_space_t pns)
{
    send_ctl->ctl_time_of_last_sent_ack_eliciting_packet[pns] = 0;
    send_ctl->ctl_loss_time[pns] = 0;
    send_ctl->ctl_pto_count = 0;
    send_ctl->ctl_pto_count_since_last_tra_path_status_changed = 0;
    xqc_log(send_ctl->ctl_conn->log, XQC_LOG_INFO, "|xqc_send_ctl_set_loss_detection_timer on discard pns:%ud", pns);
    xqc_send_ctl_set_loss_detection_timer(send_ctl);
}


static void 
xqc_send_ctl_update_cwnd_limited(xqc_send_ctl_t *send_ctl)
{
    if (send_ctl->ctl_bytes_in_flight > send_ctl->ctl_max_bytes_in_flight) {
        send_ctl->ctl_max_bytes_in_flight = send_ctl->ctl_bytes_in_flight;
    }
    uint32_t cwnd_bytes = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong);
    /* If we can not send the next full-size packet, we are CWND limited. */
    xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|path:%ui|cwnd:%ud|inflight:%ud|",
            send_ctl->ctl_path->path_id, cwnd_bytes, send_ctl->ctl_bytes_in_flight);
      
    send_ctl->ctl_is_cwnd_limited = 0;
    uint32_t actual_mss = xqc_conn_get_mss(send_ctl->ctl_conn);
    if ((send_ctl->ctl_bytes_in_flight + actual_mss) > cwnd_bytes) {
        send_ctl->ctl_is_cwnd_limited = 1;
    }
}


/**
 * OnPacketSent
 */
void
xqc_send_ctl_on_packet_sent(xqc_send_ctl_t *send_ctl, xqc_pn_ctl_t *pn_ctl, xqc_packet_out_t *packet_out, xqc_usec_t now, ssize_t sent)
{
    xqc_pkt_num_space_t pns = packet_out->po_pkt.pkt_pns;

    if (send_ctl->ctl_conn->enable_multipath == XQC_CONN_MULTIPATH_SINGLE_PNS) {
        int ret = xqc_sent_record_add(&send_ctl->ctl_sent_record[pns], packet_out->po_pkt.pkt_num, packet_out->po_sent_time);
        if (ret != XQC_OK) {
            xqc_log(send_ctl->ctl_conn->log, XQC_LOG_ERROR, "|xqc_sent_record_add error|path:%ui|pkt_num:%ui|",
                        send_ctl->ctl_path->path_id, packet_out->po_pkt.pkt_num);
        }
    }

    xqc_sample_on_sent(packet_out, send_ctl, now);

    xqc_packet_number_t orig_pktnum = packet_out->po_origin ? packet_out->po_origin->po_pkt.pkt_num : 0;
    xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG,
            "|conn:%p|path:%ui|pkt_num:%ui|origin_pktnum:%ui|size:%ud|pkt_type:%s|frame:%s|conn_state:%s|po_in_flight:%d|",
            send_ctl->ctl_conn, send_ctl->ctl_path->path_id, packet_out->po_pkt.pkt_num, orig_pktnum, packet_out->po_used_size,
            xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
            xqc_frame_type_2_str(packet_out->po_frame_types),
            xqc_conn_state_2_str(send_ctl->ctl_conn->conn_state),
            packet_out->po_flag & XQC_POF_IN_FLIGHT ? 1: 0);
    
    if (packet_out->po_frame_types 
        & (XQC_FRAME_BIT_DATA_BLOCKED 
           | XQC_FRAME_BIT_STREAM_DATA_BLOCKED 
           | XQC_FRAME_BIT_MAX_STREAM_DATA 
           | XQC_FRAME_BIT_MAX_DATA))
    {
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG,
            "|conn:%p|path:%ui|pkt_num:%ui|origin_pktnum:%ui|size:%ud|"
            "pkt_type:%s|frame:%s|conn_state:%s|po_in_flight:%d|",
            send_ctl->ctl_conn, send_ctl->ctl_path->path_id, 
            packet_out->po_pkt.pkt_num, orig_pktnum, packet_out->po_used_size,
            xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
            xqc_frame_type_2_str(packet_out->po_frame_types),
            xqc_conn_state_2_str(send_ctl->ctl_conn->conn_state), 
            packet_out->po_flag & XQC_POF_IN_FLIGHT ? 1: 0);
    }

    if (packet_out->po_pkt.pkt_num > pn_ctl->ctl_largest_sent[pns]) {
        pn_ctl->ctl_largest_sent[pns] = packet_out->po_pkt.pkt_num;
    }

    send_ctl->ctl_bytes_send += sent;

    if (packet_out->po_largest_ack > 0) {
        xqc_ack_sent_record_add(&pn_ctl->ack_sent_record[pns], packet_out, send_ctl->ctl_srtt, now);
    }

    if (XQC_CAN_IN_FLIGHT(packet_out->po_frame_types)) {

        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            send_ctl->ctl_time_of_last_sent_ack_eliciting_packet[pns] =
            packet_out->po_sent_time;
            send_ctl->ctl_last_sent_ack_eliciting_packet_number[pns] =
            packet_out->po_pkt.pkt_num;
        }
        xqc_conn_update_stream_stats_on_sent(send_ctl->ctl_conn, packet_out, now);

        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG,
                "|path:%ui|inflight:%ud|applimit:%ui|",
                send_ctl->ctl_path->path_id, send_ctl->ctl_bytes_in_flight, send_ctl->ctl_app_limited);
        if (send_ctl->ctl_bytes_in_flight == 0) {
            if (send_ctl->ctl_cong_callback->xqc_cong_ctl_init_bbr
                && send_ctl->ctl_app_limited > 0)
            {
                uint8_t mode, idle_restart;
                mode = send_ctl->ctl_cong_callback->
                    xqc_cong_ctl_info_cb->mode(send_ctl->ctl_cong);
                idle_restart = send_ctl->ctl_cong_callback->
                            xqc_cong_ctl_info_cb->
                            idle_restart(send_ctl->ctl_cong);
                xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG,
                        "|BeforeRestartFromIdle|mode %ud|idle %ud"
                        "|bw %ud|pacing rate %ud|",
                        (unsigned int)mode, (unsigned int)idle_restart, send_ctl->ctl_cong_callback->
                        xqc_cong_ctl_get_bandwidth_estimate(send_ctl->ctl_cong),
                        send_ctl->ctl_cong_callback->
                        xqc_cong_ctl_get_pacing_rate(send_ctl->ctl_cong));

                send_ctl->ctl_cong_callback->xqc_cong_ctl_restart_from_idle(send_ctl->ctl_cong, send_ctl->ctl_delivered);
                xqc_log_event(send_ctl->ctl_conn->log, REC_CONGESTION_STATE_UPDATED, "restart");

                xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG,
                        "|AfterRestartFromIdle|mode %ud|"
                        "idle %ud|bw %ud|pacing rate %ud|",
                        (unsigned int)mode, (unsigned int)idle_restart, send_ctl->ctl_cong_callback->
                        xqc_cong_ctl_get_bandwidth_estimate(send_ctl->ctl_cong),
                        send_ctl->ctl_cong_callback->xqc_cong_ctl_get_pacing_rate(send_ctl->ctl_cong));
            }
            if (!send_ctl->ctl_cong_callback->xqc_cong_ctl_init_bbr) {
                xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|Restart from idle|");
                send_ctl->ctl_cong_callback->xqc_cong_ctl_restart_from_idle(send_ctl->ctl_cong, send_ctl->ctl_last_inflight_pkt_sent_time);
                xqc_log_event(send_ctl->ctl_conn->log, REC_CONGESTION_STATE_UPDATED, "restart");
            }
        }

        if (!(packet_out->po_flag & XQC_POF_IN_FLIGHT)) {
            xqc_send_ctl_increase_inflight(send_ctl->ctl_conn, packet_out);
            xqc_conn_increase_unacked_stream_ref(send_ctl->ctl_conn, packet_out);
        }

        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            xqc_send_ctl_set_loss_detection_timer(send_ctl);
        }

        if (packet_out->po_flag & XQC_POF_LOST) {
            ++send_ctl->ctl_lost_count;
            packet_out->po_flag &= ~XQC_POF_LOST;

        } else if (packet_out->po_flag & XQC_POF_TLP) {
            ++send_ctl->ctl_tlp_count;
            packet_out->po_flag &= ~XQC_POF_TLP;
        }
        ++send_ctl->ctl_send_count;
        xqc_stream_path_metrics_on_send(send_ctl->ctl_conn, packet_out);

        send_ctl->ctl_last_inflight_pkt_sent_time = now;
        xqc_send_ctl_update_cwnd_limited(send_ctl);
    }

    if (packet_out->po_frame_types & XQC_FRAME_BIT_CONNECTION_CLOSE) {
        if (send_ctl->ctl_conn->conn_close_send_time == 0) {
            send_ctl->ctl_conn->conn_close_send_time = now;
        }
    }

    send_ctl->ctl_conn->conn_last_send_time = now;

}

void
xqc_send_ctl_maybe_update_rtt_spns(xqc_connection_t *conn, xqc_ack_info_t *const ack_info, xqc_usec_t ack_recv_time)
{
    xqc_path_ctx_t *path = xqc_conn_find_path_by_path_id(conn, ack_info->path_id);
    if (path == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_find_path_by_path_id error|");
        return;
    }

    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    xqc_pkt_num_space_t pns = ack_info->pns;
    xqc_sent_record_t *sent_record = &send_ctl->ctl_sent_record[pns];
    xqc_packet_number_node_t *pn_node = NULL;

    /* TODO: 没有考虑 ack_eliciting, 是bug，会出现 largest_ack 是 non-ack-eliciting，收发两端不匹配 */
    int ret = xqc_sent_record_get_largest_pn_in_ack(sent_record, ack_info, &pn_node);
    if (ret != XQC_OK || pn_node == NULL) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_sent_record_get_largest_pn_in_ack no result|");
        return;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG,
                "|conn:%p|path:%ui|largest_pn_in_ack:%ui|path_largest_ack:%ui|path_latest_rtt_ack:%ui|",
                conn, ack_info->path_id, pn_node->pkt_num, send_ctl->ctl_largest_acked[pns], sent_record->latest_rtt_pn);

    if (pn_node->pkt_num > sent_record->latest_rtt_pn ||
        sent_record->latest_rtt_pn == XQC_MAX_UINT64_VALUE)
    {
        /* 更新 ctl_latest_rtt */
        send_ctl->ctl_latest_rtt = ack_recv_time - pn_node->pkt_sent_time;
        /* 更新rtt */
        xqc_send_ctl_update_rtt(send_ctl, &send_ctl->ctl_latest_rtt, ack_info->ack_delay);
        ++send_ctl->ctl_update_latest_rtt_count;
        /* 更新 latest_rtt_pn */
        sent_record->latest_rtt_pn = pn_node->pkt_num;
    }
}


/* on ack received */
int
xqc_send_ctl_on_ack_received_spns(xqc_connection_t *conn, xqc_ack_info_t *const ack_info, xqc_usec_t ack_recv_time)
{
    xqc_send_queue_t *send_queue = conn->conn_send_queue;
    xqc_path_ctx_t *path = NULL;
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *first_unacked_po = NULL;
    xqc_pkt_num_space_t pns = ack_info->pns;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        int ret = xqc_send_ctl_on_ack_received(path->path_send_ctl, xqc_get_pn_ctl(conn, path),
                                                send_queue, ack_info, ack_recv_time);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|on_ack_received error|path_id:%ui|", path->path_id);
            return ret;
        }
    }

    xqc_send_ctl_maybe_update_rtt_spns(conn, ack_info, ack_recv_time);

    /* 移除不再需要记录的pn */
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        xqc_sent_record_del(&path->path_send_ctl->ctl_sent_record[pns]);
    }
    return XQC_OK;
}

/**
 * OnAckReceived
 */
int
xqc_send_ctl_on_ack_received(xqc_send_ctl_t *send_ctl, xqc_pn_ctl_t *pn_ctl, xqc_send_queue_t *send_queue, xqc_ack_info_t *const ack_info, xqc_usec_t ack_recv_time)
{
    /* ack info里包含的packet不一定会是send_ctl这条路径发出的 */
    /* info里的largest ack 不一定是send_ctl这条路径的largest ack */

    xqc_connection_t *conn = send_ctl->ctl_conn;

    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;
    xqc_pktno_range_t *range = &ack_info->ranges[ack_info->n_ranges - 1];
    xqc_pkt_num_space_t pns = ack_info->pns;

    /* 标记ack info里是否有这条路径发出的包 */
    unsigned char has_acked = 0, update_largest_ack = 0;
    unsigned char has_ack_eliciting = 0, spurious_loss_detected = 0;
    xqc_packet_number_t frame_largest_ack = ack_info->ranges[0].high;
    xqc_packet_number_t spurious_loss_pktnum = 0;
    xqc_usec_t spurious_loss_sent_time = 0;
    unsigned char need_del_record = 0;
    int stream_frame_acked = 0;
    unsigned char same_path_rtt = ack_info->path_id == send_ctl->ctl_path->path_id? 1 : 0;

    xqc_packet_number_t largest_acked_ack = xqc_ack_sent_record_on_ack(&pn_ctl->ack_sent_record[pns], ack_info);
    if (largest_acked_ack > pn_ctl->ctl_largest_acked_ack[pns]) {
        pn_ctl->ctl_largest_acked_ack[pns] = largest_acked_ack;
        need_del_record = 1;
    }

    /* 记录ack info里这条路径发出的最大pn的包 */
    xqc_packet_number_t path_largest_pkt_num = 0;

    xqc_init_sample_before_ack(&send_ctl->sampler);

    /* detect and remove acked packets */
    xqc_list_for_each_safe(pos, next, &send_queue->sndq_unacked_packets[pns]) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        // 筛选出当前路径的packet
        if (packet_out->po_path_id != send_ctl->ctl_path->path_id) {
            continue;
        }

        // 直到pn超过frame_largest_ack，结束遍历
        if (packet_out->po_pkt.pkt_num > frame_largest_ack) {
            break;
        }

        // 如果pn大于pns所发的最大pn，报错
        if (packet_out->po_pkt.pkt_num > pn_ctl->ctl_largest_sent[pns]) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|pkt is not sent yet|%ui|", packet_out->po_pkt.pkt_num);
            return -XQC_EPROTO;
        }

        // range从后数，ack range递增
        while (packet_out->po_pkt.pkt_num > range->high && range != ack_info->ranges) {
            --range;
        }

        if (packet_out->po_pkt.pkt_num >= range->low) {
            // this packet is acked

            // 修改标志位
            if (has_acked == 0) {
                /* 初始化 */
                send_ctl->ctl_prior_delivered = send_ctl->ctl_delivered;
                send_ctl->ctl_prior_bytes_in_flight = send_ctl->ctl_bytes_in_flight;

                has_acked = 1;
            }

            path_largest_pkt_num = packet_out->po_pkt.pkt_num;

            // 更新ctl_largest_acked
            // 若ack info里此路径最大pn大于path largest acked，更新 largest acked
            if (packet_out->po_pkt.pkt_num > send_ctl->ctl_largest_acked[pns] ||
                send_ctl->ctl_largest_acked[pns] == XQC_MAX_UINT64_VALUE)
			{
                update_largest_ack = 1;
                send_ctl->ctl_largest_acked[pns] = packet_out->po_pkt.pkt_num;
                send_ctl->ctl_largest_acked_sent_time[pns] = packet_out->po_sent_time;
            }

            // 更新 largest_ack_both
            if (packet_out->po_largest_ack > pn_ctl->ctl_largest_acked_ack[pns]) {
                pn_ctl->ctl_largest_acked_ack[pns] = packet_out->po_largest_ack;
                need_del_record = 1;
            }

            xqc_log(conn->log, XQC_LOG_DEBUG,
                "|conn:%p|path:%ui|pkt_num:%ui|origin_pktnum:%ui|size:%ud|pns:%d|pkt_type:%s|frame:%s|conn_state:%s|frame_largest_ack:%ui|path_largest_ack:%ui|",
                conn, send_ctl->ctl_path->path_id, packet_out->po_pkt.pkt_num,
                (xqc_packet_number_t)packet_out->po_origin ? packet_out->po_origin->po_pkt.pkt_num : 0,
                packet_out->po_used_size, pns,
                xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                xqc_frame_type_2_str(packet_out->po_frame_types),
                xqc_conn_state_2_str(conn->conn_state),
                frame_largest_ack, send_ctl->ctl_largest_acked[pns]);

            // 更新sample
            xqc_update_sample(&send_ctl->sampler, packet_out, send_ctl, ack_recv_time);

            /* Packet previously declared lost gets acked */
            if (!packet_out->po_acked && (packet_out->po_flag & XQC_POF_RETRANSED)) {
                ++send_ctl->ctl_spurious_loss_count;
                if (!spurious_loss_detected) {
                    spurious_loss_detected = 1;
                    spurious_loss_pktnum = packet_out->po_pkt.pkt_num;
                    spurious_loss_sent_time = packet_out->po_sent_time;
                }
            }

            xqc_send_ctl_on_packet_acked(send_ctl, packet_out, ack_recv_time, 1);

            xqc_send_queue_maybe_remove_unacked(packet_out, send_queue, NULL);

            xqc_log(conn->log, XQC_LOG_DEBUG, "|sndq_packets_used:%ud||sndq_packets_used_bytes:%ud|sndq_packets_free:%ud|",
                    send_queue->sndq_packets_used, send_queue->sndq_packets_used_bytes, send_queue->sndq_packets_free);

            if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
                has_ack_eliciting = 1;
            }
        }
    }

    /* 此path没有ack */
    if (!has_acked) {
        return XQC_OK;
    }

    if (update_largest_ack && has_ack_eliciting && same_path_rtt == 1) {
        /* 更新 ctl_latest_rtt */
        send_ctl->ctl_latest_rtt = ack_recv_time - send_ctl->ctl_largest_acked_sent_time[pns];
        /* 更新rtt */
        xqc_send_ctl_update_rtt(send_ctl, &send_ctl->ctl_latest_rtt, ack_info->ack_delay);
        /* 更新 latest_rtt_pn */
        send_ctl->ctl_sent_record[pns].latest_rtt_pn = send_ctl->ctl_largest_acked[pns];
    }

    /* TODO: ECN */

    /* spurious loss */
    if (spurious_loss_detected) {
        xqc_send_ctl_on_spurious_loss_detected(send_ctl, pns, ack_recv_time, path_largest_pkt_num,
                                               spurious_loss_pktnum, spurious_loss_sent_time);
    }

    /* DetectAndRemoveLostPackets + OnPacketsLost */
    xqc_send_ctl_detect_lost(send_ctl, send_queue, pns, ack_recv_time);

    // 更新recv record
    if (need_del_record) {
        xqc_recv_record_del(&pn_ctl->ctl_recv_record[pns], pn_ctl->ctl_largest_acked_ack[pns] + 1);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_recv_record_del from %ui|pns:%d|",
                pn_ctl->ctl_largest_acked_ack[pns] + 1, pns);
    }

    // xqc_recv_record_log(conn, &pn_ctl->ctl_recv_record[pns]);

    /*
     * reset pto_count unless the client is unsure if the server has
     * validated the client's address
     */
    if (xqc_conn_peer_complete_address_validation(conn)) {
        send_ctl->ctl_pto_count = 0;
        send_ctl->ctl_pto_count_since_last_tra_path_status_changed = 0;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_set_loss_detection_timer|acked|pto_count:%ud|", send_ctl->ctl_pto_count);
    xqc_send_ctl_set_loss_detection_timer(send_ctl);

    /* Clear app-limited field if the bubble is gone. */
    /* @NOTE: we need to clear it for Cubic/Reno as well. */
    if (send_ctl->ctl_app_limited 
        && send_ctl->ctl_delivered > send_ctl->ctl_app_limited)
    {
        send_ctl->ctl_app_limited = 0;
    }

    /* BBR */
    if (send_ctl->ctl_cong_callback->xqc_cong_ctl_init_bbr /* && stream_frame_acked */) {

        uint64_t bw_before = 0, bw_after = 0;
        int bw_record_flag = 0;
        xqc_usec_t now = ack_recv_time;
        xqc_sample_type_t sample_type = xqc_generate_sample(&send_ctl->sampler, send_ctl, ack_recv_time);

        /* Make sure that we do not call BBR with a invalid sampler. */
        if (sample_type == XQC_RATE_SAMPLE_VALID) {
            if ((send_ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate != NULL)
                && send_ctl->ctl_conn->log->log_level >= XQC_LOG_STATS
                && (send_ctl->ctl_info.last_bw_time + send_ctl->ctl_info.record_interval <= now))
            {
                bw_before = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(send_ctl->ctl_cong);
                if (bw_before != 0) {
                    bw_record_flag = 1;
                }
            }

            send_ctl->ctl_cong_callback->xqc_cong_ctl_on_ack_multiple_pkts(send_ctl->ctl_cong, &send_ctl->sampler);
        }

        if (send_ctl->ctl_conn->log->log_level >= XQC_LOG_DEBUG) {
            uint8_t mode, full_bw_reached;
            uint8_t recovery_mode, round_start;
            uint8_t packet_conservation, idle_restart;
            float pacing_gain, cwnd_gain;
            uint64_t min_rtt, recovery_start_time;
            xqc_bbr_info_interface_t *info = send_ctl->ctl_cong_callback->xqc_cong_ctl_info_cb;
            mode = info->mode(send_ctl->ctl_cong);
            full_bw_reached = info->full_bw_reached(send_ctl->ctl_cong);
            recovery_mode = info->recovery_mode(send_ctl->ctl_cong);
            round_start = info->round_start(send_ctl->ctl_cong);
            packet_conservation = info->packet_conservation(send_ctl->ctl_cong);
            idle_restart = info->idle_restart(send_ctl->ctl_cong);
            pacing_gain = info->pacing_gain(send_ctl->ctl_cong);
            cwnd_gain = info->cwnd_gain(send_ctl->ctl_cong);
            min_rtt = info->min_rtt(send_ctl->ctl_cong);
            recovery_start_time = info->recovery_start_time(send_ctl->ctl_cong);
            xqc_conn_log(conn, XQC_LOG_DEBUG,
                 "|bbr on ack|mode:%ud|pacing_rate:%ud|bw:%ud|"
                 "cwnd:%ui|full_bw_reached:%ud|inflight:%ud|"
                 "srtt:%ui|latest_rtt:%ui|min_rtt:%ui|applimit:%ud|"
                 "lost:%ud|recovery:%ud|recovery_start:%ui|"
                 "idle_restart:%ud|packet_conservation:%ud|round_start:%ud|",
                 (unsigned int) mode,
                 send_ctl->ctl_cong_callback->xqc_cong_ctl_get_pacing_rate(send_ctl->ctl_cong),
                 send_ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(send_ctl->ctl_cong),
                 send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong),
                 (unsigned int) full_bw_reached, send_ctl->ctl_bytes_in_flight,
                 send_ctl->ctl_srtt, send_ctl->ctl_latest_rtt, min_rtt,
                 send_ctl->sampler.is_app_limited, send_ctl->ctl_lost_count,
                 (unsigned int) recovery_mode, recovery_start_time, (unsigned int) idle_restart,
                 (unsigned int) packet_conservation, (unsigned int) round_start);
        }

        if (bw_record_flag) {
            bw_after = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(send_ctl->ctl_cong);
            if (bw_after > 0) {
                if (xqc_sub_abs(bw_after, bw_before) * 100 > (bw_before * send_ctl->ctl_info.bw_change_threshold)) {

                    send_ctl->ctl_info.last_bw_time = now;
                    xqc_conn_log(conn, XQC_LOG_STATS,
                                 "|bandwidth change record|bw_before:%ui|bw_after:%ui|srtt:%ui|cwnd:%ui|",
                                 bw_before, bw_after, send_ctl->ctl_srtt, send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong));
                }
            }
        }

    } else if (send_ctl->ctl_cong_callback->xqc_cong_ctl_on_ack_multiple_pkts) {
        xqc_sample_type_t sample_type = xqc_generate_sample(&send_ctl->sampler, send_ctl, ack_recv_time);
        /* Currently, this is only the case for Copa. */
        if (sample_type != XQC_RATE_SAMPLE_ACK_NOTHING) {
            send_ctl->ctl_cong_callback->xqc_cong_ctl_on_ack_multiple_pkts(send_ctl->ctl_cong, &send_ctl->sampler);
        }
    }

    xqc_send_ctl_info_circle_record(send_ctl);
    xqc_log_event(conn->log, REC_METRICS_UPDATED, send_ctl);
    return XQC_OK;
}

/**
 * OnDatagramReceived
 */
void
xqc_send_ctl_on_dgram_received(xqc_send_ctl_t *send_ctl, size_t dgram_size)
{
    xqc_bool_t aal = xqc_send_ctl_check_anti_amplification(send_ctl, 0);

    send_ctl->ctl_bytes_recv += dgram_size;
    send_ctl->ctl_recv_count++;

    /*
     * If this datagram unblocks the server's anti-amplification limit,
     * arm the PTO timer to avoid deadlock.
     */

    if (aal && !xqc_send_ctl_check_anti_amplification(send_ctl, 0)) {
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|anti-amplification state unlock|");
        xqc_send_ctl_set_loss_detection_timer(send_ctl);
    }
}

void
xqc_send_ctl_latest_rtt_tracking(xqc_send_ctl_t *send_ctl, xqc_usec_t *latest_rtt)
{
    /* if sum is closed to range */
    if (send_ctl->ctl_latest_rtt_square_sum > ((uint64_t)1 << 62)) {
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|out of range|");
        return;
    }

    ++send_ctl->ctl_update_latest_rtt_count;

    xqc_msec_t sample = (*latest_rtt)/1000;
    send_ctl->ctl_latest_rtt_sum += sample;
    send_ctl->ctl_latest_rtt_square_sum += sample * sample;
}


/**
 * UpdateRtt
 */
void
xqc_send_ctl_update_rtt(xqc_send_ctl_t *send_ctl, xqc_usec_t *latest_rtt, xqc_usec_t ack_delay)
{
    xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG,
            "|before update rtt|conn:%p|srtt:%ui|rttvar:%ui|minrtt:%ui|latest_rtt:%ui|ack_delay:%ui|",
            send_ctl->ctl_conn, send_ctl->ctl_srtt, send_ctl->ctl_rttvar, send_ctl->ctl_minrtt, *latest_rtt, ack_delay);

    xqc_send_ctl_latest_rtt_tracking(send_ctl, latest_rtt);

    /* Based on {{RFC6298}}. */
    if (send_ctl->ctl_first_rtt_sample_time == 0) {
        send_ctl->ctl_minrtt = *latest_rtt;
        send_ctl->ctl_srtt = *latest_rtt;
        send_ctl->ctl_rttvar = *latest_rtt >> 1;
        send_ctl->ctl_first_rtt_sample_time = xqc_monotonic_timestamp();

    } else {
        send_ctl->ctl_minrtt = xqc_min(*latest_rtt, send_ctl->ctl_minrtt);

        if (xqc_conn_is_handshake_confirmed(send_ctl->ctl_conn)) {
            ack_delay = xqc_min(ack_delay, send_ctl->ctl_conn->remote_settings.max_ack_delay * 1000);
        }

        /* Adjust for ack delay if it's plausible. */
        xqc_usec_t adjusted_rtt = *latest_rtt;
        if (*latest_rtt >= (send_ctl->ctl_minrtt + ack_delay)) {
            adjusted_rtt -= ack_delay;
        }

        uint64_t srtt = send_ctl->ctl_srtt;
        uint64_t rttvar = send_ctl->ctl_rttvar;

        /* rttvar = 3/4 * rttvar + 1/4 * abs(smoothed_rtt - adjusted_rtt)  */
        send_ctl->ctl_rttvar -= send_ctl->ctl_rttvar >> 2;
        send_ctl->ctl_rttvar += (send_ctl->ctl_srtt > adjusted_rtt
                            ? send_ctl->ctl_srtt - adjusted_rtt : adjusted_rtt - send_ctl->ctl_srtt) >> 2;

        /* smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt */
        send_ctl->ctl_srtt -= send_ctl->ctl_srtt >> 3;
        send_ctl->ctl_srtt += adjusted_rtt >> 3;

        if (xqc_sub_abs(send_ctl->ctl_srtt, srtt)  > send_ctl->ctl_info.rtt_change_threshold) {
            xqc_usec_t now = xqc_monotonic_timestamp();
            if (send_ctl->ctl_info.last_rtt_time + send_ctl->ctl_info.record_interval <= now) {
                send_ctl->ctl_info.last_rtt_time = now;
                xqc_conn_log(send_ctl->ctl_conn, XQC_LOG_STATS, "|before update rtt|srtt:%ui|rttvar:%ui|"
                            "after update rtt|srtt:%ui|rttvar:%ui|minrtt:%ui|latest_rtt:%ui|ack_delay:%ui|",
                             srtt, rttvar, send_ctl->ctl_srtt, send_ctl->ctl_rttvar, send_ctl->ctl_minrtt, *latest_rtt, ack_delay);
            }
        }
    }

    xqc_conn_log(send_ctl->ctl_conn, XQC_LOG_DEBUG,
                 "|after update rtt|conn:%p|srtt:%ui|rttvar:%ui|minrtt:%ui|latest_rtt:%ui|ack_delay:%ui|",
                 send_ctl->ctl_conn, send_ctl->ctl_srtt, send_ctl->ctl_rttvar, send_ctl->ctl_minrtt, *latest_rtt, ack_delay);
}

void
xqc_send_ctl_on_spurious_loss_detected(xqc_send_ctl_t *send_ctl,
    xqc_pkt_num_space_t pns, xqc_usec_t ack_recv_time,
    xqc_packet_number_t largest_ack,
    xqc_packet_number_t spurious_loss_pktnum,
    xqc_usec_t spurious_loss_sent_time)
{
    if (!send_ctl->ctl_conn->conn_settings.spurious_loss_detect_on) {
        return;
    }

    /* Adjust Packet Threshold */
    if (largest_ack < spurious_loss_pktnum) {
        return;
    }
    send_ctl->ctl_reordering_packet_threshold = xqc_max(send_ctl->ctl_reordering_packet_threshold,
                                                        xqc_send_ctl_get_pkt_num_gap(send_ctl, pns, spurious_loss_pktnum, largest_ack) + 1);


    /* Adjust Time Threshold */
    if (ack_recv_time < spurious_loss_sent_time) {
        return;
    }
    xqc_usec_t reorder_time_interval = ack_recv_time - spurious_loss_sent_time;
    xqc_usec_t max_rtt = xqc_max(send_ctl->ctl_latest_rtt, send_ctl->ctl_srtt);
    while (max_rtt + (max_rtt >> send_ctl->ctl_reordering_time_threshold_shift) < reorder_time_interval
           && send_ctl->ctl_reordering_time_threshold_shift > 0)
    {
        --send_ctl->ctl_reordering_time_threshold_shift;
    }

    xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|ctl_reordering_packet_threshold:%ui|ctl_reordering_time_threshold_shift:%d|",
            send_ctl->ctl_reordering_packet_threshold, send_ctl->ctl_reordering_time_threshold_shift);
}

/**
 * DetectAndRemoveLostPackets + OnPacketsLost
 */
void
xqc_send_ctl_detect_lost(xqc_send_ctl_t *send_ctl, xqc_send_queue_t *send_queue, xqc_pkt_num_space_t pns, xqc_usec_t now)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *po, *largest_lost = NULL;
    uint64_t lost_n = 0;

    send_ctl->ctl_loss_time[pns] = 0;
    send_ctl->sampler.loss = 0;

    xqc_connection_t *conn = send_ctl->ctl_conn;

    if (send_ctl->ctl_largest_acked[pns] == XQC_MAX_UINT64_VALUE) {
        xqc_log(conn->log, XQC_LOG_WARN, "|exception|largest acked is not recorded|");
        return;
    }

    /* loss_delay = 9/8 * max(latest_rtt, smoothed_rtt) */
    xqc_usec_t loss_delay = xqc_max(send_ctl->ctl_latest_rtt, send_ctl->ctl_srtt);
    loss_delay += loss_delay >> send_ctl->ctl_reordering_time_threshold_shift;

    /* Minimum time of kGranularity before packets are deemed lost. */
    loss_delay = xqc_max(loss_delay, XQC_kGranularity);

    /* Packets sent before this time are deemed lost. */
    xqc_usec_t lost_send_time = now - loss_delay;

    /* Packets with packet numbers before this are deemed lost. */
    /* 若 lost_pn == XQC_MAX_UINT64_VALUE, 无丢包 */
    xqc_packet_number_t lost_pn = xqc_send_ctl_get_lost_sent_pn(send_ctl, pns);

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_unacked_packets[pns]) {
        po = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        if (po->po_path_id != send_ctl->ctl_path->path_id) {
            continue;
        }

        /* If this packet is not lost, so is the next packet */
        if (po->po_pkt.pkt_num > send_ctl->ctl_largest_acked[pns]) {
            break;
        }

        if (xqc_send_ctl_indirectly_ack_po(conn, po)) {
            continue;
        }

        /* Mark packet as lost, or set time when it should be marked. */
        if (po->po_sent_time <= lost_send_time
			|| (lost_pn != XQC_MAX_UINT64_VALUE && po->po_pkt.pkt_num <= lost_pn))
		{
            if (po->po_flag & XQC_POF_IN_FLIGHT) {
                xqc_send_ctl_decrease_inflight(conn, po);

                /* if a packet don't need to be repair, don't retransmit it */
                if (!XQC_NEED_REPAIR(po->po_frame_types)) {
                    xqc_send_queue_remove_unacked(po, send_queue);
                    xqc_send_queue_insert_free(po, &send_queue->sndq_free_packets, send_queue);

                } else {
                    xqc_send_queue_copy_to_lost(po, send_queue);
                }

                lost_n++;

                xqc_log(conn->log, XQC_LOG_DEBUG, "|mark lost|pns:%d|pkt_num:%ui|"
                        "lost_pn:%ui|po_sent_time:%ui|lost_send_time:%ui|loss_delay:%ui|frame:%s|repair:%d|",
                        pns, po->po_pkt.pkt_num, lost_pn, po->po_sent_time, lost_send_time, loss_delay,
                        xqc_frame_type_2_str(po->po_frame_types), XQC_NEED_REPAIR(po->po_frame_types));
                xqc_log_event(conn->log, REC_PACKET_LOST, po);

            } else {
                xqc_log(conn->log, XQC_LOG_DEBUG, "|it's a copy of origin pkt|acked:%d|origin_acked:%d|origin_ref_cnt:%d|",
                        po->po_acked, po->po_origin ? po->po_origin->po_acked : -1,
                        po->po_origin ? po->po_origin->po_origin_ref_cnt : -1);
                continue;
            }

            /* remember largest_loss for OnPacketsLost */
            if (largest_lost == NULL
                || (po->po_pkt.pkt_num > largest_lost->po_pkt.pkt_num))
            {
                largest_lost = po;
            }

        } else {
            if (send_ctl->ctl_loss_time[pns] == 0) {
                send_ctl->ctl_loss_time[pns] = po->po_sent_time + loss_delay;

            } else {
                send_ctl->ctl_loss_time[pns] = xqc_min(send_ctl->ctl_loss_time[pns], po->po_sent_time + loss_delay);
            }
        }
    }

    /* update statistic */
    send_ctl->ctl_lost_pkts_number += lost_n;
    send_ctl->sampler.loss = lost_n;

    /**
     * OnPacketsLost
     */
    if (largest_lost) {
        /*
         * Start a new congestion epoch if the last lost packet
         * has passed the end of the previous recovery epoch.
         * enter loss recovery here
         */
        xqc_log(conn->log, XQC_LOG_DEBUG, "|OnLostDetection|largest_lost sent time: %lu|", largest_lost->po_sent_time);
        xqc_send_ctl_congestion_event(send_ctl, largest_lost->po_sent_time);

        if (send_ctl->ctl_first_rtt_sample_time == 0) {
            return;
        }

        /* Collapse congestion window if persistent congestion */
        if (send_ctl->ctl_cong_callback->xqc_cong_ctl_reset_cwnd
            && xqc_send_ctl_in_persistent_congestion(send_ctl, largest_lost, now))
        {
            /* For loss-based CCs, it means we are gonna slow start again. */
            send_ctl->ctl_max_bytes_in_flight = 0;
            /* we reset BBR's cwnd here */
            xqc_log(conn->log, XQC_LOG_DEBUG, "|OnLostDetection|%s|", "Persistent congestion occurs");
            send_ctl->ctl_cong_callback->xqc_cong_ctl_reset_cwnd(send_ctl->ctl_cong);
        }

        if (send_ctl->ctl_info.last_lost_time + send_ctl->ctl_info.record_interval <= now) {
            xqc_usec_t lost_interval = now - send_ctl->ctl_info.last_lost_time;
            send_ctl->ctl_info.last_lost_time = now;
            uint64_t lost_count = send_ctl->ctl_lost_count + lost_n - send_ctl->ctl_info.last_lost_count;
            uint64_t send_count = send_ctl->ctl_send_count - send_ctl->ctl_info.last_send_count;
            send_ctl->ctl_info.last_lost_count = send_ctl->ctl_lost_count + lost_n;
            send_ctl->ctl_info.last_send_count = send_ctl->ctl_send_count;
            uint64_t bw = 0;
            if (send_ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate) {
                bw = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(send_ctl->ctl_cong);
            }
            xqc_conn_log(conn, XQC_LOG_STATS, "|lost interval:%ui|lost_count:%ui|send_count:%ui|pkt_num:%ui"
                        "|po_send_time:%ui|srtt:%ui|cwnd:%ud|bw:%ui|conn_life:%ui|now:%ui|last_lost_time:%ui|",
                        lost_interval, lost_count, send_count, largest_lost->po_pkt.pkt_num, largest_lost->po_sent_time, send_ctl->ctl_srtt,
                        send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong), bw, now - conn->conn_create_time);
        }
    }
}

/**
 * InPersistentCongestion
 */
xqc_bool_t
xqc_send_ctl_in_persistent_congestion(xqc_send_ctl_t *send_ctl, xqc_packet_out_t *largest_lost, xqc_usec_t now)
{
    if (send_ctl->ctl_pto_count >= XQC_CONSECUTIVE_PTO_THRESH) {
        xqc_usec_t duration = (send_ctl->ctl_srtt + xqc_max(send_ctl->ctl_rttvar << 2, XQC_kGranularity)
            + send_ctl->ctl_conn->remote_settings.max_ack_delay * 1000) * XQC_kPersistentCongestionThreshold;
        if (now - largest_lost->po_sent_time > duration) {
            return XQC_TRUE;
        }
    }

    return XQC_FALSE;
}

/**
 * CongestionEvent
 */
void
xqc_send_ctl_congestion_event(xqc_send_ctl_t *send_ctl, xqc_usec_t sent_time)
{
    if (send_ctl->ctl_cong_callback->xqc_cong_ctl_on_lost) {
        send_ctl->ctl_cong_callback->xqc_cong_ctl_on_lost(send_ctl->ctl_cong, sent_time);
    }
}


/**
 * IsAppLimited
 */
int
xqc_send_ctl_is_app_limited(xqc_send_ctl_t *send_ctl)
{
    return send_ctl->ctl_app_limited > 0;
}

/* This function is called inside cc's on_ack callbacks if needed */
int
xqc_send_ctl_is_cwnd_limited(xqc_send_ctl_t *send_ctl)
{
    if (send_ctl->ctl_cong_callback->xqc_cong_ctl_in_slow_start(send_ctl->ctl_cong)) {
        uint32_t double_cwnd = send_ctl->ctl_max_bytes_in_flight << 1;
        uint32_t cwnd = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong);
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG,
                "|cwnd: %ud, 2*max_inflight: %ud|", cwnd, double_cwnd);
        return cwnd < double_cwnd;
    }
    return (send_ctl->ctl_is_cwnd_limited);
}

void
xqc_send_ctl_cc_on_ack(xqc_send_ctl_t *send_ctl, xqc_packet_out_t *acked_packet,
                       xqc_usec_t now)
{
    if (send_ctl->ctl_cong_callback->xqc_cong_ctl_on_ack) {
        send_ctl->ctl_cong_callback->xqc_cong_ctl_on_ack(send_ctl->ctl_cong, acked_packet, now);
    }
    /* For CUBIC debug */
#if 0
    // xqc_cubic_t *c = (xqc_cubic_t*)(send_ctl->ctl_cong);
    // xqc_log(send_ctl->ctl_conn->log, XQC_LOG_WARN, "|cubic|time: %ui, sent_time: %ui, rtt: %ui|acked: %ud|"
    //         "cwnd: %ud, ssthresh: %ud, recovery: 0, cwnd_limited: 0, in_lss: 0|",
    //         now, acked_packet->po_sent_time, now - acked_packet->po_sent_time,
    //         acked_packet->po_used_size,
    //         c->cwnd/1200, c->ssthresh/1200);
    xqc_cubic_kernel_t *c = (xqc_cubic_kernel_t*)(send_ctl->ctl_cong);
    xqc_log(send_ctl->ctl_conn->log, XQC_LOG_ERROR, "|pathid:%ui|cubic|time: %ui, sent_time: %ui, rtt: %ui|acked: %ud|"
            "cwnd: %ud, ssthresh: %ud, delay_min: %ui, "
            "tcp_cwnd: %ud, cnt: %ud, last_max_cwnd: %ud,"
            "last_cwnd: %ud, last_time: %ui, orig_point: %ud,"
            "K: %ud, epoch_start: %ui, ack_cnt: %ud, "
            "cwnd_cnt: %ud, init_cwnd: %ud, recovery: %ui|cwnd_limited: %ud|"
            "hystart++|"
            "prev_delivered: %ui, next_deliverd: %ui, po_delivered: %ui, "
            "curr_mrtt: %ui, last_mrtt: %ui, rtt_cnt: %ud, "
            "in_lss: %ud, lss_bytes: %ud, total_delivered: %ui|pktnum: %ui, PNS: %ud|",
            send_ctl->ctl_path->path_id,
            now, acked_packet->po_sent_time, now - acked_packet->po_sent_time,
            acked_packet->po_used_size,
            c->cwnd, c->ssthresh, c->delay_min,
            c->tcp_cwnd, c->cnt, c->last_max_cwnd,
            c->last_cwnd, c->last_time, c->bic_origin_point, c->bic_K,
            c->epoch_start, c->ack_cnt, c->cwnd_cnt, c->init_cwnd,
            c->recovery_start_time,
            send_ctl->ctl_is_cwnd_limited,
            c->prev_round_delivered, c->next_round_delivered, acked_packet->po_delivered,
            c->current_round_mrtt, c->last_round_mrtt, c->rtt_sample_cnt,
            c->in_lss, c->lss_accumulated_bytes, c->ctl_ctx->ctl_delivered,
            acked_packet->po_pkt.pkt_num, acked_packet->po_pkt.pkt_pns);
#endif
}

/**
 * OnPacketAcked
 */
void
xqc_send_ctl_on_packet_acked(xqc_send_ctl_t *send_ctl,
    xqc_packet_out_t *acked_packet, xqc_usec_t now, int do_cc)
{
    xqc_stream_t *stream;
    xqc_packet_out_t *packet_out = acked_packet;
    xqc_connection_t *conn = send_ctl->ctl_conn;

    if ((conn->conn_type == XQC_CONN_TYPE_SERVER) && (acked_packet->po_frame_types & XQC_FRAME_BIT_HANDSHAKE_DONE)) {
        conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_DONE_ACKED;
    }

    xqc_conn_decrease_unacked_stream_ref(send_ctl->ctl_conn, packet_out);

    /* If a packet marked as STREAM_CLOSED, when it is acked, it comes here */
    if (packet_out->po_flag & XQC_POF_IN_FLIGHT) {
        xqc_send_ctl_decrease_inflight(send_ctl->ctl_conn, packet_out);

        if (packet_out->po_frame_types & XQC_FRAME_BIT_RESET_STREAM) {
            xqc_send_ctl_on_reset_stream_acked(send_ctl, packet_out);
        }

        if (packet_out->po_frame_types & XQC_FRAME_BIT_CRYPTO && packet_out->po_pkt.pkt_pns == XQC_PNS_HSK) {
            conn->conn_flag |= XQC_CONN_FLAG_HSK_ACKED;
        }

        if (packet_out->po_frame_types & XQC_FRAME_BIT_PING) {
            if (conn->app_proto_cbs.conn_cbs.conn_ping_acked
                && (packet_out->po_flag & XQC_POF_NOTIFY))
            {
                conn->app_proto_cbs.conn_cbs.conn_ping_acked(conn, &conn->scid_set.user_scid,
                                                        packet_out->po_user_data, conn->user_data, conn->proto_data);
            }
        }

        /* TODO: fix NEW_CID_RECEIVED */
        if (packet_out->po_frame_types & XQC_FRAME_BIT_NEW_CONNECTION_ID) {
            packet_out->po_frame_types &= ~XQC_FRAME_BIT_NEW_CONNECTION_ID;
            conn->conn_flag |= XQC_CONN_FLAG_NEW_CID_RECEIVED;
        }

        if (packet_out->po_frame_types & XQC_FRAME_BIT_PATH_ABANDON) {
            xqc_path_abandon_acked(conn, packet_out->po_abandon_path_id);
        }

        if (do_cc) {
            xqc_send_ctl_cc_on_ack(send_ctl, packet_out, now);
        }
    }

    packet_out->po_acked = 1;
    if (packet_out->po_origin) {
        packet_out->po_origin->po_acked = 1;
    }
}


xqc_usec_t
xqc_send_ctl_get_pto_time_and_space(xqc_send_ctl_t *send_ctl, xqc_usec_t now, xqc_pkt_num_space_t *pns_ret)
{
    xqc_usec_t t;
    xqc_usec_t pto_timeout = XQC_MAX_UINT64_VALUE;
    xqc_connection_t *c = send_ctl->ctl_conn;
    xqc_int_t pto_cnt = send_ctl->ctl_pto_count;

    /* get pto duration */
    xqc_usec_t duration = (send_ctl->ctl_srtt
        + xqc_max(4 * send_ctl->ctl_rttvar, XQC_kGranularity * 1000)) * xqc_send_ctl_pow(pto_cnt);

    /* Arm PTO from now when there are no inflight packets */
    if (send_ctl->ctl_bytes_in_flight == 0) {
        /* assert(!PeerCompletedAddressValidation()) */
        if (xqc_conn_peer_complete_address_validation(c)) {
            xqc_log(c->log, XQC_LOG_WARN, "|exception|handshake not confirmed");
            /* return pto_timeout; */
        }

        pto_timeout = xqc_monotonic_timestamp() + duration;
        if (xqc_conn_has_hsk_keys(c)) {
            *pns_ret = XQC_PNS_HSK;

        } else {
            *pns_ret = XQC_PNS_INIT;
        }

    } else {
        *pns_ret = XQC_PNS_INIT;

        for (xqc_pkt_num_space_t pns = XQC_PNS_INIT; pns <= XQC_PNS_APP_DATA; ++pns) {
            xqc_log(c->log, XQC_LOG_DEBUG, "|conn:%p|path:%ui|PNS: %ud, unacked: %ud|",
                    c, send_ctl->ctl_path->path_id, pns, send_ctl->ctl_bytes_ack_eliciting_inflight[pns]);

            /* skip if no bytes inflight in pns */
            if (send_ctl->ctl_bytes_ack_eliciting_inflight[pns] > 0) {
                /* Skip Application Data until handshake confirmed. */
                if (pns == XQC_PNS_APP_DATA) {
                    if (!xqc_conn_is_handshake_confirmed(send_ctl->ctl_conn)) {
                        xqc_log(c->log, XQC_LOG_DEBUG, "|handshake not confirmed|");
                        break;
                    }

                    duration += c->remote_settings.max_ack_delay * 1000 * xqc_send_ctl_pow(send_ctl->ctl_pto_count);
                }

                t = send_ctl->ctl_time_of_last_sent_ack_eliciting_packet[pns] + duration;
                if (t < pto_timeout) {
                    pto_timeout = t;
                    *pns_ret = pns;
                }
            }
        }
    }

    return pto_timeout;
}


/**
 * SetLossDetectionTimer
 */
void
xqc_send_ctl_set_loss_detection_timer(xqc_send_ctl_t *send_ctl)
{
    xqc_pkt_num_space_t pns;

    xqc_connection_t *conn = send_ctl->ctl_conn;
    xqc_path_ctx_t *path = send_ctl->ctl_path;
    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_usec_t interval = 0;

    xqc_usec_t loss_time = xqc_send_ctl_get_earliest_loss_time(send_ctl, &pns);
    interval = (loss_time > now) ? (loss_time - now) : 0;
    if (loss_time != 0) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_timer_set|earliest loss time|XQC_TIMER_LOSS_DETECTION|"
                "conn:%p|path:%ui|pns:%d|expire:%ui|now:%ui|interval:%ui|", conn, path->path_id, pns, loss_time, now, interval);

        /* Time threshold loss detection. */
        xqc_timer_set(&send_ctl->path_timer_manager, XQC_TIMER_LOSS_DETECTION, now, interval);
        return;
    }

    /* if at anti-amplification limit, nothing would be sent, unset the loss detection timer */
    if (xqc_send_ctl_check_anti_amplification(send_ctl, 0)) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|amplification limit|stop timer|conn:%p|path:%ui|", conn, path->path_id);
        xqc_timer_unset(&send_ctl->path_timer_manager, XQC_TIMER_LOSS_DETECTION);
        return;
    }

    /* Don't arm timer if there are no ack-eliciting packets in flight. */
    if (0 == send_ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_INIT]
        && 0 == send_ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_HSK]
        && 0 == send_ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_APP_DATA]
        && xqc_conn_peer_complete_address_validation(conn))
    {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|unset|no ack-eliciting pkts in flight|conn:%p|path:%ui|", conn, path->path_id);
        xqc_timer_unset(&send_ctl->path_timer_manager, XQC_TIMER_LOSS_DETECTION);
        return;
    }

    /* get PTO timeout and update loss detection timer */
    xqc_usec_t timeout = xqc_send_ctl_get_pto_time_and_space(send_ctl, now, &pns);
    interval = (timeout > now) ? (timeout - now) : 0;
    xqc_timer_set(&send_ctl->path_timer_manager, XQC_TIMER_LOSS_DETECTION, now, interval);

    xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_timer_set|update|PTO|XQC_TIMER_LOSS_DETECTION"
            "|conn:%p|path:%ui|pns:%d|expire:%ui|now:%ui|interval:%ui|pto_count:%ud|srtt:%ui",
            conn, path->path_id, pns, timeout, now, interval, send_ctl->ctl_pto_count, send_ctl->ctl_srtt);

}


/**
 * GetLossTimeAndSpace
 */
xqc_usec_t
xqc_send_ctl_get_earliest_loss_time(xqc_send_ctl_t *send_ctl, xqc_pkt_num_space_t *pns_ret)
{
    xqc_usec_t time = send_ctl->ctl_loss_time[XQC_PNS_INIT];
    *pns_ret = XQC_PNS_INIT;
    for (xqc_pkt_num_space_t pns = XQC_PNS_HSK; pns <= XQC_PNS_APP_DATA; ++pns) {
        if (send_ctl->ctl_loss_time[pns] != 0
            && (time == 0 || send_ctl->ctl_loss_time[pns] < time))
        {
            time = send_ctl->ctl_loss_time[pns];
            *pns_ret = pns;
        }
    }
    return time;
}


xqc_usec_t
xqc_send_ctl_get_srtt(xqc_send_ctl_t *send_ctl)
{
    return send_ctl->ctl_srtt;
}

float
xqc_send_ctl_get_retrans_rate(xqc_send_ctl_t *send_ctl)
{
    if (send_ctl->ctl_send_count <= 0) {
        return 0.0f;

    } else {
        return (float)(send_ctl->ctl_lost_count + send_ctl->ctl_tlp_count) / send_ctl->ctl_send_count;
    }
}

float
xqc_send_ctl_get_spurious_loss_rate(xqc_send_ctl_t *send_ctl)
{
    if (send_ctl->ctl_send_count <= 0) {
        return 0.0f;

    } else {
        return (float)(send_ctl->ctl_spurious_loss_count) / send_ctl->ctl_send_count;
    }
}


xqc_bool_t
xqc_send_ctl_check_anti_amplification(xqc_send_ctl_t *send_ctl, size_t send_bytes)
{
    xqc_connection_t *conn = send_ctl->ctl_conn;
    xqc_path_ctx_t *path = send_ctl->ctl_path;

    xqc_bool_t limit = XQC_FALSE;
    xqc_bool_t check = XQC_FALSE;

    if (conn->conn_type == XQC_CONN_TYPE_SERVER && send_ctl->ctl_bytes_send > 0) {
        if (xqc_path_is_initial_path(path)) {
            /* initial path => Before Address Validation */
            if (!(conn->conn_flag & XQC_CONN_FLAG_ADDR_VALIDATED)) {
                check = XQC_TRUE;
            }

        } else {
            /* multipath => Before Path Active */
            if (path->path_state < XQC_PATH_STATE_ACTIVE) {
                check = XQC_TRUE;
            }
        }
    }

    /* anti-amplifier attack limit */
    if (check) {
        limit = (send_ctl->ctl_bytes_send + send_bytes
                >= conn->conn_settings.anti_amplification_limit * send_ctl->ctl_bytes_recv);
    }

    return limit;
}


void
xqc_send_ctl_rearm_ld_timer(xqc_send_ctl_t *send_ctl)
{
    /* make sure the loss detection timer is armed */
    if (!xqc_timer_is_set(&send_ctl->path_timer_manager, XQC_TIMER_LOSS_DETECTION)) {
        xqc_send_ctl_set_loss_detection_timer(send_ctl);
    }
}


xqc_bool_t
xqc_send_ctl_ack_received_in_pns(xqc_send_ctl_t *send_ctl, xqc_pkt_num_space_t pns)
{
    return send_ctl->ctl_largest_acked_sent_time[pns] > 0;
}

xqc_packet_number_t
xqc_send_ctl_get_lost_sent_pn(xqc_send_ctl_t *send_ctl, xqc_pkt_num_space_t pns)
{
    xqc_packet_number_t largest_acked = send_ctl->ctl_largest_acked[pns];
    xqc_packet_number_t threshold = send_ctl->ctl_reordering_packet_threshold;
    xqc_packet_number_t lost_pn = XQC_MAX_UINT64_VALUE;     /* pkt num从0开始 */

    if (send_ctl->ctl_conn->enable_multipath == XQC_CONN_MULTIPATH_SINGLE_PNS) {
        /* Single pns */
        int ret = xqc_sent_record_lost_sent_pn(&send_ctl->ctl_sent_record[pns], largest_acked, threshold, &lost_pn);
        if (ret != XQC_OK) {
            xqc_log(send_ctl->ctl_conn->log, XQC_LOG_ERROR, "|xqc_sent_record_lost_sent_pn error|path:%ui|largest_acked:%ui|threshold:%ui|",
                        send_ctl->ctl_path->path_id, largest_acked, threshold);
        }
    }
    else {
        /* Multiple pns & Single path */
        if (largest_acked >= threshold) {
            lost_pn = largest_acked - threshold;
        }
    }

    return lost_pn;
}

xqc_packet_number_t
xqc_send_ctl_get_pkt_num_gap(xqc_send_ctl_t *send_ctl, xqc_pkt_num_space_t pns, xqc_packet_number_t front, xqc_packet_number_t back)
{
    xqc_packet_number_t gap = 0;

    if (send_ctl->ctl_conn->enable_multipath == XQC_CONN_MULTIPATH_SINGLE_PNS) {
        /* Single pns */
        int ret = xqc_sent_record_pn_gap(&send_ctl->ctl_sent_record[pns], front, back, &gap);
        if (ret != XQC_OK) {
            gap = 0;
            xqc_log(send_ctl->ctl_conn->log, XQC_LOG_ERROR, "|xqc_sent_record_pn_gap error|path:%ui|front:%ui|back:%ui|",
                        send_ctl->ctl_path->path_id, front, back);
        }
    }
    else {
        /* Multiple pns & Single path */
        gap = back - front;
    }

    return gap;
}

void
xqc_sent_record_init(xqc_sent_record_t *sent_record)
{
    xqc_memzero(sent_record, sizeof(xqc_sent_record_t));
    xqc_init_list_head(&sent_record->sent_pn_list);
    sent_record->latest_rtt_pn = XQC_MAX_UINT64_VALUE;
}

void
xqc_sent_record_release(xqc_sent_record_t *sent_record)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_number_node_t *pnode;
    xqc_list_for_each_safe(pos, next, &sent_record->sent_pn_list) {
        pnode = xqc_list_entry(pos, xqc_packet_number_node_t, pn_list);
        xqc_list_del_init(pos);
        xqc_free(pnode);
    }
}

xqc_int_t
xqc_sent_record_add(xqc_sent_record_t *sent_record, xqc_packet_number_t pkt_num, xqc_usec_t sent_time)
{
    xqc_packet_number_node_t *new_pn_node = NULL;
    xqc_packet_number_node_t *largest_pn_node = NULL;

    /* 检查pn单调递增 */
    if (!xqc_list_empty(&sent_record->sent_pn_list)) {
        largest_pn_node = xqc_list_entry(sent_record->sent_pn_list.prev, xqc_packet_number_node_t, pn_list);
        if (largest_pn_node->pkt_num >= pkt_num) {
            return XQC_ERROR;
        }
    }

    new_pn_node = xqc_calloc(1, sizeof(xqc_packet_number_node_t));
    if (new_pn_node == NULL) {
        return XQC_ERROR;
    }

    new_pn_node->pkt_num = pkt_num;
    new_pn_node->pkt_sent_time = sent_time;

    xqc_list_add_tail(&new_pn_node->pn_list, &sent_record->sent_pn_list);
    return XQC_OK;
}

void
xqc_sent_record_del(xqc_sent_record_t *sent_record)
{
    if (sent_record->latest_rtt_pn == XQC_MAX_UINT64_VALUE) {
        return;
    }

    xqc_list_head_t *head = &sent_record->sent_pn_list;
    xqc_list_head_t *pos, *next;
    xqc_packet_number_node_t *pn_node = NULL;

    xqc_list_for_each_safe(pos, next, head) {
        pn_node = xqc_list_entry(pos, xqc_packet_number_node_t, pn_list);

        if (pn_node->pkt_num < sent_record->latest_rtt_pn) {
            xqc_list_del_init(pos);
            xqc_free(pn_node);
        }
        else {
            break;
        }
    }
}

xqc_int_t
xqc_sent_record_lost_sent_pn(xqc_sent_record_t *sent_record, xqc_packet_number_t largest_acked, xqc_packet_number_t threshold, xqc_packet_number_t *lost_pn)
{
    xqc_list_head_t *head = &sent_record->sent_pn_list;
    xqc_list_head_t *pos, *next;
    xqc_list_head_t *pos_thrs;
    xqc_packet_number_node_t *pn_node = NULL;
    xqc_packet_number_node_t *lost_node = NULL;
    *lost_pn = XQC_MAX_UINT64_VALUE;

    xqc_list_for_each_safe(pos_thrs, next, head) {
        if (--threshold == 0) {
            break;
        }
    }

    /* largest_acked 之前的 pn数量小于 threshold */
    pn_node = xqc_list_entry(pos_thrs, xqc_packet_number_node_t, pn_list);
    if (threshold > 0 || pn_node->pkt_num >= largest_acked) {
        return XQC_OK;
    }

    pos = head->next;
    pos_thrs = pos_thrs->next;
    xqc_list_for_each_from(pos_thrs, head) {
        pn_node = xqc_list_entry(pos_thrs, xqc_packet_number_node_t, pn_list);
        if (pn_node->pkt_num >= largest_acked) {
            break;
        }
        pos = pos->next;
    }

    /* largest_acked不存在sent record里*/
    if (pn_node->pkt_num != largest_acked) {
        return XQC_ERROR;
    }

    lost_node = xqc_list_entry(pos, xqc_packet_number_node_t, pn_list);
    *lost_pn = lost_node->pkt_num;
    return XQC_OK;
}

/** Example
 * sent record: {1, 3, 5, 7, 9}
 * front = 3, back = 7
 * gap = 2
 */

xqc_int_t
xqc_sent_record_pn_gap(xqc_sent_record_t *sent_record, xqc_packet_number_t front, xqc_packet_number_t back, xqc_packet_number_t *gap)
{
    xqc_list_head_t *head = &sent_record->sent_pn_list;
    xqc_list_head_t *pos, *next;
    xqc_packet_number_node_t *pn_node = NULL;
    *gap = 0;

    xqc_list_for_each_safe(pos, next, head) {
        pn_node = xqc_list_entry(pos, xqc_packet_number_node_t, pn_list);
        if (pn_node->pkt_num >= front) {
            break;
        }
    }

    /* front 不存在 sent record 里*/
    if (pn_node->pkt_num != front) {
        return XQC_ERROR;
    }

    xqc_list_for_each_from(pos, head) {
        pn_node = xqc_list_entry(pos, xqc_packet_number_node_t, pn_list);
        if (pn_node->pkt_num >= back) {
            break;
        }
        *gap += 1;
    }

    /* back 不存在 sent record 里*/
    if (pn_node->pkt_num != back) {
        return XQC_ERROR;
    }

    return XQC_OK;
}

xqc_int_t
xqc_sent_record_get_largest_pn_in_ack(xqc_sent_record_t *sent_record, xqc_ack_info_t *const ack_info, xqc_packet_number_node_t **largest_pn_node)
{
    xqc_list_head_t *head = &sent_record->sent_pn_list;
    xqc_list_head_t *pos, *next;
    xqc_packet_number_node_t *pn_node = NULL;
    *largest_pn_node = NULL;
    xqc_packet_number_t largest_ack = ack_info->ranges[0].high;
    xqc_pktno_range_t *range = &ack_info->ranges[ack_info->n_ranges - 1];

    xqc_list_for_each_safe(pos, next, head) {
        pn_node = xqc_list_entry(pos, xqc_packet_number_node_t, pn_list);

        if (pn_node->pkt_num > largest_ack) {
            break;
        }

        while (pn_node->pkt_num > range->high && range != ack_info->ranges) {
            --range;
        }

        if (pn_node->pkt_num >= range->low) {
            *largest_pn_node = pn_node;
        }
    }

    return XQC_OK;
}

/*
void
xqc_sent_record_log(xqc_send_ctl_t *send_ctl, xqc_packet_out_t *packet_out)
{
    xqc_pkt_num_space_t pns = packet_out->po_pkt.pkt_pns;
    xqc_packet_number_node_t *first_node = xqc_list_entry(send_ctl->ctl_sent_record[pns].sent_pn_list.next, xqc_packet_number_node_t, pn_list);
    xqc_packet_number_node_t *last_node = xqc_list_entry(send_ctl->ctl_sent_record[pns].sent_pn_list.prev, xqc_packet_number_node_t, pn_list);
    xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|path:%ui|pkt_num:%ui|record_smallest_pn:%ui|record_largest_pn:%ui|",
            send_ctl->ctl_path->path_id, packet_out->po_pkt.pkt_num, first_node->pkt_num, last_node->pkt_num);
}
*/