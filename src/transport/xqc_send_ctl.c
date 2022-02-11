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
#include "src/common/xqc_timer.h"
#include "src/common/xqc_memory_pool.h"
#include "src/congestion_control/xqc_sample.h"
#include "src/transport/xqc_pacing.h"
#include "src/transport/xqc_utils.h"

int
xqc_send_ctl_indirectly_ack_po(xqc_send_ctl_t *ctl, xqc_packet_out_t *packet_out)
{
    if (packet_out->po_acked
        || (packet_out->po_origin && packet_out->po_origin->po_acked))
    {
        if (packet_out->po_origin && packet_out->po_origin->po_acked) {
            /* We should not do congestion control here. */
            xqc_send_ctl_on_packet_acked(ctl, packet_out, 0, 0);
        }
        xqc_send_ctl_maybe_remove_unacked(packet_out, ctl);
        return XQC_TRUE;
    }
    return XQC_FALSE;
}


xqc_send_ctl_t *
xqc_send_ctl_create(xqc_connection_t *conn)
{
    uint64_t now = xqc_monotonic_timestamp();
    xqc_send_ctl_t *send_ctl;
    send_ctl = xqc_pcalloc(conn->conn_pool, sizeof(xqc_send_ctl_t));
    if (send_ctl == NULL) {
        return NULL;
    }

    send_ctl->ctl_conn = conn;

    send_ctl->ctl_pto_count = 0;
    send_ctl->ctl_minrtt = XQC_MAX_UINT32_VALUE;
    send_ctl->ctl_srtt = XQC_kInitialRtt * 1000;
    send_ctl->ctl_rttvar = XQC_kInitialRtt * 1000 / 2;
    send_ctl->ctl_max_bytes_in_flight = 0;
    send_ctl->ctl_reordering_packet_threshold = XQC_kPacketThreshold;
    send_ctl->ctl_reordering_time_threshold_shift = XQC_kTimeThresholdShift;

    for (size_t i = 0; i < XQC_PNS_N; i++) {
        send_ctl->ctl_largest_acked[i] = XQC_MAX_UINT64_VALUE;
        send_ctl->ctl_time_of_last_sent_ack_eliciting_packet[i] = 0;
        send_ctl->ctl_loss_time[i] = 0;
    }

    memset(&send_ctl->ctl_largest_acked_sent_time, 0,
           sizeof(send_ctl->ctl_largest_acked_sent_time));

    send_ctl->ctl_is_cwnd_limited = 0;
    send_ctl->ctl_delivered = 0;
    send_ctl->ctl_lost_pkts_number = 0;
    send_ctl->ctl_last_inflight_pkt_sent_time = 0;

    xqc_init_list_head(&send_ctl->ctl_send_packets);
    xqc_init_list_head(&send_ctl->ctl_send_packets_high_pri);
    xqc_init_list_head(&send_ctl->ctl_pto_probe_packets);
    xqc_init_list_head(&send_ctl->ctl_lost_packets);
    xqc_init_list_head(&send_ctl->ctl_free_packets);
    xqc_init_list_head(&send_ctl->ctl_buff_1rtt_packets);
    for (xqc_pkt_num_space_t pns = 0; pns < XQC_PNS_N; ++pns) {
        xqc_init_list_head(&send_ctl->ctl_unacked_packets[pns]);
    }

    send_ctl->ctl_packets_used_max = XQC_CTL_PACKETS_USED_MAX;

    xqc_send_ctl_timer_init(send_ctl);

    xqc_send_ctl_timer_set(send_ctl, XQC_TIMER_IDLE,
                           now, xqc_conn_get_idle_timeout(conn) * 1000);

    if (conn->conn_settings.ping_on && conn->conn_type == XQC_CONN_TYPE_CLIENT) {
        xqc_send_ctl_timer_set(send_ctl, XQC_TIMER_PING, now, XQC_PING_TIMEOUT * 1000);
    }

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
xqc_send_ctl_destroy(xqc_send_ctl_t *ctl)
{
    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|destroy|");
    xqc_send_ctl_destroy_packets_lists(ctl);
}

xqc_packet_out_t *
xqc_send_ctl_get_packet_out(xqc_send_ctl_t *ctl, unsigned need, xqc_pkt_type_t pkt_type)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t  *pos;

    xqc_list_for_each_reverse(pos, &ctl->ctl_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == pkt_type 
            && packet_out->po_buf_size - packet_out->po_used_size >= need)
        {
            return packet_out;
        }
    }

    packet_out = xqc_packet_out_get_and_insert_send(ctl, pkt_type);
    if (packet_out == NULL) {
        return NULL;
    }

    return packet_out;
}

void
xqc_send_ctl_destroy_packets_list(xqc_list_head_t *head)
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
xqc_send_ctl_destroy_packets_lists(xqc_send_ctl_t *ctl)
{
    xqc_send_ctl_destroy_packets_list(&ctl->ctl_send_packets);
    xqc_send_ctl_destroy_packets_list(&ctl->ctl_send_packets_high_pri);
    xqc_send_ctl_destroy_packets_list(&ctl->ctl_lost_packets);
    xqc_send_ctl_destroy_packets_list(&ctl->ctl_pto_probe_packets);
    xqc_send_ctl_destroy_packets_list(&ctl->ctl_free_packets);
    xqc_send_ctl_destroy_packets_list(&ctl->ctl_buff_1rtt_packets);

    for (xqc_pkt_num_space_t pns = 0; pns < XQC_PNS_N; ++pns) {
        xqc_send_ctl_destroy_packets_list(&ctl->ctl_unacked_packets[pns]);
        ctl->ctl_bytes_ack_eliciting_inflight[pns] = 0;
    }

    ctl->ctl_bytes_in_flight = 0;
    ctl->ctl_packets_used = 0;
    ctl->ctl_packets_free = 0;
}

int
xqc_send_ctl_out_q_empty(xqc_send_ctl_t *ctl)
{
    int empty;
    empty = xqc_list_empty(&ctl->ctl_send_packets)
            && xqc_list_empty(&ctl->ctl_send_packets_high_pri)
            && xqc_list_empty(&ctl->ctl_lost_packets)
            && xqc_list_empty(&ctl->ctl_pto_probe_packets)
            && xqc_list_empty(&ctl->ctl_buff_1rtt_packets);
    if (!empty) {
        return empty;
    }

    for (xqc_pkt_num_space_t pns = 0; pns < XQC_PNS_N; ++pns) {
        empty = empty && xqc_list_empty(&ctl->ctl_unacked_packets[pns]);
    }

    return empty;
}

void 
xqc_send_ctl_info_circle_record(xqc_connection_t *conn)
{
    if (conn->conn_type != XQC_CONN_TYPE_SERVER) {
        return; /* client do not need record */
    }
    xqc_send_ctl_t *conn_send_ctl = conn->conn_send_ctl;
    xqc_send_ctl_info_t *ctl_info = &conn_send_ctl->ctl_info;

    xqc_usec_t now = xqc_monotonic_timestamp();
    if (ctl_info->record_interval < 10000) { /* minimum 10ms interval to avoid log flooding */
        return;
    }

    if (ctl_info->last_record_time + ctl_info->record_interval > now) { /* not yet time to record */
        return;
    }
    ctl_info->last_record_time = now;

    uint64_t cwnd = conn_send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(conn_send_ctl->ctl_cong);

    uint64_t bw = 0;
    uint64_t pacing_rate = 0;
    int mode = 0;
    int recovery = 0;
    int slow_start = 0;
    xqc_usec_t min_rtt = 0;

    if (conn_send_ctl->ctl_cong_callback->xqc_cong_ctl_init_bbr) {
        bw = conn_send_ctl->ctl_cong_callback->
             xqc_cong_ctl_get_bandwidth_estimate(conn_send_ctl->ctl_cong);
        pacing_rate = conn_send_ctl->ctl_cong_callback->
                      xqc_cong_ctl_get_pacing_rate(conn_send_ctl->ctl_cong);
        mode = conn_send_ctl->ctl_cong_callback->
               xqc_cong_ctl_info_cb->mode(conn_send_ctl->ctl_cong);
        min_rtt = conn_send_ctl->ctl_cong_callback->
                  xqc_cong_ctl_info_cb->min_rtt(conn_send_ctl->ctl_cong);
    }
    recovery = conn_send_ctl->ctl_cong_callback->xqc_cong_ctl_in_recovery(conn_send_ctl->ctl_cong);
    if (conn_send_ctl->ctl_cong_callback->xqc_cong_ctl_in_slow_start) {
        slow_start = conn_send_ctl->ctl_cong_callback->xqc_cong_ctl_in_slow_start(conn_send_ctl->ctl_cong);
    }
    uint64_t srtt = conn_send_ctl->ctl_srtt;
    xqc_conn_log(conn, XQC_LOG_STATS,
                 "|cwnd:%ui|inflight:%ud|mode:%ud|applimit:%ud|pacing_rate:%ui|bw:%ui|"
                 "srtt:%ui|latest_rtt:%ui|min_rtt:%ui|send:%ud|lost:%ud|tlp:%ud|recv:%ud|"
                 "recovery:%ud|slow_start:%ud|conn_life:%ui|",
                 cwnd, conn_send_ctl->ctl_bytes_in_flight,
                 mode, conn_send_ctl->ctl_app_limited, pacing_rate, bw,
                 srtt, conn_send_ctl->ctl_latest_rtt, min_rtt,
                 conn_send_ctl->ctl_send_count, conn_send_ctl->ctl_lost_count,
                 conn_send_ctl->ctl_tlp_count,
                 conn_send_ctl->ctl_recv_count,
                 recovery, slow_start,
                 now - conn->conn_create_time);

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
xqc_send_ctl_can_send(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    int can = 1;
    unsigned congestion_window =
            conn->conn_send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(conn->conn_send_ctl->ctl_cong);

    if (conn->conn_settings.so_sndbuf > 0) {
        congestion_window = xqc_min(congestion_window, conn->conn_settings.so_sndbuf);
    }

    if (conn->conn_send_ctl->ctl_bytes_in_flight + packet_out->po_used_size > congestion_window) {
        can = 0;
    }

    /* anti-amplifier attack limit */
    if (conn->conn_type == XQC_CONN_TYPE_SERVER
        && !(conn->conn_flag & XQC_CONN_FLAG_ADDR_VALIDATED))
    {
        if (xqc_send_ctl_check_anti_amplification(conn, packet_out->po_used_size)) {
            can = 0;
        }
    }

    xqc_conn_log(conn, XQC_LOG_DEBUG, "|can:%d|pkt_sz:%ud|inflight:%ud|cwnd:%ud|conn:%p|",
                 can, packet_out->po_used_size, conn->conn_send_ctl->ctl_bytes_in_flight,
                 congestion_window, conn);
    return can;
}

void
xqc_send_ctl_maybe_remove_unacked(xqc_packet_out_t *packet_out, xqc_send_ctl_t *ctl)
{
    /* it is origin & some pkt ref to this packet */
    if (packet_out->po_origin == NULL && packet_out->po_origin_ref_cnt != 0) {
        return;
    }

    xqc_send_ctl_remove_unacked(packet_out, ctl);
    xqc_send_ctl_insert_free(&packet_out->po_list, &ctl->ctl_free_packets, ctl);

    if (packet_out->po_origin
        && (--packet_out->po_origin->po_origin_ref_cnt) == 0)
    {
        xqc_send_ctl_remove_unacked(packet_out->po_origin, ctl);
        xqc_send_ctl_insert_free(&packet_out->po_origin->po_list, &ctl->ctl_free_packets, ctl);
    }
}

void
xqc_send_ctl_copy_to_lost(xqc_packet_out_t *packet_out, xqc_send_ctl_t *ctl)
{
    xqc_packet_out_t *new_po = xqc_packet_out_get(ctl);
    if (!new_po) {
        XQC_CONN_ERR(ctl->ctl_conn, XQC_EMALLOC);
        return;
    }

    xqc_packet_out_copy(new_po, packet_out);

    if ((new_po->po_ack_offset > 0) && (new_po->po_frame_types & XQC_FRAME_BIT_ACK)) {
        new_po->po_frame_types &= ~XQC_FRAME_BIT_ACK;
        new_po->po_used_size = new_po->po_ack_offset;
        int ret = xqc_write_ack_to_one_packet(ctl->ctl_conn, new_po, new_po->po_pkt.pkt_pns);
        if (ret < 0) {
            xqc_log(ctl->ctl_conn->log, XQC_LOG_WARN, "|xqc_write_ack_to_one_packet error|");
        }
    }

    xqc_send_ctl_insert_lost(&new_po->po_list, &ctl->ctl_lost_packets);
    ctl->ctl_packets_used++;
    packet_out->po_flag |= XQC_POF_RETRANSED;
}

void
xqc_send_ctl_copy_to_pto_probe_list(xqc_packet_out_t *packet_out, xqc_send_ctl_t *ctl)
{
    xqc_packet_out_t *new_po = xqc_packet_out_get(ctl);
    if (!new_po) {
        XQC_CONN_ERR(ctl->ctl_conn, XQC_EMALLOC);
        return;
    }

    xqc_packet_out_copy(new_po, packet_out);

    if ((new_po->po_ack_offset > 0) && (new_po->po_frame_types & XQC_FRAME_BIT_ACK)) {
        new_po->po_frame_types &= ~XQC_FRAME_BIT_ACK;
        new_po->po_used_size = new_po->po_ack_offset;
        int ret = xqc_write_ack_to_one_packet(ctl->ctl_conn, new_po, new_po->po_pkt.pkt_pns);
        if (ret < 0) {
            xqc_log(ctl->ctl_conn->log, XQC_LOG_WARN, "|xqc_write_ack_to_one_packet error|");
        }
    }

    xqc_send_ctl_insert_probe(&new_po->po_list, &ctl->ctl_pto_probe_packets);
    ctl->ctl_packets_used++;
    packet_out->po_flag |= XQC_POF_RETRANSED;
}

void
xqc_send_ctl_on_reset_stream_acked(xqc_send_ctl_t *ctl, xqc_packet_out_t *packet_out)
{
    if (packet_out->po_frame_types & XQC_FRAME_BIT_RESET_STREAM) {
        xqc_stream_t *stream;
        for (int i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
            if (packet_out->po_stream_frames[i].ps_is_used == 0) {
                break;
            }
            stream = xqc_find_stream_by_id(packet_out->po_stream_frames[i].ps_stream_id, ctl->ctl_conn->streams_hash);
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
xqc_send_ctl_increase_unacked_stream_ref(xqc_send_ctl_t *ctl, xqc_packet_out_t *packet_out)
{
    if ((packet_out->po_frame_types & XQC_FRAME_BIT_STREAM)
        && !(packet_out->po_flag & XQC_POF_STREAM_UNACK))
    {
        if ((!packet_out->po_origin)) {
            xqc_stream_t *stream;
            for (int i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
                if (packet_out->po_stream_frames[i].ps_is_used == 0) {
                    break;
                }
                stream = xqc_find_stream_by_id(packet_out->po_stream_frames[i].ps_stream_id, ctl->ctl_conn->streams_hash);
                if (stream != NULL) {
                    stream->stream_unacked_pkt++;
                    /* Update stream state */
                    if (stream->stream_state_send == XQC_SEND_STREAM_ST_READY) {
                        xqc_stream_send_state_update(stream, XQC_SEND_STREAM_ST_SEND);
                    }
                    if (packet_out->po_stream_frames[i].ps_has_fin
                        && stream->stream_state_send == XQC_SEND_STREAM_ST_SEND)
                    {
                        xqc_stream_send_state_update(stream, XQC_SEND_STREAM_ST_DATA_SENT);
                    }
                }
            }
        }
        packet_out->po_flag |= XQC_POF_STREAM_UNACK;
    }
}

void
xqc_send_ctl_decrease_unacked_stream_ref(xqc_send_ctl_t *ctl, xqc_packet_out_t *packet_out)
{
    int first_time_ack = 1;
    if (packet_out->po_flag & XQC_POF_STREAM_UNACK) {
        first_time_ack = first_time_ack && (!packet_out->po_acked);
        if (packet_out->po_origin) {
            first_time_ack = first_time_ack && (!packet_out->po_origin->po_acked);
        }
        if (first_time_ack) {
            xqc_stream_t *stream;
            for (int i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
                if (packet_out->po_stream_frames[i].ps_is_used == 0) {
                    break;
                }
                stream = xqc_find_stream_by_id(packet_out->po_stream_frames[i].ps_stream_id, ctl->ctl_conn->streams_hash);
                if (stream != NULL) {
                    if (stream->stream_unacked_pkt == 0) {
                        xqc_log(ctl->ctl_conn->log, XQC_LOG_ERROR, "|stream_unacked_pkt too small|");

                    } else {
                        stream->stream_unacked_pkt--;
                    }

                    if (packet_out->po_stream_frames[i].ps_has_fin && stream->stream_stats.first_fin_ack_time == 0) {
                        stream->stream_stats.first_fin_ack_time = xqc_monotonic_timestamp();
                    }
                    
                    /* Update stream state */
                    if (stream->stream_unacked_pkt == 0 && stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_SENT) {
                        xqc_stream_send_state_update(stream, XQC_SEND_STREAM_ST_DATA_RECVD);
                        xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|stream enter DATA RECVD|");
                        xqc_stream_maybe_need_close(stream);
                    }
                }
            }
        }
        packet_out->po_flag &= ~XQC_POF_STREAM_UNACK;
    }
}

void
xqc_send_ctl_increase_inflight(xqc_send_ctl_t *ctl, xqc_packet_out_t *packet_out)
{
    if (!(packet_out->po_flag & XQC_POF_IN_FLIGHT) && XQC_CAN_IN_FLIGHT(packet_out->po_frame_types)) {
        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            ctl->ctl_bytes_in_flight += packet_out->po_used_size;
            ctl->ctl_bytes_ack_eliciting_inflight[packet_out->po_pkt.pkt_pns] += packet_out->po_used_size;
            packet_out->po_flag |= XQC_POF_IN_FLIGHT;
        }
    }
}

void
xqc_send_ctl_decrease_inflight(xqc_send_ctl_t *ctl, xqc_packet_out_t *packet_out)
{
    if (packet_out->po_flag & XQC_POF_IN_FLIGHT) {
        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            if (ctl->ctl_bytes_ack_eliciting_inflight[packet_out->po_pkt.pkt_pns] < packet_out->po_used_size) {
                xqc_log(ctl->ctl_conn->log, XQC_LOG_ERROR, "|ctl_bytes_in_flight too small|");
                ctl->ctl_bytes_ack_eliciting_inflight[packet_out->po_pkt.pkt_pns] = 0;
                ctl->ctl_bytes_in_flight = 0;

            } else {
                ctl->ctl_bytes_ack_eliciting_inflight[packet_out->po_pkt.pkt_pns] -= packet_out->po_used_size;
                ctl->ctl_bytes_in_flight -= packet_out->po_used_size;
            }
            packet_out->po_flag &= ~XQC_POF_IN_FLIGHT;
        }
    }
}

void
xqc_send_ctl_remove_unacked(xqc_packet_out_t *packet_out, xqc_send_ctl_t *ctl)
{
    xqc_list_del_init(&packet_out->po_list);

}

void
xqc_send_ctl_insert_unacked(xqc_packet_out_t *packet_out, xqc_list_head_t *head, xqc_send_ctl_t *ctl)
{
    xqc_list_add_tail(&packet_out->po_list, head);
}

void
xqc_send_ctl_remove_send(xqc_list_head_t *pos)
{
    xqc_list_del_init(pos);
}

void
xqc_send_ctl_insert_send(xqc_list_head_t *pos, xqc_list_head_t *head, xqc_send_ctl_t *ctl)
{
    xqc_list_add_tail(pos, head);
    ctl->ctl_packets_used++;
}

void
xqc_send_ctl_remove_probe(xqc_list_head_t *pos)
{
    xqc_list_del_init(pos);
}

void
xqc_send_ctl_insert_probe(xqc_list_head_t *pos, xqc_list_head_t *head)
{
    xqc_list_add_tail(pos, head);
}

void
xqc_send_ctl_remove_lost(xqc_list_head_t *pos)
{
    xqc_list_del_init(pos);
}

void
xqc_send_ctl_insert_lost(xqc_list_head_t *pos, xqc_list_head_t *head)
{
    xqc_list_add_tail(pos, head);
}

void
xqc_send_ctl_remove_free(xqc_list_head_t *pos, xqc_send_ctl_t *ctl)
{
    xqc_list_del_init(pos);
    ctl->ctl_packets_free--;
}

void
xqc_send_ctl_insert_free(xqc_list_head_t *pos, xqc_list_head_t *head, xqc_send_ctl_t *ctl)
{
    xqc_list_add_tail(pos, head);
    ctl->ctl_packets_free++;
    ctl->ctl_packets_used--;
}

void
xqc_send_ctl_remove_buff(xqc_list_head_t *pos, xqc_send_ctl_t *ctl)
{
    xqc_list_del_init(pos);
    ctl->ctl_packets_used--;
}

void
xqc_send_ctl_insert_buff(xqc_list_head_t *pos, xqc_list_head_t *head)
{
    xqc_list_add_tail(pos, head);
}

void
xqc_send_ctl_move_to_head(xqc_list_head_t *pos, xqc_list_head_t *head)
{
    xqc_list_del_init(pos);
    xqc_list_add(pos, head);
}

void
xqc_send_ctl_move_to_high_pri(xqc_list_head_t *pos, xqc_send_ctl_t *ctl)
{
    xqc_list_del_init(pos);
    xqc_list_add_tail(pos, &ctl->ctl_send_packets_high_pri);
}

void
xqc_send_ctl_drop_packets(xqc_send_ctl_t *ctl)
{
    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|ctl_bytes_in_flight:%ui|"
            "ctl_packets_used:%ud|ctl_packets_free:%ud|",
            ctl->ctl_bytes_in_flight, ctl->ctl_packets_used, ctl->ctl_packets_free);
    xqc_send_ctl_destroy_packets_lists(ctl);
}

void
xqc_send_ctl_drop_0rtt_packets(xqc_send_ctl_t *ctl)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *packet_out;
    xqc_list_for_each_safe(pos, next, &ctl->ctl_unacked_packets[XQC_PNS_APP_DATA]) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
            xqc_send_ctl_remove_unacked(packet_out, ctl);
            xqc_send_ctl_insert_free(pos, &ctl->ctl_free_packets, ctl);
            xqc_send_ctl_decrease_inflight(ctl, packet_out);
            if (packet_out->po_origin == NULL) {
                xqc_send_ctl_decrease_unacked_stream_ref(ctl, packet_out);
            }
        }
    }

    xqc_list_for_each_safe(pos, next, &ctl->ctl_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
            xqc_send_ctl_remove_send(pos);
            xqc_send_ctl_insert_free(pos, &ctl->ctl_free_packets, ctl);
        }
    }

    xqc_list_for_each_safe(pos, next, &ctl->ctl_lost_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
            xqc_send_ctl_remove_lost(pos);
            xqc_send_ctl_insert_free(pos, &ctl->ctl_free_packets, ctl);
        }
    }

    xqc_list_for_each_safe(pos, next, &ctl->ctl_pto_probe_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
            xqc_send_ctl_remove_probe(pos);
            xqc_send_ctl_insert_free(pos, &ctl->ctl_free_packets, ctl);
        }
    }
}


void
xqc_send_ctl_drop_packets_from_list_with_type(xqc_send_ctl_t *ctl, xqc_pkt_type_t type,
    xqc_list_head_t *list, const char *list_name)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *packet_out;

    xqc_list_for_each_safe(pos, next, list) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == type) {
            xqc_send_ctl_remove_send(pos);
            xqc_send_ctl_insert_free(pos, &ctl->ctl_free_packets, ctl);

        xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|drop pkt from %s list|inflight:%ud|cwnd:%ui|"
                "pkt_num:%ui|ptype:%d|frames:%s|len:%ud|", list_name, ctl->ctl_bytes_in_flight,
                ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong), packet_out->po_pkt.pkt_num, 
                packet_out->po_pkt.pkt_type, xqc_frame_type_2_str(packet_out->po_frame_types),
                packet_out->po_used_size);
        }
    }
}

void
xqc_send_ctl_drop_packets_with_type(xqc_send_ctl_t *ctl, xqc_pkt_type_t type)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *packet_out;

    xqc_pkt_num_space_t pns = xqc_packet_type_to_pns(type);
    if (pns == XQC_PNS_N) {
        xqc_log(ctl->ctl_conn->log, XQC_LOG_ERROR, "|illegal packet type|type:%d|", type);
        return;
    }

    xqc_list_for_each_safe(pos, next, &ctl->ctl_unacked_packets[pns]) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        xqc_send_ctl_remove_unacked(packet_out, ctl);
        xqc_send_ctl_insert_free(pos, &ctl->ctl_free_packets, ctl);
        xqc_send_ctl_decrease_inflight(ctl, packet_out);
        xqc_send_ctl_decrease_unacked_stream_ref(ctl, packet_out);

        xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|drop pkt from unacked|inflight:%ui|cwnd:%ui|"
                "pkt_num:%ui|ptype:%d|frames:%s|", ctl->ctl_bytes_in_flight, 
            ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong), packet_out->po_pkt.pkt_num, 
            packet_out->po_pkt.pkt_type, xqc_frame_type_2_str(packet_out->po_frame_types));
    }

    xqc_send_ctl_drop_packets_from_list_with_type(ctl, type, &ctl->ctl_send_packets_high_pri, "high_pri");
    xqc_send_ctl_drop_packets_from_list_with_type(ctl, type, &ctl->ctl_send_packets, "send");
    xqc_send_ctl_drop_packets_from_list_with_type(ctl, type, &ctl->ctl_lost_packets, "lost");
    xqc_send_ctl_drop_packets_from_list_with_type(ctl, type, &ctl->ctl_pto_probe_packets, "pto_probe");
}

void
xqc_send_ctl_on_pns_discard(xqc_send_ctl_t *ctl, xqc_pkt_num_space_t pns)
{
    ctl->ctl_time_of_last_sent_ack_eliciting_packet[pns] = 0;
    ctl->ctl_loss_time[pns] = 0;
    ctl->ctl_pto_count = 0;
    xqc_log(ctl->ctl_conn->log, XQC_LOG_INFO, "|xqc_send_ctl_set_loss_detection_timer on discard pns:%ud", pns);
    xqc_send_ctl_set_loss_detection_timer(ctl);
}

void
xqc_send_ctl_drop_pkts_with_pn(xqc_send_ctl_t *ctl, xqc_pkt_num_space_t pn)
{
    switch (pn) {
    case XQC_PNS_INIT:
        xqc_send_ctl_drop_packets_with_type(ctl, XQC_PTYPE_INIT);
        break;

    case XQC_PNS_HSK:
        xqc_send_ctl_drop_packets_with_type(ctl, XQC_PTYPE_HSK);
        break;
    
    default:
        break;
    }

    xqc_send_ctl_on_pns_discard(ctl, pn);
}

int
xqc_send_ctl_stream_frame_can_drop(xqc_send_ctl_t *ctl, xqc_packet_out_t *packet_out, xqc_stream_id_t stream_id)
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
xqc_send_ctl_drop_stream_frame_packets(xqc_send_ctl_t *ctl, xqc_stream_id_t stream_id)
{
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

    xqc_list_for_each_safe(pos, next, &ctl->ctl_unacked_packets[XQC_PNS_APP_DATA]) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_frame_types == XQC_FRAME_BIT_STREAM) {
            drop = xqc_send_ctl_stream_frame_can_drop(ctl, packet_out, stream_id);
            if (drop) {
                count++;
                xqc_send_ctl_decrease_inflight(ctl, packet_out);
                xqc_send_ctl_remove_unacked(packet_out, ctl);
                xqc_send_ctl_insert_free(pos, &ctl->ctl_free_packets, ctl);
            }
        }
    }

    xqc_list_for_each_safe(pos, next, &ctl->ctl_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_frame_types == XQC_FRAME_BIT_STREAM) {
            drop = xqc_send_ctl_stream_frame_can_drop(ctl, packet_out, stream_id);
            if (drop) {
                count++;
                xqc_send_ctl_remove_send(pos);
                xqc_send_ctl_insert_free(pos, &ctl->ctl_free_packets, ctl);
            }
        }
    }

    xqc_list_for_each_safe(pos, next, &ctl->ctl_lost_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_frame_types == XQC_FRAME_BIT_STREAM) {
            drop = xqc_send_ctl_stream_frame_can_drop(ctl, packet_out, stream_id);
            if (drop) {
                count++;
                xqc_send_ctl_remove_lost(pos);
                xqc_send_ctl_insert_free(pos, &ctl->ctl_free_packets, ctl);
            }
        }
    }

    xqc_list_for_each_safe(pos, next, &ctl->ctl_pto_probe_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_frame_types == XQC_FRAME_BIT_STREAM) {
            drop = xqc_send_ctl_stream_frame_can_drop(ctl, packet_out, stream_id);
            if (drop) {
                count++;
                xqc_send_ctl_remove_probe(pos);
                xqc_send_ctl_insert_free(pos, &ctl->ctl_free_packets, ctl);
            }
        }
    }

    if (count > 0) {
        xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|stream_id:%ui|to_drop: %d|count:%d|", stream_id, to_drop, count);
    }
}

static void 
xqc_send_ctl_update_cwnd_limited(xqc_send_ctl_t *ctl)
{
    if (ctl->ctl_bytes_in_flight > ctl->ctl_max_bytes_in_flight) {
        ctl->ctl_max_bytes_in_flight = ctl->ctl_bytes_in_flight;
    }
    uint32_t cwnd_bytes = ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong);
    /* If we can not send the next full-size packet, we are CWND limited. */
    ctl->ctl_is_cwnd_limited = 0;
    if ((ctl->ctl_bytes_in_flight + XQC_QUIC_MSS) > cwnd_bytes) {
        ctl->ctl_is_cwnd_limited = 1;
    }
}

static void
xqc_send_ctl_update_stream_stats_on_sent(xqc_send_ctl_t *ctl, xqc_packet_out_t *packet_out, xqc_usec_t now)
{
    xqc_stream_id_t stream_id;
    xqc_stream_t *stream;
    if (packet_out->po_frame_types & XQC_FRAME_BIT_STREAM) {
        for (int i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
            if (packet_out->po_stream_frames[i].ps_is_used == 0) {
                break;
            }
            stream_id = packet_out->po_stream_frames[i].ps_stream_id;
            stream = xqc_find_stream_by_id(stream_id, ctl->ctl_conn->streams_hash);
            if (stream) {
                if (stream->stream_stats.first_snd_time == 0) {
                    stream->stream_stats.first_snd_time = now;
                }
                if (packet_out->po_stream_frames[i].ps_has_fin) {
                    stream->stream_stats.local_fin_snd_time = now;
                }
                if (packet_out->po_stream_frames[i].ps_is_reset) {
                    stream->stream_stats.local_reset_time = now;
                }
            }

        }
    }
}

/**
 * OnPacketSent
 */
void
xqc_send_ctl_on_packet_sent(xqc_send_ctl_t *ctl, xqc_packet_out_t *packet_out, xqc_usec_t now)
{
    xqc_pkt_num_space_t pns = packet_out->po_pkt.pkt_pns;

    xqc_sample_on_sent(packet_out, ctl, now);

    xqc_packet_number_t orig_pktnum = packet_out->po_origin ? packet_out->po_origin->po_pkt.pkt_num : 0;
    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG,
            "|conn:%p|pkt_num:%ui|origin_pktnum:%ui|size:%ud|pkt_type:%s|frame:%s|conn_state:%s|po_in_flight:%d|",
            ctl->ctl_conn, packet_out->po_pkt.pkt_num, orig_pktnum, packet_out->po_used_size,
            xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
            xqc_frame_type_2_str(packet_out->po_frame_types),
            xqc_conn_state_2_str(ctl->ctl_conn->conn_state), 
            packet_out->po_flag & XQC_POF_IN_FLIGHT ? 1: 0);

    if (packet_out->po_pkt.pkt_num > ctl->ctl_largest_sent[pns]) {
        ctl->ctl_largest_sent[pns] = packet_out->po_pkt.pkt_num;
    }

    ctl->ctl_bytes_send += packet_out->po_used_size;

    if (XQC_CAN_IN_FLIGHT(packet_out->po_frame_types)) {

        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            ctl->ctl_time_of_last_sent_ack_eliciting_packet[pns] = 
            packet_out->po_sent_time;
            ctl->ctl_last_sent_ack_eliciting_packet_number[pns] = 
            packet_out->po_pkt.pkt_num;
            /*
             * The timer is also restarted
             * when sending a packet containing frames other than ACK or PADDING (an
             * ACK-eliciting packet
             */
            /* udp does not recognize if a packet is actually sent to the peer */
            /* TODO: xqc_send_ctl_timer_set(ctl, XQC_TIMER_IDLE, now + ctl->ctl_conn->local_settings.idle_timeout * 1000); */
        }
        xqc_send_ctl_update_stream_stats_on_sent(ctl, packet_out, now);

        xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, 
                "|inflight:%ud|applimit:%ui|", 
                ctl->ctl_bytes_in_flight, ctl->ctl_app_limited);
        if (ctl->ctl_bytes_in_flight == 0) {
            if (ctl->ctl_cong_callback->xqc_cong_ctl_init_bbr 
                && ctl->ctl_app_limited > 0)
            {
                uint8_t mode, idle_restart;
                mode = ctl->ctl_cong_callback->
                    xqc_cong_ctl_info_cb->mode(ctl->ctl_cong);
                idle_restart = ctl->ctl_cong_callback->
                            xqc_cong_ctl_info_cb->
                            idle_restart(ctl->ctl_cong);
                xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, 
                        "|BeforeRestartFromIdle|mode %ud|idle %ud"
                        "|bw %ud|pacing rate %ud|",
                        (unsigned int)mode, (unsigned int)idle_restart, ctl->ctl_cong_callback->
                        xqc_cong_ctl_get_bandwidth_estimate(ctl->ctl_cong),
                        ctl->ctl_cong_callback->
                        xqc_cong_ctl_get_pacing_rate(ctl->ctl_cong));

                ctl->ctl_cong_callback->xqc_cong_ctl_restart_from_idle(ctl->ctl_cong, ctl->ctl_delivered);
                xqc_log_event(ctl->ctl_conn->log, REC_CONGESTION_STATE_UPDATED, "restart");

                xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, 
                        "|AfterRestartFromIdle|mode %ud|"
                        "idle %ud|bw %ud|pacing rate %ud|",
                        (unsigned int)mode, (unsigned int)idle_restart, ctl->ctl_cong_callback->
                        xqc_cong_ctl_get_bandwidth_estimate(ctl->ctl_cong),
                        ctl->ctl_cong_callback->xqc_cong_ctl_get_pacing_rate(ctl->ctl_cong));
            }
            if (!ctl->ctl_cong_callback->xqc_cong_ctl_init_bbr) {
                xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|Restart from idle|");
                ctl->ctl_cong_callback->xqc_cong_ctl_restart_from_idle(ctl->ctl_cong, ctl->ctl_last_inflight_pkt_sent_time);
                xqc_log_event(ctl->ctl_conn->log, REC_CONGESTION_STATE_UPDATED, "restart");
            }
        }

        if (!(packet_out->po_flag & XQC_POF_IN_FLIGHT)) {
            xqc_send_ctl_increase_inflight(ctl, packet_out);
            xqc_send_ctl_increase_unacked_stream_ref(ctl, packet_out);
        }

        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            xqc_send_ctl_set_loss_detection_timer(ctl);
        }

        if (packet_out->po_flag & XQC_POF_LOST) {
            ++ctl->ctl_lost_count;
            packet_out->po_flag &= ~XQC_POF_LOST;

        } else if (packet_out->po_flag & XQC_POF_TLP) {
            ++ctl->ctl_tlp_count;
            packet_out->po_flag &= ~XQC_POF_TLP;
        }
        ++ctl->ctl_send_count;

        ctl->ctl_last_inflight_pkt_sent_time = now;
        xqc_send_ctl_update_cwnd_limited(ctl);
    }
}

/**
 * OnAckReceived
 */
int
xqc_send_ctl_on_ack_received(xqc_send_ctl_t *ctl, xqc_ack_info_t *const ack_info, xqc_usec_t ack_recv_time)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;
    unsigned char update_rtt = 0, has_ack_eliciting = 0, spurious_loss_detected = 0;
    xqc_packet_number_t largest_ack = ack_info->ranges[0].high;
    xqc_packet_number_t spurious_loss_pktnum = 0;
    xqc_usec_t spurious_loss_sent_time = 0;
    xqc_pktno_range_t *range = &ack_info->ranges[ack_info->n_ranges - 1];
    xqc_pkt_num_space_t pns = ack_info->pns;
    unsigned char need_del_record = 0;
    int stream_frame_acked = 0;
    ctl->ctl_prior_delivered = ctl->ctl_delivered;
    ctl->ctl_prior_bytes_in_flight = ctl->ctl_bytes_in_flight;

    if (ctl->ctl_largest_acked[pns] == XQC_MAX_UINT64_VALUE) {
        ctl->ctl_largest_acked[pns] = largest_ack;

    } else {
        ctl->ctl_largest_acked[pns] = xqc_max(ctl->ctl_largest_acked[pns], largest_ack);
    }

    if (largest_ack > ctl->ctl_largest_sent[pns]) {
        xqc_log(ctl->ctl_conn->log, XQC_LOG_ERROR, "|acked pkt is not sent yet|%ui|", largest_ack);
        return -XQC_EPROTO;
    }

    /* detect and remove acked packets */
    xqc_list_for_each_safe(pos, next, &ctl->ctl_unacked_packets[pns]) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_num > largest_ack) {
            break;
        }

        while (packet_out->po_pkt.pkt_num > range->high && range != ack_info->ranges) {
            --range;
        }

        if (packet_out->po_pkt.pkt_num >= range->low) {
            if (packet_out->po_pkt.pkt_num >= ctl->ctl_largest_acked[pns]) {
                ctl->ctl_largest_acked[pns] = packet_out->po_pkt.pkt_num;
                ctl->ctl_largest_acked_sent_time[pns] = packet_out->po_sent_time;
            }

            if (packet_out->po_largest_ack > ctl->ctl_largest_ack_both[pns]) {
                ctl->ctl_largest_ack_both[pns] = packet_out->po_largest_ack;
                need_del_record = 1;
            }

            xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG,
                "|conn:%p|pkt_num:%ui|origin_pktnum:%ui|size:%ud|pkt_type:%s|frame:%s|conn_state:%s|",
                ctl->ctl_conn, packet_out->po_pkt.pkt_num,
                (xqc_packet_number_t)packet_out->po_origin ? packet_out->po_origin->po_pkt.pkt_num : 0,
                packet_out->po_used_size,
                xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                xqc_frame_type_2_str(packet_out->po_frame_types),
                xqc_conn_state_2_str(ctl->ctl_conn->conn_state));

            xqc_update_sample(&ctl->sampler, packet_out, ctl, ack_recv_time);

            /* Packet previously declared lost gets acked */
            if (!packet_out->po_acked && (packet_out->po_flag & XQC_POF_RETRANSED)) {
                ++ctl->ctl_spurious_loss_count;
                if (!spurious_loss_detected) {
                    spurious_loss_detected = 1;
                    spurious_loss_pktnum = packet_out->po_pkt.pkt_num;
                    spurious_loss_sent_time = packet_out->po_sent_time;
                }
            }
            xqc_send_ctl_on_packet_acked(ctl, packet_out, ack_recv_time, 1);

            xqc_send_ctl_maybe_remove_unacked(packet_out, ctl);

            xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|ctl_packets_used:%ud|ctl_packets_free:%ud|",
                    ctl->ctl_packets_used, ctl->ctl_packets_free);

            if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
                has_ack_eliciting = 1;
            }

            if (packet_out->po_pkt.pkt_num == largest_ack
                && packet_out->po_pkt.pkt_num == ctl->ctl_largest_acked[pns])
            {
                update_rtt = 1;
                ctl->ctl_latest_rtt = ack_recv_time - ctl->ctl_largest_acked_sent_time[pns];
            }
        }
    }

    update_rtt &= has_ack_eliciting;

    if (update_rtt) {
        xqc_send_ctl_update_rtt(ctl, &ctl->ctl_latest_rtt, ack_info->ack_delay);
    }

    /* TODO: ECN */

    /* spurious loss */
    if (spurious_loss_detected) {
        xqc_send_ctl_on_spurious_loss_detected(ctl, ack_recv_time, largest_ack,
                                               spurious_loss_pktnum, spurious_loss_sent_time);
    }

    /* DetectAndRemoveLostPackets + OnPacketsLost */
    xqc_send_ctl_detect_lost(ctl, pns, ack_recv_time);

    if (need_del_record) {
        xqc_recv_record_del(&ctl->ctl_conn->recv_record[pns], ctl->ctl_largest_ack_both[pns] + 1);
        xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|xqc_recv_record_del from %ui|pns:%d|",
                ctl->ctl_largest_ack_both[pns] + 1, pns);
    }

    xqc_recv_record_log(ctl->ctl_conn, &ctl->ctl_conn->recv_record[pns]);

    /*
     * reset pto_count unless the client is unsure if the server has
     * validated the client's address
     */
    if (xqc_conn_peer_complete_address_validation(ctl->ctl_conn)) {
        ctl->ctl_pto_count = 0;
    }

    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_set_loss_detection_timer|acked|pto_count:%ud|", ctl->ctl_pto_count);
    xqc_send_ctl_set_loss_detection_timer(ctl);

    /* CCC */
    if (ctl->ctl_cong_callback->xqc_cong_ctl_bbr /* && stream_frame_acked */) {

        uint64_t bw_before = 0, bw_after = 0;
        int bw_record_flag = 0;
        xqc_usec_t now = ack_recv_time;

        /* Make sure that we do not call BBR with a invalid sampler. */
        if (xqc_generate_sample(&ctl->sampler, ctl, ack_recv_time)) {
            if ((ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate != NULL)
                && (ctl->ctl_info.last_bw_time + ctl->ctl_info.record_interval <= now))
            {
                bw_before = ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(ctl->ctl_cong);
                if (bw_before != 0) {
                    bw_record_flag = 1;
                }
            }

            ctl->ctl_cong_callback->xqc_cong_ctl_bbr(ctl->ctl_cong, &ctl->sampler);
        }
        uint8_t mode, full_bw_reached;
        uint8_t recovery_mode, round_start;
        uint8_t packet_conservation, idle_restart;
        float pacing_gain, cwnd_gain;
        uint64_t min_rtt, recovery_start_time;
        mode = ctl->ctl_cong_callback->
               xqc_cong_ctl_info_cb->mode(ctl->ctl_cong);
        full_bw_reached = ctl->ctl_cong_callback->
                          xqc_cong_ctl_info_cb->full_bw_reached(ctl->ctl_cong);
        recovery_mode = ctl->ctl_cong_callback->
                        xqc_cong_ctl_info_cb->recovery_mode(ctl->ctl_cong);
        round_start = ctl->ctl_cong_callback->
                      xqc_cong_ctl_info_cb->round_start(ctl->ctl_cong);
        packet_conservation = ctl->ctl_cong_callback->
                              xqc_cong_ctl_info_cb->
                              packet_conservation(ctl->ctl_cong);
        idle_restart = ctl->ctl_cong_callback->
                       xqc_cong_ctl_info_cb->idle_restart(ctl->ctl_cong);
        pacing_gain = ctl->ctl_cong_callback->
                      xqc_cong_ctl_info_cb->pacing_gain(ctl->ctl_cong);
        cwnd_gain = ctl->ctl_cong_callback->
                    xqc_cong_ctl_info_cb->cwnd_gain(ctl->ctl_cong);
        min_rtt = ctl->ctl_cong_callback->
                  xqc_cong_ctl_info_cb->min_rtt(ctl->ctl_cong);
        recovery_start_time = ctl->ctl_cong_callback->
                              xqc_cong_ctl_info_cb->
                              recovery_start_time(ctl->ctl_cong);
        xqc_conn_log(ctl->ctl_conn, XQC_LOG_DEBUG,
                "|bbr on ack|mode:%ud|pacing_rate:%ud|bw:%ud|"
                "cwnd:%ui|full_bw_reached:%ud|inflight:%ud|"
                "srtt:%ui|latest_rtt:%ui|min_rtt:%ui|applimit:%ud|"
                "lost:%ud|recovery:%ud|recovery_start:%ui|"
                "idle_restart:%ud|packet_conservation:%ud|round_start:%ud|",
                (unsigned int) mode, ctl->ctl_cong_callback->
                xqc_cong_ctl_get_pacing_rate(ctl->ctl_cong),
                ctl->ctl_cong_callback->
                xqc_cong_ctl_get_bandwidth_estimate(ctl->ctl_cong),
                ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong),
                (unsigned int)full_bw_reached, ctl->ctl_bytes_in_flight,
                ctl->ctl_srtt, ctl->ctl_latest_rtt, min_rtt,
                ctl->sampler.is_app_limited, ctl->ctl_lost_count,
                (unsigned int)recovery_mode, recovery_start_time, (unsigned int)idle_restart,
                (unsigned int)packet_conservation, (unsigned int)round_start);
        /*xqc_log(ctl->ctl_conn->log, XQC_LOG_INFO,
                "|sock: 10086, est.bw: %ud, pacing_rate: %ud, cwnd: %ud, srtt: %ui, rack.rtt: %ui, min_rtt: %ui,"
                "pacing_gain: %.2f, cwnd_gain: %.2f",
                ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(ctl->ctl_cong),
                ctl->ctl_cong_callback->xqc_cong_ctl_get_pacing_rate(ctl->ctl_cong),
                ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong),
                ctl->ctl_srtt, ctl->ctl_latest_rtt, min_rtt,
                pacing_gain, cwnd_gain);*/

        if (bw_record_flag) {
            bw_after = ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(ctl->ctl_cong);
            if (bw_after > 0) {
                if (xqc_sub_abs(bw_after, bw_before) * 100 > (bw_before * ctl->ctl_info.bw_change_threshold)) {

                    ctl->ctl_info.last_bw_time = now;
                    xqc_conn_log(ctl->ctl_conn, XQC_LOG_STATS,
                                 "|bandwidth change record|bw_before:%ui|bw_after:%ui|srtt:%ui|cwnd:%ui|",
                                 bw_before, bw_after, ctl->ctl_srtt, ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong));
                }
            }
        }

        ctl->sampler.prior_time = 0;
    }

    xqc_send_ctl_info_circle_record(ctl->ctl_conn);
    xqc_log_event(ctl->ctl_conn->log, REC_METRICS_UPDATED, ctl);
    return XQC_OK;
}

/**
 * OnDatagramReceived
 */
void
xqc_send_ctl_on_dgram_received(xqc_send_ctl_t *ctl, size_t dgram_size, xqc_usec_t recv_time)
{
    xqc_connection_t *c = ctl->ctl_conn;
    xqc_bool_t aal = xqc_send_ctl_check_anti_amplification(c, 0);

    /* refresh recv state */
    c->conn_send_ctl->ctl_recv_count++;
    c->conn_send_ctl->ctl_bytes_recv += dgram_size;

    /*
     * If this datagram unblocks the server's anti-amplification limit, 
     * arm the PTO timer to avoid deadlock. 
     */
    if (aal && !xqc_send_ctl_check_anti_amplification(c, 0)) {
        xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|anti-amplification state unlock|");
        xqc_send_ctl_set_loss_detection_timer(ctl);
    }
}

/**
 * UpdateRtt
 */
void
xqc_send_ctl_update_rtt(xqc_send_ctl_t *ctl, xqc_usec_t *latest_rtt, xqc_usec_t ack_delay)
{
    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG,
            "|before update rtt|conn:%p|srtt:%ui|rttvar:%ui|minrtt:%ui|latest_rtt:%ui|ack_delay:%ui|",
            ctl->ctl_conn, ctl->ctl_srtt, ctl->ctl_rttvar, ctl->ctl_minrtt, *latest_rtt, ack_delay);

    /* Based on {{RFC6298}}. */
    if (ctl->ctl_first_rtt_sample_time == 0) {
        ctl->ctl_minrtt = *latest_rtt;
        ctl->ctl_srtt = *latest_rtt;
        ctl->ctl_rttvar = *latest_rtt >> 1;
        ctl->ctl_first_rtt_sample_time = xqc_monotonic_timestamp();

    } else {
        ctl->ctl_minrtt = xqc_min(*latest_rtt, ctl->ctl_minrtt);

        if (xqc_conn_is_handshake_confirmed(ctl->ctl_conn)) {
            ack_delay = xqc_min(ack_delay, ctl->ctl_conn->local_settings.max_ack_delay * 1000);
        }

        /* Adjust for ack delay if it's plausible. */
        xqc_usec_t adjusted_rtt = *latest_rtt;
        if (*latest_rtt >= (ctl->ctl_minrtt + ack_delay)) {
            adjusted_rtt -= ack_delay;
        }

        uint64_t srtt = ctl->ctl_srtt;
        uint64_t rttvar = ctl->ctl_rttvar;

        /* rttvar = 3/4 * rttvar + 1/4 * abs(smoothed_rtt - adjusted_rtt)  */
        ctl->ctl_rttvar -= ctl->ctl_rttvar >> 2;
        ctl->ctl_rttvar += (ctl->ctl_srtt > adjusted_rtt
                            ? ctl->ctl_srtt - adjusted_rtt : adjusted_rtt - ctl->ctl_srtt) >> 2;

        /* smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt */
        ctl->ctl_srtt -= ctl->ctl_srtt >> 3;
        ctl->ctl_srtt += adjusted_rtt >> 3;

        if (xqc_sub_abs(ctl->ctl_srtt, srtt)  > ctl->ctl_info.rtt_change_threshold) {
            xqc_usec_t now = xqc_monotonic_timestamp();
            if (ctl->ctl_info.last_rtt_time + ctl->ctl_info.record_interval <= now) {
                ctl->ctl_info.last_rtt_time = now;
                xqc_conn_log(ctl->ctl_conn, XQC_LOG_STATS, "|before update rtt|srtt:%ui|rttvar:%ui|"
                            "after update rtt|srtt:%ui|rttvar:%ui|minrtt:%ui|latest_rtt:%ui|ack_delay:%ui|",
                             srtt, rttvar, ctl->ctl_srtt, ctl->ctl_rttvar, ctl->ctl_minrtt, *latest_rtt, ack_delay);
            }
        }
    }

    xqc_conn_log(ctl->ctl_conn, XQC_LOG_DEBUG,
                 "|after update rtt|conn:%p|srtt:%ui|rttvar:%ui|minrtt:%ui|latest_rtt:%ui|ack_delay:%ui|",
                 ctl->ctl_conn, ctl->ctl_srtt, ctl->ctl_rttvar, ctl->ctl_minrtt, *latest_rtt, ack_delay);
}

void
xqc_send_ctl_on_spurious_loss_detected(xqc_send_ctl_t *ctl, xqc_usec_t ack_recv_time,
    xqc_packet_number_t largest_ack,
    xqc_packet_number_t spurious_loss_pktnum,
    xqc_usec_t spurious_loss_sent_time)
{
    if (!ctl->ctl_conn->conn_settings.spurious_loss_detect_on) {
        return;
    }

    /* Adjust Packet Threshold */
    if (largest_ack < spurious_loss_pktnum) {
        return;
    }
    ctl->ctl_reordering_packet_threshold = xqc_max(
            ctl->ctl_reordering_packet_threshold, largest_ack - spurious_loss_pktnum + 1);


    /* Adjust Time Threshold */
    if (ack_recv_time < spurious_loss_sent_time) {
        return;
    }
    xqc_usec_t reorder_time_interval = ack_recv_time - spurious_loss_sent_time;
    xqc_usec_t max_rtt = xqc_max(ctl->ctl_latest_rtt, ctl->ctl_srtt);
    while (max_rtt + (max_rtt >> ctl->ctl_reordering_time_threshold_shift) < reorder_time_interval
           && ctl->ctl_reordering_time_threshold_shift > 0)
    {
        --ctl->ctl_reordering_time_threshold_shift;
    }

    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|ctl_reordering_packet_threshold:%ui|ctl_reordering_time_threshold_shift:%d|",
            ctl->ctl_reordering_packet_threshold, ctl->ctl_reordering_time_threshold_shift);
}

/**
 * DetectAndRemoveLostPackets + OnPacketsLost
 */
void
xqc_send_ctl_detect_lost(xqc_send_ctl_t *ctl, xqc_pkt_num_space_t pns, xqc_usec_t now)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *po, *largest_lost = NULL;
    uint64_t lost_n = 0;

    ctl->ctl_loss_time[pns] = 0;
    ctl->sampler.loss = 0;

    if (ctl->ctl_largest_acked[pns] == XQC_MAX_UINT64_VALUE) {
        xqc_log(ctl->ctl_conn->log, XQC_LOG_WARN, "|exception|largest acked is not recorded|");
        return;
    }

    /* loss_delay = 9/8 * max(latest_rtt, smoothed_rtt) */
    xqc_usec_t loss_delay = xqc_max(ctl->ctl_latest_rtt, ctl->ctl_srtt);
    loss_delay += loss_delay >> ctl->ctl_reordering_time_threshold_shift;

    /* Minimum time of kGranularity before packets are deemed lost. */
    loss_delay = xqc_max(loss_delay, XQC_kGranularity);

    /* Packets sent before this time are deemed lost. */
    xqc_usec_t lost_send_time = now - loss_delay;

    /* Packets with packet numbers before this are deemed lost. */
    xqc_packet_number_t lost_pn = ctl->ctl_largest_acked[pns];
    if (ctl->ctl_largest_acked[pns] > ctl->ctl_reordering_packet_threshold) {
        lost_pn -= ctl->ctl_reordering_packet_threshold;
    }

    xqc_list_for_each_safe(pos, next, &ctl->ctl_unacked_packets[pns]) {
        po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (po->po_pkt.pkt_num > ctl->ctl_largest_acked[pns]) {
            continue;
        }

        if (xqc_send_ctl_indirectly_ack_po(ctl, po)) {
            continue;
        }

        /* Mark packet as lost, or set time when it should be marked. */
        if (po->po_sent_time <= lost_send_time || po->po_pkt.pkt_num <= lost_pn) {
            xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|mark lost|pns:%d|pkt_num:%ui|"
                    "lost_pn:%ui|po_sent_time:%ui|lost_send_time:%ui|loss_delay:%ui|frame:%s|repair:%d|",
                    pns, po->po_pkt.pkt_num, lost_pn, po->po_sent_time, lost_send_time, loss_delay, 
                    xqc_frame_type_2_str(po->po_frame_types), XQC_NEED_REPAIR(po->po_frame_types));
            xqc_log_event(ctl->ctl_conn->log, REC_PACKET_LOST, po);

            if (po->po_flag & XQC_POF_IN_FLIGHT) {
                xqc_send_ctl_decrease_inflight(ctl, po);

                /* if a packet don't need to be repair, don't retransmit it */
                if (!XQC_NEED_REPAIR(po->po_frame_types)) {
                    xqc_send_ctl_remove_unacked(po, ctl);
                    xqc_send_ctl_insert_free(&(po->po_list), &ctl->ctl_free_packets, ctl);

                } else {
                    xqc_send_ctl_copy_to_lost(po, ctl);
                }

                lost_n++;

            } else {
                xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|it's a copy of origin pkt|acked:%d|origin_acked:%d|origin_ref_cnt:%d|",
                        po->po_acked, po->po_origin ? po->po_origin->po_acked : -1,
                        po->po_origin ? po->po_origin->po_origin_ref_cnt : -1);
            }

            /* remember largest_loss for OnPacketsLost */
            if (largest_lost == NULL
                || (po->po_pkt.pkt_num > largest_lost->po_pkt.pkt_num))
            {
                largest_lost = po;
            }

        } else {
            if (ctl->ctl_loss_time[pns] == 0) {
                ctl->ctl_loss_time[pns] = po->po_sent_time + loss_delay;

            } else {
                ctl->ctl_loss_time[pns] = xqc_min(ctl->ctl_loss_time[pns], po->po_sent_time + loss_delay);
            }
        }
    }

    /* update statistic */
    ctl->ctl_lost_pkts_number += lost_n;
    ctl->sampler.loss = lost_n;

    /**
     * OnPacketsLost
     */
    if (largest_lost) {
        /*
         * Start a new congestion epoch if the last lost packet
         * is past the end of the previous recovery epoch.
         * enter loss recovery here
         */
        xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|OnLostDetection|largest_lost sent time: %lu|", largest_lost->po_sent_time);
        xqc_send_ctl_congestion_event(ctl, largest_lost->po_sent_time);

        if (ctl->ctl_first_rtt_sample_time == 0) {
            return;
        }

        /* Collapse congestion window if persistent congestion */
        if (ctl->ctl_cong_callback->xqc_cong_ctl_reset_cwnd
            && xqc_send_ctl_in_persistent_congestion(ctl, largest_lost, now))
        {
            /* For loss-based CCs, it means we are gonna slow start again. */
            ctl->ctl_max_bytes_in_flight = 0;
            /* we reset BBR's cwnd here */
            xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|OnLostDetection|%s|", "Persistent congestion occurs");
            ctl->ctl_cong_callback->xqc_cong_ctl_reset_cwnd(ctl->ctl_cong);
        }

        if (ctl->ctl_info.last_lost_time + ctl->ctl_info.record_interval <= now) {
            xqc_usec_t lost_interval = now - ctl->ctl_info.last_lost_time;
            ctl->ctl_info.last_lost_time = now;
            uint64_t lost_count = ctl->ctl_lost_count + lost_n - ctl->ctl_info.last_lost_count;
            uint64_t send_count = ctl->ctl_send_count - ctl->ctl_info.last_send_count;
            ctl->ctl_info.last_lost_count = ctl->ctl_lost_count + lost_n;
            ctl->ctl_info.last_send_count = ctl->ctl_send_count;
            uint64_t bw = 0;
            if (ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate) {
                bw = ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(ctl->ctl_cong);
            }
            xqc_conn_log(ctl->ctl_conn, XQC_LOG_STATS, "|lost interval:%ui|lost_count:%ui|send_count:%ui|pkt_num:%ui"
                        "|po_send_time:%ui|srtt:%ui|cwnd:%ud|bw:%ui|conn_life:%ui|now:%ui|last_lost_time:%ui|",
                        lost_interval, lost_count, send_count, largest_lost->po_pkt.pkt_num, largest_lost->po_sent_time, ctl->ctl_srtt,
                        ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong), bw, now - ctl->ctl_conn->conn_create_time);
        }
    }
}

/**
 * InPersistentCongestion
 */
xqc_bool_t
xqc_send_ctl_in_persistent_congestion(xqc_send_ctl_t *ctl, xqc_packet_out_t *largest_lost, xqc_usec_t now)
{
    if (ctl->ctl_pto_count >= XQC_CONSECUTIVE_PTO_THRESH) {
        xqc_usec_t duration = (ctl->ctl_srtt + xqc_max(ctl->ctl_rttvar << 2, XQC_kGranularity)
            + ctl->ctl_conn->remote_settings.max_ack_delay * 1000) * XQC_kPersistentCongestionThreshold;
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
xqc_send_ctl_congestion_event(xqc_send_ctl_t *ctl, xqc_usec_t sent_time)
{
    if (ctl->ctl_cong_callback->xqc_cong_ctl_on_lost) {
        ctl->ctl_cong_callback->xqc_cong_ctl_on_lost(ctl->ctl_cong, sent_time);
    }
}


/**
 * IsAppLimited
 */
int
xqc_send_ctl_is_app_limited(xqc_send_ctl_t *ctl)
{
    return 0;
}

/* This function is called inside cc's on_ack callbacks if needed */
int
xqc_send_ctl_is_cwnd_limited(xqc_send_ctl_t *ctl)
{
    if (ctl->ctl_cong_callback->xqc_cong_ctl_in_slow_start(ctl->ctl_cong)) {
        uint32_t double_cwnd = ctl->ctl_max_bytes_in_flight << 1;
        uint32_t cwnd = ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong);
        xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG,
                "|cwnd: %ud, 2*max_inflight: %ud|", cwnd, double_cwnd);
        return cwnd < double_cwnd;
    }
    return (ctl->ctl_is_cwnd_limited);
}

void
xqc_send_ctl_cc_on_ack(xqc_send_ctl_t *ctl, xqc_packet_out_t *acked_packet, 
                       xqc_usec_t now)
{
    if (ctl->ctl_cong_callback->xqc_cong_ctl_on_ack) {
        ctl->ctl_cong_callback->xqc_cong_ctl_on_ack(ctl->ctl_cong, acked_packet, now);
    }
    /* For CUBIC debug */
#if 0
    // xqc_cubic_t *c = (xqc_cubic_t*)(ctl->ctl_cong);
    // xqc_log(ctl->ctl_conn->log, XQC_LOG_WARN, "|cubic|time: %ui, sent_time: %ui, rtt: %ui|acked: %ud|"
    //         "cwnd: %ud, ssthresh: %ud, recovery: 0, cwnd_limited: 0, in_lss: 0|",
    //         now, acked_packet->po_sent_time, now - acked_packet->po_sent_time,
    //         acked_packet->po_used_size,
    //         c->cwnd/1200, c->ssthresh/1200);
#endif
}

/**
 * OnPacketAcked
 */
void
xqc_send_ctl_on_packet_acked(xqc_send_ctl_t *ctl, 
    xqc_packet_out_t *acked_packet, xqc_usec_t now, int do_cc)
{
    xqc_stream_t *stream;
    xqc_packet_out_t *packet_out = acked_packet;
    xqc_connection_t *conn = ctl->ctl_conn;

    if ((conn->conn_type == XQC_CONN_TYPE_SERVER) && (acked_packet->po_frame_types & XQC_FRAME_BIT_HANDSHAKE_DONE)) {
        conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_DONE_ACKED;
    }

    xqc_send_ctl_decrease_unacked_stream_ref(ctl, packet_out);

    /* If a packet marked as STREAM_CLOSED, when it is acked, it comes here */
    if (packet_out->po_flag & XQC_POF_IN_FLIGHT) {
        xqc_send_ctl_decrease_inflight(ctl, packet_out);

        if (packet_out->po_frame_types & XQC_FRAME_BIT_RESET_STREAM) {
            xqc_send_ctl_on_reset_stream_acked(ctl, packet_out);
        }

        if (packet_out->po_frame_types & XQC_FRAME_BIT_CRYPTO && packet_out->po_pkt.pkt_pns == XQC_PNS_HSK) {
            conn->conn_flag |= XQC_CONN_FLAG_HSK_ACKED;
        }

        if (packet_out->po_frame_types & XQC_FRAME_BIT_PING) {
            if (conn->app_proto_cbs.conn_cbs.conn_ping_acked
                && (packet_out->po_flag & XQC_POF_NOTIFY))
            {
                conn->app_proto_cbs.conn_cbs.conn_ping_acked(conn, &conn->scid_set.user_scid,
                                                        packet_out->po_user_data, conn->app_proto_user_data);
            }
        }

        /* TODO: fix NEW_CID_RECEIVED */
        if (packet_out->po_frame_types & XQC_FRAME_BIT_NEW_CONNECTION_ID) {
            packet_out->po_frame_types &= ~XQC_FRAME_BIT_NEW_CONNECTION_ID;
            conn->conn_flag |= XQC_CONN_FLAG_NEW_CID_RECEIVED;
        }

        if (do_cc) {
            xqc_send_ctl_cc_on_ack(ctl, packet_out, now);
        }
    }

    packet_out->po_acked = 1;
    if (packet_out->po_origin) {
        packet_out->po_origin->po_acked = 1;
    }
}



/* if handshake is not completed, endpoint will try to send something more aggressively */
static const xqc_usec_t xqc_pto_timeout_threshold_hsk = 2000000;

static const xqc_usec_t xqc_pto_timeout_threshold = 5 * 1000000;

xqc_usec_t
xqc_send_ctl_get_pto_time_and_space(xqc_send_ctl_t *ctl, xqc_usec_t now, xqc_pkt_num_space_t *pns_ret)
{
    xqc_usec_t t;
    xqc_usec_t pto_timeout = XQC_MAX_UINT64_VALUE;
    xqc_connection_t *c = ctl->ctl_conn;
    xqc_int_t pto_cnt = ctl->ctl_pto_count;

    /* get pto duration */
    xqc_usec_t duration = (ctl->ctl_srtt
        + xqc_max(4 * ctl->ctl_rttvar, XQC_kGranularity * 1000)) * xqc_send_ctl_pow(pto_cnt);

    /* Arm PTO from now when there are no inflight packets */
    if (ctl->ctl_bytes_in_flight == 0) {
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
            xqc_log(c->log, XQC_LOG_DEBUG, "|conn:%p|PNS: %ud, unacked: %ud|", 
                    c, pns, ctl->ctl_bytes_ack_eliciting_inflight[pns]);

            /* skip if no bytes inflight in pns */
            if (ctl->ctl_bytes_ack_eliciting_inflight[pns] > 0) {
                /* Skip Application Data until handshake confirmed. */
                if (pns == XQC_PNS_APP_DATA) {
                    if (!xqc_conn_is_handshake_confirmed(ctl->ctl_conn)) {
                        xqc_log(c->log, XQC_LOG_DEBUG, "|handshake not confirmed|");
                        break;
                    }

                    duration += c->remote_settings.max_ack_delay * 1000 * xqc_send_ctl_pow(ctl->ctl_pto_count);
                }

                t = ctl->ctl_time_of_last_sent_ack_eliciting_packet[pns] + duration;
                if (t < pto_timeout) {
                    pto_timeout = t;
                    *pns_ret = pns;
                }
            }
        }
    }

    /* set a threshold for pto timer in case of very large pto interval */
    if (!xqc_conn_check_handshake_completed(c)) {
        if (pto_timeout - now > xqc_pto_timeout_threshold_hsk) {
            pto_timeout = now + xqc_pto_timeout_threshold_hsk;
        }

    } else {
        if (pto_timeout - now > xqc_pto_timeout_threshold) {
            pto_timeout = now + xqc_pto_timeout_threshold;
        }
    }

    return pto_timeout;
}


/**
 * SetLossDetectionTimer
 */
void
xqc_send_ctl_set_loss_detection_timer(xqc_send_ctl_t *ctl)
{
    xqc_pkt_num_space_t pns;
    xqc_usec_t loss_time;

    xqc_connection_t *conn = ctl->ctl_conn;
    xqc_usec_t now = xqc_monotonic_timestamp();

    loss_time = xqc_send_ctl_get_earliest_loss_time(ctl, &pns);
    if (loss_time != 0) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_timer_set|earliest losss time|XQC_TIMER_LOSS_DETECTION|"
                "conn:%p|expire:%ui|now:%ui|interval:%ui|", conn, loss_time, now, loss_time - now);

        /* Time threshold loss detection. */
        xqc_send_ctl_timer_set(ctl, XQC_TIMER_LOSS_DETECTION, now, loss_time - now);
        return;
    }

    /* if at anti-amplification limit, nothing would be sent, unset the loss detection timer */
    if (xqc_send_ctl_check_anti_amplification(conn, 0)) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|amplification limit|stop timer|conn:%p|", conn);
        xqc_send_ctl_timer_unset(ctl, XQC_TIMER_LOSS_DETECTION);
        return;
    }

    /* Don't arm timer if there are no ack-eliciting packets in flight. */
    if (0 == ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_INIT]
        && 0 == ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_HSK]
        && 0 == ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_APP_DATA]
        && xqc_conn_peer_complete_address_validation(conn))
    {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|unset|no ack-eliciting pkts in flight|conn:%p|", conn);
        xqc_send_ctl_timer_unset(ctl, XQC_TIMER_LOSS_DETECTION);
        return;
    }

    /* get PTO timeout and update loss detection timer */
    xqc_usec_t timeout = xqc_send_ctl_get_pto_time_and_space(ctl, now, &pns);
    xqc_send_ctl_timer_set(ctl, XQC_TIMER_LOSS_DETECTION, now, timeout - now);

    xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_timer_set|update|PTO|XQC_TIMER_LOSS_DETECTION"
            "|conn:%p|expire:%ui|now:%ui|interval:%ui|pto_count:%ud|srtt:%ui",
            conn, timeout, now, timeout - now, ctl->ctl_pto_count, ctl->ctl_srtt);

}


/**
 * GetLossTimeAndSpace
 */
xqc_usec_t
xqc_send_ctl_get_earliest_loss_time(xqc_send_ctl_t *ctl, xqc_pkt_num_space_t *pns_ret)
{
    xqc_usec_t time = ctl->ctl_loss_time[XQC_PNS_INIT];
    *pns_ret = XQC_PNS_INIT;
    for (xqc_pkt_num_space_t pns = XQC_PNS_HSK; pns <= XQC_PNS_APP_DATA; ++pns) {
        if (ctl->ctl_loss_time[pns] != 0
            && (time == 0 || ctl->ctl_loss_time[pns] < time))
        {
            time = ctl->ctl_loss_time[pns];
            *pns_ret = pns;
        }
    }
    return time;
}


xqc_usec_t
xqc_send_ctl_get_srtt(xqc_send_ctl_t *ctl)
{
    return ctl->ctl_srtt;
}

float
xqc_send_ctl_get_retrans_rate(xqc_send_ctl_t *ctl)
{
    if (ctl->ctl_send_count <= 0) {
        return 0.0f;

    } else {
        return (float)(ctl->ctl_lost_count + ctl->ctl_tlp_count) / ctl->ctl_send_count;
    }
}


xqc_bool_t
xqc_send_ctl_check_anti_amplification(xqc_connection_t *conn, size_t byte_cnt)
{
    xqc_bool_t limit = XQC_FALSE;
    /* anti-amplifier attack limit */
    if (conn->conn_type == XQC_CONN_TYPE_SERVER
        && conn->conn_send_ctl->ctl_bytes_send > 0
        && !(conn->conn_flag & XQC_CONN_FLAG_ADDR_VALIDATED))
    {
        limit = (conn->conn_send_ctl->ctl_bytes_send + byte_cnt
                >= conn->conn_settings.anti_amplification_limit * conn->conn_send_ctl->ctl_bytes_recv);
    }

    return limit;
}


void
xqc_send_ctl_rearm_ld_timer(xqc_send_ctl_t *ctl)
{
    /* make sure the loss detection timer is armed */
    if (!xqc_send_ctl_timer_is_set(ctl, XQC_TIMER_LOSS_DETECTION)) {
        xqc_send_ctl_set_loss_detection_timer(ctl);
    }
}


xqc_bool_t
xqc_send_ctl_ack_received_in_pns(xqc_send_ctl_t *ctl, xqc_pkt_num_space_t pns)
{
    return ctl->ctl_largest_acked_sent_time[pns] > 0;
}

/*
 * *****************TIMER*****************
 */
static const char * const timer_type_2_str[XQC_TIMER_N] = {
    [XQC_TIMER_ACK_INIT]        = "ACK_INIT",
    [XQC_TIMER_ACK_HSK]         = "ACK_HSK",
    [XQC_TIMER_ACK_01RTT]       = "ACK_01RTT",
    [XQC_TIMER_LOSS_DETECTION]  = "LOSS_DETECTION",
    [XQC_TIMER_IDLE]            = "IDLE",
    [XQC_TIMER_DRAINING]        = "DRAINING",
    [XQC_TIMER_PACING]          = "PACING",
    [XQC_TIMER_STREAM_CLOSE]    = "STREAM_CLOSE",
    [XQC_TIMER_PING]            = "PING",
    [XQC_TIMER_RETIRE_CID]      = "RETIRE_CID",
    [XQC_TIMER_LINGER_CLOSE]    = "LINGER_CLOSE",
    [XQC_TIMER_KEY_UPDATE]      = "KEY_UPDATE",
};

const char *
xqc_timer_type_2_str(xqc_send_ctl_timer_type timer_type)
{
    return timer_type_2_str[timer_type];
}

/* timer callbacks */
void
xqc_send_ctl_ack_timeout(xqc_send_ctl_timer_type type, xqc_usec_t now, void *ctx)
{
    xqc_connection_t *conn = ((xqc_send_ctl_t*)ctx)->ctl_conn;
    xqc_pkt_num_space_t pns = type - XQC_TIMER_ACK_INIT;
    conn->conn_flag |= XQC_CONN_FLAG_SHOULD_ACK_INIT << pns;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|pns:%d|", pns);
}

/**
 * OnLossDetectionTimeout
 */
void
xqc_send_ctl_loss_detection_timeout(xqc_send_ctl_timer_type type, xqc_usec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t*)ctx;
    xqc_connection_t *conn = ctl->ctl_conn;
    xqc_log(conn->log, XQC_LOG_DEBUG, "|loss_detection_timeout|");
    xqc_usec_t loss_time;
    xqc_pkt_num_space_t pns;
    loss_time = xqc_send_ctl_get_earliest_loss_time(ctl, &pns);
    if (loss_time != 0) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_detect_lost|");
        /* Time threshold loss Detection */
        xqc_send_ctl_detect_lost(ctl, pns, now);
        xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_set_loss_detection_timer|loss|");
        xqc_send_ctl_set_loss_detection_timer(ctl);
        return;
    }

    if (ctl->ctl_bytes_in_flight > 0) {
        /*
         * PTO. Send new data if available, else retransmit old data.
         * If neither is available, send a single PING frame
         */
        xqc_log(conn->log, XQC_LOG_DEBUG, "|send Probe pkts|conn:%p|bytes_in_flight:%ud|", 
                conn, ctl->ctl_bytes_in_flight);
        xqc_usec_t t = xqc_send_ctl_get_pto_time_and_space(ctl, now, &pns);
        xqc_conn_send_one_or_two_ack_elicit_pkts(conn, pns);

    } else {
        /* assert(!PeerCompletedAddressValidation()) */
        if (xqc_conn_peer_complete_address_validation(conn)) {
            xqc_log(conn->log, XQC_LOG_WARN, "|exception|peer validated address while inflight bytes is 0|");
            return;
        }

        /* Client sends an anti-deadlock packet */
        if (xqc_conn_has_hsk_keys(conn)) {
            /* send Handshake packet proves address ownership. */
            xqc_conn_send_one_ack_eliciting_pkt(conn, XQC_PNS_HSK);

        } else {
            /* send Initial to earn more anti-amplification credit */
            xqc_conn_send_one_ack_eliciting_pkt(conn, XQC_PNS_INIT);
        }
    }

    ctl->ctl_pto_count++;
    xqc_log(ctl->ctl_conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_set_loss_detection_timer|PTO|conn:%p|pto_count:%ud", 
            conn, ctl->ctl_pto_count);
    xqc_send_ctl_set_loss_detection_timer(ctl);
}

void
xqc_send_ctl_idle_timeout(xqc_send_ctl_timer_type type, xqc_usec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t*)ctx;
    xqc_connection_t *conn = ctl->ctl_conn;

    conn->conn_flag |= XQC_CONN_FLAG_TIME_OUT;
}

void
xqc_send_ctl_draining_timeout(xqc_send_ctl_timer_type type, xqc_usec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t*)ctx;
    xqc_connection_t *conn = ctl->ctl_conn;

    conn->conn_flag |= XQC_CONN_FLAG_TIME_OUT;
}

void
xqc_send_ctl_pacing_timeout(xqc_send_ctl_timer_type type, xqc_usec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t*)ctx;
    xqc_pacing_t *pacing = &ctl->ctl_pacing;
    xqc_pacing_on_timeout(pacing);
}

void
xqc_send_ctl_stream_close_timeout(xqc_send_ctl_timer_type type, xqc_usec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t*)ctx;
    xqc_connection_t *conn = ctl->ctl_conn;

    xqc_list_head_t *pos, *next;
    xqc_stream_t *stream;
    xqc_usec_t min_expire = XQC_MAX_UINT64_VALUE, later = 0;
    xqc_list_for_each_safe(pos, next, &conn->conn_closing_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, closing_stream_list);
        if (stream->stream_close_time <= now) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|stream_id:%ui|stream_type:%d|stream close|", 
                    stream->stream_id, stream->stream_type);
            xqc_list_del_init(pos);
            xqc_destroy_stream(stream);

        } else {
            min_expire = xqc_min(min_expire, stream->stream_close_time);
        }
    }

    if (min_expire != XQC_MAX_UINT64_VALUE) {
        xqc_send_ctl_timer_set(ctl, XQC_TIMER_STREAM_CLOSE, now, min_expire - now);
    }
}

void
xqc_send_ctl_ping_timeout(xqc_send_ctl_timer_type type, xqc_usec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t *) ctx;
    xqc_connection_t *conn = ctl->ctl_conn;

    conn->conn_flag |= XQC_CONN_FLAG_PING;

    if (conn->conn_settings.ping_on && conn->conn_type == XQC_CONN_TYPE_CLIENT) {
        xqc_send_ctl_timer_set(ctl, XQC_TIMER_PING, now, XQC_PING_TIMEOUT * 1000);
    }
}

/* TODO: independent timer in cid.c */
void
xqc_send_ctl_retire_cid_timeout(xqc_send_ctl_timer_type type, xqc_usec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t *) ctx;
    xqc_connection_t *conn = ctl->ctl_conn;

    xqc_cid_inner_t *inner_cid;
    xqc_list_head_t *pos, *next;

    xqc_int_t ret;
    xqc_usec_t next_time = XQC_MAX_UINT64_VALUE;

    xqc_list_for_each_safe(pos, next, &conn->scid_set.cid_set.list_head) {
        inner_cid = xqc_list_entry(pos, xqc_cid_inner_t, list);

        if (inner_cid->state == XQC_CID_RETIRED) {

            if (inner_cid->retired_ts < now) {
                /* switch state to REMOVED & delete from cid_set */
                if (xqc_find_conns_hash(conn->engine->conns_hash, conn, &inner_cid->cid)) {
                    xqc_remove_conns_hash(conn->engine->conns_hash, conn, &inner_cid->cid);
                }

                ret = xqc_cid_switch_to_next_state(&conn->scid_set.cid_set, inner_cid, XQC_CID_REMOVED);
                if (ret != XQC_OK) {
                    xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_cid_switch_to_next_state error|");
                    return;
                }

                xqc_list_del(pos);
                xqc_free(inner_cid);

            } else {
                /* record the earliest time that has not yet expired */
                if (inner_cid->retired_ts < next_time) {
                    next_time = inner_cid->retired_ts;
                }

            }
        }
    }

    if (conn->scid_set.cid_set.retired_cnt > 0) {
        if (next_time == XQC_MAX_UINT64_VALUE) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|next_time is not assigned a value|");
            return;
        }
        xqc_send_ctl_timer_set(ctl, XQC_TIMER_RETIRE_CID, now, next_time - now);
    }
}

void
xqc_send_ctl_linger_close_timeout(xqc_send_ctl_timer_type type, xqc_usec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t *) ctx;
    xqc_connection_t *conn = ctl->ctl_conn;
    xqc_int_t ret;

    conn->conn_flag &= ~XQC_CONN_FLAG_LINGER_CLOSING;

    ret = xqc_conn_immediate_close(conn);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_immediate_close error|");
        return;
    }
}

void
xqc_send_ctl_key_update_timeout(xqc_send_ctl_timer_type type, xqc_usec_t now, void *ctx)
{
    xqc_send_ctl_t *ctl = (xqc_send_ctl_t *) ctx;
    xqc_connection_t *conn = ctl->ctl_conn;

    xqc_tls_discard_old_1rtt_keys(conn->tls);
}

/* timer callbacks end */

void
xqc_send_ctl_timer_init(xqc_send_ctl_t *ctl)
{
    memset(ctl->ctl_timer, 0, XQC_TIMER_N * sizeof(xqc_send_ctl_timer_t));
    xqc_send_ctl_timer_t *timer;
    for (xqc_send_ctl_timer_type type = 0; type < XQC_TIMER_N; ++type) {
        timer = &ctl->ctl_timer[type];
        if (type == XQC_TIMER_ACK_INIT || type == XQC_TIMER_ACK_HSK || type == XQC_TIMER_ACK_01RTT) {
            timer->ctl_timer_callback = xqc_send_ctl_ack_timeout;
            timer->ctl_ctx = ctl;

        } else if (type == XQC_TIMER_LOSS_DETECTION) {
            timer->ctl_timer_callback = xqc_send_ctl_loss_detection_timeout;
            timer->ctl_ctx = ctl;

        } else if (type == XQC_TIMER_IDLE) {
            timer->ctl_timer_callback = xqc_send_ctl_idle_timeout;
            timer->ctl_ctx = ctl;

        } else if (type == XQC_TIMER_DRAINING) {
            timer->ctl_timer_callback = xqc_send_ctl_draining_timeout;
            timer->ctl_ctx = ctl;

        } else if (type == XQC_TIMER_PACING) {
            timer->ctl_timer_callback = xqc_send_ctl_pacing_timeout;
            timer->ctl_ctx = ctl;

        } else if (type == XQC_TIMER_STREAM_CLOSE) {
            timer->ctl_timer_callback = xqc_send_ctl_stream_close_timeout;
            timer->ctl_ctx = ctl;

        } else if (type == XQC_TIMER_PING) {
            timer->ctl_timer_callback = xqc_send_ctl_ping_timeout;
            timer->ctl_ctx = ctl;

        } else if (type == XQC_TIMER_RETIRE_CID) {
            timer->ctl_timer_callback = xqc_send_ctl_retire_cid_timeout;
            timer->ctl_ctx = ctl;

        } else if (type == XQC_TIMER_LINGER_CLOSE) {
            timer->ctl_timer_callback = xqc_send_ctl_linger_close_timeout;
            timer->ctl_ctx = ctl;

        } else if (type == XQC_TIMER_KEY_UPDATE) {
            timer->ctl_timer_callback = xqc_send_ctl_key_update_timeout;
            timer->ctl_ctx = ctl;
        }
    }
}

/*
 * *****************TIMER END*****************
 */
