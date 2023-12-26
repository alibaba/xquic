/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/congestion_control/xqc_sample.h"
#include "src/common/xqc_config.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet.h"


void xqc_init_sample_before_ack(xqc_sample_t *sampler)
{
    xqc_send_ctl_t *ctl = sampler->send_ctl;
    memset(sampler, 0, sizeof(xqc_sample_t));
    sampler->send_ctl = ctl;
}

/**
 * see https://tools.ietf.org/html/draft-cheng-iccrg-delivery-rate-estimation-00#section-3.3
 */
/* Upon receiving ACK, fill in delivery rate sample rs. */
xqc_sample_type_t 
xqc_generate_sample(xqc_sample_t *sampler, xqc_send_ctl_t *send_ctl, 
    xqc_usec_t now)
{
    
    /* we do NOT have a valid sample yet. */
    /* the ACK acks nothing */
    if (sampler->prior_time == 0) {
        sampler->interval = 0;
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_WARN, 
                "|sampler_prior_time_is_zero!|");
        return XQC_RATE_SAMPLE_ACK_NOTHING;
    }

    sampler->acked = send_ctl->ctl_delivered - send_ctl->ctl_prior_delivered;
    /* Use the longer of the send_elapsed and ack_elapsed */
    sampler->interval = xqc_max(sampler->ack_elapse, sampler->send_elapse);
    sampler->delivered = send_ctl->ctl_delivered - sampler->prior_delivered;
    /* This is for BBRv2 */
    sampler->lost_pkts = send_ctl->ctl_lost_pkts_number - sampler->prior_lost;

    /* 
     * Even if the interval is too small, 
     * we need to update these data for Copa. 
     */
    sampler->now = now;
    sampler->rtt = send_ctl->ctl_latest_rtt;
    sampler->srtt = send_ctl->ctl_srtt;
    sampler->bytes_inflight = send_ctl->ctl_bytes_in_flight;
    sampler->prior_inflight = send_ctl->ctl_prior_bytes_in_flight;
    sampler->total_acked = send_ctl->ctl_delivered;
    sampler->total_lost_pkts = send_ctl->ctl_lost_pkts_number;

    /* 
     * Normally we expect interval >= MinRTT.
     * Note that rate may still be over-estimated when a spuriously
     * retransmitted skb was first (s)acked because "interval"
     * is under-estimated (up to an RTT). However, continuously
     * measuring the delivery rate during loss recovery is crucial
     * for connections suffer heavy or prolonged losses.
     */
    if (sampler->interval < send_ctl->ctl_minrtt) {
        sampler->interval = 0;
        return XQC_RATE_SAMPLE_INTERVAL_TOO_SAMLL;
    }
    if (sampler->interval != 0) {
        /* unit of interval is us */
        sampler->delivery_rate = (uint64_t)(1e6 * sampler->delivered / sampler->interval);
    }

    xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
            "|sampler: send_elapse %ui, ack_elapse %ui, "
            "delivered %ud|rate %ui|lost %ud|",
            sampler->send_elapse, sampler->ack_elapse,
            sampler->delivered, sampler->delivery_rate,
            sampler->total_lost_pkts);
            
    return XQC_RATE_SAMPLE_VALID;
}

/* Update rs when packet is SACKed or ACKed. */
void 
xqc_update_sample(xqc_sample_t *sampler, xqc_packet_out_t *packet,
    xqc_send_ctl_t *send_ctl, xqc_usec_t now)
{
    if (packet->po_delivered_time == 0) {
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
                "|packet:%ui already acked|", packet->po_pkt.pkt_num);
        return; /* P already SACKed */
    }

    send_ctl->ctl_delivered += packet->po_used_size;
    send_ctl->ctl_delivered_time = now;

    /* Update info using the newest packet: */
    /* if it's the ACKs from the first RTT round, we use the sample anyway */

    if ((sampler->prior_delivered == 0)
        || (packet->po_delivered > sampler->prior_delivered)) 
    {
        sampler->prior_lost = packet->po_lost;
        sampler->tx_in_flight = packet->po_tx_in_flight;
        sampler->prior_delivered = packet->po_delivered;
        sampler->prior_time = packet->po_delivered_time;

        if (xqc_conn_is_handshake_confirmed(send_ctl->ctl_conn)) {
            sampler->is_app_limited = packet->po_is_app_limited;

        } else {
            sampler->is_app_limited = 1;
        }
        
        sampler->send_elapse = packet->po_sent_time - 
                               packet->po_first_sent_time;
        sampler->ack_elapse = send_ctl->ctl_delivered_time - 
                              packet->po_delivered_time;
        send_ctl->ctl_first_sent_time = packet->po_sent_time;
        sampler->lagest_ack_time = now;
    }
    xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|sampler_update|"
            "prior_lost:%ud|tx_in_flight:%ui|"
            "prior_delivered:%ui|prior_time:%ui|is_app_limited:%ud|"
            "send_elapse:%ui|ack_elapse:%ui|ctl_first_sent_time:%ui|"
            "lagest_ack_time:%ui|curr_delivered:%ui|",
            sampler->prior_lost, sampler->tx_in_flight,
            sampler->prior_delivered, sampler->prior_time, 
            sampler->is_app_limited, sampler->send_elapse, sampler->ack_elapse, 
            send_ctl->ctl_first_sent_time, sampler->lagest_ack_time,
            send_ctl->ctl_delivered);
    
    /* always keep it updated with the largest acked packet */
    sampler->po_sent_time = packet->po_sent_time; 
    xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
            "|sampler_sent_time_update:%ui|", sampler->po_sent_time);
    /* 
     * Mark the packet as delivered once it's SACKed to
     * avoid being used again when it's cumulatively acked.
     */
    packet->po_delivered_time = 0;
}

xqc_bool_t
xqc_sample_check_app_limited(xqc_sample_t *sampler, xqc_send_ctl_t *send_ctl, xqc_send_queue_t *send_queue)
{
    uint32_t cwnd_bytes = send_ctl->ctl_cong_callback->
                          xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong);
    uint32_t actual_mss = xqc_conn_get_mss(send_ctl->ctl_conn);
    xqc_bool_t not_cwnd_limited = send_ctl->ctl_bytes_in_flight + actual_mss <= 
                                  cwnd_bytes;
    /* @FIXME: We should find a better way to adapt it to multipath. 
     * The current implemetation is problematic. As even if we have pkts 
     * in snd/lost/pto list, they may not be scheduled on the path. Therefore,
     * if the path buffer is empty, there might be some "bubbles" in the pipe.
     * However, we have no better idea to handle this problem at this moment.
     */

    xqc_bool_t all_path_buffer_empty = XQC_TRUE;
    int i;
    for (i = XQC_SEND_TYPE_NORMAL; i < XQC_SEND_TYPE_N; i++) {
        if (!xqc_list_empty(&send_ctl->ctl_path->path_schedule_buf[i])) {
            all_path_buffer_empty = XQC_FALSE;
        }
    }

    xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
            "|check_applimit|path:%ui|inflight:%ud|"
            "now_cwnd_limited:%d|all_path_empty:%d|"
            "sndq:%d|lostq:%d|ptoq:%d|",
            send_ctl->ctl_path->path_id, send_ctl->ctl_bytes_in_flight, 
            !send_ctl->ctl_is_cwnd_limited, all_path_buffer_empty,
            xqc_list_empty(&send_queue->sndq_send_packets),
            xqc_list_empty(&send_queue->sndq_lost_packets),
            xqc_list_empty(&send_queue->sndq_pto_probe_packets));

    if (not_cwnd_limited    /* We are not limited by CWND. */
        && xqc_list_empty(&send_queue->sndq_send_packets)  /* We have no packet to send. */
        && xqc_list_empty(&send_queue->sndq_lost_packets)  /* All lost packets have been retransmitted. */
        && xqc_list_empty(&send_queue->sndq_pto_probe_packets)
        && all_path_buffer_empty)
    {
        send_ctl->ctl_app_limited = (send_ctl->ctl_delivered + 
                                    send_ctl->ctl_bytes_in_flight) ?
                                    (send_ctl->ctl_delivered + 
                                    send_ctl->ctl_bytes_in_flight)
                                    : 1;
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|path:%ui|"
                "applimit:%ui|", send_ctl->ctl_path->path_id,
                send_ctl->ctl_app_limited);
        if (send_ctl->ctl_app_limited > 0) {
            xqc_log_event(send_ctl->ctl_conn->log, REC_CONGESTION_STATE_UPDATED, "application_limit");
        }
        return XQC_TRUE;
    }

    return XQC_FALSE;
}

void 
xqc_sample_on_sent(xqc_packet_out_t *packet_out, xqc_send_ctl_t *send_ctl, 
    xqc_usec_t now)
{
    if (send_ctl->ctl_bytes_in_flight == 0) {
        send_ctl->ctl_delivered_time = send_ctl->ctl_first_sent_time = now;
    }
    packet_out->po_delivered_time = send_ctl->ctl_delivered_time;
    packet_out->po_first_sent_time = send_ctl->ctl_first_sent_time;
    packet_out->po_delivered = send_ctl->ctl_delivered;
    packet_out->po_is_app_limited = send_ctl->ctl_app_limited > 0 ? XQC_TRUE : XQC_FALSE;
    packet_out->po_lost = send_ctl->ctl_lost_pkts_number;
    packet_out->po_tx_in_flight = send_ctl->ctl_bytes_in_flight + 
                                  packet_out->po_used_size;
}