/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/congestion_control/xqc_sample.h"
#include "src/common/xqc_config.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet.h"

/**
 * see https://tools.ietf.org/html/draft-cheng-iccrg-delivery-rate-estimation-00#section-3.3
 */
/* Upon receiving ACK, fill in delivery rate sample rs. */
xqc_bool_t 
xqc_generate_sample(xqc_sample_t *sampler, xqc_send_ctl_t *send_ctl, 
    xqc_usec_t now)
{
    /* Clear app-limited field if bubble is ACKed and gone. */
    if (send_ctl->ctl_app_limited 
        && send_ctl->ctl_delivered > send_ctl->ctl_app_limited)
    {
        send_ctl->ctl_app_limited = 0;
    }

    /* we do NOT have a valid sample yet. */
    if (sampler->prior_time == 0) {
        sampler->interval = 0;
        return XQC_FALSE;
    }

    sampler->acked = send_ctl->ctl_delivered - send_ctl->ctl_prior_delivered;
    /* Use the longer of the send_elapsed and ack_elapsed */
    sampler->interval = xqc_max(sampler->ack_elapse, sampler->send_elapse);

    sampler->delivered = send_ctl->ctl_delivered - sampler->prior_delivered;
    /* This is for BBRv2 */
    sampler->lost_pkts = send_ctl->ctl_lost_pkts_number - sampler->prior_lost;

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
        return XQC_FALSE;
    }
    if (sampler->interval != 0) {
        /* unit of interval is us */
        sampler->delivery_rate = (uint64_t)(1e6 * sampler->delivered / sampler->interval);
    }
    sampler->now = now;
    sampler->rtt = send_ctl->ctl_latest_rtt;
    sampler->srtt = send_ctl->ctl_srtt;
    sampler->bytes_inflight = send_ctl->ctl_bytes_in_flight;
    sampler->prior_inflight = send_ctl->ctl_prior_bytes_in_flight;
    sampler->total_acked = send_ctl->ctl_delivered;

    xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
            "|sampler: send_elapse %ui, ack_elapse %ui, "
            "delivered %ud|",
            sampler->send_elapse, sampler->ack_elapse,
            sampler->delivered);
    return XQC_TRUE;
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

    if ((!sampler->is_initialized)
        || (packet->po_delivered > sampler->prior_delivered)) 
    {
        sampler->is_initialized = 1;
        sampler->prior_lost = packet->po_lost;
        sampler->tx_in_flight = packet->po_tx_in_flight;
        sampler->prior_delivered = packet->po_delivered;
        sampler->prior_time = packet->po_delivered_time;
        sampler->is_app_limited = packet->po_is_app_limited;
        sampler->send_elapse = packet->po_sent_time - 
                               packet->po_first_sent_time;
        sampler->ack_elapse = send_ctl->ctl_delivered_time - 
                              packet->po_delivered_time;
        send_ctl->ctl_first_sent_time = packet->po_sent_time;
        sampler->lagest_ack_time = now;
        sampler->po_sent_time = packet->po_sent_time; /* always keep it updated */
    }
    /* 
     * Mark the packet as delivered once it's SACKed to
     * avoid being used again when it's cumulatively acked.
     */
    packet->po_delivered_time = 0;
}

xqc_bool_t
xqc_sample_check_app_limited(xqc_sample_t *sampler, xqc_send_ctl_t *send_ctl)
{
    uint8_t not_cwnd_limited = 0;
    uint32_t cwnd = send_ctl->ctl_cong_callback->
                    xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong);
    if (send_ctl->ctl_bytes_in_flight < cwnd) {
        /* QUIC MSS */
        not_cwnd_limited = (cwnd - send_ctl->ctl_bytes_in_flight) >= XQC_QUIC_MSS; 
    }

    if (not_cwnd_limited    /* We are not limited by CWND. */
        && xqc_list_empty(&send_ctl->ctl_send_packets)  /* We have no packet to send. */
        && xqc_list_empty(&send_ctl->ctl_lost_packets)  /* All lost packets have been retransmitted. */
        && xqc_list_empty(&send_ctl->ctl_pto_probe_packets))
    {
        send_ctl->ctl_app_limited = (send_ctl->ctl_delivered + 
                                    send_ctl->ctl_bytes_in_flight) ?: 1;
        if (send_ctl->ctl_app_limited > 0) {
            xqc_log_event(send_ctl->ctl_conn->log, REC_CONGESTION_STATE_UPDATED, "application_limit");
        }
        return XQC_TRUE;
    }

    return XQC_FALSE;
}

void 
xqc_sample_on_sent(xqc_packet_out_t *packet_out, xqc_send_ctl_t *ctl, 
    xqc_usec_t now)
{
    if (ctl->ctl_bytes_in_flight == 0) {
        ctl->ctl_delivered_time = ctl->ctl_first_sent_time = now;
    }
    packet_out->po_delivered_time = ctl->ctl_delivered_time;
    packet_out->po_first_sent_time = ctl->ctl_first_sent_time;
    packet_out->po_delivered = ctl->ctl_delivered;
    packet_out->po_is_app_limited = ctl->ctl_app_limited > 0 ? XQC_TRUE : XQC_FALSE;
    packet_out->po_lost = ctl->ctl_lost_pkts_number;
    packet_out->po_tx_in_flight = ctl->ctl_bytes_in_flight + 
                                  packet_out->po_used_size;
}