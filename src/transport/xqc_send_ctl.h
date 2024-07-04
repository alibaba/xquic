/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_SEND_CTL_H_INCLUDED_
#define _XQC_SEND_CTL_H_INCLUDED_

#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_pacing.h"
#include "src/congestion_control/xqc_sample.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_timer.h"
#include "src/transport/xqc_multipath.h"
#include <math.h>

#define XQC_kPacketThreshold                3
#define XQC_kTimeThresholdShift             3
#define XQC_kPersistentCongestionThreshold  3

#define XQC_CONSECUTIVE_PTO_THRESH          2
/*
 * Timer granularity.  This is a system-dependent value.
 * However, implementations SHOULD use a value no smaller than 1ms.
 */
#define XQC_kGranularity                    2

#define XQC_kInitialRtt_us                  250000

/* 2^n */
#define xqc_send_ctl_pow(n)                 (1 << n)
#define xqc_send_ctl_pow_x(x, n)            (fabs(x - 2) < 1e-7) ? xqc_send_ctl_pow(n) : pow(x, n)


#define XQC_DEFAULT_RECORD_INTERVAL         (100000)    /* 100ms record interval */
#define XQC_DEFAULT_RTT_CHANGE_THRESHOLD    (50 * 1000) /* 50ms */
#define XQC_DEFAULT_BW_CHANGE_THRESHOLD     (50)        /* percentage of bandwidth change */
typedef struct {
    xqc_usec_t  last_record_time;     /* last periodic record time */
    xqc_usec_t  last_rtt_time;        /* last time the rtt was drastically changed */
    xqc_usec_t  last_lost_time;       /* last time a packet loss was recorded */
    xqc_usec_t  last_bw_time;         /* last time the bandwidth was drastically changed */
    uint64_t    record_interval;      /* all types of records are recorded only once in the interval */
    uint64_t    rtt_change_threshold; /* threshold of rtt change */
    uint64_t    bw_change_threshold;  /* threshold of bandwidth change */
    uint64_t    last_lost_count;      /* number of packets lost in the last record */
    uint64_t    last_send_count;      /* number of packets sent in the last record */
}xqc_send_ctl_info_t;

typedef struct xqc_pn_ctl_s {

    xqc_packet_number_t         ctl_packet_number[XQC_PNS_N];

    /* maximum value of Largest Acknowledged in the packet_out that sent ACK and was ACKed
     * ensures that the ACK has been received by the peer,
     * so that the sender can no longer generate ACKs smaller than that value */
    xqc_packet_number_t         ctl_largest_acked_ack[XQC_PNS_N];

    /* largest packet number of the packets sent */
    xqc_packet_number_t         ctl_largest_sent[XQC_PNS_N];

    /* record received pkt number range in a list */
    xqc_recv_record_t           ctl_recv_record[XQC_PNS_N];

    /* record ack sent */
    xqc_ack_sent_record_t       ack_sent_record[XQC_PNS_N];

} xqc_pn_ctl_t;

typedef struct xqc_send_ctl_s {
    xqc_connection_t            *ctl_conn;
    xqc_path_ctx_t              *ctl_path;

    /* largest packet number of the acked packets in packet_out */
    xqc_packet_number_t         ctl_largest_acked[XQC_PNS_N];

    /* sending time of largest packet */
    xqc_usec_t                  ctl_largest_acked_sent_time[XQC_PNS_N];

    /* largest packet number of the received packets in packet_in */
    xqc_packet_number_t         ctl_largest_received[XQC_PNS_N];
    
    /* received time of largest packet */
    xqc_usec_t                  ctl_largest_recv_time[XQC_PNS_N];

    /* Ack-eliciting Packets received since last ack sent */
    uint32_t                    ctl_ack_eliciting_pkt[XQC_PNS_N];

    xqc_usec_t                  ctl_loss_time[XQC_PNS_N];

    xqc_usec_t                  ctl_last_inflight_pkt_sent_time;
    xqc_usec_t                  ctl_time_of_last_sent_ack_eliciting_packet[XQC_PNS_N];
    xqc_packet_number_t         ctl_last_sent_ack_eliciting_packet_number[XQC_PNS_N];
    xqc_usec_t                  ctl_srtt,
                                ctl_rttvar,
                                ctl_minrtt,
                                ctl_latest_rtt;
    xqc_usec_t                  ctl_first_rtt_sample_time; /* The time when the conn gets the first RTT sample. */

    /* data record - latest rtt */
    uint32_t                    ctl_update_latest_rtt_count;
    xqc_msec_t                  ctl_latest_rtt_sum;
    xqc_msec_t                  ctl_latest_rtt_square_sum;

    xqc_timer_manager_t         path_timer_manager;

    unsigned                    ctl_pto_count;

    unsigned                    ctl_send_count;
    unsigned                    ctl_lost_count;
    unsigned                    ctl_tlp_count;
    unsigned                    ctl_spurious_loss_count;
    unsigned                    ctl_lost_dgram_cnt;

    /* record time for last three cwnd limitation and rtt mutation*/
    xqc_msec_t                  ctl_recent_cwnd_limitation_time[3];
    uint8_t                     ctl_cwndlim_update_idx;
    
    unsigned                    ctl_recv_count;

    /* for QUIC datagrams */
    uint32_t                    ctl_dgram_send_count;
    uint32_t                    ctl_dgram_recv_count;
    uint32_t                    ctl_reinj_dgram_send_count;
    uint32_t                    ctl_reinj_dgram_recv_count;

    uint32_t                    ctl_max_bytes_in_flight;
    uint8_t                     ctl_is_cwnd_limited;

    unsigned                    ctl_bytes_in_flight;
    uint32_t                    ctl_bytes_ack_eliciting_inflight[XQC_PNS_N];
    unsigned                    ctl_prior_bytes_in_flight;

    uint64_t                    ctl_bytes_send;
    uint64_t                    ctl_bytes_recv;

    const
    xqc_cong_ctrl_callback_t    *ctl_cong_callback;
    void                        *ctl_cong;

    xqc_pacing_t                ctl_pacing;

    uint64_t                    ctl_prior_delivered;    /* the amount of data delivered in the last call of on_ack_received*/
    uint64_t                    ctl_delivered;          /* the amount of data that has been marked as sent at the current ack moment */
    uint64_t                    ctl_app_limited;        /* The index of the last transmitted packet marked as application-limited,
                                                         * or 0 if the connection is not currently application-limited. */
    xqc_usec_t                  ctl_delivered_time;     /* time when the current packet was acked */
    xqc_usec_t                  ctl_first_sent_time;    /* Send time of the first packet in the current sampling period */
    uint32_t                    ctl_lost_pkts_number;   /* how many packets have been lost so far */

    xqc_packet_number_t         ctl_reordering_packet_threshold;
    int32_t                     ctl_reordering_time_threshold_shift;

    xqc_sample_t                sampler;

    xqc_send_ctl_info_t         ctl_info;

    unsigned                    ctl_recent_send_count[2];
    unsigned                    ctl_recent_lost_count[2];
    xqc_usec_t                  ctl_recent_stats_timestamp;

    uint64_t                    ctl_ack_sent_cnt;

} xqc_send_ctl_t;


static inline xqc_usec_t
xqc_send_ctl_calc_pto(xqc_send_ctl_t *send_ctl)
{
    return send_ctl->ctl_srtt + xqc_max(4 * send_ctl->ctl_rttvar, XQC_kGranularity * 1000)
        + send_ctl->ctl_conn->local_settings.max_ack_delay * 1000;
}


void xqc_send_ctl_on_dgram_dropped(xqc_connection_t *conn, xqc_packet_out_t *po);

int xqc_send_ctl_may_remove_unacked_dgram(xqc_connection_t *conn, xqc_packet_out_t *po);

int xqc_send_ctl_indirectly_ack_or_drop_po(xqc_connection_t *conn, xqc_packet_out_t *po);

xqc_send_ctl_t *xqc_send_ctl_create(xqc_path_ctx_t *path);

void xqc_send_ctl_destroy(xqc_send_ctl_t *send_ctl);

void xqc_send_ctl_reset(xqc_send_ctl_t *send_ctl);

xqc_pn_ctl_t *xqc_pn_ctl_create(xqc_connection_t *conn);

void xqc_pn_ctl_destroy(xqc_pn_ctl_t *pn_ctl);

xqc_pn_ctl_t *xqc_get_pn_ctl(xqc_connection_t *conn, xqc_path_ctx_t *path);

int xqc_send_ctl_can_send(xqc_send_ctl_t *send_ctl, xqc_packet_out_t *packet_out, uint32_t schedule_bytes);

xqc_bool_t xqc_send_packet_cwnd_allows(xqc_send_ctl_t *send_ctl, 
    xqc_packet_out_t *packet_out, uint32_t schedule_bytes, xqc_usec_t now);

xqc_bool_t xqc_send_packet_pacer_allows(xqc_send_ctl_t *send_ctl, 
    xqc_packet_out_t *packet_out, uint32_t schedule_bytes, xqc_usec_t now);

xqc_bool_t xqc_send_packet_check_cc(xqc_send_ctl_t *send_ctl, xqc_packet_out_t *packet_out, uint32_t schedule_bytes, xqc_usec_t now);

void xqc_send_ctl_increase_inflight(xqc_connection_t *conn, xqc_packet_out_t *packet_out);

void xqc_send_ctl_decrease_inflight(xqc_connection_t *conn, xqc_packet_out_t *packet_out);

void xqc_send_ctl_on_pns_discard(xqc_send_ctl_t *send_ctl, xqc_pkt_num_space_t pns);

void xqc_send_ctl_on_packet_sent(xqc_send_ctl_t *send_ctl, xqc_pn_ctl_t *pn_ctl, xqc_packet_out_t *packet_out, xqc_usec_t now);

int xqc_send_ctl_on_ack_received (xqc_send_ctl_t *send_ctl, xqc_pn_ctl_t *pn_ctl, xqc_send_queue_t *send_queue, xqc_ack_info_t *const ack_info, xqc_usec_t ack_recv_time, xqc_bool_t ack_on_same_path);

void xqc_send_ctl_on_dgram_received(xqc_send_ctl_t *send_ctl, size_t dgram_size);

void xqc_send_ctl_update_rtt(xqc_send_ctl_t *send_ctl, xqc_usec_t *latest_rtt, xqc_usec_t ack_delay);

void xqc_send_ctl_on_spurious_loss_detected(xqc_send_ctl_t *send_ctl,
    xqc_pkt_num_space_t pns, xqc_usec_t ack_recv_time,
    xqc_packet_number_t largest_ack, xqc_packet_number_t spurious_loss_pktnum,
    xqc_usec_t spurious_loss_sent_time);

void xqc_send_ctl_detect_lost(xqc_send_ctl_t *send_ctl, xqc_send_queue_t *send_queue, xqc_pkt_num_space_t pns, xqc_usec_t now);

xqc_bool_t xqc_send_ctl_in_persistent_congestion(xqc_send_ctl_t *send_ctl, xqc_packet_out_t *largest_lost, xqc_usec_t now);

void xqc_send_ctl_congestion_event(xqc_send_ctl_t *send_ctl, xqc_usec_t sent_time);

int xqc_send_ctl_in_recovery(xqc_send_ctl_t *send_ctl, xqc_usec_t sent_time);

int xqc_send_ctl_is_app_limited(xqc_send_ctl_t *send_ctl);

int xqc_send_ctl_is_cwnd_limited(xqc_send_ctl_t *send_ctl);

void xqc_send_ctl_cc_on_ack(xqc_send_ctl_t *send_ctl, xqc_packet_out_t *acked_packet, xqc_usec_t now);

void xqc_send_ctl_on_packet_acked(xqc_send_ctl_t *send_ctl, xqc_packet_out_t *acked_packet, xqc_usec_t now, int do_cc);

void xqc_send_queue_maybe_remove_unacked(xqc_packet_out_t *packet_out, xqc_send_queue_t *send_queue, xqc_path_ctx_t *path);

xqc_usec_t xqc_send_ctl_get_pto_time_and_space(xqc_send_ctl_t *send_ctl, xqc_usec_t now, xqc_pkt_num_space_t *pns_ret);

void xqc_send_ctl_set_loss_detection_timer(xqc_send_ctl_t *send_ctl);

xqc_usec_t xqc_send_ctl_get_earliest_loss_time(xqc_send_ctl_t *send_ctl, xqc_pkt_num_space_t *pns_ret);

xqc_usec_t xqc_send_ctl_get_srtt(xqc_send_ctl_t *send_ctl);

float xqc_send_ctl_get_retrans_rate(xqc_send_ctl_t *send_ctl);

float xqc_send_ctl_get_spurious_loss_rate(xqc_send_ctl_t *send_ctl);

/**
 * check amplification limit state
 * @param send_bytes input 0 to check if server is at limit now, input non-zero to
 * check if this byte count will trigger amplification limit
 * @return XQC_FALSE: not at amplification limit, XQC_TRUE: at amplification limit
 */
xqc_bool_t xqc_send_ctl_check_anti_amplification(xqc_send_ctl_t *send_ctl, size_t send_bytes);

void xqc_send_ctl_rearm_ld_timer(xqc_send_ctl_t *send_ctl);

xqc_bool_t xqc_send_ctl_ack_received_in_pns(xqc_send_ctl_t *send_ctl, xqc_pkt_num_space_t pns);

xqc_packet_number_t xqc_send_ctl_get_lost_sent_pn(xqc_send_ctl_t *send_ctl, xqc_pkt_num_space_t pns);

xqc_packet_number_t xqc_send_ctl_get_pkt_num_gap(xqc_send_ctl_t *send_ctl, xqc_pkt_num_space_t pns, xqc_packet_number_t front, xqc_packet_number_t back);

/* bytes per second */
uint64_t xqc_send_ctl_get_est_bw(xqc_send_ctl_t *send_ctl);
uint64_t xqc_send_ctl_get_pacing_rate(xqc_send_ctl_t *send_ctl);

#endif /* _XQC_SEND_CTL_H_INCLUDED_ */
