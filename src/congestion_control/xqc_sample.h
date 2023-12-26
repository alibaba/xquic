/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_SAMPLE_H_INCLUDED_
#define _XQC_SAMPLE_H_INCLUDED_

#include <xquic/xquic_typedef.h>


typedef struct xqc_sample_s {
    /* sampling time */
    xqc_usec_t       now;
    /* the number of packets that have been transferred when the packet currently in ack is being sent */
    uint64_t         prior_delivered;
    /* time interval between samples */
    xqc_usec_t       interval;
    /* the amount of data transferred (ack) between two samples */
    uint32_t         delivered;
    /* the amount of newly delivered data*/
    uint32_t         acked;
    /* the amount of data sent but not received ack */
    uint32_t         bytes_inflight;
    /* before processing this ack */
    uint32_t         prior_inflight;
    /* sampled rtt */
    xqc_usec_t       rtt;
    uint32_t         is_app_limited;
    /* whether packet loss */
    uint32_t         loss;
    uint64_t         total_acked;
    xqc_usec_t       srtt;
    /* used to determine if generate_sample needs to be called */
    xqc_usec_t       prior_time;
    xqc_usec_t       ack_elapse;
    xqc_usec_t       send_elapse;
    uint32_t         delivery_rate;
    xqc_usec_t       lagest_ack_time;
    xqc_send_ctl_t  *send_ctl;
 
    xqc_usec_t       po_sent_time;
 
    /* for BBRv2 */ 
    uint32_t         prior_lost;
    uint64_t         tx_in_flight;
    uint32_t         lost_pkts;

    uint32_t         total_lost_pkts;

} xqc_sample_t;

void xqc_init_sample_before_ack(xqc_sample_t *sampler);

/**
 * @brief 
 * @return: 0, success; 1, the ACK acks nothing; 2, the interval is too small.
 */
typedef enum {
    XQC_RATE_SAMPLE_VALID = 0,
    XQC_RATE_SAMPLE_ACK_NOTHING = 1,
    XQC_RATE_SAMPLE_INTERVAL_TOO_SAMLL = 2,
} xqc_sample_type_t;

xqc_sample_type_t xqc_generate_sample(xqc_sample_t *sampler, 
    xqc_send_ctl_t *send_ctl, xqc_usec_t now);
void xqc_update_sample(xqc_sample_t *sample, xqc_packet_out_t *packet, 
    xqc_send_ctl_t *send_ctl, xqc_usec_t now);
xqc_bool_t xqc_sample_check_app_limited(xqc_sample_t *sampler, 
    xqc_send_ctl_t *send_ctl, xqc_send_queue_t *send_queue);
void xqc_sample_on_sent(xqc_packet_out_t *packet_out, xqc_send_ctl_t *send_ctl, 
    xqc_usec_t now);

#endif