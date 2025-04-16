#ifndef _XQC_RECV_TIMESTAMPS_INFO_H_INCLUDED_
#define _XQC_RECV_TIMESTAMPS_INFO_H_INCLUDED_

#include <xquic/xquic_typedef.h>

#define XQC_RECV_TIMESTAMPS_INFO_MAX_LENGTH 64

/*
 * xqc_recv_timestamps_info_t: using a circular deque with fix length
 * to save packet receive timestamp in ascending order of pkt num. If 
 * one packet arrives out of order, just discard and don't report it.
*/
typedef struct xqc_recv_timestamps_info_s {
    uint32_t                start_idx;
    uint32_t                end_idx;
    uint32_t                cur_len;
    xqc_packet_number_t     expected_next_pkt_num;
    xqc_usec_t              recv_timestamps[XQC_RECV_TIMESTAMPS_INFO_MAX_LENGTH];
    xqc_packet_number_t     pkt_nums[XQC_RECV_TIMESTAMPS_INFO_MAX_LENGTH];
    /* 
    * if XQC_RECV_TIMESTAMPS_INFO_MAX_LENGTH > 64, 
    *    new_range_flag should be implemented in another way.
    */
    uint64_t                new_range_flag;
    uint8_t                 is_first_pkt;
    uint8_t                 nobuf_for_ts_in_last_ext_ack;
} xqc_recv_timestamps_info_t;

typedef struct xqc_ack_timestamp_info_s {
    uint32_t                report_num;
    xqc_packet_number_t     pkt_nums[XQC_RECV_TIMESTAMPS_INFO_MAX_LENGTH];
    uint64_t                recv_ts[XQC_RECV_TIMESTAMPS_INFO_MAX_LENGTH];
} xqc_ack_timestamp_info_t;

xqc_recv_timestamps_info_t *xqc_recv_timestamps_info_create();

void xqc_recv_timestamps_info_destroy(xqc_recv_timestamps_info_t *ts_info);

void xqc_recv_timestamps_info_add_pkt(xqc_recv_timestamps_info_t *ts_info,
    xqc_packet_number_t pkt_num, xqc_usec_t recv_time);

void xqc_recv_timestamps_info_clear(xqc_recv_timestamps_info_t *ts_info);

int xqc_recv_timestamps_info_length(xqc_recv_timestamps_info_t *ts_info);

int xqc_recv_timestamps_info_fetch(xqc_recv_timestamps_info_t *ts_info, uint32_t idx,
    xqc_packet_number_t *pkt_num, xqc_usec_t *recv_time);

size_t xqc_recv_timestamps_info_need_bytes_estimate(xqc_recv_timestamps_info_t *ts_info);

void xqc_recv_timestamps_info_set_nobuf_flag(xqc_recv_timestamps_info_t *ts_info, uint8_t has_ts_in_ack_ext);

#endif /* _XQC_RECV_TIMESTAMPS_INFO_H_INCLUDED_ */