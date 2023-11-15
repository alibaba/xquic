/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_RECV_RECORD_H_INCLUDED_
#define _XQC_RECV_RECORD_H_INCLUDED_

#include "src/common/utils/ringarray/xqc_ring_array.h"
#include "src/transport/xqc_packet.h"

typedef enum {
    XQC_PKTRANGE_OK,
    XQC_PKTRANGE_DUP,
    XQC_PKTRANGE_ERR,
} xqc_pkt_range_status;

typedef struct xqc_pktno_range_s {
    xqc_packet_number_t low, high;
} xqc_pktno_range_t;

typedef struct xqc_pktno_range_node_s {
    xqc_pktno_range_t   pktno_range;
    xqc_list_head_t     list;
} xqc_pktno_range_node_t;

typedef struct xqc_recv_record_s {
    xqc_list_head_t         list_head;  /* xqc_pktno_range_node_t */
    xqc_packet_number_t     rr_del_from;
    xqc_int_t               node_count;
} xqc_recv_record_t;

#define XQC_MAX_ACK_RANGE_CNT 64

typedef struct xqc_ack_info_s {
    xqc_pkt_num_space_t     pns;
    uint64_t                dcid_seq_num;
    unsigned                n_ranges;  /* must > 0 */
    xqc_pktno_range_t       ranges[XQC_MAX_ACK_RANGE_CNT];
    xqc_usec_t              ack_delay;
} xqc_ack_info_t;

typedef struct xqc_ack_sent_entry_s {
    xqc_packet_number_t pkt_num;
    xqc_packet_number_t largest_ack;
} xqc_ack_sent_entry_t;

typedef struct xqc_ack_sent_record_s {
    xqc_rarray_t       *ack_sent;
    xqc_usec_t          last_add_time;
} xqc_ack_sent_record_t;

void xqc_recv_record_log(xqc_connection_t *conn, xqc_recv_record_t *recv_record);

void xqc_recv_record_print(xqc_connection_t *conn, xqc_recv_record_t *recv_record, char *buff, unsigned buff_size);

void xqc_recv_record_del(xqc_recv_record_t *recv_record, xqc_packet_number_t del_from);

void xqc_recv_record_destroy(xqc_recv_record_t *recv_record);

void xqc_recv_record_move(xqc_recv_record_t *dst, xqc_recv_record_t *src);

xqc_pkt_range_status xqc_recv_record_add(xqc_recv_record_t *recv_record, xqc_packet_number_t packet_number);

xqc_packet_number_t xqc_recv_record_largest(xqc_recv_record_t *recv_record);

void xqc_maybe_should_ack(xqc_connection_t *conn, xqc_path_ctx_t *path, xqc_pn_ctl_t *pn_ctl, xqc_pkt_num_space_t pns, int out_of_order, xqc_usec_t now);

int xqc_ack_sent_record_init(xqc_ack_sent_record_t *record);

void xqc_ack_sent_record_reset(xqc_ack_sent_record_t *record);

void xqc_ack_sent_record_destroy(xqc_ack_sent_record_t *record);

int xqc_ack_sent_record_add(xqc_ack_sent_record_t *record, xqc_packet_out_t *packet_out, xqc_usec_t srtt, xqc_usec_t now);

xqc_packet_number_t xqc_ack_sent_record_on_ack(xqc_ack_sent_record_t *record, xqc_ack_info_t *ack_info);

#endif /* _XQC_RECV_RECORD_H_INCLUDED_ */
