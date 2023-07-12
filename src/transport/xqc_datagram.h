/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_DATAGRAM_H_INCLUDED_
#define _XQC_DATAGRAM_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include "src/common/xqc_list.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_frame_parser.h"

typedef struct xqc_datagram_0rtt_buffer_s {
    xqc_list_head_t list;
    struct iovec iov;
    uint64_t dgram_id;
    xqc_data_qos_level_t qos_level;
} xqc_datagram_0rtt_buffer_t;

xqc_datagram_0rtt_buffer_t* xqc_datagram_create_0rtt_buffer(void *data, 
    size_t data_len, uint64_t dgram_id, xqc_data_qos_level_t qos_level);

void xqc_datagram_destroy_0rtt_buffer(xqc_datagram_0rtt_buffer_t* buffer);

void xqc_datagram_record_mss(xqc_connection_t *conn);

void xqc_datagram_notify_write(xqc_connection_t *conn);

xqc_int_t xqc_datagram_notify_loss(xqc_connection_t *conn, xqc_packet_out_t *po);

void xqc_datagram_notify_ack(xqc_connection_t *conn, xqc_packet_out_t *po);

xqc_int_t xqc_datagram_send_multiple_internal(xqc_connection_t *conn, 
    struct iovec *iov, uint64_t *dgram_id_list, size_t iov_size, 
    size_t *sent_cnt, size_t *sent_bytes, xqc_data_qos_level_t qos_level, 
    xqc_bool_t use_supplied_dgram_id);

#endif