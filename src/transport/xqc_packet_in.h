/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_PACKET_IN_H_INCLUDED_
#define _XQC_PACKET_IN_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_frame.h"


struct xqc_packet_in_s {
    xqc_packet_t            pi_pkt;
    xqc_list_head_t         pi_list;
    const unsigned char    *buf;
    size_t                  buf_size;
    unsigned char          *decode_payload;
    size_t                  decode_payload_size;
    size_t                  decode_payload_len;
    unsigned char          *pos;
    unsigned char          *last;
    xqc_usec_t              pkt_recv_time;  /* microsecond */
    xqc_frame_type_bit_t    pi_frame_types;
};


#define XQC_BUFF_LEFT_SIZE(pos, last) ((last) > (pos) ? (last) - (pos) : 0)

void xqc_packet_in_init(xqc_packet_in_t *packet_in,
    const unsigned char *packet_in_buf,
    size_t packet_in_size,
    unsigned char *decode_payload,
    size_t decode_payload_size,
    xqc_usec_t recv_time);

void xqc_packet_in_destroy(xqc_packet_in_t *packet_in, xqc_connection_t *conn);


#endif /* _XQC_PACKET_IN_H_INCLUDED_ */
