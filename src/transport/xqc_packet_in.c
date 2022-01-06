/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/transport/xqc_packet_in.h"
#include "src/common/xqc_memory_pool.h"
#include "src/transport/xqc_conn.h"


void
xqc_packet_in_init(xqc_packet_in_t *packet_in,
    const unsigned char *packet_in_buf,
    size_t packet_in_size,
    unsigned char *decode_payload,
    size_t decode_payload_size,
    xqc_usec_t recv_time)
{
    packet_in->buf = packet_in_buf;
    packet_in->buf_size = packet_in_size;
    packet_in->decode_payload = decode_payload;
    packet_in->decode_payload_size = decode_payload_size;
    packet_in->pos = (unsigned char *)packet_in_buf;
    packet_in->last = (unsigned char *)packet_in_buf + packet_in_size;
    packet_in->pkt_recv_time = recv_time;
}

void
xqc_packet_in_destroy(xqc_packet_in_t *packet_in, xqc_connection_t *conn)
{
    xqc_free((void *)packet_in->buf);
    xqc_free((void *)packet_in->decode_payload);
    xqc_free(packet_in);
}

