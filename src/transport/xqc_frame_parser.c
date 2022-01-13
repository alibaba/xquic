/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <string.h>
#include <sys/types.h>
#include "src/transport/xqc_frame_parser.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/common/xqc_log.h"
#include "src/common/xqc_log_event_callback.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet_parser.h"



ssize_t
xqc_gen_stream_frame(xqc_packet_out_t *packet_out,
    xqc_stream_id_t stream_id, size_t offset, uint8_t fin,
    const unsigned char *payload, size_t size, size_t *written_size)
{
    /* 
     * 0b00001XXX
     *  0x4     OFF
     *  0x2     LEN
     *  0x1     FIN
     */

    /*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Stream ID (i)                       ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         [Offset (i)]                        ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         [Length (i)]                        ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Stream Data (*)                      ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    size_t dst_buf_len = packet_out->po_buf_size - packet_out->po_used_size;

    *written_size = 0;
    /*  variable length integer's most significant 2 bits */
    unsigned stream_id_bits, offset_bits, length_bits;
    /* variable length integer's size(byte) */
    unsigned stream_id_len, offset_len, length_len;
    /* 0b00001XXX point to second byte */
    unsigned char *p = dst_buf + 1;

    stream_id_bits = xqc_vint_get_2bit(stream_id);
    stream_id_len = xqc_vint_len(stream_id_bits);
    if (offset) {
        offset_bits = xqc_vint_get_2bit(offset);
        offset_len = xqc_vint_len(offset_bits);

    } else {
        offset_len = 0;
    }

    /* fin_only means there is no stream data */
    uint8_t fin_only = (fin && !size);

    if (!fin_only) {
        ssize_t n_avail;

        n_avail = dst_buf_len - (p + stream_id_len + offset_len - dst_buf);

        /* 
         * If we cannot fill remaining buffer, we need to include data
         * length.
         */
        if (size <= n_avail) {
            length_bits = xqc_vint_get_2bit(size);
            length_len = xqc_vint_len(length_bits);
            n_avail -= length_len;
            if (size > n_avail) {
                size = n_avail;
                fin = 0;
            }

        } else {
            /* length_len = 0; reserve ACK, must have length. */
            size = n_avail;
            length_bits = xqc_vint_get_2bit(size);
            length_len = xqc_vint_len(length_bits);
            fin = 0;
        }

        if (n_avail <= 0 || size > n_avail) {
            return -XQC_ENOBUF;
        }

        xqc_vint_write(p, stream_id, stream_id_bits, stream_id_len);
        p += stream_id_len;

        if (offset_len) {
            xqc_vint_write(p, offset, offset_bits, offset_len);
        }
        p += offset_len;

        memcpy(p + length_len, payload, size);
        *written_size = size;

        if (length_len) {
            xqc_vint_write(p, size, length_bits, length_len);
        }

        p += length_len + size;

    } else {
        /* check if there is enough space to put Length */
        length_len = 1 + stream_id_len + offset_len < dst_buf_len ? 1 : 0;
        if (1 + stream_id_len + offset_len + length_len > dst_buf_len) {
            return -XQC_ENOBUF;
        }
        xqc_vint_write(p, stream_id, stream_id_bits, stream_id_len);
        p += stream_id_len;

        if (offset_len) {
            xqc_vint_write(p, offset, offset_bits, offset_len);
        }
        p += offset_len;

        if (length_len) {
            *p++ = 0;
        }
    }

    dst_buf[0] = 0x08
                 | (!!offset_len << 2)
                 | (!!length_len << 1)
                 | (!!fin << 0);

    packet_out->po_frame_types |= XQC_FRAME_BIT_STREAM;

    return p - dst_buf;
}

xqc_int_t
xqc_parse_stream_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn,
    xqc_stream_frame_t *frame, xqc_stream_id_t *stream_id)
{
    uint64_t offset;
    uint64_t length;
    int      vlen;

    const unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;

    const unsigned char first_byte = *p++;

    vlen = xqc_vint_read(p, end, stream_id);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    if (first_byte & 0x04) {
        vlen = xqc_vint_read(p, end, &offset);
        if (vlen < 0) {
            return -XQC_EVINTREAD;
        }
        p += vlen;
        frame->data_offset = offset;

    } else {
        frame->data_offset = 0;
    }

    if (first_byte & 0x02) {
        vlen = xqc_vint_read(p, end, &length);
        if (vlen < 0) {
            return -XQC_EVINTREAD;
        }

        if (length > end - p) {
            return -XQC_EILLEGAL_FRAME;
        }
        p += vlen;
        frame->data_length = length;

    } else {
        frame->data_length = end - p;
    }

    if (first_byte & 0x01) {
        frame->fin = 1;

    } else {
        frame->fin = 0;
    }

    if (frame->data_length > 0) {
        frame->data = xqc_malloc(frame->data_length);
        if (!frame->data) {
            return -XQC_EMALLOC;
        }
        memcpy(frame->data, p, frame->data_length);
    }
    p += frame->data_length;

    packet_in->pos = (unsigned char *)p;
    packet_in->pi_frame_types |= XQC_FRAME_BIT_STREAM;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_STREAM, frame);
    return XQC_OK;
}


/*
 *
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Offset (i)                         ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Length (i)                         ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Crypto Data (*)                      ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                      Figure 19: CRYPTO Frame Format
 */
ssize_t
xqc_gen_crypto_frame(xqc_packet_out_t *packet_out, size_t offset,
    const unsigned char *payload, size_t payload_size, size_t *written_size)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    size_t dst_buf_len = packet_out->po_buf_size - packet_out->po_used_size;

    unsigned char offset_bits, length_bits;
    unsigned offset_vlen, length_vlen;
    unsigned char *begin = dst_buf;

    *dst_buf++ = 0x06;

    offset_bits = xqc_vint_get_2bit(offset);
    offset_vlen = xqc_vint_len(offset_bits);

    length_bits = xqc_vint_get_2bit(payload_size);
    length_vlen = xqc_vint_len(length_bits);

    if (1 + offset_vlen + length_vlen + 1 > dst_buf_len) {
        return -XQC_ENOBUF;
    }

    xqc_vint_write(dst_buf, offset, offset_bits, offset_vlen);
    dst_buf += offset_vlen;

    *written_size = payload_size;
    if (1 + offset_vlen + length_vlen + payload_size > dst_buf_len) {
        *written_size = dst_buf_len - (1 + offset_vlen + length_vlen);
    }

    xqc_vint_write(dst_buf, *written_size, length_bits, length_vlen);
    dst_buf += length_vlen;

    memcpy(dst_buf, payload, *written_size);
    dst_buf += *written_size;

    packet_out->po_frame_types |= XQC_FRAME_BIT_CRYPTO;
    return dst_buf - begin;
}

xqc_int_t
xqc_parse_crypto_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn,
    xqc_stream_frame_t *frame)
{
    int      vlen;
    uint64_t offset;
    uint64_t length;
    const unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;

    const unsigned char first_byte = *p++;

    vlen = xqc_vint_read(p, end, &offset);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    frame->data_offset = offset;
    p += vlen;

    vlen = xqc_vint_read(p, end, &length);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    frame->data_length = length;
    p += vlen;

    if (frame->data_length > 0) {
        frame->data = xqc_malloc(frame->data_length);
        if (!frame->data) {
            return -XQC_EMALLOC;
        }
        memcpy(frame->data, p, frame->data_length);
    }

    p += length;

    packet_in->pos = (unsigned char *)p;
    packet_in->pi_frame_types |= XQC_FRAME_BIT_CRYPTO;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_CRYPTO, offset, length);
    return XQC_OK;
}

void
xqc_gen_padding_frame(xqc_packet_out_t *packet_out)
{
    if (packet_out->po_used_size < XQC_PACKET_INITIAL_MIN_LENGTH) {
        memset(packet_out->po_buf + packet_out->po_used_size, 0, XQC_PACKET_INITIAL_MIN_LENGTH - packet_out->po_used_size);
        packet_out->po_used_size = XQC_PACKET_INITIAL_MIN_LENGTH;
        packet_out->po_frame_types |= XQC_FRAME_BIT_PADDING;
    }
}

xqc_int_t
xqc_parse_padding_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn)
{
    packet_in->pi_frame_types |= XQC_FRAME_BIT_PADDING;
    packet_in->pos++;   /* skip frame type 0x00 */
    uint32_t length = 1;

    /* skip all padding bytes(0x00) */
    while (packet_in->pos < packet_in->last && *packet_in->pos == 0x00) {
        packet_in->pos++;
        length++;
    }

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_PADDING, length);
    return XQC_OK;
}

ssize_t
xqc_gen_ping_frame(xqc_packet_out_t *packet_out)
{
    /* Client send ping, server respond ack */
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;
    unsigned need = 1;
    if (need > packet_out->po_buf_size - packet_out->po_used_size) {
        return -XQC_ENOBUF;
    }
    *dst_buf++ = 0x01;
    packet_out->po_frame_types |= XQC_FRAME_BIT_PING;

    return dst_buf - begin;
}

xqc_int_t
xqc_parse_ping_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn)
{
    ++packet_in->pos;
    packet_in->pi_frame_types |= XQC_FRAME_BIT_PING;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_PING);
    return XQC_OK;
}


/*
 *
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Largest Acknowledged (i)                ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          ACK Delay (i)                      ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       ACK Range Count (i)                   ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       First ACK Range (i)                   ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          ACK Ranges (*)                     ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          [ECN Counts]                       ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                        Figure 17: ACK Frame Format

    FOR EXAMPLE:
    110 109 108 107 106 105 104 103 102 101 100   //pkt num
    1   1   1   0   1   1   0   0   1   1   1     //1 means received

    Largest Acknowledged 110
    ACK Range Count 2
    First ACK Range 2
    Gap 0 Ack Range 1
    Gap 1 Ack Range 2
 */
ssize_t
xqc_gen_ack_frame(xqc_connection_t *conn, xqc_packet_out_t *packet_out,
    xqc_usec_t now, int ack_delay_exponent, xqc_recv_record_t *recv_record,
    int *has_gap, xqc_packet_number_t *largest_ack)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    size_t dst_buf_len = packet_out->po_buf_size - packet_out->po_used_size + XQC_ACK_SPACE;

    xqc_packet_number_t lagest_recv, prev_low;
    xqc_usec_t ack_delay;

    const unsigned char *begin = dst_buf;
    const unsigned char *end = dst_buf + dst_buf_len;
    unsigned char *p_range_count;
    unsigned range_count = 0, first_ack_range, gap, acks, gap_bits, acks_bits, need;

    xqc_list_head_t *pos, *next;
    xqc_pktno_range_node_t *range_node;

    xqc_pktno_range_node_t *first_range = NULL;
    xqc_list_for_each_safe(pos, next, &recv_record->list_head) {
        first_range = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        break;
    }

    if (first_range == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|recv_record empty|");
        return -XQC_ENULLPTR;
    }

    ack_delay = (now - recv_record->largest_pkt_recv_time);
    lagest_recv = first_range->pktno_range.high;
    first_ack_range = lagest_recv - first_range->pktno_range.low;
    prev_low = first_range->pktno_range.low;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|lagest_recv:%ui|ack_delay:%ui|first_ack_range:%ud|largest_pkt_recv_time:%ui|",
            lagest_recv, ack_delay, first_ack_range, recv_record->largest_pkt_recv_time);

    ack_delay = ack_delay >> ack_delay_exponent;

    unsigned lagest_recv_bits = xqc_vint_get_2bit(lagest_recv);
    unsigned ack_delay_bits = xqc_vint_get_2bit(ack_delay);
    unsigned first_ack_range_bits = xqc_vint_get_2bit(first_ack_range);

    need = 1    /* type */
            + xqc_vint_len(lagest_recv_bits)
            + xqc_vint_len(ack_delay_bits)
            + 1 /* range_count */
            + xqc_vint_len(first_ack_range_bits);

    if (dst_buf + need > end) {
        return -XQC_ENOBUF;
    }

    *dst_buf++ = 0x02;

    xqc_vint_write(dst_buf, lagest_recv, lagest_recv_bits, xqc_vint_len(lagest_recv_bits));
    dst_buf += xqc_vint_len(lagest_recv_bits);

    *largest_ack = lagest_recv;

    xqc_vint_write(dst_buf, ack_delay, ack_delay_bits, xqc_vint_len(ack_delay_bits));
    dst_buf += xqc_vint_len(ack_delay_bits);

    p_range_count = dst_buf;
    dst_buf += 1;   /* max range_count 63, 1 byte */

    xqc_vint_write(dst_buf, first_ack_range, first_ack_range_bits, xqc_vint_len(first_ack_range_bits));
    dst_buf += xqc_vint_len(first_ack_range_bits);

    int is_first = 1;
    xqc_list_for_each_safe(pos, next, &recv_record->list_head) {    /* from second node */
        range_node = xqc_list_entry(pos, xqc_pktno_range_node_t, list);

        xqc_log(conn->log, XQC_LOG_DEBUG, "|high:%ui|low:%ui|pkt_pns:%d|",
                range_node->pktno_range.high, range_node->pktno_range.low, packet_out->po_pkt.pkt_pns);
        if (is_first) {
            is_first = 0;
            continue;
        }

        gap = prev_low - range_node->pktno_range.high - 2;
        acks = range_node->pktno_range.high - range_node->pktno_range.low;

        gap_bits = xqc_vint_get_2bit(gap);
        acks_bits = xqc_vint_get_2bit(acks);

        need = xqc_vint_len(gap_bits) + xqc_vint_len(acks_bits);
        if (dst_buf + need > end) {
            return -XQC_ENOBUF;
        }

        xqc_vint_write(dst_buf, gap, gap_bits, xqc_vint_len(gap_bits));
        dst_buf += xqc_vint_len(gap_bits);

        xqc_vint_write(dst_buf, acks, acks_bits, xqc_vint_len(acks_bits));
        dst_buf += xqc_vint_len(acks_bits);

        prev_low = range_node->pktno_range.low;

        ++range_count;
        if (range_count >= XQC_MAX_ACK_RANGE_CNT - 1) {
            break;
        }
    }

    if (range_count > 0) {
        *has_gap = 1;

    } else {
        *has_gap = 0;
    }
    xqc_vint_write(p_range_count, range_count, 0, 1);

    packet_out->po_frame_types |= XQC_FRAME_BIT_ACK;
    return dst_buf - begin;
}

/**
 * parse ack frame to ack_info
 */
xqc_int_t
xqc_parse_ack_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn, xqc_ack_info_t *ack_info)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    const unsigned char first_byte = *p++;

    int vlen;
    uint64_t largest_acked;
    uint64_t ack_range_count;   /* the actual range cnt */
    uint64_t first_ack_range;
    uint64_t range, gap;

    unsigned n_ranges = 0;      /* the range cnt stored */

    ack_info->pns = packet_in->pi_pkt.pkt_pns;

    vlen = xqc_vint_read(p, end, &largest_acked);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    vlen = xqc_vint_read(p, end, &ack_info->ack_delay);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    ack_info->ack_delay = ack_info->ack_delay << conn->remote_settings.ack_delay_exponent;

    vlen = xqc_vint_read(p, end, &ack_range_count);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    vlen = xqc_vint_read(p, end, &first_ack_range);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    ack_info->ranges[n_ranges].high = largest_acked;
    ack_info->ranges[n_ranges].low = largest_acked - first_ack_range;
    n_ranges++;

    for (int i = 0; i < ack_range_count; ++i) {
        vlen = xqc_vint_read(p, end, &gap);
        if (vlen < 0) {
            return -XQC_EVINTREAD;
        }
        p += vlen;

        vlen = xqc_vint_read(p, end, &range);
        if (vlen < 0) {
            return -XQC_EVINTREAD;
        }
        p += vlen;

        if (n_ranges < XQC_MAX_ACK_RANGE_CNT) {
            ack_info->ranges[n_ranges].high = ack_info->ranges[n_ranges - 1].low - gap - 2;
            ack_info->ranges[n_ranges].low = ack_info->ranges[n_ranges].high - range;
            n_ranges++;
        }
    }

    /* 
     * if the actual ack_range_count plus first ack_range is larger than
     * the XQC_MAX_ACK_RANGE_CNT, ack_info don't have enough space to store
     *  all the ack_ranges
     */
    if (ack_range_count + 1 > XQC_MAX_ACK_RANGE_CNT) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|ACK range exceed XQC_MAX_ACK_RANGE_CNT|");
    }

    ack_info->n_ranges = n_ranges;
    packet_in->pos = p;
    packet_in->pi_frame_types |= XQC_FRAME_BIT_ACK;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_ACK, ack_info);
    return XQC_OK;
}


/*
 *
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Error Code (i)                      ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       [ Frame Type (i) ]                    ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Reason Phrase Length (i)                 ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Reason Phrase (*)                    ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
ssize_t
xqc_gen_conn_close_frame(xqc_packet_out_t *packet_out, 
    uint64_t err_code, int is_app, int frame_type)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;

    unsigned char *reason = NULL;
    int reason_len = 0;

    unsigned frame_type_bits = xqc_vint_get_2bit(frame_type);
    unsigned reason_len_bits = xqc_vint_get_2bit(reason_len);
    unsigned err_code_len_bits = xqc_vint_get_2bit(err_code);

    unsigned need = 1
                    + xqc_vint_len(err_code_len_bits)
                    + xqc_vint_len(frame_type_bits)
                    + xqc_vint_len(reason_len_bits)
                    + reason_len;
    if (need > packet_out->po_buf_size - packet_out->po_used_size) {
        return -XQC_ENOBUF;
    }

    if (is_app) {
        *dst_buf++ = 0x1d;

    } else {
        *dst_buf++ = 0x1c;
    }

    xqc_vint_write(dst_buf, err_code, err_code_len_bits, xqc_vint_len(err_code_len_bits));
    dst_buf += xqc_vint_len(err_code_len_bits);

    if (!is_app) {
        xqc_vint_write(dst_buf, frame_type, frame_type_bits, xqc_vint_len(frame_type_bits));
        dst_buf += xqc_vint_len(frame_type_bits);
    }

    xqc_vint_write(dst_buf, reason_len, reason_len_bits, xqc_vint_len(reason_len_bits));
    dst_buf += xqc_vint_len(reason_len_bits);

#if 0   /* TODO: reason not supported yet */
    if (reason_len > 0) {
        memcpy(dst_buf, reason, reason_len);
        dst_buf += reason_len;
    }
#endif

    packet_out->po_frame_types |= XQC_FRAME_BIT_CONNECTION_CLOSE;

    return dst_buf - begin;
}


xqc_int_t
xqc_parse_conn_close_frame(xqc_packet_in_t *packet_in, uint64_t *err_code, xqc_connection_t *conn)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    const unsigned char first_byte = *p++;

    int vlen;
    uint64_t reason_len;
    uint64_t frame_type;

    vlen = xqc_vint_read(p, end, err_code);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    if (first_byte == 0x1c) {
        vlen = xqc_vint_read(p, end, &frame_type);
        if (vlen < 0) {
            return -XQC_EVINTREAD;
        }
        p += vlen;
    }

    vlen = xqc_vint_read(p, end, &reason_len);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    /* TODO: get reason string */
    p += reason_len;

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_CONNECTION_CLOSE;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_CONNECTION_CLOSE, *err_code);
    return XQC_OK;
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Stream ID (i)                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  Application Error Code (i)                 ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Final Size (i)                       ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 */
ssize_t
xqc_gen_reset_stream_frame(xqc_packet_out_t *packet_out, xqc_stream_id_t stream_id,
    uint64_t err_code, uint64_t final_size)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;

    unsigned final_size_bits = xqc_vint_get_2bit(final_size);
    unsigned stream_id_bits = xqc_vint_get_2bit(stream_id);
    unsigned err_code_bits = xqc_vint_get_2bit(err_code);

    unsigned need = 1
                    + xqc_vint_len(stream_id_bits)
                    + xqc_vint_len(err_code_bits)
                    + xqc_vint_len(final_size_bits)
                    ;
    if (need > packet_out->po_buf_size - packet_out->po_used_size) {
        return -XQC_ENOBUF;
    }

    *dst_buf++ = 0x04;

    xqc_vint_write(dst_buf, stream_id, stream_id_bits, xqc_vint_len(stream_id_bits));
    dst_buf += xqc_vint_len(stream_id_bits);

    xqc_vint_write(dst_buf, err_code, err_code_bits, xqc_vint_len(err_code_bits));
    dst_buf += xqc_vint_len(err_code_bits);

    xqc_vint_write(dst_buf, final_size, final_size_bits, xqc_vint_len(final_size_bits));
    dst_buf += xqc_vint_len(final_size_bits);

    packet_out->po_frame_types |= XQC_FRAME_BIT_RESET_STREAM;

    return dst_buf - begin;
}


xqc_int_t
xqc_parse_reset_stream_frame(xqc_packet_in_t *packet_in, xqc_stream_id_t *stream_id,
    uint64_t *err_code, uint64_t *final_size, xqc_connection_t *conn)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    const unsigned char first_byte = *p++;

    int vlen;

    vlen = xqc_vint_read(p, end, stream_id);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    vlen = xqc_vint_read(p, end, err_code);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    vlen = xqc_vint_read(p, end, final_size);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_RESET_STREAM;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_RESET_STREAM, *stream_id, *err_code, *final_size);
    return XQC_OK;
}

/*
 *
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Stream ID (i)                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  Application Error Code (i)                 ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
ssize_t
xqc_gen_stop_sending_frame(xqc_packet_out_t *packet_out, xqc_stream_id_t stream_id,
    uint64_t err_code)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;

    unsigned stream_id_bits = xqc_vint_get_2bit(stream_id);
    unsigned err_code_bits = xqc_vint_get_2bit(err_code);

    unsigned need = 1
                    + xqc_vint_len(stream_id_bits)
                    + xqc_vint_len(err_code_bits)
                    ;
    if (need > packet_out->po_buf_size - packet_out->po_used_size) {
        return -XQC_ENOBUF;
    }

    *dst_buf++ = 0x05;

    xqc_vint_write(dst_buf, stream_id, stream_id_bits, xqc_vint_len(stream_id_bits));
    dst_buf += xqc_vint_len(stream_id_bits);

    xqc_vint_write(dst_buf, err_code, err_code_bits, xqc_vint_len(err_code_bits));
    dst_buf += xqc_vint_len(err_code_bits);

    packet_out->po_frame_types |= XQC_FRAME_BIT_STOP_SENDING;

    return dst_buf - begin;
}


xqc_int_t
xqc_parse_stop_sending_frame(xqc_packet_in_t *packet_in, xqc_stream_id_t *stream_id,
    uint64_t *err_code, xqc_connection_t *conn)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    const unsigned char first_byte = *p++;

    int vlen;

    vlen = xqc_vint_read(p, end, stream_id);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    vlen = xqc_vint_read(p, end, err_code);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_STOP_SENDING;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_STOP_SENDING, *stream_id, *err_code);
    return XQC_OK;
}

/*
 *     0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Data Limit (i)                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
ssize_t
xqc_gen_data_blocked_frame(xqc_packet_out_t *packet_out, uint64_t data_limit)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;

    *dst_buf++ = 0x14;

    unsigned data_limit_bits = xqc_vint_get_2bit(data_limit);
    xqc_vint_write(dst_buf, data_limit, data_limit_bits, xqc_vint_len(data_limit_bits));
    dst_buf += xqc_vint_len(data_limit_bits);

    packet_out->po_frame_types |= XQC_FRAME_BIT_DATA_BLOCKED;

    return dst_buf - begin;
}

xqc_int_t
xqc_parse_data_blocked_frame(xqc_packet_in_t *packet_in, uint64_t *data_limit, xqc_connection_t *conn)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    const unsigned char first_byte = *p++;

    int vlen;

    vlen = xqc_vint_read(p, end, data_limit);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_DATA_BLOCKED;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_DATA_BLOCKED, *data_limit);
    return XQC_OK;
}


/*
 *     0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Stream ID (i)                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Stream Data Limit (i)                    ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
ssize_t
xqc_gen_stream_data_blocked_frame(xqc_packet_out_t *packet_out, xqc_stream_id_t stream_id, uint64_t stream_data_limit)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;

    *dst_buf++ = 0x15;

    unsigned stream_id_bits = xqc_vint_get_2bit(stream_id);
    unsigned data_limit_bits = xqc_vint_get_2bit(stream_data_limit);

    xqc_vint_write(dst_buf, stream_id, stream_id_bits, xqc_vint_len(stream_id_bits));
    dst_buf += xqc_vint_len(stream_id_bits);

    xqc_vint_write(dst_buf, stream_data_limit, data_limit_bits, xqc_vint_len(data_limit_bits));
    dst_buf += xqc_vint_len(data_limit_bits);

    packet_out->po_frame_types |= XQC_FRAME_BIT_STREAM_DATA_BLOCKED;

    return dst_buf - begin;
}


xqc_int_t
xqc_parse_stream_data_blocked_frame(xqc_packet_in_t *packet_in, xqc_stream_id_t *stream_id, uint64_t *stream_data_limit, xqc_connection_t *conn)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    const unsigned char first_byte = *p++;

    int vlen;

    vlen = xqc_vint_read(p, end, stream_id);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    vlen = xqc_vint_read(p, end, stream_data_limit);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_STREAM_DATA_BLOCKED;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_STREAM_DATA_BLOCKED, *stream_id, *stream_data_limit);
    return XQC_OK;
}

/*
 *  0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Stream Limit (i)                     ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
ssize_t
xqc_gen_streams_blocked_frame(xqc_packet_out_t *packet_out, uint64_t stream_limit, int bidirectional)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;

    if (bidirectional) {
        *dst_buf++ = 0x16;

    } else {
        *dst_buf++ = 0x17;
    }

    unsigned stream_limit_bits = xqc_vint_get_2bit(stream_limit);
    xqc_vint_write(dst_buf, stream_limit, stream_limit_bits, xqc_vint_len(stream_limit_bits));
    dst_buf += xqc_vint_len(stream_limit_bits);

    packet_out->po_frame_types |= XQC_FRAME_BIT_STREAMS_BLOCKED;

    return dst_buf - begin;
}


xqc_int_t
xqc_parse_streams_blocked_frame(xqc_packet_in_t *packet_in, uint64_t *stream_limit, int *bidirectional, xqc_connection_t *conn)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    const unsigned char first_byte = *p++;

    int vlen;

    if (first_byte == 0x16) {
        *bidirectional = 1;

    } else {
        *bidirectional = 0;
    }

    vlen = xqc_vint_read(p, end, stream_limit);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_STREAMS_BLOCKED;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_STREAMS_BLOCKED, *bidirectional, *stream_limit);
    return XQC_OK;
}

/*
 *
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Maximum Data (i)                     ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
ssize_t
xqc_gen_max_data_frame(xqc_packet_out_t *packet_out, uint64_t max_data)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;

    *dst_buf++ = 0x10;

    unsigned max_data_bits = xqc_vint_get_2bit(max_data);
    xqc_vint_write(dst_buf, max_data, max_data_bits, xqc_vint_len(max_data_bits));
    dst_buf += xqc_vint_len(max_data_bits);

    packet_out->po_frame_types |= XQC_FRAME_BIT_MAX_DATA;

    return dst_buf - begin;
}


xqc_int_t
xqc_parse_max_data_frame(xqc_packet_in_t *packet_in, uint64_t *max_data, xqc_connection_t *conn)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    const unsigned char first_byte = *p++;

    int vlen;

    vlen = xqc_vint_read(p, end, max_data);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_MAX_DATA;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_MAX_DATA, *max_data);
    return XQC_OK;
}

/*
 *     0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Stream ID (i)                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Maximum Stream Data (i)                  ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
ssize_t
xqc_gen_max_stream_data_frame(xqc_packet_out_t *packet_out, xqc_stream_id_t stream_id, uint64_t max_stream_data)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;

    *dst_buf++ = 0x11;

    unsigned stream_id_bits = xqc_vint_get_2bit(stream_id);
    unsigned max_stream_data_bits = xqc_vint_get_2bit(max_stream_data);

    xqc_vint_write(dst_buf, stream_id, stream_id_bits, xqc_vint_len(stream_id_bits));
    dst_buf += xqc_vint_len(stream_id_bits);

    xqc_vint_write(dst_buf, max_stream_data, max_stream_data_bits, xqc_vint_len(max_stream_data_bits));
    dst_buf += xqc_vint_len(max_stream_data_bits);

    packet_out->po_frame_types |= XQC_FRAME_BIT_MAX_STREAM_DATA;

    return dst_buf - begin;
}


xqc_int_t
xqc_parse_max_stream_data_frame(xqc_packet_in_t *packet_in, xqc_stream_id_t *stream_id, uint64_t *max_stream_data, xqc_connection_t *conn)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    const unsigned char first_byte = *p++;

    int vlen;

    vlen = xqc_vint_read(p, end, stream_id);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    vlen = xqc_vint_read(p, end, max_stream_data);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_MAX_STREAM_DATA;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_MAX_STREAM_DATA, *stream_id, *max_stream_data);
    return XQC_OK;
}

/*
 *
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Maximum Streams (i)                     ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
ssize_t
xqc_gen_max_streams_frame(xqc_packet_out_t *packet_out, uint64_t max_streams, int bidirectional)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;

    if (bidirectional) {
        *dst_buf++ = 0x12;

    } else {
        *dst_buf++ = 0x13;
    }

    unsigned max_streams_bits = xqc_vint_get_2bit(max_streams);
    xqc_vint_write(dst_buf, max_streams, max_streams_bits, xqc_vint_len(max_streams_bits));
    dst_buf += xqc_vint_len(max_streams_bits);

    packet_out->po_frame_types |= XQC_FRAME_BIT_MAX_STREAMS;

    return dst_buf - begin;
}


xqc_int_t
xqc_parse_max_streams_frame(xqc_packet_in_t *packet_in, uint64_t *max_streams, int *bidirectional, xqc_connection_t *conn)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    const unsigned char first_byte = *p++;

    int vlen;

    if (first_byte == 0x12) {
        *bidirectional = 1;

    } else {
        *bidirectional = 0;
    }

    vlen = xqc_vint_read(p, end, max_streams);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_MAX_STREAMS;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_MAX_STREAM_DATA, *bidirectional, *max_streams);
    return XQC_OK;
}

/*
 *     0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Token Length (i)  ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            Token (*)                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
ssize_t
xqc_gen_new_token_frame(xqc_packet_out_t *packet_out, const unsigned char *token, unsigned token_len)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;

    *dst_buf++ = 0x07;

    unsigned token_len_bits = xqc_vint_get_2bit(token_len);
    xqc_vint_write(dst_buf, token_len, token_len_bits, xqc_vint_len(token_len_bits));
    dst_buf += xqc_vint_len(token_len_bits);

    if (packet_out->po_used_size
        + 1
        + xqc_vint_len(token_len_bits)
        + token_len
        > packet_out->po_buf_size)
    {
        return -XQC_ENOBUF;
    }
    xqc_memcpy(dst_buf, token, token_len);
    dst_buf += token_len;

    packet_out->po_frame_types |= XQC_FRAME_BIT_NEW_TOKEN;

    return dst_buf - begin;
}


xqc_int_t
xqc_parse_new_token_frame(xqc_packet_in_t *packet_in, unsigned char *token, unsigned *token_len, xqc_connection_t *conn)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    const unsigned char first_byte = *p++;

    int vlen;
    uint64_t recv_token_len;

    vlen = xqc_vint_read(p, end, &recv_token_len);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    if (recv_token_len == 0) {
        return -XQC_EPROTO;
    }
    p += vlen;

    if (recv_token_len > *token_len) {
        return -XQC_ENOBUF;
    }
    if (p + recv_token_len > end) {
        return -XQC_EILLEGAL_FRAME;
    }
    xqc_memcpy(token, p, recv_token_len);
    *token_len = recv_token_len;
    p += recv_token_len;

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_NEW_TOKEN;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_NEW_TOKEN, recv_token_len, token);
    return XQC_OK;
}


ssize_t
xqc_gen_handshake_done_frame(xqc_packet_out_t *packet_out)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;
    unsigned need = 1; /* only need 1 byte */
    
    if (need > packet_out->po_buf_size - packet_out->po_used_size) {
        return -XQC_ENOBUF;
    }
    *dst_buf++ = 0x1e;
    
    packet_out->po_frame_types |= XQC_FRAME_BIT_HANDSHAKE_DONE;

    return dst_buf - begin;
}


xqc_int_t
xqc_parse_handshake_done_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn)
{
    ++packet_in->pos;
    packet_in->pi_frame_types |= XQC_FRAME_BIT_HANDSHAKE_DONE;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_HANDSHAKE_DONE);
    return XQC_OK;
}

/*
 * https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-19.15
 *
 * NEW_CONNECTION_ID Frame {
 *    Type (i) = 0x18,
 *    Sequence Number (i),
 *    Retire Prior To (i),
 *    Length (8),
 *    Connection ID (8..160),
 *    Stateless Reset Token (128),
 * }
 *
 *               Figure 39: NEW_CONNECTION_ID Frame Format
 * */
ssize_t
xqc_gen_new_conn_id_frame(xqc_packet_out_t *packet_out, xqc_cid_t *new_cid, uint64_t retire_prior_to, char *key, size_t keylen)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;

    *dst_buf++ = 0x18;

    unsigned char stateless_reset_token[XQC_STATELESS_RESET_TOKENLEN] = {0};

    unsigned sequence_number_bits = xqc_vint_get_2bit(new_cid->cid_seq_num);
    unsigned retire_prior_to_bits = xqc_vint_get_2bit(retire_prior_to);
    uint64_t cid_len = new_cid->cid_len;
    uint8_t cid_len_bits = xqc_vint_get_2bit(cid_len);

    /* make sure cid_len won't exceed XQC_MAX_CID_LEN */
    if (cid_len > XQC_MAX_CID_LEN) {
        return -XQC_EPARAM;
    }

    xqc_vint_write(dst_buf, new_cid->cid_seq_num, 
                   sequence_number_bits, xqc_vint_len(sequence_number_bits));
    dst_buf += xqc_vint_len(sequence_number_bits);

    xqc_vint_write(dst_buf, retire_prior_to, retire_prior_to_bits, xqc_vint_len(retire_prior_to_bits));
    dst_buf += xqc_vint_len(retire_prior_to_bits);

    xqc_vint_write(dst_buf, cid_len, cid_len_bits, xqc_vint_len(cid_len_bits));
    dst_buf += xqc_vint_len(cid_len_bits);

    xqc_memcpy(dst_buf, new_cid->cid_buf, new_cid->cid_len);
    dst_buf += new_cid->cid_len;

    xqc_gen_reset_token(new_cid, stateless_reset_token, XQC_STATELESS_RESET_TOKENLEN, key, keylen);
    xqc_memcpy(dst_buf, stateless_reset_token, XQC_STATELESS_RESET_TOKENLEN);
    dst_buf += XQC_STATELESS_RESET_TOKENLEN;

    packet_out->po_frame_types |= XQC_FRAME_BIT_NEW_CONNECTION_ID;

    return dst_buf - begin;
}

/*
 * https://datatracker.ietf.org/doc/html/rfc9000#section-19.15
 *
 * NEW_CONNECTION_ID Frame {
 *    Type (i) = 0x18,
 *    Sequence Number (i),
 *    Retire Prior To (i),
 *    Length (8),
 *    Connection ID (8..160),
 *    Stateless Reset Token (128),
 * }
 *
 *               Figure 39: NEW_CONNECTION_ID Frame Format
 * */
xqc_int_t
xqc_parse_new_conn_id_frame(xqc_packet_in_t *packet_in, xqc_cid_t *new_cid, uint64_t *retire_prior_to, xqc_connection_t *conn)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    const unsigned char first_byte = *p++;

    int vlen;
    unsigned char stateless_reset_token[XQC_STATELESS_RESET_TOKENLEN];

    /* Sequence Number (i) */
    vlen = xqc_vint_read(p, end, &new_cid->cid_seq_num);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    /* Retire Prior To (i) */
    vlen = xqc_vint_read(p, end, retire_prior_to);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    /* Length (8) */
    if (p >= end) {
        return -XQC_EPROTO;
    }
    new_cid->cid_len = *p++;
    if (new_cid->cid_len > XQC_MAX_CID_LEN) {
        return -XQC_EPROTO;
    }

    /* Connection ID (8..160) */
    if (p + new_cid->cid_len > end) {
        return -XQC_EPROTO;
    }
    xqc_memcpy(new_cid->cid_buf, p, new_cid->cid_len);
    p += new_cid->cid_len;

    /* Stateless Reset Token (128) */
    if (p + XQC_STATELESS_RESET_TOKENLEN > end) {
        return -XQC_EPROTO;
    }
    xqc_memcpy(stateless_reset_token, p, XQC_STATELESS_RESET_TOKENLEN);
    p += XQC_STATELESS_RESET_TOKENLEN;

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_NEW_CONNECTION_ID;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_NEW_CONNECTION_ID, new_cid, retire_prior_to);
    return XQC_OK;
}


/*
 * https://datatracker.ietf.org/doc/html/rfc9000#section-19.16
 *
 * RETIRE_CONNECTION_ID Frame {
 *    Type (i) = 0x19,
 *    Sequence Number (i),
 * }
 *
 *               Figure 40: RETIRE_CONNECTION_ID Frame Format
 * */
ssize_t
xqc_gen_retire_conn_id_frame(xqc_packet_out_t *packet_out, uint64_t seq_num)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;

    *dst_buf++ = 0x19;

    unsigned sequence_number_bits = xqc_vint_get_2bit(seq_num);

    xqc_vint_write(dst_buf, seq_num, sequence_number_bits, xqc_vint_len(sequence_number_bits));
    dst_buf += xqc_vint_len(sequence_number_bits);

    packet_out->po_frame_types |= XQC_FRAME_BIT_RETIRE_CONNECTION_ID;

    return dst_buf - begin;
}


xqc_int_t
xqc_parse_retire_conn_id_frame(xqc_packet_in_t *packet_in, uint64_t *seq_num)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    const unsigned char first_byte = *p++;

    int vlen;

    vlen = xqc_vint_read(p, end, seq_num);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_RETIRE_CONNECTION_ID;

    return XQC_OK;
}

