/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <string.h>
#include <sys/types.h>
#include "src/transport/xqc_frame_parser.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/common/xqc_log.h"
#include "src/common/xqc_log_event_callback.h"
#include "src/common/xqc_str.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_reinjection.h"
#include "src/transport/xqc_fec_scheme.h"

/**
 * generate datagram frame
 */
xqc_int_t
xqc_gen_datagram_frame(xqc_packet_out_t *packet_out, 
    const unsigned char *payload, size_t size)
{
    if (packet_out == NULL) {
        return -XQC_EPARAM;
    }

    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    size_t dst_buf_len = xqc_get_po_remained_size(packet_out);
    unsigned char *p = dst_buf + 1;

    if ((size + 1 + XQC_DATAGRAM_LENGTH_FIELD_BYTES) > dst_buf_len) {
        return -XQC_ENOBUF;
    }

    xqc_vint_write(p, size, XQC_DATAGRAM_LENGTH_FIELD_BYTES - 1, XQC_DATAGRAM_LENGTH_FIELD_BYTES);
    p += XQC_DATAGRAM_LENGTH_FIELD_BYTES;

    if (size > 0) {
        xqc_memcpy(p, payload, size);
    }

    p += size;
    
    dst_buf[0] = 0x31;

    packet_out->po_frame_types |= XQC_FRAME_BIT_DATAGRAM;
    packet_out->po_used_size += p - dst_buf;

    return XQC_OK;
}

xqc_int_t xqc_parse_datagram_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn,
    unsigned char **buffer, size_t *size)
{
    uint64_t length;
    int vlen = 0;
    const unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    /* skip frame type */
    const unsigned char first_byte = *p++;
    xqc_bool_t has_length = (first_byte & 0x1);

    if (has_length) {
        /*currently, the length of length field is 2 bytes*/
        vlen = xqc_vint_read(p, end, &length);
        if (vlen < 0) {
            return -XQC_EVINTREAD;
        }

        p += vlen;
        
        if (length > (end - p)) {
            return -XQC_EILLEGAL_FRAME;
        }
        
    } else {
        length = end - p;
    }

    /* recv a DATAGRAM frame larger than max_datagram_frame_size */
    if ((length + 1 + vlen) > conn->local_settings.max_datagram_frame_size) {
        return -XQC_EPROTO;
    }

    *size = length;
    *buffer = (unsigned char *)p;
    
    p += length;

    packet_in->pos = (unsigned char *)p;
    packet_in->pi_frame_types |= XQC_FRAME_BIT_DATAGRAM;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_DATAGRAM, length);

    return XQC_OK;
}




ssize_t
xqc_gen_stream_frame(xqc_packet_out_t *packet_out,
    xqc_stream_id_t stream_id, uint64_t offset, uint8_t fin,
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
    size_t dst_buf_len = xqc_get_po_remained_size(packet_out);

    *written_size = 0;
    /*  variable length integer's most significant 2 bits */
    unsigned stream_id_bits, offset_bits, length_bits;
    /* variable length integer's size(byte) */
    unsigned stream_id_len, offset_len, length_len;
    /* 0b00001XXX point to second byte */
    unsigned char *p = dst_buf + 1;
    /* fin_only means there is no stream data */
    uint8_t fin_only = (fin && !size);

    unsigned int idx = packet_out->po_stream_frames_idx;
    unsigned int prev_idx = idx - 1;
    if (idx >= XQC_MAX_STREAM_FRAME_IN_PO) {
        return -XQC_ELIMIT;
    }

    /* Try to combine with previous stream frame */
    if (idx > 0 && packet_out->po_frame_types == XQC_FRAME_BIT_STREAM /* No other frames */
        && packet_out->po_stream_frames[prev_idx].ps_stream_id == stream_id
        && packet_out->po_stream_frames[prev_idx].ps_offset + packet_out->po_stream_frames[prev_idx].ps_length == offset
        && packet_out->po_stream_frames[prev_idx].ps_length_offset > 0 /* Length field is present */)
    {
        unsigned char *p_type = packet_out->po_buf + packet_out->po_stream_frames[prev_idx].ps_type_offset;
        unsigned char *p_length = packet_out->po_buf + packet_out->po_stream_frames[prev_idx].ps_length_offset;
        size_t append_size = 0;

        /* Length is 2 Bytes */
        if ((*p_length & 0xC0) != 0x40) {
            goto new_frame;
        }

        if (!fin_only) {
            append_size = xqc_min(size, dst_buf_len);
            memcpy(dst_buf, payload, append_size);
            xqc_vint_write(p_length, packet_out->po_stream_frames[prev_idx].ps_length + append_size, 1, 2);
            packet_out->po_stream_frames[prev_idx].ps_length += append_size;
            if (append_size != size) {
                fin = 0;
            }
        }

        if (fin) {
            *p_type |= 0x01;
            packet_out->po_stream_frames[prev_idx].ps_has_fin = fin;
        }

        *written_size = append_size;
        return append_size;
    }

new_frame:
    stream_id_bits = xqc_vint_get_2bit(stream_id);
    stream_id_len = xqc_vint_len(stream_id_bits);
    if (offset) {
        offset_bits = xqc_vint_get_2bit(offset);
        offset_len = xqc_vint_len(offset_bits);

    } else {
        offset_len = 0;
    }

    if (!fin_only) {
        ssize_t n_avail;

        n_avail = dst_buf_len - (p + stream_id_len + offset_len - dst_buf);

        /* 
         * If we cannot fill remaining buffer, we need to include data
         * length.
         */
        if (size <= n_avail) {
            /* length_len set to 2 bytes, easy to combine with other stream frame */
            length_bits = 1;
            length_len = 2;
            n_avail -= length_len;
            if (size > n_avail) {
                size = n_avail;
                fin = 0;
            }

        } else {
            /* reserve ACK, must have length. */
            size = n_avail;
            length_bits = 1;
            length_len = 2;
            size -= length_len;
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
            packet_out->po_stream_frames[idx].ps_length_offset = (unsigned int)(p - packet_out->po_buf);
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

    packet_out->po_stream_frames[idx].ps_type_offset = (unsigned int)(dst_buf - packet_out->po_buf);
    packet_out->po_stream_frames[idx].ps_offset = offset;
    packet_out->po_stream_frames[idx].ps_length = (unsigned int)size;
    packet_out->po_stream_frames[idx].ps_is_used = 1;
    packet_out->po_stream_frames[idx].ps_stream_id = stream_id;
    packet_out->po_stream_frames[idx].ps_has_fin = fin;
    packet_out->po_stream_frames_idx++;

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

        p += vlen;
        if (length > end - p) {
            return -XQC_EILLEGAL_FRAME;
        }
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
xqc_gen_crypto_frame(xqc_packet_out_t *packet_out, uint64_t offset,
    const unsigned char *payload, uint64_t payload_size, size_t *written_size)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    size_t dst_buf_len = xqc_get_po_remained_size(packet_out);

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
    if (p + length > end) {
        return -XQC_EILLEGAL_FRAME;;
    }
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
xqc_gen_padding_frame(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    size_t total_len = XQC_PACKET_INITIAL_MIN_LENGTH;

    if (conn->conn_settings.enable_pmtud) {
        if ((packet_out->po_frame_types & (XQC_FRAME_BIT_PATH_CHALLENGE | XQC_FRAME_BIT_PATH_RESPONSE))
            || (packet_out->po_flag & XQC_POF_PMTUD_PROBING)) 
        {
            total_len = packet_out->po_buf_size + XQC_ACK_SPACE;
        }
    }

    if (packet_out->po_used_size < total_len) {
        packet_out->po_padding = packet_out->po_buf + packet_out->po_used_size;
        memset(packet_out->po_padding, 0, total_len - packet_out->po_used_size);
        packet_out->po_used_size = total_len;
        packet_out->po_frame_types |= XQC_FRAME_BIT_PADDING;
    }
}

xqc_int_t
xqc_gen_padding_frame_with_len(xqc_connection_t *conn, xqc_packet_out_t *packet_out,
    size_t padding_len, size_t limit)
{
    unsigned char *p;

    /* fec模式padding长度 */
    if (packet_out->po_used_size + padding_len > limit) {
        xqc_log(conn->log, XQC_LOG_WARN, "|packet_out too large|");
        return -XQC_EFEC_SYMBOL_ERROR;
    }

    if (packet_out->po_used_size < limit) {
        packet_out->po_padding = packet_out->po_buf + packet_out->po_used_size;
        memset(packet_out->po_padding, 0, padding_len);
        packet_out->po_used_size += padding_len;
        packet_out->po_frame_types |= XQC_FRAME_BIT_PADDING;
    }
    return XQC_OK;
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
    if (need > xqc_get_po_remained_size(packet_out)) {
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

#ifdef XQC_ENABLE_FEC
ssize_t
xqc_gen_sid_frame(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{   
    size_t                   dst_buf_len = XQC_FEC_SPACE;
    uint64_t                 flow_id = 0, src_payload_id = 0, frame_type = 0xfec5;
    unsigned                 need, frame_type_bits, flow_id_bits, src_payload_id_bits;
    xqc_int_t                ret = 0;
    unsigned char           *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char     *begin = dst_buf, *end = dst_buf + dst_buf_len;

    if (packet_out->po_used_size > XQC_QUIC_MAX_MSS) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|packet_out too large|");
        return -XQC_ENOBUF;
    }

    /* gen src_payload_id and save src symbol */
    ret = xqc_gen_src_payload_id(conn->fec_ctl, &src_payload_id);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|generate source payload id error.");
        return -XQC_EFEC_SYMBOL_ERROR;
    }
    frame_type_bits = xqc_vint_get_2bit(frame_type);
    flow_id_bits = xqc_vint_get_2bit(flow_id);
    src_payload_id_bits = xqc_vint_get_2bit(src_payload_id);

    need = xqc_vint_len(frame_type_bits)           /* type: 0xfec5 */
           + xqc_vint_len(flow_id_bits)
           + xqc_vint_len(src_payload_id_bits);    /* Explicit Source Payload ID */

    // xqc_log(conn->log, XQC_LOG_DEBUG, "|src_payload_id: %d, len: %d, sid_frame_len: %d",
    //         src_payload_id, xqc_vint_len(src_payload_id_bits), need);
    
    if (dst_buf + need > end) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|data length exceed packetout buffer.");
        return -XQC_ENOBUF;
    }

    xqc_vint_write(dst_buf, frame_type, frame_type_bits, xqc_vint_len(frame_type_bits));
    dst_buf += xqc_vint_len(frame_type_bits);

    xqc_vint_write(dst_buf, flow_id, flow_id_bits, xqc_vint_len(flow_id_bits));
    dst_buf += xqc_vint_len(flow_id_bits);

    xqc_vint_write(dst_buf, src_payload_id, src_payload_id_bits, xqc_vint_len(src_payload_id_bits));
    dst_buf += xqc_vint_len(src_payload_id_bits);
    
    packet_out->po_frame_types |= XQC_FRAME_BIT_SID;
    return dst_buf - begin;
}

xqc_int_t
xqc_parse_sid_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    int                     vlen;
    uint64_t                frame_type, flow_id, src_payload_id;
    xqc_int_t               ret, sid_frame_len, symbol_size, symbol_idx, max_src_symbol_num, tmp_block_idx, block_cache_idx, window_size;
    unsigned char          *p = packet_in->pos, *tmp_payload_p;
    const unsigned char    *end = packet_in->last;

    ret = sid_frame_len = symbol_size = symbol_idx = tmp_block_idx = block_cache_idx = 0;
    max_src_symbol_num = conn->remote_settings.fec_max_symbols_num;
    window_size = conn->conn_settings.fec_params.fec_max_window_size;

    vlen = xqc_vint_read(p, end, &frame_type);
    if (vlen < 0 || frame_type != 0xfec5) {
        return -XQC_EVINTREAD;
    }
    p += vlen;
    sid_frame_len += vlen;

    vlen = xqc_vint_read(p, end, &flow_id);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;
    sid_frame_len += vlen;

    vlen = xqc_vint_read(p, end, &src_payload_id);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    if ((packet_in->pi_flag & XQC_PIF_FEC_RECOVERED) != 0) {
        goto end_parse;
    }

    sid_frame_len += vlen;
    tmp_block_idx = (int)src_payload_id / max_src_symbol_num;
    block_cache_idx = tmp_block_idx % window_size;

    if (max_src_symbol_num <= 0
        || max_src_symbol_num > XQC_FEC_MAX_SYMBOL_NUM_PBLOCK)
    {
        xqc_log(conn->log, XQC_LOG_ERROR, "|remote max_src_symbol_num invalid|");
        ret = -XQC_EPARAM;
        goto end_parse;
    }

    symbol_size = packet_in->decode_payload_len - sid_frame_len;
    if (symbol_size != conn->remote_settings.fec_max_symbol_size) {
        /* symbol size is different from the declared one */
        xqc_log(conn->log, XQC_LOG_DEBUG, "|fec symbol size error, src_payload_id: %d, remote declared size: %d, received size: %d, sid_frame_len: %d, packet_num: %d",
                src_payload_id, conn->remote_settings.fec_max_symbol_size, symbol_size, sid_frame_len, packet_in->pi_pkt.pkt_num);
        goto end_parse;
    }

    symbol_idx = src_payload_id % max_src_symbol_num;
    if (xqc_process_valid_symbol(conn, tmp_block_idx, symbol_idx, packet_in->decode_payload, symbol_size) != XQC_OK) {
        goto end_parse;
    }

    if (conn->fec_ctl->fec_recv_symbols_num[block_cache_idx] >= max_src_symbol_num) {
        /* FEC解码操作/flush缓存 */
        ret = xqc_fec_decoder(conn, block_cache_idx);
        xqc_fec_ctl_init_recv_params(conn->fec_ctl, block_cache_idx);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|fec decode error|");
            goto end_parse;
        }
    }

end_parse:
    packet_in->pos = (unsigned char *)p;
    packet_in->pi_frame_types |= XQC_FRAME_BIT_SID;
    return ret;
}

xqc_int_t
xqc_gen_repair_frame(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_int_t fss_esi,
    xqc_int_t repair_idx, xqc_int_t repair_key_size)
{
    if (packet_out == NULL
        || repair_idx < 0
        || repair_idx >= XQC_REPAIR_LEN
        || repair_key_size < 0)
    {
        xqc_log(conn->log, XQC_LOG_WARN, "fec parameter error");
        return -XQC_EPARAM;
    }

    if (conn->conn_settings.fec_params.fec_ele_bit_size <= 0
        || (!conn->fec_ctl->fec_send_repair_key[repair_idx].is_valid && conn->conn_settings.fec_params.fec_encoder_scheme != XQC_XOR_CODE)
        || conn->conn_settings.fec_params.fec_max_symbol_size <= 0
        || !conn->fec_ctl->fec_send_repair_symbols_buff[repair_idx].is_valid)
    {
        xqc_log(conn->log, XQC_LOG_WARN, "No available repair key or repair symbol");
        return -XQC_EFEC_SYMBOL_ERROR;
    }

    size_t               dst_buf_len;
    uint64_t             flow_id, frame_type, repair_payload_id;
    unsigned             need, frame_type_bits, flow_id_bits, fss_esi_bits, repair_key_bits, repair_payload_id_bits;
    xqc_int_t            ret, repair_symbol_size;
    unsigned char       *dst_buf, *repair_symbol_p, *repair_key_p;

    const unsigned char *begin, *end;

    dst_buf_len = xqc_get_po_remained_size_with_ack_spc(packet_out) + XQC_FEC_SPACE;
    dst_buf = packet_out->po_buf + packet_out->po_used_size;
    begin = dst_buf; end = dst_buf + dst_buf_len;

    frame_type = 0xfec6;
    flow_id = conn->fec_ctl->fec_flow_id;
    repair_payload_id = repair_idx;
    repair_symbol_size = conn->local_settings.fec_max_symbol_size;

    frame_type_bits = xqc_vint_get_2bit(frame_type);
    flow_id_bits = xqc_vint_get_2bit(flow_id);
    fss_esi_bits = xqc_vint_get_2bit(fss_esi);
    repair_payload_id_bits = xqc_vint_get_2bit(repair_payload_id);
    repair_key_p = conn->fec_ctl->fec_send_repair_key[repair_idx].payload;
    repair_symbol_p = conn->fec_ctl->fec_send_repair_symbols_buff[repair_idx].payload;

    if (conn->conn_settings.fec_params.fec_encoder_scheme == XQC_XOR_CODE) {
        repair_key_size = 0;
    }

    need = xqc_vint_len(frame_type_bits)
           + xqc_vint_len(flow_id_bits)
           + xqc_vint_len(fss_esi_bits)
           + xqc_vint_len(repair_payload_id_bits)
           + repair_key_size
           + repair_symbol_size;

    if (dst_buf + need > end) {
        return -XQC_ENOBUF;
    }


    xqc_vint_write(dst_buf, frame_type, frame_type_bits, xqc_vint_len(frame_type_bits));
    dst_buf += xqc_vint_len(frame_type_bits);

    xqc_vint_write(dst_buf, flow_id, flow_id_bits, xqc_vint_len(flow_id_bits));
    dst_buf += xqc_vint_len(flow_id_bits);

    xqc_vint_write(dst_buf, fss_esi, fss_esi_bits, xqc_vint_len(fss_esi_bits));
    dst_buf += xqc_vint_len(fss_esi_bits);

    xqc_vint_write(dst_buf, repair_payload_id, repair_payload_id_bits, xqc_vint_len(repair_payload_id_bits));
    dst_buf += xqc_vint_len(repair_payload_id_bits);

    xqc_memcpy(dst_buf, repair_key_p, repair_key_size);
    dst_buf += repair_key_size;

    xqc_memcpy(dst_buf, repair_symbol_p, repair_symbol_size);
    dst_buf += repair_symbol_size;

    
    packet_out->po_frame_types |= XQC_FRAME_BIT_REPAIR_SYMBOL;
    packet_out->po_used_size += dst_buf - begin;
    return XQC_OK;
}

xqc_int_t
xqc_parse_repair_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    int                  vlen = 0;
    uint64_t             frame_type, flow_id, fss_esi, repair_payload_id, repair_payload_len, symbol_idx, symbol_size;
    xqc_int_t            ret, repair_symbol_size, repair_key_size, src_symbol_num, tmp_block_idx, block_cache_idx, window_size;
    unsigned char       *p = packet_in->pos, *end = packet_in->last, *tmp_payload_p, *repair_key_p, *repair_symbol_p;

    frame_type = flow_id = fss_esi = repair_payload_id = symbol_idx = 0;
    ret = tmp_block_idx = 0;
    repair_symbol_size = conn->remote_settings.fec_max_symbol_size;
    symbol_size = repair_payload_len = block_cache_idx = 0;
    src_symbol_num = conn->remote_settings.fec_max_symbols_num;
    window_size = conn->conn_settings.fec_params.fec_max_window_size;
    if (conn->conn_settings.fec_params.fec_decoder_scheme == XQC_XOR_CODE) {
        repair_key_size = 0;
    } else {
        repair_key_size = ((conn->conn_settings.fec_params.fec_ele_bit_size - 1) / 8 + 1) * src_symbol_num;
    }

    vlen = xqc_vint_read(p, end, &frame_type);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;
    repair_payload_len += vlen;

    vlen = xqc_vint_read(p, end, &flow_id);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;
    repair_payload_len += vlen;
    vlen = xqc_vint_read(p, end, &fss_esi);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;
    repair_payload_len += vlen;
    tmp_block_idx = (int)fss_esi / src_symbol_num;
    block_cache_idx = tmp_block_idx % window_size;

    vlen = xqc_vint_read(p, end, &repair_payload_id);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;
    repair_payload_len += vlen;

    repair_key_p = p;
    repair_symbol_p = p + repair_key_size;
    p += repair_key_size + repair_symbol_size;

    if ((packet_in->pi_flag & XQC_PIF_FEC_RECOVERED) != 0) {
        goto end_parse_repair;
    }

    if (conn->fec_ctl->fec_recv_repair_num == XQC_MAX_UINT32_VALUE) {
        xqc_log(conn->log, XQC_LOG_WARN, "|fec recovered packet number exceeds maximum.\n");
        conn->fec_ctl->fec_recv_repair_num = 0;
    }
    conn->fec_ctl->fec_recv_repair_num++;

    if (conn->remote_settings.fec_max_symbol_size <= 0
        || conn->remote_settings.fec_max_symbols_num <= 0)
    {
        xqc_log(conn->log, XQC_LOG_ERROR, "|repair symbol size error or repair symbol len error|fec_max_symbol_size:%d|fec_max_symbols_num:%d|",
            conn->remote_settings.fec_max_symbol_size, conn->remote_settings.fec_max_symbols_num);
        ret = -XQC_EFEC_SYMBOL_ERROR;
        goto end_parse_repair;
    }
    
    symbol_size = packet_in->decode_payload_len - repair_payload_len - repair_key_size;
    if (symbol_size != conn->remote_settings.fec_max_symbol_size) {
        /* symbol size is different from the declared one */
        xqc_log(conn->log, XQC_LOG_DEBUG, "|fec symbol size error, fss_esi: %d, remote declared size: %d, received size: %d, repair_payload_id: %d, repair_key_size:%d, packet_num: %d",
                fss_esi, conn->remote_settings.fec_max_symbol_size, symbol_size, repair_payload_id, repair_key_size, packet_in->pi_pkt.pkt_num);
        ret = -XQC_EFEC_SYMBOL_ERROR;
        goto end_parse_repair;
    }

    symbol_idx = src_symbol_num + repair_payload_id;
    if (xqc_process_valid_symbol(conn, tmp_block_idx, symbol_idx, repair_symbol_p, repair_symbol_size) != XQC_OK) {
        goto end_parse_repair;
    }

    ret = xqc_fec_ctl_save_symbol(&conn->fec_ctl->fec_recv_repair_key[block_cache_idx][repair_payload_id].payload,
                                  repair_key_p, repair_key_size);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|save repair key error|");
        goto end_parse_repair;
    }
    tmp_payload_p = conn->fec_ctl->fec_recv_repair_key[block_cache_idx][repair_payload_id].payload;
    xqc_set_object_value(&conn->fec_ctl->fec_recv_repair_key[block_cache_idx][repair_payload_id], 1, tmp_payload_p, repair_key_size);

    conn->fec_ctl->fec_recv_repair_symbols_num[block_cache_idx]++;

    if (conn->fec_ctl->fec_recv_symbols_num[block_cache_idx] >= src_symbol_num) {
        /* FEC解码操作 */
        ret = xqc_fec_decoder(conn, block_cache_idx);
        /* flush symbol缓存 */
        xqc_fec_ctl_init_recv_params(conn->fec_ctl, block_cache_idx);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|fec decode error|");
            goto end_parse_repair;
        }
    }

end_parse_repair:
    packet_in->pos = (unsigned char *) p;
    packet_in->pi_frame_types |= XQC_FRAME_BIT_REPAIR_SYMBOL;

    return ret;
}
#endif
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
xqc_gen_ack_frame(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_usec_t now, 
    int ack_delay_exponent, xqc_recv_record_t *recv_record, xqc_usec_t largest_pkt_recv_time, 
    int *has_gap, xqc_packet_number_t *largest_ack)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    size_t dst_buf_len = xqc_get_po_remained_size_with_ack_spc(packet_out);

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

    ack_delay = (now - largest_pkt_recv_time);
    lagest_recv = first_range->pktno_range.high;
    first_ack_range = lagest_recv - first_range->pktno_range.low;
    prev_low = first_range->pktno_range.low;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|lagest_recv:%ui|ack_delay:%ui|first_ack_range:%ud|largest_pkt_recv_time:%ui|",
            lagest_recv, ack_delay, first_ack_range, largest_pkt_recv_time);

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

    /* 
     * mpquic draft-04: If the multipath extension has been successfully 
     * negotiated, ACK frames in 1-RTT packets acknowledge packets sent 
     * with the Connection ID having sequence number 0.
     */
    ack_info->dcid_seq_num = 0;
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
    if (need > xqc_get_po_remained_size(packet_out)) {
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
    if (need > xqc_get_po_remained_size(packet_out)) {
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
    if (need > xqc_get_po_remained_size(packet_out)) {
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

    if (1
        + xqc_vint_len(token_len_bits)
        + token_len
        > xqc_get_po_remained_size(packet_out))
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
    
    if (need > xqc_get_po_remained_size(packet_out)) {
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
xqc_gen_new_conn_id_frame(xqc_packet_out_t *packet_out, xqc_cid_t *new_cid,
    uint64_t retire_prior_to, const uint8_t *sr_token)
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

    if (sr_token) {
        xqc_memcpy(dst_buf, sr_token, XQC_STATELESS_RESET_TOKENLEN);
        dst_buf += XQC_STATELESS_RESET_TOKENLEN;
    }

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
    xqc_memcpy(new_cid->sr_token, p, XQC_STATELESS_RESET_TOKENLEN);
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


/*
 * https://datatracker.ietf.org/doc/html/rfc9000#section-19.17
 *
 * PATH_CHALLENGE Frame {
 *    Type (i) = 0x1a,
 *    Data (64),
 * }
 *
 *               Figure 41: PATH_CHALLENGE Frame Format
 */

ssize_t
xqc_gen_path_challenge_frame(xqc_packet_out_t *packet_out, unsigned char *data)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;
    unsigned need = 0;

    uint64_t frame_type = 0x1a;
    unsigned frame_type_bits = xqc_vint_get_2bit(frame_type);
    need = xqc_vint_len(frame_type_bits) + XQC_PATH_CHALLENGE_DATA_LEN;

    /* check packout_out have enough buffer length */
    if (need > xqc_get_po_remained_size(packet_out)) {
        return -XQC_ENOBUF;
    }

    /* Type(i) */
    xqc_vint_write(dst_buf, frame_type, frame_type_bits, xqc_vint_len(frame_type_bits));
    dst_buf += xqc_vint_len(frame_type_bits);

    /* Data (64) */
    xqc_memcpy(dst_buf, data, XQC_PATH_CHALLENGE_DATA_LEN);
    dst_buf += XQC_PATH_CHALLENGE_DATA_LEN;

    packet_out->po_frame_types |= XQC_FRAME_BIT_PATH_CHALLENGE;

    return dst_buf - begin;
}

xqc_int_t
xqc_parse_path_challenge_frame(xqc_packet_in_t *packet_in, unsigned char *data)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    const unsigned char first_byte = *p++;

    if (p + XQC_PATH_CHALLENGE_DATA_LEN > end) {
        return -XQC_EVINTREAD;
    }
    xqc_memcpy(data, p, XQC_PATH_CHALLENGE_DATA_LEN);
    p += XQC_PATH_CHALLENGE_DATA_LEN;

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_PATH_CHALLENGE;

    return XQC_OK;
}

/*
 * https://datatracker.ietf.org/doc/html/rfc9000#section-19.18
 *
 * PATH_RESPONSE Frame {
 *    Type (i) = 0x1b,
 *    Data (64),
 * }
 *
 *               Figure 42: PATH_RESPONSE Frame Format
 */

ssize_t
xqc_gen_path_response_frame(xqc_packet_out_t *packet_out, unsigned char *data)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;
    unsigned need = 0;

    uint64_t frame_type = 0x1b;
    unsigned frame_type_bits = xqc_vint_get_2bit(frame_type);
    need = xqc_vint_len(frame_type_bits) + XQC_PATH_CHALLENGE_DATA_LEN;

    /* check packout_out have enough buffer length */
    if (need > xqc_get_po_remained_size(packet_out)) {
        return -XQC_ENOBUF;
    }

    /* Type(i) */
    xqc_vint_write(dst_buf, frame_type, frame_type_bits, xqc_vint_len(frame_type_bits));
    dst_buf += xqc_vint_len(frame_type_bits);

    /* Data (64) */
    xqc_memcpy(dst_buf, data, XQC_PATH_CHALLENGE_DATA_LEN);
    dst_buf += XQC_PATH_CHALLENGE_DATA_LEN;

    packet_out->po_frame_types |= XQC_FRAME_BIT_PATH_RESPONSE;

    return dst_buf - begin;
}

xqc_int_t
xqc_parse_path_response_frame(xqc_packet_in_t *packet_in, unsigned char *data)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    const unsigned char first_byte = *p++;

    if (p + XQC_PATH_CHALLENGE_DATA_LEN > end) {
        return -XQC_EVINTREAD;
    }

    xqc_memcpy(data, p, XQC_PATH_CHALLENGE_DATA_LEN);
    p += XQC_PATH_CHALLENGE_DATA_LEN;

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_PATH_RESPONSE;

    return XQC_OK;
}

/*
 * https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-05#name-ack_mp-frame
 *
 * ACK_MP Frame {
 *    Type (i) = TBD-00..TBD-01 ,
 *    Destination Connection ID Sequence Number (i),
 *    Largest Acknowledged (i),
 *    ACK Delay (i),
 *    ACK Range Count (i),
 *    First ACK Range (i),
 *    ACK Range (..) ...,
 *    [ECN Counts (..)],
 * }
 *
 *               Figure 6: ACK_MP Frame Format
 */

ssize_t
xqc_gen_ack_mp_frame(xqc_connection_t *conn, uint64_t dcid_seq,
    xqc_packet_out_t *packet_out, xqc_usec_t now, int ack_delay_exponent,
    xqc_recv_record_t *recv_record, xqc_usec_t largest_pkt_recv_time, 
    int *has_gap, xqc_packet_number_t *largest_ack)
{
    uint64_t frame_type;
    
    if (conn->conn_settings.multipath_version == XQC_MULTIPATH_04) {
        frame_type = 0xbaba00;

    } else if (conn->conn_settings.multipath_version >= XQC_MULTIPATH_05) {
        /* 06 is the same with 05 */
        frame_type = 0x15228c00;

    } else {
        return -XQC_EMP_INVALID_MP_VERTION;
    }

    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    size_t dst_buf_len = xqc_get_po_remained_size_with_ack_spc(packet_out);

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

    ack_delay = (now - largest_pkt_recv_time);
    /*
     * Because the receiver doesn't use the ACK Delay for Initial and Handshake packets,
     * a sender SHOULD send a value of 0.
     */
    if (packet_out->po_pkt.pkt_pns == XQC_PNS_INIT || packet_out->po_pkt.pkt_pns == XQC_PNS_HSK) {
        ack_delay = 0;
    }

    lagest_recv = first_range->pktno_range.high;
    first_ack_range = lagest_recv - first_range->pktno_range.low;
    prev_low = first_range->pktno_range.low;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|lagest_recv:%ui|ack_delay:%ui|first_ack_range:%ud|largest_pkt_recv_time:%ui|",
            lagest_recv, ack_delay, first_ack_range, largest_pkt_recv_time);

    ack_delay = ack_delay >> ack_delay_exponent;

    unsigned frame_type_bits = xqc_vint_get_2bit(frame_type);
    unsigned dcid_seq_bits = xqc_vint_get_2bit(dcid_seq);
    unsigned lagest_recv_bits = xqc_vint_get_2bit(lagest_recv);
    unsigned ack_delay_bits = xqc_vint_get_2bit(ack_delay);
    unsigned first_ack_range_bits = xqc_vint_get_2bit(first_ack_range);

    need = + xqc_vint_len(frame_type_bits)
           + xqc_vint_len(dcid_seq_bits)
           + xqc_vint_len(lagest_recv_bits)
           + xqc_vint_len(ack_delay_bits)
           + 1  /* range_count */
           + xqc_vint_len(first_ack_range_bits);

    if (dst_buf + need > end) {
        return -XQC_ENOBUF;
    }

    xqc_vint_write(dst_buf, frame_type, frame_type_bits, xqc_vint_len(frame_type_bits));
    dst_buf += xqc_vint_len(frame_type_bits);

    xqc_vint_write(dst_buf, dcid_seq, dcid_seq_bits, xqc_vint_len(dcid_seq_bits));
    dst_buf += xqc_vint_len(dcid_seq_bits);

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
                range_node->pktno_range.high, range_node->pktno_range.low,
                packet_out->po_pkt.pkt_pns);

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

    packet_out->po_frame_types |= XQC_FRAME_BIT_ACK_MP;
    return dst_buf - begin;
}

xqc_int_t
xqc_parse_ack_mp_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn,
    uint64_t *dcid_seq_num, xqc_ack_info_t *ack_info)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;
    uint64_t frame_type = 0;

    int vlen;
    uint64_t largest_acked;
    uint64_t ack_range_count;   /* the actual range cnt */
    uint64_t first_ack_range;
    uint64_t range, gap;

    unsigned n_ranges = 0;      /* the range cnt stored */

    vlen = xqc_vint_read(p, end, &frame_type);  /* get frame_type */
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    vlen = xqc_vint_read(p, end, dcid_seq_num);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    ack_info->dcid_seq_num = *dcid_seq_num;
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
    packet_in->pi_frame_types |= XQC_FRAME_BIT_ACK_MP;

    xqc_log_event(conn->log, TRA_FRAMES_PROCESSED, XQC_FRAME_ACK_MP, ack_info);
    return XQC_OK;
}


/*
 * https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-05#name-path_abandon-frame
 *
 * PATH_ABANDON Frame {
 *    Type (i) = TBD-03,
 *    DCID Sequence Number (i),
 *    Error Code (i),
 *    Reason Phrase Length (i),
 *    Reason Phrase (..),
 * }
 *
 *               Figure 6: PATH_ABANDON Frame Format
 */

ssize_t
xqc_gen_path_abandon_frame(xqc_connection_t *conn, xqc_packet_out_t *packet_out,
    uint64_t dcid_seq_num, uint64_t error_code)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;
    unsigned need, po_remained_size;
    uint64_t frame_type;

    need = po_remained_size = 0;

    if (conn->conn_settings.multipath_version == XQC_MULTIPATH_04) {
        frame_type = 0xbaba05;

    } else if (conn->conn_settings.multipath_version >= XQC_MULTIPATH_05) {
        /* same frame type in 05 and 06 */
        frame_type = 0x15228c05;

    } else {
        return -XQC_EMP_INVALID_MP_VERTION;
    }

    uint64_t reason_len = 0;
    uint8_t *reason = NULL;

    unsigned frame_type_bits = xqc_vint_get_2bit(frame_type);
    unsigned dcid_seq_num_bits = xqc_vint_get_2bit(dcid_seq_num);
    unsigned error_code_bits = xqc_vint_get_2bit(error_code);
    unsigned reason_len_bits = xqc_vint_get_2bit(reason_len);

    need = xqc_vint_len(frame_type_bits)
           + xqc_vint_len(dcid_seq_num_bits)
           + xqc_vint_len(error_code_bits)
           + xqc_vint_len(reason_len_bits)
           + reason_len;

    po_remained_size = xqc_get_po_remained_size(packet_out);

    /* check packout_out have enough buffer length */
    if (need > po_remained_size) {
        return -XQC_ENOBUF;
    }

    /* Type(i) */
    xqc_vint_write(dst_buf, frame_type, frame_type_bits, xqc_vint_len(frame_type_bits));
    dst_buf += xqc_vint_len(frame_type_bits);

    /* DCID Sequence Number (i) */
    xqc_vint_write(dst_buf, dcid_seq_num, dcid_seq_num_bits, xqc_vint_len(dcid_seq_num_bits));
    dst_buf += xqc_vint_len(dcid_seq_num_bits);

    /* Error Code (i) */
    xqc_vint_write(dst_buf, error_code, error_code_bits, xqc_vint_len(error_code_bits));
    dst_buf += xqc_vint_len(error_code_bits);

    /* Reason Phrase Length (i) */
    xqc_vint_write(dst_buf, reason_len, reason_len_bits, xqc_vint_len(reason_len_bits));
    dst_buf += xqc_vint_len(reason_len_bits);

    /* Reason Phrase (..) */
    if (reason_len > 0) {
        xqc_memcpy(dst_buf, reason, reason_len);
        dst_buf += reason_len;
    }

    packet_out->po_frame_types |= XQC_FRAME_BIT_PATH_ABANDON;

    return dst_buf - begin;
}

xqc_int_t
xqc_parse_path_abandon_frame(xqc_packet_in_t *packet_in,
    uint64_t *dcid_seq_num, uint64_t *error_code)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;

    int vlen;
    uint64_t reason_len = 0;

    uint64_t frame_type = 0;
    vlen = xqc_vint_read(p, end, &frame_type);  /* get frame_type */
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    /* DCID Sequence Number (i) */
    vlen = xqc_vint_read(p, end, dcid_seq_num);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    /* Error Code (i) */
    vlen = xqc_vint_read(p, end, error_code);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    /* Reason Phrase Length (i) */
    vlen = xqc_vint_read(p, end, &reason_len);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

     /* Reason Phrase (..) */
    if (reason_len > 0) {
        p += reason_len;
    }

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_PATH_ABANDON;

    return XQC_OK;
}


/*
 * https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-05#name-path_status-frame
 *
 *    PATH_STATUS Frame {
 *      Type (i) = TBD-03,
 *      DCID Sequence Number (i),
 *      Path Status sequence number (i),
 *      Path Status (i),
 *    }
 *
 *                    Figure 7: PATH_STATUS Frame Format
 */

ssize_t
xqc_gen_path_status_frame(xqc_connection_t *conn,
    xqc_packet_out_t *packet_out,
    uint64_t dcid_seq_num,
    uint64_t path_status_seq_num, uint64_t path_status)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;
    unsigned need = 0;

    uint64_t frame_type;
    if (conn->conn_settings.multipath_version == XQC_MULTIPATH_04) {
        frame_type = 0xbaba06;

    } else if (conn->conn_settings.multipath_version == XQC_MULTIPATH_05) {
        frame_type = 0x15228c06;
        
    } else {
        return -XQC_EMP_INVALID_MP_VERTION;
    }

    unsigned frame_type_bits = xqc_vint_get_2bit(frame_type);
    unsigned dcid_seq_num_bits = xqc_vint_get_2bit(dcid_seq_num);
    unsigned path_status_seq_num_bits = xqc_vint_get_2bit(path_status_seq_num);
    unsigned path_status_bits = xqc_vint_get_2bit(path_status);

    need = xqc_vint_len(frame_type_bits)
           + xqc_vint_len(dcid_seq_num_bits)
           + xqc_vint_len(path_status_seq_num_bits)
           + xqc_vint_len(path_status_bits);

    /* check packout_out have enough buffer length */
    if (need > xqc_get_po_remained_size(packet_out)) {
        return -XQC_ENOBUF;
    }

    /* Type(i) */
    xqc_vint_write(dst_buf, frame_type, frame_type_bits, xqc_vint_len(frame_type_bits));
    dst_buf += xqc_vint_len(frame_type_bits);

    /* DCID Sequence Number (i) */
    xqc_vint_write(dst_buf, dcid_seq_num, dcid_seq_num_bits, xqc_vint_len(dcid_seq_num_bits));
    dst_buf += xqc_vint_len(dcid_seq_num_bits);

    /* Path Status sequence number (i) */
    xqc_vint_write(dst_buf, path_status_seq_num, path_status_seq_num_bits, xqc_vint_len(path_status_seq_num_bits));
    dst_buf += xqc_vint_len(path_status_seq_num_bits);

    /* Path Status (i) */
    xqc_vint_write(dst_buf, path_status, path_status_bits, xqc_vint_len(path_status_bits));
    dst_buf += xqc_vint_len(path_status_bits);

    packet_out->po_frame_types |= XQC_FRAME_BIT_PATH_STATUS;

    return dst_buf - begin;

}

xqc_int_t
xqc_parse_path_status_frame(xqc_packet_in_t *packet_in,
    uint64_t *dcid_seq_num,
    uint64_t *path_status_seq_num, uint64_t *path_status)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;

    int vlen;

    uint64_t frame_type = 0;
    vlen = xqc_vint_read(p, end, &frame_type);  /* get frame_type */
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    /* DCID Sequence Number (i) */
    vlen = xqc_vint_read(p, end, dcid_seq_num);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    /* Path Status sequence number (i) */
    vlen = xqc_vint_read(p, end, path_status_seq_num);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    /* Path Status (i) */
    vlen = xqc_vint_read(p, end, path_status);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_PATH_STATUS;

    return XQC_OK;
}

/*
 *  PATH_STANDBY Frame {
 *    Type (i) = TBD-03 (experiments use 0x15228c07)
 *    Destination Connection ID Sequence Number (i),
 *    Path Status sequence number (i),
 *  }
 *
 *  https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-06#section-8.3
 * */
ssize_t
xqc_gen_path_standby_frame(xqc_connection_t *conn,
    xqc_packet_out_t *packet_out,
    uint64_t dcid_seq_num,
    uint64_t path_status_seq_num)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;
    unsigned need = 0;

    uint64_t frame_type;
    if (conn->conn_settings.multipath_version >= XQC_MULTIPATH_06) {
        frame_type = 0x15228c07;
    } else {
        return -XQC_EMP_INVALID_MP_VERTION;
    }

    unsigned frame_type_bits = xqc_vint_get_2bit(frame_type);
    unsigned dcid_seq_num_bits = xqc_vint_get_2bit(dcid_seq_num);
    unsigned path_status_seq_num_bits = xqc_vint_get_2bit(path_status_seq_num);

    need = xqc_vint_len(frame_type_bits)
           + xqc_vint_len(dcid_seq_num_bits)
           + xqc_vint_len(path_status_seq_num_bits);

    /* check packout_out have enough buffer length */
    if (need > xqc_get_po_remained_size(packet_out)) {
        return -XQC_ENOBUF;
    }

    /* Type(i) */
    xqc_vint_write(dst_buf, frame_type, frame_type_bits, xqc_vint_len(frame_type_bits));
    dst_buf += xqc_vint_len(frame_type_bits);

    /* DCID Sequence Number (i) */
    xqc_vint_write(dst_buf, dcid_seq_num, dcid_seq_num_bits, xqc_vint_len(dcid_seq_num_bits));
    dst_buf += xqc_vint_len(dcid_seq_num_bits);

    /* Path Status sequence number (i) */
    xqc_vint_write(dst_buf, path_status_seq_num, path_status_seq_num_bits, xqc_vint_len(path_status_seq_num_bits));
    dst_buf += xqc_vint_len(path_status_seq_num_bits);

    packet_out->po_frame_types |= XQC_FRAME_BIT_PATH_STANDBY;

    return dst_buf - begin;
}

xqc_int_t
xqc_parse_path_standby_frame(xqc_packet_in_t *packet_in,
    uint64_t *dcid_seq_num,
    uint64_t *path_status_seq_num, uint64_t *path_status)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;

    int vlen;

    uint64_t frame_type = 0;
    vlen = xqc_vint_read(p, end, &frame_type);  /* get frame_type */
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    /* DCID Sequence Number (i) */
    vlen = xqc_vint_read(p, end, dcid_seq_num);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    /* Path Status sequence number (i) */
    vlen = xqc_vint_read(p, end, path_status_seq_num);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    *path_status = 1; /* 1 - Standby */

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_PATH_STANDBY;

    return XQC_OK;
}

/*
 *
 *  PATH_AVAILABLE Frame {
 *    Type (i) = TBD-03 (experiments use 0x15228c08),
 *    Destination Connection ID Sequence Number (i),
 *    Path Status sequence number (i),
 *  }
 *
 *
 *  https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-06#section-8.4
 * */
ssize_t
xqc_gen_path_available_frame(xqc_connection_t *conn,
    xqc_packet_out_t *packet_out,
    uint64_t dcid_seq_num,
    uint64_t path_status_seq_num)
{
    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    const unsigned char *begin = dst_buf;
    unsigned need = 0;

    uint64_t frame_type;
    if (conn->conn_settings.multipath_version >= XQC_MULTIPATH_06) {
        frame_type = 0x15228c08;
    } else {
        return -XQC_EMP_INVALID_MP_VERTION;
    }

    unsigned frame_type_bits = xqc_vint_get_2bit(frame_type);
    unsigned dcid_seq_num_bits = xqc_vint_get_2bit(dcid_seq_num);
    unsigned path_status_seq_num_bits = xqc_vint_get_2bit(path_status_seq_num);

    need = xqc_vint_len(frame_type_bits)
           + xqc_vint_len(dcid_seq_num_bits)
           + xqc_vint_len(path_status_seq_num_bits);

    /* check packout_out have enough buffer length */
    if (need > xqc_get_po_remained_size(packet_out)) {
        return -XQC_ENOBUF;
    }

    /* Type(i) */
    xqc_vint_write(dst_buf, frame_type, frame_type_bits, xqc_vint_len(frame_type_bits));
    dst_buf += xqc_vint_len(frame_type_bits);

    /* DCID Sequence Number (i) */
    xqc_vint_write(dst_buf, dcid_seq_num, dcid_seq_num_bits, xqc_vint_len(dcid_seq_num_bits));
    dst_buf += xqc_vint_len(dcid_seq_num_bits);

    /* Path Status sequence number (i) */
    xqc_vint_write(dst_buf, path_status_seq_num, path_status_seq_num_bits, xqc_vint_len(path_status_seq_num_bits));
    dst_buf += xqc_vint_len(path_status_seq_num_bits);

    packet_out->po_frame_types |= XQC_FRAME_BIT_PATH_AVAILABLE;

    return dst_buf - begin;
}

xqc_int_t
xqc_parse_path_available_frame(xqc_packet_in_t *packet_in,
    uint64_t *dcid_seq_num,
    uint64_t *path_status_seq_num, uint64_t *path_status)
{
    unsigned char *p = packet_in->pos;
    const unsigned char *end = packet_in->last;

    int vlen;

    uint64_t frame_type = 0;
    vlen = xqc_vint_read(p, end, &frame_type);  /* get frame_type */
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    /* DCID Sequence Number (i) */
    vlen = xqc_vint_read(p, end, dcid_seq_num);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    *path_status = 2; /* 2 - available */

    /* Path Status sequence number (i) */
    vlen = xqc_vint_read(p, end, path_status_seq_num);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    p += vlen;

    packet_in->pos = p;

    packet_in->pi_frame_types |= XQC_FRAME_BIT_PATH_AVAILABLE;

    return XQC_OK;
}
