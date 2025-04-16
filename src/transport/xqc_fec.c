
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#include "src/transport/xqc_fec.h"
#include "src/transport/xqc_fec_scheme.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_packet_out.h"


#define XQC_FEC_MAX_SCHEME_VAL  32
#define MAX_FEC_CODE_RATE      (20)

xqc_int_t
xqc_set_valid_encoder_scheme_cb(xqc_fec_code_callback_t *callback, xqc_int_t scheme)
{
    switch (scheme) {
#ifdef XQC_ENABLE_RSC
    case XQC_REED_SOLOMON_CODE:
        callback->xqc_fec_init = xqc_reed_solomon_code_cb.xqc_fec_init;
        callback->xqc_fec_init_one = xqc_reed_solomon_code_cb.xqc_fec_init_one;
        callback->xqc_fec_encode = xqc_reed_solomon_code_cb.xqc_fec_encode;
        return XQC_OK;
#endif
#ifdef XQC_ENABLE_XOR
    case XQC_XOR_CODE:
        callback->xqc_fec_init = xqc_xor_code_cb.xqc_fec_init;
        callback->xqc_fec_init_one = xqc_xor_code_cb.xqc_fec_init_one;
        callback->xqc_fec_encode = xqc_xor_code_cb.xqc_fec_encode;
        return XQC_OK;
#endif
#ifdef XQC_ENABLE_PKM
    case XQC_PACKET_MASK_CODE:
        callback->xqc_fec_init = xqc_packet_mask_code_cb.xqc_fec_init;
        callback->xqc_fec_init_one = xqc_packet_mask_code_cb.xqc_fec_init_one;
        callback->xqc_fec_encode = xqc_packet_mask_code_cb.xqc_fec_encode;
        return XQC_OK;
#endif
    }

    return -XQC_EFEC_SCHEME_ERROR;
}

xqc_int_t
xqc_set_valid_decoder_scheme_cb(xqc_fec_code_callback_t *callback, xqc_int_t scheme)
{
    switch (scheme) {
#ifdef XQC_ENABLE_RSC
    case XQC_REED_SOLOMON_CODE:
        callback->xqc_fec_decode = xqc_reed_solomon_code_cb.xqc_fec_decode;
        return XQC_OK;
#endif
#ifdef XQC_ENABLE_XOR
    case XQC_XOR_CODE:
        callback->xqc_fec_decode = xqc_xor_code_cb.xqc_fec_decode;
        return XQC_OK;
#endif
#ifdef XQC_ENABLE_PKM
    case XQC_PACKET_MASK_CODE:
        callback->xqc_fec_decode_one = xqc_packet_mask_code_cb.xqc_fec_decode_one;
        return XQC_OK;
#endif
    }

    return -XQC_EFEC_SCHEME_ERROR;
}

unsigned char *
xqc_get_fec_scheme_str(xqc_fec_schemes_e scheme)
{
    switch (scheme) {
    case XQC_REED_SOLOMON_CODE:
        return "Reed-Solomon";
    case XQC_XOR_CODE:
        return "XOR";
    case XQC_PACKET_MASK_CODE:
        return "Packet-Mask";
    default:
        return "NO_FEC";
    }
}

unsigned char*
xqc_get_fec_enc_level_str(xqc_fec_level_e fec_level)
{
    switch (fec_level) {
    case XQC_FEC_CONN_LEVEL:
        return "FEC_CONN_LEVEL";
    case XQC_FEC_STREAM_LEVEL:
        return "FEC_STREAM_LEVEL";
    default:
        return "UNDEFINED";
    }
}

unsigned char *
xqc_get_fec_mp_mode_str(xqc_fec_ctl_t *fec_ctl)
{
    if (fec_ctl == NULL) {
        return "NO_FEC";
    }
    if (fec_ctl->fec_mp_mode == XQC_FEC_MP_USE_STB) {
        if (fec_ctl->fec_rep_path_id != XQC_MAX_UINT64_VALUE) {
            return "USE_STB_PATH"; 
        } else {
            return "NO_AVAI_STB_PATH";
        }
    }
    return "DEFAULT";
}

xqc_int_t
xqc_set_final_scheme(xqc_connection_t *conn, xqc_fec_schemes_e *local_fec_schemes_buff, xqc_int_t *local_fec_schemes_buff_len,
    xqc_fec_schemes_e *remote_fec_schemes_buff, xqc_int_t remote_fec_schemes_buff_len)
{
    uint32_t   p, schemes_flag;
    xqc_int_t  i, ret;
    
    if (*local_fec_schemes_buff_len == 0 || remote_fec_schemes_buff_len == 0) {
        return 0;
    }

    p = schemes_flag = 0;
    ret = 0;

    for (i = 0; i < remote_fec_schemes_buff_len; i++) {
        if (remote_fec_schemes_buff[i] > XQC_FEC_MAX_SCHEME_VAL) {
            continue;
        }
        p = 1 << remote_fec_schemes_buff[i];
        schemes_flag |= p;
    }

    /* 初始化schemes_flag */
    for (i = 0; i < *local_fec_schemes_buff_len; i++) {
        if (schemes_flag & (1 << local_fec_schemes_buff[i])) {
            ret = local_fec_schemes_buff[i];
            break;
        }
    }

    return ret;
}

xqc_int_t
xqc_set_fec_scheme(uint64_t in, xqc_fec_schemes_e *out)
{
    switch (in) {
    case XQC_REED_SOLOMON_CODE:
        *out = XQC_REED_SOLOMON_CODE;
        return XQC_OK;
    case XQC_XOR_CODE:
        *out = XQC_XOR_CODE;
        return XQC_OK;
    case XQC_PACKET_MASK_CODE:
        *out = XQC_PACKET_MASK_CODE;
        return XQC_OK;
    default:
        break;
    }

    return -XQC_EFEC_SCHEME_ERROR;
}

xqc_int_t
xqc_set_fec_schemes(const xqc_fec_schemes_e *schemes, xqc_int_t schemes_len,
    xqc_fec_schemes_e *fec_schemes_buff, xqc_int_t *fec_schemes_buff_len)
{
    xqc_int_t i = 0, j = 0;

    for (i = 0; i < XQC_FEC_MAX_SCHEME_NUM; i++)
    {
        fec_schemes_buff[i] = 0;
    }

    *fec_schemes_buff_len = 0;
    for (i = 0, j = 0; i < schemes_len && j < XQC_FEC_MAX_SCHEME_NUM; i++) {
        switch (schemes[i]) {
        case XQC_XOR_CODE:
            fec_schemes_buff[j] = XQC_XOR_CODE;
            j++;
            break;
        case XQC_REED_SOLOMON_CODE:
            fec_schemes_buff[j] = XQC_REED_SOLOMON_CODE;
            j++;
            break;
        case XQC_PACKET_MASK_CODE:
            fec_schemes_buff[j] = XQC_PACKET_MASK_CODE;
            j++;
            break;
        default:
            break;
        }

        if (j != *fec_schemes_buff_len) {
            *fec_schemes_buff_len = j;
        }
    }
    return XQC_OK;
}

/**
 * @brief 
 * return XQC_TRUE if obj and cmp_buff has SAME payload content,
 * otherwise return XQC_FALSE
 * @param obj 
 * @param cmp_buff 
 * @return xqc_bool_t 
 */
xqc_bool_t
xqc_fec_object_compare(xqc_fec_object_t *obj, unsigned char *cmp_buff)
{
    size_t  obj_size;
    unsigned char *obj_buff;

    if (!obj->is_valid) {
        return XQC_FALSE;
    }
    obj_size = obj->payload_size;
    obj_buff = obj->payload;
    return xqc_memcmp(obj_buff, cmp_buff, obj_size) == 0 ? XQC_TRUE : XQC_FALSE;
}

xqc_int_t
xqc_send_repair_packets_ahead(xqc_connection_t *conn, xqc_list_head_t *prev, uint8_t fec_bm_mode)
{
    uint32_t        i, fss_esi, repair_num, cur_syb_num, tmp_repair_num;
    xqc_int_t       ret;
    unsigned char  *repair_key_p;

    if (fec_bm_mode >= XQC_BLOCK_MODE_LEN) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|invalid fec_bm_mode:%d|", fec_bm_mode);
        return -XQC_EPARAM;
    }

    cur_syb_num = conn->fec_ctl->fec_send_symbol_num[fec_bm_mode];
    fss_esi = conn->fec_ctl->fec_send_block_num[fec_bm_mode];
    repair_num = conn->fec_ctl->fec_send_required_repair_num[fec_bm_mode];
    tmp_repair_num = 0;

    if (cur_syb_num <= 1) {
        /* TODO: whether protect if only one src syb? */
        return XQC_OK;
    }

    for (i = 0; i < repair_num; i++) {
        if (!conn->fec_ctl->fec_send_repair_key[fec_bm_mode][i].is_valid) {
            continue;
        }

        xqc_packet_out_t *packet_out = xqc_write_one_repair_packet(conn, fss_esi, tmp_repair_num, fec_bm_mode);
        if (packet_out == NULL) {
            xqc_log(conn->log ,XQC_LOG_ERROR, "|quic_fec|generate one repair packet error");
            return -XQC_EFEC_SYMBOL_ERROR;
        }
        tmp_repair_num++;
        conn->fec_ctl->fec_send_ahead++;
        xqc_send_queue_move_to_head(&packet_out->po_list, prev);
        prev = &packet_out->po_list;
    }

    xqc_fec_ctl_init_send_params(conn, fec_bm_mode);

    return XQC_OK;
}

xqc_int_t
xqc_send_repair_packets(xqc_connection_t *conn, xqc_fec_schemes_e scheme, xqc_list_head_t *prev,
    uint8_t fec_bm_mode)
{
    uint32_t        i, fss_esi, repair_num, pm_size, tmp_repair_num;
    xqc_int_t       ret;
    unsigned char  *pm_p;

    if (fec_bm_mode >= XQC_BLOCK_MODE_LEN) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|invalid fec_bm_mode:%d|", fec_bm_mode);
        return -XQC_EPARAM;
    }

    repair_num = conn->fec_ctl->fec_send_required_repair_num[fec_bm_mode];
    fss_esi = conn->fec_ctl->fec_send_block_num[fec_bm_mode];
    tmp_repair_num = 0;

    if (repair_num > XQC_REPAIR_LEN) {
        xqc_log(conn->log ,XQC_LOG_ERROR, "|quic_fec|repair number exceeds buff size");
        return -XQC_EFEC_SYMBOL_ERROR;
    }
    if (repair_num > conn->fec_ctl->fec_send_symbol_num[fec_bm_mode]) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|source symbols number or repair symbol number invalid|src:%d|rpr:%d|", conn->fec_ctl->fec_send_symbol_num[fec_bm_mode], repair_num);
        return -XQC_EFEC_SYMBOL_ERROR;
    }

    switch (scheme) {
    case XQC_REED_SOLOMON_CODE:
    case XQC_XOR_CODE:
        /* Generate repair packets */
        ret = xqc_write_repair_packets(conn, fss_esi, prev, repair_num, fec_bm_mode);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_process_fec_protected_packet|xqc_gen_repair_packet error|");
            return -XQC_EWRITE_PKT;
        }
        break;
    case XQC_PACKET_MASK_CODE:
        for (i = 0; i < repair_num; i++) {
            pm_p = conn->fec_ctl->fec_send_decode_matrix[fec_bm_mode][i];
            if (xqc_fec_object_compare(&conn->fec_ctl->fec_send_repair_key[fec_bm_mode][i], pm_p)) {
                xqc_packet_out_t *packet_out = xqc_write_one_repair_packet(conn, fss_esi, tmp_repair_num, fec_bm_mode);
                if (packet_out == NULL) {
                    xqc_log(conn->log ,XQC_LOG_ERROR, "|quic_fec|generate one repair packet error");
                    continue;
                }

                tmp_repair_num++;
                xqc_send_queue_move_to_head(&packet_out->po_list, prev);
                prev = &packet_out->po_list;
            }
        }
        break;
    default:
        xqc_log(conn->log ,XQC_LOG_ERROR, "|quic_fec|error type of fec scheme");
        return -XQC_EFEC_SCHEME_ERROR;
    }

    return XQC_OK;
}

xqc_int_t
xqc_is_packet_fec_protected(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    if (packet_out->po_flag & XQC_POF_USE_FEC
        && packet_out->po_frame_types & conn->conn_settings.fec_params.fec_protected_frames)
    {
        return XQC_OK;
    }

    return -XQC_EFEC_NOT_SUPPORT_FEC;
}

xqc_int_t
xqc_check_fec_params(xqc_connection_t *conn, xqc_int_t src_symbol_num, xqc_int_t repair_symbol_num,
    xqc_int_t max_window_size, xqc_int_t symbol_size)
{
    if (repair_symbol_num < 0 || repair_symbol_num > XQC_REPAIR_LEN || repair_symbol_num > src_symbol_num) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|invalid fec repair symbol:%d|src_num:%d|", repair_symbol_num, src_symbol_num);
        return -XQC_EFEC_SCHEME_ERROR;
    }
    if (repair_symbol_num == 0) {
        xqc_log(conn->log, XQC_LOG_WARN, "|quic_fec|xqc_fec_encoder|current code rate is too low to generate repair packets.");
        return -XQC_EFEC_SYMBOL_ERROR;
    }
    if (src_symbol_num <= 0 || src_symbol_num > XQC_FEC_MAX_SYMBOL_NUM_PBLOCK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|src_symbol_num invalid|%d|", src_symbol_num);
        return -XQC_EFEC_SYMBOL_ERROR;
    }
    if (max_window_size <= 0 || max_window_size > XQC_SYMBOL_CACHE_LEN) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|max_window_size invalid|%d|", max_window_size);
        return -XQC_EFEC_SYMBOL_ERROR;
    }
    if (symbol_size < 0 || symbol_size > XQC_MAX_SYMBOL_SIZE) {
        xqc_log(conn->log, XQC_LOG_WARN, "|quic_fec|symbol_size invalid|%d|", symbol_size);
        return -XQC_EFEC_SYMBOL_ERROR;
    }

    return XQC_OK;
}

/* process fec protected packet with stream mode */
xqc_int_t
xqc_process_fec_protected_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    uint8_t         fec_bm_mode;
    xqc_int_t       i, ret, fss_esi, header_len, payload_len, max_src_symbol_num, repair_symbol_num;
    xqc_fec_schemes_e encoder_scheme;
    unsigned char  *p;

    header_len = packet_out->po_payload - packet_out->po_buf;
    payload_len = packet_out->po_used_size - header_len;
    fec_bm_mode = packet_out->po_stream_fec_blk_mode;
    max_src_symbol_num = xqc_get_fec_blk_size(conn, fec_bm_mode);
    repair_symbol_num = conn->fec_ctl->fec_send_required_repair_num[fec_bm_mode];
    encoder_scheme = conn->conn_settings.fec_params.fec_encoder_scheme;

    ret = xqc_check_fec_params(conn, max_src_symbol_num, repair_symbol_num, conn->conn_settings.fec_params.fec_max_window_size, payload_len);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_is_fec_params_valid|fec params invalid|");
        return -XQC_EPARAM;
    }

    /* attach sid frame to current packet */
    ret = xqc_write_sid_frame_to_one_packet(conn, packet_out);
    if (ret == -XQC_EFEC_TOLERABLE_ERROR) {
        return XQC_OK;

    } else if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_write_sid_frame_to_one_packet error|");
        return -XQC_EFEC_SYMBOL_ERROR;
    }

    /* FEC encoder */
    ret = xqc_fec_encoder(conn, packet_out->po_payload, payload_len, fec_bm_mode);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_fec_encoder error|");
        xqc_fec_ctl_init_send_params(conn, fec_bm_mode);
        return ret;
    }

    conn->fec_ctl->fec_send_symbol_num[fec_bm_mode] += 1;
    /* Try to generate repair packets, only succeed when send_symbol_numbers satisfy the limits */
    if (conn->fec_ctl->fec_send_symbol_num[fec_bm_mode] == max_src_symbol_num) {
        ret = xqc_send_repair_packets(conn, conn->conn_settings.fec_params.fec_encoder_scheme, &packet_out->po_list, fec_bm_mode);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_send_repair_packets error: %d|", ret);
        }
        xqc_fec_ctl_init_send_params(conn, fec_bm_mode);
    }

    return XQC_OK;
}
void
xqc_stream_fec_init(xqc_stream_t *stream)
{
    double              fec_code_rate;
    xqc_connection_t   *conn;

    conn = stream->stream_conn;

    // if FEC negotiation success, set current block size
    if (conn->conn_settings.fec_params.fec_encoder_scheme == XQC_PACKET_MASK_CODE) {
        // set fec symbol number in trans stream in the first round
        if (stream->stream_fec_ctl.stream_fec_syb_num != 0) {
            conn->conn_settings.fec_params.fec_code_rate = stream->stream_fec_ctl.fec_code_rate;
            xqc_fec_on_stream_size_changed(stream);
        }
    }
}


xqc_int_t
xqc_process_fec_protected_packet_moq(xqc_stream_t *stream)
{
    uint8_t             fec_bm_mode;
    xqc_int_t           ret, header_len, payload_len, max_src_symbol_num, repair_symbol_num;
    xqc_list_head_t    *pos, *next;
    xqc_list_head_t    *fec_enc_pkts;
    xqc_packet_out_t   *packet_out;
    xqc_connection_t   *conn;
    xqc_send_queue_t   *send_queue;

    fec_bm_mode = 0;
    conn = stream->stream_conn;
    send_queue = conn->conn_send_queue;
    // fec_enc_pkts = &stream->stream_fec_ctl.stream_fec_send_packets;
    fec_enc_pkts = stream->stream_fec_ctl.stream_fec_head;


    xqc_stream_fec_init(stream);
    max_src_symbol_num = stream->stream_fec_ctl.stream_fec_syb_num;
    repair_symbol_num = conn->fec_ctl->fec_send_required_repair_num[fec_bm_mode];

    ret = xqc_check_fec_params(conn, xqc_min(max_src_symbol_num, XQC_FEC_MAX_SYMBOL_NUM_PBLOCK), repair_symbol_num, conn->conn_settings.fec_params.fec_max_window_size, 0);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_is_fec_params_valid|fec params invalid|");
        return -XQC_EFEC_SYMBOL_ERROR;
    }

    xqc_list_for_each_safe(pos, next, fec_enc_pkts) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        header_len = packet_out->po_payload - packet_out->po_buf;
        payload_len = packet_out->po_used_size - header_len;
        if (payload_len < 0 || payload_len > XQC_MAX_SYMBOL_SIZE) {
            continue;
        }
        /* attach sid frame to current packet */
        ret = xqc_write_sid_frame_to_one_packet(conn, packet_out);
        if (ret == -XQC_EFEC_TOLERABLE_ERROR) {
            return XQC_OK;

        } else if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_write_sid_frame_to_one_packet error|");
            return -XQC_EFEC_SYMBOL_ERROR;
        }

        /* FEC encoder */
        ret = xqc_fec_encoder(conn, packet_out->po_payload, payload_len, fec_bm_mode);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_fec_encoder error|");
            xqc_fec_ctl_init_send_params(conn, fec_bm_mode);
            return ret;
        }

        conn->fec_ctl->fec_send_symbol_num[fec_bm_mode] += 1;
        /* if source symbols number GT max symbol number(48), generate repair packets in ahead */
        if (conn->fec_ctl->fec_send_symbol_num[fec_bm_mode] == XQC_FEC_MAX_SYMBOL_NUM_PBLOCK) {
            ret = xqc_send_repair_packets(conn, XQC_PACKET_MASK_CODE, (&conn->conn_send_queue->sndq_send_packets)->prev, 0);
            if (ret != XQC_OK) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_send_repair_packets error: %d|", ret);
                break;
            }

            stream->stream_stats.fec_send_rpr_cnt += repair_symbol_num;

            xqc_fec_ctl_init_send_params(conn, 0);
            stream->stream_fec_ctl.stream_fec_syb_num -= XQC_FEC_MAX_SYMBOL_NUM_PBLOCK;
            if (stream->stream_fec_ctl.stream_fec_syb_num != 0) {
                xqc_fec_on_stream_size_changed(stream);
                repair_symbol_num = conn->fec_ctl->fec_send_required_repair_num[fec_bm_mode];
            }
        }

        if (pos == stream->stream_fec_ctl.stream_fec_tail) {
            break;
        }
    }

    if (stream->stream_fec_ctl.stream_fec_syb_num != 0) {
        /* Try to generate repair packets, only succeed when send_symbol_numbers satisfy the limits */
        ret = xqc_send_repair_packets(conn, XQC_PACKET_MASK_CODE, (&conn->conn_send_queue->sndq_send_packets)->prev, 0);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_send_repair_packets error: %d|", ret);

        } else {
            stream->stream_stats.fec_send_rpr_cnt += repair_symbol_num;
        }
    }

    ret = xqc_fec_ctl_init_send_params(conn, 0);

    stream->stream_fec_ctl.stream_fec_syb_num = 0;
    stream->stream_fec_ctl.stream_fec_head = stream->stream_fec_ctl.stream_fec_tail = NULL;

    return XQC_OK;
}


xqc_int_t
xqc_gen_src_payload_id(xqc_fec_ctl_t *fec_ctl, uint64_t *payload_id, uint8_t bm_idx)
{
    xqc_connection_t *conn = fec_ctl->conn;

    if (fec_ctl->fec_send_block_num[bm_idx] > XQC_FEC_MAX_BLOCK_NUM || fec_ctl->fec_send_symbol_num[bm_idx] > XQC_FEC_MAX_SYMBOL_NUM) {
        return -XQC_EFEC_SYMBOL_ERROR;
    }
    *payload_id = fec_ctl->fec_send_block_num[bm_idx] << 8 | fec_ctl->fec_send_symbol_num[bm_idx];
    return XQC_OK;
}

xqc_fec_ctl_t *
xqc_fec_ctl_create(xqc_connection_t *conn)
{
    xqc_int_t       i, j;
    uint32_t        repair_num;
    xqc_fec_ctl_t  *fec_ctl = NULL;

    fec_ctl = xqc_calloc(1, sizeof(xqc_fec_ctl_t));
    if (fec_ctl == NULL) {
        return NULL;
    }

    fec_ctl->conn = conn;
    if (conn->conn_settings.fec_params.fec_code_rate == 0) {
        fec_ctl->fec_send_required_repair_num[XQC_DEFAULT_SIZE_REQ] = 1;

    } else {
        repair_num = xqc_max(1, conn->conn_settings.fec_params.fec_max_symbol_num_per_block * conn->conn_settings.fec_params.fec_code_rate);
        fec_ctl->fec_send_required_repair_num[XQC_DEFAULT_SIZE_REQ] = xqc_min(repair_num, XQC_REPAIR_LEN);
    }

    if (conn->conn_settings.enable_multipath) {
        fec_ctl->fec_mp_mode = conn->conn_settings.fec_params.fec_mp_mode;
    }
    fec_ctl->fec_rep_path_id = XQC_MAX_UINT64_VALUE;

    for (i = 0; i < XQC_REPAIR_LEN; i++) {
        unsigned char *recv_syb_p = xqc_calloc(XQC_MAX_SYMBOL_SIZE, sizeof(unsigned char));
        if (recv_syb_p == NULL) {
            goto process_emalloc;
        }
        xqc_set_object_value(&fec_ctl->fec_gen_repair_symbols_buff[i], 0, recv_syb_p, 0);
    }

    for (i = 0; i < XQC_BLOCK_MODE_LEN; i++) {
        if (i == XQC_SLIM_SIZE_REQ) {
            continue;
        }
        fec_ctl->fec_send_block_num[i] = i;
        for (j = 0; j < XQC_REPAIR_LEN; j++) {
            unsigned char *key_p = xqc_calloc(XQC_MAX_RPR_KEY_SIZE, sizeof(unsigned char));
            if (key_p == NULL) {
                goto process_emalloc;
            }
            xqc_set_object_value(&fec_ctl->fec_send_repair_key[i][j], 0, key_p, 0);

            unsigned char *syb_p = xqc_calloc(XQC_MAX_SYMBOL_SIZE, sizeof(unsigned char));
            if (syb_p == NULL) {
                goto process_emalloc;
            }
            xqc_set_object_value(&fec_ctl->fec_send_repair_symbols_buff[i][j], 0, syb_p, 0);
        }
    }

    for (i = 0; i < XQC_FEC_BLOCK_NUM; i++) {
        fec_ctl->latest_stream_id[i] = -1;
    }

    // FEC 2.0: init repair symbols list and source symbols list
    fec_ctl->fec_src_syb_num = 0;
    fec_ctl->fec_rpr_syb_num = 0;
    xqc_init_list_head(&fec_ctl->fec_recv_rpr_syb_list);
    xqc_init_list_head(&fec_ctl->fec_recv_src_syb_list);
    xqc_init_list_head(&fec_ctl->fec_free_src_list);
    xqc_init_list_head(&fec_ctl->fec_free_rpr_list);

    return fec_ctl;
process_emalloc:
    xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|create_fec_ctl fail to malloc for params");
    xqc_fec_ctl_destroy(fec_ctl);
    return NULL;
}

void
xqc_fec_ctl_destroy(xqc_fec_ctl_t *fec_ctl)
{
    xqc_int_t i, j;
    xqc_list_head_t *pos, *next;

    fec_ctl->fec_flow_id = 0;
    for (i = 0; i < XQC_REPAIR_LEN; i++) {
        if (fec_ctl->fec_gen_repair_symbols_buff[i].payload != NULL) {
            xqc_free(fec_ctl->fec_gen_repair_symbols_buff[i].payload);
            fec_ctl->fec_gen_repair_symbols_buff[i].is_valid = 0;
        }
    }

    for (i = 0; i < XQC_BLOCK_MODE_LEN; i++) {
        if (i == XQC_SLIM_SIZE_REQ) {
            continue;
        }
        fec_ctl->fec_send_symbol_num[i] = 0;
        fec_ctl->fec_send_block_num[i] = 0;
        for (j = 0; j < XQC_REPAIR_LEN; j++) {
            if (fec_ctl->fec_send_repair_key[i][j].payload != NULL) {
                xqc_free(fec_ctl->fec_send_repair_key[i][j].payload);
                fec_ctl->fec_send_repair_key[i][j].is_valid = 0;
            }
            if (fec_ctl->fec_send_repair_symbols_buff[i][j].payload != NULL) {
                xqc_free(fec_ctl->fec_send_repair_symbols_buff[i][j].payload);
                fec_ctl->fec_send_repair_symbols_buff[i][j].is_valid = 0;
            }
        }
    }

    xqc_list_for_each_safe(pos, next, &fec_ctl->fec_recv_src_syb_list) {
        xqc_fec_src_syb_t *symbol = xqc_list_entry(pos, xqc_fec_src_syb_t, fec_list);
        xqc_free(symbol->payload);
        xqc_free(symbol);
    }

    xqc_list_for_each_safe(pos, next, &fec_ctl->fec_recv_rpr_syb_list) {
        xqc_fec_rpr_syb_t *symbol = xqc_list_entry(pos, xqc_fec_rpr_syb_t, fec_list);
        xqc_free(symbol->payload);
        xqc_free(symbol);
    }

    xqc_list_for_each_safe(pos, next, &fec_ctl->fec_free_src_list) {
        xqc_fec_src_syb_t *symbol = xqc_list_entry(pos, xqc_fec_src_syb_t, fec_list);
        xqc_free(symbol->payload);
        xqc_free(symbol);
    }

    xqc_list_for_each_safe(pos, next, &fec_ctl->fec_free_rpr_list) {
        xqc_fec_rpr_syb_t *symbol = xqc_list_entry(pos, xqc_fec_rpr_syb_t, fec_list);
        xqc_free(symbol->payload);
        xqc_free(symbol->repair_key);
        xqc_free(symbol->recv_mask);
        xqc_free(symbol);
    }
    
    xqc_free(fec_ctl);
}

void
xqc_set_fec_blk_size(xqc_connection_t *conn, xqc_transport_params_t params)
{
    switch (params.fec_version) {
    case XQC_FEC_02:
        xqc_memcpy(conn->fec_ctl->fec_send_block_mode_size, fec_blk_size_v2, XQC_BLOCK_MODE_LEN);
        break;

    default:
        break;
    }
}

uint8_t
xqc_get_fec_blk_size(xqc_connection_t *conn, uint8_t blk_md) {
    if (blk_md == XQC_DEFAULT_SIZE_REQ) {
        return xqc_min(XQC_FEC_MAX_SYMBOL_NUM_PBLOCK, xqc_max(0, conn->conn_settings.fec_params.fec_max_symbol_num_per_block));
    }
    return conn->fec_ctl->fec_send_block_mode_size[blk_md];
}

xqc_int_t
xqc_fec_ctl_save_symbol(unsigned char **symbol_buff_addr, const unsigned char *data,
    xqc_int_t data_len)
{
    if (*symbol_buff_addr == NULL) {
        return -XQC_EMALLOC;
    }
    xqc_memset(*symbol_buff_addr, 0, data_len);
    xqc_memcpy(*symbol_buff_addr, data, data_len);
    return XQC_OK;
}

xqc_int_t
xqc_fec_ctl_init_send_params(xqc_connection_t *conn, uint8_t bm_idx)
{
    double loss_rate;
    uint32_t send_repair_num;
    xqc_int_t i, symbol_size, key_size;
    xqc_fec_ctl_t *fec_ctl = conn->fec_ctl;

    symbol_size = key_size = 0;
    fec_ctl->fec_send_symbol_num[bm_idx] = 0;

    for (i = 0 ; i < XQC_REPAIR_LEN; i++) {
        if (conn->conn_settings.fec_params.fec_encoder_scheme != XQC_REED_SOLOMON_CODE) {
            if (fec_ctl->fec_send_repair_key[bm_idx][i].is_valid) {
                fec_ctl->fec_send_repair_key[bm_idx][i].payload_size = XQC_MAX_RPR_KEY_SIZE;
                xqc_init_object_value(&fec_ctl->fec_send_repair_key[bm_idx][i]);
            }
        }
        if (fec_ctl->fec_send_repair_symbols_buff[bm_idx][i].is_valid) {
            fec_ctl->fec_send_repair_symbols_buff[bm_idx][i].payload_size = XQC_MAX_SYMBOL_SIZE;
            xqc_init_object_value(&fec_ctl->fec_send_repair_symbols_buff[bm_idx][i]);
        }
    }
    // each time init send param, add 1 to send_block_num, so that symbol from different block won't be mixed
    if (conn->fec_ctl->fec_send_block_num[bm_idx] >= XQC_FEC_MAX_BLOCK_NUM - XQC_BLOCK_MODE_LEN) {
        conn->fec_ctl->fec_send_block_num[bm_idx] = bm_idx;

    } else {
        conn->fec_ctl->fec_send_block_num[bm_idx] += XQC_BLOCK_MODE_LEN;
    }

    if (conn->conn_settings.fec_params.fec_code_rate == 0 && conn->conn_settings.fec_params.fec_encoder_scheme != XQC_XOR_CODE) {
        loss_rate = xqc_conn_recent_loss_rate(conn);
        send_repair_num = xqc_min(XQC_REPAIR_LEN, xqc_max(1, (int)(loss_rate * xqc_get_fec_blk_size(conn, bm_idx) / 100)));
        if (conn->fec_ctl->fec_send_required_repair_num[bm_idx] != send_repair_num) {
            // edit encode repair key
            conn->fec_ctl->fec_send_required_repair_num[bm_idx] = send_repair_num;
            conn->conn_settings.fec_callback.xqc_fec_init_one(conn, bm_idx);
        }
    }
    return XQC_OK;
}

void
xqc_set_object_value(xqc_fec_object_t *object, xqc_int_t is_valid,
    unsigned char *payload, size_t size)
{
    object->is_valid = is_valid;
    object->payload = payload;
    object->payload_size = xqc_min(XQC_MAX_SYMBOL_SIZE, size);
}

void
xqc_init_object_value(xqc_fec_object_t *object)
{
    object->is_valid = 0;
    xqc_memset(object->payload, 0, object->payload_size);
    object->payload_size = 0;
}

void
xqc_init_src_symbol_value(xqc_fec_src_syb_t *symbol)
{
    symbol->block_id = 0;
    symbol->symbol_idx = 0;
    xqc_memset(symbol->payload, 0, xqc_min(XQC_MAX_SYMBOL_SIZE, symbol->payload_size));
    symbol->payload_size = 0;
}

void
xqc_init_rpr_symbol_value(xqc_fec_rpr_syb_t *symbol)
{
    symbol->block_id = 0;
    symbol->symbol_idx = 0;
    xqc_memset(symbol->payload, 0, XQC_MAX_SYMBOL_SIZE);
    symbol->payload_size = 0;
    xqc_memset(symbol->repair_key, 0, XQC_MAX_RPR_KEY_SIZE);
    xqc_memset(symbol->recv_mask, 0, XQC_MAX_RPR_KEY_SIZE);
    symbol->repair_key_size = 0;
}

void
xqc_remove_src_symbol_from_list(xqc_fec_ctl_t *fec_ctl, xqc_fec_src_syb_t *src_symbol)
{
    xqc_list_del_init(&src_symbol->fec_list);
    xqc_init_src_symbol_value(src_symbol);
    // save payload for further uses
    xqc_list_add_tail(&src_symbol->fec_list, &fec_ctl->fec_free_src_list);
    fec_ctl->fec_src_syb_num--;
}

void
xqc_remove_rpr_symbol_from_list(xqc_fec_ctl_t *fec_ctl, xqc_fec_rpr_syb_t *rpr_symbol)
{
    xqc_list_del_init(&rpr_symbol->fec_list);
    xqc_init_rpr_symbol_value(rpr_symbol);
    // save payload for further uses
    xqc_list_add_tail(&rpr_symbol->fec_list, &fec_ctl->fec_free_rpr_list);
    fec_ctl->fec_rpr_syb_num--;
}

xqc_int_t
xqc_fec_ctl_init_recv_params(xqc_fec_ctl_t *fec_ctl, uint64_t block_id)
{
    xqc_int_t j, symbol_size, key_size;
    xqc_list_head_t *pos, *next;


    // FEC 2.0 update symbols list
    xqc_list_for_each_safe(pos, next, &fec_ctl->fec_recv_src_syb_list) {
        xqc_fec_src_syb_t *src_symbol = xqc_list_entry(pos, xqc_fec_src_syb_t, fec_list);
        if (src_symbol->block_id > block_id) {
            break;
        }
        if (src_symbol->block_id == block_id) {
            xqc_remove_src_symbol_from_list(fec_ctl, src_symbol);
        }
    }

    xqc_list_for_each_safe(pos, next, &fec_ctl->fec_recv_rpr_syb_list) {
        xqc_fec_rpr_syb_t *rpr_symbol = xqc_list_entry(pos, xqc_fec_rpr_syb_t, fec_list);
        if (rpr_symbol->block_id > block_id) {
            break;
        }
        if (rpr_symbol->block_id == block_id) {
            xqc_remove_rpr_symbol_from_list(fec_ctl, rpr_symbol);
        }
    }

    return XQC_OK;
}

xqc_int_t
xqc_negotiate_fec_schemes(xqc_connection_t *conn, xqc_transport_params_t params)
{
    xqc_int_t ret, encode_scheme, decode_scheme;
    xqc_trans_settings_t *ls = &conn->local_settings;
    ret = -XQC_EFEC_NOT_SUPPORT_FEC;
    /*
     * 如果对端发来了多种FEC schemes选择，接收端需要选择其中的一种FEC schemes并重新encode local_settings
     * AS Server：
     * 如果FEC协商成功 且 收到的FEC schemes列表长度大于1，需要进行选择；
     * 随后需要进行重新设置并encode选择完成后的schemes list，其长度必须为1；
     * AS Client：
     * 需要设置服务端选择的FEC Scheme至conn_settings
     */
    if (params.fec_version == XQC_ERR_FEC_VERSION) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|remote fec version is not supported.");
        conn->fec_neg_fail_reason |= XQC_OLD_FEC_VERSION;
        return ret;
    }

    if (ls->enable_encode_fec && params.enable_decode_fec) {
        // server should provide only 1 scheme if negotiation success;
        if (conn->conn_type == XQC_CONN_TYPE_CLIENT
            && params.fec_decoder_schemes_num > 1) 
        {
            conn->fec_neg_fail_reason |= XQC_CLIENT_RECEIVE_INV_DEC;
            goto set_decoder;
        }

        encode_scheme = xqc_set_final_scheme(conn, ls->fec_encoder_schemes, &ls->fec_encoder_schemes_num,
                                             params.fec_decoder_schemes, params.fec_decoder_schemes_num);
        if (encode_scheme == 0) {
            ls->enable_encode_fec = 0;
            conn->conn_settings.enable_encode_fec = 0;
            conn->fec_neg_fail_reason |= XQC_NO_COMMON_FEC_ENC;
            xqc_log(conn->log, XQC_LOG_DEBUG, "|quic_fec|negotiate fec encoder schemes failed.");
            goto set_decoder;
        }
        // set valid encoder scheme
        ret = xqc_set_valid_encoder_scheme_cb(&conn->conn_settings.fec_callback, encode_scheme);
        if (ret != XQC_OK) {
            ls->enable_encode_fec = 0;
            conn->conn_settings.enable_encode_fec = 0;
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|set fec encoder cb failed with scheme num: %d", encode_scheme);
            goto set_decoder;
        }
        conn->conn_settings.fec_params.fec_encoder_scheme = encode_scheme;
        // change fec scheme in local_settings
        ls->fec_encoder_schemes[0] = conn->conn_settings.fec_params.fec_encoder_scheme;
        ls->fec_encoder_schemes_num = 1;
        xqc_log(conn->log, XQC_LOG_INFO, "|set final encoder fec scheme: %s|fec_level: %s|",
                xqc_get_fec_scheme_str(conn->conn_settings.fec_params.fec_encoder_scheme), xqc_get_fec_enc_level_str(conn->conn_settings.fec_level));
        ret = XQC_OK;
    }

set_decoder:
    if (ls->enable_decode_fec && params.enable_encode_fec) {
        // server should provide only 1 scheme if negotiation success;
        if (conn->conn_type == XQC_CONN_TYPE_CLIENT
            && params.fec_encoder_schemes_num > 1) 
        {
            conn->fec_neg_fail_reason |= XQC_CLIENT_RECEIVE_INV_ENC;
            goto end;
        }

        decode_scheme = xqc_set_final_scheme(conn, ls->fec_decoder_schemes, &ls->fec_decoder_schemes_num,
                                             params.fec_encoder_schemes, params.fec_encoder_schemes_num);
        if (decode_scheme == 0) {
            ls->enable_decode_fec = 0;
            conn->conn_settings.enable_decode_fec = 0;
            conn->fec_neg_fail_reason |= XQC_NO_COMMON_FEC_DEC;
            xqc_log(conn->log, XQC_LOG_DEBUG, "|quic_fec|negotiate fec decoder schemes failed.");
            goto end;
        }
        // set valid encoder scheme
        ret = xqc_set_valid_decoder_scheme_cb(&conn->conn_settings.fec_callback, decode_scheme);
        if (ret != XQC_OK) {
            ls->enable_decode_fec = 0;
            conn->conn_settings.enable_decode_fec = 0;
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|set fec decoder cb failed with scheme num: %d", decode_scheme);
            goto end;
        }
        conn->conn_settings.fec_params.fec_decoder_scheme = decode_scheme;
        // change fec scheme in local_settings
        ls->fec_decoder_schemes[0] = conn->conn_settings.fec_params.fec_decoder_scheme;
        ls->fec_decoder_schemes_num = 1;
        xqc_log(conn->log, XQC_LOG_INFO, "|set final decoder fec scheme: %s",
                xqc_get_fec_scheme_str(conn->conn_settings.fec_params.fec_decoder_scheme));
        ret = XQC_OK;
    }
end:
    if (conn->conn_type == XQC_CONN_TYPE_CLIENT) {
        if (conn->conn_settings.fec_params.fec_encoder_scheme == 0) {
            conn->conn_settings.enable_encode_fec = 0;
            xqc_log(conn->log, XQC_LOG_DEBUG, "|quic_fec|negotiate fec encoder schemes failed.");
        }
        if (conn->conn_settings.fec_params.fec_decoder_scheme == 0) {
            conn->conn_settings.enable_decode_fec = 0;
            xqc_log(conn->log, XQC_LOG_DEBUG, "|quic_fec|negotiate fec decoder schemes failed.");
        }
    }
    return ret;
}
xqc_int_t
xqc_insert_src_symbol_by_seq(xqc_connection_t *conn, xqc_list_head_t *symbol_list, 
    uint64_t block_id, uint64_t symbol_idx, xqc_int_t *blk_output,
    unsigned char *symbol, xqc_int_t symbol_size)
{
    xqc_list_head_t *pos, *next;
    xqc_int_t        ret, blk_num_flag;
    xqc_fec_src_syb_t *src_symbol;
    
    ret = 0;
    blk_num_flag = 1;
    src_symbol = NULL;

    xqc_list_for_each_reverse_safe(pos, next, symbol_list) {
            xqc_fec_src_syb_t *cur_symbol = xqc_list_entry(pos, xqc_fec_src_syb_t, fec_list);
            if (block_id < cur_symbol->block_id) {
                continue;
            }
            if (block_id == cur_symbol->block_id) {
                if (symbol_idx < cur_symbol->symbol_idx) {
                    continue;

                } else if (cur_symbol->symbol_idx == symbol_idx) {
                    // current symbol already exists.
                    return -XQC_EFEC_TOLERABLE_ERROR;
                }   
            }
            break;

    }

    // push into src symbol list;
    src_symbol = xqc_build_src_symbol(conn, block_id, symbol_idx, symbol, symbol_size);
    if (src_symbol == NULL) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|quic_fec|build source symbol error|block_id:%d|symbol_idx:%d|symbol_size:%d", block_id, symbol_idx, symbol_size);
        return -XQC_EMALLOC;
    }

    // insert into proper position
    xqc_list_add(&src_symbol->fec_list, pos);
    *blk_output += 1;
    return XQC_OK;
}

xqc_int_t
xqc_insert_rpr_symbol_by_seq(xqc_connection_t *conn, xqc_list_head_t *symbol_list, 
    xqc_fec_rpr_syb_t *tmp_rpr_symbol, xqc_int_t *blk_output, xqc_fec_rpr_syb_t **rpr_symbol)
{
    xqc_list_head_t *pos, *next;
    xqc_int_t        ret, blk_num_flag, window_limit, block_id, symbol_idx;

    ret = 0;
    blk_num_flag = 1;
    window_limit = conn->conn_settings.fec_params.fec_max_window_size;
    *rpr_symbol = NULL;
    block_id = tmp_rpr_symbol->block_id;
    symbol_idx = tmp_rpr_symbol->symbol_idx;

    if (block_id < 0) {
        return -XQC_EFEC_SYMBOL_ERROR;
    }

    xqc_list_for_each_reverse_safe(pos, next, symbol_list) {
        xqc_fec_rpr_syb_t *cur_symbol = xqc_list_entry(pos, xqc_fec_rpr_syb_t, fec_list);
        if (block_id < cur_symbol->block_id) {
            continue;
        }

        if (block_id == cur_symbol->block_id) {
            if (symbol_idx < cur_symbol->symbol_idx) {
                continue;

            } else if (cur_symbol->symbol_idx == symbol_idx) {
                // current symbol already exists.
                return -XQC_EFEC_TOLERABLE_ERROR;
            }
        }
        break;
    }

    // insert into rpr symbol list;
    *rpr_symbol = xqc_build_rpr_symbol(conn, tmp_rpr_symbol);
    if (*rpr_symbol == NULL) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|quic_fec|build repair symbol error|block_id:%d|symbol_idx:%d|symbol_size:%d", block_id, symbol_idx, tmp_rpr_symbol->payload_size);
        return -XQC_EMALLOC;
    }

    // insert into proper position
    xqc_list_add(&(*rpr_symbol)->fec_list, pos);
    *blk_output += 1;
    return XQC_OK;
}


xqc_fec_src_syb_t *
xqc_create_src_symbol()
{
    xqc_fec_src_syb_t *src_symbol = (xqc_fec_src_syb_t *)xqc_calloc(1, sizeof(xqc_fec_src_syb_t));
    if (src_symbol == NULL) {
        return NULL;
    }

    src_symbol->payload = xqc_calloc(XQC_MAX_SYMBOL_SIZE, sizeof(unsigned char));
    if (src_symbol->payload == NULL) {
        xqc_free(src_symbol);
        return NULL;
    }

    return src_symbol;
}

xqc_fec_rpr_syb_t *
xqc_create_rpr_symbol()
{
    xqc_fec_rpr_syb_t *rpr_symbol = (xqc_fec_rpr_syb_t *)xqc_calloc(1, sizeof(xqc_fec_rpr_syb_t));
    if (rpr_symbol == NULL) {
        return NULL;
    }
    rpr_symbol->payload = xqc_calloc(XQC_MAX_SYMBOL_SIZE, sizeof(unsigned char));
    rpr_symbol->repair_key = xqc_calloc(XQC_MAX_RPR_KEY_SIZE, sizeof(unsigned char));
    rpr_symbol->recv_mask = xqc_calloc(XQC_MAX_RPR_KEY_SIZE, sizeof(unsigned char));
    if (rpr_symbol->payload == NULL || rpr_symbol->repair_key == NULL || rpr_symbol->recv_mask == NULL) {
        if (rpr_symbol->payload != NULL) {
            xqc_free(rpr_symbol->payload);
        }
        if (rpr_symbol->repair_key != NULL) {
            xqc_free(rpr_symbol->repair_key);
        }
        if (rpr_symbol->recv_mask != NULL) {
            xqc_free(rpr_symbol->recv_mask);
        }
        xqc_free(rpr_symbol);
        return NULL;
    }
    return rpr_symbol;
}

xqc_fec_src_syb_t *
xqc_new_src_symbol(xqc_list_head_t *fec_free_list)
{
    // try to fetch an available symbol in free list, otherwise malloc a new space
    xqc_list_head_t *pos, *next;
    xqc_fec_src_syb_t *src_symbol;

    xqc_list_for_each_safe(pos, next, fec_free_list) {
        src_symbol = xqc_list_entry(pos, xqc_fec_src_syb_t, fec_list);
        xqc_list_del_init(&src_symbol->fec_list);
        if (src_symbol->payload == NULL) {
            xqc_free(src_symbol);
            return NULL;
        }
        return src_symbol;
    }
    return xqc_create_src_symbol();
}

xqc_fec_rpr_syb_t *
xqc_new_rpr_symbol(xqc_list_head_t *fec_free_list)
{
    // try to fetch an available symbol in free list, otherwise malloc a new space
    xqc_list_head_t *pos, *next;
    xqc_fec_rpr_syb_t *rpr_symbol;

    xqc_list_for_each_safe(pos, next, fec_free_list) {
        rpr_symbol = xqc_list_entry(pos, xqc_fec_rpr_syb_t, fec_list);
        xqc_list_del_init(&rpr_symbol->fec_list);
        return rpr_symbol;
    }
    return xqc_create_rpr_symbol();
}

xqc_fec_rpr_syb_t *
xqc_get_rpr_symbol(xqc_list_head_t *head, uint64_t block_id, uint64_t symbol_id)
{
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, head) {
        xqc_fec_rpr_syb_t *symbol = xqc_list_entry(pos, xqc_fec_rpr_syb_t, fec_list);
        if (symbol->block_id > block_id) {
            break;
        }
        if (symbol->block_id == block_id) {
            if (symbol->symbol_idx > symbol_id) {
                break;
            }
            if (symbol->symbol_idx == symbol_id){
                return symbol;
            }
        }
    }
    return NULL;
}

void
xqc_update_rpr_symbol_mask_on_src(xqc_list_head_t *head, xqc_int_t block_id,
    xqc_int_t pi_sym_idx)
{
    xqc_list_head_t *pos, *next;
    xqc_int_t mask_offset;

    mask_offset = pi_sym_idx / 8;

    if (mask_offset >= XQC_MAX_RPR_KEY_SIZE) {
        return;
    }

    // traverse rpr list
    xqc_list_for_each_safe(pos, next, head) {
        xqc_fec_rpr_syb_t *symbol = xqc_list_entry(pos, xqc_fec_rpr_syb_t, fec_list);
        if (symbol->block_id > block_id) {
            break;
        }

        if (symbol->block_id == block_id
            && *(symbol->repair_key + mask_offset) & (1 << (7 - pi_sym_idx % 8)))
        {
            *(symbol->recv_mask + mask_offset) |= (1 << (7 - pi_sym_idx % 8));
        }
    }
}

void
xqc_update_rpr_symbol_mask_on_rpr(xqc_list_head_t *head, xqc_fec_rpr_syb_t *rpr_symbol)
{
    xqc_list_head_t *pos, *next;
    
    // traverse src list
    xqc_list_for_each_safe(pos, next, head) {
        xqc_fec_src_syb_t *symbol = xqc_list_entry(pos, xqc_fec_src_syb_t, fec_list);
        xqc_int_t block_id, symbol_idx, mask_offset;

        block_id = symbol->block_id;
        symbol_idx = symbol->symbol_idx;
        mask_offset = symbol_idx / 8;

        if (mask_offset >= XQC_MAX_RPR_KEY_SIZE) {
            continue;
        }

        if (block_id > rpr_symbol->block_id) {
            break;
        }

        if (block_id == rpr_symbol->block_id
            && *(rpr_symbol->repair_key + mask_offset) & (1 << (7 - symbol_idx % 8)))
        {
            *(rpr_symbol->recv_mask + mask_offset) |= (1 << (7 - symbol_idx % 8));
        }
    }
}


xqc_fec_src_syb_t *
xqc_build_src_symbol(xqc_connection_t *conn, uint64_t block_id, uint64_t symbol_idx,
    unsigned char *symbol, xqc_int_t symbol_size)
{
    xqc_int_t is_repair_symbol = 0, ret;
    xqc_list_head_t *fec_free_src_list;
    xqc_fec_src_syb_t *src_symbol = NULL;
    
    if (symbol_size > XQC_MAX_SYMBOL_SIZE) {
        return src_symbol;
    }

    fec_free_src_list = &conn->fec_ctl->fec_free_src_list;
    src_symbol = xqc_new_src_symbol(fec_free_src_list);
    if (src_symbol == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|get src symbol error|");
        return NULL;
    }
    src_symbol->block_id = block_id;
    src_symbol->symbol_idx = symbol_idx;
    xqc_memcpy(src_symbol->payload, symbol, symbol_size);
    src_symbol->payload_size = symbol_size;
    xqc_init_list_head(&src_symbol->fec_list);

    return src_symbol;
}


xqc_fec_rpr_syb_t *
xqc_build_rpr_symbol(xqc_connection_t *conn, xqc_fec_rpr_syb_t *tmp_rpr_symbol)
{
    size_t symbol_size, repair_key_size;
    xqc_int_t is_repair_symbol = 1, ret;
    xqc_list_head_t *fec_free_rpr_list;
    xqc_fec_rpr_syb_t *rpr_symbol = NULL;

    symbol_size = tmp_rpr_symbol->payload_size;
    repair_key_size = tmp_rpr_symbol->repair_key_size;

    if (symbol_size > XQC_MAX_SYMBOL_SIZE || repair_key_size > XQC_MAX_RPR_KEY_SIZE) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|invalid symbol params|symbol_size:%d|symbol_key_size:%d|", symbol_size, repair_key_size);
        return rpr_symbol;
    }

    fec_free_rpr_list = &conn->fec_ctl->fec_free_rpr_list;
    rpr_symbol = xqc_new_rpr_symbol(fec_free_rpr_list);

    if (rpr_symbol == NULL || rpr_symbol->payload == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|get rpr symbol error|");
        return rpr_symbol;
    }
    rpr_symbol->block_id = tmp_rpr_symbol->block_id;
    rpr_symbol->symbol_idx = tmp_rpr_symbol->symbol_idx;
    xqc_memcpy(rpr_symbol->payload, tmp_rpr_symbol->payload, symbol_size);
    rpr_symbol->payload_size = symbol_size;
    xqc_memcpy(rpr_symbol->repair_key, tmp_rpr_symbol->repair_key, repair_key_size);
    rpr_symbol->repair_key_size = repair_key_size;
    xqc_init_list_head(&rpr_symbol->fec_list);

    return rpr_symbol;
}

xqc_int_t
xqc_get_min_src_blk_num(xqc_connection_t *conn)
{   
    xqc_fec_ctl_t *fec_ctl = conn->fec_ctl;
    if (!xqc_list_empty(&fec_ctl->fec_recv_src_syb_list)) {
        xqc_fec_src_syb_t *src_symbol = xqc_list_entry(fec_ctl->fec_recv_src_syb_list.next, xqc_fec_src_syb_t, fec_list);
        return src_symbol->block_id;
    }
    return -1;
}

xqc_int_t
xqc_get_min_rpr_blk_num(xqc_connection_t *conn)
{   
    xqc_fec_ctl_t *fec_ctl = conn->fec_ctl;
    if (!xqc_list_empty(&fec_ctl->fec_recv_rpr_syb_list)) {
        xqc_fec_rpr_syb_t *rpr_symbol = xqc_list_entry(fec_ctl->fec_recv_rpr_syb_list.next, xqc_fec_rpr_syb_t, fec_list);
        return rpr_symbol->block_id;
    }
    return -1;
}


xqc_bool_t
xqc_if_src_blk_exists(xqc_fec_ctl_t *fec_ctl, uint64_t block_id)
{
    xqc_list_head_t  *pos, *next;

    xqc_list_for_each_safe(pos, next, &fec_ctl->fec_recv_src_syb_list) {
        xqc_fec_src_syb_t *src_symbol = xqc_list_entry(pos, xqc_fec_src_syb_t, fec_list);
        if (src_symbol->block_id == block_id) {
            return XQC_TRUE;
        }
    }
    return XQC_FALSE;
}

xqc_bool_t
xqc_if_rpr_blk_exists(xqc_fec_ctl_t *fec_ctl, uint64_t block_id)
{
    xqc_list_head_t  *pos, *next;

    xqc_list_for_each_safe(pos, next, &fec_ctl->fec_recv_rpr_syb_list) {
        xqc_fec_rpr_syb_t *rpr_symbol = xqc_list_entry(pos, xqc_fec_rpr_syb_t, fec_list);
        if (rpr_symbol->block_id == block_id) {
            return XQC_TRUE;
        }
    }
    return XQC_FALSE;
}


xqc_int_t
xqc_process_src_symbol(xqc_connection_t *conn, uint64_t block_id, uint64_t symbol_idx,
    unsigned char *symbol, xqc_int_t symbol_size)
{
    xqc_int_t           ret, window_size, min_block_id;
    xqc_fec_ctl_t       *fec_ctl;
    xqc_list_head_t     *symbol_list, *rpr_list;
    xqc_fec_src_syb_t   *src_symbol;
    
    window_size = conn->conn_settings.fec_params.fec_max_window_size;
    fec_ctl = conn->fec_ctl;
    symbol_list = &conn->fec_ctl->fec_recv_src_syb_list;
    src_symbol = NULL;

    if (block_id != 0
        && !xqc_if_src_blk_exists(conn->fec_ctl, block_id)
        && block_id <= conn->fec_ctl->fec_max_fin_blk_id)
    {
        return -XQC_EFEC_TOLERABLE_ERROR;
    }

    if (conn->fec_ctl->fec_src_syb_num > window_size
        && !xqc_if_src_blk_exists(conn->fec_ctl, block_id))
    {
        while (conn->fec_ctl->fec_src_syb_num > window_size) {
            min_block_id = xqc_get_min_src_blk_num(conn);
            if (min_block_id == -1) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|window_size and src_symbol_list length is not match");
                return -XQC_EFEC_TOLERABLE_ERROR;
            }
            // flush the smallest old block
            xqc_fec_ctl_init_recv_params(conn->fec_ctl, min_block_id);
        }
    }

    // insert into src symbol_list according to block id and symbol idx
    ret = xqc_insert_src_symbol_by_seq(conn, symbol_list, block_id, symbol_idx, &conn->fec_ctl->fec_src_syb_num, symbol, symbol_size);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|quic_fec|current symbol is already exists|block_id:%d|symbol_idx:%d", block_id, symbol_idx);
        return ret;
    }

    // update repair symbol recv_mask
    if (conn->conn_settings.fec_params.fec_decoder_scheme == XQC_PACKET_MASK_CODE) {
        rpr_list = &conn->fec_ctl->fec_recv_rpr_syb_list;
        xqc_update_rpr_symbol_mask_on_src(rpr_list, block_id, symbol_idx);
    }

    return XQC_OK;
} 


xqc_int_t
xqc_process_rpr_symbol(xqc_connection_t *conn, xqc_fec_rpr_syb_t *tmp_rpr_symbol)
{
    xqc_int_t           ret, window_size, min_block_id, block_id;
    xqc_fec_ctl_t       *fec_ctl;
    xqc_list_head_t     *symbol_list, *src_list;
    xqc_fec_rpr_syb_t   *rpr_symbol;

    window_size = conn->conn_settings.fec_params.fec_max_window_size;
    fec_ctl = conn->fec_ctl;
    symbol_list = &conn->fec_ctl->fec_recv_rpr_syb_list;
    rpr_symbol = NULL;
    min_block_id = xqc_get_min_rpr_blk_num(conn);
    block_id = tmp_rpr_symbol->block_id;

    if (block_id != 0
        && !xqc_if_src_blk_exists(conn->fec_ctl, block_id)
        && block_id <= conn->fec_ctl->fec_max_fin_blk_id)
    {
        return -XQC_EFEC_TOLERABLE_ERROR;
    }

    if (conn->fec_ctl->fec_rpr_syb_num > window_size
        && !xqc_if_rpr_blk_exists(conn->fec_ctl, block_id))
    {
        while (conn->fec_ctl->fec_rpr_syb_num > window_size) {
            min_block_id = xqc_get_min_rpr_blk_num(conn);
            if (min_block_id == -1) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|window_size and rpr_symbol_list length is not match");
                return -XQC_EFEC_TOLERABLE_ERROR;
            }
            // flush the smallest old block
            xqc_fec_ctl_init_recv_params(conn->fec_ctl, min_block_id);
        }
    }

    // insert into src symbol_list according to block id and symbol idx
    ret = xqc_insert_rpr_symbol_by_seq(conn, symbol_list, tmp_rpr_symbol, &conn->fec_ctl->fec_rpr_syb_num, &rpr_symbol);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|quic_fec|current symbol is already exists|block_id:%d|symbol_idx:%d", block_id, tmp_rpr_symbol->symbol_idx);
        return ret;
    }

    // link src symbols to the rpr symbols using pkt mask
    if (conn->conn_settings.fec_params.fec_decoder_scheme == XQC_PACKET_MASK_CODE) {
        src_list = &conn->fec_ctl->fec_recv_src_syb_list;
        xqc_update_rpr_symbol_mask_on_rpr(src_list, rpr_symbol);
        tmp_rpr_symbol->recv_mask = rpr_symbol->recv_mask;
    }
    rpr_symbol->recv_time = xqc_monotonic_timestamp();

    return XQC_OK;
}

xqc_int_t
xqc_get_symbol_flag(xqc_connection_t *conn, uint64_t block_id)
{
    xqc_list_head_t *pos, *next;
    xqc_int_t symbol_flag, max_src_symbol_num;
    
    symbol_flag = 0;
    max_src_symbol_num = conn->remote_settings.fec_max_symbols_num;

    xqc_list_for_each_safe(pos, next, &conn->fec_ctl->fec_recv_src_syb_list) {
        xqc_fec_src_syb_t *src_symbol = xqc_list_entry(pos, xqc_fec_src_syb_t, fec_list);
        if (src_symbol->block_id > block_id) {
            break;
        }
        if (src_symbol->block_id == block_id) {
            symbol_flag |= (1 << src_symbol->symbol_idx);
        }
    }
    xqc_list_for_each_safe(pos, next, &conn->fec_ctl->fec_recv_rpr_syb_list) {
        xqc_fec_rpr_syb_t *rpr_symbol = xqc_list_entry(pos, xqc_fec_rpr_syb_t, fec_list);
        if (rpr_symbol->block_id > block_id) {
            break;
        }
        if (rpr_symbol->block_id == block_id) {
            symbol_flag |= (1 << (rpr_symbol->symbol_idx + max_src_symbol_num));
        }
    }
    return symbol_flag;
}

xqc_int_t
xqc_get_symbols_buff(unsigned char **output, xqc_fec_ctl_t *fec_ctl, uint64_t block_id, size_t *size)
{
    xqc_list_head_t *pos, *next, *fec_recv_src_syb_list, *fec_recv_rpr_syb_list;
    xqc_int_t i = 0;

    fec_recv_src_syb_list = &fec_ctl->fec_recv_src_syb_list;
    fec_recv_rpr_syb_list = &fec_ctl->fec_recv_rpr_syb_list;
    *size = 0;

    // check 一下当前block idx能否成功被flush

    xqc_list_for_each_safe(pos, next, fec_recv_src_syb_list) {
        xqc_fec_src_syb_t *src_syb = xqc_list_entry(pos, xqc_fec_src_syb_t, fec_list);
        if (src_syb->block_id == block_id) {
            xqc_memcpy(output[i++], src_syb->payload, xqc_min(XQC_MAX_SYMBOL_SIZE, src_syb->payload_size));
        }
    }

    xqc_list_for_each_safe(pos, next, fec_recv_rpr_syb_list) {
        xqc_fec_rpr_syb_t *rpr_syb = xqc_list_entry(pos, xqc_fec_rpr_syb_t, fec_list);
        if (rpr_syb->block_id == block_id) {
            if (rpr_syb->payload_size > XQC_MAX_SYMBOL_SIZE) {
                return -XQC_EPARAM;   
            }
            xqc_memcpy(output[i++], rpr_syb->payload, xqc_min(XQC_MAX_SYMBOL_SIZE, rpr_syb->payload_size));
            if (rpr_syb->payload_size > *size) {
                *size = rpr_syb->payload_size;
            }
        }
    }
    return i;
}


xqc_int_t
xqc_cnt_src_symbols_num(xqc_fec_ctl_t *fec_ctl, uint64_t block_id)
{
    xqc_int_t ret = 0;
    xqc_list_head_t *pos, *next;
 
    xqc_list_for_each_safe(pos, next, &fec_ctl->fec_recv_src_syb_list) {
        xqc_fec_src_syb_t *src_symbol = xqc_list_entry(pos, xqc_fec_src_syb_t, fec_list);
        if (src_symbol->block_id > block_id) {
            break;
        }
        if (src_symbol->block_id == block_id) {
            ret++;
        }
    }
    return ret;
}

xqc_int_t
xqc_cnt_rpr_symbols_num(xqc_fec_ctl_t *fec_ctl, uint64_t block_id)
{
    xqc_int_t ret = 0;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &fec_ctl->fec_recv_rpr_syb_list) {
        xqc_fec_rpr_syb_t *rpr_symbol = xqc_list_entry(pos, xqc_fec_rpr_syb_t, fec_list);
        if (rpr_symbol->block_id > block_id) {
            break;
        }
        if (rpr_symbol->block_id == block_id) {
            ret++;
        }
    }
    return ret;
}

void
xqc_on_fec_negotiate_success(xqc_connection_t *conn, xqc_transport_params_t params)
{
    uint8_t i;
    if (conn->conn_settings.enable_encode_fec) {
        if (conn->conn_settings.fec_params.fec_encoder_scheme == XQC_PACKET_MASK_CODE) {
            xqc_set_fec_blk_size(conn, params);
            for (i = XQC_NORMAL_SIZE_REQ; i < XQC_BLOCK_MODE_LEN; i++) {
                if (conn->conn_settings.fec_params.fec_code_rate == 0) {
                    conn->fec_ctl->fec_send_required_repair_num[i] = 1;

                } else {
                    conn->fec_ctl->fec_send_required_repair_num[i] = xqc_min(xqc_max(1, conn->fec_ctl->fec_send_block_mode_size[i] * conn->conn_settings.fec_params.fec_code_rate), XQC_REPAIR_LEN);
                }
            }
        }
        if (conn->conn_settings.fec_callback.xqc_fec_init != NULL) {
            conn->conn_settings.fec_callback.xqc_fec_init(conn);
        }
    }
}

xqc_int_t
xqc_get_fec_rpr_num(float fec_code_rate, xqc_int_t src_syb_num)
{
    return xqc_min(XQC_REPAIR_LEN, xqc_max(1, xqc_min(src_syb_num, XQC_FEC_MAX_SYMBOL_NUM_PBLOCK) * fec_code_rate + 1));
}

void
xqc_fec_on_stream_size_changed(xqc_stream_t *quic_stream)
{
    float fec_code_rate;
    xqc_connection_t   *conn;
    uint32_t        src_syb_num, rpr_syb_num;

    conn = quic_stream->stream_conn;
    src_syb_num = xqc_min(quic_stream->stream_fec_ctl.stream_fec_syb_num, XQC_FEC_MAX_SYMBOL_NUM_PBLOCK);
    // fec_code_rate should be pre-set in bitrate_allocator
    fec_code_rate = conn->conn_settings.fec_params.fec_code_rate;
    rpr_syb_num = xqc_get_fec_rpr_num(fec_code_rate, src_syb_num);

    // if fec block size or repair number is different, init fec parameters
    if (conn->fec_ctl->fec_send_required_repair_num[0] != rpr_syb_num
        || conn->conn_settings.fec_params.fec_max_symbol_num_per_block != src_syb_num)
    {
        conn->fec_ctl->fec_send_required_repair_num[0] = rpr_syb_num;
        conn->conn_settings.fec_params.fec_max_symbol_num_per_block = src_syb_num;
        conn->conn_settings.fec_callback.xqc_fec_init_one(conn, 0);
    }
}