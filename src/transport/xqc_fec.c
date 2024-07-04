
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#include "src/transport/xqc_fec.h"
#include "src/transport/xqc_fec_scheme.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_fec_scheme.h"


#define XQC_FEC_MAX_SCHEME_VAL 32


xqc_int_t
xqc_is_fec_scheme_valid(xqc_fec_schemes_e scheme, xqc_fec_schemes_e *supported_schemes_buff,
    xqc_int_t supported_schemes_buff_len)
{
    for (xqc_int_t i = 0; i < supported_schemes_buff_len; i++) {
        if (scheme == supported_schemes_buff[i]
            && xqc_is_fec_cb_exist(scheme) == XQC_OK)
        {
            return XQC_OK;
        }
    }
    return -XQC_EFEC_NOT_SUPPORT_FEC;
}

xqc_int_t
xqc_is_fec_cb_exist(xqc_fec_schemes_e scheme)
{
    switch (scheme) {
    case XQC_REED_SOLOMON_CODE:
    case XQC_XOR_CODE:
        return XQC_OK;
    
    default:
        return -XQC_EFEC_NOT_SUPPORT_FEC;
    }
}

xqc_int_t
xqc_set_valid_scheme_cb(xqc_fec_code_callback_t *callback, xqc_int_t scheme)
{
    switch (scheme) {
    case XQC_REED_SOLOMON_CODE:
        *callback = xqc_reed_solomon_code_cb;
        return XQC_OK;
    case XQC_XOR_CODE:
        *callback = xqc_xor_code_cb;
        return XQC_OK;
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
    case XQC_PACKET_MASK:
        return "Packet-Mask";
    default:
        return "Unknown";
    }
}

xqc_int_t
xqc_set_final_scheme(xqc_connection_t *conn, xqc_fec_schemes_e *local_fec_schemes_buff, xqc_int_t *local_fec_schemes_buff_len,
    xqc_fec_schemes_e *remote_fec_schemes_buff, xqc_int_t remote_fec_schemes_buff_len, xqc_int_t *final_scheme, xqc_fec_code_callback_t *callback)
{
    uint32_t   p, schemes_flag;
    xqc_int_t  i;
    
    if (*local_fec_schemes_buff_len == 0 || remote_fec_schemes_buff_len == 0) {
        return -XQC_EFEC_NOT_SUPPORT_FEC;
    }

    p = schemes_flag = 0;
    *final_scheme = 0;

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
            *final_scheme = local_fec_schemes_buff[i];
            break;
        }
    }

    if (*final_scheme == 0) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|Neither of the client and server have the same FEC scheme.|");
        return -XQC_EFEC_NOT_SUPPORT_FEC;
    }

    if (xqc_set_valid_scheme_cb(callback, *final_scheme) != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_set_final_scheme|set valid scheme cb error|scheme_str: %s|scheme_num:%d|", xqc_get_fec_scheme_str(*final_scheme), *final_scheme);
        return -XQC_EFEC_SCHEME_ERROR;
    }

    local_fec_schemes_buff[0] = *final_scheme;
    *local_fec_schemes_buff_len = 1;
    xqc_log(conn->log, XQC_LOG_DEBUG, "|set final fec scheme: %s", xqc_get_fec_scheme_str(*final_scheme));
    return XQC_OK;
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
    case XQC_PACKET_MASK:
        *out = XQC_PACKET_MASK;
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
        case XQC_PACKET_MASK:
            fec_schemes_buff[j] = XQC_PACKET_MASK;
            j++;
            break;
        default:
            /* TODOfec: 失败报错, 缺少报错途径 */
            break;
        }

        if (j != *fec_schemes_buff_len) {
            *fec_schemes_buff_len = j;
        }
    }
    return XQC_OK;
}

xqc_int_t
xqc_is_packet_fec_protected(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    if (packet_out->po_frame_types & conn->conn_settings.fec_params.fec_protected_frames) {
        return XQC_OK;
    }
    return -XQC_EFEC_NOT_SUPPORT_FEC;
}

xqc_int_t
xqc_is_fec_params_valid(xqc_int_t src_symbol_num, xqc_int_t total_symbol_num,
    xqc_int_t max_window_size)
{
    if (src_symbol_num <= 0 || src_symbol_num > XQC_FEC_MAX_SYMBOL_NUM_PBLOCK) {
        return -XQC_EFEC_SYMBOL_ERROR;
    }
    if (total_symbol_num <= src_symbol_num) {
        return -XQC_EFEC_SYMBOL_ERROR;
    }
    if (max_window_size <= 0 || max_window_size > XQC_SYMBOL_CACHE_LEN) {
        return -XQC_EFEC_SYMBOL_ERROR;
    }

    return XQC_OK;
}

/* process fec protected packet with stream mode */
xqc_int_t
xqc_process_fec_protected_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    xqc_int_t i, ret, fss_esi, header_len, payload_len, symbol_idx, max_src_symbol_num, max_total_symbol_num, max_symbol_size;
    unsigned char *p;

    symbol_idx = 0;
    max_src_symbol_num = conn->local_settings.fec_max_symbols_num;
    max_total_symbol_num = conn->conn_settings.fec_params.fec_max_symbol_num_per_block;
    max_symbol_size = conn->conn_settings.fec_params.fec_max_symbol_size;
    
    if (xqc_is_packet_fec_protected(conn, packet_out) != XQC_OK) {
        return -XQC_EFEC_NOT_SUPPORT_FEC;
    }

    if (xqc_is_fec_params_valid(max_src_symbol_num, max_total_symbol_num, conn->conn_settings.fec_params.fec_max_window_size) != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_process_fec_protected_packet|xqc_is_fec_params_valid|fec params invalid|");
        return -XQC_EFEC_SYMBOL_ERROR;
    }

    if (packet_out->po_frame_types & XQC_FRAME_BIT_SID
        || packet_out->po_frame_types & XQC_FRAME_BIT_REPAIR_SYMBOL)
    {
        return XQC_OK;
    }

    header_len = packet_out->po_payload - packet_out->po_buf;
    payload_len = packet_out->po_used_size - header_len;
    if (max_symbol_size < payload_len) {
        return -XQC_EFEC_NOT_SUPPORT_FEC;
    }
    /* padding symbol to max symbol size */
    ret = xqc_gen_padding_frame_with_len(conn, packet_out, max_symbol_size - payload_len,
                                         XQC_PACKET_OUT_SIZE + XQC_ACK_SPACE - XQC_FEC_SPACE);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_WARN, "|quic_fec|xqc_process_fec_protected_packet|packet header is larger than expected(32 bytes)");
        return -XQC_EFEC_SYMBOL_ERROR;
    }

    symbol_idx = conn->fec_ctl->fec_send_src_symbols_num % max_src_symbol_num;
    payload_len = packet_out->po_used_size - header_len;
    if (payload_len != max_symbol_size) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_process_fec_protected_packet|payload len is not equal to fec max symbol size|");
        return -XQC_EFEC_SYMBOL_ERROR;
    }

    /* 为当前packet 生成SID Frame */
    ret = xqc_write_sid_frame_to_one_packet(conn, packet_out);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_process_fec_protected_packet|xqc_write_sid_frame_to_one_packet error|");
        return -XQC_EFEC_SYMBOL_ERROR;
    }
    /* FEC encoder */
    ret = xqc_fec_encoder(conn, packet_out->po_payload);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_process_fec_protected_packet|xqc_fec_encoder error|");
        return ret;
    }

    conn->fec_ctl->fec_send_src_symbols_num += 1;
    /* Whether current symbol is the final of one block. */
    symbol_idx = conn->fec_ctl->fec_send_src_symbols_num % max_src_symbol_num;
    if (symbol_idx == 0) {
        fss_esi = conn->fec_ctl->fec_send_src_symbols_num - max_src_symbol_num;

        /* Generate repair packets. */
        ret = xqc_write_repair_packets(conn, fss_esi, &packet_out->po_list);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_process_fec_protected_packet|xqc_gen_repair_packet error|");
            return -XQC_EWRITE_PKT;
        }
        /* Free the src symbol buff after we've finished the process of the block. */
        xqc_fec_ctl_init_send_params(conn->fec_ctl);
        if (conn->fec_ctl->fec_send_src_symbols_num >= XQC_FEC_MAX_SYMBOL_PAYLOAD_ID) {
            conn->fec_ctl->fec_send_src_symbols_num = 0;
            fss_esi = 0;
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_gen_src_payload_id(xqc_fec_ctl_t *fec_ctl, uint64_t *payload_id)
{
    xqc_connection_t *conn = fec_ctl->conn;
    if (fec_ctl->fec_send_src_symbols_num < 0 || fec_ctl->fec_send_src_symbols_num >= XQC_FEC_MAX_SYMBOL_PAYLOAD_ID) {
        return -XQC_EFEC_SYMBOL_ERROR;
    }
    *payload_id = fec_ctl->fec_send_src_symbols_num;
    return XQC_OK;
}

xqc_fec_ctl_t *
xqc_fec_ctl_create(xqc_connection_t *conn)
{
    xqc_int_t       i, j;
    xqc_fec_ctl_t  *fec_ctl = NULL;
    
    fec_ctl = xqc_malloc(sizeof(xqc_fec_ctl_t));
    if (fec_ctl == NULL) {
        return NULL;
    }

    fec_ctl->conn = conn;
    fec_ctl->fec_flow_id = 0;
    fec_ctl->fec_recover_pkt_cnt = 0;
    fec_ctl->fec_processed_blk_num = 0;
    fec_ctl->fec_flush_blk_cnt = 0;
    fec_ctl->fec_recover_failed_cnt = 0;
    fec_ctl->fec_ignore_blk_cnt = 0;
    fec_ctl->fec_recv_repair_num = 0;

    fec_ctl->fec_send_src_symbols_num = 0;
    fec_ctl->fec_send_repair_symbols_num = 0;


    for (i = 0; i < XQC_REPAIR_LEN; i++) {
        unsigned char *key_p = xqc_calloc(1, XQC_FEC_MAX_SYMBOL_NUM_PBLOCK);
        xqc_set_object_value(&fec_ctl->fec_send_repair_key[i], 0, key_p, 0);

        unsigned char *syb_p = xqc_calloc(1, XQC_PACKET_OUT_SIZE + XQC_ACK_SPACE - XQC_HEADER_SPACE - XQC_FEC_SPACE);
        xqc_set_object_value(&fec_ctl->fec_send_repair_symbols_buff[i], 0, syb_p, 0);
    }

    for (i = 0; i < XQC_SYMBOL_CACHE_LEN; i++) {
        fec_ctl->fec_recv_block_idx[i] = -1;
        fec_ctl->fec_recv_symbols_num[i] = 0;
        fec_ctl->fec_recv_repair_symbols_num[i] = 0;
        fec_ctl->fec_recv_symbols_flag[i] = 0;
        for (j = 0; j < XQC_FEC_MAX_SYMBOL_NUM_PBLOCK; j++) {
            unsigned char *syb_p = xqc_calloc(1, XQC_PACKET_OUT_SIZE + XQC_ACK_SPACE - XQC_HEADER_SPACE - XQC_FEC_SPACE);
            xqc_set_object_value(&fec_ctl->fec_recv_symbols_buff[i][j], 0, syb_p, 0);
        }
        for (j = 0; j < XQC_REPAIR_LEN; j++) {
            unsigned char *key_p = xqc_calloc(1, XQC_FEC_MAX_SYMBOL_NUM_PBLOCK);
            xqc_set_object_value(&fec_ctl->fec_recv_repair_key[i][j], 0, key_p, 0);
        }
    }

    return fec_ctl;
}

void
xqc_fec_ctl_destroy(xqc_fec_ctl_t *fec_ctl)
{
    xqc_int_t i, j;
    fec_ctl->fec_flow_id = 0;
    fec_ctl->fec_send_src_symbols_num = 0;
    fec_ctl->fec_send_repair_symbols_num = 0;
    for (i = 0; i < XQC_REPAIR_LEN; i++) {
        if (fec_ctl->fec_send_repair_key[i].payload != NULL) {
            xqc_free(fec_ctl->fec_send_repair_key[i].payload);
            fec_ctl->fec_send_repair_key[i].is_valid = 0;
        }
        if (fec_ctl->fec_send_repair_symbols_buff[i].payload != NULL) {
            xqc_free(fec_ctl->fec_send_repair_symbols_buff[i].payload);
            fec_ctl->fec_send_repair_symbols_buff[i].is_valid = 0;
        }
    }

    for (i = 0; i < XQC_SYMBOL_CACHE_LEN; i++) {
        fec_ctl->fec_recv_symbols_flag[i] = 0;
        fec_ctl->fec_recv_symbols_num[i] = 0;
        fec_ctl->fec_recv_block_idx[i] = 0;

        for (j = 0; j < XQC_FEC_MAX_SYMBOL_NUM_PBLOCK; j++) {
            if (fec_ctl->fec_recv_symbols_buff[i][j].payload != NULL) {
                xqc_free(fec_ctl->fec_recv_symbols_buff[i][j].payload);
                fec_ctl->fec_recv_symbols_buff[i][j].is_valid = 0;
            }
        }
        for (j = 0; j < XQC_REPAIR_LEN; j++) {
            if (fec_ctl->fec_recv_repair_key[i][j].payload != NULL) {
                xqc_free(fec_ctl->fec_recv_repair_key[i][j].payload);
                fec_ctl->fec_recv_repair_key[i][j].is_valid = 0;
            }
        }
    }

    xqc_free(fec_ctl);
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
xqc_fec_ctl_init_send_params(xqc_fec_ctl_t *fec_ctl)
{
    xqc_int_t i, symbol_size, key_size;
    
    symbol_size = key_size = 0;
    fec_ctl->fec_send_repair_symbols_num = 0;

    for (i = 0 ; i < XQC_REPAIR_LEN; i++) {
        if (fec_ctl->fec_send_repair_key[i].is_valid) {
            xqc_init_object_value(&fec_ctl->fec_send_repair_key[i]);
        }

        if (fec_ctl->fec_send_repair_symbols_buff[i].is_valid) {
            xqc_init_object_value(&fec_ctl->fec_send_repair_symbols_buff[i]);
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
    object->payload_size = size;
}

void
xqc_init_object_value(xqc_fec_object_t *object)
{
    object->is_valid = 0;
    xqc_memset(object->payload, 0, object->payload_size);
    object->payload_size = 0;
}

xqc_int_t
xqc_fec_ctl_init_recv_params(xqc_fec_ctl_t *fec_ctl, xqc_int_t block_idx)
{
    xqc_int_t j, symbol_size, key_size;

    fec_ctl->fec_recv_symbols_num[block_idx] = 0;
    fec_ctl->fec_recv_repair_symbols_num[block_idx] = 0;
    fec_ctl->fec_recv_symbols_flag[block_idx] = 0;

    for (j = 0; j < XQC_FEC_MAX_SYMBOL_NUM_PBLOCK; j++) {
        if (fec_ctl->fec_recv_symbols_buff[block_idx][j].is_valid) {
            xqc_init_object_value(&fec_ctl->fec_recv_symbols_buff[block_idx][j]);
        }
    }

    for (j = 0; j < XQC_REPAIR_LEN; j++) {
        if (fec_ctl->fec_recv_repair_key[block_idx][j].is_valid) {
            xqc_init_object_value(&fec_ctl->fec_recv_repair_key[block_idx][j]);
        }
    }

    return XQC_OK;
}

xqc_int_t
xqc_negotiate_fec_schemes(xqc_connection_t *conn, xqc_transport_params_t params)
{
    xqc_int_t ret;

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
        conn->conn_settings.enable_encode_fec = 0;
        conn->conn_settings.enable_decode_fec = 0;
        return ret;
    }

    if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
        /* server as encoder */
        if (params.enable_decode_fec
            && params.fec_decoder_schemes_num > 0
            && conn->local_settings.enable_encode_fec
            && conn->local_settings.fec_encoder_schemes_num > 0
            && xqc_set_final_scheme(conn, conn->local_settings.fec_encoder_schemes, &conn->local_settings.fec_encoder_schemes_num, params.fec_decoder_schemes,
                                    params.fec_decoder_schemes_num, &conn->conn_settings.fec_params.fec_encoder_scheme, &conn->conn_settings.fec_encode_callback) == XQC_OK)
        {
            /* TODOfec:变长数组/单测 */
            /* 设置重新编码至transport param的flag */
            xqc_log(conn->log, XQC_LOG_DEBUG, "|server set final encoder fec scheme: %s",
                    xqc_get_fec_scheme_str(conn->conn_settings.fec_params.fec_encoder_scheme));
            ret = XQC_OK;

        } else {
            conn->local_settings.enable_encode_fec = 0;
            conn->local_settings.fec_encoder_schemes_num = 0;
            conn->conn_settings.enable_encode_fec = 0;
            conn->conn_settings.fec_params.fec_encoder_scheme = 0;
            xqc_log(conn->log, XQC_LOG_DEBUG, "|negotiation on final encoder scheme failed.|");
        }

        /* server as encoder */
        if (params.enable_encode_fec
            && params.fec_encoder_schemes_num > 0
            && conn->local_settings.enable_decode_fec
            && conn->local_settings.fec_decoder_schemes_num > 0
            && xqc_set_final_scheme(conn, conn->local_settings.fec_decoder_schemes, &conn->local_settings.fec_decoder_schemes_num, params.fec_encoder_schemes,
                                    params.fec_encoder_schemes_num, &conn->conn_settings.fec_params.fec_decoder_scheme, &conn->conn_settings.fec_decode_callback) == XQC_OK)
        {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|server set final decoder fec scheme: %s",
                    xqc_get_fec_scheme_str(conn->conn_settings.fec_params.fec_decoder_scheme));
            ret = XQC_OK;

        } else {
            conn->local_settings.enable_decode_fec = 0;
            conn->local_settings.fec_decoder_schemes_num = 0;
            conn->conn_settings.enable_decode_fec = 0;
            conn->conn_settings.fec_params.fec_decoder_scheme = 0;
            xqc_log(conn->log, XQC_LOG_DEBUG, "|negotiation on final decoder scheme failed.|");
        }
        return ret;
    }

    /* client端接收fec schemes逻辑 */
    if (conn->conn_type == XQC_CONN_TYPE_CLIENT
        && params.enable_decode_fec
        && params.fec_decoder_schemes_num == 1
        && conn->local_settings.enable_encode_fec
        && xqc_is_fec_scheme_valid(params.fec_decoder_schemes[0], conn->local_settings.fec_encoder_schemes, conn->local_settings.fec_encoder_schemes_num) == XQC_OK)
    {
        conn->conn_settings.fec_params.fec_encoder_scheme = params.fec_decoder_schemes[0];
        ret = xqc_set_valid_scheme_cb(&conn->conn_settings.fec_encode_callback, conn->conn_settings.fec_params.fec_encoder_scheme);
        if (ret == XQC_OK) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|client set final encoder fec scheme: %s",
                    xqc_get_fec_scheme_str(conn->conn_settings.fec_params.fec_encoder_scheme));

        } else {
            conn->conn_settings.enable_encode_fec = 0;
            conn->conn_settings.fec_params.fec_encoder_scheme = 0;
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|set valid scheme %s error|ret:%d|",
                    conn->conn_settings.fec_params.fec_encoder_scheme, ret);
        }

    } else {
        conn->conn_settings.enable_encode_fec = 0;
        conn->conn_settings.fec_params.fec_encoder_scheme = 0;
        xqc_log(conn->log, XQC_LOG_DEBUG, "|invalid fec schemes, negotiation on final encoder scheme failed.");
    }

    if (conn->conn_type == XQC_CONN_TYPE_CLIENT
        && params.enable_encode_fec
        && params.fec_encoder_schemes_num == 1
        && conn->local_settings.enable_decode_fec
        && xqc_is_fec_scheme_valid(params.fec_encoder_schemes[0], conn->local_settings.fec_decoder_schemes, conn->local_settings.fec_decoder_schemes_num) == XQC_OK)
    {
        conn->conn_settings.fec_params.fec_decoder_scheme = params.fec_encoder_schemes[0];
        ret = xqc_set_valid_scheme_cb(&conn->conn_settings.fec_decode_callback, conn->conn_settings.fec_params.fec_decoder_scheme);
        if (ret == XQC_OK) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|client set final decoder fec scheme: %s",
                    xqc_get_fec_scheme_str(conn->conn_settings.fec_params.fec_decoder_scheme));

        } else {
            conn->conn_settings.enable_decode_fec = 0;
            conn->conn_settings.fec_params.fec_decoder_scheme = 0;
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|set valid scheme scheme error|ret:%d|", ret);
        }

    } else {
        conn->conn_settings.enable_decode_fec = 0;
        conn->conn_settings.fec_params.fec_decoder_scheme = 0;
        xqc_log(conn->log, XQC_LOG_DEBUG, "|invalid fec schemes, negotiation on final decoder scheme failed.");
    }
    return ret;
}

void
xqc_fec_record_flush_blk(xqc_connection_t *conn, xqc_int_t block_id)
{
    xqc_int_t skip_block, window_size, block_cache_idx;

    window_size = conn->conn_settings.fec_params.fec_max_window_size;
    block_cache_idx = block_id % window_size;

    if (conn->fec_ctl->fec_recv_symbols_num[block_cache_idx] != 0) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|block_%d will be flushed by block_%d|", conn->fec_ctl->fec_recv_block_idx[block_cache_idx], block_id);
        if (conn->fec_ctl->fec_flush_blk_cnt == XQC_MAX_UINT32_VALUE) {
            xqc_log(conn->log, XQC_LOG_WARN, "|fec flushed block count exceeds maximum.");
            conn->fec_ctl->fec_flush_blk_cnt = 0;
        }
        conn->fec_ctl->fec_flush_blk_cnt++;

        /* record the number of blocks that is skipped */
        if (block_id - conn->fec_ctl->fec_recv_block_idx[block_cache_idx] > window_size) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|block_%d skipped to block_%d|", conn->fec_ctl->fec_recv_block_idx[block_cache_idx], block_id);
            if (conn->fec_ctl->fec_ignore_blk_cnt == XQC_MAX_UINT32_VALUE) {
                xqc_log(conn->log, XQC_LOG_WARN, "|fec ignored block count exceeds maximum.");
                conn->fec_ctl->fec_ignore_blk_cnt = 0;
            }
            skip_block = (block_id - conn->fec_ctl->fec_recv_block_idx[block_cache_idx]) / window_size - 1;
            conn->fec_ctl->fec_ignore_blk_cnt += skip_block;
        }
    }
}

xqc_int_t
xqc_process_valid_symbol(xqc_connection_t *conn, xqc_int_t block_id, xqc_int_t symbol_idx,
    unsigned char *symbol, xqc_int_t symbol_size)
{
    xqc_int_t           ret, block_cache_idx, window_size;
    unsigned char      *tmp_payload_p;

    window_size = conn->conn_settings.fec_params.fec_max_window_size;
    block_cache_idx = block_id % window_size;

    /* if block_id exceeds the older block id, flush the old block */
    if (block_id > conn->fec_ctl->fec_recv_block_idx[block_cache_idx]) {
        /* record the number of non-empty older blocks */
        xqc_fec_record_flush_blk(conn, block_id);
        /* flush the old block */
        xqc_fec_ctl_init_recv_params(conn->fec_ctl, block_cache_idx);
        conn->fec_ctl->fec_recv_block_idx[block_cache_idx] = block_id;
        xqc_log(conn->log, XQC_LOG_DEBUG, "|init fec block id: %d|", conn->fec_ctl->fec_recv_block_idx[block_cache_idx]);

    } else if (block_id != conn->fec_ctl->fec_recv_block_idx[block_cache_idx]) {
        /* receive block idx smaller than current block idx. */
        xqc_log(conn->log, XQC_LOG_DEBUG, "|fec window is taken by other block|block_id:%d|", conn->fec_ctl->fec_recv_block_idx[block_cache_idx]);
        return -XQC_EFEC_SYMBOL_ERROR;

    } else if (conn->fec_ctl->fec_recv_symbols_num[block_cache_idx] == 0) {
        return XQC_OK;
    }

    if (conn->fec_ctl->fec_recv_symbols_flag[block_cache_idx] & (1 << symbol_idx)
        || conn->fec_ctl->fec_recv_symbols_buff[block_cache_idx][symbol_idx].is_valid)
    {
        /* here the symbol value should not exits，otherwise it means there're some repeated sid in this block. */
        return -XQC_EFEC_SYMBOL_ERROR;
    }

    ret = xqc_fec_ctl_save_symbol(&conn->fec_ctl->fec_recv_symbols_buff[block_cache_idx][symbol_idx].payload,
                                  symbol, symbol_size);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|save source symbol error|");
        return -XQC_EFEC_SYMBOL_ERROR;
    }

    tmp_payload_p = conn->fec_ctl->fec_recv_symbols_buff[block_cache_idx][symbol_idx].payload;

    xqc_set_object_value(&conn->fec_ctl->fec_recv_symbols_buff[block_cache_idx][symbol_idx], 1, tmp_payload_p, symbol_size);

    conn->fec_ctl->fec_recv_symbols_flag[block_cache_idx] ^= (1 << symbol_idx);
    conn->fec_ctl->fec_recv_symbols_num[block_cache_idx]++;

    return XQC_OK;
}