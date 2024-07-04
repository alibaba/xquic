
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#include "src/transport/xqc_fec_scheme.h"
#include "src/transport/xqc_conn.h"


xqc_int_t
xqc_fec_encoder(xqc_connection_t *conn, unsigned char *stream)
{
    xqc_int_t i, ret, symbol_idx, src_symbol_num, max_symbol_num, repair_symbol_num;
    unsigned char *repair_symbols_payload_buff[XQC_REPAIR_LEN];

    src_symbol_num =  conn->conn_settings.fec_params.fec_max_symbol_num_per_block * conn->conn_settings.fec_params.fec_code_rate;
    symbol_idx = conn->fec_ctl->fec_send_src_symbols_num % src_symbol_num;
    max_symbol_num =  conn->conn_settings.fec_params.fec_max_symbol_num_per_block;
    repair_symbol_num = max_symbol_num - src_symbol_num;

    if (repair_symbol_num < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_fec_encoder|fec source symbols' number exceeds maximum symbols number per block");
        return -XQC_EFEC_SCHEME_ERROR;
    }

    if (repair_symbol_num == 0) {
        xqc_log(conn->log, XQC_LOG_WARN, "|quic_fec|xqc_fec_encoder|current code rate is too low to generate repair packets.");
        return XQC_OK;
    }

    conn->fec_ctl->fec_send_repair_symbols_num = repair_symbol_num;

    if (conn->conn_settings.fec_encode_callback.xqc_fec_encode == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_fec_encoder|fec encode_uni callback is NULL");
        return -XQC_EFEC_SCHEME_ERROR;
    }

    for (i = 0; i < repair_symbol_num; i++) {
        repair_symbols_payload_buff[i] = conn->fec_ctl->fec_send_repair_symbols_buff[i].payload;
    }

    ret = conn->conn_settings.fec_encode_callback.xqc_fec_encode(conn, stream, repair_symbols_payload_buff);

    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_WARN, "|quic_fec|xqc_fec_encoder|fec scheme encode_uni error");
        return -XQC_EFEC_SCHEME_ERROR;
    }

    for (i = 0; i < repair_symbol_num; i++) {
        xqc_set_object_value(&conn->fec_ctl->fec_send_repair_symbols_buff[i], 1, repair_symbols_payload_buff[i],
                             conn->conn_settings.fec_params.fec_max_symbol_size);
    }

    return XQC_OK;
}

xqc_int_t
xqc_process_recovered_packet(xqc_connection_t *conn, unsigned char **recovered_symbols_buff,
    xqc_int_t loss_symbol_idx_len)
{
    xqc_int_t i, ret, res, symbol_idx, symbol_size;

    symbol_size = conn->remote_settings.fec_max_symbol_size;
    res = XQC_OK;

    for (i = 0; i < loss_symbol_idx_len; i++) {
        symbol_idx = i;
        if (recovered_symbols_buff[symbol_idx] == NULL) {
            xqc_log(conn->log, XQC_LOG_WARN, "|quic_fec|xqc_process_recovered_packet|symbol %d recover failed", symbol_idx);
            continue;
        }
        xqc_packet_in_t *new_packet = xqc_calloc(1, sizeof(xqc_packet_in_t));
        if (new_packet == NULL) {
            return -XQC_EMALLOC;
        }

        new_packet->decode_payload = recovered_symbols_buff[symbol_idx];
        new_packet->decode_payload_len = symbol_size;
        new_packet->pos = new_packet->decode_payload;
        new_packet->last = new_packet->decode_payload + symbol_size;
        new_packet->pkt_recv_time = xqc_monotonic_timestamp();
        new_packet->pi_path_id = 0;
        new_packet->pi_flag |= XQC_PIF_FEC_RECOVERED;

        ret = xqc_process_frames(conn, new_packet);
        xqc_free(new_packet);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_process_recovered_packet|process recovered packet failed");
            res = -XQC_EFEC_SCHEME_ERROR;

        } else {
            if (conn->fec_ctl->fec_recover_pkt_cnt == XQC_MAX_UINT32_VALUE) {
                xqc_log(conn->log, XQC_LOG_WARN, "|fec recovered packet number exceeds maximum.");
                conn->fec_ctl->fec_recover_pkt_cnt = 0;
            }
            conn->fec_ctl->fec_recover_pkt_cnt++;
        }
    }
    return res;
}

xqc_int_t
xqc_fec_decoder(xqc_connection_t *conn, xqc_int_t block_idx)
{
    xqc_int_t           i, ret, max_src_symbol_num, loss_src_num;
    xqc_int_t           loss_symbol_idx[XQC_FEC_MAX_SYMBOL_NUM_PBLOCK] = {-1};
    unsigned char      *recovered_symbols_buff[XQC_FEC_MAX_SYMBOL_NUM_PBLOCK];

    ret = loss_src_num = 0;
    for (i = 0; i < XQC_FEC_MAX_SYMBOL_NUM_PBLOCK; i++) {
        recovered_symbols_buff[i] = xqc_calloc(1, XQC_PACKET_OUT_SIZE + XQC_ACK_SPACE - XQC_HEADER_SPACE - XQC_FEC_SPACE);
    }
    
    max_src_symbol_num = conn->remote_settings.fec_max_symbols_num;

    if (conn->fec_ctl->fec_recv_symbols_num[block_idx] < max_src_symbol_num) {
        ret = -XQC_EFEC_SYMBOL_ERROR;
        goto end;
    }
    for (i = 0; i < max_src_symbol_num; i++) {
        if ((conn->fec_ctl->fec_recv_symbols_flag[block_idx] & (1 << i)) == 0) {
            loss_symbol_idx[loss_src_num] = i;
            loss_src_num++;
        }
    }
    /* proceeds if there's no loss src symbol */
    if (loss_src_num == 0) {
        ret = XQC_OK;
        goto end;
    }
    
    /* generate loss packets payload */
    if (conn->conn_settings.fec_decode_callback.xqc_fec_decode == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_fec_decoder|fec decode callback is NULL");
        ret = -XQC_EFEC_SCHEME_ERROR;
        goto end;
    }
    ret = conn->conn_settings.fec_decode_callback.xqc_fec_decode(conn, recovered_symbols_buff, block_idx, loss_symbol_idx, loss_src_num);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_WARN, "|fec scheme decode error");
        ret = -XQC_EFEC_SCHEME_ERROR;
        goto end;
    }

    /* 封装 new packets并解析数据帧 */
    ret = xqc_process_recovered_packet(conn, recovered_symbols_buff, loss_src_num);
    if (ret == XQC_OK) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|process packet of block %d successfully.", conn->fec_ctl->fec_recv_block_idx[block_idx]);
    }

end:
    if (conn->fec_ctl->fec_processed_blk_num == XQC_MAX_UINT32_VALUE) {
        xqc_log(conn->log, XQC_LOG_WARN, "|fec processed block number exceeds maximum.");
        conn->fec_ctl->fec_processed_blk_num = 0;
    }
    conn->fec_ctl->fec_processed_blk_num++;
    /* free recovered symbols buff */
    for (i = 0; i < XQC_FEC_MAX_SYMBOL_NUM_PBLOCK; i++) {
        if (recovered_symbols_buff[i] != NULL) {
            xqc_free(recovered_symbols_buff[i]);
        }
    }
    if (ret == XQC_OK) {
        return XQC_OK;
    }

    if (conn->fec_ctl->fec_recover_failed_cnt == XQC_MAX_UINT32_VALUE) {
        xqc_log(conn->log, XQC_LOG_WARN, "|fec recovered failed number exceeds maximum.");
        conn->fec_ctl->fec_recover_failed_cnt = 0;
    }
    conn->fec_ctl->fec_recover_failed_cnt++;
    return ret;
}