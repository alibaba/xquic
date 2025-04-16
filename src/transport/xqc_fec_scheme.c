
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#include "src/transport/xqc_fec_scheme.h"
#include "src/transport/xqc_fec.h"
#include "src/transport/xqc_conn.h"

xqc_int_t
xqc_fec_encoder_check_params(xqc_connection_t *conn, xqc_int_t repair_symbol_num, xqc_fec_schemes_e encoder_scheme, size_t st_size)
{
    if (encoder_scheme == XQC_XOR_CODE) {
        if (repair_symbol_num > 1) {
            xqc_log(conn->log, XQC_LOG_WARN, "|quic_fec|xqc_fec_encoder|xor fec scheme can only maintain one repair symbol");
            return -XQC_EPARAM;
        }
    }

    if (st_size > XQC_MAX_SYMBOL_SIZE) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|stream size is too large to get fec encode|st_size:%zu|", st_size);
        return -XQC_EPARAM;
    }

    return XQC_OK;
}

xqc_int_t
xqc_fec_encoder(xqc_connection_t *conn, unsigned char *input, size_t st_size, uint8_t fec_bm_mode)
{
    xqc_int_t i, ret;
    unsigned char *repair_symbols_payload_buff[XQC_REPAIR_LEN] = {0};
    xqc_int_t repair_symbol_num;

    repair_symbol_num = conn->fec_ctl->fec_send_required_repair_num[fec_bm_mode];

    // validate encode params
    ret = xqc_fec_encoder_check_params(conn, repair_symbol_num, conn->conn_settings.fec_params.fec_encoder_scheme, st_size);
    if (ret != XQC_OK) {
        return ret;
    }

    if (conn->conn_settings.fec_callback.xqc_fec_encode) {
        // encode stream value into fec_send_repair_symbols_buff
        for (i = 0; i < repair_symbol_num; i++) {
            repair_symbols_payload_buff[i] = conn->fec_ctl->fec_send_repair_symbols_buff[fec_bm_mode][i].payload;
            if (repair_symbols_payload_buff[i] == NULL) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|fail to malloc memory for fec_send_repair_symbols_buff");
                return -XQC_EMALLOC;
            }
        }

        ret = conn->conn_settings.fec_callback.xqc_fec_encode(conn, input, st_size, repair_symbols_payload_buff, fec_bm_mode);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_WARN, "|quic_fec|xqc_fec_encoder|fec scheme encode_uni error");
            return -XQC_EFEC_SCHEME_ERROR;
        }

    } else {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_fec_encoder|fec encode_uni callback is NULL");
        return -XQC_EFEC_SCHEME_ERROR;
    }

    return XQC_OK;
}

xqc_int_t
xqc_process_recovered_packet(xqc_connection_t *conn, unsigned char *recovered_payload, size_t symbol_size, xqc_usec_t rpr_recv_time)
{
    xqc_int_t i, ret, res;

    res = XQC_OK;
    xqc_packet_in_t *new_packet = xqc_calloc(1, sizeof(xqc_packet_in_t));
    if (new_packet == NULL) {
        return -XQC_EMALLOC;
    }

    new_packet->decode_payload = recovered_payload;
    new_packet->decode_payload_len = symbol_size;
    new_packet->pos = new_packet->decode_payload;
    new_packet->last = new_packet->decode_payload + symbol_size;
    new_packet->pkt_recv_time = xqc_monotonic_timestamp();
    new_packet->pi_path_id = 0;
    new_packet->pi_flag |= XQC_PIF_FEC_RECOVERED;
    new_packet->pi_fec_process_time = rpr_recv_time;

    ret = xqc_process_frames(conn, new_packet);
    xqc_free(new_packet);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|process recovered packet failed|ret:%d", ret);
        res = -XQC_EFEC_SCHEME_ERROR;

    } else {
        conn->fec_ctl->fec_recover_pkt_cnt++;
    }
    return res;
}


xqc_int_t
xqc_fec_cc_decoder(xqc_connection_t *conn, xqc_fec_rpr_syb_t *rpr_symbol, uint8_t lack_syb_id)
{
    xqc_int_t ret, block_id, symbol_idx, mask_offset;
    unsigned char *payload_p;

    ret = -XQC_EFEC_SYMBOL_ERROR;
    block_id = rpr_symbol->block_id;
    symbol_idx = rpr_symbol->symbol_idx;
    payload_p = conn->fec_ctl->fec_gen_repair_symbols_buff[0].payload;

    if (payload_p == NULL || (rpr_symbol->payload_size <= 0 && rpr_symbol->payload_size > XQC_MAX_SYMBOL_SIZE)) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|invalid symbol payload");
        goto cc_decoder_end;
    }
    if (conn->conn_settings.fec_callback.xqc_fec_decode_one == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_fec_decode_one doesn't exists");
        goto cc_decoder_end;
    }

    ret = conn->conn_settings.fec_callback.xqc_fec_decode_one(conn, payload_p, block_id, symbol_idx);
    xqc_set_object_value(&conn->fec_ctl->fec_gen_repair_symbols_buff[0], 1, payload_p, rpr_symbol->payload_size);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_fec_decode_one error");
        goto cc_decoder_end;
    }
    ret = xqc_process_recovered_packet(conn, payload_p, rpr_symbol->payload_size, rpr_symbol->recv_time);
    if (ret == XQC_OK) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|process packet of block %d successfully.", block_id);
        // insert into source list
        ret = xqc_process_src_symbol(conn, block_id, lack_syb_id, payload_p, rpr_symbol->payload_size);
        if (ret == -XQC_EFEC_TOLERABLE_ERROR) {
            ret = XQC_OK;
        }
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|process source symbol error|ret:%d", ret);
        }
    } else {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|process recovered packet error|ret:%d|bid:%d|symbol_size:%d", ret, block_id, rpr_symbol->payload_size);
    }

cc_decoder_end:
    if (conn->fec_ctl->fec_gen_repair_symbols_buff[0].is_valid) {
        conn->fec_ctl->fec_gen_repair_symbols_buff[0].payload_size = XQC_MAX_SYMBOL_SIZE;
        xqc_init_object_value(&conn->fec_ctl->fec_gen_repair_symbols_buff[0]);
    }
    conn->fec_ctl->fec_processed_blk_num++;

    if (ret == XQC_OK) {
        return XQC_OK;
    }

    conn->fec_ctl->fec_recover_failed_cnt++;
    return ret;
}

/**
 * @brief fec block code decoder;
 * 
 * @param conn 
 * @param block_id 
 * @return xqc_int_t 
 */
xqc_int_t
xqc_fec_bc_decoder(xqc_connection_t *conn, xqc_int_t block_id, xqc_int_t loss_src_num, xqc_usec_t rpr_time)
{
    size_t              symbol_size;
    xqc_int_t           i, ret, symbol_flag, rpr_syb_num, src_syb_num, symbol_idx;
    unsigned char      *recovered_symbols_buff[XQC_REPAIR_LEN];
    xqc_list_head_t     *pos, *next;

    ret = symbol_size = 0;
    /* proceeds if there's no loss src symbol */
    if (loss_src_num == 0) {
        ret = XQC_OK;
        goto bc_decoder_end;
    }

    for (i = 0; i < loss_src_num; i++) {
        recovered_symbols_buff[i] = conn->fec_ctl->fec_gen_repair_symbols_buff[i].payload;
        if (recovered_symbols_buff[i] == NULL) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|fec_gen_repair_symbols_buff is NULL");
            ret = -XQC_EMALLOC;
            goto bc_decoder_end;
        }
    }

    /* generate loss packets payload */
    if (conn->conn_settings.fec_callback.xqc_fec_decode) {
        ret = conn->conn_settings.fec_callback.xqc_fec_decode(conn, recovered_symbols_buff, &symbol_size, block_id);
        for (i = 0; i < loss_src_num; i++) {
            xqc_set_object_value(&conn->fec_ctl->fec_gen_repair_symbols_buff[i], 1, recovered_symbols_buff[i],
                                 symbol_size);
        }
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_WARN, "|quic_fec|fec scheme decode error");
            ret = -XQC_EFEC_SCHEME_ERROR;
            goto bc_decoder_end;
        }

    } else {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_fec_bc_decoder|fec decode callback is NULL");
        ret = -XQC_EFEC_SCHEME_ERROR;
        goto bc_decoder_end;
    }

    for (i = 0; i < loss_src_num; i++) {
        if (recovered_symbols_buff[i] == NULL) {
            xqc_log(conn->log, XQC_LOG_WARN, "|quic_fec|xqc_process_recovered_packet|symbol %d recover failed", i);
            break;
        }
        ret = xqc_process_recovered_packet(conn, recovered_symbols_buff[i], symbol_size, rpr_time);
        if (ret == XQC_OK) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|process packet of block %d successfully.", block_id);
        }
    }

bc_decoder_end:
    conn->fec_ctl->fec_processed_blk_num++;
    /* free recovered symbols buff */
    for (i = 0; i < loss_src_num; i++) {
        if (conn->fec_ctl->fec_gen_repair_symbols_buff[i].is_valid) {
            conn->fec_ctl->fec_gen_repair_symbols_buff[i].payload_size = XQC_MAX_SYMBOL_SIZE;
            xqc_init_object_value(&conn->fec_ctl->fec_gen_repair_symbols_buff[i]);
        }
    }
    if (ret == XQC_OK) {
        return XQC_OK;
    }

    conn->fec_ctl->fec_recover_failed_cnt++;
    return ret;
}