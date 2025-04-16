/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
*/

#include "src/transport/fec_schemes/xqc_packet_mask.h"
#include "src/transport/fec_schemes/xqc_xor.h"
#include "src/transport/fec_schemes/xqc_packet_mask_value.h"
#include "src/transport/fec_schemes/xqc_galois_calculation.h"
#include "src/transport/xqc_fec.h"
#include "src/transport/xqc_conn.h"

const uint8_t *
xqc_get_mask_tbl(xqc_connection_t *conn)
{
    if (conn->conn_settings.fec_params.fec_packet_mask_mode == XQC_FEC_BURST_TBL)
    {
        return xqc_bst_pm_tbl;
    }
    return xqc_rnd_pm_tbl;
}

void
xqc_lookup_pkm(xqc_connection_t *conn, xqc_int_t src_symbol_num, xqc_int_t rpr_symbol_num, uint8_t *output)
{
    const uint8_t *table = NULL, *mask_entry = NULL;
    uint8_t increment, count;
    uint16_t tbl_len;

    table = xqc_get_mask_tbl(conn);

    if (src_symbol_num > XQC_MAX_LOOKUP_MASK_SIZE) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|invalid symbol number for constant mask tbl|src num:%d|rpr num:%d", src_symbol_num, rpr_symbol_num);
        return;
    }

    tbl_len = table[0];
    increment = 2;
    mask_entry = &table[1];

    // skip entries before src_symbol_num'th one;
    for (uint32_t i = 0; i < src_symbol_num - 1; i++) {
        count = mask_entry[0];
        mask_entry = &mask_entry[1];
        for (uint32_t j = 0; j < count; j++) {
            mask_entry += increment * (j + 1);
        }
    }

    count = mask_entry[0];
    mask_entry = &mask_entry[1];
    // skip entries before repair_num;
    for (uint32_t i = 0; i < rpr_symbol_num - 1; i++) {
        mask_entry += increment * (i + 1);
    }

    xqc_memcpy(output, mask_entry, increment * rpr_symbol_num);
}

void
xqc_get_packet_mask(xqc_connection_t *conn, xqc_int_t src_symbol_num, xqc_int_t rpr_symbol_num, uint8_t *tbl)
{
    size_t      tbl_size, increment;
    uint32_t    i, j;

    xqc_memset(tbl, 0, XQC_MAX_PM_SIZE);
    if (src_symbol_num <= XQC_MAX_LOOKUP_MASK_SIZE) {
        xqc_lookup_pkm(conn, src_symbol_num, rpr_symbol_num, tbl);
        return;
    }

    tbl_size = src_symbol_num;
    increment = src_symbol_num > 16 ? 6 : 2;
    for(i = 0; i < rpr_symbol_num; i++) {
        for (j = 0; j < increment; j++) {
            tbl[i * increment + j] = 
                ((j * 8) % rpr_symbol_num == i && (j * 8) < src_symbol_num ? 0x80: 0x00) |
                ((j * 8 + 1) % rpr_symbol_num == i && (j * 8 + 1) < src_symbol_num ? 0x40: 0x00) |
                ((j * 8 + 2) % rpr_symbol_num == i && (j * 8 + 2) < src_symbol_num ? 0x20: 0x00) |
                ((j * 8 + 3) % rpr_symbol_num == i && (j * 8 + 3) < src_symbol_num ? 0x10: 0x00) |
                ((j * 8 + 4) % rpr_symbol_num == i && (j * 8 + 4) < src_symbol_num ? 0x08: 0x00) |
                ((j * 8 + 5) % rpr_symbol_num == i && (j * 8 + 5) < src_symbol_num ? 0x04: 0x00) |
                ((j * 8 + 6) % rpr_symbol_num == i && (j * 8 + 6) < src_symbol_num ? 0x02: 0x00) |
                ((j * 8 + 7) % rpr_symbol_num == i && (j * 8 + 7) < src_symbol_num ? 0x01: 0x00);
        }
    }
}

void
xqc_packet_mask_init_one(xqc_connection_t *conn, uint8_t bm_idx)
{
    // init packet mask with default block size and code rate
    uint8_t k, *output = NULL, table[XQC_MAX_PM_SIZE];
    uint16_t repair_num, increment;
    const uint8_t *tbl_p = table;

    repair_num = conn->fec_ctl->fec_send_required_repair_num[bm_idx];
    k = xqc_get_fec_blk_size(conn, bm_idx);
    increment = k > 16 ? 6 : 2;

    if (k > 48 || repair_num <= 0 || repair_num > xqc_min(k, XQC_REPAIR_LEN)) {
        conn->conn_settings.enable_encode_fec = 0;
        conn->local_settings.enable_encode_fec = 0;
        return;
    }

    xqc_get_packet_mask(conn, k, repair_num, table);

    for (uint32_t j = 0; j < repair_num; j++) {
        output = conn->fec_ctl->fec_send_decode_matrix[bm_idx][j];
        xqc_memset(output, 0, increment);
        xqc_memcpy(output, tbl_p, increment);
        tbl_p += increment;
    }

    return;
}

void
xqc_packet_mask_init(xqc_connection_t *conn)
{
    // init packet mask with default block size and code rate
    uint8_t i, k, *output = NULL, table[XQC_MAX_PM_SIZE];
    uint16_t repair_num, increment;
    const uint8_t *tbl_p = table;

    for (i = 0; i < XQC_BLOCK_MODE_LEN; i++) {
        if (i == XQC_SLIM_SIZE_REQ) {
            continue;
        }
        repair_num = conn->fec_ctl->fec_send_required_repair_num[i];
        k = xqc_get_fec_blk_size(conn, i);
        increment = k > 16 ? 6 : 2;

        if (k > 48 || repair_num <= 0 || repair_num > xqc_min(k, XQC_REPAIR_LEN)) {
            conn->conn_settings.enable_encode_fec = 0;
            conn->local_settings.enable_encode_fec = 0;
            return;
        }

        xqc_get_packet_mask(conn, k, repair_num, table);
        tbl_p = table;

        for (uint32_t j = 0; j < repair_num; j++) {
            output = conn->fec_ctl->fec_send_decode_matrix[i][j];
            xqc_memset(output, 0, increment);
            xqc_memcpy(output, tbl_p, increment);
            tbl_p += increment;
        }
    }

    return;
}

xqc_int_t
xqc_pm_code_symbols(xqc_connection_t *conn, unsigned char *input, size_t in_size, unsigned char **outputs,
    uint8_t fec_bm_mode)
{
    size_t tmp_size;
    uint32_t src_syb_num, repair_num, symbol_idx;
    unsigned char pm_size, pm_offset, symbol_flag, *output_p = NULL, *pm_p = NULL, *rpr_key_p = NULL;
    xqc_int_t ret = XQC_OK;

    if (fec_bm_mode >= XQC_BLOCK_MODE_LEN) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|invalid fec_bm_mode:%d|", fec_bm_mode);
        return -XQC_EPARAM;
    }
    src_syb_num = xqc_get_fec_blk_size(conn, fec_bm_mode);
    repair_num = conn->fec_ctl->fec_send_required_repair_num[fec_bm_mode];
    symbol_idx = conn->fec_ctl->fec_send_symbol_num[fec_bm_mode];
    symbol_flag = 1 << (7 - symbol_idx % 8);
    pm_offset = symbol_idx / 8;
    pm_size = src_syb_num > 16 ? 6 : 2;

    if (repair_num > XQC_REPAIR_LEN) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|repair number exceeds buff size");
        return -XQC_EPARAM;
    }

    if (pm_offset >= pm_size) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|invalid symbol index");
        return -XQC_EPARAM;
    }

    for (uint32_t i = 0; i < repair_num; i++) {
        pm_p = conn->fec_ctl->fec_send_decode_matrix[fec_bm_mode][i];
        rpr_key_p = conn->fec_ctl->fec_send_repair_key[fec_bm_mode][i].payload;
        if (*(rpr_key_p + pm_offset) & symbol_flag) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|source symbol already been calculated");

        } else if (symbol_flag & *(pm_p + pm_offset)) {
            output_p = outputs[i];
            ret = xqc_xor_code_one_symbol(input, output_p, in_size);
            // set validation and payload size of fec_send_repair_symbols_buff object
            tmp_size = xqc_max(in_size, conn->fec_ctl->fec_send_repair_symbols_buff[fec_bm_mode][i].payload_size);
            if (tmp_size > XQC_MAX_SYMBOL_SIZE) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|repair symbol payload exceeds the buffer size");
                ret = -XQC_EFEC_SCHEME_ERROR;
            }
            // have to set fec_send_repair_symbols_buff, otherwise the payload won't be set to 0 after encode process
            xqc_set_object_value(&conn->fec_ctl->fec_send_repair_symbols_buff[fec_bm_mode][i], 1, output_p,
                                tmp_size);
            if (ret == XQC_OK) {
                // update repair key value with symbol flag
                *(rpr_key_p + pm_offset) |= symbol_flag;
                xqc_set_object_value(&conn->fec_ctl->fec_send_repair_key[fec_bm_mode][i], 1, rpr_key_p, pm_size);
            }
        }
    }
    return ret;
}

/**
 * TODOfec: maybe need a function to update block size/ code rate, 
 *          for packet mask can be changed according to network conditions;
 */

xqc_int_t
xqc_packet_mask_encode(xqc_connection_t *conn, unsigned char *stream, size_t st_size, unsigned char **outputs,
    uint8_t fec_bm_mode)
{
    xqc_int_t ret;
    if (st_size > XQC_MAX_SYMBOL_SIZE) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_packet_mask_encode|invalid input size:%d|", st_size);
        return -XQC_EFEC_SYMBOL_ERROR;
    }

    ret = xqc_pm_code_symbols(conn, stream, st_size, outputs, fec_bm_mode);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_packet_mask_encode|code symbols failed with errno: %d|", ret);
        return -XQC_EFEC_SCHEME_ERROR;
    }

    return ret;
}

xqc_int_t
xqc_packet_mask_decode_one(xqc_connection_t *conn, unsigned char *recovered_symbols_buff,
    xqc_int_t block_id, xqc_int_t symbol_idx)
{
    xqc_int_t ret, src_block_id, src_symbol_idx, src_mask_offset;
    xqc_list_head_t *pos, *next, *src_list, *rpr_list;
    xqc_fec_rpr_syb_t *rpr_symbol;

    if (recovered_symbols_buff == NULL) {
        return -XQC_EPARAM;
    }
    
    src_list = &conn->fec_ctl->fec_recv_src_syb_list;
    rpr_list = &conn->fec_ctl->fec_recv_rpr_syb_list;
    rpr_symbol = xqc_get_rpr_symbol(rpr_list, block_id, symbol_idx);
    if (rpr_symbol == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|no such repair symbol|");
        return -XQC_EPARAM;
    }

    if (rpr_symbol->payload_size > XQC_MAX_SYMBOL_SIZE) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|pkm decoder can't process rpr symbol with size bigger than XQC_MAX_SYMBOL_SIZE.");
        return -XQC_EFEC_SCHEME_ERROR;
    }
    ret = xqc_xor_code_one_symbol(rpr_symbol->payload, recovered_symbols_buff, rpr_symbol->payload_size);
    
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|packet_mask calculate xor error");
        return -XQC_EFEC_SCHEME_ERROR;
    }

    xqc_list_for_each_safe(pos, next, src_list) {
        xqc_fec_src_syb_t *src_symbol = xqc_list_entry(pos, xqc_fec_src_syb_t, fec_list);

        if (src_symbol->block_id > block_id) {
            break;
        }
        src_block_id = src_symbol->block_id;
        src_symbol_idx = src_symbol->symbol_idx;
        src_mask_offset = src_symbol_idx / 8;
        if (src_mask_offset >= XQC_MAX_RPR_KEY_SIZE) {
            return -XQC_EFEC_SCHEME_ERROR;
        }

        if (src_block_id == block_id
            && *(rpr_symbol->recv_mask + src_mask_offset) & (1 << (7 - src_symbol_idx % 8)))
        {
            if (src_symbol->payload_size > XQC_MAX_SYMBOL_SIZE) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|pkm decoder can't process src symbol with size bigger than XQC_MAX_SYMBOL_SIZE.");
                return -XQC_EFEC_SCHEME_ERROR;
            }
            ret = xqc_xor_code_one_symbol(src_symbol->payload, recovered_symbols_buff, src_symbol->payload_size);
            
            if (ret != XQC_OK) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|packet_mask calculate xor error");
                return -XQC_EFEC_SCHEME_ERROR;
            }
        }
    }
    
    return ret;
}

const xqc_fec_code_callback_t xqc_packet_mask_code_cb = {
    .xqc_fec_init           = xqc_packet_mask_init,
    .xqc_fec_init_one       = xqc_packet_mask_init_one,
    .xqc_fec_encode         = xqc_packet_mask_encode,
    .xqc_fec_decode_one     = xqc_packet_mask_decode_one
    // .destroy = xqc_rs_destroy,
};