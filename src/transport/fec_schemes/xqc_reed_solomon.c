
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
*/


#include "src/transport/fec_schemes/xqc_reed_solomon.h"
#include "src/transport/fec_schemes/xqc_galois_calculation.h"
#include "src/transport/xqc_conn.h"


void
xqc_build_generator_matrix(unsigned char src_symbol_num, unsigned char total_symbol_num,
    unsigned char (*GM)[XQC_MAX_MT_ROW])
{
    unsigned char tmp_GM[XQC_MAX_MT_ROW][XQC_MAX_MT_ROW], invert_GM[XQC_MAX_MT_ROW][XQC_MAX_MT_ROW];

    xqc_build_vandermonde_matrix(total_symbol_num, src_symbol_num, tmp_GM);
    /* invert GM rows corresponds to src symbols */
    xqc_submatrix(0, src_symbol_num, 0, src_symbol_num, 256, 256, &invert_GM[0][0], &tmp_GM[0][0]);

    xqc_invert_matrix(src_symbol_num, src_symbol_num, invert_GM);
    
    xqc_matrix_time(total_symbol_num, src_symbol_num, tmp_GM,
                    src_symbol_num, src_symbol_num, invert_GM,
                    total_symbol_num, src_symbol_num, GM);
}

void
xqc_reed_solomon_init(xqc_connection_t *conn)
{
    xqc_build_generator_matrix(XQC_FEC_MAX_SYMBOL_NUM_PBLOCK - XQC_REPAIR_LEN, XQC_FEC_MAX_SYMBOL_NUM_PBLOCK, conn->fec_ctl->LC_GM);
}

xqc_int_t
xqc_rs_code_one_symbol(unsigned char (*GM_rows)[XQC_MAX_MT_ROW], unsigned char *input, unsigned char **outputs,
    xqc_int_t outputs_rows_num, xqc_int_t item_size, xqc_int_t input_idx)
{
    xqc_int_t output_i, j;
    unsigned char *output_p, *gm_p;
    output_i = 0;

    if (input_idx > XQC_MAX_MT_ROW) {
        return -XQC_EFEC_SCHEME_ERROR;
    }

    for (output_i = 0; output_i < outputs_rows_num; output_i++) {
        /* 一个单位的repair key的长度为symbollen */
        if (outputs[output_i] == NULL) {
            if (input_idx != 0) {
                return -XQC_EFEC_SCHEME_ERROR;
            }
            return -XQC_EMALLOC;
        }

        if (input_idx == 0) {
            xqc_memset(outputs[output_i], 0, item_size);
        }
        output_p = outputs[output_i];
        gm_p = GM_rows[output_i];
        for (j = 0; j < item_size; j++) {
            *(output_p + j) ^= xqc_galois_multiply(*(gm_p + input_idx), *(input + j));
        }
    }
    return XQC_OK;
}

xqc_int_t
xqc_rs_code_symbols(unsigned char (*GM_rows)[XQC_MAX_MT_ROW], unsigned char **inputs, xqc_int_t inputs_rows_num,
    unsigned char **outputs, xqc_int_t outputs_rows_num, xqc_int_t item_size)
{
    xqc_int_t input_i, output_i, ret;
    unsigned char *input_p, *output_p, *gm_p;
    input_i = output_i = 0;

    /**
     * outputs[i][byte j] = GM_rows[i][0]*Inputs[0][bytej] + GM_rows[i][1]*Inputs[1][bytej] + ...
     * The "+" is equal to XOR in galois fields
     */
    for (input_i = 0; input_i < inputs_rows_num; input_i++) {
        input_p = inputs[input_i];
        ret = xqc_rs_code_one_symbol(GM_rows, input_p, outputs, outputs_rows_num, item_size, input_i);
        if (ret != XQC_OK) {
            return ret;
        }
    }

    return XQC_OK;
}

xqc_int_t
xqc_reed_solomon_encode(xqc_connection_t *conn, unsigned char *stream, unsigned char **outputs)
{
    size_t              stream_size;
    xqc_int_t           i, ret, max_src_symbol_num, repair_symbol_num, total_symbol_num, symbol_idx;
    unsigned char       *key_p;
    /* Record multiplication result in galois field. */

    repair_symbol_num = conn->fec_ctl->fec_send_repair_symbols_num;
    max_src_symbol_num = conn->conn_settings.fec_params.fec_max_symbol_num_per_block * conn->conn_settings.fec_params.fec_code_rate;
    total_symbol_num = max_src_symbol_num + repair_symbol_num;
    symbol_idx = conn->fec_ctl->fec_send_src_symbols_num % max_src_symbol_num;
    stream_size = conn->conn_settings.fec_params.fec_max_symbol_size;

    ret = xqc_rs_code_one_symbol(conn->fec_ctl->LC_GM + max_src_symbol_num, stream, outputs,
                                 repair_symbol_num, stream_size, symbol_idx);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_reed_solomon_encode|xqc_rs_code_one_symbol failed");
        return -XQC_EFEC_SCHEME_ERROR;
    }

    /* If it's the last symbol in block, save it's key; */
    if (symbol_idx == max_src_symbol_num - 1) {
        for (i = 0 ; i < repair_symbol_num; i++) {
            key_p = conn->fec_ctl->fec_send_repair_key[i].payload;
            if (key_p == NULL) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_reed_solomon_encode|malloc key failed");
                return -XQC_EMALLOC;
            }
            xqc_memset(key_p, 0, max_src_symbol_num);
            xqc_memcpy(key_p, conn->fec_ctl->LC_GM + max_src_symbol_num + i, max_src_symbol_num);
            xqc_set_object_value(&conn->fec_ctl->fec_send_repair_key[i], 1, key_p, max_src_symbol_num);
        }
    }

    return XQC_OK;
}

void
xqc_gen_invert_GM(xqc_connection_t *conn, unsigned char (*GM)[XQC_MAX_MT_ROW], xqc_int_t block_idx)
{
    xqc_int_t i, j, k, symbol_num, repair_symbol_num, symbol_idx;
    symbol_num = conn->fec_ctl->fec_recv_symbols_num[block_idx];
    repair_symbol_num = conn->fec_ctl->fec_recv_repair_symbols_num[block_idx];
    symbol_idx = 0;

    xqc_memset(GM, 0, XQC_MAX_MT_ROW * XQC_MAX_MT_ROW);
    for (i = 0, j = 0; i < symbol_num; i++) {
        if (i < symbol_num - repair_symbol_num) {
            for (k = symbol_idx; k < symbol_num; k++) {
                if (conn->fec_ctl->fec_recv_symbols_flag[block_idx] & (1 << k)) {
                    symbol_idx = k;
                    GM[i][symbol_idx] = 1;
                    symbol_idx++;
                    break;
                }
            }

        } else {
            if (!conn->fec_ctl->fec_recv_repair_key[block_idx][j].is_valid) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_gen_invert_GM|repair key is null");
                return;
            }
            xqc_memcpy(GM[i], conn->fec_ctl->fec_recv_repair_key[block_idx][j].payload, conn->remote_settings.fec_max_symbols_num);
            j++;
        }
    }
    xqc_invert_matrix(symbol_num, symbol_num, GM);
}

xqc_int_t
xqc_reed_solomon_decode(xqc_connection_t *conn, unsigned char **outputs, xqc_int_t block_idx,
    xqc_int_t *loss_symbols_idx, xqc_int_t loss_symbols_len)
{
    /**
     * 根据fec_recv_symbols_buff和fec_recv_repair_key复原丢失的srcsymbol：
     * 1. 生成GM的逆矩阵
     * 2. 将recv symbols格式化
     * 3. 逆矩阵 * recv symbols
     */
    uint64_t            symbol_size;
    xqc_int_t           i, j, ret, recv_symbols_num, recv_repair_symbols_num;
    unsigned char       GM[XQC_MAX_MT_ROW][XQC_MAX_MT_ROW], *recv_symbols_buff[XQC_FEC_MAX_SYMBOL_NUM_PBLOCK - XQC_REPAIR_LEN], *recovered_symbols_buff[XQC_FEC_MAX_SYMBOL_NUM_PBLOCK];
    
    for (i = 0; i < XQC_FEC_MAX_SYMBOL_NUM_PBLOCK; i++) {
        if (i < XQC_FEC_MAX_SYMBOL_NUM_PBLOCK - XQC_REPAIR_LEN) {
            recv_symbols_buff[i] = NULL;
        }
        recovered_symbols_buff[i] = xqc_calloc(1, XQC_PACKET_OUT_SIZE + XQC_ACK_SPACE - XQC_HEADER_SPACE - XQC_FEC_SPACE);
    }

    recv_symbols_num = conn->fec_ctl->fec_recv_symbols_num[block_idx];
    recv_repair_symbols_num = conn->fec_ctl->fec_recv_repair_symbols_num[block_idx];
    symbol_size = conn->remote_settings.fec_max_symbol_size;
    xqc_gen_invert_GM(conn, GM, block_idx);
    /* 将收到的symbol整顿为矩阵 */
    for (i = 0, j = 0; i < recv_symbols_num && j < recv_symbols_num + recv_repair_symbols_num; j++) {
        if (conn->fec_ctl->fec_recv_symbols_flag[block_idx] & (1 << j)
            && conn->fec_ctl->fec_recv_symbols_buff[block_idx][j].is_valid)
        {
            recv_symbols_buff[i] = conn->fec_ctl->fec_recv_symbols_buff[block_idx][j].payload;
            i++;
        }
    }
    if (i != recv_symbols_num) {
        xqc_log(conn->log, XQC_LOG_WARN, "|quic_fec|xqc_reed_solomon_decode|recv symbols not enouph to recover lost symbols");
        return -XQC_EFEC_SCHEME_ERROR;
    }

    ret = xqc_rs_code_symbols(GM, recv_symbols_buff, recv_symbols_num,
                              recovered_symbols_buff, recv_symbols_num,
                              symbol_size);

    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_reed_solomon_decode|reed solomon decode symbols failed");
    }

    for (i = 0; i < loss_symbols_len; i++) {
        xqc_fec_ctl_save_symbol(&outputs[i], recovered_symbols_buff[loss_symbols_idx[i]], symbol_size);
    }

    for (i = 0; i < recv_symbols_num; i++) {
        if (recovered_symbols_buff[i] != NULL) {
            xqc_free(recovered_symbols_buff[i]);
        }
    }

    return ret;
}


const xqc_fec_code_callback_t xqc_reed_solomon_code_cb = {
    .xqc_fec_init           = xqc_reed_solomon_init,
    .xqc_fec_decode         = xqc_reed_solomon_decode,
    .xqc_fec_encode         = xqc_reed_solomon_encode,
    // .destroy = xqc_rs_destroy,
};