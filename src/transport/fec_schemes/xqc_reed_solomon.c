
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
*/


#include "src/transport/fec_schemes/xqc_reed_solomon.h"
#include "src/transport/fec_schemes/xqc_galois_calculation.h"
#include "src/transport/xqc_conn.h"


void
xqc_build_generator_matrix(unsigned char src_symbol_num, unsigned char total_symbol_num,
    unsigned char (*GM)[XQC_RSM_COL])
{
    int tmp_gm_col, invert_gm_col;
    unsigned char tmp_GM[XQC_RSM_COL * 2][XQC_RSM_COL] = {{0}}, invert_GM[XQC_RSM_COL][XQC_RSM_COL] = {{0}};

    tmp_gm_col = invert_gm_col = XQC_RSM_COL;

    xqc_build_vandermonde_matrix(total_symbol_num, src_symbol_num, tmp_GM);
    /* invert GM rows corresponds to src symbols */
    xqc_submatrix(0, src_symbol_num, 0, src_symbol_num, invert_gm_col, tmp_gm_col, &invert_GM[0][0], &tmp_GM[0][0]);

    xqc_invert_matrix(src_symbol_num, src_symbol_num, invert_GM);
    
    xqc_matrix_time(total_symbol_num, src_symbol_num, tmp_GM,
                    src_symbol_num, src_symbol_num, invert_GM,
                    total_symbol_num, src_symbol_num, GM);
}

void
xqc_reed_solomon_init_one(xqc_connection_t *conn, uint8_t bm_idx)
{
    return;
}

void
xqc_reed_solomon_init(xqc_connection_t *conn)
{
    xqc_int_t           i, j, ret, max_src_symbol_num, repair_symbol_num, symbol_idx;
    unsigned char       *key_p;

    max_src_symbol_num = xqc_get_fec_blk_size(conn, XQC_DEFAULT_SIZE_REQ);
    repair_symbol_num = conn->fec_ctl->fec_send_required_repair_num[XQC_DEFAULT_SIZE_REQ];

    if (max_src_symbol_num > XQC_REPAIR_LEN) {
        conn->conn_settings.enable_encode_fec = 0;
        conn->local_settings.enable_encode_fec = 0;
        conn->conn_settings.fec_params.fec_encoder_scheme = 0;
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec| reed-solomon code init error");
        return;
    }

    xqc_build_generator_matrix(max_src_symbol_num, max_src_symbol_num + repair_symbol_num, conn->fec_ctl->decode_matrix);

    /* If it's the last symbol in block, save it's key; */
    for (i = 0 ; i < repair_symbol_num; i++) {
        key_p = conn->fec_ctl->fec_send_repair_key[XQC_DEFAULT_SIZE_REQ][i].payload;
        if (key_p == NULL) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_reed_solomon_encode|malloc key failed");
            return;
        }
        xqc_memset(key_p, 0, max_src_symbol_num);
        xqc_memcpy(key_p, conn->fec_ctl->decode_matrix[max_src_symbol_num + i], max_src_symbol_num);
        xqc_set_object_value(&conn->fec_ctl->fec_send_repair_key[XQC_DEFAULT_SIZE_REQ][i], 1, key_p, max_src_symbol_num);
    }

}

xqc_int_t
xqc_rs_code_one_symbol(unsigned char (*GM_rows)[XQC_RSM_COL], unsigned char *input, unsigned char **outputs,
    xqc_int_t outputs_rows_num, xqc_int_t item_size, xqc_int_t input_idx)
{
    xqc_int_t output_i, j;
    unsigned char *output_p, *gm_p;
    output_i = 0;

    if (input_idx > XQC_FEC_MAX_SYMBOL_NUM_PBLOCK) {
        return -XQC_EFEC_SCHEME_ERROR;
    }

    for (output_i = 0; output_i < outputs_rows_num; output_i++) {
        /* symbol_length is the length of a repair key unit */
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
xqc_rs_code_symbols(unsigned char (*GM_rows)[XQC_RSM_COL], unsigned char **inputs, xqc_int_t inputs_rows_num,
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
xqc_reed_solomon_encode(xqc_connection_t *conn, unsigned char *stream, size_t st_size, unsigned char **outputs,
    uint8_t fec_bm_mode)
{
    size_t              tmp_size;
    xqc_int_t           i, ret, max_src_symbol_num, repair_symbol_num, symbol_idx;
    unsigned char       *key_p, *output_p;
    /* Record multiplication result in galois field. */

    max_src_symbol_num = xqc_get_fec_blk_size(conn, XQC_DEFAULT_SIZE_REQ);
    symbol_idx = conn->fec_ctl->fec_send_symbol_num[fec_bm_mode];
    repair_symbol_num = conn->fec_ctl->fec_send_required_repair_num[fec_bm_mode];

    ret = xqc_rs_code_one_symbol(conn->fec_ctl->decode_matrix + max_src_symbol_num, stream, outputs,
                                 repair_symbol_num, st_size, symbol_idx);
    for (i = 0; i < repair_symbol_num; i++) {
        // set validation and payload size of fec_send_repair_symbols_buff object
        tmp_size = xqc_max(st_size, conn->fec_ctl->fec_send_repair_symbols_buff[fec_bm_mode][i].payload_size);
        if (tmp_size > XQC_MAX_SYMBOL_SIZE) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|repair symbol payload exceeds the buffer size");
            ret = -XQC_EFEC_SCHEME_ERROR;
        }
        output_p = outputs[i];
        // have to set fec_send_repair_symbols_buff, otherwise the payload won't be set to 0 after encode process
        xqc_set_object_value(&conn->fec_ctl->fec_send_repair_symbols_buff[fec_bm_mode][i], 1, output_p,
                             tmp_size);
    }
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_reed_solomon_encode|xqc_rs_code_one_symbol failed");
        return -XQC_EFEC_SCHEME_ERROR;
    }

    return XQC_OK;
}

void
xqc_gen_invert_GM(xqc_connection_t *conn, int row, int col, unsigned char (*GM)[XQC_RSM_COL], xqc_int_t block_idx, xqc_int_t symbol_flag)
{
    xqc_int_t i, j, k, symbol_num, repair_symbol_num, src_symbol_num, symbol_idx, ret;
    xqc_list_head_t *pos, *next;
    xqc_fec_rpr_syb_t *rpr_symbol;

    src_symbol_num = xqc_cnt_src_symbols_num(conn->fec_ctl, block_idx);
    repair_symbol_num = xqc_cnt_rpr_symbols_num(conn->fec_ctl, block_idx);
    symbol_num = src_symbol_num + repair_symbol_num;
    symbol_idx = 0;
    rpr_symbol = NULL;

    xqc_memset(GM, 0, col * sizeof(*GM));

    for (i = 0; i < row; i++) {
        for (k = symbol_idx; k < col; k++) {
            if (symbol_flag & (1 << k)) {
                symbol_idx = k;
                GM[i][symbol_idx] = 1;
                symbol_idx++;
                break;
            }
        }
    }

    xqc_list_for_each_safe(pos, next, &conn->fec_ctl->fec_recv_rpr_syb_list) {
        xqc_fec_rpr_syb_t *rpr_symbol = xqc_list_entry(pos, xqc_fec_rpr_syb_t, fec_list);
        if (rpr_symbol->block_id > block_idx) {
            break;
        }
        if (rpr_symbol->block_id == block_idx) {
            xqc_memcpy(GM[i], rpr_symbol->repair_key, rpr_symbol->repair_key_size);
            i++;
        }
    }

    xqc_invert_matrix(col, col, GM);
}

xqc_int_t
xqc_reed_solomon_decode(xqc_connection_t *conn, unsigned char **outputs, size_t *output_size, xqc_int_t block_idx)
{
    /**
     * 根据fec_recv_symbols_buff和fec_recv_repair_key复原丢失的srcsymbol：
     * 1. 生成GM的逆矩阵
     * 2. 将recv symbols格式化
     * 3. 逆矩阵 * recv symbols
     */
    xqc_int_t           i, j, ret, recv_symbols_num, recv_source_symbols_num, symbol_flag, max_src_symbol_num, loss_src_num;
    unsigned char       GM[XQC_RSM_COL][XQC_RSM_COL] = {{0}}, *recv_symbols_buff[XQC_RSM_COL], *recovered_symbols_buff[XQC_FEC_MAX_SYMBOL_NUM_PBLOCK];
    xqc_int_t           loss_symbol_idx[XQC_RSM_COL] = {-1};

    *output_size = loss_src_num = 0;
    recv_source_symbols_num = xqc_cnt_src_symbols_num(conn->fec_ctl, block_idx);
    recv_symbols_num =  recv_source_symbols_num + xqc_cnt_rpr_symbols_num(conn->fec_ctl, block_idx);
    symbol_flag = xqc_get_symbol_flag(conn, block_idx);
    max_src_symbol_num = conn->remote_settings.fec_max_symbols_num;

    for (i = 0; i < recv_symbols_num; i++) {
        recv_symbols_buff[i] = xqc_calloc(XQC_MAX_SYMBOL_SIZE, sizeof(unsigned char));
        recovered_symbols_buff[i] = xqc_calloc(XQC_MAX_SYMBOL_SIZE, sizeof(unsigned char));
    }

    for (i = 0; i < max_src_symbol_num; i++) {
        if ((symbol_flag & (1 << i)) == 0) {
            loss_symbol_idx[loss_src_num] = i;
            loss_src_num++;
        }
    }

    xqc_gen_invert_GM(conn, recv_source_symbols_num, recv_symbols_num, GM, block_idx, symbol_flag);

    // get symbols and make them into matrix according to block idx;
    i = xqc_get_symbols_buff(recv_symbols_buff, conn->fec_ctl, block_idx, output_size);
    if (i < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_get_symbols_buff|recv invalid symbols");
        return -XQC_EFEC_SCHEME_ERROR;
    }
    if (i != recv_symbols_num) {
        xqc_log(conn->log, XQC_LOG_WARN, "|quic_fec|xqc_reed_solomon_decode|recv symbols not enouph to recover lost symbols");
        return -XQC_EFEC_SCHEME_ERROR;
    }

    ret = xqc_rs_code_symbols(GM, recv_symbols_buff, recv_symbols_num, 
                              recovered_symbols_buff, recv_symbols_num,
                              *output_size);

    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_reed_solomon_decode|reed solomon decode symbols failed");
    }

    for (i = 0; i < loss_src_num; i++) {
        xqc_fec_ctl_save_symbol(&outputs[i], recovered_symbols_buff[loss_symbol_idx[i]], *output_size);
    }

    for (i = 0; i < recv_symbols_num; i++) {
        if (recv_symbols_buff[i] != NULL) {
            xqc_free(recv_symbols_buff[i]);
        }
        if (recovered_symbols_buff[i] != NULL) {
            xqc_free(recovered_symbols_buff[i]);
        }
    }

    return ret;
}


const xqc_fec_code_callback_t xqc_reed_solomon_code_cb = {
    .xqc_fec_init           = xqc_reed_solomon_init,
    .xqc_fec_init_one       = xqc_reed_solomon_init_one,
    .xqc_fec_decode         = xqc_reed_solomon_decode,
    .xqc_fec_encode         = xqc_reed_solomon_encode,
    // .destroy = xqc_rs_destroy,
};