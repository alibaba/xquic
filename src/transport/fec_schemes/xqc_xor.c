
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
*/


#include "src/transport/fec_schemes/xqc_xor.h"
#include "src/transport/xqc_conn.h"

void
xqc_xor_init(xqc_connection_t *conn)
{
    return;
}

xqc_int_t
xqc_xor_code_one_symbol(unsigned char *input, unsigned char **outputs,
    xqc_int_t item_size)
{
    xqc_int_t i;
    unsigned char *output_p;

    if (*outputs == NULL) {
        return -XQC_EMALLOC;
    }

    output_p = *outputs;
    for (i = 0; i < item_size; i++) {
        *(output_p + i) ^= *(input + i);
    }

    return XQC_OK;
}

xqc_int_t
xqc_xor_code_symbols(unsigned char **inputs, xqc_int_t inputs_rows_num, unsigned char **outputs,
    xqc_int_t outputs_rows_num, xqc_int_t item_size)
{
    xqc_int_t input_i, output_i, ret;
    unsigned char *input_p, *output_p;
    if (outputs_rows_num != 1) {
        return -XQC_EFEC_SYMBOL_ERROR;
    }

    for (input_i = 0; input_i < inputs_rows_num; input_i++) {
        input_p = inputs[input_i];
        ret = xqc_xor_code_one_symbol(input_p, &outputs[0], item_size);
        if (ret != XQC_OK) {
            return ret;
        }
    }

    return XQC_OK;
}

xqc_int_t
xqc_xor_decode(xqc_connection_t *conn, unsigned char **outputs, xqc_int_t block_idx,
    xqc_int_t *loss_symbols_idx, xqc_int_t loss_symbols_len)
{
    xqc_int_t i, j, ret, recv_symbols_num, recv_repair_symbols_num, output_len;
    unsigned char *recv_symbols_buff[XQC_FEC_MAX_SYMBOL_NUM_PBLOCK - XQC_REPAIR_LEN];

    /* TODOfec: 对xor来说，若XQC_FEC_MAX_SYMBOL_NUM_PBLOCK - XQC_REPAIR_LEN != 1, 不该通过协商*/

    recv_symbols_num = conn->fec_ctl->fec_recv_symbols_num[block_idx];
    recv_repair_symbols_num = conn->fec_ctl->fec_recv_repair_symbols_num[block_idx];
    output_len = 1;

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
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_xor_decode|process recv_symbols into matrix failed");
        return -XQC_EFEC_SCHEME_ERROR;
    }

    ret = xqc_xor_code_symbols(recv_symbols_buff, recv_symbols_num, outputs,
                           output_len, conn->remote_settings.fec_max_symbol_size);

    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_xor_decode|xor decode symbols failed");
        return ret;
    }

    return XQC_OK;
}

xqc_int_t
xqc_xor_encode(xqc_connection_t *conn, unsigned char *stream, unsigned char **outputs)
{
    size_t              stream_size;
    xqc_int_t           ret;

    stream_size = conn->conn_settings.fec_params.fec_max_symbol_size;

    ret = xqc_xor_code_one_symbol(stream, &outputs[0], stream_size);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_xor_encode|code one symbol failed");
        return -XQC_EFEC_SCHEME_ERROR;
    }
    
    return XQC_OK;
}

const xqc_fec_code_callback_t xqc_xor_code_cb = {
    .xqc_fec_init           = xqc_xor_init,
    .xqc_fec_decode         = xqc_xor_decode,
    .xqc_fec_encode         = xqc_xor_encode,
    // .destroy = xqc_rs_destroy,
};