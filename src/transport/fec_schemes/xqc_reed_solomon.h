
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#ifndef _XQC_FEC_REED_SOLOMON_H_
#define _XQC_FEC_REED_SOLOMON_H_


#include <xquic/xquic.h>
#include <xquic/xqc_errno.h>
#include <xquic/xquic_typedef.h>
#include "src/transport/xqc_defs.h"

extern const xqc_fec_code_callback_t xqc_reed_solomon_code_cb;

xqc_int_t xqc_rs_code_one_symbol(unsigned char (*GM_rows)[XQC_MAX_MT_ROW], unsigned char *input, unsigned char **outputs,
    xqc_int_t outputs_rows_num, xqc_int_t item_size, xqc_int_t input_idx);
void xqc_build_generator_matrix(unsigned char src_symbol_num, unsigned char total_symbol_num,
    unsigned char (*GM)[XQC_MAX_MT_ROW]);

xqc_int_t xqc_rs_code_symbols(unsigned char (*GM_rows)[XQC_MAX_MT_ROW], unsigned char **inputs, xqc_int_t inputs_rows_num,
    unsigned char **outputs, xqc_int_t outputs_rows_num, xqc_int_t item_size);

void xqc_reed_solomon_init();
xqc_int_t xqc_reed_solomon_decode(xqc_connection_t *conn, unsigned char **recovered_symbols_buff, xqc_int_t block_idx,
    xqc_int_t *loss_symbols_idx, xqc_int_t loss_symbols_len);
xqc_int_t xqc_reed_solomon_encode(xqc_connection_t *conn, unsigned char *stream, unsigned char **outputs);

#endif