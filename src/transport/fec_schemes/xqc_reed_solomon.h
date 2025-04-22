
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

xqc_int_t xqc_rs_code_one_symbol(unsigned char (*GM_rows)[XQC_RSM_COL], unsigned char *input, unsigned char **outputs,
    xqc_int_t outputs_rows_num, xqc_int_t item_size, xqc_int_t input_idx);

void xqc_build_generator_matrix(unsigned char src_symbol_num, unsigned char total_symbol_num,
    unsigned char (*GM)[XQC_RSM_COL]);

xqc_int_t xqc_rs_code_symbols(unsigned char (*GM_rows)[XQC_RSM_COL], unsigned char **inputs, xqc_int_t inputs_rows_num,
    unsigned char **outputs, xqc_int_t outputs_rows_num, xqc_int_t item_size);

void xqc_reed_solomon_init(xqc_connection_t *conn);
void xqc_reed_solomon_init_one(xqc_connection_t *conn, uint8_t bm_idx);
xqc_int_t xqc_reed_solomon_decode(xqc_connection_t *conn, unsigned char **outputs, size_t *output_size, xqc_int_t block_idx);
xqc_int_t xqc_reed_solomon_encode(xqc_connection_t *conn, unsigned char *stream, size_t st_size, unsigned char **outputs,
    uint8_t fec_bm_mode);

#endif