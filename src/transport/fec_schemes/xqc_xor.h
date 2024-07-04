
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#ifndef _XQC_FEC_XOR_H_
#define _XQC_FEC_XOR_H_


#include "src/transport/fec_schemes/xqc_xor.h"
#include "src/transport/fec_schemes/xqc_galois_calculation.h"
#include <xquic/xquic.h>
#include <xquic/xqc_errno.h>
#include <xquic/xquic_typedef.h>

extern const xqc_fec_code_callback_t xqc_xor_code_cb;

xqc_int_t xqc_xor_code_one_symbol(unsigned char *input, unsigned char **outputs, xqc_int_t item_size);
xqc_int_t xqc_xor_code_symbols(unsigned char **inputs, xqc_int_t inputs_rows_num, unsigned char **outputs,
    xqc_int_t outputs_rows_num, xqc_int_t item_size);

void xqc_xor_init();
xqc_int_t xqc_xor_decode(xqc_connection_t *conn, unsigned char **outputs, xqc_int_t block_idx,
    xqc_int_t *loss_symbols_idx, xqc_int_t loss_symbols_len);
xqc_int_t xqc_xor_encode(xqc_connection_t *conn, unsigned char *stream, unsigned char **outputs);

#endif