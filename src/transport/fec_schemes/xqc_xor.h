
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#ifndef _XQC_FEC_XOR_H_
#define _XQC_FEC_XOR_H_


#include "src/transport/fec_schemes/xqc_galois_calculation.h"
#include <xquic/xquic.h>
#include <xquic/xqc_errno.h>
#include <xquic/xquic_typedef.h>

extern const xqc_fec_code_callback_t xqc_xor_code_cb;

xqc_int_t xqc_xor_code_one_symbol(unsigned char *input, unsigned char *outputs, xqc_int_t item_size);

void xqc_xor_init(xqc_connection_t *conn);
void xqc_xor_init_one(xqc_connection_t *conn, uint8_t bm_idx);
xqc_int_t xqc_xor_decode(xqc_connection_t *conn, unsigned char **outputs, size_t *output_size, xqc_int_t block_idx);
xqc_int_t xqc_xor_encode(xqc_connection_t *conn, unsigned char *stream, size_t st_size, unsigned char **outputs,
    uint8_t fec_bm_mode);

#endif