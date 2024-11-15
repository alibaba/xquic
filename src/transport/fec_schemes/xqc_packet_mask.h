
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#ifndef _XQC_FEC_PACKET_MASK_H_
#define _XQC_FEC_PACKET_MASK_H_

#include "src/transport/fec_schemes/xqc_galois_calculation.h"
#include <xquic/xquic.h>
#include <xquic/xqc_errno.h>
#include <xquic/xquic_typedef.h>

// TODOfec: might needed change according to the draft
#define XQC_MAX_MASK_SIZE 48
#define XQC_MAX_LOOKUP_MASK_SIZE 12

extern const xqc_fec_code_callback_t xqc_packet_mask_code_cb;

void xqc_packet_mask_init(xqc_connection_t *conn);

void
xqc_packet_mask_init_one(xqc_connection_t *conn, uint8_t bm_idx);

xqc_int_t xqc_packet_mask_encode(xqc_connection_t *conn, unsigned char *stream, size_t st_size, unsigned char **outputs,
    uint8_t fec_bm_mode);

xqc_int_t xqc_packet_mask_decode_one(xqc_connection_t *conn, unsigned char *recovered_symbols_buff,
    xqc_int_t block_id, xqc_int_t symbol_idx);
#endif