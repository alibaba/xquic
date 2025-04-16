
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#ifndef _XQC_FEC_SCHEME_H_INCLUDED_
#define _XQC_FEC_SCHEME_H_INCLUDED_


#include <xquic/xquic_typedef.h>
#include <xquic/xqc_errno.h>
#include "src/transport/xqc_fec.h"
#include "src/transport/fec_schemes/xqc_reed_solomon.h"


typedef enum {
    XQC_FEC_ENCODE_TYPE_NORMAL,
    XQC_FEC_ENCODE_TYPE_UNI,
} xqc_fec_encode_type_t;


xqc_int_t xqc_fec_encoder(xqc_connection_t *conn, unsigned char *input, size_t st_size, uint8_t fec_bm_mode);

xqc_int_t xqc_fec_bc_decoder(xqc_connection_t *conn, xqc_int_t block_id, xqc_int_t loss_src_num, xqc_usec_t rpr_time);

xqc_int_t xqc_fec_cc_decoder(xqc_connection_t *conn, xqc_fec_rpr_syb_t *rpr_symbol, uint8_t lack_syb_id);

xqc_int_t xqc_process_recovered_packet(xqc_connection_t *conn, unsigned char *recovered_payload, size_t symbol_size, xqc_usec_t rpr_recv_time);

xqc_int_t xqc_fec_encoder_check_params(xqc_connection_t *conn, xqc_int_t repair_symbol_num, xqc_fec_schemes_e encoder_scheme, size_t st_size);

#endif /* _XQC_FEC_SCHEME_H_INCLUDED_ */
