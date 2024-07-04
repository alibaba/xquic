
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#ifndef _XQC_FEC_SCHEME_H_INCLUDED_
#define _XQC_FEC_SCHEME_H_INCLUDED_


#include <xquic/xquic_typedef.h>
#include <xquic/xqc_errno.h>
#include "src/transport/fec_schemes/xqc_reed_solomon.h"


typedef enum {
    XQC_FEC_ENCODE_TYPE_NORMAL,
    XQC_FEC_ENCODE_TYPE_UNI,
} xqc_fec_encode_type_t;


xqc_int_t xqc_fec_encoder(xqc_connection_t *conn, unsigned char *stream);

xqc_int_t xqc_fec_decoder(xqc_connection_t *conn, xqc_int_t block_idx);

xqc_int_t xqc_process_recovered_packet(xqc_connection_t *conn, unsigned char **recovered_symbols_buff,
    xqc_int_t loss_symbol_idx_len);

#endif /* _XQC_FEC_SCHEME_H_INCLUDED_ */
