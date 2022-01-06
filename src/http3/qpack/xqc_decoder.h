/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_DECODER_H_
#define _XQC_DECODER_H_

#include "src/http3/qpack/xqc_qpack_defs.h"
#include "src/http3/qpack/xqc_rep.h"
#include "src/http3/qpack/stable/xqc_stable.h"
#include "src/http3/qpack/dtable/xqc_dtable.h"

typedef struct xqc_decoder_s xqc_decoder_t;


/**
 * @brief create decoder
 * @return xqc_decoder_t* decoder handler
 */
xqc_decoder_t *xqc_decoder_create(xqc_log_t *log, size_t max_dtable_cap);


/**
 * @brief destroy decoder
 * @param dec decoder handler
 */
void xqc_decoder_destroy(xqc_decoder_t *dec);


/**
 * @brief set the dynamic table capacity of decoder
 * @param dec decoder handler
 * @param cap capacity
 * @return xqc_int_t XQC_OK for success, others for failure
 */
xqc_int_t xqc_decoder_set_dtable_cap(xqc_decoder_t *dec, uint64_t cap);


/**
 * @brief duplicate an entry with absolute index
 * @param dec decoder handler
 * @param idx index of entry
 * @return xqc_int_t XQC_OK for success, others for failure
 */
xqc_int_t xqc_decoder_duplicate(xqc_decoder_t *dec, uint64_t idx);


/**
 * @brief insert name-value pair into decoder's dynamic table
 * @param dec decoder handler
 * @param name entry name
 * @param nlen entry name len
 * @param value entry value
 * @param vlen entry value len
 * @return XQC_OK for success, others for failure
 */
xqc_int_t xqc_decoder_insert_literal(xqc_decoder_t *dec, unsigned char *name, size_t nlen,
    unsigned char *value, size_t vlen);


/**
 * @brief react on Insert With Name Reference instruction
 * @param dec decoder handler
 * @param t table flag: XQC_DTABLE_FLAG or XQC_STABLE_FLAG
 * @param nidx index of name-referred entry
 * @param value entry value
 * @param vlen entry value len
 * @return XQC_OK for success, others for failure 
 */
xqc_int_t xqc_decoder_insert_name_ref(xqc_decoder_t *dec, xqc_flag_t t, uint64_t nidx, 
    unsigned char *value, size_t vlen);

uint64_t xqc_decoder_get_insert_cnt(xqc_decoder_t *dec);

ssize_t xqc_decoder_dec_header(xqc_decoder_t *dec, xqc_rep_ctx_t *ctx,
    unsigned char *buf, size_t buf_len, xqc_http_header_t *hdr, xqc_bool_t *blocked);

#endif
