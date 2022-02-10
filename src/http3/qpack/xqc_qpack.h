/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_QPACK_H_
#define _XQC_QPACK_H_

#include "src/http3/qpack/xqc_qpack_defs.h"
#include "src/http3/qpack/xqc_encoder.h"
#include "src/http3/qpack/xqc_decoder.h"
#include "src/http3/qpack/xqc_rep.h"
#include "src/http3/qpack/xqc_ins.h"
#include "src/common/xqc_log.h"


typedef struct xqc_qpack_s xqc_qpack_t;


typedef enum xqc_qpack_ins_type_s {
    XQC_INS_TYPE_ENCODER,
    XQC_INS_TYPE_DECODER,
} xqc_qpack_ins_type_t;

/**
 * @brief get buffer to write instruction
 * 
 */
typedef xqc_var_buf_t *(*xqc_get_ins_buf_pt)(xqc_qpack_ins_type_t type, void *user_data);

/**
 * @brief output instruction callback function.
 * instructions might be generated in multiple situations,
 * it easier to handle them with a callback
 */
typedef ssize_t (*xqc_write_ins_pt)(xqc_qpack_ins_type_t type, xqc_var_buf_t *buf,
    void *user_data);

/* instruction buffer callback */
typedef struct xqc_qpack_ins_cb_s {
    xqc_get_ins_buf_pt  get_buf_cb;
    xqc_write_ins_pt    write_ins_cb;
} xqc_qpack_ins_cb_t;


/**
 * @brief create qpack handler, qpack module is responsible for:
 * 1. write and parse encode/decode instruction,
 * 2. encoding http headers, decoding encoded field sections
 * @param max_cap the local configured max capacity of dtable. this value is effective for DECODER
 * @param ins_cb the callback for encoder/decoder instruction buffer and send
 * @param user_data callback user data in ins_cb
 * @param log log handler for log print
 * @return qpack handler, will be used when qpack functions called
 */
xqc_qpack_t *xqc_qpack_create(uint64_t max_cap, xqc_log_t *log, const xqc_qpack_ins_cb_t *ins_cb,
    void *user_data);

/**
 * @brief destroy qpack handler
 * @param qpk qpack handler
 */
void xqc_qpack_destroy(xqc_qpack_t *qpk);


/**
 * @brief set ENCODER's max dynamic table capacity.
 * @param qpk qpack handler
 * @param max_cap max capacity of dynamic table. SETTINGS_QPACK_MAX_TABLE_CAPACITY from peer
 * @return XQC_OK for suc; negative for failure 
 */
xqc_int_t xqc_qpack_set_enc_max_dtable_cap(xqc_qpack_t *qpk, size_t max_cap);

/**
 * @brief set ENCODER's dynamic table capacity, the final capacity will be negotiated. capacity of
 * the decoder's dynamic table is set after receiving peer's Set Dynamic Table Capacity instruction
 * @param qpk, qpack instance
 * @param cap, the input cap
 * @return XQC_OK for suc; negative for failure. when there are still referred entries in dynamic 
 * table, set capacity might return error
 */
xqc_int_t xqc_qpack_set_dtable_cap(xqc_qpack_t *qpk, size_t cap);

/**
 * @brief set max blocked stream
 */
xqc_int_t xqc_qpack_set_max_blocked_stream(xqc_qpack_t *qpk, size_t max_blocked_stream);

/**
 * @brief get insert count
 */
uint64_t xqc_qpack_get_dec_insert_count(xqc_qpack_t *qpk);


/**
 * @brief process encoder instructions
 */
ssize_t xqc_qpack_process_encoder(xqc_qpack_t *qpk, unsigned char *data, size_t data_len);

/**
 * @brief process decoder instructions
 */
ssize_t xqc_qpack_process_decoder(xqc_qpack_t *qpk, unsigned char *data, size_t data_len);



/**
 * @brief create parse context for request stream, this shall be invoked everytime when a new
 * request stream is created
 * @return the context handler of request stream
 */
xqc_rep_ctx_t *xqc_qpack_create_req_ctx(uint64_t stream_id);

/**
 * @brief reset context, called when an HEADERS frame was totally decoded
 */
void xqc_qpack_clear_req_ctx(void *ctx);

/**
 * @brief destroy ctx created by xqc_qpack_create_req_ctx
 */
void xqc_qpack_destroy_req_ctx(void *ctx);

/**
 * @brief get required insert count
 */
uint64_t xqc_qpack_get_req_rqrd_insert_cnt(void *ctx);


/**
 * @brief set encoder's dtable insert limit for name and entry. long name and large entry exceed
 * their percentage limit will not be inserted into dtable and be sent as Literal Field Lines. the
 * length limited equals to (capacity * percent_limit)
 * @param name_limit the limit of name length percent of dtable capacity, [0, 1]
 * @param entry_limit the limit of entry length percent of dtable capacity, [0, 1]
 * @return XQC_OK for success, others for failure 
 */
void xqc_qpack_set_enc_insert_limit(xqc_qpack_t *qpk, double name_limit, double entry_limit);


/**
 * @brief decode bytes from request stream
 * @param qpk qpack handler
 * @param ctx context for decoding representation
 * @param data input data
 * @param headers output headers
 * @param fin if stream is finished
 * @param blocked [out] tells that if this request stream is blocked
 * @return >= 0 for bytes consumed, others for failure
 */
ssize_t xqc_qpack_dec_headers(xqc_qpack_t *qpk, xqc_rep_ctx_t *req_ctx, unsigned char *data,
    size_t data_len, xqc_http_headers_t *headers, xqc_bool_t fin, xqc_bool_t *blocked);

/**
 * @brief encode http headers to encoded field section
 * @param qpk qpack handler
 * @param stream_id QUIC stream's id of the request
 * @param headers h3 request headers
 * @param rep_buf representation buff
 * @param ins_buf instruction buff
 * @return XQC_OK for success, < 0 for failure
 */
xqc_int_t xqc_qpack_enc_headers(xqc_qpack_t *qpk, uint64_t stream_id,
    xqc_http_headers_t *headers, xqc_var_buf_t *rep_buf);

#endif
