/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_REP_H_
#define _XQC_REP_H_

#include "src/http3/qpack/xqc_qpack_defs.h"
#include "src/http3/qpack/xqc_prefixed_int.h"
#include "src/http3/qpack/xqc_prefixed_str.h"
#include "src/common/xqc_common_inc.h"
#include "src/http3/qpack/xqc_qpack_defs.h"

typedef struct xqc_rep_ctx_s xqc_rep_ctx_t;

/* decode stages of representation */
typedef enum xqc_rep_decode_state_s {
    /* request insert count */
    XQC_REP_DECODE_STATE_RICNT = 0,

    /* S bit */
    XQC_REP_DECODE_STATE_BASE_SIGN,

    /* Delta Base */
    XQC_REP_DECODE_STATE_BASE,

    /* field line type */
    XQC_REP_DECODE_STATE_OPCODE,

    /* index, which will be referred when parsing all
       filed lines besides XQC_REP_TYPE_LITERAL  */
    XQC_REP_DECODE_STATE_INDEX,

    /* name, referred when parsing XQC_REP_TYPE_LITERAL */
    XQC_REP_DECODE_STATE_NAME,

    /* value, referred when parsing XQC_REP_TYPE_NAME_REFERENCE,
       XQC_REP_TYPE_POST_BASE_NAME_REFERENCE, XQC_REP_TYPE_LITERAL */
    XQC_REP_DECODE_STATE_VALUE,

    /* finish of decoding a field line */
    XQC_REP_DECODE_STATE_FINISH

} xqc_rep_decode_state_t;

/* type of representation */
typedef enum xqc_rep_type_s {
    /* Indexed Field Line */
    XQC_REP_TYPE_INDEXED = 0,

    /* Indexed Field Line With Post-Base Index */
    XQC_REP_TYPE_POST_BASE_INDEXED,

    /* Literal Field Line With Name Reference */
    XQC_REP_TYPE_NAME_REFERENCE,

    /* Literal Field Line With Post-Base Name Reference */
    XQC_REP_TYPE_POST_BASE_NAME_REFERENCE,

    /* Literal Field Line With Literal name */
    XQC_REP_TYPE_LITERAL,
} xqc_rep_type_t;


/* context of representation */
typedef struct xqc_rep_ctx_s {
    /* parsing state */
    xqc_rep_decode_state_t  state;
    /* stream_id of the request stream */
    uint64_t                stream_id;

    /* required insert count */
    xqc_prefixed_int_t      ric;
    /* sign bit of encoded field section prefix */
    uint8_t                 sign;
    /* base of encoded field section prefix */
    xqc_prefixed_int_t      base;

    /* current representation type */
    xqc_rep_type_t          type;
    /* never flag */
    uint8_t                 never;
    /* table flag */
    uint8_t                 table;
    /* name of Literal Field Line with Literal Name */
    xqc_prefixed_str_t     *name;
    /* index of Indexed Field Line, Index Field Line with Post Base, Literal Field Line with Indexed
       Name, Literal Field Line with Post-Base Indexed Name */
    xqc_prefixed_int_t      index;
    /* value of field line */
    xqc_prefixed_str_t     *value;
} xqc_rep_ctx_s;


/**
 * @brief create representation parsing context
 * @param stream_id stream ID of request stream
 */
xqc_rep_ctx_t *xqc_rep_ctx_create(uint64_t stream_id);

/**
 * @brief clear the whole request context
 */
void xqc_rep_ctx_clear(xqc_rep_ctx_t *ctx);

/**
 * @brief clear the context for parsing one representation
 */
void xqc_rep_ctx_clear_rep(xqc_rep_ctx_t *ctx);

/**
 * @brief destroy representation parsing context
 */
void xqc_rep_ctx_free(xqc_rep_ctx_t *ctx);

/**
 * @brief get required insert count of Encoded Filed Section
 */
uint64_t xqc_rep_get_ric(xqc_rep_ctx_t *ctx);

/**
 * @brief decode encoded field section prefix
 * @param ctx rep context
 * @param max_ents the max dynamic table entry count configured by decoder
 * @param icnt insert count of decoder's dynamic table
 * @param buf input buffer
 * @param buf_len input buffer len
 * @return ssize_t >= 0 for bytes consumed, < 0 for failure
 */
ssize_t xqc_rep_decode_prefix(xqc_rep_ctx_t *ctx, size_t max_ents, uint64_t icnt,
    unsigned char *buf, uint64_t buf_len);

/**
 * @brief decode a filed line
 * @param ctx rep context
 * @param pos start of buffer
 * @param end end of buffer
 * @return ssize_t >= 0 for bytes consumed, < 0 for failure
 */
ssize_t xqc_rep_decode_field_line(xqc_rep_ctx_t *ctx, unsigned char *pos, uint64_t buf_len);


/**
 * @brief write encoded field section prefix
 * @param buf dst buf
 * @param max_ents max entries in encoder's dynamic table
 * @param ricnt required insert count
 * @param base base
 * @return ssize_t
 */
xqc_int_t xqc_rep_write_prefix(xqc_var_buf_t *buf, uint64_t max_ents, uint64_t ricnt, uint64_t base);

/**
 * @brief Indexed Field Line
 * @param buf dst buf
 * @param t table flag, 0 for dynamic table, 1 for static table
 * @param idx absolute index
 * @return ssize_t 
 */
xqc_int_t xqc_rep_write_indexed(xqc_var_buf_t *buf, xqc_flag_t t, uint64_t idx);

/**
 * @brief Indexed Field Line With Post-Base Index
 * @param buf dst buf
 * @param idx absolute index
 * @return ssize_t 
 */
xqc_int_t xqc_rep_write_indexed_pb(xqc_var_buf_t *buf, uint64_t idx);

/**
 * @brief Literal Field Line With Name Reference
 * @param buf dst buf
 * @param n never index flag
 * @param t table flag, 0 for dynamic table, 1 for static table
 * @param idx name index
 * @param h value huffman flag, 1 for huffman encode, 0 for not
 * @param vlen value len
 * @param value value string
 * @return ssize_t 
 */
xqc_int_t xqc_rep_write_literal_with_name_ref(xqc_var_buf_t *buf, xqc_flag_t n, xqc_flag_t t,
    uint64_t nidx, uint64_t vlen, uint8_t *value);

/**
 * @brief Literal Field Line With Post-Base Name Reference
 * @param buf dst buf
 * @param base base index
 * @param n never index flag
 * @param idx name index
 * @param h value huffman flag, 1 for huffman encode, 0 for not
 * @param vlen value len
 * @param value value string
 * @return ssize_t 
 */
xqc_int_t xqc_rep_write_literal_with_pb_name_ref(xqc_var_buf_t *buf, xqc_flag_t n, uint64_t nidx,
    uint64_t vlen, uint8_t *value);

/**
 * @brief Literal Field Line With Literal name
 * @param buf dst buf
 * @param n never index flag
 * @param nh name huffman flag
 * @param nlen name len
 * @param name name string
 * @param vh value huffman flag
 * @param vlen value len
 * @param value value string
 * @return ssize_t 
 */
xqc_int_t xqc_rep_write_literal_name_value(xqc_var_buf_t *buf, xqc_flag_t n, uint64_t nlen,
    uint8_t *name, uint64_t vlen, uint8_t *value);


#endif
