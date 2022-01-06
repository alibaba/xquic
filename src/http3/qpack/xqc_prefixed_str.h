/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_PREFIXED_STRING_H
#define XQC_PREFIXED_STRING_H


#include "src/common/xqc_common_inc.h"
#include "src/http3/xqc_var_buf.h"
#include "xqc_prefixed_int.h"


/*
     0   1   2   3   4   5   6   7
   +---+---+---+---+---+---+---+---+
   | H |     Value Length (n+)     |
   +---+---------------------------+
   |  Value String (Length bytes)  |
   +-------------------------------+

*/

typedef enum xqc_prefixed_str_stage_s {
    XQC_PS_STAGE_H,
    XQC_PS_STAGE_LEN,
    XQC_PS_STAGE_VALUE,
    XQC_PS_STAGE_FINISH,
} xqc_prefixed_str_stage_t;


/* prefixed string */
typedef struct xqc_prefixed_str_s {
    /* huffman flag of prefixed string */
    xqc_flag_t          huff_flag;

    /* total length of string. which is the original length of prefixed string */
    xqc_prefixed_int_t  len;

    /* length of read bytes */
    uint64_t            used_len;

    /* result string. if huff_flag is 1, this is the huffman decode result of original string.
       if huff_flag is 0, this is equal to original string */
    xqc_var_buf_t      *value;

    /* parsing context */
    xqc_prefixed_str_stage_t    stg;
    xqc_huffman_dec_ctx         huff_ctx;
} xqc_prefixed_str_t;


/**
 * @brief create a prefixed string
 * @param capacity initial capacity
 */
xqc_prefixed_str_t *xqc_prefixed_str_pctx_create(size_t capacity);

/**
 * @brief initialize or free parsing context of prefixed string
 */
void xqc_prefixed_str_init(xqc_prefixed_str_t *pctx, uint8_t n);
void xqc_prefixed_str_free(xqc_prefixed_str_t *pctx);

/**
 * @brief parse prefixed string
 * @param buf input buffer of prefixed string, allow to be truncated
 * @param len input buffer len
 * @param n prefixed bits
 * @param pstr prefixed string
 * @return ssize_t bytes consumed
 */
ssize_t xqc_parse_prefixed_str(xqc_prefixed_str_t *pstr, uint8_t *buf, size_t len, int *fin_flag);

/**
 * @brief write prefixed string
 * @param buf destination buffer
 * @param str string to be written
 * @param len length of str
 * @param n prefixed bits
 * @return xqc_int_t 
 */
xqc_int_t xqc_write_prefixed_str(xqc_var_buf_t *buf, uint8_t *str, uint64_t len, uint8_t n);



#endif

