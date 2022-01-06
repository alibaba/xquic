/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_PREFIXED_H_
#define _XQC_PREFIXED_H_

#include "src/http3/qpack/xqc_qpack_defs.h"

/* prefixed N-bits integer */
typedef struct xqc_prefixed_int_s {
    size_t      prefix;     /* prefixed N bits */
    size_t      shift;
    uint64_t    value;      /* value */
} xqc_prefixed_int_t;

/**
 * @brief initialize or reset parsing context of prefixed integer
 */
void xqc_prefixed_int_init(xqc_prefixed_int_t *pint, size_t prefix);

/**
 * @brief parse prefixed integer, if fin is 1 after calling, the prefixed integer is available, 
 * caller can get the value 
 */
ssize_t xqc_prefixed_int_read(xqc_prefixed_int_t *pint, uint8_t *begin, uint8_t *end, int *fin);

/**
 * @brief calculate the length of value n with prefix
 */
size_t xqc_prefixed_int_put_len(uint64_t n, size_t prefix);

/**
 * @brief write prefixed integer to buffer
 */
uint8_t * xqc_prefixed_int_put(uint8_t *buf, uint64_t n, size_t prefix);

#endif
