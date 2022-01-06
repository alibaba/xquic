/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_QPACK_DEFS_H_
#define _XQC_QPACK_DEFS_H_

#include <xquic/xqc_http3.h>
#include "src/http3/xqc_var_buf.h"
#include "src/http3/xqc_h3_defs.h"

#define XQC_QPACK_MAX_TABLE_CAPACITY            (16 * 1024)

#define XQC_QPACK_MAX_BLOCK_STREAM              (64)

#define XQC_QPACK_DEFAULT_HASH_TABLE_SIZE       (128)

#define XQC_QPACK_INT_MAX                       ((1ull << 62) - 1)

#define XQC_QPACK_HEADERS_PAYLOAD_SLICE_SIZE    (1024)

#define XQC_MAX_INDEX                           (1ull << 62)

#define XQC_INVALID_INDEX                       0xFFFFFFFFFFFFFFFF


#define XQC_HTTP3_QPACK_MAX_VALUELEN            (32*1024)
#define XQC_HTTP3_QPACK_MAX_NAMELEN             256
#define XQC_HTTP3_QPACK_MAX_NAME_BUFLEN         (XQC_HTTP3_QPACK_MAX_NAMELEN + 1)
#define XQC_HTTP3_QPACK_MAX_VALUE_BUFLEN        (XQC_HTTP3_QPACK_MAX_VALUELEN + 1)



/* t flag in field line representations */
#define XQC_DTABLE_FLAG     0
#define XQC_STABLE_FLAG     1


/*
 * the minimum memory cost of an entry when name and value are empty, only name len, name buf ptr,
 * value len, value buf ptr are to be stored, for each the cost is 8 bytes at most, make it 32 total
 */
#define XQC_QPACK_ENTRY_SIZE_BASE   (32)



/*
 * name-value pair
 */
typedef struct xqc_nv_t {
    xqc_str_t   name;
    xqc_str_t   value;
} xqc_nv_t;



/* lookup reference result */
typedef enum xqc_nv_ref_type_s {
    XQC_NV_REF_NONE = 0,        /* none is matched */
    XQC_NV_REF_NAME,            /* only name is matched */
    XQC_NV_REF_NAME_AND_VALUE,  /* both name and value are matched */
} xqc_nv_ref_type_t;


/* post-base relative index to absolute index */
static inline uint64_t
xqc_pbrel2abs(uint64_t base, uint64_t rel_idx)
{
    return rel_idx + base;
}

/* base relative index to absolute index */
static inline uint64_t
xqc_brel2abs(uint64_t base, uint64_t rel_idx)
{
    return base - rel_idx - 1;
}

/* absolute index to post-base relative index */
static inline uint64_t
xqc_abs2pbrel(uint64_t base, uint64_t abs_idx)
{
    return abs_idx - base;
}

/* absolute index to base relative index */
static inline uint64_t
xqc_abs2brel(uint64_t base, uint64_t abs_idx)
{
    return base - abs_idx - 1;
}

#endif
