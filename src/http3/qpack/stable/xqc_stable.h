/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_STABLE_H_
#define _XQC_STABLE_H_


#include "src/http3/qpack/xqc_qpack_defs.h"
#include "src/http3/xqc_h3_header.h"



/**
 * @brief get name-value pair with static table entry index
 * @param idx entry index, ranges in [0, 98]
 * @param name_buf output name buffer
 * @param value_buf output value buffer, this parameter could be NULL if user don't need value
 * @return XQC_OK for success, others for failure
 */
xqc_int_t xqc_stable_get_nv(uint64_t idx, xqc_var_buf_t *name_buf, xqc_var_buf_t *value_buf);


/**
 * @brief lookup name-value from static table
 * @param name name buf
 * @param nlen name length
 * @param value value buf
 * @param vlen value length
 * @param htype header type. this param MUST BE exactly what header really is.
 * @param idx output index of static table entry, if XQC_NV_REF_NONE returned, shall be meaningless
 * @return xqc_nv_ref_type_t the reference mode of name-value pair
 */
xqc_nv_ref_type_t xqc_stable_lookup(unsigned char *name, size_t nlen,
    unsigned char *value, size_t vlen, xqc_hdr_type_t htype, uint64_t *idx);


#endif
