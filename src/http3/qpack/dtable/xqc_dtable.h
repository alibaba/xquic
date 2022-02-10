/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_DTABLE_H_
#define _XQC_DTABLE_H_


#include "src/http3/qpack/xqc_qpack_defs.h"


typedef struct xqc_dtable_s xqc_dtable_t;


/**
 * @brief create a dynamic table object
 * @param htable_buckets the bucket count of 2d hash table
 */
xqc_dtable_t *xqc_dtable_create(size_t htable_buckets, xqc_log_t *log);


/**
 * @brief destroy a dynamic table object
 */
void xqc_dtable_free(xqc_dtable_t *dt);


/**
 * @brief set capacity of dynamic table
 * @param dt dynamic table handler
 * @param capacity capacity of dynamic table
 * @return XQC_OK for success, others for failure
 */
xqc_int_t xqc_dtable_set_capacity(xqc_dtable_t *dt, uint64_t capacity);


/**
 * @brief insert name-value pair into dynamic table, while the value could be empty
 * @param dt dynamic table handler
 * @param name name string
 * @param nlen length of name
 * @param value value string
 * @param vlen length of value
 * @return XQC_OK for success, others for failure
 */
xqc_int_t xqc_dtable_add(xqc_dtable_t *dt, unsigned char *name, uint64_t nlen,
    unsigned char *value, uint64_t vlen, uint64_t *idx);


/**
 * @brief duplicate an entry from the dynamic table with ABSOLUTE INDEX
 * @param dt dynamic table handler
 * @param idx ABSOLUTE INDEX of the duplicated entry
 * @param new_idx output the duplicated index
 * @return XQC_OK for success, others for failure
 */
xqc_int_t xqc_dtable_duplicate(xqc_dtable_t *dt, uint64_t idx, uint64_t *new_idx);


/**
 * @brief get name-value pair from dynamic table with absolute index
 * @param dt dynamic table handler
 * @param idx absolute index
 * @param name_buf output name buffer
 * @param value_buf output value buffer
 * @return XQC_OK for success, others for failure
 */
xqc_int_t xqc_dtable_get_nv(xqc_dtable_t *dt, uint64_t idx,
    xqc_var_buf_t *name_buf, xqc_var_buf_t *value_buf);


/**
 * @brief lookup name-value pair from dtable
 * @param dt dynamic table handler
 * @param name information of name
 * @param nlen length of name
 * @param value information of value
 * @param vlen length of value
 * @param idx output absolute index of entry if found
 * @return xqc_nv_ref_type_t result of lookup 
 */
xqc_nv_ref_type_t xqc_dtable_lookup(xqc_dtable_t *dt, unsigned char *name, size_t nlen,
    unsigned char *value, size_t vlen, uint64_t *idx);


/**
 * @brief set the minimum referred entry in dynamic table, dynamic table use this value to ensure
 * the referred and unacked entries are safe when used by encoder
 * @param dt dynamic table handler
 * @param ref referred entry index
 * @return XQC_OK for success, others for failure 
 */
xqc_int_t xqc_dtable_set_min_ref(xqc_dtable_t *dt, uint64_t ref);


/**
 * @brief set the known received count of entries. when reached max blocked stream limit. lookup
 * will return those entries with index smaller than known received count. 
 * @param dt dynamic table handler
 * @param known_cnt known received count.
 * @return XQC_OK for success, others for failure 
 */
xqc_int_t xqc_dtable_set_known_rcvd_cnt(xqc_dtable_t *dt, uint64_t known_cnt);


/**
 * @brief get dynamic table insert count. insert count equals the current maximum index plus one
 * @param dt dynamic table handler
 * @return insert count
 */
uint64_t xqc_dtable_get_insert_cnt(xqc_dtable_t *dt);


/**
 * @brief check if entry is draining in dynamic table. if entry memory is in range of the eldest
 * bytes, it is considered to be draining
 * @param dt 
 * @param idx 
 * @param draining 
 * @return xqc_int_t 
 */
xqc_int_t xqc_dtable_is_entry_draining(xqc_dtable_t *dt, uint64_t idx, xqc_bool_t *draining);


/* calculate the size of an entry in dynamic table */
static inline size_t
xqc_dtable_entry_size(size_t name_len, size_t value_len)
{
    /* sizeof(name_len) + sizeof(value_len) + sizeof(name_buf_ptr) + sizeof(value_buf_ptr) +
       sizeof(name) + sizeof(value) */
    return XQC_QPACK_ENTRY_SIZE_BASE + name_len + value_len;
}


static inline uint64_t
xqc_dtable_max_entry_cnt(uint64_t capacity)
{
    return capacity / XQC_QPACK_ENTRY_SIZE_BASE;
}


#endif
