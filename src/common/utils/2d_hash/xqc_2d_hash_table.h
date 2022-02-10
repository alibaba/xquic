/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_2D_HASH_TABLE_H
#define XQC_2D_HASH_TABLE_H

#include "src/common/xqc_common_inc.h"



/**
 * @brief 2d hash table is a variant of single hash table, and actually get 2 hash values to form up
 * comparison with 2 dimensions. 2d hash table is mainly used to retrieve name-value pair.
 */
typedef struct xqc_2d_hash_table_s xqc_2d_hash_table_t;


/* data comparison result, user shall return these values in comparison callback function */
typedef enum xqc_2d_cmp_res_s {
    /* both name and value are not matched */
    XQC_2D_CMP_RES_NONE = 0x00,

    /* only name is matched */
    XQC_2D_CMP_RES_1D,

    /* both name and value are matched */
    XQC_2D_CMP_RES_2D,

} xqc_2d_cmp_res_t;

/* comparison dimensions */
typedef enum xqc_2d_cmp_dim_s {
    /* only first dimension need to be checked */
    XQC_2D_CMP_DIM_1,

    /* both dimensions are to be checked */
    XQC_2D_CMP_DIM_2,
} xqc_2d_cmp_dim_t;


/* data comparison callback, used to check if data is same */
typedef int (*xqc_2d_hash_table_data_cmp)(void *data1, void *data2, void *ud);

/* value comparison callback, used to check if value matches data */
typedef xqc_2d_cmp_res_t (*xqc_2d_hash_table_value_cmp)(
    void *data, void *v1, size_t len1, void *v2, size_t len2, xqc_2d_cmp_dim_t dims, void *ud);


/**
 * @brief create a 2d hash table
 * @param bkt_cnt bucket count, shall be power of 2, if not, will make the bucket count power of 2
 * @param dcmp data comparison callback, for deleting a node from 2d hash table
 * @param vcmp value comparison callback, for lookup values from 2d hash table
 * @param ud user data
 * @return the handler of 2d hash table, return NULL for failure
 */
xqc_2d_hash_table_t *xqc_2d_hash_table_create(size_t bkt_cnt, xqc_2d_hash_table_data_cmp dcmp, 
    xqc_2d_hash_table_value_cmp vcmp, void *ud);


/**
 * @brief free 2d hash table
 * @param ht 2d hash table handler
 */
void xqc_2d_hash_table_free(xqc_2d_hash_table_t *ht);


/**
 * @brief insert a node into 2d hash table
 * @param ht 2d hash table handler
 * @param first the hash value of first dimension
 * @param second the hash value of second dimension
 * @param data data pointer
 * @return xqc_int_t XQC_OK for success, others for failure
 */
xqc_int_t xqc_2d_hash_table_add(xqc_2d_hash_table_t *ht, uint64_t first, uint64_t second,
    void *data);


/**
 * @brief remove a node from 2d hash table
 * @param ht 2d hash table handler
 * @param first the hash value of first dimension
 * @param second the hash value of second dimension
 * @param data data pointer
 * @return xqc_int_t XQC_OK for success, others for failure
 */
xqc_int_t xqc_2d_hash_table_remove(xqc_2d_hash_table_t *ht, uint64_t first, uint64_t second,
    void *data);


/**
 * @brief lookup a node from 2d hash table with input hash and value.
 * @param ht 2d hash table handler
 * @param h1 the hash value of first dimension
 * @param v1 the first value
 * @param h2 the hash value of second dimension
 * @param v2 the second value
 * @param data output data pointer
 * @return comparison result, XQC_2D_CMP_RES_2D for both dimensions are matched, XQC_2D_CMP_RES_1D
 * for only first dimension is matched, XQC_2D_CMP_RES_NONE for none matched
 */
xqc_2d_cmp_res_t xqc_2d_hash_lookup(xqc_2d_hash_table_t *ht, uint64_t h1, void *v1, size_t len1,
    uint64_t h2, void *v2, size_t len2, void **data);


#endif
