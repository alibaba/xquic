/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_RING_ARRAY_H_
#define _XQC_RING_ARRAY_H_

#include "src/common/xqc_common_inc.h"


typedef struct xqc_rarray_s xqc_rarray_t;

/**
 * @brief create a ring array with FIFO
 * @param cap the capacity of array
 * @param esize the size of each element
 * @return xqc_rarray_t* the pointer of ring array
 */
xqc_rarray_t *xqc_rarray_create(size_t cap, size_t esize);


/**
 * @brief destroy a ring array
 * @param ra pointer of ring array
 */
void xqc_rarray_destroy(xqc_rarray_t *ra);


/**
 * @brief get the element pointer at specified index
 * @param ra pointer of ring array
 * @param idx index of element, starts from 0
 * @return void* the memory block of input index. caller shall not remember this value
 */
void *xqc_rarray_get(xqc_rarray_t *ra, uint64_t idx);


/**
 * @brief get the count of elements
 */
size_t xqc_rarray_size(xqc_rarray_t *ra);


/**
 * @brief get front element
 */
void *xqc_rarray_front(xqc_rarray_t *ra);


/**
 * @brief push element to the end of array
 * @param ra pointer of ring array
 * @param element pointer of element, will be copy to ring array with esize
 * @return xqc_int_t XQC_OK for success, others for failure
 */
void *xqc_rarray_push(xqc_rarray_t *ra);


/**
 * @brief pop element from the front of array
 */
xqc_int_t xqc_rarray_pop_front(xqc_rarray_t *ra);

/**
 * @brief pop element from the end of array
 */
xqc_int_t xqc_rarray_pop_back(xqc_rarray_t *ra);


/**
 * @brief resize ring array
 */
xqc_int_t xqc_rarray_resize(xqc_rarray_t *ra, uint64_t cap);

#endif
