/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_RING_MEM_H
#define XQC_RING_MEM_H

#include "src/common/xqc_common_inc.h"


/*
 * circular memory, maintains a linear memory block, and can be used to store objects with
 * Irregular sizes as a queue, xqc_ring_mem_t will maintain the memory as FIFO order
 */
typedef struct xqc_ring_mem_s xqc_ring_mem_t;

/* inserted memory block index, user shall remember this value after an insertion */
typedef uint64_t xqc_ring_mem_idx_t;
#define XQC_RING_MEM_INVALID_IDX    0xffffffffffffffff



/**
 * @brief create a ring memory
 * @param sz size of ring memory, if sz is not a power of 2, will make it a power of 2
 * @return not NULL if success
 */
xqc_ring_mem_t *xqc_ring_mem_create(size_t sz);


/**
 * @brief destroy a ring memory
 * @param rmem ring memory pointer that will be destroyed
 */
void xqc_ring_mem_free(xqc_ring_mem_t *rmem);


/**
 * @brief resize a ring memory
 * @param rmem ring memory
 * @param cap new capacity
 * @return XQC_OK for success, others for failure
 */
xqc_int_t xqc_ring_mem_resize(xqc_ring_mem_t *rmem, size_t cap);


/**
 * @brief get the used size of ring memory
 * @param rmem ring memory object
 * @return used size
 */
size_t xqc_ring_mem_used_size(xqc_ring_mem_t *rmem);


/**
 * @brief copy data from a memory block with specified index to buf
 * @param rmem ring memory
 * @param idx index of memory block
 * @param len len of memory block
 * @param buf destination
 * @param sz size of buf
 * @return xqc_int_t 
 */
xqc_int_t xqc_ring_mem_copy(xqc_ring_mem_t *rmem, xqc_ring_mem_idx_t idx,
    size_t len, uint8_t *buf, size_t sz);


/**
 * @brief enqueue a buffer
 * @param rmem ring memory
 * @param data input data
 * @param len length of data
 * @param idx output buffer index
 * @return XQC_OK for success, others for failure
 */
xqc_int_t xqc_ring_mem_enqueue(xqc_ring_mem_t *rmem, uint8_t *data, size_t len,
    xqc_ring_mem_idx_t *idx);


/**
 * @brief dequeue a buffer with index
 * @param rmem ring memory
 * @param idx index of buffer that will be dequeue from ring memory
 * @param len length of buffer
 * @return xqc_int_t 
 */
xqc_int_t xqc_ring_mem_dequeue(xqc_ring_mem_t *rmem, xqc_ring_mem_idx_t idx, size_t len);


/**
 * @brief sometimes we might regret it after enqueue or dequeue a memory block
 * @return XQC_OK for success, others for failure 
 */
xqc_int_t xqc_ring_mem_undo(xqc_ring_mem_t *rmem, xqc_ring_mem_idx_t idx, size_t len);


/**
 * @brief compare a memory block with input data
 * @return same semantic result with memcmp
 */
int xqc_ring_mem_cmp(xqc_ring_mem_t *rmem, xqc_ring_mem_idx_t idx, uint8_t *data, size_t len);


/**
 * @brief duplicate a memory block to the end of ring memory
 * @param rmem ring memory
 * @param ori_idx index of source memory block
 * @param len length of memory block
 * @param new_idx [out] the index of duplicated memory block
 * @return xqc_int_t 
 */
xqc_int_t xqc_ring_mem_duplicate(xqc_ring_mem_t *rmem, xqc_ring_mem_idx_t ori_idx, size_t len,
    xqc_ring_mem_idx_t *new_idx);

#endif
