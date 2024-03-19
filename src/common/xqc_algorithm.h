/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_ALGORITHM_H_INCLUDED
#define XQC_ALGORITHM_H_INCLUDED

#include <stdint.h>
#include <stdio.h>


static inline int
xqc_uint32_list_find(const uint32_t *list, size_t count, uint32_t target)
{
    for (size_t i = 0; i < count; ++i) {
        if (list[i] == target) {
            return i; 
        }
    }
    return -1;
}

static inline uint64_t
xqc_uint64_bounded_subtract(uint64_t a, uint64_t b)
{
    return a > b ? a - b : 0;
}

static inline uint32_t
xqc_uint32_bounded_subtract(uint32_t a, uint32_t b)
{
    return a > b ? a - b : 0;
}

#endif /* XQC_ALGORITHM_H_INCLUDED */
