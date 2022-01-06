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

#endif /* XQC_ALGORITHM_H_INCLUDED */
