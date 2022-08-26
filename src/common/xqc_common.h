/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_COMMON_H_INCLUDED_
#define _XQC_COMMON_H_INCLUDED_

#include <string.h>
#include <stdint.h>
#include <xquic/xqc_errno.h>
#include <xquic/xquic_typedef.h>


#ifndef XQC_LITTLE_ENDIAN
# define XQC_LITTLE_ENDIAN 1
#endif

#ifndef XQC_NONALIGNED
# define XQC_NONALIGNED 1
#endif

typedef unsigned char   u_char;


static inline uint64_t
xqc_pow2_upper(uint64_t n)
{
    size_t m = 1;
    for(; m < n; m = m << 1);
    return m;
}


#endif /*_XQC_COMMON_H_INCLUDED_*/
