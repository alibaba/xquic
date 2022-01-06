/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_H_CONFIG_INCLUDED_
#define _XQC_H_CONFIG_INCLUDED_

#define xqc_min(a, b) ((a) < (b) ? (a) : (b))
#define xqc_max(a, b) ((a) > (b) ? (a) : (b))
#define xqc_sub_abs(a, b) ((a) > (b) ? ((a) - (b)): ((b) - (a)))
#define xqc_clamp(a, min, max) xqc_max(xqc_min(a, max), min)

#define LF     (unsigned char) '\n'
#define CR     (unsigned char) '\r'
#define CRLF   "\r\n"

#define XQC_PTR_SIZE 8

#define XQC_INT32_LEN   (sizeof("-2147483648") - 1)
#define XQC_INT64_LEN   (sizeof("-9223372036854775808") - 1)

#if (XQC_PTR_SIZE == 4)
# define XQC_INT_T_LEN XQC_INT32_LEN
# define XQC_MAX_INT_T_VALUE  2147483647

#else
# define XQC_INT_T_LEN XQC_INT64_LEN
# define XQC_MAX_INT_T_VALUE  9223372036854775807
#endif

#define XQC_MAX_UINT32_VALUE  (uint32_t) 0xffffffff
#define XQC_MAX_INT32_VALUE   (uint32_t) 0x7fffffff

#define XQC_MAX_UINT64_VALUE  (uint64_t) 0xffffffffffffffff
#define XQC_MAX_INT64_VALUE   (uint64_t) 0x7fffffffffffffff

#define XQC_MICROS_PER_SECOND 1000000   /* 1s=1000000us */

#endif /*_XQC_H_CONFIG_INCLUDED_*/
