/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_STR_H_INCLUDED_
#define _XQC_STR_H_INCLUDED_

#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <stddef.h>
#include <sys/types.h>

#include <include/xquic/xquic_typedef.h>
#include "src/common/xqc_config.h"

#ifndef  XQC_SYS_WINDOWS
#include <sys/resource.h>
#endif

typedef struct xqc_str_s {
    size_t          len;
    unsigned char  *data;
} xqc_str_t;

#define xqc_string(str)         { sizeof(str) - 1, (unsigned char *) str }
#define xqc_null_string         { 0, NULL }
#define xqc_str_set(str, text)  (str)->len = sizeof(text) - 1; (str)->data = (unsigned char *) text
#define xqc_str_null(str)       (str)->len = 0; (str)->data = NULL

#define xqc_str_equal(s1, s2)   ((s1).len == (s2).len && memcmp((s1).data, (s2).data, (s1).len) == 0)

#define xqc_tolower(c)          (unsigned char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define xqc_toupper(c)          (unsigned char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)


#define xqc_memzero(buf, n)     (void) memset(buf, 0, n)
#define xqc_memset(buf, c, n)   (void) memset(buf, c, n)

#define xqc_memcpy(dst, src, n) (void) memcpy(dst, src, n)
#define xqc_cpymem(dst, src, n) (((unsigned char *) memcpy(dst, src, n)) + (n))

#define xqc_memcmp(s1, s2, n)   memcmp((const char *) s1, (const char *) s2, n)

#define xqc_lengthof(x)         (sizeof(x) - 1)


unsigned char *xqc_hex_dump(unsigned char *dst, const unsigned char *src, size_t len);
unsigned char *xqc_vsprintf(unsigned char *buf, unsigned char *last, const char *fmt, va_list args);
unsigned char *xqc_sprintf_num(unsigned char *buf, unsigned char *last,
    uint64_t ui64, unsigned char zero, uintptr_t hexadecimal, uintptr_t width);

static inline int
xqc_memcpy_with_cap(void *dst, size_t cap, const void *src, size_t n)
{
    if (n == 0) {
        return XQC_OK;
    }

    if (n <= cap) {
        xqc_memcpy(dst, src, n);
        return XQC_OK;
    }

    return -XQC_ENOBUF;
}

static inline void
xqc_str_tolower(unsigned char *dst, unsigned char *src, size_t n)
{
    while (n) {
        *dst = xqc_tolower(*src);
        dst++;
        src++;
        n--;
    }
}

static inline unsigned char * 
xqc_sprintf(unsigned char *buf, unsigned char *last, const char *fmt, ...)
{
    unsigned char *p;
    va_list args;
    va_start(args, fmt);
    p = xqc_vsprintf(buf, last, fmt, args);
    va_end(args);
    return p;
}


inline static xqc_bool_t
xqc_memeq(const void *s1, const void *s2, size_t n)
{
    return n == 0 || memcmp(s1, s2, n) == 0;
}

inline static xqc_bool_t
xqc_char_is_letter_or_number(char c)
{
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') 
        || (c >= '0' && c <= '9'))
    {
        return XQC_TRUE;
    }
    return XQC_FALSE;
}

static inline void
xqc_int_2_str(char *output, uint32_t val, xqc_int_t val_len)
{
    xqc_int_t i, tail;
    i = val_len - 1;
    while (val > 0 && i >= 0) {
        tail = val % 10;
        output[i] = '0' + tail;
        i--;
        val /= 10;
    }
    for (i; i >= 0; i--) {
        output[i] = '0';
    }
}

static inline uint32_t
xqc_str_2_int(char *str, xqc_int_t str_len)
{
    xqc_int_t i, tmp, result;
    result = 0;

    for (i = 0; i < str_len; i++) {
        result *= 10;
        tmp = str[i] - '0';
        result += tmp;
    }

    return result;
}

#ifndef XQC_ONLY_CLIENT_LIB
inline static size_t
xqc_uint64_decimal_len(uint64_t value)
{
    size_t len = 1;
    while (value >= 10) {
        value /= 10;
        len++;
    }
    return len;
}
#endif

static inline unsigned char *
xqc_fmt_uint(unsigned char *buf, unsigned char *last, uint64_t n)
{
    static const char lut[200] = {
        '0','0','0','1','0','2','0','3','0','4','0','5','0','6','0','7','0','8','0','9',
        '1','0','1','1','1','2','1','3','1','4','1','5','1','6','1','7','1','8','1','9',
        '2','0','2','1','2','2','2','3','2','4','2','5','2','6','2','7','2','8','2','9',
        '3','0','3','1','3','2','3','3','3','4','3','5','3','6','3','7','3','8','3','9',
        '4','0','4','1','4','2','4','3','4','4','4','5','4','6','4','7','4','8','4','9',
        '5','0','5','1','5','2','5','3','5','4','5','5','5','6','5','7','5','8','5','9',
        '6','0','6','1','6','2','6','3','6','4','6','5','6','6','6','7','6','8','6','9',
        '7','0','7','1','7','2','7','3','7','4','7','5','7','6','7','7','7','8','7','9',
        '8','0','8','1','8','2','8','3','8','4','8','5','8','6','8','7','8','8','8','9',
        '9','0','9','1','9','2','9','3','9','4','9','5','9','6','9','7','9','8','9','9',
    };
    unsigned char temp[20];
    unsigned char *t = temp + 20;
    size_t len;

    if (n == 0) {
        if (buf < last) *buf++ = '0';
        return buf;
    }

    if (n <= (uint64_t)0xFFFFFFFFu) {
        uint32_t n32 = (uint32_t)n;
        while (n32 >= 100) {
            unsigned idx = (n32 % 100) * 2;
            n32 /= 100;
            *--t = (unsigned char)lut[idx + 1];
            *--t = (unsigned char)lut[idx];
        }
        if (n32 >= 10) {
            unsigned idx = n32 * 2;
            *--t = (unsigned char)lut[idx + 1];
            *--t = (unsigned char)lut[idx];
        } else {
            *--t = (unsigned char)('0' + n32);
        }
    } else {
        while (n >= 100) {
            unsigned idx = (unsigned)(n % 100) * 2;
            n /= 100;
            *--t = (unsigned char)lut[idx + 1];
            *--t = (unsigned char)lut[idx];
        }
        if (n >= 10) {
            unsigned idx = (unsigned)n * 2;
            *--t = (unsigned char)lut[idx + 1];
            *--t = (unsigned char)lut[idx];
        } else {
            *--t = (unsigned char)('0' + n);
        }
    }

    len = (size_t)((temp + 20) - t);
    if ((size_t)(last - buf) < len) len = (size_t)(last - buf);
    memcpy(buf, t, len);
    return buf + len;
}

#endif /*_XQC_STR_H_INCLUDED_*/
