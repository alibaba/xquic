/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_VARIABLE_LEN_INT_H_INCLUDED_
#define _XQC_VARIABLE_LEN_INT_H_INCLUDED_

#include <stdint.h>
#include "src/common/xqc_str.h"
#include <netinet/in.h>

#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__NetBSD__)
#include <sys/endian.h>
#define bswap_16 bswap16
#define bswap_32 bswap32
#define bswap_64 bswap64
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define bswap_16 OSSwapInt16
#define bswap_32 OSSwapInt32
#define bswap_64 OSSwapInt64
#elif defined(WIN32)
#include <stdlib.h>
#define bswap_16 _byteswap_ushort
#define bswap_32 _byteswap_ulong
#define bswap_64 _byteswap_uint64
#else
#include <byteswap.h>
#endif

#define XQC_VINT_MASK ((1 << 6) - 1)

/*
          +------+--------+-------------+-----------------------+
          | 2Bit | Length | Usable Bits | Range                 |
          +------+--------+-------------+-----------------------+
          | 00   | 1      | 6           | 0-63                  |
          |      |        |             |                       |
          | 01   | 2      | 14          | 0-16383               |
          |      |        |             |                       |
          | 10   | 4      | 30          | 0-1073741823          |
          |      |        |             |                       |
          | 11   | 8      | 62          | 0-4611686018427387903 |
          +------+--------+-------------+-----------------------+
 */

/* return 2Bit 00, 01, 10 or 11 (0, 1, 2, or 3) */
#define xqc_vint_get_2bit(val) (    \
    ((val) >= (1 << 6) ? 1 : 0) + ((val) >= (1 << 14) ? 1 : 0) + ((val) >= (1 << 30) ? 1 : 0))

/* return Usable Bits according to 2Bit.
 * parameter two_bit can be 0, 1, 2, 3
 */
#define xqc_vint_usable_bits(two_bit) ((1 << (3 + (two_bit))) - 2)

/* get Length by 2Bit */
#define xqc_vint_len(two_bit) (1 << (two_bit))

#define xqc_vint_len_by_val(val) (1 << (xqc_vint_get_2bit(val)))

/* write val to dst buf with len bytes  */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define xqc_vint_write(dst, val, two_bit, len) do {                              \
    uint64_t buf_ = (val) | (uint64_t) (two_bit) << xqc_vint_usable_bits(two_bit);\
    buf_ = bswap_64(buf_);                                                  \
    memcpy(dst, (unsigned char *) &buf_ + 8 - (len), (len));                \
} while (0)
#else
#define xqc_vint_write(dst, val, two_bit, len) do {                                \
    uint64_t buf_ = (val) | (uint64_t) (two_bit) << xqc_vint_usable_bits(two_bit);\
    memcpy(dst, (unsigned char *) &buf_ + 8 - (len), (len));                \
} while (0)
#endif

static inline uint8_t *
xqc_put_uint64be(uint8_t *p, uint64_t n)
{
    n = bswap_64(n);
    return xqc_cpymem(p, (const uint8_t *)&n, sizeof(n));
}

static inline uint8_t *
xqc_put_uint48be(uint8_t *p, uint64_t n)
{
    n = bswap_64(n);
    return xqc_cpymem(p, ((const uint8_t *)&n) + 2, 6);
}

static inline uint8_t *
xqc_put_uint32be(uint8_t *p, uint32_t n)
{
    n = htonl(n);
    return xqc_cpymem(p, (const uint8_t *)&n, sizeof(n));
}

static inline uint8_t *
xqc_put_uint24be(uint8_t *p, uint32_t n)
{
    n = htonl(n);
    return xqc_cpymem(p, ((const uint8_t *)&n) + 1, 3);
}

static inline uint8_t *
xqc_put_uint16be(uint8_t *p, uint16_t n)
{
    n = htons(n);
    return xqc_cpymem(p, (const uint8_t *)&n, sizeof(n));
}

/**
* @return number of bytes read from p (1, 2, 4, or 8)
* @param p pointer of variable length integer
* @param valp output the value of variable length integer
*/
int xqc_vint_read(const unsigned char *p, const unsigned char *end, uint64_t *valp);

static inline size_t xqc_get_varint_len(const uint8_t *p) { return 1u << (*p >> 6); }
static inline int64_t xqc_get_varint_fb(const uint8_t *p) { return *p & 0x3f; }

size_t xqc_put_varint_len(uint64_t n);
uint8_t *xqc_put_varint(uint8_t *p, uint64_t n);

#endif /* _XQC_VARIABLE_LEN_INT_H_INCLUDED_ */
