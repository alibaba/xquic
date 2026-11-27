/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_variable_len_int.h"

#define XQC_CHAR_BIT 8
#define XQC_VINT_MASK ((1 << 6) - 1)
#define XQC_VI64_PREFIX_BIT (1u << (XQC_CHAR_BIT - 1))

int
xqc_vint_read(const unsigned char *p, const unsigned char *end, uint64_t *valp)
{
    uint64_t val;

    if (p >= end) {
        return -1;
    }

    switch (*p >> 6u) {
    case 0:
        *valp = *p;
        return 1;

    case 1:
        if (p + 1 >= end) {
            return -1;
        }
        *valp = (p[0] & XQC_VINT_MASK) << 8
                | p[1];
        return 2;

    case 2:
        if (p + 3 >= end) {
            return -1;
        }
        *valp = (p[0] & XQC_VINT_MASK) << 24
                | p[1] << 16
                | p[2] << 8
                | p[3] << 0;
        return 4;

    default:
        if (p + 7 >= end) {
            return -1;
        }
        memcpy(&val, p, 8);
#if __BYTE_ORDER == __LITTLE_ENDIAN
        val = bswap_64(val);
#endif
        val &= (1ULL << 62) - 1;
        *valp = val;
        return 8;
    }
}

size_t
xqc_put_varint_len(uint64_t n)
{
    if (n < 64) {
        return 1;
    }

    if (n < 16384) {
        return 2;
    }

    if (n < 1073741824) {
        return 4;
    }

    return 8;
}

uint8_t *
xqc_put_varint(uint8_t *p, uint64_t n)
{
    uint8_t *rv;
    if (n < 64) {
        *p++ = (uint8_t)n;
        return p;
    }

    if (n < 16384) {
        rv = xqc_put_uint16be(p, (uint16_t)n);
        *p |= 0x40;
        return rv;
    }

    if (n < 1073741824) {
        rv = xqc_put_uint32be(p, (uint32_t)n);
        *p |= 0x80;
        return rv;
    }

    if (n >= 4611686018427387904ULL) {
        return NULL;
    }

    rv = xqc_put_uint64be(p, n);
    *p |= 0xc0;
    return rv;
}

size_t
xqc_vi64_len(uint64_t value)
{
    size_t len = 1;

    while (value >= XQC_VI64_PREFIX_BIT && len < XQC_VI64_MAX_LEN) {
        value >>= XQC_CHAR_BIT - 1;
        len++;
    }

    return len;
}

xqc_int_t
xqc_vi64_write(uint8_t *p, const uint8_t *end, uint64_t value)
{
    size_t len = xqc_vi64_len(value);

    if (p > end || (size_t)(end - p) < len) {
        return -1;
    }

    for (size_t i = len - 1; i > 0; i--) {
        p[i] = (uint8_t)value;
        value >>= XQC_CHAR_BIT;
    }

    p[0] = (uint8_t)(UINT8_MAX << (XQC_VI64_MAX_LEN - len))
           | (uint8_t)value;
    return (xqc_int_t)len;
}

xqc_int_t
xqc_vi64_read(const uint8_t *p, const uint8_t *end, uint64_t *value)
{
    if (p >= end) {
        return -1;
    }

    uint64_t result = *p;
    uint8_t mask = XQC_VI64_PREFIX_BIT;
    size_t len = 1;

    while (result & mask) {
        result &= ~(uint64_t)mask;
        mask >>= 1;
        len++;
    }

    if ((size_t)(end - p) < len) {
        return -1;
    }

    for (size_t i = 1; i < len; i++) {
        result = (result << XQC_CHAR_BIT) | p[i];
    }

    *value = result;
    return (xqc_int_t)len;
}
