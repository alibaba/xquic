/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_variable_len_int.h"

#define XQC_VINT_MASK ((1 << 6) - 1)

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
    for (size_t len = 1; len < XQC_VI64_MAX_LEN; len++) {
        uint64_t max = (UINT64_C(1) << (7 * len)) - 1;
        if (value <= max) {
            return len;
        }
    }

    return XQC_VI64_MAX_LEN;
}

uint8_t *
xqc_vi64_write(uint8_t *p, uint64_t value)
{
    size_t len = xqc_vi64_len(value);
    if (len == XQC_VI64_MAX_LEN) {
        p[0] = 0xff;
        for (size_t i = XQC_VI64_MAX_LEN - 1; i > 0; i--) {
            p[i] = (uint8_t)(value & 0xff);
            value >>= 8;
        }
        return p + XQC_VI64_MAX_LEN;
    }

    for (size_t i = len; i > 0; i--) {
        p[i - 1] = (uint8_t)(value & 0xff);
        value >>= 8;
    }
    p[0] |= (uint8_t)(0xffu << (XQC_VI64_MAX_LEN - len));
    return p + len;
}

int
xqc_vi64_read(const uint8_t *p, const uint8_t *end, uint64_t *value)
{
    if (p == NULL || end == NULL || value == NULL || p >= end) {
        return -1;
    }

    uint8_t first = p[0];
    size_t leading_ones = 0;
    for (uint8_t marker = 0x80; marker != 0 && (first & marker); marker >>= 1) {
        leading_ones++;
    }

    size_t len = leading_ones + 1;
    if ((size_t)(end - p) < len) {
        return -1;
    }

    uint64_t decoded = 0;
    if (len < XQC_VI64_MAX_LEN) {
        decoded = first & (uint8_t)(0xffu >> len);
    }
    for (size_t i = 1; i < len; i++) {
        decoded = (decoded << 8) | p[i];
    }

    *value = decoded;
    return (int)len;
}
