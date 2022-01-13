/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/http3/qpack/xqc_prefixed_int.h"

void
xqc_prefixed_int_init(xqc_prefixed_int_t *pint, size_t prefix)
{
    pint->value  = 0;
    pint->prefix = prefix;
    pint->shift  = 0;
}

ssize_t
xqc_prefixed_int_read(xqc_prefixed_int_t *pint, uint8_t *begin, uint8_t *end, int *fin)
{
    if (pint->prefix == 0) {
        pint->prefix = 8;
    }
    uint64_t k = (uint8_t) ((1 << pint->prefix) - 1);
    uint64_t n = pint->value;
    uint64_t add;
    uint8_t *p = begin;
    size_t shift = pint->shift;

    pint->shift = 0;
    *fin = 0;

    /* first decode */
    if (n == 0) {
        if (((*p) & k) != k) {
            pint->value = (*p) & k;
            *fin = 1;   /* mean varint read finish */
            return 1;   /* read only one byte */
        }

        n = k;
        if (++p == end) {
            pint->value = n;
            return (ssize_t) (p - begin);
        }
    }

    for (; p != end; ++p, shift += 7) {
        add = (*p) & 0x7f;
        /* shift means already read bits */
        if (shift > 62) {
            return -XQC_QPACK_DECODER_VARINT_ERROR;
        }

        if ((XQC_QPACK_INT_MAX >> shift) < add) {
            /* bigger than max varint is invalid */
            return -XQC_QPACK_DECODER_VARINT_ERROR;
        }

        add <<= shift;
        if (XQC_QPACK_INT_MAX - add < n) {
            /* too big */
            return -XQC_QPACK_DECODER_VARINT_ERROR;
        }

        n += add;
        if (((*p) & (1 << 7)) == 0) {
            /* read varint end */
            p++;
            *fin = 1;
            break;
        }
    }

    pint->shift = shift;
    pint->value = n;
    return (ssize_t) (p - begin);
}

size_t
xqc_prefixed_int_put_len(uint64_t n, size_t prefix)
{
    size_t len = 0;

    size_t k = (size_t) ((1 << prefix) - 1);
    if (n < k) {
        return 1;
    }

    n -= k;
    ++len;

    for (; n >= 128; n >>= 7, ++len) {
        /* void */
    }

    return len + 1;
}

uint8_t *
xqc_prefixed_int_put(uint8_t *buf, uint64_t n, size_t prefix)
{
    size_t k = (size_t) ((1 << prefix) - 1);
    *buf = (uint8_t) (*buf & ~k);

    if (n < k) {
        *buf = (uint8_t) (*buf | n);
        return buf + 1;
    }

    *buf = (uint8_t) (*buf | k);
    ++buf;

    n -= k;
    for (; n >= 128; n >>= 7) {
        *buf++ = (uint8_t) ((1 << 7) | (n & 0x7f));
    }

    *buf++ = (uint8_t) n;
    return buf;
}


