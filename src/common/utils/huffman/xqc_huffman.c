/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_huffman.h"
#include "xqc_huffman_code.h"
#include <string.h>
#include <assert.h>
#include <stdio.h>



size_t
xqc_huffman_enc_len(const uint8_t *src, size_t len)
{
    size_t bits_cnt = 0;
    for (size_t i = 0; i < len; ++i) {
        bits_cnt += xqc_huffman_enc_code_table[src[i]].bits;
    }

    /* pad the prefix of EOS (256) */
    return (bits_cnt + 7) / 8;
}


/**
 * encode one symbol
 * @param dest destination buffer
 * @param prembits count of the least bits which is not used
 * of the first byte from dest
 * @param ec the huffman encode code
 * @return the pointer of unused buffer
 */
static inline uint8_t *
xqc_huffman_encode_sym(uint8_t *dest, 
    size_t *prembits, const xqc_huffman_enc_code_t *ec)
{
    size_t nbits = ec->bits;
    size_t rembits = *prembits;
    uint32_t code = ec->lsb;

    if (rembits > nbits) {
        *dest |= (uint8_t)(code << (rembits - nbits));
        *prembits = rembits - nbits;
        return dest;
    }

    if (rembits == nbits) {
        *dest++ |= (uint8_t)code;
        *prembits = 8;
        return dest;
    }

    *dest++ |= (uint8_t)(code >> (nbits - rembits));

    nbits -= rembits;
    if (nbits & 0x7) {
        code <<= 8 - (nbits & 0x7);
    }

    if (nbits < 8) {
        *dest = (uint8_t)code;
        *prembits = 8 - nbits;
        return dest;
    }

    if (nbits > 24) {
        *dest++ = (uint8_t)(code >> 24);
        nbits -= 8;
    }

    if (nbits > 16) {
        *dest++ = (uint8_t)(code >> 16);
        nbits -= 8;
    }

    if (nbits > 8) {
        *dest++ = (uint8_t)(code >> 8);
        nbits -= 8;
    }

    if (nbits == 8) {
        *dest++ = (uint8_t)code;
        *prembits = 8;
        return dest;
    }

    *dest = (uint8_t)code;
    *prembits = 8 - nbits;
    return dest;
}


uint8_t *
xqc_huffman_enc(uint8_t *dest, const uint8_t *src, size_t srclen)
{
    size_t rembits = 8;
    const xqc_huffman_enc_code_t *sym;

    for (size_t i = 0; i < srclen; ++i) {
        sym = &xqc_huffman_enc_code_table[src[i]];
        if (rembits == 8) {
            *dest = 0;
        }
        dest = xqc_huffman_encode_sym(dest, &rembits, sym);
    }
    /* 256 is special terminal symbol, pad with its prefix */
    if (rembits < 8) {
        sym = &xqc_huffman_enc_code_table[256];
        *dest++ |= (uint8_t)(sym->lsb >> (sym->bits - rembits));
    }

    return dest;
}


void
xqc_huffman_dec_ctx_init(xqc_huffman_dec_ctx *ctx)
{
    ctx->state = 0;
    ctx->pre_state = 0;
    ctx->end = 1;
    ctx->high_bits = XQC_TRUE;
    ctx->bit = 0;
}


/* decode 4 bits */
static inline ssize_t
xqc_huffman_dec_bits(xqc_huffman_dec_ctx *ctx, uint8_t bits, uint8_t *dst)
{
    ssize_t ret = 0;
    const xqc_huffman_dec_code_t *code = &xqc_huffman_dec_code_table[ctx->state][bits];
    if (code->flags & XQC_HUFFMAN_FAIL) {
        return -XQC_QPACK_HUFFMAN_DEC_ERROR;
    }

    if (code->flags & XQC_HUFFMAN_SYM) {
        *dst = code->sym;
        ret = 1;
    }

    ctx->bit = bits;
    ctx->pre_state = ctx->state;
    ctx->state = code->state;
    ctx->end = (code->flags & XQC_HUFFMAN_END) ? XQC_TRUE : XQC_FALSE;
    return ret;
}


ssize_t
xqc_huffman_dec(xqc_huffman_dec_ctx *ctx,
    uint8_t *dest, size_t dstlen, const uint8_t *src, size_t srclen, int fin, size_t *write)
{
    ssize_t ret = 0;
    const uint8_t *pos = src;
    const uint8_t *end = src + srclen;
    uint8_t *pchar = dest;
    const uint8_t *dst_end = dest + dstlen;

    while (pos < end) {
        /* process high bits first */
        if (ctx->high_bits == XQC_TRUE) {
            ret = xqc_huffman_dec_bits(ctx, *pos >> 4, pchar);
            if (ret < 0) {
                return ret;
            }
            pchar += ret;
            ctx->high_bits = XQC_FALSE;

            /* dest full */
            if (pchar == dst_end) {
                return pchar - dest;
            }
        }

        /* process low bits */
        ret = xqc_huffman_dec_bits(ctx, *pos & 0x0f, pchar);
        if (ret < 0) {
            return ret;
        }
        pchar += ret;
        ctx->high_bits = XQC_TRUE;

        pos++;

        /* dest full */
        if (pchar == dst_end) {
            return pchar - dest;
        }
    }

    /* the end flag shall be set if all input buff is decoded */
    if (fin && !ctx->end) {
        return -XQC_QPACK_HUFFMAN_DEC_STATE_ERROR;
    }

    *write = pchar - dest;
    return pos - src;
}
