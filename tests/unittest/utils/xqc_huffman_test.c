/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_huffman_test.h"
#include "src/common/utils/huffman/xqc_huffman.h"
#include "src/common/utils/huffman/xqc_huffman_code.h"
#include "src/http3/xqc_var_buf.h"
#include <inttypes.h>
#include <stdlib.h>
#include <time.h>

static uint8_t *
old_xqc_huffman_encode_sym(uint8_t *dest, size_t *prembits, const xqc_huffman_enc_code_t *sym)
{
    size_t nbits = sym->bits;
    size_t rembits = *prembits;
    uint32_t code = sym->lsb;

    /* We assume that sym->nbits <= 32 */
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
        /* align code to MSB byte boundary */
        code <<= 8 - (nbits & 0x7);
    }

    /* fast path, since most code is less than 8 */
    if (nbits < 8) {
        *dest = (uint8_t)code;
        *prembits = 8 - nbits;
        return dest;
    }

    /* handle longer code path */
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

size_t
old_xqc_http3_qpack_huffman_encode_count(const uint8_t *src, size_t len)
{
    size_t i;
    size_t nbits = 0;

    for (i = 0; i < len; ++i) {
        nbits += xqc_huffman_enc_code_table[src[i]].bits;
    }
    /* pad the prefix of EOS (256) */
    return (nbits + 7) / 8;
}

uint8_t *
old_xqc_http3_qpack_huffman_encode(uint8_t *dest, const uint8_t *src, size_t srclen)
{
    size_t rembits = 8;
    size_t i;
    const xqc_huffman_enc_code_t *sym;

    for (i = 0; i < srclen; ++i) {
        sym = &xqc_huffman_enc_code_table[src[i]];
        if (rembits == 8) {
            *dest = 0;
        }
        dest = old_xqc_huffman_encode_sym(dest, &rembits, sym);
    }
    /* 256 is special terminal symbol, pad with its prefix */
    if (rembits < 8) {
        /*
         * if rembits < 8, we should have at least 1 buffer space
         * available 
         */
        sym = &xqc_huffman_enc_code_table[256];
        *dest++ |= (uint8_t)(sym->lsb >> (sym->bits - rembits));
    }

    return dest;
}

void
old_xqc_http3_qpack_huffman_decode_context_init(xqc_huffman_dec_ctx *ctx)
{
    ctx->state = 0;
    ctx->end = 1;
}

ssize_t
old_xqc_http3_qpack_huffman_decode(xqc_huffman_dec_ctx *ctx, uint8_t *dest, size_t dstlen,
    const uint8_t *src, size_t srclen, int fin)
{
    uint8_t *p = dest;
    size_t i;
    size_t dst_sz = dstlen;
    const xqc_huffman_dec_code_t *t;

    /*
     * We use the decoding algorithm described in
     * http://graphics.ics.uci.edu/pub/Prefix.pdf
     */
    for (i = 0; i < srclen; ++i) {
        t = &xqc_huffman_dec_code_table[ctx->state][src[i] >> 4];
        if (t->flags & XQC_HUFFMAN_FAIL) {
            return -1;
        }
        if (t->flags & XQC_HUFFMAN_SYM) {
            if (dst_sz > 0) {
                *p++ = t->sym;
                dst_sz--;

            } else {
                return -XQC_ENOBUF;
            }
        }

        t = &xqc_huffman_dec_code_table[t->state][src[i] & 0xf];
        if (t->flags & XQC_HUFFMAN_FAIL) {
            return -1;
        }
        if (t->flags & XQC_HUFFMAN_SYM) {
            if (dst_sz > 0) {
                *p++ = t->sym;
                dst_sz--;

            } else {
                return -XQC_ENOBUF;
            }
        }

        ctx->state = t->state;
        ctx->end = (t->flags & XQC_HUFFMAN_END) != 0;
    }

    if (fin && !ctx->end) {
        return -1;
    }
    return p - dest;
}


void
xqc_test_huffman_basic()
{
    size_t i, j;
    size_t len;
    int fin;
    uint8_t raw[256], ebuf[4096], dbuf[4096];
    uint8_t *end;
    xqc_huffman_dec_ctx ctx = {0};
    ssize_t nwrite = 0, processed, consumed;

    srandom(time(NULL));

    /* loop for 10000 times */
    for (i = 0; i < 10000; ++i) {
        /* generate random buffer with random length */
        len = (random() & 255) + 1;
        for (j = 0; j < len; ++j) {
            raw[j] = (uint8_t)round(((double)random() / RAND_MAX * 255));
        }
        end = xqc_huffman_enc(ebuf, raw, len);

        xqc_huffman_dec_ctx_init(&ctx);
        nwrite = 0;
        for (j = 0; j < end - ebuf; ++j) {
            if (j == end - ebuf - 1) {
                fin = 1;
            } else {
                fin = 0;
            }
            consumed = xqc_huffman_dec(&ctx, dbuf + nwrite, 4096 - nwrite, ebuf + j, (size_t) 1, fin, &processed);
            CU_ASSERT(processed >= 0);
            CU_ASSERT(consumed == 1);
            nwrite += processed;
        }
        CU_ASSERT((len == (size_t) nwrite));
        CU_ASSERT(0 == memcmp(raw, dbuf, len));
    }
}


void
xqc_test_huffman_len()
{
    size_t i, j;
    size_t len;
    int fin;
    uint8_t *raw = malloc(20000);
    uint8_t *ebuf = malloc(40000);
    uint8_t *dbuf = malloc(40000);
    uint8_t *old_ebuf = malloc(40000);
    uint8_t *old_dbuf = malloc(40000);
    uint8_t *end, *old_end;
    xqc_huffman_dec_ctx ctx = {0}, old_ctx = {0};
    ssize_t nwrite = 0, processed, consumed, old_processed, old_consumed;

    srandom(time(NULL));

    /* loop for 10000 times */
    for (i = 0; i < 1000; ++i) {
        /* generate random buffer with random length */
        len = i + 1;
        for (j = 0; j < len; ++j) {
            raw[j] = (uint8_t)round(((double)random() / RAND_MAX * 255));
        }
        end = xqc_huffman_enc(ebuf, raw, len);
        old_end = old_xqc_http3_qpack_huffman_encode(old_ebuf, raw, len);
        CU_ASSERT(end - ebuf == old_end - old_ebuf);
        CU_ASSERT(0 == memcmp(ebuf, old_ebuf, end - ebuf));

        old_xqc_http3_qpack_huffman_decode_context_init(&old_ctx);
        xqc_huffman_dec_ctx_init(&ctx);
        nwrite = 0;
        for (j = 0; j < end - ebuf; ++j) {
            if (j == end - ebuf - 1) {
                fin = 1;

            } else {
                fin = 0;
            }
            consumed = xqc_huffman_dec(&ctx, dbuf + nwrite, 40000 - nwrite, ebuf + j, (size_t) 1, fin, &processed);
            old_processed = old_xqc_http3_qpack_huffman_decode(&old_ctx, old_dbuf + nwrite, 40000, old_ebuf + j, (size_t) 1, fin);
            CU_ASSERT(processed == old_processed);
            CU_ASSERT(processed >= 0);
            CU_ASSERT(consumed == 1);
            nwrite += processed;
        }
        CU_ASSERT(ctx.high_bits == 1);
        CU_ASSERT((len == (size_t) nwrite));
        CU_ASSERT(memcmp(raw, dbuf, len) == 0);
        CU_ASSERT(memcmp(raw, old_dbuf, len) == 0);
    }

    free(raw);
    free(ebuf);
    free(dbuf);
    free(old_ebuf);
    free(old_dbuf);
}


void
xqc_test_huffman()
{
    xqc_test_huffman_basic();
    xqc_test_huffman_len();
}