/**
 * @copyright Copyright (c) 2025, Alibaba Group Holding Limited
 */

#ifndef _XQC_SIPHASH_H_INCLUDED_
#define _XQC_SIPHASH_H_INCLUDED_

#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include "src/common/xqc_common.h"

#define XQC_SIPHASH_KEY_SIZE        16
#define XQC_SIPHASH_C_ROUNDS        2
#define XQC_SIPHASH_D_ROUNDS        4
#define XQC_DEFAULT_HASH_SIZE       8

/* save siphash context */
typedef struct xqc_siphash_ctx {
    /* v0 v1 v2 v3  */
    uint64_t v0;
    uint64_t v1;
    uint64_t v2;
    uint64_t v3;
    int hash_size; /* save sizeof(hash), only 8 or 16 */
    /*  SipHash-2-4  */
    int crounds; 
    int drounds;
} xqc_siphash_ctx_t;

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define U32TO8_LE(p, v)                                                        \
    (p)[0] = (uint8_t)((v));                                                   \
    (p)[1] = (uint8_t)((v) >> 8);                                              \
    (p)[2] = (uint8_t)((v) >> 16);                                             \
    (p)[3] = (uint8_t)((v) >> 24);

#define U64TO8_LE(p, v)                                                        \
    U32TO8_LE((p), (uint32_t)((v)));                                           \
    U32TO8_LE((p) + 4, (uint32_t)((v) >> 32));

#define U8TO64_LE(p)                                                           \
    (((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8) |                        \
     ((uint64_t)((p)[2]) << 16) | ((uint64_t)((p)[3]) << 24) |                 \
     ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) |                 \
     ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56))

#define SIPROUND                                                               \
    do {                                                                       \
        v0 += v1;                                                              \
        v1 = ROTL(v1, 13);                                                     \
        v1 ^= v0;                                                              \
        v0 = ROTL(v0, 32);                                                     \
        v2 += v3;                                                              \
        v3 = ROTL(v3, 16);                                                     \
        v3 ^= v2;                                                              \
        v0 += v3;                                                              \
        v3 = ROTL(v3, 21);                                                     \
        v3 ^= v0;                                                              \
        v2 += v1;                                                              \
        v1 = ROTL(v1, 17);                                                     \
        v1 ^= v2;                                                              \
        v2 = ROTL(v2, 32);                                                     \
    } while (0)

static inline int 
xqc_siphash_init(xqc_siphash_ctx_t *ctx, const unsigned char *k, size_t key_len,
    size_t hash_size, int crounds, int drounds)
{
    uint64_t k0, k1;
    if (key_len != XQC_SIPHASH_KEY_SIZE) {
        return XQC_ERROR;
    }
    /* hash_size must be 8 or 16 */
    if (hash_size != 8 && hash_size != 16) {
        return XQC_ERROR;
    }
    k0 = U8TO64_LE(k);
    k1 = U8TO64_LE(k + 8);
    
    ctx->v0 = 0x736f6d6570736575ULL ^ k0;
    ctx->v1 = 0x646f72616e646f6dULL ^ k1;
    ctx->v2 = 0x6c7967656e657261ULL ^ k0;
    ctx->v3 = 0x7465646279746573ULL ^ k1;

    ctx->hash_size = hash_size;
    if (hash_size == 16) {
        ctx->v1 ^= 0xee;
    }
    /* default: SipHash-2-4 */
    if (crounds == 0) {
        ctx->crounds = XQC_SIPHASH_C_ROUNDS;
    } else {
        ctx->crounds = crounds;
    }
    if (drounds == 0) {
        ctx->drounds = XQC_SIPHASH_D_ROUNDS;
    } else {
        ctx->drounds = drounds;
    }
    return XQC_OK;
}


/*
    Computes a SipHash value
    *ctx: point to siphash context 
    *in: pointer to input data (read-only)
    inlen: input data length in bytes (any size_t value)
    *out: pointer to output data (write-only), outlen bytes must be allocated
    outlen: length of the output in bytes, must be 8 or 16
*/

static inline int
xqc_siphash(xqc_siphash_ctx_t *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
    uint64_t b = (uint64_t)inlen << 56, m;
    const uint8_t *pi = in, *end = in + inlen - (inlen % sizeof(uint64_t));
    int left = inlen & 7;
    int i = 0;
    uint64_t v0 = ctx->v0;
    uint64_t v1 = ctx->v1;
    uint64_t v2 = ctx->v2;
    uint64_t v3 = ctx->v3;

    if (outlen != ctx->hash_size) {
        return XQC_ERROR;
    }

    for(; pi != end; pi += 8) {
        m = U8TO64_LE(pi);
        v3 ^= m;
        for (i = 0; i < ctx->crounds; i++) {
            SIPROUND; 
        }
        v0 ^= m;
    }

    switch (left) {
    case 7:
        b |= ((uint64_t)pi[6]) << 48;
    case 6:
        b |= ((uint64_t)pi[5]) << 40;
    case 5:
        b |= ((uint64_t)pi[4]) << 32;
    case 4:
        b |= ((uint64_t)pi[3]) << 24;
    case 3:
        b |= ((uint64_t)pi[2]) << 16;
    case 2:
        b |= ((uint64_t)pi[1]) << 8;
    case 1:
        b |= ((uint64_t)pi[0]);
        break;
    case 0:
        break;
    }

    v3 ^= b;
    for (i = 0; i < ctx->crounds; ++i)
        SIPROUND;
    v0 ^= b;

    if (outlen == 16) {
        v2 ^= 0xee;
    } else {
        v2 ^= 0xff;
    }

    for (i = 0; i < ctx->drounds; ++i)
        SIPROUND;

    b = v0 ^ v1 ^ v2  ^ v3;
    U64TO8_LE(out, b);
    if (outlen == 8) {
        return XQC_OK;
    }
    v1 ^= 0xdd;
    for (i = 0; i < ctx->drounds; ++i)
        SIPROUND;
    b = v0 ^ v1 ^ v2  ^ v3;
    U64TO8_LE(out + 8, b);
    return XQC_OK;
}




#endif /* _XQC_SIPHASH_H_INCLUDED_ */
