/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/tls/xqc_crypto.h"
#include "src/common/xqc_malloc.h"
#include <openssl/aes.h>
#include <openssl/chacha.h>
#include <openssl/mem.h>


void *
xqc_aead_ctx_new(const xqc_pkt_protect_aead_t *pp_aead, xqc_key_type_t type,
                 const uint8_t *key, size_t noncelen)
{
    (void)noncelen;
    (void)type;

    size_t keylen = EVP_AEAD_key_length(pp_aead->aead);
    return EVP_AEAD_CTX_new(pp_aead->aead, key, keylen, pp_aead->taglen);
}

void
xqc_aead_ctx_free(void *aead_ctx)
{
    if (aead_ctx) {
        EVP_AEAD_CTX_free(aead_ctx);
    }
}

xqc_int_t 
xqc_bssl_aead_encrypt(const xqc_pkt_protect_aead_t *pp_aead, void *aead_ctx,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen)
{
    (void)pp_aead;
    (void)key;
    (void)keylen;

    EVP_AEAD_CTX *ctx = (EVP_AEAD_CTX *)aead_ctx;
    if (!ctx) {
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    int ret = EVP_AEAD_CTX_seal(ctx, dest, destlen, destcap, nonce, noncelen,
                                plaintext, plaintextlen, ad, adlen);

    if (ret != XQC_SSL_SUCCESS) {
        goto err;
    }

    return XQC_OK;

err:
    return -XQC_TLS_ENCRYPT_DATA_ERROR;
}

xqc_int_t
xqc_bssl_aead_decrypt(const xqc_pkt_protect_aead_t *pp_aead, void *aead_ctx,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *ciphertext, size_t ciphertextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen)
{
    (void)pp_aead;
    (void)key;
    (void)keylen;

    EVP_AEAD_CTX *ctx = (EVP_AEAD_CTX *)aead_ctx;
    if (!ctx) {
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    int ret = EVP_AEAD_CTX_open(ctx, dest, destlen, destcap, nonce, noncelen,
                                ciphertext, ciphertextlen, ad, adlen);

    if (ret != XQC_SSL_SUCCESS) {
        goto err;
    }

    return XQC_OK;

err:
    return -XQC_TLS_DECRYPT_DATA_ERROR;
}


/*
 * The header protection context of an AES cipher is the AES key schedule of
 * the header protection key: each mask is one AES block, see
 * xqc_bssl_hp_mask().
 */
void *
xqc_hp_ctx_new(const xqc_hdr_protect_cipher_t *hp_cipher, const uint8_t *key)
{
    AES_KEY *aes_key = xqc_malloc(sizeof(AES_KEY));
    if (aes_key == NULL) {
        return NULL;
    }

    if (AES_set_encrypt_key(key, (unsigned) hp_cipher->keylen * 8, aes_key)
        != 0)
    {
        xqc_free(aes_key);
        return NULL;
    }

    return aes_key;
}

void
xqc_hp_ctx_free(void *hp_ctx)
{
    if (hp_ctx) {
        OPENSSL_cleanse(hp_ctx, sizeof(AES_KEY));
        xqc_free(hp_ctx);
    }
}

/*
 * RFC 9001 Section 5.4.3: the AES-based header protection mask is
 * AES-ECB(hp_key, sample), the first block of AES-CTR with the sample as
 * the counter block. One block cipher call computes it, with the key
 * schedule that xqc_hp_ctx_new() prepared.
 */
xqc_int_t
xqc_bssl_hp_mask(const xqc_hdr_protect_cipher_t *hp_cipher, void *hp_ctx,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *sample, size_t samplelen)
{
    uint8_t  block[AES_BLOCK_SIZE];
    size_t   i;

    (void)hp_cipher;
    (void)key;
    (void)keylen;

    if (hp_ctx == NULL) {
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    if (samplelen < AES_BLOCK_SIZE || plaintextlen > AES_BLOCK_SIZE
        || plaintextlen > destcap)
    {
        return -XQC_TLS_ENCRYPT_DATA_ERROR;
    }

    AES_encrypt(sample, block, (const AES_KEY *) hp_ctx);

    for (i = 0; i < plaintextlen; i++) {
        dest[i] = block[i] ^ plaintext[i];
    }
    *destlen = plaintextlen;

    return XQC_OK;
}

xqc_int_t
xqc_bssl_hp_mask_chacha20(const xqc_hdr_protect_cipher_t *hp_cipher, void *hp_ctx,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *sample, size_t samplelen)
{
    (void)hp_cipher;
    (void)hp_ctx;
    (void)destcap;

    if (XQC_UNLIKELY(keylen != 32 && samplelen != 16)) {
        return -XQC_TLS_INVALID_ARGUMENT;
    }
    /*
     * RFC 9001 §5.4.4: decode the counter as little-endian without
     * alignment or strict-aliasing requirements on sample.
     */
    uint32_t counter = (uint32_t)sample[0]
                     | ((uint32_t)sample[1] << 8)
                     | ((uint32_t)sample[2] << 16)
                     | ((uint32_t)sample[3] << 24);
    sample += sizeof(counter);

    CRYPTO_chacha_20(dest, plaintext, plaintextlen, key, sample, counter);

    *destlen = plaintextlen;
    return XQC_OK;
}