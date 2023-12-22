/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/tls/xqc_crypto.h"
#include <openssl/chacha.h>


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


void *
xqc_hp_ctx_new(const xqc_hdr_protect_cipher_t *hp_cipher, const uint8_t *key)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return NULL;
    }

    if (EVP_EncryptInit_ex(ctx, hp_cipher->cipher, NULL, key, NULL) != XQC_SSL_SUCCESS) {
        goto err;
    }

    return ctx;
err:
    xqc_hp_ctx_free(ctx);
    return NULL;
}

void
xqc_hp_ctx_free(void *hp_ctx)
{
    if (hp_ctx) {
        EVP_CIPHER_CTX_free(hp_ctx);
    }
}

xqc_int_t
xqc_bssl_hp_mask(const xqc_hdr_protect_cipher_t *hp_cipher, void *hp_ctx,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *sample, size_t samplelen)
{
    size_t outlen = 0;
    int len = 0;
    (void)hp_cipher;
    (void)destcap;
    (void)key;
    (void)keylen;
    (void)samplelen;

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)hp_ctx;
    if (!ctx) {
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, sample) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_EncryptUpdate(ctx, dest, &len, plaintext, plaintextlen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    outlen = len;

    if (EVP_EncryptFinal_ex(ctx, dest + outlen, &len) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (len != 0 /* NO PADDING */) {
        goto err;
    }

    *destlen = outlen;

    return XQC_OK;

err:
    return -XQC_TLS_ENCRYPT_DATA_ERROR;
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
    uint32_t *counter = (uint32_t *)(sample);
    sample += sizeof(uint32_t);

    CRYPTO_chacha_20(dest, plaintext, plaintextlen, key, sample, *counter);

    *destlen = plaintextlen;
    return XQC_OK;
}