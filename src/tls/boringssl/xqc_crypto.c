/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/tls/xqc_crypto.h"
#include <openssl/chacha.h>

xqc_int_t 
xqc_bssl_aead_encrypt(const xqc_pkt_protect_aead_t *pp_aead,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen)
{
    EVP_AEAD_CTX *ctx = EVP_AEAD_CTX_new(pp_aead->aead, key, keylen, pp_aead->taglen);
    if (ctx == NULL) {
        return XQC_TLS_NOBUF;
    }

    int ret = EVP_AEAD_CTX_seal(ctx, dest, destlen, destcap, nonce, noncelen,
                                plaintext, plaintextlen, ad, adlen);

    if (ret != XQC_SSL_SUCCESS) {
        goto err;
    }

    EVP_AEAD_CTX_free(ctx);
    return XQC_OK;

err:
    EVP_AEAD_CTX_free(ctx);
    return -XQC_TLS_ENCRYPT_DATA_ERROR;
}

xqc_int_t
xqc_bssl_aead_decrypt(const xqc_pkt_protect_aead_t *pp_aead,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *ciphertext, size_t ciphertextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen)
{
    EVP_AEAD_CTX *ctx = EVP_AEAD_CTX_new(pp_aead->aead, key, keylen, pp_aead->taglen);
    if (ctx == NULL) {
        return XQC_TLS_NOBUF;
    }

    int ret = EVP_AEAD_CTX_open(ctx, dest, destlen, destcap, nonce, noncelen,
                                ciphertext, ciphertextlen, ad, adlen);

    if (ret != XQC_SSL_SUCCESS) {
        goto err;
    }

    EVP_AEAD_CTX_free(ctx);
    return XQC_OK;

err:
    EVP_AEAD_CTX_free(ctx);
    return -XQC_TLS_DECRYPT_DATA_ERROR;
}

xqc_int_t
xqc_bssl_hp_mask(const xqc_hdr_protect_cipher_t *hp_cipher,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *sample, size_t samplelen)
{
    size_t outlen = 0;
    int len = 0;

    EVP_CIPHER_CTX  *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -XQC_TLS_NOBUF;
    }

    if (EVP_EncryptInit_ex(ctx, hp_cipher->cipher, NULL, key, sample) != XQC_SSL_SUCCESS) {
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

    EVP_CIPHER_CTX_free(ctx);
    return XQC_OK;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -XQC_TLS_ENCRYPT_DATA_ERROR;
}

xqc_int_t
xqc_bssl_hp_mask_chacha20(const xqc_hdr_protect_cipher_t *hp_cipher,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *sample, size_t samplelen)
{
    (void) hp_cipher;

    if (XQC_UNLIKELY(keylen != 32 && samplelen != 16)) {
        return -XQC_TLS_INVALID_ARGUMENT;
    }
    uint32_t *counter = (uint32_t *)(sample);
    sample += sizeof(uint32_t);

    CRYPTO_chacha_20(dest, plaintext, plaintextlen, key, sample, *counter);

    *destlen = plaintextlen;
    return XQC_OK;
}