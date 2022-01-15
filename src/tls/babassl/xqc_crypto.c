/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/tls/xqc_crypto.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

xqc_int_t 
xqc_ossl_aead_encrypt(const xqc_pkt_protect_aead_t *pp_aead,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen)
{
    ssize_t taglen = pp_aead->taglen;
    size_t outlen = 0;
    int len = 0;

    if (destcap <  plaintextlen + xqc_aead_overhead(pp_aead, plaintextlen)) {
        return -XQC_TLS_NOBUF;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    if (EVP_EncryptInit_ex(ctx, pp_aead->aead, NULL, NULL, NULL) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, NULL) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_EncryptUpdate(ctx, NULL, &len, ad, adlen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_EncryptUpdate(ctx, dest, &len, plaintext, plaintextlen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    outlen = len;

    if (EVP_EncryptFinal_ex(ctx, dest + outlen, &len) != XQC_SSL_SUCCESS) {
        goto err;
    }

    outlen += len;

    if (outlen + taglen > destcap) {
        goto err;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen, dest + outlen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    outlen += taglen;

    *destlen = outlen;

    EVP_CIPHER_CTX_free(ctx);
    return XQC_OK;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -XQC_TLS_ENCRYPT_DATA_ERROR;
}

xqc_int_t
xqc_ossl_aead_decrypt(const xqc_pkt_protect_aead_t *pp_aead,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *ciphertext, size_t ciphertextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen)
{
    ssize_t taglen = pp_aead->taglen;
    size_t outlen = 0;
    int len = 0;

    if (taglen > ciphertextlen || ciphertextlen > destcap + xqc_aead_overhead(pp_aead, destcap)) {
        return -XQC_TLS_NOBUF;
    }

    ciphertextlen -= taglen;
    uint8_t *tag = (uint8_t *)(ciphertext + ciphertextlen);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    if (EVP_DecryptInit_ex(ctx, pp_aead->aead, NULL, NULL, NULL) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, NULL) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_DecryptUpdate(ctx, NULL, &len, ad, adlen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_DecryptUpdate(ctx, dest, &len, ciphertext, ciphertextlen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    outlen = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, taglen, (uint8_t *)(tag)) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_DecryptFinal_ex(ctx, dest + outlen, &len) != XQC_SSL_SUCCESS) {
        goto err;
    }

    outlen += len;

    *destlen = outlen;

    EVP_CIPHER_CTX_free(ctx);
    return XQC_OK;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -XQC_TLS_DECRYPT_DATA_ERROR;
}


xqc_int_t
xqc_ossl_hp_mask(const xqc_hdr_protect_cipher_t *hp_cipher,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *sample, size_t samplelen)
{
    size_t outlen = 0;
    int len = 0;

    EVP_CIPHER_CTX  *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    if (EVP_EncryptInit_ex(ctx, hp_cipher->cipher, NULL, key, sample) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_EncryptUpdate(ctx, dest, &len, plaintext, plaintextlen ) != XQC_SSL_SUCCESS) {
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