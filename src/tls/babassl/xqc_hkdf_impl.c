/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/tls/xqc_hkdf.h"
#include <openssl/kdf.h>


xqc_int_t
xqc_hkdf_expand(uint8_t *dest, size_t destlen, const uint8_t *secret, size_t secretlen,
    const uint8_t *info, size_t infolen, const xqc_digest_t *ctx) 
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        return -XQC_TLS_NOBUF;
    }

    if (EVP_PKEY_derive_init(pctx) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, ctx->digest) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, "", 0) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infolen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_derive(pctx, dest, &destlen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    EVP_PKEY_CTX_free(pctx);
    return XQC_OK;

err:
    EVP_PKEY_CTX_free(pctx);
    return -XQC_TLS_DERIVE_KEY_ERROR;
}


xqc_int_t
xqc_hkdf_extract(uint8_t *dest, size_t destlen, const uint8_t *secret, size_t secretlen,
    const uint8_t *salt, size_t saltlen, const xqc_digest_t *ctx)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        return -XQC_TLS_NOBUF;
    }

    if (EVP_PKEY_derive_init(pctx) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, ctx->digest) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_derive(pctx, dest, &destlen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    EVP_PKEY_CTX_free(pctx);
    return XQC_OK;

err:
    EVP_PKEY_CTX_free(pctx);
    return -XQC_TLS_DERIVE_KEY_ERROR;
}

