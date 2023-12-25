/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/tls/xqc_hkdf.h"
#include <openssl/hkdf.h>
#include <openssl/err.h>
#include <openssl/chacha.h>


xqc_int_t
xqc_hkdf_extract(uint8_t *dest, size_t destlen, const uint8_t *secret, size_t secretlen,
    const uint8_t *salt, size_t saltlen, const xqc_digest_t *md) 
{
    if (XQC_SSL_SUCCESS != HKDF_extract(dest, &destlen, md->digest,
                                        secret, secretlen, salt, saltlen))
    {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    return XQC_OK;
}

xqc_int_t
xqc_hkdf_expand(uint8_t *dest, size_t destlen, const uint8_t *secret, size_t secretlen,
    const uint8_t *info, size_t infolen, const xqc_digest_t *md) 
{
    if (XQC_SSL_SUCCESS != HKDF_expand(dest, destlen, md->digest,
                                       secret, secretlen, info, infolen))
    {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    return XQC_OK;
}
