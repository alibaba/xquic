/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/tls/xqc_crypto.h"


static xqc_int_t
xqc_null_aead_encrypt(const xqc_pkt_protect_aead_t *pp_aead,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen)
{
    *destlen = plaintextlen + xqc_aead_overhead(pp_aead, plaintextlen);
    if (XQC_UNLIKELY(*destlen > destcap)) {
        return -XQC_TLS_INTERNAL;
    }

    if (XQC_LIKELY(dest != plaintext)) {
        memmove(dest, plaintext, plaintextlen);
    }
    return XQC_OK;
}

static xqc_int_t
xqc_null_aead_decrypt(const xqc_pkt_protect_aead_t *pp_aead,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *ciphertext, size_t ciphertextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen)
{
    size_t length = ciphertextlen - xqc_aead_overhead(pp_aead, ciphertextlen);
    *destlen = length;

    if (XQC_UNLIKELY(*destlen > destcap)) {
        return -XQC_TLS_INTERNAL;
    }

    if (XQC_LIKELY(dest != ciphertext)) {
        memmove(dest, ciphertext, length);
    }

    return XQC_OK;
}

static xqc_int_t
xqc_null_hp_mask(const xqc_hdr_protect_cipher_t *hp_cipher,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *sample, size_t samplelen)
{
    *destlen = plaintextlen;

    if (XQC_UNLIKELY(*destlen > destcap)) {
        return -XQC_TLS_INTERNAL;
    }

    if (XQC_UNLIKELY(dest != plaintext)) {
        memmove(dest, plaintext, plaintextlen);
    }

    return XQC_OK;
}


void
xqc_aead_init_null(xqc_pkt_protect_aead_t *pp_aead, size_t taglen)
{
    pp_aead->keylen     = 1;
    pp_aead->noncelen   = 1;
    pp_aead->taglen     = taglen;

    pp_aead->encrypt    = xqc_null_aead_encrypt;
    pp_aead->decrypt    = xqc_null_aead_decrypt;
}

void
xqc_cipher_init_null(xqc_hdr_protect_cipher_t *hp_cipher)
{
    hp_cipher->keylen   = 1;
    hp_cipher->noncelen = 1;

    hp_cipher->hp_mask  = xqc_null_hp_mask;
}