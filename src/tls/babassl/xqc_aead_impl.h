/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_AEAD_IMPL_H_
#define XQC_AEAD_IMPL_H_

#include <openssl/evp.h>
#include <openssl/ssl.h>

#ifndef XQC_CRYPTO_PRIVATE
#error "Do not include this file directly，include xqc_crypto.h"
#endif


/* Cipher id definition for tls 13 */
#define XQC_TLS13_AES_128_GCM_SHA256                TLS1_3_CK_AES_128_GCM_SHA256
#define XQC_TLS13_AES_256_GCM_SHA384                TLS1_3_CK_AES_256_GCM_SHA384
#define XQC_TLS13_CHACHA20_POLY1305_SHA256          TLS1_3_CK_CHACHA20_POLY1305_SHA256


#define XQC_CIPHER_SUITES_IMPL        const EVP_CIPHER *
#define XQC_AEAD_SUITES_IMPL          XQC_CIPHER_SUITES_IMPL

#define XQC_AEAD_OVERHEAD_IMPL(obj, cln)            (0) + (obj)->taglen

/* inner definition, MUST NOT be called directly */
#define DO_NOT_CALL_XQC_AEAD_INIT(obj, a, tgl) ({                           \
    obj->aead       = a;                                                    \
    obj->keylen     = EVP_CIPHER_key_length(obj->aead);                     \
    obj->noncelen   = EVP_CIPHER_iv_length(obj->aead);                      \
    obj->taglen     = (tgl);                                                \
    obj->encrypt    = xqc_ossl_aead_encrypt;                                \
    obj->decrypt    = xqc_ossl_aead_decrypt;                                \
})

/* inner definition, MUST NOT be called directly */
#define DO_NOT_CALL_XQC_CIPHER_INIT(obj, c)     ({                          \
    obj->cipher     = c;                                                    \
    obj->keylen     = EVP_CIPHER_key_length(obj->cipher);                   \
    obj->noncelen   = EVP_CIPHER_iv_length(obj->cipher);                    \
    obj->hp_mask    = xqc_ossl_hp_mask;                                     \
})

/* aes gcm initialization */
#define XQC_AEAD_INIT_AES_GCM_IMPL(obj, d, ...)   ({                                \
    xqc_pkt_protect_aead_t *___aead  = (obj);                                       \
    DO_NOT_CALL_XQC_AEAD_INIT(___aead, EVP_aes_##d##_gcm(), EVP_GCM_TLS_TAG_LEN);   \
})

/* chacha20 initialization */
#define XQC_AEAD_INIT_CHACHA20_POLY1305_IMPL(obj, ...) ({                                       \
    xqc_pkt_protect_aead_t *___aead = (obj);                                                    \
    DO_NOT_CALL_XQC_AEAD_INIT(___aead, EVP_chacha20_poly1305(), EVP_CHACHAPOLY_TLS_TAG_LEN);    \
})

/* aes cipher initialization */
#define XQC_CIPHER_INIT_AES_CTR_IMPL(obj, d, ...) ({                        \
    xqc_hdr_protect_cipher_t *___cipher = (obj);                            \
    DO_NOT_CALL_XQC_CIPHER_INIT(___cipher, EVP_aes_##d##_ctr());            \
})

/* chacha20 cipher initialization */
#define XQC_CIPHER_INIT_CHACHA20_IMPL(obj, ...)  ({                         \
    xqc_hdr_protect_cipher_t *___cipher = (obj);                            \
    DO_NOT_CALL_XQC_CIPHER_INIT(___cipher, EVP_chacha20());                 \
})


xqc_int_t xqc_ossl_aead_encrypt(const xqc_pkt_protect_aead_t *pp_aead,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen);

xqc_int_t xqc_ossl_aead_decrypt(const xqc_pkt_protect_aead_t *pp_aead,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *ciphertext, size_t ciphertextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen);


xqc_int_t xqc_ossl_hp_mask(const xqc_hdr_protect_cipher_t *hp_cipher,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *sample, size_t samplelen);

#endif
