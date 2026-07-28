/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_TLS_COMMON_H
#define XQC_TLS_COMMON_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <xquic/xquic.h>

/**
 * @brief definitions for inner usage
 */

#ifdef WORDS_BIGENDIAN
#  define bswap64(N) (N)
#else /* !WORDS_BIGENDIAN */
#  define bswap64(N)                                                           \
    ((uint64_t)(ntohl((uint32_t)(N))) << 32 | ntohl((uint32_t)((N) >> 32)))
#endif /* !WORDS_BIGENDIAN */


#define XQC_SSL_SUCCESS 1   /* openssl or boringssl 1 success */
#define XQC_SSL_FAIL    0   /* openssl or boringssl 0 failure */


#define XQC_UINT32_MAX  (0xffffffff)


#define XQC_SESSION_DEFAULT_TIMEOUT (7 * 24 * 60 * 60)

#define INITIAL_SECRET_MAX_LEN  32

/* length of QUIC initial salt (all versions use 20 bytes) */
#define XQC_INITIAL_SALT_LEN    20

static const uint8_t xqc_crypto_initial_salt[][XQC_INITIAL_SALT_LEN] = {
    /* placeholder */
    [XQC_IDRAFT_INIT_VER] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    },

    /* QUIC v1 (RFC 9001, Section 5.2) */
    [XQC_VERSION_V1] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    },

    /* draft-29 ~ draft-32 */
    [XQC_IDRAFT_VER_29] = {
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
        0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99
    },

    /* version negotiation */
    [XQC_IDRAFT_VER_NEGOTIATION] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    },
};

static const char * const (xqc_crypto_retry_key)[] = {
    /* placeholder */
    [XQC_IDRAFT_INIT_VER] = 
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",

    /* QUIC v1 */
    [XQC_VERSION_V1] = 
        "\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e",

    /* draft-29 ~ draft-32 */
    [XQC_IDRAFT_VER_29] = 
        "\xcc\xce\x18\x7e\xd0\x9a\x09\xd0\x57\x28\x15\x5a\x6c\xb9\x6b\xe1",

    /* version negotiation */
    [XQC_IDRAFT_VER_NEGOTIATION] = 
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
};

static const char * const (xqc_crypto_retry_nonce)[] = {
    /* placeholder */
    [XQC_IDRAFT_INIT_VER] = 
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",

    /* QUIC v1 */
    [XQC_VERSION_V1] = 
        "\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb",

    /* draft-29 ~ draft-32 */
    [XQC_IDRAFT_VER_29] = 
        "\xe5\x49\x30\xf9\x7f\x21\x36\xf0\x53\x0a\x8c\x1c",

    /* version negotiation */
    [XQC_IDRAFT_VER_NEGOTIATION] = 
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
};


typedef struct xqc_ssl_session_ticket_key_s {
    size_t                      size;
    uint8_t                     name[16];
    uint8_t                     hmac_key[32];
    uint8_t                     aes_key[32];
} xqc_ssl_session_ticket_key_t;


#define XQC_EARLY_DATA_CONTEXT          "xquic"
#define XQC_EARLY_DATA_CONTEXT_LEN      (sizeof(XQC_EARLY_DATA_CONTEXT) - 1)



/* the default max depth of cert chain is 100 */
#define XQC_MAX_VERIFY_DEPTH 100

#define XQC_TLS_SELF_SIGNED_CERT(err_code) \
    (err_code == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT \
        || err_code == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)


#endif
