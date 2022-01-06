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

static const char * const (xqc_crypto_initial_salt)[] = {
    /* placeholder */
    [XQC_IDRAFT_INIT_VER] = 
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",

    /* QUIC v1 */
    [XQC_VERSION_V1] = 
        "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a",

    /* draft-29 ~ draft-32 */
    [XQC_IDRAFT_VER_29] = 
        "\xaf\xbf\xec\x28\x99\x93\xd2\x4c\x9e\x97\x86\xf1\x9c\x61\x11\xe0\x43\x90\xa8\x99",

    /* version negotiation */
    [XQC_IDRAFT_VER_NEGOTIATION] = 
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
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
