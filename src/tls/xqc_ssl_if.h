/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_SSL_INTERFACE_H
#define XQC_SSL_INTERFACE_H

#include <xquic/xquic_typedef.h>
#include "xqc_tls_defs.h"

#include <openssl/ssl.h>

/**
 * @brief this file wraps ssl interfaces between different ssl implements
 */

typedef enum xqc_ssl_handshake_res_s {
    XQC_SSL_HSK_RES_FAIL    = -1,
    XQC_SSL_HSK_RES_WAIT    = 0,
    XQC_SSL_HSK_RES_FIN     = 1,
} xqc_ssl_handshake_res_t;


void xqc_ssl_ctx_set_timeout(SSL_CTX *ctx, uint32_t timeout);

xqc_int_t xqc_ssl_ctx_set_cipher_suites(SSL_CTX *ctx, const char *ciphers);

/**
 * @brief early data related functions
 */
void xqc_ssl_ctx_enable_max_early_data(SSL_CTX *ctx);
xqc_bool_t xqc_ssl_session_is_early_data_enabled(SSL_SESSION *session);
xqc_bool_t xqc_ssl_is_early_data_accepted(SSL *ssl);
void xqc_ssl_enable_max_early_data(SSL *ssl);

xqc_int_t xqc_ssl_get_certs_array(SSL *ssl, X509_STORE_CTX *store_ctx, unsigned char **certs_array,
    size_t array_cap, size_t *certs_array_len, size_t *certs_len);
void xqc_ssl_free_certs_array(unsigned char **certs_array, size_t certs_array_len);

xqc_ssl_handshake_res_t xqc_ssl_do_handshake(SSL *ssl);

#endif