/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "src/tls/xqc_ssl_if.h"
#include "src/tls/xqc_tls_common.h"


void
xqc_ssl_ctx_set_timeout(SSL_CTX *ctx, uint32_t timeout)
{
    timeout = (timeout == 0 ? XQC_SESSION_DEFAULT_TIMEOUT : timeout);
    SSL_CTX_set_timeout(ctx, timeout);
}

void
xqc_ssl_ctx_enable_max_early_data(SSL_CTX *ctx)
{
    SSL_CTX_set_max_early_data(ctx, XQC_UINT32_MAX);
}


xqc_int_t
xqc_ssl_ctx_set_cipher_suites(SSL_CTX *ctx, const char *ciphers)
{
    int ret = SSL_CTX_set_ciphersuites(ctx, ciphers);
    if (ret != XQC_SSL_SUCCESS) {
        return -XQC_TLS_INTERNAL;
    }

    return XQC_OK;
}


xqc_bool_t
xqc_ssl_is_early_data_enabled(SSL_SESSION *session)
{
    return SSL_SESSION_get_max_early_data(session) == XQC_UINT32_MAX;
}


void
xqc_ssl_enable_max_early_data(SSL *ssl)
{
    SSL_set_quic_early_data_enabled(ssl, 1);
}


xqc_int_t
xqc_ssl_get_certs_array(SSL *ssl, X509_STORE_CTX *store_ctx, unsigned char **certs_array,
    size_t array_cap, size_t *certs_array_len, size_t *certs_len)
{

    unsigned char *cert_buf = NULL;
    X509 *cert = NULL;
    int cert_size = 0;
    const STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(store_ctx);

    *certs_array_len = sk_X509_num(chain);
    if (*certs_array_len > XQC_MAX_VERIFY_DEPTH) { /* impossible */
        X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_CERT_CHAIN_TOO_LONG);
        return -XQC_TLS_INTERNAL;
    }

    for (int i = 0; i < *certs_array_len; i++) {
        cert = sk_X509_value(chain, i);

        cert_size = i2d_X509(cert, NULL);
        if (cert_size <= 0) {
            return -XQC_TLS_INTERNAL;
        }

        /* remember to free memory before return */
        certs_array[i] = xqc_malloc(cert_size);
        if (certs_array[i] == NULL) {
            return -XQC_TLS_INTERNAL;
        }

        cert_buf = certs_array[i];
        cert_size = i2d_X509(cert, &cert_buf);
        if (cert_size <= 0) {
            return -XQC_TLS_INTERNAL;
        }
        certs_len[i] = cert_size;
    }

    return XQC_OK;
}

void
xqc_ssl_free_certs_array(unsigned char **certs_array, size_t certs_array_len)
{
    for (int i = 0; i < certs_array_len; i++) {
        if (certs_array[i] != NULL) {
            xqc_free(certs_array[i]);
        }
    }
}

xqc_bool_t
xqc_ssl_is_early_data_accepted(SSL *ssl)
{
    return SSL_get_early_data_status(ssl) == SSL_EARLY_DATA_ACCEPTED ? XQC_TRUE : XQC_FALSE;
}


xqc_bool_t
xqc_ssl_session_is_early_data_enabled(SSL_SESSION *session)
{
    return SSL_SESSION_get_max_early_data(session) == XQC_UINT32_MAX;
}


xqc_ssl_handshake_res_t
xqc_ssl_do_handshake(SSL *ssl)
{
    int rv = SSL_do_handshake(ssl);
    if (rv <= 0) {
        int err = SSL_get_error(ssl, rv);
        switch (err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return XQC_SSL_HSK_RES_WAIT;

        case SSL_ERROR_SSL:
        default:
            return XQC_SSL_HSK_RES_FAIL;
        }
    }

    return XQC_SSL_HSK_RES_FIN;
}

