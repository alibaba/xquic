/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <openssl/base.h>
#include <openssl/ssl.h>
#include "src/tls/xqc_ssl_if.h"
#include "src/tls/xqc_tls_common.h"


void
xqc_ssl_ctx_set_timeout(SSL_CTX *ctx, uint32_t timeout)
{
    timeout = (timeout == 0 ? XQC_SESSION_DEFAULT_TIMEOUT : timeout);

    SSL_CTX_set_timeout(ctx, timeout);
    SSL_CTX_set_session_psk_dhe_timeout(ctx, timeout);
}


void
xqc_ssl_ctx_enable_max_early_data(SSL_CTX *ctx)
{
    /* for encapsulation, BoringSSL has no interface to enable max_early_data on SSL_CTX */
}


xqc_int_t
xqc_ssl_ctx_set_cipher_suites(SSL_CTX *ctx, const char *ciphers)
{
    /* BoringSSL have a built-in preference order and do not support setting TLS 1.3 cipher */
    return XQC_OK;
}



xqc_bool_t
xqc_ssl_session_is_early_data_enabled(SSL_SESSION *session)
{
    return SSL_SESSION_early_data_capable(session);
}


void
xqc_ssl_enable_max_early_data(SSL *ssl)
{
    SSL_set_early_data_enabled(ssl, 1); 
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
        /* get the size of cert */
        cert = sk_X509_value(chain, i);
        cert_size = i2d_X509(cert, NULL);
        if (cert_size <= 0) {
            return -XQC_TLS_INTERNAL;
        }

        /* malloc memory for copy cert */
        certs_array[i] = xqc_malloc(cert_size);
        if (certs_array[i] == NULL) {
            return -XQC_TLS_NOMEM;
        }

        /* copy cert */
        certs_len[i] = i2d_X509(cert, &certs_array[i]);
        if (certs_len[i] <= 0) {
            return -XQC_TLS_INTERNAL;
        }
    }

    return XQC_OK;
}

void
xqc_ssl_free_certs_array(unsigned char **certs_array, size_t certs_array_len)
{
}


xqc_bool_t
xqc_ssl_is_early_data_accepted(SSL *ssl)
{
    return SSL_early_data_accepted(ssl) ? XQC_TRUE : XQC_FALSE;
}


xqc_ssl_handshake_res_t
xqc_ssl_do_handshake(SSL *ssl)
{
    int ret;

again:
    ERR_clear_error();
    ret = SSL_do_handshake(ssl);
    if (ret <= 0) {
        switch (SSL_get_error(ssl, ret)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return XQC_SSL_HSK_RES_WAIT;

        case SSL_ERROR_EARLY_DATA_REJECTED: {
            /* reset the state */
            SSL_reset_early_data_reject(ssl);
            /* resume handshake */
            goto again;
        }

        case SSL_ERROR_SSL:
        default:
            return XQC_SSL_HSK_RES_FAIL;
        }
    }

    /* early return */
    if (SSL_in_early_data(ssl)) {
        return XQC_SSL_HSK_RES_WAIT;
    }

    return XQC_SSL_HSK_RES_FIN;
}
