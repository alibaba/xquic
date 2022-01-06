/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_TLS_CTX_H
#define XQC_TLS_CTX_H

#include "xqc_tls.h"
#include "xqc_tls_common.h"
#include <openssl/ssl.h>
#include <openssl/err.h>


/**
 * @brief get SSL_CTX object
 */
SSL_CTX *xqc_tls_ctx_get_ssl_ctx(xqc_tls_ctx_t *ctx);

/**
 * @brief get configured tls context type
 */
xqc_tls_type_t xqc_tls_ctx_get_type(xqc_tls_ctx_t *ctx);

/**
 * @brief get callback functions registered by upper layer
 */
void xqc_tls_ctx_get_tls_callbacks(xqc_tls_ctx_t *ctx, xqc_tls_callbacks_t **tls_cbs);

/**
 * @brief get session ticket key
 */
void xqc_tls_ctx_get_session_ticket_key(xqc_tls_ctx_t *ctx, xqc_ssl_session_ticket_key_t **stk);

/**
 * @brief get ssl common config, basically for server
 */
void xqc_tls_ctx_get_cfg(xqc_tls_ctx_t *ctx, xqc_engine_ssl_config_t **cfg);

/**
 * @brief get alpn list, will be used for application layer protocol negotiation
 */
void xqc_tls_ctx_get_alpn_list(xqc_tls_ctx_t *ctx, unsigned char **alpn_list,
    size_t *alpn_list_len);

#endif
