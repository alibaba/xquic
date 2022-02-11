/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_tls_ctx.h"
#include "xqc_tls_defs.h"
#include "xqc_ssl_cbs.h"
#include "xqc_ssl_if.h"
#include "src/common/xqc_malloc.h"


typedef struct xqc_tls_ctx_s {
    xqc_tls_type_t                  type;

    /* ssl context */
    SSL_CTX                        *ssl_ctx;

    /* general config for ssl */
    xqc_engine_ssl_config_t         cfg;

    /* callback functions for tls connection */
    xqc_tls_callbacks_t             tls_cbs;

    /* session ticket key */
    xqc_ssl_session_ticket_key_t    session_ticket_key;

    /* log handler */
    xqc_log_t                      *log;

    /* the buffer of alpn, for server alpn selection */
    unsigned char                  *alpn_list;
    size_t                          alpn_list_sz;
    size_t                          alpn_list_len;
} xqc_tls_ctx_t;



xqc_int_t
xqc_create_client_ssl_ctx(xqc_tls_ctx_t *ctx)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
    if (NULL == ssl_ctx) {
        xqc_log(ctx->log, XQC_LOG_ERROR, "|create client SSL_CTX error|%s",
                ERR_error_string(ERR_get_error(), NULL));
        return -XQC_TLS_INTERNAL;
    }

    /* set tls version */
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

    if (SSL_CTX_set1_curves_list(ssl_ctx, ctx->cfg.groups) != XQC_SSL_SUCCESS) {
        xqc_log(ctx->log, XQC_LOG_ERROR, "|SSL_CTX_set1_groups_list failed| error info:%s|", 
                ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }

    /* enable session cache */
    SSL_CTX_set_session_cache_mode(ssl_ctx, 
        SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);

    /* set session ticket callback */
    SSL_CTX_sess_set_new_cb(ssl_ctx, xqc_ssl_new_session_cb);

    /* set the lifetime of session */
    xqc_ssl_ctx_set_timeout(ssl_ctx, ctx->cfg.session_timeout);

    ctx->ssl_ctx = ssl_ctx;
    return XQC_OK;

fail:
    SSL_CTX_free(ssl_ctx);
    return -XQC_TLS_INTERNAL;
}


xqc_int_t
xqc_create_server_ssl_ctx(xqc_tls_ctx_t *ctx)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
    if (NULL == ssl_ctx) {
        xqc_log(ctx->log, XQC_LOG_ERROR, "|create server SSL_CTX error|%s",
                ERR_error_string(ERR_get_error(), NULL));
        return -XQC_TLS_INTERNAL;
    }

    /* set tls version */
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

    /* set context options */
    long ssl_opts = (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS)
        | SSL_OP_SINGLE_ECDH_USE
#ifdef SSL_OP_NO_ANTI_REPLAY
        | SSL_OP_NO_ANTI_REPLAY
#endif
        ;
    SSL_CTX_set_options(ssl_ctx, ssl_opts);

    /* Save RAM by releasing read and write buffers when they're empty */
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

    /* set curves list */
    if (SSL_CTX_set1_curves_list(ssl_ctx, ctx->cfg.groups) != XQC_SSL_SUCCESS) {
        xqc_log(ctx->log, XQC_LOG_ERROR, "|SSL_CTX_set1_groups_list failed| error info:%s|",
                ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }

    /* set private key file */
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, ctx->cfg.private_key_file, SSL_FILETYPE_PEM)
        != XQC_SSL_SUCCESS)
    {
        xqc_log(ctx->log, XQC_LOG_ERROR, "|SSL_CTX_use_PrivateKey_file| error info:%s|",
                ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }

    /* set cert file */
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, ctx->cfg.cert_file) != XQC_SSL_SUCCESS) {
        xqc_log(ctx->log, XQC_LOG_ERROR, "|SSL_CTX_use_PrivateKey_file| error info:%s|",
                ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }

    /* check private key of certificate */
    if (SSL_CTX_check_private_key(ssl_ctx) != XQC_SSL_SUCCESS) {
        xqc_log(ctx->log, XQC_LOG_ERROR, "|SSL_CTX_check_private_key| error info:%s|",
                ERR_error_string(ERR_get_error(), NULL));
        goto fail;
    }

    /* set session ticket key callback */
    if (ctx->cfg.session_ticket_key_len == 0
        || ctx->cfg.session_ticket_key_data == NULL)
    {
        xqc_log(ctx->log, XQC_LOG_WARN, "|read ssl session ticket key error|");

    } else {
        SSL_CTX_set_tlsext_ticket_key_cb(ssl_ctx, xqc_ssl_session_ticket_key_cb);
    }

    SSL_CTX_set_default_verify_paths(ssl_ctx);
    SSL_CTX_set_alpn_select_cb(ssl_ctx, xqc_ssl_alpn_select_cb, ctx);

    xqc_ssl_ctx_enable_max_early_data(ssl_ctx);
    xqc_ssl_ctx_set_timeout(ssl_ctx, ctx->cfg.session_timeout);

    ctx->ssl_ctx = ssl_ctx;
    return XQC_OK;

fail:
    SSL_CTX_free(ssl_ctx);
    return -XQC_TLS_INTERNAL;
}


xqc_int_t
xqc_init_session_ticket_keys(xqc_ssl_session_ticket_key_t *key, char *session_key_data,
    size_t session_key_len)
{
    if (session_key_len != 48 && session_key_len != 80) {
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    memset(key, 0, sizeof(xqc_ssl_session_ticket_key_t));

    if (session_key_len == 48) {
        key->size = 48;
        memcpy(key->name, session_key_data, 16);
        memcpy(key->aes_key, session_key_data + 16, 16);
        memcpy(key->hmac_key, session_key_data + 32, 16);

    } else {
        key->size = 80;
        memcpy(key->name, session_key_data, 16);
        memcpy(key->hmac_key, session_key_data + 16, 32);
        memcpy(key->aes_key, session_key_data + 48, 32);
    }

    return XQC_OK;
}



xqc_int_t
xqc_tls_ctx_set_config(xqc_tls_ctx_t *ctx, const xqc_engine_ssl_config_t *src)
{
    xqc_int_t ret = XQC_OK;
    xqc_engine_ssl_config_t *dst = &ctx->cfg;

    dst->session_timeout = src->session_timeout;

    /* copy ciphers */
    if (src->ciphers && *src->ciphers) {
        int len = strlen(src->ciphers) + 1;
        dst->ciphers = (char *)xqc_malloc(len);
        memcpy(dst->ciphers, src->ciphers, len);

    } else {
        int len = sizeof(XQC_TLS_CIPHERS);
        dst->ciphers = (char *)xqc_malloc(len);
        memcpy(dst->ciphers, XQC_TLS_CIPHERS, len);
    }

    /* copy curves list */
    if (src->groups && *src->groups) {
        int len = strlen(src->groups) + 1;
        dst->groups = (char *)xqc_malloc(len);
        memcpy(dst->groups, src->groups, len);

    } else {
        int len = sizeof(XQC_TLS_GROUPS);
        dst->groups = (char *)xqc_malloc(len);
        memcpy(dst->groups, XQC_TLS_GROUPS, len);
    }

    if (ctx->type == XQC_TLS_TYPE_SERVER) {
        /* copy private key file */
        if (src->private_key_file && *src->private_key_file) {
            int len = strlen(src->private_key_file) + 1;
            dst->private_key_file = (char *)xqc_malloc(len);
            memcpy(dst->private_key_file, src->private_key_file, len);

        } else {
            xqc_log(ctx->log, XQC_LOG_ERROR, "|no private key file|");
            return -XQC_TLS_INVALID_ARGUMENT;
        }

        /* copy cert file */
        if (src->cert_file && *src->cert_file) {
            int len = strlen(src->cert_file) + 1;
            dst->cert_file = (char *)xqc_malloc(len);
            memcpy(dst->cert_file, src->cert_file, len);

        } else {
            xqc_log(ctx->log, XQC_LOG_ERROR, "|no cert file|");
            return -XQC_TLS_INVALID_ARGUMENT;
        }

        /* copy and init session ticket key */
        if (src->session_ticket_key_len > 0) {
            dst->session_ticket_key_len = src->session_ticket_key_len;
            dst->session_ticket_key_data = (char *)xqc_malloc(src->session_ticket_key_len);
            memcpy(dst->session_ticket_key_data, src->session_ticket_key_data,
                src->session_ticket_key_len);

            /* init session ticket key */
            if (xqc_init_session_ticket_keys(&ctx->session_ticket_key, dst->session_ticket_key_data,
                                             dst->session_ticket_key_len) < 0)
            {
                xqc_log(ctx->log, XQC_LOG_ERROR, "|read session ticket key error|");
                return -XQC_TLS_INVALID_ARGUMENT;
            }

        } else {
            dst->session_ticket_key_len = 0;
            dst->session_ticket_key_data = NULL;
            xqc_log(ctx->log, XQC_LOG_WARN, "|no session ticket key data|");
        }
    }

    return XQC_OK;
}


xqc_tls_ctx_t *
xqc_tls_ctx_create(xqc_tls_type_t type, const xqc_engine_ssl_config_t *cfg,
    const xqc_tls_callbacks_t *cbs, xqc_log_t *log)
{
    xqc_tls_ctx_t *ctx = xqc_calloc(1, sizeof(xqc_tls_ctx_t));
    if (NULL == ctx) {
        xqc_log(log, XQC_LOG_ERROR, "|calloc memory for tls ctx error|");
        return NULL;
    }

    ctx->type = type;
    ctx->tls_cbs = *cbs;
    ctx->log = log;

    /* copy config */
    xqc_int_t ret = xqc_tls_ctx_set_config(ctx, cfg);
    if (ret != XQC_OK) {
        goto fail;
    }

    /* init ssl context */
    if (type == XQC_TLS_TYPE_SERVER) {
        ret = xqc_create_server_ssl_ctx(ctx);

    } else {
        ret = xqc_create_client_ssl_ctx(ctx);
    }

    if (ret != XQC_OK) {
        goto fail;
    }

    /* set cipher suites */
    if (cfg->ciphers) {
        ret = xqc_ssl_ctx_set_cipher_suites(ctx->ssl_ctx, cfg->ciphers);
        if (ret != XQC_OK) {
            xqc_log(ctx->log, XQC_LOG_INFO, "|set cipher suites fail|");
            goto fail;
        }

        xqc_log(ctx->log, XQC_LOG_INFO, "|set cipher suites suc|ciphers:%s", cfg->ciphers);
    }

    /* set keylog callback, this will be callback to xqc_tls_t */
    if (cbs->keylog_cb) {
        SSL_CTX_set_keylog_callback(ctx->ssl_ctx, xqc_ssl_keylog_cb);
    }

    return ctx;

fail:
    xqc_tls_ctx_destroy(ctx);
    return NULL;
}


void
xqc_tls_ctx_free_cfg(xqc_tls_ctx_t *ctx)
{
    xqc_engine_ssl_config_t *cfg = &ctx->cfg;
    if (cfg->ciphers) {
        xqc_free(ctx->cfg.ciphers);
    }

    if (cfg->groups) {
        xqc_free(cfg->groups);
    }

    if (cfg->private_key_file) {
        xqc_free(cfg->private_key_file);
    }

    if (cfg->cert_file) {
        xqc_free(cfg->cert_file);
    }

    if (cfg->session_ticket_key_data) {
        xqc_free(cfg->session_ticket_key_data);
    }
}


void
xqc_tls_ctx_destroy(xqc_tls_ctx_t *ctx)
{
    if (ctx != NULL) {
        SSL_CTX_free(ctx->ssl_ctx);

        /* free config memory */
        xqc_tls_ctx_free_cfg(ctx);

        /* free alpn selection buffer */
        if (ctx->alpn_list) {
            xqc_free(ctx->alpn_list);
            ctx->alpn_list = NULL;
        }

        xqc_free(ctx);
        ctx = NULL;
    }
}

SSL_CTX *
xqc_tls_ctx_get_ssl_ctx(xqc_tls_ctx_t *ctx)
{
    return ctx->ssl_ctx;
}


xqc_tls_type_t
xqc_tls_ctx_get_type(xqc_tls_ctx_t *ctx)
{
    return ctx->type;
}


void
xqc_tls_ctx_get_tls_callbacks(xqc_tls_ctx_t *ctx, xqc_tls_callbacks_t **tls_cbs)
{
    *tls_cbs = &ctx->tls_cbs;
}


void
xqc_tls_ctx_get_session_ticket_key(xqc_tls_ctx_t *ctx, xqc_ssl_session_ticket_key_t **stk)
{
    *stk = &ctx->session_ticket_key;
}


void
xqc_tls_ctx_get_cfg(xqc_tls_ctx_t *ctx, xqc_engine_ssl_config_t **cfg)
{
    *cfg = &ctx->cfg;
}


xqc_int_t
xqc_tls_ctx_register_alpn(xqc_tls_ctx_t *ctx, const char *alpn, size_t alpn_len)
{
    xqc_list_head_t *pos, *next;

    if (NULL == alpn || 0 == alpn_len) {
        return -XQC_EPARAM;
    }

    if (alpn_len + 1 > ctx->alpn_list_sz - ctx->alpn_list_len) {
        /* realloc buffer */
        size_t new_alpn_list_sz = 2 * (ctx->alpn_list_sz + alpn_len) + 1;
        char *alpn_list_new = xqc_malloc(new_alpn_list_sz);
        ctx->alpn_list_sz = new_alpn_list_sz;

        /* copy alpn_list */
        xqc_memcpy(alpn_list_new, ctx->alpn_list, ctx->alpn_list_len);
        alpn_list_new[ctx->alpn_list_len] = '\0';

        /* replace */
        xqc_free(ctx->alpn_list);
        ctx->alpn_list = alpn_list_new;
    }

    /* sprintf new alpn to the end of alpn_list buffer */
    snprintf(ctx->alpn_list + ctx->alpn_list_len,
             ctx->alpn_list_sz - ctx->alpn_list_len, "%c%s", (uint8_t)alpn_len, alpn);
    ctx->alpn_list_len = strlen(ctx->alpn_list);

    xqc_log(ctx->log, XQC_LOG_INFO, "|alpn registered|alpn:%s|alpn_list:%s", alpn, ctx->alpn_list);
    return XQC_OK;
}


xqc_int_t
xqc_tls_ctx_unregister_alpn(xqc_tls_ctx_t *ctx, const char *alpn, size_t alpn_len)
{
    if (NULL == alpn || 0 == alpn_len) {
        return -XQC_EPARAM;
    }

    unsigned char *pos = ctx->alpn_list;
    unsigned char *end = ctx->alpn_list + ctx->alpn_list_len;
    while (pos < end) {
        size_t node_len = *pos;     /* length for current alpn node */
        unsigned char *next_node = pos + node_len + 1;
        if (node_len == alpn_len) {
            int cmp_res = memcmp(pos + 1, alpn, alpn_len);
            if (cmp_res == 0) {
                /* found alpn, delete it */
                size_t remain_len = end - next_node;
                memmove(pos, next_node, remain_len);
                ctx->alpn_list_len -= alpn_len + 1;
                return XQC_OK;
            }
        }

        /* move to next node */
        pos = next_node;
    }

    return -XQC_EALPN_NOT_REGISTERED;
}


void
xqc_tls_ctx_get_alpn_list(xqc_tls_ctx_t *ctx, unsigned char **alpn_list, size_t *alpn_list_len)
{
    *alpn_list = ctx->alpn_list;
    *alpn_list_len = ctx->alpn_list_len;
}
