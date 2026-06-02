/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <xquic/xquic_typedef.h>
#include "xqc_h3_ctx.h"
#include "xqc_h3_conn.h"
#include "xqc_h3_stream.h"
#include "xqc_h3_ext_dgram.h"
#include "src/transport/xqc_engine.h"


xqc_h3_ctx_t*
xqc_h3_ctx_create(xqc_h3_callbacks_t *h3_cbs)
{
    xqc_h3_ctx_t *h3_ctx = NULL;

    h3_ctx = xqc_calloc(1, sizeof(xqc_h3_ctx_t));

    if (h3_ctx) {
        /* save h3 callbacks */
        h3_ctx->h3_cbs = *h3_cbs;
        h3_ctx->h3c_def_local_settings = default_local_h3_conn_settings;
    }

    return h3_ctx;
}

xqc_int_t
xqc_h3_ctx_init_for_alpn(xqc_engine_t *engine, const char *alpn,
    size_t alpn_len, xqc_h3_callbacks_t *h3_cbs)
{
    if (engine == NULL || alpn == NULL || alpn_len == 0 || h3_cbs == NULL) {
        return -XQC_EPARAM;
    }

    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs   = h3_conn_callbacks,
        .stream_cbs = h3_stream_callbacks,
    };
    if (engine->config->enable_h3_ext) {
        ap_cbs.dgram_cbs = h3_ext_datagram_callbacks;
    }

    xqc_h3_ctx_t *h3_ctx = xqc_h3_ctx_create(h3_cbs);
    if (h3_ctx == NULL) {
        return -XQC_EMALLOC;
    }

    if (xqc_engine_register_alpn(engine, alpn, alpn_len, &ap_cbs, h3_ctx) != XQC_OK) {
        xqc_free(h3_ctx);
        return -XQC_EFATAL;
    }

    return XQC_OK;
}

xqc_int_t
xqc_h3_ctx_init(xqc_engine_t *engine, xqc_h3_callbacks_t *h3_cbs)
{
    if (engine == NULL || h3_cbs == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_h3_ctx_init_for_alpn(engine, XQC_ALPN_H3,
        strlen(XQC_ALPN_H3), h3_cbs);
    if (ret != XQC_OK) {
        goto error;
    }

    ret = xqc_h3_ctx_init_for_alpn(engine, XQC_ALPN_H3_29,
        strlen(XQC_ALPN_H3_29), h3_cbs);
    if (ret != XQC_OK) {
        goto error;
    }

    if (engine->config->enable_h3_ext) {
        ret = xqc_h3_ctx_init_for_alpn(engine, XQC_ALPN_H3_EXT,
            strlen(XQC_ALPN_H3_EXT), h3_cbs);
        if (ret != XQC_OK) {
            goto error;
        }
    }

    return XQC_OK;

error:
    xqc_h3_ctx_destroy(engine);
    return ret;
}


xqc_int_t
xqc_h3_ctx_destroy(xqc_engine_t *engine)
{
    xqc_h3_ctx_t *h3_ctx;

    h3_ctx = xqc_engine_get_alpn_ctx(engine, XQC_ALPN_H3_29, strlen(XQC_ALPN_H3_29));
    if (h3_ctx) {
        xqc_free(h3_ctx);
    }

    h3_ctx = xqc_engine_get_alpn_ctx(engine, XQC_ALPN_H3, strlen(XQC_ALPN_H3));
    if (h3_ctx) {
        xqc_free(h3_ctx);
    }

    h3_ctx = xqc_engine_get_alpn_ctx(engine, XQC_ALPN_H3_EXT, strlen(XQC_ALPN_H3_EXT));
    if (h3_ctx) {
        xqc_free(h3_ctx);
    }


    xqc_engine_unregister_alpn(engine, XQC_ALPN_H3_29, strlen(XQC_ALPN_H3_29));
    xqc_engine_unregister_alpn(engine, XQC_ALPN_H3, strlen(XQC_ALPN_H3));
    xqc_engine_unregister_alpn(engine, XQC_ALPN_H3_EXT, strlen(XQC_ALPN_H3_EXT));

    return XQC_OK;
}


xqc_int_t
xqc_h3_ctx_get_app_callbacks(xqc_engine_t *engine, char *alpn, 
    size_t alpn_len, xqc_h3_callbacks_t **h3_cbs)
{
    xqc_list_head_t *pos, *next;
    xqc_alpn_registration_t *alpn_reg;
    xqc_h3_ctx_t *h3_ctx = NULL;

    h3_ctx = xqc_engine_get_alpn_ctx(engine, alpn, alpn_len);

    if (h3_ctx == NULL) {
        return -XQC_EFATAL;
    }

    *h3_cbs = &h3_ctx->h3_cbs;

    return XQC_OK;
}

xqc_int_t 
xqc_h3_ctx_get_default_conn_settings(xqc_engine_t *engine, char *alpn, 
    size_t alpn_len, xqc_h3_conn_settings_t **settings)
{
    xqc_list_head_t *pos, *next;
    xqc_alpn_registration_t *alpn_reg;
    xqc_h3_ctx_t *h3_ctx = NULL;

    h3_ctx = xqc_engine_get_alpn_ctx(engine, alpn, alpn_len);

    if (h3_ctx == NULL) {
        return -XQC_EFATAL;
    }

    *settings = &h3_ctx->h3c_def_local_settings;

    return XQC_OK;
}
