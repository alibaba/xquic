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
xqc_h3_ctx_init(xqc_engine_t *engine, xqc_h3_callbacks_t *h3_cbs)
{
    if (engine == NULL || h3_cbs == NULL) {
        return -XQC_EPARAM;
    }

    xqc_h3_ctx_t *h3_ctx = NULL;
    xqc_int_t ret = XQC_OK;

    /* init http3 layer callbacks */
    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs       = h3_conn_callbacks,
        .stream_cbs     = h3_stream_callbacks,
    };

    h3_ctx = xqc_h3_ctx_create(h3_cbs);
    if (h3_ctx == NULL) {
        return -XQC_EMALLOC;
    }

    /* register H3 */
    if (xqc_engine_register_alpn(engine, XQC_ALPN_H3, strlen(XQC_ALPN_H3), &ap_cbs, h3_ctx) != XQC_OK) {
        xqc_free(h3_ctx);
        ret = -XQC_EFATAL;
        goto error;
    }

    h3_ctx = xqc_h3_ctx_create(h3_cbs);
    if (h3_ctx == NULL) {
        ret = -XQC_EMALLOC;
        goto error;
    }

    /* register H3-29 */
    if (xqc_engine_register_alpn(engine, XQC_ALPN_H3_29, strlen(XQC_ALPN_H3_29), &ap_cbs, h3_ctx) != XQC_OK) {
        xqc_free(h3_ctx);
        ret = -XQC_EFATAL;
        goto error;
    }

    if (engine->config->enable_h3_ext) {

        ap_cbs.dgram_cbs = h3_ext_datagram_callbacks;

        h3_ctx = xqc_h3_ctx_create(h3_cbs);
        if (h3_ctx == NULL) {
            ret = -XQC_EMALLOC;
            goto error;
        }

        /* register h3-ext ALPN */
        if (xqc_engine_register_alpn(engine, XQC_ALPN_H3_EXT, strlen(XQC_ALPN_H3_EXT), &ap_cbs, h3_ctx) != XQC_OK) {
            xqc_free(h3_ctx);
            ret = -XQC_EFATAL;
            goto error;
        }
    }

    return ret;

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
        if (h3_ctx->extension_registered
            && h3_ctx->extension_ops.ctx_destroy)
        {
            h3_ctx->extension_ops.ctx_destroy(h3_ctx->extension_data);
        }
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

static void
xqc_h3_extension_ctx_destroy(void *data)
{
    xqc_h3_ctx_t *ctx = data;
    if (ctx->extension_ops.ctx_destroy) {
        ctx->extension_ops.ctx_destroy(ctx->extension_data);
    }
    xqc_free(ctx);
}

xqc_int_t
xqc_h3_extension_register(xqc_engine_t *engine,
    const xqc_h3_extension_ops_t *ops, void *ctx)
{
    if (engine == NULL || ops == NULL) {
        return -XQC_EPARAM;
    }

    xqc_h3_ctx_t *h3_ctx = xqc_engine_get_alpn_ctx(engine, XQC_ALPN_H3,
                                                 strlen(XQC_ALPN_H3));
    if (h3_ctx == NULL) {
        xqc_h3_callbacks_t callbacks = {0};
        xqc_int_t ret = xqc_h3_ctx_init(engine, &callbacks);
        if (ret != XQC_OK) {
            return ret;
        }
        h3_ctx = xqc_engine_get_alpn_ctx(engine, XQC_ALPN_H3,
                                        strlen(XQC_ALPN_H3));
    }
    if (h3_ctx->extension_registered) {
        return -XQC_ESTATE;
    }

    xqc_app_proto_callbacks_t callbacks = {
        .conn_cbs = h3_conn_callbacks,
        .stream_cbs = h3_stream_callbacks,
        .dgram_cbs = ops->datagram_callbacks,
    };
    xqc_int_t ret = xqc_engine_register_alpn(engine, XQC_ALPN_H3,
        strlen(XQC_ALPN_H3), &callbacks, h3_ctx);
    if (ret != XQC_OK) {
        return ret;
    }
    h3_ctx->extension_ops = *ops;
    h3_ctx->extension_data = ctx;
    h3_ctx->extension_registered = XQC_TRUE;
    return xqc_engine_set_alpn_ctx_destructor(engine, XQC_ALPN_H3,
        strlen(XQC_ALPN_H3), xqc_h3_extension_ctx_destroy);
}

void *
xqc_h3_extension_get_context(xqc_engine_t *engine)
{
    if (engine == NULL) {
        return NULL;
    }
    xqc_h3_ctx_t *h3_ctx = xqc_engine_get_alpn_ctx(engine, XQC_ALPN_H3,
                                                 strlen(XQC_ALPN_H3));
    return h3_ctx && h3_ctx->extension_registered
        ? h3_ctx->extension_data : NULL;
}
