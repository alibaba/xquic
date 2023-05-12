/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <xquic/xquic_typedef.h>
#include "xqc_h3_ctx.h"
#include "xqc_h3_conn.h"
#include "xqc_h3_stream.h"
#include "xqc_h3_ext_dgram.h"
#include "src/transport/xqc_engine.h"

/* 应用层注册回调，放到engine */
typedef struct xqc_h3_ctx_s {
    xqc_h3_callbacks_t  h3_cbs;
} xqc_h3_ctx_t;


xqc_h3_ctx_t *h3_ctx = NULL;

xqc_int_t
xqc_h3_ctx_init(xqc_engine_t *engine, xqc_h3_callbacks_t *h3_cbs)
{
    if (engine == NULL || h3_cbs == NULL) {
        return -XQC_EPARAM;
    }

    if (NULL == h3_ctx) {
        h3_ctx = xqc_malloc(sizeof(xqc_h3_ctx_t));
        if (NULL == h3_ctx) {
            return -XQC_EMALLOC;
        }
    }

    /* save h3 callbacks */
    h3_ctx->h3_cbs = *h3_cbs;

    /* init http3 layer callbacks */
    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs       = h3_conn_callbacks,
        .stream_cbs     = h3_stream_callbacks,
    };

    /* register ALPN and transport layer callbacks */
    if (xqc_engine_register_alpn(engine, XQC_ALPN_H3, strlen(XQC_ALPN_H3), &ap_cbs) != XQC_OK
        || xqc_engine_register_alpn(engine, XQC_ALPN_H3_29, strlen(XQC_ALPN_H3_29), &ap_cbs) != XQC_OK)
    {
        xqc_h3_ctx_destroy(engine);
        return -XQC_EFATAL;
    }

    if (engine->config->enable_h3_ext) {

        ap_cbs.dgram_cbs = h3_ext_datagram_callbacks;

        /* register h3-ext ALPN */
        if (xqc_engine_register_alpn(engine, XQC_ALPN_H3_EXT, strlen(XQC_ALPN_H3_EXT), &ap_cbs) != XQC_OK)
        {
            xqc_h3_ctx_destroy(engine);
            return -XQC_EFATAL;
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_h3_ctx_destroy(xqc_engine_t *engine)
{
    xqc_engine_unregister_alpn(engine, XQC_ALPN_H3_29, strlen(XQC_ALPN_H3_29));
    xqc_engine_unregister_alpn(engine, XQC_ALPN_H3, strlen(XQC_ALPN_H3));
    xqc_engine_unregister_alpn(engine, XQC_ALPN_H3_EXT, strlen(XQC_ALPN_H3_EXT));

    if (h3_ctx) {
        xqc_free(h3_ctx);
        h3_ctx = NULL;
    }

    return XQC_OK;
}


xqc_int_t
xqc_h3_ctx_get_app_callbacks(xqc_h3_callbacks_t **h3_cbs)
{
    if (NULL == h3_ctx) {
        return -XQC_EFATAL;
    }

    *h3_cbs = &h3_ctx->h3_cbs;
    return XQC_OK;
}
