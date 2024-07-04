/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_hq_ctx.h"
#include "xqc_hq.h"
#include "xqc_hq_defs.h"
#include "xqc_hq_conn.h"
#include "xqc_hq_request.h"
#include "src/common/xqc_malloc.h"
#include <xquic/xqc_errno.h>


typedef struct xqc_hq_ctx_s {
    xqc_hq_callbacks_t  hq_cbs;
} xqc_hq_ctx_t;

xqc_hq_ctx_t*
xqc_hq_ctx_create(xqc_hq_callbacks_t *hq_cbs)
{
    xqc_hq_ctx_t *hq_ctx = NULL;

    hq_ctx = xqc_malloc(sizeof(xqc_hq_callbacks_t));
    if (hq_ctx) {
        hq_ctx->hq_cbs = *hq_cbs;
    }

    return hq_ctx;
}

xqc_int_t
xqc_hq_ctx_init(xqc_engine_t *engine, xqc_hq_callbacks_t *hq_cbs)
{
    if (engine == NULL || hq_cbs == NULL) {
        return -XQC_EPARAM;
    }

    xqc_hq_ctx_t *hq_ctx;
    xqc_int_t ret = XQC_OK;
    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs   = hq_conn_callbacks,
        .stream_cbs = hq_stream_callbacks
    };

    hq_ctx = xqc_hq_ctx_create(hq_cbs);
    if (hq_ctx == NULL) {
        ret = -XQC_EMALLOC;
        goto error;
    }

    /* register ALPN and Application-Layer-Protocol callbacks */
    if (xqc_engine_register_alpn(engine, XQC_ALPN_HQ_INTEROP, XQC_ALPN_HQ_INTEROP_LEN, &ap_cbs, hq_ctx) != XQC_OK) {
        xqc_free(hq_ctx);
        ret = -XQC_EFATAL;
        goto error;
    }

    hq_ctx = xqc_hq_ctx_create(hq_cbs);
    if (hq_ctx == NULL) {
        ret = -XQC_EMALLOC;
        goto error;
    }

    /* register ALPN and Application-Layer-Protocol callbacks */
    if (xqc_engine_register_alpn(engine, XQC_ALPN_HQ_29, XQC_ALPN_HQ_29_LEN, &ap_cbs, hq_ctx) != XQC_OK) {
        xqc_free(hq_ctx);
        ret = -XQC_EFATAL;
        goto error;
    }

    return ret;
error:
    xqc_hq_ctx_destroy(engine);
    return ret;
}


xqc_int_t
xqc_hq_ctx_destroy(xqc_engine_t *engine)
{
    xqc_hq_ctx_t *hq_ctx;

    hq_ctx = xqc_engine_get_alpn_ctx(engine, XQC_ALPN_HQ_29, XQC_ALPN_HQ_29_LEN);
    if (hq_ctx) {
        xqc_free(hq_ctx);
    }

    hq_ctx = xqc_engine_get_alpn_ctx(engine, XQC_ALPN_HQ_INTEROP, XQC_ALPN_HQ_INTEROP_LEN);
    if (hq_ctx) {
        xqc_free(hq_ctx);
    }

    xqc_engine_unregister_alpn(engine, XQC_ALPN_HQ_29, XQC_ALPN_HQ_29_LEN);
    xqc_engine_unregister_alpn(engine, XQC_ALPN_HQ_INTEROP, XQC_ALPN_HQ_INTEROP_LEN);
    return XQC_OK;
}

xqc_int_t
xqc_hq_ctx_get_callbacks(xqc_engine_t *engine, char *alpn, size_t alpn_len, xqc_hq_callbacks_t **hq_cbs)
{
    xqc_hq_ctx_t *hq_ctx;

    hq_ctx = xqc_engine_get_alpn_ctx(engine, XQC_ALPN_HQ_29, XQC_ALPN_HQ_29_LEN);

    if (hq_ctx == NULL) {
        return -XQC_EFATAL;
    }

    *hq_cbs = &hq_ctx->hq_cbs;
    return XQC_OK;
}