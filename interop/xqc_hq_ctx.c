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


xqc_hq_ctx_t *hq_ctx = NULL;


xqc_int_t
xqc_hq_ctx_init(xqc_engine_t *engine, xqc_hq_callbacks_t *hq_cbs)
{
    if (engine == NULL || hq_cbs == NULL) {
        return -XQC_EPARAM;
    }

    if (hq_ctx == NULL) {
        hq_ctx = xqc_malloc(sizeof(xqc_hq_callbacks_t));
        if (NULL == hq_ctx) {
            return -XQC_EMALLOC;
        }
    }

    hq_ctx->hq_cbs = *hq_cbs;

    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs   = hq_conn_callbacks,
        .stream_cbs = hq_stream_callbacks
    };

    /* register ALPN and Application-Layer-Protocol callbacks */
    if (xqc_engine_register_alpn(engine, XQC_ALPN_HQ_INTEROP, XQC_ALPN_HQ_INTEROP_LEN, &ap_cbs) != XQC_OK
        || xqc_engine_register_alpn(engine, XQC_ALPN_HQ_29, XQC_ALPN_HQ_29_LEN, &ap_cbs) != XQC_OK)
    {
        xqc_hq_ctx_destroy(engine);
        return -XQC_EFATAL;
    }

    return XQC_OK;
}


xqc_int_t
xqc_hq_ctx_destroy(xqc_engine_t *engine)
{
    xqc_engine_unregister_alpn(engine, XQC_ALPN_HQ_29, XQC_ALPN_HQ_29_LEN);
    xqc_engine_unregister_alpn(engine, XQC_ALPN_HQ_INTEROP, XQC_ALPN_HQ_INTEROP_LEN);

    if (hq_ctx) {
        xqc_free(hq_ctx);
        hq_ctx = NULL;
    }

    return XQC_OK;
}

xqc_int_t
xqc_hq_ctx_get_conn_callbacks(xqc_hq_conn_callbacks_t **hqc_cbs)
{
    if (NULL == hq_ctx || NULL == hqc_cbs) {
        return -XQC_EFATAL;
    }

    *hqc_cbs = &hq_ctx->hq_cbs.hqc_cbs;
    return XQC_OK;
}


xqc_int_t
xqc_hq_ctx_get_request_callbacks(xqc_hq_request_callbacks_t **hqr_cbs)
{
    if (NULL == hq_ctx || NULL == hqr_cbs) {
        return -XQC_EFATAL;
    }

    *hqr_cbs = &hq_ctx->hq_cbs.hqr_cbs;
    return XQC_OK;
}
