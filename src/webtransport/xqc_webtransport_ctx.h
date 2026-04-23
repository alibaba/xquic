/**
 * xqc_webtransport_ctx.h
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_CTX_H
#define XQC_WEBTRANSPORT_CTX_H

#include "src/common/utils/var_buf/xqc_var_buf.h"
#include "src/http3/xqc_h3_defs.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/transport/xqc_conn.h"
#include <xquic/xqc_http3.h>
#include <xquic/xqc_webtransport.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xqc_wt_ctx_s {
    xqc_webtransport_stream_callbacks_t   stream_cbs;   /* value-copied from caller */
    xqc_webtransport_session_callbacks_t  session_cbs;
    xqc_webtransport_dgram_callbacks_t    dgram_cbs;
    uint64_t                              max_sessions;  /* 0 means default (1) */
} xqc_wt_ctx_t;

/**
 * @brief Get wt_ctx from engine via alpn ctx.
 * Falls back through: wt_conn->wt_ctx → engine alpn ext_ctx.
 */
xqc_wt_ctx_t *xqc_wt_ctx_get_by_engine(xqc_engine_t *engine);

/**
 * @brief WebTransport uni stream hooks called from H3 layer.
 * Declared here so xqc_h3_stream.c can include this header
 * instead of using bare extern declarations.
 */
void xqc_wt_h3_uni_stream_created(xqc_h3_conn_t *h3c,
    xqc_h3_stream_t *h3s, int *ret);
void xqc_wt_h3_uni_stream_recv(xqc_h3_conn_t *h3c,
    xqc_h3_stream_t *h3s, uint8_t *data, size_t size, int *ret);

#ifdef __cplusplus
}
#endif

#endif
