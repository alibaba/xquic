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
    xqc_webtransport_stream_callbacks_t  *stream_cbs;
    xqc_webtransport_session_callbacks_t *session_cbs;
    xqc_webtransport_dgram_callbacks_t   *dgram_cbs;
} xqc_wt_ctx_t;


#ifdef __cplusplus
}
#endif

#endif
