/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_CTX_H
#define XQC_WEBTRANSPORT_CTX_H

#include <xquic/xqc_webtransport.h>

typedef struct xqc_wt_ctx_s {
    xqc_webtransport_stream_callbacks_t   stream_cbs;
    xqc_webtransport_session_callbacks_t  session_cbs;
    xqc_webtransport_dgram_callbacks_t    dgram_cbs;
    xqc_webtransport_conn_settings_t      settings;
    uint64_t                             pending_window;
    size_t                               pending_count_max;
    size_t                               pending_bytes_max;
    xqc_bool_t                           started;
} xqc_wt_ctx_t;

#endif
