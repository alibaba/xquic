/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_CTX_H
#define XQC_WEBTRANSPORT_CTX_H

#include <xquic/xqc_webtransport.h>

/* Implementation defaults and resource policy, not protocol limits. */
#define XQC_WT_DEFAULT_MAX_SESSIONS 1
#define XQC_WT_DEFAULT_MAX_STREAMS 128
#define XQC_WT_DEFAULT_RECV_WINDOW (1024 * 1024)
#define XQC_WT_MAX_SESSIONS 1024

/* RFC 9114 Section 6.2: control and both QPACK streams. */
#define XQC_WT_MIN_UNI_STREAMS 3

/* RFC 9221 Section 3 recommends accepting any packet-sized DATAGRAM. */
#define XQC_WT_MAX_DATAGRAM_FRAME_SIZE 65535

/* Draft-07 Section 3.1: Datagram, max sessions and server CONNECT. */
#define XQC_WT_ENABLE_SETTINGS_COUNT 3

typedef struct xqc_wt_ctx_s {
    xqc_webtransport_stream_callbacks_t   stream_cbs;
    xqc_webtransport_session_callbacks_t  session_cbs;
    xqc_webtransport_dgram_callbacks_t    dgram_cbs;
    xqc_webtransport_conn_settings_t      settings;
    uint64_t                              pending_window;
    size_t                                pending_count_max;
    size_t                                pending_bytes_max;
    xqc_h3_conn_callbacks_t               app_conn_callbacks;
    xqc_bool_t                            started;
} xqc_wt_ctx_t;

xqc_wt_ctx_t *xqc_wt_ctx_get(xqc_engine_t *engine);

#endif
