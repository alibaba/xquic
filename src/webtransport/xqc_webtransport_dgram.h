/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_DGRAM_H
#define XQC_WEBTRANSPORT_DGRAM_H
#include <xquic/xqc_webtransport.h>

void xqc_wt_dgram_callbacks(xqc_datagram_callbacks_t *callbacks);
void xqc_wt_dgram_resume(xqc_wt_session_t *session);
void xqc_wt_dgram_clear(xqc_wt_conn_t *conn);
#endif
