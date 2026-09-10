/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_REQUEST_ADAPTER_H
#define XQC_WEBTRANSPORT_REQUEST_ADAPTER_H

#include <xquic/xqc_webtransport.h>

void xqc_wt_request_adapter_init(xqc_wt_conn_t *conn);
void xqc_wt_request_adapter_detach(xqc_h3_request_t *request);
xqc_int_t xqc_wt_request_read(xqc_h3_request_t *request,
    xqc_request_notify_flag_t flags, void *data);

#endif
