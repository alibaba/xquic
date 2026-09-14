/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_SESSION_H
#define XQC_WEBTRANSPORT_SESSION_H

#include <xquic/xqc_webtransport.h>
#include "src/common/xqc_list.h"

#define XQC_WT_CLOSE_REASON_MAX 1024
#define XQC_WT_CAPSULE_BUFFER_SIZE (XQC_WT_CLOSE_REASON_MAX + 32)

struct xqc_webtransport_session_s {
    uint64_t              sessionID;
    xqc_wt_conn_t        *wt_conn;
    xqc_h3_stream_t      *h3_stream;
    xqc_h3_request_t     *request;
    xqc_list_head_t       stream_list;
    xqc_list_head_t       conn_list;
    xqc_bool_t            open;
    xqc_bool_t            closed;
    xqc_bool_t            draining;
    xqc_bool_t            close_notified;
    uint32_t              close_error;
    char                  close_reason[XQC_WT_CLOSE_REASON_MAX + 1];
    unsigned char         send_buf[XQC_WT_CAPSULE_BUFFER_SIZE];
    size_t                send_len;
    size_t                send_offset;
    xqc_bool_t            send_fin;
    unsigned char         recv_header[16];
    size_t                recv_header_len;
    uint64_t              capsule_type;
    uint64_t              capsule_remaining;
    xqc_bool_t            capsule_body;
    unsigned char         recv_buf[XQC_WT_CAPSULE_BUFFER_SIZE];
    size_t                recv_len;
};

xqc_int_t xqc_wt_session_close(xqc_wt_session_t *session);
void xqc_wt_session_destroy(xqc_wt_session_t *session);
void xqc_wt_session_notify_closed(xqc_wt_session_t *session);
xqc_int_t xqc_wt_session_flush(xqc_wt_session_t *session);
xqc_int_t xqc_wt_session_recv_capsules(xqc_wt_session_t *session,
    const unsigned char *data, size_t len, xqc_bool_t fin);
xqc_bool_t xqc_wt_session_is_writable(xqc_wt_session_t *session);
const xqc_webtransport_stream_callbacks_t *
xqc_wt_session_get_stream_callbacks(xqc_wt_session_t *session);
void *xqc_wt_session_get_callback_user_data(xqc_wt_session_t *session);

#endif
