/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_SESSION_H
#define XQC_WEBTRANSPORT_SESSION_H

#include <xquic/xqc_webtransport.h>
#include "src/common/xqc_list.h"

/* RFC 9000 Section 16: two length bits and up to 62 value bits. */
#define XQC_WT_VARINT_MAX ((UINT64_C(1) << 62) - 1)
#define XQC_WT_VARINT_MAX_LEN 8
#define XQC_WT_VARINT_PREFIX_MASK 0x3f

/* Encoders return 0 on error; decoders return a negative error code. */
size_t xqc_wt_put_varint(uint64_t value, uint8_t *buf, size_t buf_len);
ssize_t xqc_wt_get_varint(const uint8_t *buf, size_t buf_len, uint64_t *value);

#define XQC_WT_CAPSULE_HEADER_MAX (2 * XQC_WT_VARINT_MAX_LEN)

#define XQC_WT_CLOSE_REASON_MAX 1024
#define XQC_WT_CAPSULE_BUFFER_SIZE (XQC_WT_CLOSE_REASON_MAX + 32)

xqc_bool_t xqc_wt_valid_utf8(const unsigned char *data, size_t len);

struct xqc_webtransport_session_s {
    uint64_t              session_id;
    xqc_wt_conn_t        *wt_conn;
    xqc_h3_stream_t      *h3_stream;
    xqc_h3_request_t     *request;
    xqc_list_head_t       stream_list;
    xqc_list_head_t       conn_list;
    xqc_bool_t            open;
    xqc_bool_t            closed;
    xqc_bool_t            draining;
    xqc_bool_t            close_notified;
    xqc_bool_t            client;
    xqc_bool_t            request_sent;
    xqc_bool_t            peer_closed;
    xqc_bool_t            flow_control;
    uint64_t              send_stream_limit[2];
    uint64_t              recv_stream_limit[2];
    uint64_t              recv_stream_target[2];
    uint64_t              sent_streams[2];
    uint64_t              recv_streams[2];
    uint64_t              send_data_limit;
    uint64_t              recv_data_limit;
    uint64_t              sent_data;
    uint64_t              recv_data;
    unsigned              response_status;
    /* Authority owns one allocation; path and origin point inside it. */
    char                 *client_authority;
    char                 *client_path;
    char                 *client_origin;
    char                 *client_protocols;
    char                 *application_protocol;
    uint32_t              close_error;
    char                  close_reason[XQC_WT_CLOSE_REASON_MAX + 1];
    unsigned char         send_buf[XQC_WT_CAPSULE_BUFFER_SIZE];
    size_t                send_len;
    size_t                send_offset;
    xqc_bool_t            send_fin;
    unsigned char         recv_header[XQC_WT_CAPSULE_HEADER_MAX];
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
void xqc_wt_session_stream_closed(xqc_wt_session_t *session, xqc_bool_t bidi);
xqc_bool_t xqc_wt_session_prepare_flow_credit(xqc_wt_session_t *session);
xqc_int_t xqc_wt_session_recv_capsules(xqc_wt_session_t *session,
    const unsigned char *data, size_t len, xqc_bool_t fin);
void xqc_wt_session_init_flow_control(xqc_wt_session_t *session);
void xqc_wt_session_fail_flow_control(xqc_wt_session_t *session);
xqc_bool_t xqc_wt_session_is_writable(xqc_wt_session_t *session);
void xqc_wt_session_notify_draining(xqc_wt_session_t *session);
const xqc_webtransport_stream_callbacks_t *
xqc_wt_session_get_stream_callbacks(xqc_wt_session_t *session);
void *xqc_wt_session_get_callback_user_data(xqc_wt_session_t *session);

xqc_h3_stream_t *xqc_wt_session_get_h3_stream(xqc_wt_session_t *session);

xqc_wt_session_t *xqc_wt_session_init(uint64_t session_id,
    xqc_wt_conn_t *conn, xqc_h3_stream_t *stream);

#endif
