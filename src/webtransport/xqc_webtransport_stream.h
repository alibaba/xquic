/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_STREAM_H
#define XQC_WEBTRANSPORT_STREAM_H

#include <xquic/xqc_webtransport.h>
#include "src/common/xqc_list.h"

typedef struct {
    ssize_t (*send)(xqc_h3_stream_t *stream, const unsigned char *data,
        size_t len, uint8_t fin);
    xqc_int_t (*reset)(xqc_h3_stream_t *stream, uint64_t error);
    xqc_int_t (*stop)(xqc_h3_stream_t *stream, uint64_t error);
    xqc_int_t (*pause)(xqc_h3_stream_t *stream, xqc_bool_t paused);
    void (*detach)(xqc_h3_stream_t *stream);
} xqc_wt_stream_io_ops_t;

typedef struct xqc_wt_stream_base_s {
    xqc_list_head_t              list;
    xqc_wt_session_t           *session;
    xqc_h3_stream_t            *h3_stream;
    const xqc_wt_stream_io_ops_t *io;
    xqc_stream_id_t             id;
    uint64_t                    session_id;
    void                       *user_data;
    unsigned                    callback_depth;
    xqc_bool_t                  bidi;
    xqc_bool_t                  can_send;
    xqc_bool_t                  can_recv;
    xqc_bool_t                  send_fin;
    xqc_bool_t                  recv_fin;
    xqc_bool_t                  send_reset;
    xqc_bool_t                  recv_reset;
    xqc_bool_t                  read_paused;
    xqc_bool_t                  closed;
    xqc_bool_t                  listed;
    xqc_bool_t                  stop_sending;
    xqc_bool_t                  session_id_complete;
    unsigned char               prefix[16];
    size_t                      prefix_len;
    size_t                      prefix_sent;
    unsigned char               session_prefix[8];
    size_t                      session_prefix_len;
    size_t                      session_prefix_need;
    wt_stream_close_func_pt      legacy_close;
    wt_stream_close_func_pt      legacy_recv_close;
} xqc_wt_stream_base_t;

struct xqc_wt_unistream_s {
    xqc_wt_stream_base_t base;
};

struct xqc_wt_bidistream_s {
    xqc_wt_stream_base_t base;
};

xqc_wt_stream_base_t *xqc_wt_stream_bind(xqc_wt_session_t *session,
    xqc_h3_stream_t *h3_stream, xqc_bool_t bidi, xqc_bool_t outgoing,
    void *user_data);

xqc_int_t xqc_wt_stream_notify_create(xqc_wt_stream_base_t *stream);
ssize_t xqc_wt_stream_notify_read(xqc_wt_stream_base_t *stream,
    const unsigned char *data, size_t len, uint8_t fin);
void xqc_wt_stream_notify_closing(xqc_wt_stream_base_t *stream,
    xqc_bool_t stop_sending);
void xqc_wt_stream_notify_close(xqc_wt_stream_base_t *stream);

ssize_t xqc_wt_stream_read(xqc_h3_stream_t *stream, void *conn_ctx,
    const unsigned char *data, size_t len, uint8_t fin);
xqc_int_t xqc_wt_stream_write(xqc_h3_stream_t *stream, void *stream_ctx);
void xqc_wt_stream_closing(xqc_h3_stream_t *stream, xqc_int_t error,
    void *stream_ctx);
void xqc_wt_stream_close(xqc_h3_stream_t *stream, void *stream_ctx);
void xqc_wt_session_close_streams(xqc_wt_session_t *session);
void xqc_wt_conn_resume_streams(xqc_wt_conn_t *conn);
void xqc_wt_conn_close_pending_streams(xqc_wt_conn_t *conn);

xqc_wt_bidistream_t *xqc_wt_create_bidistream(xqc_h3_stream_t *stream,
    xqc_wt_session_t *session, wt_stream_close_func_pt send_close_func,
    wt_stream_close_func_pt recv_close_func, xqc_bool_t passive_created);
xqc_h3_stream_t *xqc_wt_bidistream_get_h3_stream(
    xqc_wt_bidistream_t *stream);
xqc_h3_stream_t *xqc_wt_unistream_get_h3_stream(xqc_wt_unistream_t *stream);
xqc_int_t xqc_wt_bidistream_destroy(xqc_wt_bidistream_t *stream);
uint64_t xqc_wt_unistream_getid(xqc_wt_unistream_t *stream);
void xqc_wt_unistream_set_sessionID(xqc_wt_unistream_t *stream,
    uint64_t session_id);

#endif
