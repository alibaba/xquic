/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#ifndef XQC_H3_EXTENSION_H
#define XQC_H3_EXTENSION_H

#include <xquic/xqc_http3.h>

#define XQC_H3_EXTENSION_MAX_SETTINGS 16

typedef struct {
    uint64_t identifier;
    uint64_t value;
} xqc_h3_extension_setting_t;

/*
 * One optional protocol adapter per H3 context. H3 copies this table and
 * borrows ctx until ctx_destroy. Application user_data is never replaced.
 * Stream type is consumed by H3; raw_read receives only bytes after it.
 */
typedef struct {
    void (*ctx_destroy)(void *ctx);
    void *(*conn_create)(xqc_h3_conn_t *h3c, void *ctx);
    void (*conn_close)(xqc_h3_conn_t *h3c, void *conn_ctx);
    void (*handshake_finished)(xqc_h3_conn_t *h3c, void *conn_ctx);
    ssize_t (*local_settings)(xqc_h3_conn_t *h3c, void *conn_ctx,
        xqc_h3_extension_setting_t *settings, size_t capacity);
    xqc_int_t (*peer_setting)(xqc_h3_conn_t *h3c, void *conn_ctx,
        uint64_t identifier, uint64_t value);
    xqc_int_t (*peer_settings_complete)(xqc_h3_conn_t *h3c,
        void *conn_ctx);

    /* request_headers: 1 claims the request, 0 leaves it to ordinary H3. */
    xqc_int_t (*request_headers)(xqc_h3_request_t *request, void *conn_ctx,
        const xqc_http_headers_t *headers);
    xqc_int_t (*request_read)(xqc_h3_request_t *request,
        xqc_request_notify_flag_t flags, void *request_ctx);
    xqc_int_t (*request_write)(xqc_h3_request_t *request, void *request_ctx);
    void (*request_closing)(xqc_h3_request_t *request, xqc_int_t error,
        void *request_ctx);
    void (*request_close)(xqc_h3_request_t *request, void *request_ctx);

    xqc_bool_t (*raw_stream_type)(xqc_h3_conn_t *h3c, void *conn_ctx,
        uint64_t type, xqc_bool_t bidi);
    ssize_t (*raw_read)(xqc_h3_stream_t *stream, void *conn_ctx,
        const unsigned char *data, size_t data_len, uint8_t fin);
    xqc_int_t (*raw_write)(xqc_h3_stream_t *stream, void *stream_ctx);
    void (*raw_closing)(xqc_h3_stream_t *stream, xqc_int_t error,
        void *stream_ctx);
    void (*raw_close)(xqc_h3_stream_t *stream, void *stream_ctx);

    xqc_datagram_callbacks_t datagram_callbacks;
} xqc_h3_extension_ops_t;

/* Register before creating any connection. Existing H3 callbacks survive. */
xqc_int_t xqc_h3_extension_register(xqc_engine_t *engine,
    const xqc_h3_extension_ops_t *ops, void *ctx);

void *xqc_h3_extension_get_context(xqc_engine_t *engine);

/* Outgoing raw streams carry application-owned prefix bytes on send. */
xqc_h3_stream_t *xqc_h3_extension_stream_create(xqc_h3_conn_t *h3c,
    xqc_bool_t bidi, void *stream_ctx);

xqc_int_t xqc_h3_extension_stream_set_read_paused(xqc_h3_stream_t *stream,
    xqc_bool_t paused);

void xqc_h3_extension_stream_detach(xqc_h3_stream_t *stream);

#endif
