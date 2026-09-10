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
 * flat context data. Each connection owns its callback and context state;
 * it must not retain pointers into the H3 context. Application user_data
 * is never replaced.
 * stream_read receives wire bytes, including the initial type. The adapter
 * calls xqc_h3_stream_process_in for ordinary HTTP input. Stream state is
 * opaque to H3; stream_close must release it and clear extension_data.
 */
typedef struct {
    void *(*conn_create)(xqc_h3_conn_t *h3c, void *ctx);
    void (*conn_close)(xqc_h3_conn_t *h3c, void *conn_ctx);
    ssize_t (*local_settings)(xqc_h3_conn_t *h3c, void *conn_ctx,
        xqc_h3_extension_setting_t *settings, size_t capacity);
    xqc_int_t (*peer_setting)(xqc_h3_conn_t *h3c, void *conn_ctx,
        uint64_t identifier, uint64_t value);
    xqc_int_t (*peer_settings_complete)(xqc_h3_conn_t *h3c,
        void *conn_ctx);

    xqc_int_t (*stream_read)(xqc_h3_stream_t *stream, void *conn_ctx,
        unsigned char *data, size_t data_len, uint8_t fin);
    /* -XQC_EAGAIN suspends reading until the adapter makes it ready again. */
    xqc_int_t (*stream_prepare_read)(xqc_h3_stream_t *stream,
        void *stream_ctx);
    xqc_int_t (*stream_write)(xqc_h3_stream_t *stream, void *stream_ctx);
    void (*stream_closing)(xqc_h3_stream_t *stream, xqc_int_t error,
        void *stream_ctx);
    void (*stream_close)(xqc_h3_stream_t *stream, void *stream_ctx);

    xqc_datagram_callbacks_t datagram_callbacks;
} xqc_h3_extension_ops_t;

/* Register before creating any connection. Existing H3 callbacks survive. */
xqc_int_t xqc_h3_extension_register(xqc_engine_t *engine,
    const xqc_h3_extension_ops_t *ops, const void *ctx, size_t ctx_size);

void *xqc_h3_extension_get_context(xqc_engine_t *engine);

#endif
