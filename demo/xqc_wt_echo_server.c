/* Copyright (c) 2026, Alibaba Group Holding Limited. */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xquic/xqc_webtransport.h>
#include "xqc_wt_echo_server.h"

#define XQC_DEMO_WT_PENDING_MAX (64 * 1024)

typedef struct xqc_demo_wt_stream_s xqc_demo_wt_stream_t;

struct xqc_demo_wt_stream_s {
    xqc_demo_wt_stream_t *next;
    xqc_wt_session_t    *session;
    xqc_stream_id_t      id;
    unsigned char      *pending;
    size_t              pending_len;
    int                 fin;
    int                 send_closed;
};

static xqc_demo_wt_stream_t *xqc_demo_wt_streams;
static void (*xqc_demo_wt_schedule_send)(void *user_data);
static void *xqc_demo_wt_schedule_data;

static int xqc_demo_wt_header_equal(const xqc_http_header_t *header,
    const char *name, const char *value);
static int xqc_demo_wt_accept(xqc_http_headers_t *headers,
    xqc_http_headers_t *response);
static int xqc_demo_wt_session_create(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data);
static int xqc_demo_wt_session_close(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data);
static void xqc_demo_wt_handshake(xqc_h3_conn_t *h3_conn, void *user_data);
static void xqc_demo_wt_drain(xqc_wt_session_t *session, void *user_data);
static xqc_demo_wt_stream_t *xqc_demo_wt_find(xqc_wt_session_t *session,
    xqc_stream_id_t id);
static xqc_int_t xqc_demo_wt_bidi_flush(xqc_wt_bidistream_t *stream,
    xqc_demo_wt_stream_t *ctx);
static xqc_int_t xqc_demo_wt_bidi_create(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data);
static xqc_int_t xqc_demo_wt_bidi_read(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t len, void *user_data);
static xqc_int_t xqc_demo_wt_bidi_write(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data);
static xqc_int_t xqc_demo_wt_bidi_closing(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data);
static xqc_int_t xqc_demo_wt_bidi_close(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data);
static xqc_int_t xqc_demo_wt_uni_notify(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *user_data);
static xqc_int_t xqc_demo_wt_uni_read(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t len, void *user_data);
static void xqc_demo_wt_dgram_read(xqc_wt_session_t *session,
    const void *data, size_t len, void *user_data, uint64_t recv_time);
static void xqc_demo_wt_dgram_write(xqc_wt_session_t *session,
    void *user_data);
static void xqc_demo_wt_dgram_acked(xqc_wt_session_t *session,
    uint64_t id, void *user_data);
static int xqc_demo_wt_dgram_lost(xqc_wt_session_t *session,
    uint64_t id, void *user_data);
static void xqc_demo_wt_dgram_mss(xqc_wt_session_t *session,
    size_t mss, void *user_data);

static int
xqc_demo_wt_header_equal(const xqc_http_header_t *header,
    const char *name, const char *value)
{
    return header->name.iov_len == strlen(name)
        && header->value.iov_len == strlen(value)
        && memcmp(header->name.iov_base, name, strlen(name)) == 0
        && memcmp(header->value.iov_base, value, strlen(value)) == 0;
}

static int
xqc_demo_wt_accept(xqc_http_headers_t *headers,
    xqc_http_headers_t *response)
{
    size_t i;
    int path = 0;
    int origin = 0;
    int origins = 0;

    for (i = 0; i < headers->count; i++) {
        xqc_http_header_t *header = &headers->headers[i];
        path += xqc_demo_wt_header_equal(header, ":path", "/wt");
        if (header->name.iov_len == 6
            && memcmp(header->name.iov_base, "origin", 6) == 0)
        {
            origins++;
        }
        origin += xqc_demo_wt_header_equal(header, "origin",
                                          "http://127.0.0.1:8080");
        origin += xqc_demo_wt_header_equal(header, "origin",
                                          "http://localhost:8080");
    }

    if (path != 1 || origin != 1 || origins != 1) {
        printf("WT reject: path=%d allowed_origin=%d origin_count=%d\n",
               path, origin, origins);
        return 0;
    }
    return 1;
}

static int
xqc_demo_wt_session_create(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data)
{
    printf("WT ready: session=%p h3_user_data=%p\n", (void *) session,
           xqc_h3_conn_get_user_data(xqc_wt_session_get_h3_conn(session)));
    return XQC_OK;
}

static int
xqc_demo_wt_session_close(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data)
{
    xqc_demo_wt_stream_t **link = &xqc_demo_wt_streams;

    printf("WT closed: code=%" PRIu32 "\n",
           xqc_wt_session_get_close_error_code(session));
    while (*link != NULL) {
        xqc_demo_wt_stream_t *ctx = *link;
        if (ctx->session == session) {
            *link = ctx->next;
            free(ctx->pending);
            free(ctx);

        } else {
            link = &ctx->next;
        }
    }
    return XQC_OK;
}

static void
xqc_demo_wt_handshake(xqc_h3_conn_t *h3_conn, void *user_data)
{
    printf("WT handshake complete\n");
}

static void
xqc_demo_wt_drain(xqc_wt_session_t *session, void *user_data)
{
    printf("WT draining\n");
}

static xqc_demo_wt_stream_t *
xqc_demo_wt_find(xqc_wt_session_t *session, xqc_stream_id_t id)
{
    xqc_demo_wt_stream_t *ctx;

    for (ctx = xqc_demo_wt_streams; ctx != NULL; ctx = ctx->next) {
        if (ctx->session == session && ctx->id == id) {
            return ctx;
        }
    }
    return NULL;
}

static xqc_int_t
xqc_demo_wt_bidi_flush(xqc_wt_bidistream_t *stream,
    xqc_demo_wt_stream_t *ctx)
{
    if (ctx->send_closed || (ctx->pending_len == 0 && !ctx->fin)) {
        return XQC_OK;
    }

    xqc_int_t sent = xqc_wt_bidistream_send(stream, ctx->pending,
                                           ctx->pending_len, ctx->fin);
    xqc_demo_wt_schedule_send(xqc_demo_wt_schedule_data);
    if (sent == -XQC_EAGAIN || sent == -XQC_ECONN_BLOCKED
        || sent == -XQC_ESTREAM_BLOCKED)
    {
        return XQC_OK;
    }
    if (sent < 0 || (size_t) sent > ctx->pending_len) {
        return XQC_ERROR;
    }
    ctx->pending_len -= sent;
    if (ctx->pending_len > 0) {
        memmove(ctx->pending, ctx->pending + sent, ctx->pending_len);

    } else if (ctx->fin) {
        ctx->send_closed = 1;
    }
    return XQC_OK;
}

static xqc_int_t
xqc_demo_wt_bidi_create(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    xqc_demo_wt_stream_t *ctx = calloc(1, sizeof(*ctx));

    if (ctx == NULL) {
        return XQC_ERROR;
    }
    ctx->pending = malloc(XQC_DEMO_WT_PENDING_MAX);
    if (ctx->pending == NULL) {
        free(ctx);
        return XQC_ERROR;
    }
    ctx->session = session;
    ctx->id = xqc_wt_bidistream_id(stream);
    ctx->next = xqc_demo_wt_streams;
    xqc_demo_wt_streams = ctx;
    return XQC_OK;
}

static xqc_int_t
xqc_demo_wt_bidi_read(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t len, void *user_data)
{
    xqc_demo_wt_stream_t *ctx = xqc_demo_wt_find(session,
                                               xqc_wt_bidistream_id(stream));

    if (ctx == NULL) {
        return XQC_ERROR;
    }
    if (ctx->send_closed) {
        return XQC_OK;
    }
    if (len > XQC_DEMO_WT_PENDING_MAX - ctx->pending_len) {
        xqc_wt_bidistream_stop_sending(stream, 1);
        xqc_wt_bidistream_reset(stream, 1);
        xqc_demo_wt_schedule_send(xqc_demo_wt_schedule_data);
        return XQC_ERROR;
    }
    if (len > 0) {
        memcpy(ctx->pending + ctx->pending_len, data, len);
        ctx->pending_len += len;
    }
    ctx->fin = xqc_wt_bidistream_get_recv_fin(stream);
    printf("WT bidi echo: id=%" PRIu64 " bytes=%zu fin=%d\n",
           (uint64_t) ctx->id, len, ctx->fin);
    return xqc_demo_wt_bidi_flush(stream, ctx);
}

static xqc_int_t
xqc_demo_wt_bidi_write(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    xqc_demo_wt_stream_t *ctx = xqc_demo_wt_find(session,
                                               xqc_wt_bidistream_id(stream));
    return ctx ? xqc_demo_wt_bidi_flush(stream, ctx) : XQC_OK;
}

static xqc_int_t
xqc_demo_wt_bidi_closing(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    xqc_demo_wt_stream_t *ctx = xqc_demo_wt_find(session,
                                               xqc_wt_bidistream_id(stream));

    if (ctx && xqc_wt_bidistream_closing_is_stop_sending(stream)) {
        ctx->pending_len = 0;
        ctx->send_closed = 1;
    }
    return XQC_OK;
}

static xqc_int_t
xqc_demo_wt_bidi_close(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    xqc_demo_wt_stream_t **link = &xqc_demo_wt_streams;
    xqc_stream_id_t id = xqc_wt_bidistream_id(stream);

    while (*link != NULL) {
        xqc_demo_wt_stream_t *ctx = *link;
        if (ctx->session == session && ctx->id == id) {
            *link = ctx->next;
            free(ctx->pending);
            free(ctx);
            break;
        }
        link = &ctx->next;
    }
    return XQC_OK;
}

static xqc_int_t
xqc_demo_wt_uni_notify(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    return XQC_OK;
}

static xqc_int_t
xqc_demo_wt_uni_read(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t len, void *user_data)
{
    printf("WT uni received: id=%" PRIu64 " bytes=%zu\n",
           (uint64_t) xqc_wt_unistream_id(stream), len);
    return XQC_OK;
}

static void
xqc_demo_wt_dgram_read(xqc_wt_session_t *session,
    const void *data, size_t len, void *user_data, uint64_t recv_time)
{
    uint64_t id;
    xqc_int_t ret = xqc_wt_session_datagram_send(session, data, len, &id);

    printf("WT datagram echo: bytes=%zu result=%d\n", len, ret);
    xqc_demo_wt_schedule_send(xqc_demo_wt_schedule_data);
}

static void
xqc_demo_wt_dgram_write(xqc_wt_session_t *session, void *user_data)
{
}

static void
xqc_demo_wt_dgram_acked(xqc_wt_session_t *session,
    uint64_t id, void *user_data)
{
}

static int
xqc_demo_wt_dgram_lost(xqc_wt_session_t *session,
    uint64_t id, void *user_data)
{
    return 0;
}

static void
xqc_demo_wt_dgram_mss(xqc_wt_session_t *session,
    size_t mss, void *user_data)
{
    printf("WT datagram MSS: %zu\n", mss);
}

xqc_int_t
xqc_demo_wt_init(xqc_engine_t *engine,
    void (*schedule_send)(void *user_data), void *user_data)
{
    xqc_webtransport_dgram_callbacks_t dgram_cbs = {
        .dgram_read_notify = xqc_demo_wt_dgram_read,
        .dgram_write_notify = xqc_demo_wt_dgram_write,
        .dgram_acked_notify = xqc_demo_wt_dgram_acked,
        .dgram_lost_notify = xqc_demo_wt_dgram_lost,
        .dgram_mss_updated_notify = xqc_demo_wt_dgram_mss,
    };
    xqc_webtransport_session_callbacks_t session_cbs = {
        .webtransport_will_create_session_notify = xqc_demo_wt_accept,
        .webtransport_session_create_notify = xqc_demo_wt_session_create,
        .webtransport_session_close_notify = xqc_demo_wt_session_close,
        .webtransport_conn_handshake_finished_notify = xqc_demo_wt_handshake,
        .webtransport_session_drain_notify = xqc_demo_wt_drain,
    };
    xqc_webtransport_stream_callbacks_t stream_cbs = {
        .wt_bidistream_create_notify = xqc_demo_wt_bidi_create,
        .wt_bidistream_read_notify = xqc_demo_wt_bidi_read,
        .wt_bidistream_write_notify = xqc_demo_wt_bidi_write,
        .wt_bidistream_closing_notify = xqc_demo_wt_bidi_closing,
        .wt_bidistream_close_notify = xqc_demo_wt_bidi_close,
        .wt_unistream_create_notify = xqc_demo_wt_uni_notify,
        .wt_unistream_read_notify = xqc_demo_wt_uni_read,
        .wt_unistream_write_notify = xqc_demo_wt_uni_notify,
        .wt_unistream_closing_notify = xqc_demo_wt_uni_notify,
        .wt_unistream_close_notify = xqc_demo_wt_uni_notify,
    };
    xqc_webtransport_conn_settings_t settings = {
        .max_sessions_count = 4,
        .draft_version = XQC_WEBTRANSPORT_DRAFT_VERSION_7,
        .max_bidi_streams = 16,
        .max_uni_streams = 16,
        .init_recv_window = 1024 * 1024,
        .enable_datagram = 1,
    };

    xqc_int_t ret = xqc_wt_ctx_init(engine, &dgram_cbs, &session_cbs,
                                   &stream_cbs);
    if (ret != XQC_OK) {
        return ret;
    }
    xqc_demo_wt_schedule_send = schedule_send;
    xqc_demo_wt_schedule_data = user_data;
    return xqc_wt_engine_set_default_settings(engine, &settings);
}
