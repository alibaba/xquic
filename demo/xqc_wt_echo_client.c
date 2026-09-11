/* Copyright (c) 2026, Alibaba Group Holding Limited. */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "xqc_wt_echo_client.h"

static unsigned char xqc_demo_wt_payload[] = "xquic WebTransport\0echo";
static const unsigned char xqc_demo_wt_datagram[] = "xquic datagram";

typedef struct {
    xqc_engine_t       *engine;
    xqc_wt_session_t    *session;
    xqc_wt_bidistream_t *stream;
    size_t              sent;
    size_t              received;
    int                 ready;
    int                 fin_sent;
    int                 fin_received;
    int                 datagram_sent;
    int                 datagram_received;
    int                 close_sent;
    int                 session_closed;
    int                 failed;
    int                 stopped;
    int                 result;
    void              (*schedule_send)(void *user_data);
    void              (*finished)(void *user_data);
    void               *user_data;
} xqc_demo_wt_client_t;

/* The demo runs one connection and one WebTransport session. */
static xqc_demo_wt_client_t xqc_demo_wt_client;

static void xqc_demo_wt_client_fail(const char *operation, int error);
static int xqc_demo_wt_client_blocked(int error);
static void xqc_demo_wt_client_flush(void);
static void xqc_demo_wt_client_maybe_close(void);
static int xqc_demo_wt_client_ready(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data);
static int xqc_demo_wt_client_closed(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data);
static xqc_int_t xqc_demo_wt_client_stream_notify(
    xqc_wt_bidistream_t *stream, xqc_wt_session_t *session, void *user_data);
static xqc_int_t xqc_demo_wt_client_stream_write(
    xqc_wt_bidistream_t *stream, xqc_wt_session_t *session, void *user_data);
static xqc_int_t xqc_demo_wt_client_stream_read(
    xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *data, size_t len, void *user_data);
static void xqc_demo_wt_client_datagram_read(xqc_wt_session_t *session,
    const void *data, size_t len, void *user_data, uint64_t recv_time);
static void xqc_demo_wt_client_datagram_write(xqc_wt_session_t *session,
    void *user_data);

static void
xqc_demo_wt_client_fail(const char *operation, int error)
{
    xqc_demo_wt_client_t *ctx = &xqc_demo_wt_client;

    if (!ctx->failed) {
        printf("WT FAIL: %s error=%d\n", operation, error);
        ctx->failed = 1;
        ctx->finished(ctx->user_data);
    }
}

static int
xqc_demo_wt_client_blocked(int error)
{
    return error == -XQC_EAGAIN || error == -XQC_ECONN_BLOCKED
        || error == -XQC_ESTREAM_BLOCKED;
}

static void
xqc_demo_wt_client_flush(void)
{
    xqc_demo_wt_client_t *ctx = &xqc_demo_wt_client;
    xqc_int_t ret;
    uint64_t id;

    if (!ctx->ready || ctx->failed || ctx->close_sent) {
        return;
    }
    if (ctx->stream && !ctx->fin_sent) {
        ret = xqc_wt_bidistream_send(ctx->stream,
            xqc_demo_wt_payload + ctx->sent,
            sizeof(xqc_demo_wt_payload) - ctx->sent, 1);
        if (ret >= 0) {
            ctx->sent += ret;
            ctx->fin_sent = ctx->sent == sizeof(xqc_demo_wt_payload);

        } else if (!xqc_demo_wt_client_blocked(ret)) {
            xqc_demo_wt_client_fail("stream send", ret);
            return;
        }
    }
    if (!ctx->datagram_sent) {
        ret = xqc_wt_session_datagram_send(ctx->session,
            xqc_demo_wt_datagram, sizeof(xqc_demo_wt_datagram), &id);
        if (ret == XQC_OK) {
            ctx->datagram_sent = 1;

        } else if (!xqc_demo_wt_client_blocked(ret)) {
            xqc_demo_wt_client_fail("datagram send", ret);
            return;
        }
    }
    ctx->schedule_send(ctx->user_data);
}

static void
xqc_demo_wt_client_maybe_close(void)
{
    xqc_demo_wt_client_t *ctx = &xqc_demo_wt_client;
    xqc_int_t ret;

    if (ctx->failed || ctx->close_sent || !ctx->fin_received
        || !ctx->datagram_received)
    {
        return;
    }
    ctx->close_sent = 1;
    ret = xqc_wt_session_close_with_error(ctx->session, 0, "echo complete", 13);
    if (ret != XQC_OK) {
        xqc_demo_wt_client_fail("session close", ret);
        return;
    }
    printf("WT close sent\n");
    ctx->schedule_send(ctx->user_data);
}

static int
xqc_demo_wt_client_ready(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data)
{
    xqc_demo_wt_client_t *ctx = &xqc_demo_wt_client;
    xqc_wt_bidistream_t *reset_stream;
    int err;

    ctx->session = session;
    ctx->ready = 1;
    printf("WT ready: draft=%d status=%u\n",
           xqc_wt_session_get_draft_version(session)
               == XQC_WEBTRANSPORT_DRAFT_VERSION_16 ? 16 : 7,
           xqc_wt_session_get_response_status(session));

    reset_stream = xqc_wt_session_create_bidi_stream(session, NULL, &err);
    if (!reset_stream) {
        xqc_demo_wt_client_fail("reset stream create", err);
        return XQC_ERROR;
    }
    err = xqc_wt_bidistream_reset(reset_stream, 42);
    if (err != XQC_OK) {
        xqc_demo_wt_client_fail("stream reset", err);
        return XQC_ERROR;
    }
    printf("WT reset sent: id=%" PRIu64 " code=42\n",
           (uint64_t) xqc_wt_bidistream_id(reset_stream));

    ctx->stream = xqc_wt_session_create_bidi_stream(session, NULL, &err);
    if (!ctx->stream) {
        xqc_demo_wt_client_fail("echo stream create", err);
        return XQC_ERROR;
    }
    xqc_demo_wt_client_flush();
    return XQC_OK;
}

static int
xqc_demo_wt_client_closed(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data)
{
    xqc_demo_wt_client_t *ctx = &xqc_demo_wt_client;

    if (ctx->stopped) {
        return XQC_OK;
    }
    ctx->session_closed = 1;
    printf("WT closed: ready=%d status=%u code=%" PRIu32 "\n", ctx->ready,
           xqc_wt_session_get_response_status(session),
           xqc_wt_session_get_close_error_code(session));
    if (!ctx->failed && ctx->ready && ctx->close_sent
        && ctx->fin_received && ctx->datagram_received
        && xqc_wt_session_get_close_error_code(session) == 0)
    {
        ctx->result = 0;
    }
    ctx->session = NULL;
    ctx->stream = NULL;
    if (!ctx->failed) {
        xqc_int_t ret = xqc_h3_conn_close(ctx->engine, cid);

        if (ret != XQC_OK) {
            ctx->result = 1;
            xqc_demo_wt_client_fail("connection close", ret);
        }
    }
    if (ctx->result == 0) {
        printf("WT PASS: bidi exact echo + FIN, datagram, close\n");
    }
    ctx->finished(ctx->user_data);
    return XQC_OK;
}

static xqc_int_t
xqc_demo_wt_client_stream_notify(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    return XQC_OK;
}

static xqc_int_t
xqc_demo_wt_client_stream_write(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    if (stream == xqc_demo_wt_client.stream) {
        xqc_demo_wt_client_flush();
    }
    return XQC_OK;
}

static xqc_int_t
xqc_demo_wt_client_stream_read(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t len, void *user_data)
{
    xqc_demo_wt_client_t *ctx = &xqc_demo_wt_client;

    if (stream != ctx->stream) {
        return XQC_OK;
    }
    if (len > sizeof(xqc_demo_wt_payload) - ctx->received
        || (len && memcmp(data, xqc_demo_wt_payload + ctx->received, len)))
    {
        xqc_demo_wt_client_fail("stream echo mismatch", XQC_ERROR);
        return XQC_ERROR;
    }
    ctx->received += len;
    if (xqc_wt_bidistream_get_recv_fin(stream)) {
        if (ctx->received != sizeof(xqc_demo_wt_payload)) {
            xqc_demo_wt_client_fail("short stream echo", XQC_ERROR);
            return XQC_ERROR;
        }
        ctx->fin_received = 1;
        printf("WT bidi verified: bytes=%zu fin=1\n", ctx->received);
        xqc_demo_wt_client_maybe_close();
    }
    return XQC_OK;
}

static void
xqc_demo_wt_client_datagram_read(xqc_wt_session_t *session,
    const void *data, size_t len, void *user_data, uint64_t recv_time)
{
    xqc_demo_wt_client_t *ctx = &xqc_demo_wt_client;

    if (len != sizeof(xqc_demo_wt_datagram)
        || memcmp(data, xqc_demo_wt_datagram, len))
    {
        xqc_demo_wt_client_fail("datagram echo mismatch", XQC_ERROR);
        return;
    }
    ctx->datagram_received = 1;
    printf("WT datagram verified: bytes=%zu\n", len);
    xqc_demo_wt_client_maybe_close();
}

static void
xqc_demo_wt_client_datagram_write(xqc_wt_session_t *session, void *user_data)
{
    xqc_demo_wt_client_flush();
}

xqc_int_t
xqc_demo_wt_client_init(xqc_engine_t *engine, int draft_version,
    void (*schedule_send)(void *user_data),
    void (*finished)(void *user_data), void *user_data)
{
    xqc_webtransport_dgram_callbacks_t dgram_cbs = {
        .dgram_read_notify = xqc_demo_wt_client_datagram_read,
        .dgram_write_notify = xqc_demo_wt_client_datagram_write,
    };
    xqc_webtransport_session_callbacks_t session_cbs = {
        .webtransport_session_create_notify = xqc_demo_wt_client_ready,
        .webtransport_session_close_notify = xqc_demo_wt_client_closed,
    };
    xqc_webtransport_stream_callbacks_t stream_cbs = {
        .wt_bidistream_create_notify = xqc_demo_wt_client_stream_notify,
        .wt_bidistream_read_notify = xqc_demo_wt_client_stream_read,
        .wt_bidistream_write_notify = xqc_demo_wt_client_stream_write,
        .wt_bidistream_close_notify = xqc_demo_wt_client_stream_notify,
        .wt_bidistream_closing_notify = xqc_demo_wt_client_stream_notify,
    };
    xqc_webtransport_conn_settings_t settings = {
        .max_sessions_count = 1,
        .draft_version = draft_version == 7
            ? XQC_WEBTRANSPORT_DRAFT_VERSION_7
            : XQC_WEBTRANSPORT_DRAFT_VERSION_16,
        .max_bidi_streams = 16,
        .max_uni_streams = 16,
        .init_recv_window = 1024 * 1024,
        .enable_datagram = 1,
    };
    xqc_int_t ret;

    memset(&xqc_demo_wt_client, 0, sizeof(xqc_demo_wt_client));
    xqc_demo_wt_client.engine = engine;
    xqc_demo_wt_client.result = 1;
    xqc_demo_wt_client.schedule_send = schedule_send;
    xqc_demo_wt_client.finished = finished;
    xqc_demo_wt_client.user_data = user_data;
    ret = xqc_wt_ctx_init(engine, &dgram_cbs, &session_cbs, &stream_cbs);
    return ret == XQC_OK
        ? xqc_wt_engine_set_default_settings(engine, &settings) : ret;
}

xqc_int_t
xqc_demo_wt_client_open(xqc_h3_conn_t *h3_conn,
    const char *authority, const char *path, const char *origin)
{
    int err;

    xqc_demo_wt_client.session = xqc_wt_client_open_session(h3_conn,
        authority, path, origin, &err);
    if (!xqc_demo_wt_client.session) {
        xqc_demo_wt_client_fail("session open", err);
        return err;
    }
    xqc_demo_wt_client.schedule_send(xqc_demo_wt_client.user_data);
    return XQC_OK;
}

int
xqc_demo_wt_client_finish(void)
{
    /* Engine destruction is cleanup, not a peer close acknowledgement. */
    xqc_demo_wt_client.stopped = 1;
    return xqc_demo_wt_client.result;
}

xqc_int_t
xqc_demo_wt_client_conn_closing(xqc_connection_t *conn,
    const xqc_cid_t *cid, xqc_int_t error, void *user_data)
{
    if (!xqc_demo_wt_client.stopped && !xqc_demo_wt_client.session_closed) {
        xqc_demo_wt_client_fail("connection closed before session close", error);
    }
    return XQC_OK;
}
