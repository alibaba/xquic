/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include <CUnit/CUnit.h>
#include "xqc_common_test.h"
#include "xqc_webtransport_test.h"
#include "src/webtransport/xqc_webtransport_ctx.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/webtransport/xqc_webtransport_dgram.h"
#include "src/http3/xqc_h3_ctx.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_request.h"
#include "src/transport/xqc_stream.h"
#include "src/http3/frame/xqc_h3_frame.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"

static int wt_reads, wt_closes, wt_fin, wt_block;
static size_t wt_sent, wt_send_limit;
static unsigned char wt_output[64];
static xqc_wt_session_t *wt_last_session;
static void *wt_last_context;

static xqc_int_t
wt_read(xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *data, size_t len, void *ctx)
{
    wt_reads++;
    wt_last_context = ctx;
    wt_fin = xqc_wt_bidistream_get_recv_fin(stream);
    return wt_block ? -XQC_EAGAIN : XQC_OK;
}

static xqc_int_t
wt_close(xqc_wt_bidistream_t *stream, xqc_wt_session_t *session, void *ctx)
{
    wt_closes++;
    CU_ASSERT_PTR_NOT_NULL(session);
    return XQC_OK;
}

static ssize_t
wt_send(xqc_h3_stream_t *stream, const unsigned char *data,
    size_t len, uint8_t fin)
{
    size_t n = xqc_min(len, wt_send_limit);
    if (n) {
        memcpy(wt_output + wt_sent, data, n);
        wt_sent += n;
    }
    return n == 0 && len ? -XQC_EAGAIN : (ssize_t)n;
}

static xqc_int_t
wt_cancel(xqc_h3_stream_t *stream, uint64_t error)
{
    return XQC_OK;
}

static xqc_int_t
wt_pause(xqc_h3_stream_t *stream, xqc_bool_t paused)
{
    return XQC_OK;
}

static void
wt_detach(xqc_h3_stream_t *stream)
{
    stream->extension_data = NULL;
}

static const xqc_wt_stream_io_ops_t wt_io = {
    wt_send, wt_cancel, wt_cancel, wt_pause, wt_detach
};

static void
wt_dgram(xqc_wt_session_t *session, const void *data,
    size_t len, void *ctx, uint64_t time)
{
    wt_reads++;
    wt_last_session = session;
    CU_ASSERT(len == 1);
    CU_ASSERT(*(const unsigned char *)data == 'x');
}

void
xqc_test_wt_context(void)
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    xqc_h3_extension_ops_t ops = {0};
    CU_ASSERT(xqc_h3_extension_register(engine, &ops, NULL, 1)
              == -XQC_EPARAM);
    int marker;
    engine->user_data = &marker;
    xqc_webtransport_stream_callbacks_t cbs = {
        .wt_bidistream_read_notify = wt_read,
    };
    CU_ASSERT(xqc_wt_ctx_init(engine, NULL, NULL, &cbs) == XQC_OK);
    cbs.wt_bidistream_read_notify = NULL;
    xqc_wt_ctx_t *ctx = xqc_h3_extension_get_context(engine);
    CU_ASSERT_PTR_EQUAL(engine->user_data, &marker);
    CU_ASSERT(ctx->stream_cbs.wt_bidistream_read_notify == wt_read);
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, NULL) == XQC_OK);
    CU_ASSERT(engine->default_conn_settings.max_datagram_frame_size > 0);
    CU_ASSERT(xqc_wt_ctx_set_pending_datagram_policy(engine, 8, 2, 16)
              == XQC_OK);
    CU_ASSERT(ctx->pending_count_max == 2);
    xqc_h3_ctx_destroy(engine);
    xqc_engine_destroy(engine);
}

void
xqc_test_wt_context_errors(void)
{
    CU_ASSERT(xqc_wt_ctx_init(NULL, NULL, NULL, NULL) == -XQC_EPARAM);
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    CU_ASSERT(xqc_wt_ctx_init(engine, NULL, NULL, NULL) == XQC_OK);
    CU_ASSERT(xqc_wt_ctx_init(engine, NULL, NULL, NULL) == -XQC_ESTATE);
    xqc_wt_ctx_t *ctx = xqc_h3_extension_get_context(engine);
    xqc_webtransport_conn_settings_t settings = ctx->settings;
    settings.draft_version = XQC_WEBTRANSPORT_DRAFT_VERSION_2;
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, &settings)
              == -XQC_EPARAM);
    ctx->started = XQC_TRUE;
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, NULL) == -XQC_ESTATE);
    CU_ASSERT(xqc_wt_ctx_set_pending_datagram_policy(engine, 1, 1, 1)
              == -XQC_ESTATE);
    xqc_h3_ctx_destroy(engine);
    xqc_engine_destroy(engine);
}

static xqc_wt_session_t *
wt_session(xqc_wt_ctx_t *ctx, xqc_h3_conn_t *h3c)
{
    xqc_wt_conn_t *conn = xqc_wt_conn_create(h3c);
    if (!conn) {
        return NULL;
    }
    conn->ctx = ctx;
    xqc_wt_session_t *session = xqc_wt_session_init(4, conn, NULL);
    if (session) {
        session->open = XQC_TRUE;
    }
    return session;
}

void
xqc_test_wt_stream_io(void)
{
    xqc_wt_ctx_t ctx = {0};
    ctx.stream_cbs.wt_bidistream_read_notify = wt_read;
    ctx.stream_cbs.wt_bidistream_close_notify = wt_close;
    int marker;
    xqc_h3_conn_t h3c = {.user_data = &marker};
    xqc_wt_session_t *session = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    xqc_h3_stream_t h3s = {.stream_id = 8};
    xqc_wt_stream_base_t *stream = xqc_wt_stream_bind(session, &h3s,
        XQC_TRUE, XQC_TRUE, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    stream->io = &wt_io;
    wt_sent = 0;
    wt_send_limit = 1;
    /* draft-ietf-webtrans-http3-07 Section 4.2: prefix is not payload. */
    CU_ASSERT(xqc_wt_bidistream_send((void *)stream, "abc", 3, 1)
              == -XQC_EAGAIN);
    wt_send_limit = 2;
    CU_ASSERT(xqc_wt_bidistream_send((void *)stream, "abc", 3, 1) == 2);
    CU_ASSERT(!stream->send_fin);
    CU_ASSERT(xqc_wt_bidistream_send((void *)stream, "c", 1, 1) == 1);
    CU_ASSERT(stream->send_fin);
    CU_ASSERT(wt_sent == 6);
    CU_ASSERT(memcmp(wt_output, "\x40\x41\x04" "abc", 6) == 0);
    wt_reads = wt_fin = wt_block = wt_closes = 0;
    CU_ASSERT(xqc_wt_stream_notify_read(stream, NULL, 0, 1) == 0);
    CU_ASSERT(wt_reads == 1 && wt_fin == 1);
    CU_ASSERT_PTR_EQUAL(wt_last_context, &marker);
    xqc_wt_conn_destroy(session->wt_conn);
    CU_ASSERT(wt_closes == 1);
    CU_ASSERT_PTR_NULL(h3s.extension_data);
}

void
xqc_test_wt_stream_errors(void)
{
    xqc_wt_ctx_t ctx = {0};
    ctx.stream_cbs.wt_bidistream_read_notify = wt_read;
    xqc_h3_conn_t h3c = {0};
    xqc_wt_session_t *session = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    xqc_h3_stream_t h3s = {.stream_id = 8};
    xqc_wt_stream_base_t *stream = xqc_wt_stream_bind(session, &h3s,
        XQC_TRUE, XQC_FALSE, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    stream->io = &wt_io;
    wt_block = 1;
    CU_ASSERT(xqc_wt_stream_notify_read(stream, (void *)"x", 1, 1)
              == -XQC_EAGAIN);
    CU_ASSERT(!stream->recv_fin && stream->read_paused);
    CU_ASSERT(xqc_wt_bidistream_set_read_paused((void *)stream, 0) == XQC_OK);
    wt_block = 0;
    CU_ASSERT(xqc_wt_stream_notify_read(stream, (void *)"x", 1, 1) == 1);
    CU_ASSERT(stream->recv_fin);
    CU_ASSERT(xqc_wt_bidistream_send((void *)stream, NULL, 1, 0)
              == -XQC_EPARAM);
    session->closed = XQC_TRUE;
    CU_ASSERT(xqc_wt_bidistream_send((void *)stream, "x", 1, 0)
              == -XQC_ESTATE);
    xqc_wt_conn_destroy(session->wt_conn);
}

void
xqc_test_wt_capsules(void)
{
    xqc_wt_ctx_t ctx = {0};
    xqc_h3_conn_t h3c = {0};
    xqc_wt_session_t *session = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    /* draft-ietf-webtrans-http3-07 Section 5: split CLOSE header/body. */
    unsigned char capsule[] = {0x68, 0x43, 6, 0, 0, 0, 7, 'o', 'k'};
    for (size_t i = 0; i < sizeof(capsule); i++) {
        CU_ASSERT(xqc_wt_session_recv_capsules(session, capsule + i, 1,
                  i == sizeof(capsule) - 1) == XQC_OK);
    }
    CU_ASSERT(session->closed);
    CU_ASSERT(xqc_wt_session_get_close_error_code(session) == 7);
    CU_ASSERT_STRING_EQUAL(xqc_wt_session_get_close_reason(session), "ok");
    xqc_wt_conn_t *conn = session->wt_conn;
    xqc_wt_session_destroy(session);
    CU_ASSERT_PTR_NULL(xqc_wt_conn_find_session(conn, 4));
    CU_ASSERT_PTR_NULL(conn->wt_session);
    xqc_wt_conn_destroy(conn);
}

void
xqc_test_wt_capsule_errors(void)
{
    xqc_wt_ctx_t ctx = {0};
    xqc_h3_conn_t h3c = {0};
    xqc_wt_session_t *session = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    unsigned char short_close[] = {0x68, 0x43, 3};
    CU_ASSERT(xqc_wt_session_recv_capsules(session, short_close,
              sizeof(short_close), 0) == -XQC_H3_DECODE_ERROR);
    xqc_wt_conn_destroy(session->wt_conn);
    session = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    unsigned char truncated[] = {0x68};
    CU_ASSERT(xqc_wt_session_recv_capsules(session, truncated, 1, 1)
              == -XQC_H3_DECODE_ERROR);
    CU_ASSERT(xqc_wt_session_close_with_error(session, 0, "x", 1025)
              == -XQC_EPARAM);
    xqc_wt_conn_destroy(session->wt_conn);
}

void
xqc_test_wt_datagram_association(void)
{
    xqc_wt_ctx_t ctx = {0};
    ctx.dgram_cbs.dgram_read_notify = wt_dgram;
    ctx.pending_window = 8;
    ctx.pending_count_max = 1;
    ctx.pending_bytes_max = 8;
    xqc_connection_t transport = {0};
    xqc_h3_conn_t h3c = {.conn = &transport};
    xqc_wt_session_t *session = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    h3c.extension_data = session->wt_conn;
    transport.proto_data = &h3c;
    xqc_datagram_callbacks_t cbs = {0};
    xqc_wt_dgram_callbacks(&cbs);
    wt_reads = 0;
    /* RFC 9297 Section 2.1: Quarter Stream ID 1 identifies session 4. */
    cbs.datagram_read_notify(&transport, NULL, "\x01x", 2, 1);
    CU_ASSERT(wt_reads == 1);
    CU_ASSERT_PTR_EQUAL(wt_last_session, session);
    cbs.datagram_read_notify(&transport, NULL, "\x02x", 2, 1);
    cbs.datagram_read_notify(&transport, NULL, "\x03x", 2, 1);
    CU_ASSERT(wt_reads == 1);
    CU_ASSERT(session->wt_conn->pending_count == 1);
    xqc_wt_session_t *second = xqc_wt_session_init(8, session->wt_conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(second);
    second->open = XQC_TRUE;
    xqc_wt_dgram_resume(second);
    CU_ASSERT(wt_reads == 2);
    CU_ASSERT_PTR_EQUAL(wt_last_session, second);
    CU_ASSERT(session->wt_conn->pending_count == 0);
    cbs.datagram_read_notify(&transport, NULL, "\xff", 1, 1);
    CU_ASSERT(wt_reads == 2);
    xqc_wt_conn_destroy(session->wt_conn);
}

void
xqc_test_wt_extension_settings(void)
{
    xqc_list_head_t buffers;
    xqc_init_list_head(&buffers);
    xqc_h3_conn_settings_t settings = {0};
    xqc_h3_extension_setting_t extra[] = {{0x08, 1}, {0xc671706a, 4}};
    CU_ASSERT(xqc_h3_frm_write_settings_extended(&buffers, &settings,
              extra, 2, 0) == XQC_OK);
    while (!xqc_list_empty(&buffers)) {
        xqc_list_buf_t *item = xqc_list_entry(buffers.next,
            xqc_list_buf_t, list_head);
        xqc_list_del(&item->list_head);
        xqc_var_buf_free(item->buf);
        xqc_free(item);
    }
    /* RFC 9114 Section 7.2.4: adapter cannot repeat an H3 setting. */
    extra[0].identifier = 1;
    CU_ASSERT(xqc_h3_frm_write_settings_extended(&buffers, &settings,
              extra, 2, 0) == -XQC_EPARAM);
    CU_ASSERT(xqc_list_empty(&buffers));
}

static int wt_session_creates, wt_session_closes;
static int wt_app_creates, wt_app_reads, wt_app_writes;
static int wt_app_closings, wt_app_closes, wt_request_marker;
static int wt_app_handshakes, wt_handshakes;
static void *wt_app_conn_context;

static void
wt_app_handshake(xqc_h3_conn_t *conn, void *ctx)
{
    wt_app_handshakes++;
    CU_ASSERT_PTR_EQUAL(ctx, wt_app_conn_context);
}

static void
wt_handshake(xqc_h3_conn_t *conn, void *ctx)
{
    wt_handshakes++;
    CU_ASSERT_PTR_EQUAL(ctx, wt_app_conn_context);
}

static int
wt_app_create(xqc_h3_request_t *request, void *ctx)
{
    wt_app_creates++;
    CU_ASSERT_PTR_EQUAL(xqc_h3_get_conn_user_data_by_request(request),
                        wt_app_conn_context);
    xqc_h3_request_set_user_data(request, &wt_request_marker);
    return XQC_OK;
}

static int
wt_app_read(xqc_h3_request_t *request, xqc_request_notify_flag_t flags,
    void *ctx)
{
    unsigned char fin = 0;
    wt_app_reads++;
    CU_ASSERT_PTR_EQUAL(ctx, &wt_request_marker);
    CU_ASSERT_PTR_NOT_NULL(xqc_h3_request_recv_headers(request, &fin));
    return XQC_OK;
}

static int
wt_app_write(xqc_h3_request_t *request, void *ctx)
{
    wt_app_writes++;
    CU_ASSERT_PTR_EQUAL(ctx, &wt_request_marker);
    return XQC_OK;
}

static void
wt_app_closing(xqc_h3_request_t *request, xqc_int_t error, void *ctx)
{
    wt_app_closings++;
    CU_ASSERT_PTR_EQUAL(ctx, &wt_request_marker);
}

static int
wt_app_close(xqc_h3_request_t *request, void *ctx)
{
    wt_app_closes++;
    CU_ASSERT_PTR_EQUAL(ctx, &wt_request_marker);
    return XQC_OK;
}

static int
wt_accept(xqc_http_headers_t *headers, xqc_http_headers_t *response)
{
    xqc_http_header_t *origin = &headers->headers[5];
    return origin->value.iov_len == 7
        && memcmp(origin->value.iov_base, "allowed", 7) == 0;
}

static int
wt_session_created(xqc_wt_session_t *session, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *ctx)
{
    wt_session_creates++;
    return XQC_OK;
}

static int
wt_session_closed(xqc_wt_session_t *session, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *ctx)
{
    wt_session_closes++;
    return XQC_OK;
}

static void
wt_test_connect_request(int scenario)
{
    xqc_bool_t accepted = scenario == 1;
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    xqc_engine_t *engine = conn->engine;
    xqc_h3_callbacks_t app = {
        .h3c_cbs = {.h3_conn_handshake_finished = wt_app_handshake},
        .h3r_cbs = {
            .h3_request_create_notify = wt_app_create,
            .h3_request_read_notify = wt_app_read,
            .h3_request_write_notify = wt_app_write,
            .h3_request_closing_notify = wt_app_closing,
            .h3_request_close_notify = wt_app_close,
        },
    };
    CU_ASSERT(xqc_h3_ctx_init(engine, &app) == XQC_OK);
    xqc_webtransport_session_callbacks_t cbs = {
        .webtransport_will_create_session_notify = wt_accept,
        .webtransport_session_create_notify = wt_session_created,
        .webtransport_session_close_notify = wt_session_closed,
        .webtransport_conn_handshake_finished_notify = wt_handshake,
    };
    CU_ASSERT(xqc_wt_ctx_init(engine, NULL, &cbs, NULL) == XQC_OK);
    xqc_free(conn->alpn);
    conn->alpn = (unsigned char *)xqc_malloc(3);
    memcpy(conn->alpn, "h3", 3);
    conn->alpn_len = 2;
    CU_ASSERT(xqc_engine_get_alpn_callbacks(engine, "h3", 2,
              &conn->app_proto_cbs) == XQC_OK);
    conn->conn_type = XQC_CONN_TYPE_SERVER;
    int marker;
    wt_app_conn_context = &marker;
    wt_app_creates = wt_app_reads = wt_app_writes = 0;
    wt_app_closings = wt_app_closes = 0;
    wt_app_handshakes = wt_handshakes = 0;
    xqc_h3_conn_t *h3c = xqc_h3_conn_create(conn, &marker);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
    xqc_wt_conn_t *wt_conn = h3c->extension_data;
    xqc_wt_ctx_t *engine_ctx = xqc_h3_extension_get_context(engine);
    CU_ASSERT_PTR_NOT_EQUAL(wt_conn->ctx, engine_ctx);
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, NULL) == -XQC_ESTATE);
    conn->conn_flow_ctl.fc_max_streams_uni_can_send = 16;
    h3c->qenc_stream = xqc_h3_conn_create_uni_stream(h3c,
        XQC_H3_STREAM_TYPE_QPACK_ENCODER);
    h3c->qdec_stream = xqc_h3_conn_create_uni_stream(h3c,
        XQC_H3_STREAM_TYPE_QPACK_DECODER);
    h3c->control_stream_out = xqc_h3_conn_create_uni_stream(h3c,
        XQC_H3_STREAM_TYPE_CONTROL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c->qenc_stream);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c->qdec_stream);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c->control_stream_out);
    conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST;
    conn->remote_settings.max_datagram_frame_size = 1200;
    engine->config->manually_triggered_send = 1;
    xqc_stream_t *stream = xqc_create_stream_with_conn(conn,
        XQC_UNDEFINE_STREAM_ID, XQC_CLI_BID, NULL, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    xqc_h3_stream_t *h3s = xqc_h3_stream_create(h3c, stream,
        XQC_H3_STREAM_TYPE_REQUEST, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3s);
    xqc_h3_request_t *request = xqc_h3_request_create_inner(h3c, h3s, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(request);
    h3s->h3r = request;
    CU_ASSERT(wt_app_creates == 0);
    if (scenario == 3) {
        xqc_h3_request_closing(request, -XQC_EPARAM);
        xqc_engine_destroy(engine);
        CU_ASSERT(wt_app_creates == 0 && wt_app_closes == 0);
        CU_ASSERT(wt_app_closings == 0);
        return;
    }
    if (scenario == 4) {
        wt_conn->ctx->settings.max_sessions_count = 1;
        CU_ASSERT_PTR_NOT_NULL_FATAL(xqc_wt_session_init(4, wt_conn, NULL));
    }
    const char *names[] = {":method", ":protocol", ":scheme", ":authority",
                           ":path", "origin"};
    const char *values[] = {"CONNECT", "webtransport", "https", "localhost",
                            "/wt", accepted ? "allowed" : "denied"};
    if (scenario == 2) {
        values[0] = "GET";
        names[1] = ":scheme";
        values[1] = "https";
        names[2] = ":authority";
        values[2] = "localhost";
        names[3] = ":path";
        values[3] = "/";
        names[4] = "user-agent";
        values[4] = "test";
    }
    xqc_http_headers_t *headers = &request->h3_header[0];
    headers->headers = xqc_calloc(6, sizeof(xqc_http_header_t));
    headers->capacity = headers->count = 6;
    for (size_t i = 0; i < 6; i++) {
        xqc_http_header_t *header = &headers->headers[i];
        header->name.iov_len = strlen(names[i]);
        header->value.iov_len = strlen(values[i]);
        header->name.iov_base = xqc_malloc(header->name.iov_len);
        header->value.iov_base = xqc_malloc(header->value.iov_len);
        memcpy(header->name.iov_base, names[i], header->name.iov_len);
        memcpy(header->value.iov_base, values[i], header->value.iov_len);
        headers->total_len += header->name.iov_len + header->value.iov_len;
    }
    wt_session_creates = wt_session_closes = 0;
    /* draft-ietf-webtrans-http3-07 Section 3.1: wait for peer SETTINGS. */
    CU_ASSERT_FATAL(xqc_h3_request_on_recv_header(request) == XQC_OK);
    if (scenario == 2) {
        CU_ASSERT(wt_app_creates == 1 && wt_app_reads == 1);
        CU_ASSERT(wt_conn->session_count == 0);
        CU_ASSERT(request->request_if->h3_request_write_notify(request,
                  request->user_data) == XQC_OK);
        xqc_h3_request_closing(request, -XQC_EPARAM);
        /* QPACK-blocked H3 requests can outlive the WT connection state. */
        h3c->extension_ops->conn_close(h3c, h3c->extension_data);
        h3c->extension_data = NULL;
        xqc_engine_destroy(engine);
        CU_ASSERT(wt_app_writes == 1 && wt_app_closings == 1);
        CU_ASSERT(wt_app_closes == 1);
        return;
    }
    if (scenario == 4) {
        CU_ASSERT_PTR_NULL(xqc_wt_conn_find_session(wt_conn, h3s->stream_id));
        CU_ASSERT(wt_session_creates == 0 && wt_app_creates == 0);
        xqc_engine_destroy(engine);
        CU_ASSERT(wt_session_closes == 0 && wt_app_closes == 0);
        return;
    }
    CU_ASSERT(wt_app_creates == 0 && wt_app_reads == 0);
    CU_ASSERT(wt_session_creates == 0);
    const xqc_h3_extension_ops_t *ops = h3c->extension_ops;
    CU_ASSERT(ops->peer_setting(h3c, h3c->extension_data, 0xc671706a, 1)
              == XQC_OK);
    CU_ASSERT(ops->peer_setting(h3c, h3c->extension_data, 0x33, 1) == XQC_OK);
    CU_ASSERT(ops->peer_settings_complete(h3c, h3c->extension_data) == XQC_OK);
    CU_ASSERT(wt_session_creates == (accepted ? 1 : 0));
    xqc_wt_session_t *session = xqc_wt_conn_find_session(wt_conn,
        h3s->stream_id);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    CU_ASSERT(session->closed == !accepted);
    /* Connection snapshots survive ALPN context release by the engine. */
    memset(&engine_ctx->session_cbs, 0, sizeof(engine_ctx->session_cbs));
    xqc_h3_ctx_t *h3_ctx = xqc_engine_get_alpn_ctx(engine, "h3", 2);
    memset(&h3_ctx->extension_ops, 0, sizeof(h3_ctx->extension_ops));
    conn->app_proto_cbs.conn_cbs.conn_handshake_finished(conn, NULL, h3c);
    CU_ASSERT(wt_app_handshakes == 1 && wt_handshakes == 1);
    xqc_engine_destroy(engine);
    CU_ASSERT(wt_session_closes == (accepted ? 1 : 0));
    CU_ASSERT(wt_app_closes == 0);
}

void
xqc_test_wt_connect_accept(void)
{
    wt_test_connect_request(XQC_TRUE);
}

void
xqc_test_wt_connect_reject(void)
{
    wt_test_connect_request(XQC_FALSE);
}

void
xqc_test_wt_request_passthrough(void)
{
    wt_test_connect_request(2);
}

void
xqc_test_wt_request_incomplete(void)
{
    wt_test_connect_request(3);
}

void
xqc_test_wt_session_limit(void)
{
    wt_test_connect_request(4);
}
