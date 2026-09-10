/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "src/webtransport/xqc_webtransport_ctx.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/webtransport/xqc_webtransport_dgram.h"
#include "src/webtransport/xqc_webtransport_wire.h"
#include "src/http3/xqc_h3_extension.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_request.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"
#include "src/common/xqc_malloc.h"

/* draft-ietf-webtrans-http3-07 Sections 3.1, 3.2 and 8.2. */
#define XQC_WT_SETTING_MAX_SESSIONS UINT64_C(0xc671706a)
#define XQC_WT_SETTING_DATAGRAM 0x33
#define XQC_WT_SETTING_CONNECT 0x08

static xqc_int_t xqc_wt_request_read(xqc_h3_request_t *request,
    xqc_request_notify_flag_t flags, void *data);

static const xqc_webtransport_conn_settings_t xqc_wt_defaults = {
    .max_sessions_count = 16,
    .draft_version = XQC_WEBTRANSPORT_DRAFT_VERSION_7,
    .max_bidi_streams = 128,
    .max_uni_streams = 128,
    .init_recv_window = 1024 * 1024,
    .enable_datagram = XQC_TRUE,
};

static void
xqc_wt_ctx_destroy(void *data)
{
    xqc_free(data);
}

static void *
xqc_wt_extension_conn_create(xqc_h3_conn_t *h3c, void *data)
{
    xqc_wt_ctx_t *ctx = data;
    xqc_wt_conn_t *conn = xqc_wt_conn_create(h3c);
    if (conn) {
        ctx->started = XQC_TRUE;
        conn->ctx = ctx;
        conn->cid = h3c->conn->scid_set.user_scid;
    }
    return conn;
}

static void
xqc_wt_extension_conn_close(xqc_h3_conn_t *h3c, void *data)
{
    xqc_wt_conn_destroy(data);
}

static void
xqc_wt_handshake_finished(xqc_h3_conn_t *h3c, void *data)
{
    xqc_wt_conn_t *conn = data;
    if (conn->ctx->session_cbs.webtransport_conn_handshake_finished_notify) {
        conn->ctx->session_cbs.webtransport_conn_handshake_finished_notify(
            h3c, xqc_h3_conn_get_user_data(h3c));
    }
}

static ssize_t
xqc_wt_local_settings(xqc_h3_conn_t *h3c, void *data,
    xqc_h3_extension_setting_t *settings, size_t capacity)
{
    xqc_wt_conn_t *conn = data;
    if (capacity < 3) {
        return -XQC_EPARAM;
    }
    settings[0] = (xqc_h3_extension_setting_t){XQC_WT_SETTING_CONNECT, 1};
    settings[1] = (xqc_h3_extension_setting_t){XQC_WT_SETTING_DATAGRAM, 1};
    settings[2] = (xqc_h3_extension_setting_t){XQC_WT_SETTING_MAX_SESSIONS,
        conn->ctx->settings.max_sessions_count};
    return 3;
}

static xqc_int_t
xqc_wt_peer_setting(xqc_h3_conn_t *h3c, void *data,
    uint64_t id, uint64_t value)
{
    xqc_wt_conn_t *conn = data;
    if (id == XQC_WT_SETTING_MAX_SESSIONS) {
        conn->peer_max_sessions = value;
    } else if (id == XQC_WT_SETTING_DATAGRAM) {
        if (value > 1) {
            return -XQC_H3_SETTING_ERROR;
        }
        conn->peer_datagram = value;
    } else if (id == XQC_WT_SETTING_CONNECT) {
        if (value > 1) {
            return -XQC_H3_SETTING_ERROR;
        }
        conn->peer_connect = value;
    }
    return XQC_OK;
}

static xqc_int_t
xqc_wt_peer_settings_complete(xqc_h3_conn_t *h3c, void *data)
{
    xqc_wt_conn_t *conn = data;
    conn->settings_received = XQC_TRUE;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &conn->session_list) {
        xqc_wt_session_t *session = xqc_list_entry(pos,
            xqc_wt_session_t, conn_list);
        if (!session->open && !session->closed) {
            xqc_int_t ret = xqc_wt_request_read(session->request,
                XQC_REQ_NOTIFY_READ_HEADER | XQC_REQ_NOTIFY_READ_BODY,
                session);
            if (ret != XQC_OK) {
                return ret;
            }
        }
    }
    return XQC_OK;
}

static xqc_bool_t
xqc_wt_header_is(const xqc_http_header_t *header, const char *name,
    const char *value)
{
    return header->name.iov_len == strlen(name)
        && memcmp(header->name.iov_base, name, strlen(name)) == 0
        && (!value || (header->value.iov_len == strlen(value)
            && memcmp(header->value.iov_base, value, strlen(value)) == 0));
}

static xqc_int_t
xqc_wt_response(xqc_h3_request_t *request, const char *status)
{
    xqc_http_header_t header = {
        .name = {(void *)":status", 7},
        .value = {(void *)status, 3},
    };
    xqc_http_headers_t response = {.headers = &header, .count = 1};
    ssize_t ret = xqc_h3_request_send_headers(request, &response, 1);
    return ret < 0 ? (xqc_int_t)ret : XQC_OK;
}

static xqc_int_t
xqc_wt_request_headers(xqc_h3_request_t *request, void *data,
    const xqc_http_headers_t *headers)
{
    xqc_wt_conn_t *conn = data;
    xqc_bool_t wt = XQC_FALSE;
    for (size_t i = 0; i < headers->count; i++) {
        wt |= xqc_wt_header_is(&headers->headers[i], ":protocol",
                              "webtransport");
    }
    if (!wt) {
        return 0;
    }
    if (conn->session_count >= conn->ctx->settings.max_sessions_count) {
        xqc_int_t ret = xqc_wt_response(request, "429");
        return ret < 0 ? ret : 1;
    }
    xqc_wt_session_t *session = xqc_wt_session_init(
        request->h3_stream->stream_id, conn, request->h3_stream);
    if (!session) {
        return -XQC_EMALLOC;
    }
    request->extension_data = session;
    return 1;
}

static xqc_int_t
xqc_wt_accept_session(xqc_wt_session_t *session)
{
    xqc_wt_conn_t *conn = session->wt_conn;
    unsigned char fin = 0;
    xqc_http_headers_t *headers =
        xqc_h3_request_recv_headers(session->request, &fin);
    if (!headers) {
        return -XQC_H3_DECODE_ERROR;
    }
    unsigned method = 0, protocol = 0, scheme = 0, authority = 0, path = 0;
    for (size_t i = 0; i < headers->count; i++) {
        xqc_http_header_t *header = &headers->headers[i];
        method += xqc_wt_header_is(header, ":method", "CONNECT");
        protocol += xqc_wt_header_is(header, ":protocol", "webtransport");
        scheme += xqc_wt_header_is(header, ":scheme", "https");
        authority += xqc_wt_header_is(header, ":authority", NULL)
            && header->value.iov_len > 0;
        path += xqc_wt_header_is(header, ":path", NULL)
            && header->value.iov_len > 0;
    }
    if (method != 1 || protocol != 1 || scheme != 1 || authority != 1
        || path != 1 || fin || !conn->peer_max_sessions
        || !conn->peer_datagram
        || !conn->h3_conn->conn->remote_settings.max_datagram_frame_size)
    {
        session->closed = XQC_TRUE;
        return xqc_wt_response(session->request, "400");
    }
    xqc_http_header_t header = {
        .name = {(void *)":status", 7},
        .value = {(void *)"200", 3},
    };
    xqc_http_headers_t response = {.headers = &header, .count = 1};
    xqc_webtransport_session_callbacks_t *cbs = &conn->ctx->session_cbs;
    if (!cbs->webtransport_will_create_session_notify
        || cbs->webtransport_will_create_session_notify(headers, &response)
            != 1)
    {
        session->closed = XQC_TRUE;
        return xqc_wt_response(session->request, "403");
    }
    xqc_bool_t accepted = XQC_FALSE;
    for (size_t i = 0; i < response.count; i++) {
        xqc_http_header_t *h = &response.headers[i];
        if (xqc_wt_header_is(h, ":status", NULL) && h->value.iov_len == 3) {
            accepted = ((const char *)h->value.iov_base)[0] == '2';
        }
    }
    ssize_t ret = xqc_h3_request_send_headers(session->request, &response,
                                             !accepted);
    if (ret < 0) {
        return (xqc_int_t)ret;
    }
    if (!accepted) {
        session->closed = XQC_TRUE;
        return XQC_OK;
    }
    session->open = XQC_TRUE;
    if (cbs->webtransport_session_create_notify) {
        ret = cbs->webtransport_session_create_notify(session, headers,
            &conn->cid, xqc_wt_session_get_callback_user_data(session));
        if (ret != XQC_OK) {
            return xqc_wt_session_close_with_error(session, 1, NULL, 0);
        }
    }
    xqc_wt_conn_resume_streams(conn);
    xqc_wt_dgram_resume(session);
    return XQC_OK;
}

static xqc_int_t
xqc_wt_request_read(xqc_h3_request_t *request,
    xqc_request_notify_flag_t flags, void *data)
{
    xqc_wt_session_t *session = data;
    if (!session || (!session->open && session->closed)) {
        return XQC_OK;
    }
    if (!session->wt_conn->settings_received) {
        return XQC_OK;
    }
    if (!session->open) {
        xqc_int_t ret = xqc_wt_accept_session(session);
        if (ret != XQC_OK || !session->open) {
            return ret;
        }
    }
    if (flags & XQC_REQ_NOTIFY_READ_BODY) {
        unsigned char buffer[4096], fin = 0;
        do {
            ssize_t n = xqc_h3_request_recv_body(request, buffer,
                                                sizeof(buffer), &fin);
            if (n == -XQC_EAGAIN) {
                break;
            }
            if (n < 0) {
                return (xqc_int_t)n;
            }
            xqc_int_t ret = xqc_wt_session_recv_capsules(session, buffer,
                                                        n, fin);
            if (ret != XQC_OK) {
                xqc_h3_request_close(request);
                return XQC_OK;
            }
            if (n == 0 || fin) {
                break;
            }
        } while (1);
    }
    if (flags & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
        return xqc_wt_session_recv_capsules(session, NULL, 0, XQC_TRUE);
    }
    return XQC_OK;
}

static xqc_int_t
xqc_wt_request_write(xqc_h3_request_t *request, void *data)
{
    return data ? xqc_wt_session_flush(data) : XQC_OK;
}

static void
xqc_wt_request_closing(xqc_h3_request_t *request, xqc_int_t error,
    void *data)
{
    xqc_wt_session_t *session = data;
    if (session) {
        session->closed = XQC_TRUE;
        xqc_wt_session_close_streams(session);
    }
}

static void
xqc_wt_request_close(xqc_h3_request_t *request, void *data)
{
    xqc_wt_session_destroy(data);
}

static xqc_bool_t
xqc_wt_raw_type(xqc_h3_conn_t *h3c, void *data, uint64_t type,
    xqc_bool_t bidi)
{
    return type == (bidi ? XQC_WT_STREAM_TYPE_BIDIRECTIONAL
                        : XQC_WT_STREAM_TYPE_UNIDIRECTIONAL);
}

xqc_int_t
xqc_wt_ctx_init(xqc_engine_t *engine,
    xqc_webtransport_dgram_callbacks_t *dgram_cbs,
    xqc_webtransport_session_callbacks_t *session_cbs,
    xqc_webtransport_stream_callbacks_t *stream_cbs)
{
    if (!engine) {
        return -XQC_EPARAM;
    }
    xqc_wt_ctx_t *ctx = xqc_calloc(1, sizeof(*ctx));
    if (!ctx) {
        return -XQC_EMALLOC;
    }
    if (dgram_cbs) {
        ctx->dgram_cbs = *dgram_cbs;
    }
    if (session_cbs) {
        ctx->session_cbs = *session_cbs;
    }
    if (stream_cbs) {
        ctx->stream_cbs = *stream_cbs;
    }
    ctx->settings = xqc_wt_defaults;
    ctx->pending_window = XQC_WEBTRANSPORT_DEFAULT_UNKNOWN_SESSION_DGRAM_WINDOW;
    ctx->pending_count_max = XQC_WEBTRANSPORT_DEFAULT_PENDING_DGRAM_COUNT_MAX;
    ctx->pending_bytes_max = XQC_WEBTRANSPORT_DEFAULT_PENDING_DGRAM_BYTES_MAX;
    xqc_h3_extension_ops_t ops = {
        .ctx_destroy = xqc_wt_ctx_destroy,
        .conn_create = xqc_wt_extension_conn_create,
        .conn_close = xqc_wt_extension_conn_close,
        .handshake_finished = xqc_wt_handshake_finished,
        .local_settings = xqc_wt_local_settings,
        .peer_setting = xqc_wt_peer_setting,
        .peer_settings_complete = xqc_wt_peer_settings_complete,
        .request_headers = xqc_wt_request_headers,
        .request_read = xqc_wt_request_read,
        .request_write = xqc_wt_request_write,
        .request_closing = xqc_wt_request_closing,
        .request_close = xqc_wt_request_close,
        .raw_stream_type = xqc_wt_raw_type,
        .raw_read = xqc_wt_stream_read,
        .raw_write = xqc_wt_stream_write,
        .raw_closing = xqc_wt_stream_closing,
        .raw_close = xqc_wt_stream_close,
    };
    xqc_wt_dgram_callbacks(&ops.datagram_callbacks);
    xqc_int_t ret = xqc_h3_extension_register(engine, &ops, ctx);
    if (ret != XQC_OK) {
        xqc_free(ctx);
    }
    return ret;
}

xqc_int_t
xqc_wt_engine_set_default_settings(xqc_engine_t *engine,
    const xqc_webtransport_conn_settings_t *settings)
{
    xqc_wt_ctx_t *ctx = xqc_h3_extension_get_context(engine);
    if (!ctx || ctx->started) {
        return -XQC_ESTATE;
    }
    if (!settings) {
        settings = &xqc_wt_defaults;
    }
    if (settings->draft_version != XQC_WEBTRANSPORT_DRAFT_VERSION_7
        || !settings->enable_datagram || !settings->max_sessions_count
        || settings->max_sessions_count > 1024
        || settings->max_bidi_streams < settings->max_sessions_count
        || settings->max_uni_streams < 3 || !settings->init_recv_window)
    {
        return -XQC_EPARAM;
    }
    ctx->settings = *settings;
    xqc_conn_settings_t transport = engine->default_conn_settings;
    transport.max_streams_bidi = settings->max_bidi_streams;
    transport.max_streams_uni = settings->max_uni_streams;
    transport.init_recv_window = settings->init_recv_window;
    transport.max_datagram_frame_size = 65535;
    xqc_server_set_conn_settings(engine, &transport);
    return XQC_OK;
}

xqc_int_t
xqc_wt_ctx_set_pending_datagram_policy(xqc_engine_t *engine,
    uint64_t window, size_t count_max, size_t bytes_max)
{
    xqc_wt_ctx_t *ctx = xqc_h3_extension_get_context(engine);
    if (!ctx || ctx->started) {
        return -XQC_ESTATE;
    }
    ctx->pending_window = window;
    ctx->pending_count_max = count_max;
    ctx->pending_bytes_max = bytes_max;
    return XQC_OK;
}

const xqc_cid_t *
xqc_webtransport_connect(xqc_engine_t *engine,
    const xqc_conn_settings_t *settings, const unsigned char *token,
    unsigned token_len, const char *host, int no_crypto,
    const xqc_conn_ssl_config_t *ssl, const struct sockaddr *peer,
    socklen_t peer_len, void *user_data)
{
    return xqc_connect(engine, settings, token, token_len, host, no_crypto,
        ssl, peer, peer_len, XQC_DEFINED_ALPN_H3_EXT, user_data);
}
