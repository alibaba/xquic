/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "src/webtransport/xqc_webtransport_ctx.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "src/webtransport/xqc_webtransport_request_adapter.h"
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

static void xqc_wt_handshake_finished(xqc_h3_conn_t *h3c, void *data);

static const xqc_webtransport_conn_settings_t xqc_wt_defaults = {
    .max_sessions_count = 16,
    .draft_version = XQC_WEBTRANSPORT_DRAFT_VERSION_7,
    .max_bidi_streams = 128,
    .max_uni_streams = 128,
    .init_recv_window = 1024 * 1024,
    .enable_datagram = XQC_TRUE,
};

static void *
xqc_wt_extension_conn_create(xqc_h3_conn_t *h3c, void *data)
{
    xqc_wt_ctx_t *ctx = data;
    xqc_wt_conn_t *conn = xqc_wt_conn_create(h3c);
    if (conn) {
        ctx->started = XQC_TRUE;
        conn->ctx_storage = *ctx;
        conn->ctx = &conn->ctx_storage;
        conn->cid = h3c->conn->scid_set.user_scid;
        conn->app_handshake_finished =
            h3c->h3_conn_callbacks.h3_conn_handshake_finished;
        h3c->h3_conn_callbacks.h3_conn_handshake_finished =
            xqc_wt_handshake_finished;
        xqc_wt_request_adapter_init(conn);
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
    xqc_wt_conn_t *conn = h3c->extension_data;
    if (conn->ctx->session_cbs.webtransport_conn_handshake_finished_notify) {
        conn->ctx->session_cbs.webtransport_conn_handshake_finished_notify(
            h3c, xqc_h3_conn_get_user_data(h3c));
    }
    if (conn->app_handshake_finished) {
        conn->app_handshake_finished(h3c, data);
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
    xqc_wt_ctx_t storage = {0};
    xqc_wt_ctx_t *ctx = &storage;
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
        .conn_create = xqc_wt_extension_conn_create,
        .conn_close = xqc_wt_extension_conn_close,
        .local_settings = xqc_wt_local_settings,
        .peer_setting = xqc_wt_peer_setting,
        .peer_settings_complete = xqc_wt_peer_settings_complete,
        .raw_stream_type = xqc_wt_raw_type,
        .raw_read = xqc_wt_stream_read,
        .raw_write = xqc_wt_stream_write,
        .raw_closing = xqc_wt_stream_closing,
        .raw_close = xqc_wt_stream_close,
    };
    xqc_wt_dgram_callbacks(&ops.datagram_callbacks);
    return xqc_h3_extension_register(engine, &ops, ctx, sizeof(*ctx));
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
