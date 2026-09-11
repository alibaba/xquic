/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "src/webtransport/xqc_webtransport_ctx.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "src/webtransport/xqc_webtransport_request_adapter.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/webtransport/xqc_webtransport_h3_stream.h"
#include "src/webtransport/xqc_webtransport_dgram.h"
#include "src/webtransport/xqc_webtransport_wire.h"
#include "src/http3/xqc_h3_ctx.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_request.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"
#include "src/common/xqc_malloc.h"

/* draft-ietf-webtrans-http3-07 Sections 3.1, 3.2 and 8.2. */
#define XQC_WT_SETTING_MAX_SESSIONS UINT64_C(0xc671706a)
#define XQC_WT_SETTING_DATAGRAM 0x33
#define XQC_WT_SETTING_CONNECT 0x08

typedef struct {
    xqc_h3_ctx_t  h3;
    xqc_wt_ctx_t  wt;
} xqc_wt_registration_t;

static xqc_int_t xqc_wt_h3_conn_create(xqc_h3_conn_t *h3c,
    const xqc_cid_t *cid, void *data);
static xqc_int_t xqc_wt_h3_conn_close(xqc_h3_conn_t *h3c,
    const xqc_cid_t *cid, void *data);
static void xqc_wt_handshake_finished(xqc_h3_conn_t *h3c, void *data);

static const xqc_webtransport_conn_settings_t xqc_wt_defaults = {
    .max_sessions_count = 16,
    .draft_version = XQC_WEBTRANSPORT_DRAFT_VERSION_7,
    .max_bidi_streams = 128,
    .max_uni_streams = 128,
    .init_recv_window = 1024 * 1024,
    .enable_datagram = XQC_TRUE,
};

xqc_wt_ctx_t *
xqc_wt_ctx_get(xqc_engine_t *engine)
{
    if (engine == NULL) {
        return NULL;
    }
    xqc_h3_ctx_t *h3 = xqc_engine_get_alpn_ctx(engine, XQC_ALPN_H3,
                                             strlen(XQC_ALPN_H3));
    if (h3 == NULL
        || h3->h3_cbs.h3c_cbs.h3_conn_create_notify != xqc_wt_h3_conn_create)
    {
        return NULL;
    }
    return &((xqc_wt_registration_t *)h3)->wt;
}

static xqc_int_t
xqc_wt_h3_conn_create(xqc_h3_conn_t *h3c, const xqc_cid_t *cid, void *data)
{
    xqc_wt_ctx_t *ctx = xqc_wt_ctx_get(h3c->conn->engine);
    if (ctx == NULL) {
        return -XQC_ESTATE;
    }
    if (ctx->app_conn_callbacks.h3_conn_create_notify) {
        xqc_int_t ret = ctx->app_conn_callbacks.h3_conn_create_notify(h3c,
                                                                    cid, data);
        if (ret != XQC_OK) {
            return ret;
        }
    }
    xqc_int_t ret = xqc_h3_conn_set_setting(h3c, XQC_WT_SETTING_CONNECT, 1);
    if (ret == XQC_OK) {
        ret = xqc_h3_conn_set_setting(h3c, XQC_WT_SETTING_DATAGRAM, 1);
    }
    if (ret == XQC_OK) {
        ret = xqc_h3_conn_set_setting(h3c, XQC_WT_SETTING_MAX_SESSIONS,
                                    ctx->settings.max_sessions_count);
    }
    if (ret != XQC_OK) {
        goto fail;
    }
    xqc_wt_conn_t *conn = xqc_wt_conn_create(h3c);
    if (conn == NULL) {
        ret = -XQC_EMALLOC;
        goto fail;
    }
    ctx->started = XQC_TRUE;
    conn->ctx_storage = *ctx;
    conn->ctx = &conn->ctx_storage;
    conn->cid = h3c->conn->scid_set.user_scid;
    xqc_wt_request_adapter_init(conn);
    return XQC_OK;

fail:
    if (ctx->app_conn_callbacks.h3_conn_create_notify
        && ctx->app_conn_callbacks.h3_conn_close_notify)
    {
        ctx->app_conn_callbacks.h3_conn_close_notify(h3c, cid,
            xqc_h3_conn_get_user_data(h3c));
    }
    return ret;
}

static xqc_int_t
xqc_wt_h3_conn_close(xqc_h3_conn_t *h3c, const xqc_cid_t *cid, void *data)
{
    xqc_wt_conn_t *conn = xqc_wt_create_conn(h3c);
    if (conn == NULL) {
        return XQC_OK;
    }
    xqc_h3_conn_callbacks_t app = conn->ctx->app_conn_callbacks;
    xqc_wt_conn_destroy(conn);
    return app.h3_conn_create_notify && app.h3_conn_close_notify
        ? app.h3_conn_close_notify(h3c, cid, data) : XQC_OK;
}

static void
xqc_wt_handshake_finished(xqc_h3_conn_t *h3c, void *data)
{
    xqc_wt_conn_t *conn = xqc_wt_create_conn(h3c);
    if (conn == NULL) {
        return;
    }
    if (conn->ctx->session_cbs.webtransport_conn_handshake_finished_notify) {
        conn->ctx->session_cbs.webtransport_conn_handshake_finished_notify(
            h3c, xqc_h3_conn_get_user_data(h3c));
    }
    if (conn->ctx->app_conn_callbacks.h3_conn_handshake_finished) {
        conn->ctx->app_conn_callbacks.h3_conn_handshake_finished(h3c, data);
    }
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
    if (xqc_wt_ctx_get(engine)) {
        return -XQC_ESTATE;
    }
    xqc_h3_ctx_t *h3 = xqc_engine_get_alpn_ctx(engine, XQC_ALPN_H3,
                                             strlen(XQC_ALPN_H3));
    if (h3 == NULL) {
        xqc_h3_callbacks_t callbacks = {0};
        xqc_int_t ret = xqc_h3_ctx_init(engine, &callbacks);
        if (ret != XQC_OK) {
            return ret;
        }
        h3 = xqc_engine_get_alpn_ctx(engine, XQC_ALPN_H3,
                                     strlen(XQC_ALPN_H3));
    }
    /* Existing ALPN cleanup frees this single WT-owned allocation. */
    xqc_wt_registration_t *registration = xqc_calloc(1,
                                                    sizeof(*registration));
    if (registration == NULL) {
        return -XQC_EMALLOC;
    }
    registration->h3 = *h3;
    xqc_wt_ctx_t *ctx = &registration->wt;
    ctx->app_conn_callbacks = h3->h3_cbs.h3c_cbs;
    registration->h3.h3_cbs.h3c_cbs.h3_conn_create_notify =
        xqc_wt_h3_conn_create;
    registration->h3.h3_cbs.h3c_cbs.h3_conn_close_notify =
        xqc_wt_h3_conn_close;
    registration->h3.h3_cbs.h3c_cbs.h3_conn_handshake_finished =
        xqc_wt_handshake_finished;
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
    xqc_app_proto_callbacks_t callbacks = {
        .conn_cbs = h3_conn_callbacks,
        .stream_cbs = xqc_wt_h3_stream_callbacks,
    };
    xqc_wt_dgram_callbacks(&callbacks.dgram_cbs);
    xqc_int_t ret = xqc_engine_register_alpn(engine, XQC_ALPN_H3,
        strlen(XQC_ALPN_H3), &callbacks, registration);
    if (ret != XQC_OK) {
        xqc_free(registration);
        return ret;
    }
    xqc_free(h3);
    return XQC_OK;
}

xqc_int_t
xqc_wt_engine_set_default_settings(xqc_engine_t *engine,
    const xqc_webtransport_conn_settings_t *settings)
{
    xqc_wt_ctx_t *ctx = xqc_wt_ctx_get(engine);
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
    xqc_wt_ctx_t *ctx = xqc_wt_ctx_get(engine);
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
