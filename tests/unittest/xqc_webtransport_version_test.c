/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include <CUnit/CUnit.h>
#include "xqc_common_test.h"
#include "xqc_webtransport_version_test.h"
#include "src/webtransport/xqc_webtransport_ctx.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/webtransport/xqc_webtransport_request_adapter.h"
#include "src/http3/xqc_h3_ctx.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_request.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"

#define WT_TEST_SETTING_07 UINT64_C(0xc671706a)
#define WT_TEST_SETTING_16 UINT64_C(0x2c7cf000)

static int version_creates, version_closes, version_accepts;
static xqc_http_headers_t *version_response;
static xqc_log_t version_log;

static xqc_wt_conn_t *version_conn(xqc_wt_ctx_t *ctx,
    xqc_h3_conn_t *h3c, xqc_connection_t *transport,
    xqc_webtransport_draft_version_t version);
static void version_peer_settings(xqc_wt_conn_t *conn,
    xqc_bool_t draft07, xqc_bool_t draft16);
static xqc_h3_conn_t *version_engine(
    xqc_webtransport_draft_version_t version, xqc_bool_t client);
static xqc_h3_conn_t *version_engine_sessions(
    xqc_webtransport_draft_version_t version, xqc_bool_t client,
    uint64_t max_sessions);
static xqc_h3_request_t *version_request(xqc_h3_conn_t *h3c,
    const char *protocol);
static void version_headers(xqc_h3_request_t *request,
    const char **names, const char **values, size_t count);
static xqc_wt_session_t *version_capsule_session(xqc_wt_ctx_t *ctx,
    xqc_h3_conn_t *h3c, xqc_connection_t *transport);
static void version_client_response(const char *status);
static void version_protocol_response(const char *value,
    const char *expected, xqc_bool_t duplicate);
static int version_accept(xqc_http_headers_t *headers,
    xqc_http_headers_t *response, void *data);
static int version_created(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *data);
static int version_closed(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *data);

static int
version_accept(xqc_http_headers_t *headers, xqc_http_headers_t *response,
    void *data)
{
    version_accepts++;
    if (version_response) {
        *response = *version_response;
    }
    return 1;
}

void
xqc_test_wt_server_response_status(void)
{
    /* RFC 9114 Sections 4.3, 4.3.2; draft-16 Section 3.2. */
    const char *values[] = {"200", "201", "299", "403", "2ab", "20", "600",
                           "100", "200", "200", "200", "200"};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        xqc_h3_conn_t *h3c = version_engine(
            XQC_WEBTRANSPORT_DRAFT_VERSION_16, XQC_FALSE);
        CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
        xqc_wt_conn_t *conn = xqc_wt_get_conn_from_h3(h3c);
        version_peer_settings(conn, XQC_FALSE, XQC_TRUE);
        xqc_http_header_t fields[2] = {
            {.name = {(void *)":status", 7},
             .value = {(void *)values[i], strlen(values[i])}},
            {.name = {(void *)":status", 7}, .value = {(void *)"200", 3}},
        };
        xqc_http_headers_t response = {
            .headers = fields, .count = i >= 8 ? i == 9 ? 0 : 2 : 1,
        };
        if (i >= 10) {
            fields[1].name.iov_base = i == 10 ? (void *)":method"
                                             : (void *)":unknown";
            fields[1].name.iov_len = i == 10 ? 7 : 8;
        }
        version_response = &response;
        xqc_h3_request_t *request = version_request(h3c, "webtransport-h3");
        CU_ASSERT_PTR_NOT_NULL_FATAL(request);
        CU_ASSERT(xqc_h3_request_on_recv_header(request) == XQC_OK);
        version_response = NULL;
        xqc_wt_session_t *session = xqc_wt_conn_find_session(
            conn, request->h3_stream->stream_id);
        CU_ASSERT_PTR_NOT_NULL_FATAL(session);
        CU_ASSERT(version_creates == (i < 3));
        CU_ASSERT(session->open == (i < 3));
        if (i < 4) {
            CU_ASSERT(xqc_wt_session_get_response_status(session)
                      == (unsigned)atoi(values[i]));
        } else {
            CU_ASSERT(session->closed);
            CU_ASSERT(session->close_error == H3_INTERNAL_ERROR);
            CU_ASSERT(request->header_sent == 0);
        }
        xqc_engine_destroy(h3c->conn->engine);
    }
}

void
xqc_test_wt_pending_session_limit(void)
{
    /* Count pending CONNECTs even before peer SETTINGS (draft-16 §5.1). */
    xqc_h3_conn_t *h3c = version_engine(
        XQC_WEBTRANSPORT_DRAFT_VERSION_16, XQC_FALSE);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
    xqc_wt_conn_t *conn = xqc_wt_get_conn_from_h3(h3c);
    xqc_h3_request_t *first = version_request(h3c, "webtransport-h3");
    xqc_h3_request_t *second = version_request(h3c, "webtransport-h3");
    CU_ASSERT_PTR_NOT_NULL_FATAL(first);
    CU_ASSERT_PTR_NOT_NULL_FATAL(second);
    CU_ASSERT(xqc_h3_request_on_recv_header(first) == XQC_OK);
    CU_ASSERT(xqc_h3_request_on_recv_header(second) == XQC_OK);
    CU_ASSERT(conn->session_count == 1 && version_creates == 0);
    CU_ASSERT_PTR_NULL(xqc_wt_conn_find_session(
        conn, second->h3_stream->stream_id));
    CU_ASSERT(second->h3_stream->stream->stream_err == H3_REQUEST_REJECTED);
    version_peer_settings(conn, XQC_FALSE, XQC_TRUE);
    CU_ASSERT(version_creates == 1);
    xqc_wt_session_notify_closed(xqc_wt_conn_find_session(
        conn, first->h3_stream->stream_id));
    xqc_h3_request_t *third = version_request(h3c, "webtransport-h3");
    CU_ASSERT_PTR_NOT_NULL_FATAL(third);
    CU_ASSERT(xqc_h3_request_on_recv_header(third) == XQC_OK);
    CU_ASSERT(version_creates == 2);
    xqc_engine_destroy(h3c->conn->engine);
}

static int
version_created(xqc_wt_session_t *session, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *data)
{
    version_creates++;
    CU_ASSERT(session->open);
    CU_ASSERT(!session->closed);
    return XQC_OK;
}

static int
version_closed(xqc_wt_session_t *session, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *data)
{
    CU_ASSERT_PTR_NULL(headers);
    version_closes++;
    CU_ASSERT(session->closed);
    return XQC_OK;
}

static xqc_wt_conn_t *
version_conn(xqc_wt_ctx_t *ctx, xqc_h3_conn_t *h3c,
    xqc_connection_t *transport, xqc_webtransport_draft_version_t version)
{
    memset(ctx, 0, sizeof(*ctx));
    memset(h3c, 0, sizeof(*h3c));
    memset(transport, 0, sizeof(*transport));
    ctx->settings.draft_version = version;
    ctx->settings.max_sessions_count = 1;
    ctx->settings.enable_datagram = XQC_TRUE;
    h3c->conn = transport;
    h3c->log = &version_log;
    transport->log = &version_log;
    transport->conn_type = XQC_CONN_TYPE_SERVER;
    transport->local_settings.max_datagram_frame_size = 1200;
    transport->remote_settings.max_datagram_frame_size = 1200;
    transport->local_settings.reset_stream_at = XQC_TRUE;
    transport->remote_settings.reset_stream_at = XQC_TRUE;
    xqc_wt_conn_t *conn = xqc_wt_conn_create(h3c);
    if (conn) {
        conn->ctx = ctx;
    }
    return conn;
}

static void
version_peer_settings(xqc_wt_conn_t *conn, xqc_bool_t draft07,
    xqc_bool_t draft16)
{
    xqc_h3_setting_t settings[] = {
        {0x08, 1}, {0x33, 1}, {WT_TEST_SETTING_07, draft07},
        {WT_TEST_SETTING_16, draft16},
    };
    CU_ASSERT(xqc_wt_conn_peer_settings(conn->h3_conn, settings, 4, NULL)
              == XQC_H3_SETTINGS_ACCEPT);
}

void
xqc_test_wt_version_negotiation(void)
{
    /* Draft-16 Section 7.1: selection is independent of SETTINGS ordering. */
    for (unsigned order = 0; order < 2; order++) {
        xqc_wt_ctx_t ctx;
        xqc_h3_conn_t h3c;
        xqc_connection_t transport;
        xqc_wt_conn_t *conn = version_conn(&ctx, &h3c, &transport,
                                           XQC_WEBTRANSPORT_DRAFT_VERSION_16);
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        xqc_h3_setting_t settings[] = {
            {order ? WT_TEST_SETTING_07 : WT_TEST_SETTING_16, 1},
            {order ? WT_TEST_SETTING_16 : WT_TEST_SETTING_07, 1},
            {0x33, 1},
        };
        CU_ASSERT(!xqc_wt_conn_requirements_met(conn));
        CU_ASSERT(xqc_wt_conn_peer_settings(&h3c, settings, 3, NULL)
                  == XQC_H3_SETTINGS_ACCEPT);
        CU_ASSERT(conn->negotiated_version
                  == XQC_WEBTRANSPORT_DRAFT_VERSION_16);
        CU_ASSERT(xqc_wt_conn_requirements_met(conn));
        xqc_wt_session_t *session = xqc_wt_session_init(0, conn, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(session);
        CU_ASSERT(session->wt_conn->negotiated_version
                  == XQC_WEBTRANSPORT_DRAFT_VERSION_16);
        xqc_wt_conn_destroy(conn);
    }
}

void
xqc_test_wt_version_legacy(void)
{
    /* Draft-07 Sections 3.1, 6: highest revision, no reset dependency. */
    for (unsigned local = 0; local < 2; local++) {
        for (unsigned peer = 0; peer < 4; peer++) {
            xqc_wt_ctx_t ctx;
            xqc_h3_conn_t h3c;
            xqc_connection_t transport;
            xqc_wt_conn_t *conn = version_conn(&ctx, &h3c, &transport,
                local ? XQC_WEBTRANSPORT_DRAFT_VERSION_16
                      : XQC_WEBTRANSPORT_DRAFT_VERSION_7);
            CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
            transport.local_settings.reset_stream_at = XQC_FALSE;
            transport.remote_settings.reset_stream_at = XQC_FALSE;
            version_peer_settings(conn, peer & 1, (peer >> 1) & 1);
            unsigned selected = local && (peer & 2)
                ? XQC_WEBTRANSPORT_DRAFT_VERSION_16
                : (peer & 1) ? XQC_WEBTRANSPORT_DRAFT_VERSION_7 : 0;
            CU_ASSERT(conn->negotiated_version == selected);
            CU_ASSERT(xqc_wt_conn_requirements_met(conn)
                      == (selected == XQC_WEBTRANSPORT_DRAFT_VERSION_7));
            CU_ASSERT(!conn->flow_control_enabled);
            if (selected == XQC_WEBTRANSPORT_DRAFT_VERSION_7) {
                CU_ASSERT(h3c.flags & XQC_H3_CONN_FLAG_WEBTRANSPORT);
                transport.remote_settings.max_datagram_frame_size = 0;
                CU_ASSERT(!xqc_wt_conn_requirements_met(conn));
                transport.remote_settings.max_datagram_frame_size = 1200;
                transport.conn_type = XQC_CONN_TYPE_CLIENT;
                conn->peer_connect = XQC_FALSE;
                CU_ASSERT(!xqc_wt_conn_requirements_met(conn));
            }
            xqc_wt_conn_destroy(conn);
        }
    }
}

void
xqc_test_wt_version_prerequisites(void)
{
    /* Section 3: a selected draft-16 must not silently downgrade to 07. */
    for (int missing = 0; missing < 4; missing++) {
        xqc_wt_ctx_t ctx;
        xqc_memzero(&ctx, sizeof(ctx));
        xqc_h3_conn_t h3c = {0};
        xqc_connection_t transport;
        xqc_memzero(&transport, sizeof(transport));
        xqc_wt_conn_t *conn = version_conn(&ctx, &h3c, &transport,
                                           XQC_WEBTRANSPORT_DRAFT_VERSION_16);
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        if (missing == 0) {
            transport.local_settings.reset_stream_at = XQC_FALSE;
        } else if (missing == 1) {
            transport.remote_settings.reset_stream_at = XQC_FALSE;
        } else if (missing == 2) {
            transport.local_settings.max_datagram_frame_size = 0;
        } else {
            transport.remote_settings.max_datagram_frame_size = 0;
        }
        version_peer_settings(conn, XQC_TRUE, XQC_TRUE);
        CU_ASSERT(conn->negotiated_version
                  == XQC_WEBTRANSPORT_DRAFT_VERSION_16);
        CU_ASSERT(!xqc_wt_conn_requirements_met(conn));
        xqc_wt_conn_destroy(conn);
    }
    for (int missing_connect = 0; missing_connect < 2; missing_connect++) {
        xqc_wt_ctx_t ctx;
        xqc_memzero(&ctx, sizeof(ctx));
        xqc_h3_conn_t h3c = {0};
        xqc_connection_t transport;
        xqc_memzero(&transport, sizeof(transport));
        xqc_wt_conn_t *conn = version_conn(&ctx, &h3c, &transport,
                                           XQC_WEBTRANSPORT_DRAFT_VERSION_16);
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        transport.conn_type = XQC_CONN_TYPE_CLIENT;
        xqc_h3_setting_t settings[] = {
            {0x08, !missing_connect},
            {0x33, missing_connect},
            {WT_TEST_SETTING_16, 1},
        };
        CU_ASSERT(xqc_wt_conn_peer_settings(
            &h3c, settings, sizeof(settings) / sizeof(settings[0]), NULL)
            == XQC_H3_SETTINGS_ACCEPT);
        CU_ASSERT(conn->negotiated_version
                  == XQC_WEBTRANSPORT_DRAFT_VERSION_16);
        CU_ASSERT(!xqc_wt_conn_requirements_met(conn));
        xqc_wt_conn_destroy(conn);
    }
}

void
xqc_test_wt_version_settings_errors(void)
{
    const uint64_t ids[] = {WT_TEST_SETTING_16, 0x33, 0x08,
                            0x2b64, 0x2b65};
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        xqc_wt_ctx_t ctx;
        xqc_h3_conn_t h3c;
        xqc_connection_t transport;
        xqc_wt_conn_t *conn = version_conn(&ctx, &h3c, &transport,
                                           XQC_WEBTRANSPORT_DRAFT_VERSION_16);
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        xqc_h3_setting_t settings[] = {
            {0x33, 1}, {WT_TEST_SETTING_16, 1},
            {ids[i], i < 3 ? 2 : (UINT64_C(1) << 60) + 1},
        };
        CU_ASSERT(xqc_wt_conn_peer_settings(&h3c, settings, 3, NULL)
                  == XQC_H3_SETTINGS_REJECT);
        CU_ASSERT(!conn->settings_received && !conn->peer_datagram);
        CU_ASSERT(!conn->peer_draft16 && !conn->negotiated_version);
        xqc_wt_conn_destroy(conn);
    }
}

static xqc_h3_conn_t *
version_engine(xqc_webtransport_draft_version_t version, xqc_bool_t client)
{
    return version_engine_sessions(version, client, 1);
}

static xqc_h3_conn_t *
version_engine_sessions(xqc_webtransport_draft_version_t version,
    xqc_bool_t client, uint64_t max_sessions)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL(conn);
    if (!conn) {
        return NULL;
    }
    xqc_engine_t *engine = conn->engine;
    xqc_h3_callbacks_t app;
    xqc_memzero(&app, sizeof(app));
    xqc_webtransport_session_callbacks_t callbacks = {
        .webtransport_will_create_session_notify = version_accept,
        .webtransport_session_create_notify = version_created,
        .webtransport_session_close_notify = version_closed,
    };
    CU_ASSERT(xqc_h3_ctx_init(engine, &app) == XQC_OK);
    CU_ASSERT(xqc_wt_ctx_init(engine, NULL, &callbacks, NULL) == XQC_OK);
    xqc_webtransport_conn_settings_t settings =
        xqc_wt_ctx_get(engine)->settings;
    settings.draft_version = version;
    settings.max_sessions_count = max_sessions;
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, &settings) == XQC_OK);
    xqc_free(conn->alpn);
    conn->alpn = xqc_malloc(3);
    memcpy(conn->alpn, "h3", 3);
    conn->alpn_len = 2;
    CU_ASSERT(xqc_engine_get_alpn_callbacks(engine, "h3", 2,
                                            &conn->app_proto_cbs) == XQC_OK);
    conn->conn_type = client ? XQC_CONN_TYPE_CLIENT : XQC_CONN_TYPE_SERVER;
    conn->conn_flow_ctl.fc_max_streams_uni_can_send = 16;
    conn->conn_flow_ctl.fc_max_streams_bidi_can_send = 16;
    conn->local_settings.max_datagram_frame_size = 1200;
    conn->remote_settings.max_datagram_frame_size = 1200;
    conn->local_settings.reset_stream_at = XQC_TRUE;
    conn->remote_settings.reset_stream_at = XQC_TRUE;
    engine->config->manually_triggered_send = 1;
    xqc_h3_conn_t *h3c = xqc_h3_conn_create(conn, NULL);
    CU_ASSERT_PTR_NOT_NULL(h3c);
    if (!h3c) {
        xqc_engine_destroy(engine);
        return NULL;
    }
    conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST
        | XQC_CONN_FLAG_TLS_HSK_COMPLETED;
    h3c->qenc_stream = xqc_h3_conn_create_uni_stream(
        h3c, XQC_H3_STREAM_TYPE_QPACK_ENCODER);
    h3c->qdec_stream = xqc_h3_conn_create_uni_stream(
        h3c, XQC_H3_STREAM_TYPE_QPACK_DECODER);
    h3c->control_stream_out = xqc_h3_conn_create_uni_stream(
        h3c, XQC_H3_STREAM_TYPE_CONTROL);
    CU_ASSERT_PTR_NOT_NULL(h3c->qenc_stream);
    CU_ASSERT_PTR_NOT_NULL(h3c->qdec_stream);
    CU_ASSERT_PTR_NOT_NULL(h3c->control_stream_out);
    version_creates = version_closes = version_accepts = 0;
    return h3c;
}

void
xqc_test_wt_version_advertisement(void)
{
    /* Draft-07 Section 6 / draft-16 Section 7.1: advertise supported drafts. */
    for (int mode = 0; mode < 4; mode++) {
        int client = mode & 1, legacy = mode >> 1;
        xqc_h3_conn_t *h3c = version_engine(legacy
            ? XQC_WEBTRANSPORT_DRAFT_VERSION_7
            : XQC_WEBTRANSPORT_DRAFT_VERSION_16, client);
        CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
        xqc_h3_conn_settings_t *settings = &h3c->local_h3_conn_settings;
        unsigned found07 = 0, found16 = 0, datagram = 0, connect = 0;
        for (size_t i = 0; i < settings->extern_settings_count; i++) {
            uint64_t id = settings->extern_settings[i].identifier;
            CU_ASSERT(settings->extern_settings[i].value == 1);
            found07 += id == WT_TEST_SETTING_07;
            found16 += id == WT_TEST_SETTING_16;
            datagram += id == 0x33;
            connect += id == 0x08;
        }
        CU_ASSERT(found07 == 1 && found16 == !legacy && datagram == 1);
        CU_ASSERT(connect == !client);
        CU_ASSERT(settings->extern_settings_count
                  == (size_t)(4 - legacy - client));
        CU_ASSERT(h3c->conn->engine->default_conn_settings
                  .enable_reset_stream_at
                  == !legacy);
        xqc_engine_destroy(h3c->conn->engine);
    }
}

static void
version_headers(xqc_h3_request_t *request, const char **names,
    const char **values, size_t count)
{
    xqc_http_headers_t *headers = &request->h3_header[0];
    headers->headers = xqc_calloc(count, sizeof(xqc_http_header_t));
    headers->capacity = headers->count = count;
    for (size_t i = 0; i < count; i++) {
        xqc_http_header_t *header = &headers->headers[i];
        header->name.iov_len = strlen(names[i]);
        header->value.iov_len = strlen(values[i]);
        header->name.iov_base = xqc_malloc(header->name.iov_len);
        header->value.iov_base = xqc_malloc(header->value.iov_len);
        memcpy(header->name.iov_base, names[i], header->name.iov_len);
        memcpy(header->value.iov_base, values[i], header->value.iov_len);
        headers->total_len += header->name.iov_len + header->value.iov_len;
    }
}

void
xqc_test_wt_draft07_session_limits(void)
{
    /* Draft-07 Section 3.4: both local and peer limits constrain clients. */
    for (unsigned client = 0; client < 2; client++) {
        xqc_h3_conn_t *h3c = version_engine_sessions(
            XQC_WEBTRANSPORT_DRAFT_VERSION_16, client, client ? 3 : 2);
        CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
        xqc_wt_conn_t *conn = xqc_wt_get_conn_from_h3(h3c);
        h3c->conn->remote_settings.reset_stream_at = XQC_FALSE;
        xqc_h3_setting_t peer[] = {
            {0x08, 1}, {0x33, 1}, {WT_TEST_SETTING_07, 2},
            {XQC_WT_SETTING_INITIAL_MAX_DATA, 32},
        };
        CU_ASSERT(xqc_wt_conn_peer_settings(h3c, peer, 4, NULL)
                  == XQC_H3_SETTINGS_ACCEPT);
        CU_ASSERT(conn->negotiated_version == XQC_WEBTRANSPORT_DRAFT_VERSION_7);
        CU_ASSERT(!conn->flow_control_enabled);
        for (unsigned i = 0; i < 3; i++) {
            if (client) {
                int err;
                xqc_wt_session_t *session = xqc_wt_client_open_session(
                    h3c, "localhost", "/wt", "https://localhost", &err);
                CU_ASSERT((session != NULL) == (i < 2));
                if (session) {
                    CU_ASSERT(!session->flow_control && session->request_sent);
                } else {
                    CU_ASSERT(err == -XQC_ESTATE);
                }
            } else {
                xqc_h3_request_t *request =
                    version_request(h3c, "webtransport");
                CU_ASSERT_PTR_NOT_NULL_FATAL(request);
                CU_ASSERT(xqc_h3_request_on_recv_header(request) == XQC_OK);
                CU_ASSERT(version_creates == (i < 2 ? i + 1 : 2));
                CU_ASSERT(request->h3_stream->stream->stream_err
                          == (i < 2 ? 0 : H3_REQUEST_REJECTED));
            }
        }
        CU_ASSERT(xqc_wt_conn_active_session_count(conn) == 2);
        CU_ASSERT(h3c->conn->conn_err == 0);
        xqc_engine_destroy(h3c->conn->engine);
    }
}

void
xqc_test_wt_draft07_protocol_requirement(void)
{
    /* Draft-16 Section 3.3 negotiation is not part of draft-07. */
    for (unsigned ready = 0; ready < 2; ready++) {
        xqc_h3_conn_t *h3c = version_engine(
            XQC_WEBTRANSPORT_DRAFT_VERSION_16, XQC_TRUE);
        CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
        xqc_wt_conn_t *conn = xqc_wt_get_conn_from_h3(h3c);
        if (ready) {
            version_peer_settings(conn, XQC_TRUE, XQC_FALSE);
        }
        const char *protocols[] = {"required"};
        int err;
        xqc_wt_session_t *session = xqc_wt_client_open_session_with_protocols(
            h3c, "localhost", "/wt", "https://localhost", protocols, 1, &err);
        if (ready) {
            CU_ASSERT_PTR_NULL(session);
            CU_ASSERT(err == -XQC_ESTATE);
        } else {
            CU_ASSERT_PTR_NOT_NULL_FATAL(session);
            version_peer_settings(conn, XQC_TRUE, XQC_FALSE);
            CU_ASSERT(session->closed && !session->request_sent);
            CU_ASSERT(session->close_error == H3_REQUEST_REJECTED);
            CU_ASSERT(version_creates == 0 && version_closes == 1);
        }
        CU_ASSERT_PTR_NOT_NULL(xqc_wt_client_open_session(
            h3c, "localhost", "/wt", "https://localhost", &err));
        xqc_engine_destroy(h3c->conn->engine);
    }
}

static xqc_h3_request_t *
version_request(xqc_h3_conn_t *h3c, const char *protocol)
{
    xqc_stream_t *stream = xqc_create_stream_with_conn(
        h3c->conn, XQC_UNDEFINE_STREAM_ID, XQC_CLI_BID, NULL, NULL);
    if (!stream) {
        return NULL;
    }
    xqc_h3_stream_t *h3s = xqc_h3_stream_create(
        h3c, stream, XQC_H3_STREAM_TYPE_REQUEST, NULL);
    if (!h3s) {
        return NULL;
    }
    xqc_h3_request_t *request = xqc_h3_request_create_inner(h3c, h3s, NULL);
    h3s->h3r = request;
    if (request) {
        const char *names[] = {":method", ":protocol", ":scheme",
                               ":authority", ":path", "origin"};
        const char *values[] = {"CONNECT", protocol, "https", "localhost",
                                "/wt", "https://localhost"};
        version_headers(request, names, values, 6);
    }
    return request;
}

void
xqc_test_wt_response_pseudo_headers(void)
{
    /* RFC 9114 Section 4.3: only :status is a response pseudo-header. */
    const char *fields[] = {"server", ":method", ":unknown"};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        xqc_h3_conn_t *h3c = version_engine(
            XQC_WEBTRANSPORT_DRAFT_VERSION_16, XQC_TRUE);
        CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
        int err = 0;
        xqc_wt_session_t *session = xqc_wt_client_open_session(
            h3c, "localhost", "/wt", NULL, &err);
        CU_ASSERT_PTR_NOT_NULL_FATAL(session);
        version_peer_settings(session->wt_conn, XQC_FALSE, XQC_TRUE);
        const char *names[] = {":status", fields[i]};
        const char *values[] = {"200", "value"};
        version_headers(session->request, names, values, 2);
        CU_ASSERT(xqc_h3_request_on_recv_header(session->request) == XQC_OK);
        CU_ASSERT(session->open == (i == 0));
        CU_ASSERT(session->closed == (i != 0));
        CU_ASSERT(session->close_error == (i == 0 ? 0 : H3_MESSAGE_ERROR));
        CU_ASSERT(version_creates == (i == 0));
        xqc_engine_destroy(h3c->conn->engine);
    }
}

void
xqc_test_wt_connect_pseudo_headers(void)
{
    /* RFC 9114 Section 4.3 and draft-16 Section 3.2 apply before acceptance. */
    const char *names[] = {
        "origin", ":method", ":protocol", ":scheme", ":authority", ":path",
        ":method", ":protocol", ":scheme", ":authority", ":path",
        ":status", ":unknown",
    };
    const char *values[] = {
        "https://localhost", "CONNECT", "webtransport-h3", "https",
        "localhost", "/wt", "GET", "websocket", "http", "", "",
        "200", "ignored",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        xqc_h3_conn_t *h3c = version_engine(
            XQC_WEBTRANSPORT_DRAFT_VERSION_16, XQC_FALSE);
        CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
        xqc_wt_conn_t *conn = xqc_wt_get_conn_from_h3(h3c);
        version_peer_settings(conn, XQC_TRUE, XQC_TRUE);
        xqc_h3_request_t *request = version_request(h3c, "webtransport-h3");
        CU_ASSERT_PTR_NOT_NULL_FATAL(request);
        xqc_http_header_t *field = &request->h3_header[0].headers[5];
        xqc_free(field->name.iov_base);
        xqc_free(field->value.iov_base);
        field->name.iov_len = strlen(names[i]);
        field->value.iov_len = strlen(values[i]);
        field->name.iov_base = xqc_malloc(field->name.iov_len + 1);
        field->value.iov_base = xqc_malloc(field->value.iov_len + 1);
        CU_ASSERT_PTR_NOT_NULL_FATAL(field->name.iov_base);
        CU_ASSERT_PTR_NOT_NULL_FATAL(field->value.iov_base);
        memcpy(field->name.iov_base, names[i], field->name.iov_len + 1);
        memcpy(field->value.iov_base, values[i], field->value.iov_len + 1);
        CU_ASSERT(xqc_h3_request_on_recv_header(request) == XQC_OK);
        CU_ASSERT(version_accepts == (i == 0));
        CU_ASSERT(version_creates == (i == 0));
        CU_ASSERT(request->h3_stream->stream->stream_err
                  == (i == 0 ? 0 : H3_MESSAGE_ERROR));
        xqc_engine_destroy(h3c->conn->engine);
    }
}

void
xqc_test_wt_version_connect_tokens(void)
{
    /* Draft-07 Section 3.3 / draft-16 Section 3.2: distinct tokens. */
    for (int mode = 0; mode < 4; mode++) {
        int correct = mode & 1, legacy = mode >> 1;
        xqc_h3_conn_t *h3c = version_engine(legacy
            ? XQC_WEBTRANSPORT_DRAFT_VERSION_7
            : XQC_WEBTRANSPORT_DRAFT_VERSION_16, XQC_FALSE);
        CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
        xqc_wt_conn_t *conn = xqc_wt_get_conn_from_h3(h3c);
        version_peer_settings(conn, XQC_TRUE, XQC_TRUE);
        xqc_h3_request_t *request = version_request(
            h3c, correct != legacy ? "webtransport-h3" : "webtransport");
        CU_ASSERT_PTR_NOT_NULL_FATAL(request);
        CU_ASSERT(xqc_h3_request_on_recv_header(request) == XQC_OK);
        CU_ASSERT(version_creates == correct && version_accepts == correct);
        xqc_wt_session_t *session = xqc_wt_conn_find_session(
            conn, request->h3_stream->stream_id);
        if (correct) {
            CU_ASSERT_PTR_NOT_NULL_FATAL(session);
            CU_ASSERT(session->open && !session->closed);
        } else {
            CU_ASSERT_PTR_NOT_NULL_FATAL(session);
            CU_ASSERT(session->closed && !session->open);
            CU_ASSERT(session->close_error == H3_MESSAGE_ERROR);
        }
        xqc_engine_destroy(h3c->conn->engine);
    }
}

static xqc_wt_session_t *
version_capsule_session(xqc_wt_ctx_t *ctx, xqc_h3_conn_t *h3c,
    xqc_connection_t *transport)
{
    xqc_wt_conn_t *conn = version_conn(ctx, h3c, transport,
                                       XQC_WEBTRANSPORT_DRAFT_VERSION_16);
    if (!conn) {
        return NULL;
    }
    version_peer_settings(conn, XQC_FALSE, XQC_TRUE);
    xqc_wt_session_t *session = xqc_wt_session_init(0, conn, NULL);
    if (session) {
        session->open = XQC_TRUE;
    }
    return session;
}

void
xqc_test_wt_draft16_close_utf8(void)
{
    xqc_wt_ctx_t ctx;
    xqc_memzero(&ctx, sizeof(ctx));
    xqc_h3_conn_t h3c = {0};
    xqc_connection_t transport;
    xqc_memzero(&transport, sizeof(transport));
    xqc_wt_session_t *session = version_capsule_session(&ctx, &h3c,
                                                        &transport);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    /* Section 6: UTF-8 reason, including a split multibyte sequence. */
    const unsigned char capsule[] = {0x68, 0x43, 11, 0, 0, 0, 9,
        0xe4, 0xb8, 0xad, 0xf0, 0x9f, 0x8c, 0x8d};
    for (size_t i = 0; i < sizeof(capsule); i++) {
        CU_ASSERT(xqc_wt_session_recv_capsules(
            session, capsule + i, 1, i == sizeof(capsule) - 1) == XQC_OK);
    }
    CU_ASSERT(session->closed);
    CU_ASSERT(xqc_wt_session_get_close_error_code(session) == 9);
    CU_ASSERT(memcmp(xqc_wt_session_get_close_reason(session),
                     capsule + 7, 7) == 0);
    CU_ASSERT(xqc_wt_session_get_close_reason(session)[7] == '\0');
    CU_ASSERT(xqc_wt_session_recv_capsules(
        session, (const unsigned char *)"x", 1, 0) == -XQC_H3_DECODE_ERROR);
    xqc_wt_conn_destroy(session->wt_conn);
}

void
xqc_test_wt_draft16_peer_close_response(void)
{
    /* draft-ietf-webtrans-http3-16 Section 6: respond before peer FIN. */
    xqc_webtransport_draft_version_t version =
        XQC_WEBTRANSPORT_DRAFT_VERSION_16;
    xqc_h3_conn_t *h3c = version_engine(version, XQC_TRUE);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
    int err = -1;
    xqc_wt_session_t *session = xqc_wt_client_open_session(
        h3c, "localhost", "/wt", "https://localhost", &err);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    version_peer_settings(session->wt_conn, XQC_FALSE, XQC_TRUE);
    CU_ASSERT(h3c->flags & XQC_H3_CONN_FLAG_WEBTRANSPORT);
    const char *names[] = {":status"};
    const char *values[] = {"200"};
    version_headers(session->request, names, values, 1);
    CU_ASSERT(xqc_h3_request_on_recv_header(session->request) == XQC_OK);
    CU_ASSERT(session->open);
    h3c->conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    unsigned char close[] = {0x68, 0x43, 4, 0, 0, 0, 7};
    CU_ASSERT(xqc_wt_session_recv_capsules(session, close,
                                           sizeof(close), XQC_FALSE) == XQC_OK);
    CU_ASSERT(session->peer_closed && session->closed);
    CU_ASSERT(session->close_error == 7);
    xqc_bool_t fin_sent = (session->request->h3_stream->flags
        & XQC_HTTP3_STREAM_FLAG_FIN_SENT) != 0;
    CU_ASSERT(fin_sent);
    CU_ASSERT(!session->send_fin);
    CU_ASSERT(xqc_wt_session_recv_capsules(session, close, 1, XQC_FALSE)
              == -XQC_H3_DECODE_ERROR);
    xqc_engine_destroy(h3c->conn->engine);
}

void
xqc_test_wt_draft16_close_utf8_errors(void)
{
    const unsigned char invalid[][4] = {
        {0xc0, 0xaf}, {0x80}, {0xed, 0xa0, 0x80},
        {0xf4, 0x90, 0x80, 0x80}, {0xe2, 0x82},
    };
    const size_t lengths[] = {2, 1, 3, 4, 2};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        xqc_wt_ctx_t ctx;
        xqc_memzero(&ctx, sizeof(ctx));
        xqc_h3_conn_t h3c = {0};
        xqc_connection_t transport;
        xqc_memzero(&transport, sizeof(transport));
        xqc_wt_session_t *session = version_capsule_session(&ctx, &h3c,
                                                            &transport);
        CU_ASSERT_PTR_NOT_NULL_FATAL(session);
        CU_ASSERT(xqc_wt_session_close_with_error(
            session, 0, (const char *)invalid[i], lengths[i]) == -XQC_EPARAM);
        CU_ASSERT(!session->closed && session->send_len == 0);
        unsigned char capsule[11] = {0x68, 0x43, 0, 0, 0, 0, 0};
        capsule[2] = 4 + lengths[i];
        memcpy(capsule + 7, invalid[i], lengths[i]);
        CU_ASSERT(xqc_wt_session_recv_capsules(
            session, capsule, 7 + lengths[i], 1) == -XQC_H3_DECODE_ERROR);
        xqc_wt_conn_destroy(session->wt_conn);
    }

    /*
     * http3-16 Section 5.4 prohibits the per-stream HTTP/2 capsules;
     * http2-14 Sections 6.6 and 6.9 define their codepoints.
     */
    const uint64_t forbidden[] = {0x190b4d3e, 0x190b4d42};
    for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
        xqc_wt_ctx_t ctx;
        xqc_h3_conn_t h3c;
        xqc_connection_t transport;
        xqc_wt_session_t *session =
            version_capsule_session(&ctx, &h3c, &transport);
        CU_ASSERT_PTR_NOT_NULL_FATAL(session);
        unsigned char capsule[16];
        size_t n = xqc_wt_put_varint(forbidden[i], capsule,
                                     sizeof(capsule));
        capsule[n++] = 2;
        capsule[n++] = 0;
        capsule[n++] = 1;
        CU_ASSERT(xqc_wt_session_recv_capsules(session, capsule, n, 0)
            == -XQC_H3_DECODE_ERROR);
        xqc_wt_conn_destroy(session->wt_conn);
    }
}

void
xqc_test_wt_draft16_drain_streams(void)
{
    xqc_h3_conn_t *h3c = version_engine(XQC_WEBTRANSPORT_DRAFT_VERSION_16,
                                        XQC_FALSE);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
    xqc_wt_conn_t *conn = xqc_wt_get_conn_from_h3(h3c);
    version_peer_settings(conn, XQC_TRUE, XQC_TRUE);
    xqc_wt_session_t *session = xqc_wt_session_init(0, conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    session->open = XQC_TRUE;
    /* Section 5.1: no negotiated session flow control, so ignore capsules. */
    const uint64_t types[] = {0x190b4d3d, 0x190b4d3f, 0x190b4d40,
                              0x190b4d41, 0x190b4d43, 0x190b4d44};
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        unsigned char capsule[16];
        size_t n = xqc_wt_put_varint(types[i], capsule, sizeof(capsule));
        capsule[n++] = 1;
        capsule[n++] = 0;
        CU_ASSERT(xqc_wt_session_recv_capsules(session, capsule, n, 0)
                  == XQC_OK);
        CU_ASSERT(!session->closed);
    }
    /* Section 4.7: draining a session does not prohibit its data streams. */
    const unsigned char drain[] = {0x80, 0x00, 0x78, 0xae, 0};
    CU_ASSERT(xqc_wt_session_recv_capsules(session, drain, sizeof(drain), 0)
              == XQC_OK);
    CU_ASSERT(session->draining && !session->closed);
    int err = -1;
    xqc_wt_unistream_t *uni =
        xqc_wt_session_create_uni_stream(session, NULL, &err);
    CU_ASSERT_PTR_NOT_NULL(uni);
    CU_ASSERT(err == XQC_OK);
    xqc_engine_destroy(h3c->conn->engine);
}

void
xqc_test_wt_draft16_session_limit(void)
{
    xqc_h3_conn_t *h3c = version_engine(XQC_WEBTRANSPORT_DRAFT_VERSION_16,
                                        XQC_FALSE);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
    xqc_wt_conn_t *conn = xqc_wt_get_conn_from_h3(h3c);
    version_peer_settings(conn, XQC_TRUE, XQC_TRUE);
    xqc_h3_request_t *first = version_request(h3c, "webtransport-h3");
    CU_ASSERT_PTR_NOT_NULL_FATAL(first);
    CU_ASSERT(xqc_h3_request_on_recv_header(first) == XQC_OK);
    CU_ASSERT(version_creates == 1);
    xqc_h3_request_t *second = version_request(h3c, "webtransport-h3");
    CU_ASSERT_PTR_NOT_NULL_FATAL(second);
    CU_ASSERT(xqc_h3_request_on_recv_header(second) == XQC_OK);
    CU_ASSERT(version_creates == 1);
    CU_ASSERT(second->h3_stream->stream->stream_err == H3_REQUEST_REJECTED);
    xqc_wt_session_t *original = xqc_wt_conn_find_session(
        conn, first->h3_stream->stream_id);
    xqc_wt_session_t *rejected = xqc_wt_conn_find_session(
        conn, second->h3_stream->stream_id);
    CU_ASSERT_PTR_NOT_NULL_FATAL(original);
    CU_ASSERT_PTR_NULL(rejected);
    CU_ASSERT(original->open && !original->closed);
    xqc_engine_destroy(h3c->conn->engine);
}

void
xqc_test_wt_request_failure_after_transport_close(void)
{
    for (unsigned detached = 0; detached < 2; detached++) {
        xqc_h3_conn_t *h3c = version_engine(
            XQC_WEBTRANSPORT_DRAFT_VERSION_16, XQC_TRUE);
        CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
        xqc_wt_conn_t *conn = xqc_wt_get_conn_from_h3(h3c);
        version_peer_settings(conn, XQC_FALSE, XQC_TRUE);
        int err;
        xqc_wt_session_t *session = xqc_wt_client_open_session(
            h3c, "localhost", "/wt", NULL, &err);
        CU_ASSERT_PTR_NOT_NULL_FATAL(session);
        xqc_h3_stream_t *h3s = session->request->h3_stream;
        xqc_stream_t *stream = h3s->stream;
        uint64_t id = session->session_id;
        if (detached) {
            /* H3 retains a complete but QPACK-blocked response. */
            h3s->flags |= XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED
                | XQC_HTTP3_STREAM_FLAG_READ_EOF;
            CU_ASSERT(h3_stream_callbacks.stream_close_notify(stream, h3s)
                      == XQC_OK);
            CU_ASSERT_PTR_NULL(h3s->stream);
            stream->stream_flag |= XQC_STREAM_FLAG_DISCARDED;
            xqc_destroy_stream(stream);
        }
        xqc_wt_request_fail(session, H3_MESSAGE_ERROR);
        CU_ASSERT(session->closed && session->close_notified);
        CU_ASSERT(session->close_error == H3_MESSAGE_ERROR);
        CU_ASSERT(version_closes == 1);
        CU_ASSERT_PTR_EQUAL(xqc_wt_conn_find_session(conn, id), session);
        if (detached) {
            h3s->flags &= ~XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED;
            xqc_h3_stream_destroy(h3s);
            CU_ASSERT_PTR_NULL(xqc_wt_conn_find_session(conn, id));
        } else {
            CU_ASSERT(stream->stream_err == H3_MESSAGE_ERROR);
        }
        xqc_engine_destroy(h3c->conn->engine);
        CU_ASSERT(version_closes == 1);
    }
}

void
xqc_test_wt_configured_session_limit(void)
{
    /* Draft-16 Section 5.1: the local policy counts active pooled sessions. */
    xqc_h3_conn_t *h3c = version_engine_sessions(
        XQC_WEBTRANSPORT_DRAFT_VERSION_16, XQC_FALSE, 65);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
    h3c->conn->conn_flow_ctl.fc_max_streams_bidi_can_send = 128;
    xqc_wt_conn_t *conn = xqc_wt_get_conn_from_h3(h3c);
    xqc_h3_setting_t settings[] = {
        {0x33, 1}, {WT_TEST_SETTING_16, 1},
        {0x2b64, 2}, {0x2b65, 2}, {0x2b61, 4096},
    };
    CU_ASSERT(xqc_wt_conn_peer_settings(
        h3c, settings, sizeof(settings) / sizeof(settings[0]), NULL)
        == XQC_H3_SETTINGS_ACCEPT);
    CU_ASSERT(conn->flow_control_enabled);
    xqc_wt_session_t *first = NULL;
    for (unsigned i = 0; i < 66; i++) {
        xqc_h3_request_t *request = version_request(h3c, "webtransport-h3");
        CU_ASSERT_PTR_NOT_NULL_FATAL(request);
        CU_ASSERT(xqc_h3_request_on_recv_header(request) == XQC_OK);
        xqc_wt_session_t *session = xqc_wt_conn_find_session(
            conn, request->h3_stream->stream_id);
        if (i < 65) {
            CU_ASSERT_PTR_NOT_NULL_FATAL(session);
            CU_ASSERT(session->open && !session->closed);
            if (!i) {
                first = session;
            }
        } else {
            CU_ASSERT_PTR_NULL(session);
            CU_ASSERT(request->h3_stream->stream->stream_err
                      == H3_REQUEST_REJECTED);
        }
    }
    CU_ASSERT(version_creates == 65 && conn->session_count == 65);
    xqc_wt_session_notify_closed(first);
    CU_ASSERT(conn->session_count == 65);
    CU_ASSERT(xqc_wt_conn_active_session_count(conn) == 64);
    xqc_h3_request_t *request = version_request(h3c, "webtransport-h3");
    CU_ASSERT_PTR_NOT_NULL_FATAL(request);
    CU_ASSERT(xqc_h3_request_on_recv_header(request) == XQC_OK);
    CU_ASSERT(version_creates == 66 && conn->session_count == 66);
    CU_ASSERT(xqc_wt_conn_active_session_count(conn) == 65);
    xqc_engine_destroy(h3c->conn->engine);
}

void
xqc_test_wt_draft16_pooled_sessions(void)
{
    /* draft-ietf-webtrans-http3-16 §§3.2, 5.1, 5.5, 6. */
    xqc_h3_conn_t *h3c = version_engine_sessions(
        XQC_WEBTRANSPORT_DRAFT_VERSION_16, XQC_FALSE, 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
    xqc_wt_conn_t *conn = xqc_wt_get_conn_from_h3(h3c);
    CU_ASSERT(h3c->local_h3_conn_settings.extern_settings_count == 7);
    xqc_h3_setting_t settings[] = {
        {0x08, 1},
        {0x33, 1},
        {WT_TEST_SETTING_16, 1},
        {0x2b64, 2},
        {0x2b65, 2},
        {0x2b61, 4096},
    };
    CU_ASSERT(xqc_wt_conn_peer_settings(
        h3c, settings, sizeof(settings) / sizeof(settings[0]), NULL)
        == XQC_H3_SETTINGS_ACCEPT);
    CU_ASSERT(conn->flow_control_enabled);

    xqc_h3_request_t *first = version_request(h3c, "webtransport-h3");
    xqc_h3_request_t *second = version_request(h3c, "webtransport-h3");
    CU_ASSERT_PTR_NOT_NULL_FATAL(first);
    CU_ASSERT_PTR_NOT_NULL_FATAL(second);
    CU_ASSERT(xqc_h3_request_on_recv_header(first) == XQC_OK);
    CU_ASSERT(xqc_h3_request_on_recv_header(second) == XQC_OK);
    xqc_wt_session_t *a = xqc_wt_conn_find_session(conn,
                                                   first->h3_stream->stream_id);
    xqc_wt_session_t *b = xqc_wt_conn_find_session(
        conn, second->h3_stream->stream_id);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(b);
    CU_ASSERT_PTR_NOT_EQUAL(a, b);
    CU_ASSERT(a->open && b->open && a->flow_control && b->flow_control);
    CU_ASSERT(a->send_stream_limit[1] == 2);
    CU_ASSERT(b->send_stream_limit[1] == 2);
    CU_ASSERT(version_creates == 2 && conn->session_count == 2);
    xqc_wt_session_notify_closed(a);
    CU_ASSERT(a->closed && b->open && !b->closed);
    CU_ASSERT(xqc_wt_conn_find_session(conn, b->session_id) == b);
    CU_ASSERT(xqc_wt_session_is_writable(b));
    CU_ASSERT(xqc_wt_conn_active_session_count(conn) == 1);
    xqc_h3_request_t *third = version_request(h3c, "webtransport-h3");
    CU_ASSERT_PTR_NOT_NULL_FATAL(third);
    CU_ASSERT(xqc_h3_request_on_recv_header(third) == XQC_OK);
    CU_ASSERT(version_creates == 3);
    CU_ASSERT(xqc_wt_conn_active_session_count(conn) == 2);
    xqc_engine_destroy(h3c->conn->engine);
}

void
xqc_test_wt_draft16_pooling_requires_flow_control(void)
{
    /* draft-ietf-webtrans-http3-16 §5.1: either peer may decline pooling. */
    xqc_h3_conn_t *h3c = version_engine_sessions(
        XQC_WEBTRANSPORT_DRAFT_VERSION_16, XQC_FALSE, 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
    xqc_wt_conn_t *conn = xqc_wt_get_conn_from_h3(h3c);
    version_peer_settings(conn, XQC_TRUE, XQC_TRUE);
    CU_ASSERT(!conn->flow_control_enabled);
    xqc_h3_request_t *first = version_request(h3c, "webtransport-h3");
    xqc_h3_request_t *second = version_request(h3c, "webtransport-h3");
    CU_ASSERT_PTR_NOT_NULL_FATAL(first);
    CU_ASSERT_PTR_NOT_NULL_FATAL(second);
    CU_ASSERT(xqc_h3_request_on_recv_header(first) == XQC_OK);
    CU_ASSERT(xqc_h3_request_on_recv_header(second) == XQC_OK);
    CU_ASSERT(version_creates == 1);
    CU_ASSERT(second->h3_stream->stream->stream_err == H3_REQUEST_REJECTED);
    CU_ASSERT(xqc_wt_conn_find_session(conn, first->h3_stream->stream_id)
              ->open);
    xqc_engine_destroy(h3c->conn->engine);
}

void
xqc_test_wt_draft16_flow_capsules(void)
{
    /* draft-ietf-webtrans-http3-16 §§5.6.2, 5.6.4: per-session updates. */
    xqc_wt_ctx_t ctx;
    xqc_memzero(&ctx, sizeof(ctx));
    xqc_h3_conn_t h3c = {0};
    xqc_connection_t transport;
    xqc_memzero(&transport, sizeof(transport));
    xqc_wt_conn_t *conn = version_conn(&ctx, &h3c, &transport,
                                       XQC_WEBTRANSPORT_DRAFT_VERSION_16);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    ctx.settings.max_sessions_count = 2;
    ctx.settings.max_bidi_streams = 2;
    ctx.settings.max_uni_streams = 2;
    ctx.settings.init_recv_window = 32;
    xqc_h3_setting_t settings[] = {
        {WT_TEST_SETTING_16, 1},
        {0x33, 1},
        {0x2b65, 2},
        {0x2b61, 32},
    };
    CU_ASSERT(xqc_wt_conn_peer_settings(
        &h3c, settings, sizeof(settings) / sizeof(settings[0]), NULL)
        == XQC_H3_SETTINGS_ACCEPT);
    xqc_wt_session_t *a = xqc_wt_session_init(0, conn, NULL);
    xqc_wt_session_t *b = xqc_wt_session_init(4, conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(b);
    a->open = b->open = XQC_TRUE;
    CU_ASSERT(a->send_stream_limit[1] == 2 && b->send_stream_limit[1] == 2);
    unsigned char capsule[24];
    size_t n = xqc_wt_put_varint(0x190b4d3f, capsule,
                                 sizeof(capsule));
    capsule[n++] = 1;
    capsule[n++] = 3;
    for (size_t i = 0; i < n; i++) {
        CU_ASSERT(xqc_wt_session_recv_capsules(a, capsule + i, 1, 0)
                  == XQC_OK);
    }
    CU_ASSERT(a->send_stream_limit[1] == 3);
    CU_ASSERT(b->send_stream_limit[1] == 2);
    CU_ASSERT(xqc_wt_session_recv_capsules(a, capsule, n, 0)
              == -XQC_WT_FLOW_CONTROL_ERROR);
    CU_ASSERT(!b->closed);
    n = xqc_wt_put_varint(0x190b4d3d, capsule,
                          sizeof(capsule));
    capsule[n++] = 1;
    capsule[n++] = 33;
    CU_ASSERT(xqc_wt_session_recv_capsules(b, capsule, n, 0) == XQC_OK);
    CU_ASSERT(b->send_data_limit == 33 && a->send_data_limit == 32);
    capsule[n - 2] = 2;
    CU_ASSERT(xqc_wt_session_recv_capsules(b, capsule, n, 1)
              == -XQC_H3_DECODE_ERROR);
    xqc_wt_conn_destroy(conn);
}

void
xqc_test_wt_draft16_credit_renewal(void)
{
    /* draft-ietf-webtrans-http3-16 §§5.3, 5.6: absolute session credit. */
    xqc_wt_ctx_t ctx;
    xqc_memzero(&ctx, sizeof(ctx));
    xqc_h3_conn_t h3c = {0};
    xqc_connection_t transport;
    xqc_memzero(&transport, sizeof(transport));
    xqc_wt_conn_t *conn = version_conn(&ctx, &h3c, &transport,
                                       XQC_WEBTRANSPORT_DRAFT_VERSION_16);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    ctx.settings.max_bidi_streams = 1;
    ctx.settings.max_uni_streams = 1;
    ctx.settings.init_recv_window = 4;
    conn->negotiated_version = XQC_WEBTRANSPORT_DRAFT_VERSION_16;
    conn->flow_control_enabled = XQC_TRUE;
    xqc_wt_session_t *a = xqc_wt_session_init(0, conn, NULL);
    xqc_wt_session_t *b = xqc_wt_session_init(4, conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(b);
    a->open = b->open = XQC_TRUE;
    a->recv_data = 2;
    CU_ASSERT(xqc_wt_session_prepare_flow_credit(a));
    uint64_t type = 0, length = 0, value = 0;
    size_t n = xqc_wt_get_varint(a->send_buf, a->send_len, &type);
    CU_ASSERT(type == 0x190b4d3d);
    size_t m = xqc_wt_get_varint(a->send_buf + n,
                                 a->send_len - n, &length);
    CU_ASSERT(length == 1);
    CU_ASSERT(xqc_wt_get_varint(a->send_buf + n + m,
                                a->send_len - n - m, &value) == 1);
    CU_ASSERT(value == 6 && a->recv_data_limit == 6);
    CU_ASSERT(b->recv_data_limit == 4 && !b->send_len);
    CU_ASSERT(!xqc_wt_session_prepare_flow_credit(a));

    a->send_len = 0;
    xqc_wt_session_stream_closed(a, XQC_TRUE);
    CU_ASSERT(xqc_wt_session_prepare_flow_credit(a));
    n = xqc_wt_get_varint(a->send_buf, a->send_len, &type);
    m = xqc_wt_get_varint(a->send_buf + n,
                          a->send_len - n, &length);
    CU_ASSERT(type == 0x190b4d3f && length == 1);
    CU_ASSERT(xqc_wt_get_varint(a->send_buf + n + m,
                                a->send_len - n - m, &value) == 1);
    CU_ASSERT(value == 2 && a->recv_stream_limit[1] == 2);
    CU_ASSERT(b->recv_stream_limit[1] == 1);

    a->send_len = 0;
    a->closed = XQC_TRUE;
    xqc_wt_session_stream_closed(a, XQC_TRUE);
    CU_ASSERT(!xqc_wt_session_prepare_flow_credit(a));
    b->flow_control = XQC_FALSE;
    b->recv_data = 4;
    CU_ASSERT(!xqc_wt_session_prepare_flow_credit(b));
    xqc_wt_conn_destroy(conn);
}

static void
version_client_response(const char *status)
{
    xqc_h3_conn_t *h3c = version_engine(XQC_WEBTRANSPORT_DRAFT_VERSION_16,
                                        XQC_TRUE);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
    int err = -1;
    xqc_wt_session_t *session = xqc_wt_client_open_session(
        h3c, "localhost", "/wt", "https://localhost", &err);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    CU_ASSERT(err == XQC_OK && !session->open);
    CU_ASSERT(session->request->header_sent == 0);
    CU_ASSERT(session->wt_conn->negotiated_version == 0);
    version_peer_settings(session->wt_conn, XQC_TRUE, XQC_TRUE);
    CU_ASSERT(session->request->header_sent > 0);
    CU_ASSERT(version_creates == 0);
    const char *names[] = {":status"};
    const char *values[] = {status};
    version_headers(session->request, names, values, 1);
    CU_ASSERT(xqc_h3_request_on_recv_header(session->request) == XQC_OK);
    xqc_bool_t accepted = status[0] == '2';
    CU_ASSERT(version_creates == accepted);
    CU_ASSERT(session->open == accepted);
    CU_ASSERT(session->closed == !accepted);
    CU_ASSERT(xqc_wt_session_get_response_status(session)
              == (unsigned)strtoul(status, NULL, 10));
    if (!accepted) {
        CU_ASSERT(version_closes == 1);
    } else {
        /* Section 6: peer FIN can follow an already-finished local close. */
        h3c->conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
        CU_ASSERT(xqc_wt_session_close_with_error(session, 0, NULL, 0)
            == XQC_OK);
        xqc_h3_stream_t *h3s = session->request->h3_stream;
        CU_ASSERT(h3s->flags & XQC_HTTP3_STREAM_FLAG_FIN_SENT);
        uint64_t sent = h3s->stream->stream_send_offset;
        size_t body_sent = session->request->body_sent;
        CU_ASSERT(session->request->request_if->h3_request_read_notify(
            session->request, XQC_REQ_NOTIFY_READ_EMPTY_FIN,
            session->request->user_data) == XQC_OK);
        CU_ASSERT(session->peer_closed && session->closed);
        CU_ASSERT(session->close_error == 0 && h3s->stream->stream_err == 0);
        CU_ASSERT(!session->send_fin && session->send_len == 0);
        CU_ASSERT(xqc_wt_session_flush(session) == XQC_OK);
        CU_ASSERT(xqc_wt_session_flush(session) == XQC_OK);
        CU_ASSERT(h3s->stream->stream_send_offset == sent);
        CU_ASSERT(session->request->body_sent == body_sent);

        session->send_buf[0] = 0;
        session->send_len = 1;
        CU_ASSERT(xqc_wt_session_flush(session) == -XQC_ESTATE);
        CU_ASSERT(h3s->stream->stream_send_offset == sent);
        CU_ASSERT(session->close_error == 0 && h3s->stream->stream_err == 0);
        session->send_len = 0;
    }
    xqc_engine_destroy(h3c->conn->engine);
    CU_ASSERT(version_closes == 1);
}

void
xqc_test_wt_client_session_response(void)
{
    version_client_response("200");
    version_client_response("204");
}

void
xqc_test_wt_client_session_rejected(void)
{
    version_client_response("403");
    version_client_response("404");
}


static void
version_protocol_response(const char *value, const char *expected,
    xqc_bool_t duplicate)
{
    xqc_h3_conn_t *h3c = version_engine(XQC_WEBTRANSPORT_DRAFT_VERSION_16,
                                        XQC_TRUE);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
    char alpha[] = "alpha", quoted[] = "quoted\\\"proto";
    const char *protocols[] = {alpha, quoted, ""};
    int err = -1;
    xqc_wt_session_t *session = xqc_wt_client_open_session_with_protocols(
        h3c, "localhost", "/wt", NULL, protocols, 3, &err);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    CU_ASSERT(err == XQC_OK && !session->open);
    CU_ASSERT(session->request->header_sent == 0);
    CU_ASSERT_PTR_NULL(xqc_wt_session_get_application_protocol(session));
    CU_ASSERT_STRING_EQUAL(session->client_protocols,
                           "\"alpha\", \"quoted\\\\\\\"proto\", \"\"");
    memset(alpha, 'x', strlen(alpha));
    memset(quoted, 'x', strlen(quoted));
    version_peer_settings(session->wt_conn, XQC_TRUE, XQC_TRUE);
    CU_ASSERT(session->request->header_sent > 0);
    CU_ASSERT_STRING_EQUAL(session->client_protocols,
                           "\"alpha\", \"quoted\\\\\\\"proto\", \"\"");
    const char *names[] = {":status", "wt-protocol", "wt-protocol"};
    const char *values[] = {"200", value, value};
    version_headers(session->request, names, values,
                    value ? (duplicate ? 3 : 2) : 1);
    CU_ASSERT(xqc_h3_request_on_recv_header(session->request) == XQC_OK);
    if (expected) {
        CU_ASSERT(version_creates == 1 && version_closes == 0);
        CU_ASSERT(session->open && !session->closed);
        CU_ASSERT_STRING_EQUAL(
            xqc_wt_session_get_application_protocol(session), expected);
    } else {
        CU_ASSERT(version_creates == 0 && version_closes == 1);
        CU_ASSERT(!session->open && session->closed);
        CU_ASSERT_PTR_NULL(xqc_wt_session_get_application_protocol(session));
        CU_ASSERT(xqc_wt_session_get_close_error_code(session) == 0x0817b3dd);
        CU_ASSERT(session->request->h3_stream->stream->stream_err
                  == 0x0817b3dd);
        CU_ASSERT(h3c->conn->conn_err == 0);
    }
    xqc_engine_destroy(h3c->conn->engine);
    CU_ASSERT(version_closes == 1);
}

void
xqc_test_wt_application_protocol(void)
{
    /* draft-ietf-webtrans-http3-16 Section 3.3; RFC 9651 Section 4.2. */
    version_protocol_response("\"alpha\"", "alpha", XQC_FALSE);
    version_protocol_response("\"quoted\\\\\\\"proto\"",
                              "quoted\\\"proto", XQC_FALSE);
    version_protocol_response("\"\"", "", XQC_FALSE);
    version_protocol_response("  \"alpha\";flag; flag=?0;num=-1.25;int=42"
        ";date=@-5;token=*a:/;bytes=:AQI=:;text=\"a\\\"b\""
        ";display=%\"caf%c3%a9\"  ", "alpha", XQC_FALSE);
    version_protocol_response("\"alpha\";bytes=:AQI:;empty=::",
                              "alpha", XQC_FALSE);
    CU_ASSERT_PTR_NULL(xqc_wt_session_get_application_protocol(NULL));
}

void
xqc_test_wt_application_protocol_errors(void)
{
    /*
     * Section 3.3: required, malformed or unoffered selection closes only WT.
     */
    const char *invalid[] = {
        NULL, "alpha", "1", "?1", ":YWxwaGE=:", "%\"alpha\"",
        "\"beta\"", "\"alpha\", \"alpha\"", "(\"alpha\")",
        "\"alpha\"garbage", "\"alpha", "\"al\\pha\"", "\"al\npha\"",
        "\t\"alpha\"", "\"alpha\"\t", "\"alpha\" ;flag", "\"alpha\";",
        "\"alpha\";Upper", "\"alpha\";v=", "\"alpha\";v=?2",
        "\"alpha\";v=@1.5", "\"alpha\";v=@", "\"alpha\";v=-",
        "\"alpha\";v=1234567890123456", "\"alpha\";v=1234567890123.1",
        "\"alpha\";v=1.", "\"alpha\";v=1.2345", "\"alpha\";v=(1)",
        "\"alpha\";v=:a:", "\"alpha\";v=:!:", "\"alpha\";v=:AQI===:",
        "\"alpha\";v=:AQ=I:", "\"alpha\";v=:AQI", "\"alpha\";v=\"x",
        "\"alpha\";v=%\"%gg\"", "\"alpha\";v=%\"%ff\"",
        "\"alpha\";v=%\"%e2%82\"", "\"alpha\";v=%\"%\"",
        "\"alpha\";v=%oops", "\"alpha\";v=%\"unterminated",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        version_protocol_response(invalid[i], NULL, XQC_FALSE);
    }
    version_protocol_response("\"alpha\"", NULL, XQC_TRUE);
}

void
xqc_test_wt_application_protocol_inputs(void)
{
    xqc_h3_conn_t *h3c = version_engine(XQC_WEBTRANSPORT_DRAFT_VERSION_16,
                                        XQC_TRUE);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
    char long_protocol[1026];
    memset(long_protocol, 'a', sizeof(long_protocol) - 1);
    long_protocol[sizeof(long_protocol) - 1] = '\0';
    const char *invalid[] = {NULL, "bad\nprotocol", "non-ascii\x80",
                             long_protocol};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        int err = 0;
        const char *protocols[] = {invalid[i]};
        CU_ASSERT_PTR_NULL(xqc_wt_client_open_session_with_protocols(
            h3c, "localhost", "/wt", NULL, protocols, 1, &err));
        CU_ASSERT(err == -XQC_EPARAM);
        CU_ASSERT(xqc_wt_get_conn_from_h3(h3c)->session_count == 0);
    }
    int err = 0;
    CU_ASSERT_PTR_NULL(xqc_wt_client_open_session_with_protocols(
        h3c, "localhost", "/wt", NULL, NULL, 1, &err));
    CU_ASSERT(err == -XQC_EPARAM);
    const char *protocols[17];
    long_protocol[1024] = '\0';
    for (size_t i = 0; i < 17; i++) {
        protocols[i] = long_protocol;
    }
    CU_ASSERT_PTR_NULL(xqc_wt_client_open_session_with_protocols(
        h3c, "localhost", "/wt", NULL, protocols, 17, &err));
    CU_ASSERT(err == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(xqc_wt_client_open_session_with_protocols(
        h3c, "localhost", "/wt", NULL, protocols, SIZE_MAX, &err));
    CU_ASSERT(err == -XQC_EPARAM);
    xqc_wt_session_t *session = xqc_wt_client_open_session_with_protocols(
        h3c, "localhost", "/wt", NULL, protocols, 1, &err);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    CU_ASSERT(err == XQC_OK);
    CU_ASSERT(strlen(session->client_protocols) == 1026);
    xqc_engine_destroy(h3c->conn->engine);
}

static unsigned version_send_errors, version_handshake_errors;

static void version_error_log(xqc_log_level_t level, const void *buf,
    size_t size, void *data);

static void
version_error_log(xqc_log_level_t level, const void *buf,
    size_t size, void *data)
{
    char message[XQC_MAX_LOG_LEN];
    size = xqc_min(size, sizeof(message) - 1);
    memcpy(message, buf, size);
    message[size] = '\0';
    if (strstr(message, "WT CONNECT send failed")) {
        CU_ASSERT(level == XQC_LOG_ERROR);
        version_send_errors++;
    }
    if (strstr(message, "WT CONNECT after handshake failed")) {
        CU_ASSERT(level == XQC_LOG_ERROR);
        version_handshake_errors++;
    }
}

void
xqc_test_wt_handshake_request_result(void)
{
    /* Draft-16 Section 3.2: defer CONNECT until TLS handshake completion. */
    for (unsigned scenario = 0; scenario < 6; scenario++) {
        unsigned fail = scenario % 2;
        unsigned trigger = scenario / 2;
        xqc_h3_conn_t *h3c = version_engine(
            XQC_WEBTRANSPORT_DRAFT_VERSION_16, XQC_TRUE);
        CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
        xqc_connection_t *transport = h3c->conn;
        transport->conn_flag &= ~XQC_CONN_FLAG_TLS_HSK_COMPLETED;
        xqc_wt_conn_t *conn = xqc_wt_get_conn_from_h3(h3c);
        if (trigger != 1) {
            version_peer_settings(conn, XQC_FALSE, XQC_TRUE);
        }
        int err = 0;
        xqc_wt_session_t *session = xqc_wt_client_open_session(
            h3c, "localhost", "/wt", "https://localhost", &err);
        CU_ASSERT_PTR_NOT_NULL_FATAL(session);
        CU_ASSERT(err == XQC_OK && !session->request_sent && !session->closed);
        xqc_h3_request_t *request = session->request;
        xqc_log_callbacks_t callbacks = {
            .xqc_log_write_err = version_error_log,
        };
        xqc_log_t log = {
            .log_level = XQC_LOG_ERROR, .log_callbacks = &callbacks,
        };
        xqc_log_t *saved_log = h3c->log;
        h3c->log = &log;
        version_send_errors = version_handshake_errors = 0;
        if (fail) {
            /* A deterministic terminal error without allocator injection. */
            h3c->peer_h3_conn_settings.max_field_section_size = 1;
        }
        transport->conn_flag |= XQC_CONN_FLAG_TLS_HSK_COMPLETED;
        if (trigger == 0) {
            h3c->h3_conn_callbacks.h3_conn_handshake_finished(h3c, NULL);
        } else if (trigger == 1) {
            version_peer_settings(conn, XQC_FALSE, XQC_TRUE);
        } else {
            CU_ASSERT(request->request_if->h3_request_write_notify(
                request, session) == XQC_OK);
        }
        CU_ASSERT(session->request_sent == !fail);
        CU_ASSERT(session->closed == fail);
        CU_ASSERT(version_closes == fail);
        CU_ASSERT(version_send_errors == fail);
        CU_ASSERT(version_handshake_errors == (fail && trigger == 0));
        CU_ASSERT_PTR_EQUAL(session->request, request);
        CU_ASSERT(conn->session_count == 1 && transport->conn_err == 0);
        if (fail) {
            CU_ASSERT(session->close_error == H3_INTERNAL_ERROR);
            /* No second notification or premature destruction on retry. */
            h3c->h3_conn_callbacks.h3_conn_handshake_finished(h3c, NULL);
            CU_ASSERT(version_closes == 1 && version_send_errors == 1);
        }
        h3c->log = saved_log;
        xqc_engine_destroy(transport->engine);
        CU_ASSERT(version_closes == 1);
    }
}
