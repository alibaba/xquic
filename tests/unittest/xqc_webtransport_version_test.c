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
#include "src/webtransport/xqc_webtransport_wire.h"
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
static xqc_log_t version_log;

static xqc_wt_conn_t *version_conn(xqc_wt_ctx_t *ctx,
    xqc_h3_conn_t *h3c, xqc_connection_t *transport,
    xqc_webtransport_draft_version_t version);
static void version_peer_settings(xqc_wt_conn_t *conn,
    xqc_bool_t draft07, xqc_bool_t draft16);
static xqc_h3_conn_t *version_engine(
    xqc_webtransport_draft_version_t version, xqc_bool_t client);
static xqc_h3_request_t *version_request(xqc_h3_conn_t *h3c,
    const char *protocol);
static void version_headers(xqc_h3_request_t *request,
    const char **names, const char **values, size_t count);
static xqc_wt_session_t *version_capsule_session(xqc_wt_ctx_t *ctx,
    xqc_h3_conn_t *h3c, xqc_connection_t *transport);
static void version_client_response(const char *status);
static int version_accept(xqc_http_headers_t *headers,
    xqc_http_headers_t *response);
static int version_created(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *data);
static int version_closed(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *data);

static int
version_accept(xqc_http_headers_t *headers, xqc_http_headers_t *response)
{
    version_accepts++;
    return 1;
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
    xqc_h3_conn_t *h3c = conn->h3_conn;
    CU_ASSERT(xqc_h3_conn_on_settings_entry_received(0x08, 1, h3c)
              == XQC_OK);
    CU_ASSERT(xqc_h3_conn_on_settings_entry_received(0x33, 1, h3c)
              == XQC_OK);
    if (draft07) {
        CU_ASSERT(xqc_h3_conn_on_settings_entry_received(
            WT_TEST_SETTING_07, 1, h3c) == XQC_OK);
    }
    if (draft16) {
        CU_ASSERT(xqc_h3_conn_on_settings_entry_received(
            WT_TEST_SETTING_16, 1, h3c) == XQC_OK);
    }
    CU_ASSERT(h3c->on_settings_complete(conn) == XQC_OK);
}

void
xqc_test_wt_version_negotiation(void)
{
    /* draft-ietf-webtrans-http3-16 Section 3: highest common revision. */
    for (int order = 0; order < 2; order++) {
        xqc_wt_ctx_t ctx = {0};
        xqc_h3_conn_t h3c = {0};
        xqc_connection_t transport = {0};
        xqc_wt_conn_t *conn = version_conn(&ctx, &h3c, &transport,
            XQC_WEBTRANSPORT_DRAFT_VERSION_16);
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        CU_ASSERT(xqc_h3_conn_on_settings_entry_received(
            order ? WT_TEST_SETTING_07 : WT_TEST_SETTING_16, 1, &h3c)
                  == XQC_OK);
        CU_ASSERT(conn->negotiated_version == 0);
        CU_ASSERT(!xqc_wt_conn_requirements_met(conn));
        CU_ASSERT(xqc_h3_conn_on_settings_entry_received(
            order ? WT_TEST_SETTING_16 : WT_TEST_SETTING_07, 1, &h3c)
                  == XQC_OK);
        version_peer_settings(conn, XQC_FALSE, XQC_FALSE);
        CU_ASSERT(conn->negotiated_version
                  == XQC_WEBTRANSPORT_DRAFT_VERSION_16);
        CU_ASSERT(xqc_wt_conn_requirements_met(conn));
        xqc_wt_session_t *session = xqc_wt_session_init(0, conn, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(session);
        CU_ASSERT(xqc_wt_session_get_draft_version(session)
                  == XQC_WEBTRANSPORT_DRAFT_VERSION_16);
        xqc_wt_conn_destroy(conn);
    }
    CU_ASSERT(xqc_wt_session_get_draft_version(NULL) == 0);
}

void
xqc_test_wt_version_fallback(void)
{
    for (int local07 = 0; local07 < 2; local07++) {
        xqc_wt_ctx_t ctx = {0};
        xqc_h3_conn_t h3c = {0};
        xqc_connection_t transport = {0};
        xqc_wt_conn_t *conn = version_conn(&ctx, &h3c, &transport,
            local07 ? XQC_WEBTRANSPORT_DRAFT_VERSION_7
                    : XQC_WEBTRANSPORT_DRAFT_VERSION_16);
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        transport.local_settings.reset_stream_at = XQC_FALSE;
        transport.remote_settings.reset_stream_at = XQC_FALSE;
        version_peer_settings(conn, XQC_TRUE, local07);
        CU_ASSERT(conn->negotiated_version
                  == XQC_WEBTRANSPORT_DRAFT_VERSION_7);
        CU_ASSERT(xqc_wt_conn_requirements_met(conn));
        xqc_wt_conn_destroy(conn);
    }
}

void
xqc_test_wt_version_prerequisites(void)
{
    /* Section 3: a selected draft-16 must not silently downgrade to 07. */
    for (int missing = 0; missing < 4; missing++) {
        xqc_wt_ctx_t ctx = {0};
        xqc_h3_conn_t h3c = {0};
        xqc_connection_t transport = {0};
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
        xqc_wt_ctx_t ctx = {0};
        xqc_h3_conn_t h3c = {0};
        xqc_connection_t transport = {0};
        xqc_wt_conn_t *conn = version_conn(&ctx, &h3c, &transport,
            XQC_WEBTRANSPORT_DRAFT_VERSION_16);
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        transport.conn_type = XQC_CONN_TYPE_CLIENT;
        CU_ASSERT(xqc_h3_conn_on_settings_entry_received(0x08,
            !missing_connect, &h3c) == XQC_OK);
        CU_ASSERT(xqc_h3_conn_on_settings_entry_received(0x33,
            missing_connect, &h3c) == XQC_OK);
        CU_ASSERT(xqc_h3_conn_on_settings_entry_received(WT_TEST_SETTING_16,
            1, &h3c) == XQC_OK);
        CU_ASSERT(h3c.on_settings_complete(conn) == XQC_OK);
        CU_ASSERT(conn->negotiated_version
                  == XQC_WEBTRANSPORT_DRAFT_VERSION_16);
        CU_ASSERT(!xqc_wt_conn_requirements_met(conn));
        xqc_wt_conn_destroy(conn);
    }
}

void
xqc_test_wt_version_settings_errors(void)
{
    xqc_wt_ctx_t ctx = {0};
    xqc_h3_conn_t h3c = {0};
    xqc_connection_t transport = {0};
    xqc_wt_conn_t *conn = version_conn(&ctx, &h3c, &transport,
        XQC_WEBTRANSPORT_DRAFT_VERSION_16);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    CU_ASSERT(xqc_h3_conn_on_settings_entry_received(WT_TEST_SETTING_16,
              2, &h3c) == -XQC_H3_SETTING_ERROR);
    xqc_wt_conn_destroy(conn);
    memset(&h3c, 0, sizeof(h3c));
    conn = version_conn(&ctx, &h3c, &transport,
        XQC_WEBTRANSPORT_DRAFT_VERSION_7);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    version_peer_settings(conn, XQC_FALSE, XQC_TRUE);
    CU_ASSERT(conn->negotiated_version == 0);
    CU_ASSERT(!xqc_wt_conn_requirements_met(conn));
    xqc_wt_conn_destroy(conn);
}

static xqc_h3_conn_t *
version_engine(xqc_webtransport_draft_version_t version, xqc_bool_t client)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL(conn);
    if (!conn) {
        return NULL;
    }
    xqc_engine_t *engine = conn->engine;
    xqc_h3_callbacks_t app = {0};
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
    settings.max_sessions_count = 1;
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
    h3c->qenc_stream = xqc_h3_conn_create_uni_stream(h3c,
        XQC_H3_STREAM_TYPE_QPACK_ENCODER);
    h3c->qdec_stream = xqc_h3_conn_create_uni_stream(h3c,
        XQC_H3_STREAM_TYPE_QPACK_DECODER);
    h3c->control_stream_out = xqc_h3_conn_create_uni_stream(h3c,
        XQC_H3_STREAM_TYPE_CONTROL);
    CU_ASSERT_PTR_NOT_NULL(h3c->qenc_stream);
    CU_ASSERT_PTR_NOT_NULL(h3c->qdec_stream);
    CU_ASSERT_PTR_NOT_NULL(h3c->control_stream_out);
    version_creates = version_closes = version_accepts = 0;
    return h3c;
}

void
xqc_test_wt_version_advertisement(void)
{
    /* Sections 3 and 9: each advertised version keeps its own identifier. */
    for (int draft16 = 0; draft16 < 2; draft16++) {
        xqc_h3_conn_t *h3c = version_engine(draft16
            ? XQC_WEBTRANSPORT_DRAFT_VERSION_16
            : XQC_WEBTRANSPORT_DRAFT_VERSION_7, XQC_FALSE);
        CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
        unsigned found07 = 0, found16 = 0, datagram = 0, connect = 0;
        for (size_t i = 0; i < h3c->registered_settings_count; i++) {
            uint64_t id = h3c->registered_settings[i].identifier.vi;
            uint64_t value = h3c->registered_settings[i].value.vi;
            CU_ASSERT(value == 1);
            found07 += id == WT_TEST_SETTING_07;
            found16 += id == WT_TEST_SETTING_16;
            datagram += id == 0x33;
            connect += id == 0x08;
        }
        CU_ASSERT(found07 == 1 && found16 == (unsigned)draft16);
        CU_ASSERT(datagram == 1 && connect == 1);
        CU_ASSERT(h3c->registered_settings_count == (size_t)(3 + draft16));
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

static xqc_h3_request_t *
version_request(xqc_h3_conn_t *h3c, const char *protocol)
{
    xqc_stream_t *stream = xqc_create_stream_with_conn(h3c->conn,
        XQC_UNDEFINE_STREAM_ID, XQC_CLI_BID, NULL, NULL);
    if (!stream) {
        return NULL;
    }
    xqc_h3_stream_t *h3s = xqc_h3_stream_create(h3c, stream,
        XQC_H3_STREAM_TYPE_REQUEST, NULL);
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
xqc_test_wt_version_connect_tokens(void)
{
    /* Section 3: draft-16 uses webtransport-h3, draft-07 webtransport. */
    for (int draft16 = 0; draft16 < 2; draft16++) {
        for (int correct = 0; correct < 2; correct++) {
            xqc_h3_conn_t *h3c = version_engine(draft16
                ? XQC_WEBTRANSPORT_DRAFT_VERSION_16
                : XQC_WEBTRANSPORT_DRAFT_VERSION_7, XQC_FALSE);
            CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
            xqc_wt_conn_t *conn = xqc_wt_create_conn(h3c);
            version_peer_settings(conn, XQC_TRUE, draft16);
            const char *token = (draft16 == correct)
                ? "webtransport-h3" : "webtransport";
            xqc_h3_request_t *request = version_request(h3c, token);
            CU_ASSERT_PTR_NOT_NULL_FATAL(request);
            CU_ASSERT(xqc_h3_request_on_recv_header(request) == XQC_OK);
            xqc_wt_session_t *session = xqc_wt_conn_find_session(conn,
                request->h3_stream->stream_id);
            CU_ASSERT(version_creates == correct);
            CU_ASSERT(version_accepts == correct);
            if (correct) {
                CU_ASSERT_PTR_NOT_NULL_FATAL(session);
                CU_ASSERT(session->open && !session->closed);
                CU_ASSERT(xqc_wt_session_get_draft_version(session)
                          == conn->negotiated_version);
            } else {
                CU_ASSERT(session == NULL || !session->open);
                if (draft16) {
                    CU_ASSERT(request->h3_stream->stream->stream_err
                              == H3_MESSAGE_ERROR);
                } else {
                    CU_ASSERT(request->header_sent > 0);
                }
            }
            xqc_engine_destroy(h3c->conn->engine);
        }
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
    xqc_wt_ctx_t ctx = {0};
    xqc_h3_conn_t h3c = {0};
    xqc_connection_t transport = {0};
    xqc_wt_session_t *session = version_capsule_session(&ctx, &h3c,
                                                        &transport);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    /* Section 6: UTF-8 reason, including a split multibyte sequence. */
    const unsigned char capsule[] = {0x68, 0x43, 11, 0, 0, 0, 9,
        0xe4, 0xb8, 0xad, 0xf0, 0x9f, 0x8c, 0x8d};
    for (size_t i = 0; i < sizeof(capsule); i++) {
        CU_ASSERT(xqc_wt_session_recv_capsules(session, capsule + i, 1,
                  i == sizeof(capsule) - 1) == XQC_OK);
    }
    CU_ASSERT(session->closed);
    CU_ASSERT(xqc_wt_session_get_close_error_code(session) == 9);
    CU_ASSERT(memcmp(xqc_wt_session_get_close_reason(session),
                     capsule + 7, 7) == 0);
    CU_ASSERT(xqc_wt_session_get_close_reason(session)[7] == '\0');
    CU_ASSERT(xqc_wt_session_recv_capsules(session,
              (const unsigned char *)"x", 1, 0) == -XQC_H3_DECODE_ERROR);
    xqc_wt_conn_destroy(session->wt_conn);
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
        xqc_wt_ctx_t ctx = {0};
        xqc_h3_conn_t h3c = {0};
        xqc_connection_t transport = {0};
        xqc_wt_session_t *session = version_capsule_session(&ctx, &h3c,
                                                            &transport);
        CU_ASSERT_PTR_NOT_NULL_FATAL(session);
        CU_ASSERT(xqc_wt_session_close_with_error(session, 0,
            (const char *)invalid[i], lengths[i]) == -XQC_EPARAM);
        CU_ASSERT(!session->closed && session->send_len == 0);
        unsigned char capsule[11] = {0x68, 0x43, 0, 0, 0, 0, 0};
        capsule[2] = 4 + lengths[i];
        memcpy(capsule + 7, invalid[i], lengths[i]);
        CU_ASSERT(xqc_wt_session_recv_capsules(session, capsule,
            7 + lengths[i], 1) == -XQC_H3_DECODE_ERROR);
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
        size_t n = xqc_wt_encode_session_id(forbidden[i], capsule,
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
    xqc_wt_conn_t *conn = xqc_wt_create_conn(h3c);
    version_peer_settings(conn, XQC_TRUE, XQC_TRUE);
    xqc_wt_session_t *session = xqc_wt_session_init(0, conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    session->open = XQC_TRUE;
    /* Section 5.1: no negotiated session flow control, so ignore capsules. */
    const uint64_t types[] = {0x190b4d3d, 0x190b4d3f, 0x190b4d40,
                              0x190b4d41, 0x190b4d43, 0x190b4d44};
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        unsigned char capsule[16];
        size_t n = xqc_wt_encode_session_id(types[i], capsule, sizeof(capsule));
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
    xqc_wt_conn_t *conn = xqc_wt_create_conn(h3c);
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
    xqc_wt_session_t *original = xqc_wt_conn_find_session(conn,
        first->h3_stream->stream_id);
    xqc_wt_session_t *rejected = xqc_wt_conn_find_session(conn,
        second->h3_stream->stream_id);
    CU_ASSERT_PTR_NOT_NULL_FATAL(original);
    CU_ASSERT_PTR_NOT_NULL_FATAL(rejected);
    CU_ASSERT(original->open && !original->closed);
    CU_ASSERT(!rejected->open && rejected->closed);
    xqc_engine_destroy(h3c->conn->engine);
}

static void
version_client_response(const char *status)
{
    xqc_h3_conn_t *h3c = version_engine(XQC_WEBTRANSPORT_DRAFT_VERSION_16,
                                        XQC_TRUE);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
    int err = -1;
    xqc_wt_session_t *session = xqc_wt_client_open_session(h3c,
        "localhost", "/wt", "https://localhost", &err);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    CU_ASSERT(err == XQC_OK && !session->open);
    CU_ASSERT(session->request->header_sent == 0);
    CU_ASSERT(xqc_wt_session_get_draft_version(session) == 0);
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
