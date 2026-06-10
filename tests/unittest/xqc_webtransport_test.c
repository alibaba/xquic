/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <string.h>

#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_ctx.h"
#include "src/http3/xqc_h3_request.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_stream.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_request.h"
#include "src/webtransport/xqc_webtransport_ctx.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/webtransport/xqc_webtransport_wire.h"
#include "xqc_common_test.h"
#include "xqc_webtransport_test.h"

typedef struct {
    int create_cnt;
    int read_cnt;
    int write_cnt;
    int close_cnt;
    void *initial_user_data;
    void *request_user_data;
    void *read_user_data;
    void *write_user_data;
    void *close_user_data;
} xqc_wt_passthrough_test_state_t;

static xqc_wt_passthrough_test_state_t g_wt_passthrough_state;

typedef struct {
    int create_cnt;
    int read_cnt;
    xqc_wt_bidistream_t *created_stream;
    xqc_wt_session_t *created_session;
    xqc_wt_session_t *read_session;
    void *create_user_data;
    void *read_user_data;
} xqc_wt_bidi_create_test_state_t;

static xqc_wt_bidi_create_test_state_t g_wt_bidi_create_state;

typedef struct {
    int create_cnt;
    int read_cnt;
    xqc_wt_session_t *created_session;
    xqc_wt_session_t *read_session;
    void *create_user_data;
    void *read_user_data;
} xqc_wt_create_reject_test_state_t;

static xqc_wt_create_reject_test_state_t g_wt_create_reject_state;

typedef struct {
    int closing_cnt;
    xqc_wt_session_t *closing_session;
    void *closing_user_data;
} xqc_wt_closing_test_state_t;

static xqc_wt_closing_test_state_t g_wt_closing_state;

int xqc_wt_process_request_headers(xqc_wt_request_t *wt_request,
    xqc_wt_ctx_t *wt_ctx, xqc_http_headers_t *headers);
void xqc_h3_stream_closing_notify(xqc_stream_t *stream, xqc_int_t err_code,
    void *strm_user_data);

static int
xqc_test_orig_h3_request_create(xqc_h3_request_t *h3_request, void *user_data)
{
    g_wt_passthrough_state.create_cnt++;
    g_wt_passthrough_state.initial_user_data = user_data;
    xqc_h3_request_set_user_data(h3_request,
        g_wt_passthrough_state.request_user_data);
    return XQC_OK;
}

static int
xqc_test_orig_h3_request_read(xqc_h3_request_t *h3_request,
    xqc_request_notify_flag_t flag, void *user_data)
{
    g_wt_passthrough_state.read_cnt++;
    g_wt_passthrough_state.read_user_data = user_data;
    return XQC_OK;
}

static int
xqc_test_orig_h3_request_write(xqc_h3_request_t *h3_request, void *user_data)
{
    g_wt_passthrough_state.write_cnt++;
    g_wt_passthrough_state.write_user_data = user_data;
    return XQC_OK;
}

static int
xqc_test_orig_h3_request_close(xqc_h3_request_t *h3_request, void *user_data)
{
    g_wt_passthrough_state.close_cnt++;
    g_wt_passthrough_state.close_user_data = user_data;
    return XQC_OK;
}

static xqc_int_t
xqc_test_wt_bidi_create_notify(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    g_wt_bidi_create_state.create_cnt++;
    g_wt_bidi_create_state.created_stream = stream;
    g_wt_bidi_create_state.created_session = session;
    g_wt_bidi_create_state.create_user_data = user_data;
    return XQC_OK;
}

static xqc_int_t
xqc_test_wt_bidi_read_notify(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t data_len, uint8_t fin,
    void *user_data)
{
    g_wt_bidi_create_state.read_cnt++;
    g_wt_bidi_create_state.read_session = session;
    g_wt_bidi_create_state.read_user_data = user_data;
    return XQC_OK;
}

static xqc_int_t
xqc_test_wt_reject_bidi_create_notify(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    g_wt_create_reject_state.create_cnt++;
    g_wt_create_reject_state.created_session = session;
    g_wt_create_reject_state.create_user_data = user_data;
    return -XQC_EPARAM;
}

static xqc_int_t
xqc_test_wt_reject_bidi_read_notify(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t data_len, uint8_t fin,
    void *user_data)
{
    g_wt_create_reject_state.read_cnt++;
    g_wt_create_reject_state.read_session = session;
    g_wt_create_reject_state.read_user_data = user_data;
    return XQC_OK;
}

static xqc_int_t
xqc_test_wt_reject_uni_create_notify(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    g_wt_create_reject_state.create_cnt++;
    g_wt_create_reject_state.created_session = session;
    g_wt_create_reject_state.create_user_data = user_data;
    return -XQC_EPARAM;
}

static xqc_int_t
xqc_test_wt_reject_uni_read_notify(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t data_len, uint8_t fin,
    void *user_data)
{
    g_wt_create_reject_state.read_cnt++;
    g_wt_create_reject_state.read_session = session;
    g_wt_create_reject_state.read_user_data = user_data;
    return XQC_OK;
}

static xqc_int_t
xqc_test_wt_uni_closing_notify(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    g_wt_closing_state.closing_cnt++;
    g_wt_closing_state.closing_session = session;
    g_wt_closing_state.closing_user_data = user_data;
    return XQC_OK;
}

static int
xqc_test_wt_accept_session_notify(xqc_webtransport_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data)
{
    return 1;
}

void
xqc_test_wt_request_lifecycle(void)
{
    xqc_wt_request_destroy(NULL);

    xqc_wt_request_t *request = xqc_wt_request_create(NULL);
    CU_ASSERT_PTR_NULL(request);
    xqc_wt_request_destroy(request);
}

void
xqc_test_wt_h3_passthrough_callbacks(void)
{
    memset(&g_wt_passthrough_state, 0, sizeof(g_wt_passthrough_state));
    int initial_user_data = 1;
    int request_user_data = 2;
    g_wt_passthrough_state.request_user_data = &request_user_data;

    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);

    xqc_h3_callbacks_t orig_cbs = {
        .h3r_cbs = {
            .h3_request_create_notify = xqc_test_orig_h3_request_create,
            .h3_request_read_notify = xqc_test_orig_h3_request_read,
            .h3_request_write_notify = xqc_test_orig_h3_request_write,
            .h3_request_close_notify = xqc_test_orig_h3_request_close,
        },
    };
    xqc_h3_ctx_t *h3_ctx = xqc_engine_get_alpn_ctx(engine, XQC_ALPN_H3,
        strlen(XQC_ALPN_H3));
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3_ctx);
    h3_ctx->h3_cbs = orig_cbs;

    xqc_int_t ret = xqc_wt_ctx_init_for_alpns(engine, NULL, NULL, NULL, 1,
        NULL, 0);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    xqc_connection_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.engine = engine;
    conn.conn_type = XQC_CONN_TYPE_SERVER;
    conn.alpn = XQC_ALPN_H3;
    conn.alpn_len = strlen(XQC_ALPN_H3);

    xqc_h3_conn_t h3_conn;
    memset(&h3_conn, 0, sizeof(h3_conn));
    h3_conn.conn = &conn;
    h3_conn.log = engine->log;

    xqc_h3_stream_t h3_stream;
    memset(&h3_stream, 0, sizeof(h3_stream));
    h3_stream.h3c = &h3_conn;
    h3_stream.log = engine->log;

    xqc_http_header_t headers[] = {
        {
            .name = { .iov_base = ":method", .iov_len = strlen(":method") },
            .value = { .iov_base = "GET", .iov_len = strlen("GET") },
        },
        {
            .name = { .iov_base = ":path", .iov_len = strlen(":path") },
            .value = { .iov_base = "/", .iov_len = strlen("/") },
        },
    };

    xqc_h3_request_t h3_request;
    memset(&h3_request, 0, sizeof(h3_request));
    h3_request.h3_stream = &h3_stream;
    h3_request.read_flag = XQC_REQ_NOTIFY_READ_HEADER;
    h3_request.h3_header[XQC_H3_REQUEST_HEADER].headers = headers;
    h3_request.h3_header[XQC_H3_REQUEST_HEADER].count =
        sizeof(headers) / sizeof(headers[0]);
    h3_request.h3_header[XQC_H3_REQUEST_HEADER].capacity =
        sizeof(headers) / sizeof(headers[0]);

    ret = xqc_wt_h3_request_create_notify(&h3_request, &initial_user_data);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    void *wt_user_data = h3_request.user_data;
    CU_ASSERT_PTR_NOT_NULL(wt_user_data);

    ret = xqc_wt_h3_request_read_notify(&h3_request,
        XQC_REQ_NOTIFY_READ_HEADER, wt_user_data);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(g_wt_passthrough_state.create_cnt, 1);
    CU_ASSERT_EQUAL(g_wt_passthrough_state.read_cnt, 1);
    CU_ASSERT_PTR_EQUAL(g_wt_passthrough_state.initial_user_data,
        &initial_user_data);
    CU_ASSERT_PTR_EQUAL(g_wt_passthrough_state.read_user_data,
        &request_user_data);
    CU_ASSERT_PTR_EQUAL(h3_request.user_data, wt_user_data);
    CU_ASSERT(h3_request.read_flag & XQC_REQ_NOTIFY_READ_HEADER);

    ret = xqc_wt_h3_request_write_notify(&h3_request, wt_user_data);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(g_wt_passthrough_state.write_cnt, 1);
    CU_ASSERT_PTR_EQUAL(g_wt_passthrough_state.write_user_data,
        &request_user_data);

    ret = xqc_wt_h3_request_close_notify(&h3_request, wt_user_data);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(g_wt_passthrough_state.close_cnt, 1);
    CU_ASSERT_PTR_EQUAL(g_wt_passthrough_state.close_user_data,
        &request_user_data);
    CU_ASSERT_PTR_NULL(h3_request.user_data);

    xqc_engine_destroy(engine);
}

void
xqc_test_wt_bidi_create_notify_after_session_id(void)
{
    memset(&g_wt_bidi_create_state, 0, sizeof(g_wt_bidi_create_state));
    int app_user_data = 7;

    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);

    xqc_webtransport_stream_callbacks_t stream_cbs = {
        .wt_bidistream_create_notify = xqc_test_wt_bidi_create_notify,
        .wt_bidistream_read_notify = xqc_test_wt_bidi_read_notify,
    };
    xqc_int_t ret = xqc_wt_ctx_init_for_alpns(engine, NULL, NULL,
        &stream_cbs, 4, NULL, 0);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    xqc_connection_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.engine = engine;
    conn.conn_type = XQC_CONN_TYPE_SERVER;
    conn.alpn = XQC_ALPN_H3;
    conn.alpn_len = strlen(XQC_ALPN_H3);

    xqc_h3_conn_t h3_conn;
    memset(&h3_conn, 0, sizeof(h3_conn));
    h3_conn.conn = &conn;
    h3_conn.log = engine->log;
    h3_conn.local_h3_conn_settings.webtransport_mode =
        XQC_WT_MODE_BROWSER_COMPAT;

    xqc_wt_conn_t *wt_conn = xqc_wt_conn_create(&h3_conn);
    CU_ASSERT_PTR_NOT_NULL_FATAL(wt_conn);
    wt_conn->user_data = &app_user_data;
    h3_conn.wt_conn = wt_conn;

    xqc_wt_session_t *default_session =
        xqc_wt_session_init(4, wt_conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(default_session);
    xqc_wt_session_t *target_session =
        xqc_wt_session_init(8, wt_conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(target_session);
    CU_ASSERT_PTR_EQUAL(wt_conn->wt_session, default_session);

    xqc_stream_t stream;
    memset(&stream, 0, sizeof(stream));
    stream.stream_id = 12;
    stream.stream_conn = &conn;

    xqc_h3_stream_t h3_stream;
    memset(&h3_stream, 0, sizeof(h3_stream));
    h3_stream.h3c = &h3_conn;
    h3_stream.log = engine->log;
    h3_stream.stream = &stream;
    h3_stream.stream_id = stream.stream_id;

    int cb_ret = 0;
    xqc_wt_h3_bidi_stream_created(&h3_conn, &h3_stream, &cb_ret);
    CU_ASSERT_EQUAL(g_wt_bidi_create_state.create_cnt, 0);

    uint8_t data[16] = {0};
    size_t sid_len = xqc_wt_encode_session_id(target_session->session_id,
        data, sizeof(data));
    CU_ASSERT(sid_len > 0);
    data[sid_len] = 0x42;

    xqc_wt_h3_bidi_stream_recv(&h3_conn, &h3_stream, data, sid_len + 1, 0,
        &cb_ret);
    CU_ASSERT_EQUAL(cb_ret, (int)(sid_len + 1));
    CU_ASSERT_EQUAL(g_wt_bidi_create_state.create_cnt, 1);
    CU_ASSERT_PTR_EQUAL(g_wt_bidi_create_state.created_session, target_session);
    CU_ASSERT_PTR_EQUAL(g_wt_bidi_create_state.create_user_data, &app_user_data);
    CU_ASSERT_EQUAL(g_wt_bidi_create_state.read_cnt, 0);
    CU_ASSERT_PTR_NOT_NULL(g_wt_bidi_create_state.created_stream);
    if (g_wt_bidi_create_state.created_stream) {
        CU_ASSERT_EQUAL(g_wt_bidi_create_state.created_stream->session_id,
            target_session->session_id);
        CU_ASSERT_PTR_EQUAL(g_wt_bidi_create_state.created_stream->session,
            target_session);
    }

    xqc_wt_conn_close(wt_conn);
    h3_conn.wt_conn = NULL;
    xqc_engine_destroy(engine);
}

void
xqc_test_wt_browser_dgram_fallback_on_establish(void)
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);

    xqc_webtransport_session_callbacks_t session_cbs = {
        .webtransport_session_create_notify =
            xqc_test_wt_accept_session_notify,
    };
    xqc_int_t ret = xqc_wt_ctx_init_for_alpns(engine, NULL, &session_cbs,
        NULL, 2, NULL, 0);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    xqc_wt_ctx_t *wt_ctx = xqc_wt_ctx_get_by_engine(engine);
    CU_ASSERT_PTR_NOT_NULL_FATAL(wt_ctx);

    xqc_connection_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.engine = engine;
    conn.conn_type = XQC_CONN_TYPE_SERVER;
    conn.alpn = XQC_ALPN_H3;
    conn.alpn_len = strlen(XQC_ALPN_H3);
    conn.conn_flag = XQC_CONN_FLAG_CAN_SEND_1RTT;
    conn.remote_settings.max_datagram_frame_size = 0;
    conn.remote_settings.max_udp_payload_size = 1500;
    conn.pkt_out_size = 1500;

    xqc_h3_conn_t h3_conn;
    memset(&h3_conn, 0, sizeof(h3_conn));
    h3_conn.conn = &conn;
    h3_conn.log = engine->log;
    h3_conn.local_h3_conn_settings.webtransport_mode =
        XQC_WT_MODE_BROWSER_COMPAT;
    h3_conn.peer_h3_conn_settings.h3_datagram_present = XQC_TRUE;
    h3_conn.peer_h3_conn_settings.h3_datagram = XQC_TRUE;

    xqc_wt_conn_t *wt_conn = xqc_wt_conn_create(&h3_conn);
    CU_ASSERT_PTR_NOT_NULL_FATAL(wt_conn);
    h3_conn.wt_conn = wt_conn;

    xqc_h3_stream_t h3_stream;
    memset(&h3_stream, 0, sizeof(h3_stream));
    h3_stream.h3c = &h3_conn;
    h3_stream.log = engine->log;
    h3_stream.stream_id = 4;

    xqc_wt_session_t *session = xqc_wt_session_init(h3_stream.stream_id,
        wt_conn, &h3_stream);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);

    xqc_wt_request_t wt_request;
    memset(&wt_request, 0, sizeof(wt_request));
    wt_request.wt_conn = wt_conn;
    wt_request.user_data = session;

    xqc_http_headers_t headers = {0};
    ret = xqc_wt_process_request_headers(&wt_request, wt_ctx, &headers);
    CU_ASSERT_EQUAL(ret, 1);
    CU_ASSERT_EQUAL(conn.remote_settings.max_datagram_frame_size, 1200);

    xqc_wt_conn_close(wt_conn);
    h3_conn.wt_conn = NULL;
    xqc_engine_destroy(engine);
}

void
xqc_test_wt_max_sessions_setting_survives_default_update(void)
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);

    xqc_int_t ret = xqc_wt_ctx_init_for_alpns(engine, NULL, NULL, NULL, 7,
        NULL, 0);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    xqc_h3_ctx_t *h3_ctx = xqc_engine_get_alpn_ctx(engine, XQC_ALPN_H3,
        strlen(XQC_ALPN_H3));
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3_ctx);
    CU_ASSERT_EQUAL(h3_ctx->h3c_def_local_settings.webtransport_max_sessions, 7);

    ret = xqc_wt_engine_set_default_settings(engine, XQC_WT_MODE_DRAFT15_STRICT,
        1024, 1024, 16 * 1024 * 1024, 1, 1, 1);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(h3_ctx->h3c_def_local_settings.webtransport_max_sessions, 7);

    xqc_engine_destroy(engine);
}

void
xqc_test_wt_bidi_create_reject_stops_read(void)
{
    memset(&g_wt_create_reject_state, 0, sizeof(g_wt_create_reject_state));
    int app_user_data = 11;

    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);

    xqc_webtransport_stream_callbacks_t stream_cbs = {
        .wt_bidistream_create_notify = xqc_test_wt_reject_bidi_create_notify,
        .wt_bidistream_read_notify = xqc_test_wt_reject_bidi_read_notify,
    };
    xqc_int_t ret = xqc_wt_ctx_init_for_alpns(engine, NULL, NULL,
        &stream_cbs, 4, NULL, 0);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    xqc_connection_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.engine = engine;
    conn.conn_type = XQC_CONN_TYPE_SERVER;
    conn.alpn = XQC_ALPN_H3;
    conn.alpn_len = strlen(XQC_ALPN_H3);
    conn.conn_state = XQC_CONN_STATE_CLOSING;

    xqc_h3_conn_t h3_conn;
    memset(&h3_conn, 0, sizeof(h3_conn));
    h3_conn.conn = &conn;
    h3_conn.log = engine->log;

    xqc_wt_conn_t *wt_conn = xqc_wt_conn_create(&h3_conn);
    CU_ASSERT_PTR_NOT_NULL_FATAL(wt_conn);
    wt_conn->user_data = &app_user_data;
    h3_conn.wt_conn = wt_conn;

    xqc_wt_session_t *session = xqc_wt_session_init(4, wt_conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    CU_ASSERT_EQUAL(xqc_wt_session_mark_established(session), XQC_OK);

    xqc_stream_t stream;
    memset(&stream, 0, sizeof(stream));
    stream.stream_id = 12;
    stream.stream_conn = &conn;

    xqc_h3_stream_t h3_stream;
    memset(&h3_stream, 0, sizeof(h3_stream));
    h3_stream.h3c = &h3_conn;
    h3_stream.log = engine->log;
    h3_stream.stream = &stream;
    h3_stream.stream_id = stream.stream_id;

    int cb_ret = 0;
    xqc_wt_h3_bidi_stream_created(&h3_conn, &h3_stream, &cb_ret);

    uint8_t data[16] = {0};
    size_t sid_len = xqc_wt_encode_session_id(session->session_id,
        data, sizeof(data));
    CU_ASSERT(sid_len > 0);
    data[sid_len] = 0x43;

    xqc_wt_h3_bidi_stream_recv(&h3_conn, &h3_stream, data, sid_len + 1, 0,
        &cb_ret);

    CU_ASSERT_EQUAL(g_wt_create_reject_state.create_cnt, 1);
    CU_ASSERT_EQUAL(g_wt_create_reject_state.read_cnt, 0);
    CU_ASSERT_PTR_EQUAL(g_wt_create_reject_state.created_session, session);
    CU_ASSERT_PTR_EQUAL(g_wt_create_reject_state.create_user_data,
        &app_user_data);

    xqc_wt_conn_close(wt_conn);
    h3_conn.wt_conn = NULL;
    xqc_engine_destroy(engine);
}

void
xqc_test_wt_uni_create_reject_stops_read(void)
{
    memset(&g_wt_create_reject_state, 0, sizeof(g_wt_create_reject_state));
    int app_user_data = 12;

    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);

    xqc_webtransport_stream_callbacks_t stream_cbs = {
        .wt_unistream_create_notify = xqc_test_wt_reject_uni_create_notify,
        .wt_unistream_read_notify = xqc_test_wt_reject_uni_read_notify,
    };
    xqc_int_t ret = xqc_wt_ctx_init_for_alpns(engine, NULL, NULL,
        &stream_cbs, 4, NULL, 0);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    xqc_connection_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.engine = engine;
    conn.conn_type = XQC_CONN_TYPE_SERVER;
    conn.alpn = XQC_ALPN_H3;
    conn.alpn_len = strlen(XQC_ALPN_H3);
    conn.conn_state = XQC_CONN_STATE_CLOSING;

    xqc_h3_conn_t h3_conn;
    memset(&h3_conn, 0, sizeof(h3_conn));
    h3_conn.conn = &conn;
    h3_conn.log = engine->log;

    xqc_wt_conn_t *wt_conn = xqc_wt_conn_create(&h3_conn);
    CU_ASSERT_PTR_NOT_NULL_FATAL(wt_conn);
    wt_conn->user_data = &app_user_data;
    h3_conn.wt_conn = wt_conn;

    xqc_wt_session_t *session = xqc_wt_session_init(4, wt_conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    CU_ASSERT_EQUAL(xqc_wt_session_mark_established(session), XQC_OK);

    xqc_stream_t stream;
    memset(&stream, 0, sizeof(stream));
    stream.stream_id = 14;
    stream.stream_conn = &conn;

    xqc_h3_stream_t h3_stream;
    memset(&h3_stream, 0, sizeof(h3_stream));
    h3_stream.h3c = &h3_conn;
    h3_stream.log = engine->log;
    h3_stream.stream = &stream;
    h3_stream.stream_id = stream.stream_id;

    int cb_ret = 0;
    xqc_wt_h3_uni_stream_created(&h3_conn, &h3_stream, &cb_ret);

    uint8_t data[16] = {0};
    size_t sid_len = xqc_wt_encode_session_id(session->session_id,
        data, sizeof(data));
    CU_ASSERT(sid_len > 0);
    data[sid_len] = 0x44;

    xqc_wt_h3_uni_stream_recv(&h3_conn, &h3_stream, data, sid_len + 1, 0,
        &cb_ret);

    CU_ASSERT_EQUAL(g_wt_create_reject_state.create_cnt, 1);
    CU_ASSERT_EQUAL(g_wt_create_reject_state.read_cnt, 0);
    CU_ASSERT_PTR_EQUAL(g_wt_create_reject_state.created_session, session);
    CU_ASSERT_PTR_EQUAL(g_wt_create_reject_state.create_user_data,
        &app_user_data);

    xqc_wt_conn_close(wt_conn);
    h3_conn.wt_conn = NULL;
    xqc_engine_destroy(engine);
}

void
xqc_test_wt_pending_stream_fallback_to_conn_table(void)
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);

    xqc_webtransport_stream_callbacks_t stream_cbs = {
        .wt_bidistream_read_notify = xqc_test_wt_bidi_read_notify,
    };
    xqc_int_t ret = xqc_wt_ctx_init_for_alpns(engine, NULL, NULL,
        &stream_cbs, 4, NULL, 0);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    xqc_connection_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.engine = engine;
    conn.conn_type = XQC_CONN_TYPE_SERVER;
    conn.alpn = XQC_ALPN_H3;
    conn.alpn_len = strlen(XQC_ALPN_H3);

    xqc_h3_conn_t h3_conn;
    memset(&h3_conn, 0, sizeof(h3_conn));
    h3_conn.conn = &conn;
    h3_conn.log = engine->log;

    xqc_wt_conn_t *wt_conn = xqc_wt_conn_create(&h3_conn);
    CU_ASSERT_PTR_NOT_NULL_FATAL(wt_conn);
    h3_conn.wt_conn = wt_conn;

    xqc_wt_session_t *legacy_session = xqc_wt_session_init(4, wt_conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(legacy_session);
    xqc_wt_session_t *target_session = xqc_wt_session_init(8, wt_conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(target_session);
    CU_ASSERT_EQUAL(xqc_wt_session_mark_established(target_session), XQC_OK);

    xqc_stream_t stream;
    memset(&stream, 0, sizeof(stream));
    stream.stream_id = 16;
    stream.stream_conn = &conn;

    xqc_h3_stream_t h3_stream;
    memset(&h3_stream, 0, sizeof(h3_stream));
    h3_stream.h3c = &h3_conn;
    h3_stream.log = engine->log;
    h3_stream.stream = &stream;
    h3_stream.stream_id = stream.stream_id;

    xqc_wt_bidistream_t *bidi = xqc_wt_create_bidistream(&h3_stream,
        target_session, NULL, NULL, XQC_TRUE);
    CU_ASSERT_PTR_NOT_NULL_FATAL(bidi);
    bidi->session_id = target_session->session_id;
    bidi->session = NULL;
    xqc_wt_pending_stream_t *ps = xqc_malloc(sizeof(xqc_wt_pending_stream_t));
    CU_ASSERT_PTR_NOT_NULL_FATAL(ps);
    ps->type = XQC_WT_PENDING_BIDISTREAM;
    ps->stream = bidi;
    xqc_id_hash_element_t el = { stream.stream_id, ps };
    CU_ASSERT_EQUAL(xqc_id_hash_add(wt_conn->pending_streams, el), XQC_OK);

    memset(&g_wt_bidi_create_state, 0, sizeof(g_wt_bidi_create_state));
    int cb_ret = 0;
    uint8_t data[16] = {0};
    size_t sid_len = xqc_wt_encode_session_id(target_session->session_id,
        data, sizeof(data));
    CU_ASSERT(sid_len > 0);
    data[sid_len] = 0x55;

    xqc_wt_h3_bidi_stream_recv(&h3_conn, &h3_stream, data, sid_len + 1, 0,
        &cb_ret);

    CU_ASSERT_EQUAL(cb_ret, (int)(sid_len + 1));
    CU_ASSERT_EQUAL(g_wt_bidi_create_state.read_cnt, 1);
    CU_ASSERT_PTR_EQUAL(g_wt_bidi_create_state.read_session, target_session);

    xqc_wt_conn_close(wt_conn);
    h3_conn.wt_conn = NULL;
    xqc_engine_destroy(engine);
}

void
xqc_test_wt_unistream_closing_notify_dispatch(void)
{
    memset(&g_wt_closing_state, 0, sizeof(g_wt_closing_state));
    int app_user_data = 21;

    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);

    xqc_webtransport_stream_callbacks_t stream_cbs = {
        .wt_unistream_closing_notify = xqc_test_wt_uni_closing_notify,
    };
    xqc_int_t ret = xqc_wt_ctx_init_for_alpns(engine, NULL, NULL,
        &stream_cbs, 4, NULL, 0);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    xqc_connection_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.engine = engine;
    conn.conn_type = XQC_CONN_TYPE_SERVER;
    conn.alpn = XQC_ALPN_H3;
    conn.alpn_len = strlen(XQC_ALPN_H3);

    xqc_h3_conn_t h3_conn;
    memset(&h3_conn, 0, sizeof(h3_conn));
    h3_conn.conn = &conn;
    h3_conn.log = engine->log;

    xqc_wt_conn_t *wt_conn = xqc_wt_conn_create(&h3_conn);
    CU_ASSERT_PTR_NOT_NULL_FATAL(wt_conn);
    wt_conn->user_data = &app_user_data;
    h3_conn.wt_conn = wt_conn;

    xqc_wt_session_t *session = xqc_wt_session_init(4, wt_conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);

    xqc_stream_t stream;
    memset(&stream, 0, sizeof(stream));
    stream.stream_id = 14;
    stream.stream_conn = &conn;

    xqc_h3_stream_t h3_stream;
    memset(&h3_stream, 0, sizeof(h3_stream));
    h3_stream.h3c = &h3_conn;
    h3_stream.log = engine->log;
    h3_stream.stream = &stream;
    h3_stream.stream_id = stream.stream_id;
    h3_stream.type = XQC_H3_STREAM_TYPE_WT_UNI;

    xqc_wt_unistream_t *uni = xqc_wt_create_unistream(
        XQC_WT_STREAM_TYPE_RECV, session, NULL, &h3_stream);
    CU_ASSERT_PTR_NOT_NULL_FATAL(uni);
    xqc_wt_pending_stream_t *ps = xqc_malloc(sizeof(xqc_wt_pending_stream_t));
    CU_ASSERT_PTR_NOT_NULL_FATAL(ps);
    ps->type = XQC_WT_PENDING_UNISTREAM;
    ps->stream = uni;
    xqc_id_hash_element_t el = { stream.stream_id, ps };
    CU_ASSERT_EQUAL(xqc_id_hash_add(session->pending_unistreams, el), XQC_OK);

    xqc_h3_stream_closing_notify(&stream, H3_REQUEST_CANCELLED, &h3_stream);

    CU_ASSERT_EQUAL(g_wt_closing_state.closing_cnt, 1);
    CU_ASSERT_PTR_EQUAL(g_wt_closing_state.closing_session, session);
    CU_ASSERT_PTR_EQUAL(g_wt_closing_state.closing_user_data, &app_user_data);

    xqc_wt_conn_close(wt_conn);
    h3_conn.wt_conn = NULL;
    xqc_engine_destroy(engine);
}

