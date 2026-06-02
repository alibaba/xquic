/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <string.h>

#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_ctx.h"
#include "src/http3/xqc_h3_request.h"
#include "src/transport/xqc_engine.h"
#include "src/webtransport/xqc_webtransport_request.h"
#include "src/webtransport/xqc_webtransport_ctx.h"
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
