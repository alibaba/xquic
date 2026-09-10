/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_hq_test.h"
#include "xqc_common_test.h"
#include "demo/xqc_hq_conn.h"
#include "demo/xqc_hq_request.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_stream.h"


typedef struct {
    xqc_engine_t      *engine;
    xqc_connection_t  *conn;
    xqc_stream_t      *stream;
    xqc_hq_conn_t      hqc;
    xqc_hq_request_t  *hqr;
    size_t             input_offset;
    size_t             read_calls;
    size_t             copied_bytes;
    size_t             completions;
} xqc_test_hq_ctx_t;

static int xqc_test_hq_init(xqc_test_hq_ctx_t *ctx);
static void xqc_test_hq_destroy(xqc_test_hq_ctx_t *ctx);
static int xqc_test_hq_input(xqc_test_hq_ctx_t *ctx, const char *data,
    size_t len, uint8_t fin);
static int xqc_test_hq_read_notify(xqc_hq_request_t *hqr, void *user_data);


static int
xqc_test_hq_init(xqc_test_hq_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->engine = test_create_engine();
    if (ctx->engine == NULL) {
        return XQC_ERROR;
    }

    const xqc_cid_t *cid = test_cid_connect(ctx->engine);
    if (cid != NULL) {
        ctx->conn = xqc_engine_conns_hash_find(ctx->engine, cid, 's');
    }
    if (ctx->conn == NULL) {
        xqc_test_hq_destroy(ctx);
        return XQC_ERROR;
    }

    ctx->hqc.conn = ctx->conn;
    ctx->hqc.hqr_cbs.req_read_notify = xqc_test_hq_read_notify;
    xqc_conn_set_alp_user_data(ctx->conn, &ctx->hqc);
    ctx->conn->app_proto_cbs.stream_cbs = hq_stream_callbacks;
    ctx->stream = xqc_stream_create_with_direction(ctx->conn,
                                                   XQC_STREAM_BIDI, NULL);
    if (ctx->stream == NULL || ctx->stream->user_data == NULL) {
        xqc_test_hq_destroy(ctx);
        return XQC_ERROR;
    }

    ctx->hqr = ctx->stream->user_data;
    xqc_hq_request_set_user_data(ctx->hqr, ctx);
    return XQC_OK;
}


static void
xqc_test_hq_destroy(xqc_test_hq_ctx_t *ctx)
{
    if (ctx->engine != NULL) {
        /* The stream close callback owns the HQ request. */
        xqc_engine_destroy(ctx->engine);
        ctx->engine = NULL;
        ctx->conn = NULL;
    }
}


static int
xqc_test_hq_input(xqc_test_hq_ctx_t *ctx, const char *data, size_t len,
    uint8_t fin)
{
    xqc_stream_frame_t *frame = xqc_calloc(1, sizeof(*frame));
    if (frame == NULL) {
        return -XQC_EMALLOC;
    }

    frame->data = xqc_malloc(len + 1);
    if (frame->data == NULL) {
        xqc_free(frame);
        return -XQC_EMALLOC;
    }

    memcpy(frame->data, data, len);
    frame->data_length = len;
    frame->data_offset = ctx->input_offset;
    frame->fin = fin;
    int ret = xqc_insert_stream_frame(ctx->conn, ctx->stream, frame);
    if (ret != XQC_OK) {
        xqc_destroy_stream_frame(frame);
        return ret;
    }

    ctx->input_offset += len;
    if (fin) {
        ctx->stream->stream_data_in.stream_determined = 1;
        ctx->stream->stream_data_in.stream_length = ctx->input_offset;
        ctx->stream->stream_state_recv = XQC_RECV_STREAM_ST_DATA_RECVD;
    }

    return XQC_OK;
}


static int
xqc_test_hq_read_notify(xqc_hq_request_t *hqr, void *user_data)
{
    xqc_test_hq_ctx_t *ctx = user_data;
    char buf[64];
    uint8_t fin;
    ssize_t read;

    /* Bound the application's read loop so a regression cannot hang CUnit. */
    for (size_t i = 0; i < 8; i++) {
        read = xqc_hq_request_recv_req(hqr, buf, sizeof(buf), &fin);
        ctx->read_calls++;
        if (read < 0) {
            return (int)read;
        }
        if (read > 0 && read < sizeof(buf)) {
            ctx->copied_bytes += read;
        }
        if (fin) {
            ctx->completions++;
        }
        if (read == 0 || fin) {
            return XQC_OK;
        }
    }

    return -XQC_EFATAL;
}


void
xqc_test_hq_request_fin(void)
{
    xqc_test_hq_ctx_t ctx;
    char buf[32];
    uint8_t fin = 0;
    const char request[] = "GET /same-fin\r\n";
    int ret = xqc_test_hq_init(&ctx);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    if (ret != XQC_OK) {
        return;
    }

    CU_ASSERT_EQUAL(xqc_test_hq_input(&ctx, request, sizeof(request) - 1, 1),
                    XQC_OK);
    memset(buf, '!', sizeof(buf));
    ssize_t read = xqc_hq_request_recv_req(ctx.hqr, buf, sizeof(buf), &fin);
    CU_ASSERT_EQUAL(read, strlen("/same-fin"));
    CU_ASSERT_EQUAL(fin, 1);
    CU_ASSERT_STRING_EQUAL(buf, "/same-fin");
    CU_ASSERT_EQUAL(ctx.stream->stream_state_recv,
                    XQC_RECV_STREAM_ST_DATA_READ);

    fin = 1;
    read = xqc_hq_request_recv_req(ctx.hqr, buf, sizeof(buf), &fin);
    CU_ASSERT_EQUAL(read, 0);
    CU_ASSERT_EQUAL(fin, 0);
    xqc_test_hq_destroy(&ctx);
}


void
xqc_test_hq_request_delayed_fin(void)
{
    xqc_test_hq_ctx_t ctx;
    const char request[] = "GET /delayed-fin\r\n";
    int ret = xqc_test_hq_init(&ctx);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    if (ret != XQC_OK) {
        return;
    }

    /* RFC 9000 Section 19.8 permits FIN in a later, empty STREAM frame. */
    CU_ASSERT_EQUAL(xqc_test_hq_input(&ctx, request, sizeof(request) - 1, 0),
                    XQC_OK);
    ret = hq_stream_callbacks.stream_read_notify(ctx.stream, ctx.hqr);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(ctx.read_calls, 1);
    CU_ASSERT_EQUAL(ctx.copied_bytes, strlen("/delayed-fin"));
    CU_ASSERT_EQUAL(ctx.completions, 1);
    CU_ASSERT_EQUAL(ctx.stream->stream_stats.peer_fin_read_time, 0);

    /* An EAGAIN before FIN must not deliver the resource a second time. */
    ret = hq_stream_callbacks.stream_read_notify(ctx.stream, ctx.hqr);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(ctx.read_calls, 2);
    CU_ASSERT_EQUAL(ctx.completions, 1);

    CU_ASSERT_EQUAL(xqc_test_hq_input(&ctx, "", 0, 1), XQC_OK);
    ret = hq_stream_callbacks.stream_read_notify(ctx.stream, ctx.hqr);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(ctx.read_calls, 3);
    CU_ASSERT_EQUAL(ctx.copied_bytes, strlen("/delayed-fin"));
    CU_ASSERT_EQUAL(ctx.completions, 1);
    CU_ASSERT_EQUAL(ctx.stream->stream_state_recv,
                    XQC_RECV_STREAM_ST_DATA_READ);
    CU_ASSERT(ctx.stream->stream_stats.peer_fin_read_time != 0);

    ret = hq_stream_callbacks.stream_read_notify(ctx.stream, ctx.hqr);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(ctx.read_calls, 4);
    CU_ASSERT_EQUAL(ctx.completions, 1);
    xqc_test_hq_destroy(&ctx);

    ret = xqc_test_hq_init(&ctx);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    if (ret != XQC_OK) {
        return;
    }

    CU_ASSERT_EQUAL(xqc_test_hq_input(&ctx, request, sizeof(request) - 1, 0),
                    XQC_OK);
    ret = hq_stream_callbacks.stream_read_notify(ctx.stream, ctx.hqr);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(xqc_test_hq_input(&ctx, "tail", 4, 1), XQC_OK);
    ret = hq_stream_callbacks.stream_read_notify(ctx.stream, ctx.hqr);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(ctx.read_calls, 2);
    CU_ASSERT_EQUAL(ctx.copied_bytes, strlen("/delayed-fin"));
    CU_ASSERT_EQUAL(ctx.completions, 1);
    CU_ASSERT_EQUAL(ctx.stream->stream_data_in.next_read_offset,
                    sizeof(request) - 1 + 4);
    CU_ASSERT_EQUAL(ctx.stream->stream_state_recv,
                    XQC_RECV_STREAM_ST_DATA_READ);
    xqc_test_hq_destroy(&ctx);
}


void
xqc_test_hq_request_fragmented(void)
{
    xqc_test_hq_ctx_t ctx;
    const char *parts[] = {"G", "ET /frag", "mented\r", "\n"};
    char buf[32];
    uint8_t fin;
    int ret = xqc_test_hq_init(&ctx);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    if (ret != XQC_OK) {
        return;
    }

    /* RFC 9000 Section 2.2: frame boundaries do not delimit stream data. */
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
        CU_ASSERT_EQUAL(xqc_test_hq_input(&ctx, parts[i], strlen(parts[i]), 0),
                        XQC_OK);
        memset(buf, '!', sizeof(buf));
        fin = 1;
        ssize_t read = xqc_hq_request_recv_req(ctx.hqr, buf, sizeof(buf), &fin);
        if (i < 3) {
            CU_ASSERT_EQUAL(read, 0);
            CU_ASSERT_EQUAL(fin, 0);

        } else {
            CU_ASSERT_EQUAL(read, strlen("/fragmented"));
            CU_ASSERT_EQUAL(fin, 1);
            CU_ASSERT_STRING_EQUAL(buf, "/fragmented");
        }
    }

    xqc_test_hq_destroy(&ctx);

    ret = xqc_test_hq_init(&ctx);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    if (ret != XQC_OK) {
        return;
    }

    CU_ASSERT_EQUAL(xqc_test_hq_input(&ctx, "GET", 3, 1), XQC_OK);
    fin = 1;
    ssize_t read = xqc_hq_request_recv_req(ctx.hqr, buf, sizeof(buf), &fin);
    CU_ASSERT_EQUAL(read, -XQC_EPROTO);
    CU_ASSERT_EQUAL(fin, 0);
    xqc_test_hq_destroy(&ctx);
}


void
xqc_test_hq_request_small_buffer(void)
{
    xqc_test_hq_ctx_t ctx;
    const char request[] = "GET /abcdefg\r\n";
    const char *parts[] = {"/ab", "cde", "fg"};
    char buf[5];
    uint8_t fin;
    int ret = xqc_test_hq_init(&ctx);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    if (ret != XQC_OK) {
        return;
    }

    CU_ASSERT_EQUAL(xqc_test_hq_input(&ctx, request, sizeof(request) - 1, 0),
                    XQC_OK);
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
        memset(buf, '!', sizeof(buf));
        fin = 1;
        ssize_t read = xqc_hq_request_recv_req(ctx.hqr, buf, 4, &fin);
        CU_ASSERT_EQUAL(read, strlen(parts[i]));
        CU_ASSERT_EQUAL(fin, i == 2);
        CU_ASSERT_EQUAL(memcmp(buf, parts[i], strlen(parts[i])), 0);
        CU_ASSERT_EQUAL(buf[strlen(parts[i])], '\0');
        CU_ASSERT_EQUAL(buf[4], '!');
    }

    CU_ASSERT_EQUAL(xqc_test_hq_input(&ctx, "", 0, 1), XQC_OK);
    ssize_t read = xqc_hq_request_recv_req(ctx.hqr, buf, sizeof(buf), &fin);
    CU_ASSERT_EQUAL(read, 0);
    CU_ASSERT_EQUAL(fin, 0);
    CU_ASSERT_EQUAL(ctx.stream->stream_state_recv,
                    XQC_RECV_STREAM_ST_DATA_READ);
    xqc_test_hq_destroy(&ctx);
}


void
xqc_test_hq_request_no_buffer(void)
{
    xqc_test_hq_ctx_t ctx;
    const char request[] = "GET /retry-buffer\r\n";
    char buf[32];
    uint8_t fin;
    int ret = xqc_test_hq_init(&ctx);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    if (ret != XQC_OK) {
        return;
    }

    CU_ASSERT_EQUAL(xqc_test_hq_input(&ctx, request, sizeof(request) - 1, 1),
                    XQC_OK);
    for (size_t capacity = 0; capacity <= 1; capacity++) {
        memset(buf, '!', sizeof(buf));
        fin = 1;
        ssize_t read = xqc_hq_request_recv_req(ctx.hqr, buf, capacity, &fin);
        CU_ASSERT_EQUAL(read, -XQC_ENOBUF);
        CU_ASSERT_EQUAL(fin, 0);
        CU_ASSERT_EQUAL(buf[capacity], '!');
    }

    ssize_t read = xqc_hq_request_recv_req(ctx.hqr, buf, sizeof(buf), &fin);
    CU_ASSERT_EQUAL(read, strlen("/retry-buffer"));
    CU_ASSERT_EQUAL(fin, 1);
    CU_ASSERT_EQUAL(memcmp(buf, "/retry-buffer", sizeof("/retry-buffer")), 0);
    xqc_test_hq_destroy(&ctx);
}


void
xqc_test_hq_request_recv_reset(void)
{
    const char request[] = "GET /reset\r\n";
    char buf[32];
    uint8_t fin;

    for (int stage = 0; stage <= 2; stage++) {
        xqc_test_hq_ctx_t ctx;
        int ret = xqc_test_hq_init(&ctx);
        CU_ASSERT_EQUAL(ret, XQC_OK);
        if (ret != XQC_OK) {
            return;
        }

        if (stage > 0) {
            CU_ASSERT_EQUAL(xqc_test_hq_input(&ctx, request,
                                             sizeof(request) - 1, 0), XQC_OK);
            size_t capacity = stage == 1 ? 4 : sizeof(buf);
            ssize_t read = xqc_hq_request_recv_req(ctx.hqr, buf, capacity,
                                                   &fin);
            CU_ASSERT_EQUAL(read, stage == 1 ? 3 : strlen("/reset"));
            CU_ASSERT_EQUAL(fin, stage == 2);
        }

        ctx.stream->stream_state_recv = XQC_RECV_STREAM_ST_RESET_RECVD;
        fin = 1;
        ssize_t read = xqc_hq_request_recv_req(ctx.hqr, buf, sizeof(buf), &fin);
        CU_ASSERT_EQUAL(read, -XQC_ESTREAM_RESET);
        CU_ASSERT_EQUAL(fin, 0);
        CU_ASSERT_EQUAL(ctx.stream->stream_state_recv,
                        XQC_RECV_STREAM_ST_RESET_READ);
        xqc_test_hq_destroy(&ctx);
    }
}


void
xqc_test_hq_request_transport_fin(void)
{
    xqc_test_hq_ctx_t ctx;
    const char request[] = "GET /transport-fin";
    char buf[32];
    uint8_t fin = 0;
    int ret = xqc_test_hq_init(&ctx);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    if (ret != XQC_OK) {
        return;
    }

    CU_ASSERT_EQUAL(xqc_test_hq_input(&ctx, request, sizeof(request) - 1, 1),
                    XQC_OK);
    ssize_t read = xqc_hq_request_recv_req(ctx.hqr, buf, sizeof(buf), &fin);
    CU_ASSERT_EQUAL(read, strlen("/transport-fin"));
    CU_ASSERT_EQUAL(fin, 1);
    CU_ASSERT_STRING_EQUAL(buf, "/transport-fin");
    xqc_test_hq_destroy(&ctx);
}
