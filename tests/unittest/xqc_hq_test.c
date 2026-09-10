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

static xqc_stream_t *xqc_test_hq_stream(xqc_hq_conn_t *hqc);
static int xqc_test_hq_input(xqc_stream_t *stream, const char *data,
    uint8_t fin);


static xqc_stream_t *
xqc_test_hq_stream(xqc_hq_conn_t *hqc)
{
    xqc_connection_t *conn = test_engine_connect();
    if (conn == NULL) {
        return NULL;
    }

    hqc->conn = conn;
    xqc_conn_set_alp_user_data(conn, hqc);
    conn->app_proto_cbs.stream_cbs = hq_stream_callbacks;
    xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
                                                           XQC_STREAM_BIDI,
                                                           NULL);
    if (stream == NULL || stream->user_data == NULL) {
        xqc_engine_destroy(conn->engine);
        return NULL;
    }

    return stream;
}


static int
xqc_test_hq_input(xqc_stream_t *stream, const char *data, uint8_t fin)
{
    size_t len = strlen(data);
    xqc_stream_frame_t *frame = xqc_calloc(1, sizeof(*frame));
    if (frame == NULL) {
        return -XQC_EMALLOC;
    }
    frame->data = xqc_malloc(len + 1);
    if (frame->data == NULL) {
        xqc_free(frame);
        return -XQC_EMALLOC;
    }

    memcpy(frame->data, data, len + 1);
    frame->data_length = len;
    frame->data_offset = stream->stream_data_in.merged_offset_end;
    frame->fin = fin;
    int ret = xqc_insert_stream_frame(stream->stream_conn, stream, frame);
    if (ret != XQC_OK) {
        xqc_destroy_stream_frame(frame);

    } else if (fin) {
        stream->stream_data_in.stream_determined = 1;
        stream->stream_data_in.stream_length = frame->data_offset + len;
        stream->stream_state_recv = XQC_RECV_STREAM_ST_DATA_RECVD;
    }
    return ret;
}


void
xqc_test_hq_request_recv(void)
{
    const char *requests[] = {"GET /path\r\n", "GET /path", "ET /path\r\n"};
    char buf[16];
    uint8_t fin;

    for (size_t i = 0; i < 3; i++) {
        xqc_hq_conn_t hqc = {0};
        xqc_stream_t *stream = xqc_test_hq_stream(&hqc);
        CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
        xqc_hq_request_t *hqr = stream->user_data;

        if (i == 2) {
            /* RFC 9000 Section 2.2: frame boundaries do not delimit data. */
            CU_ASSERT_EQUAL(xqc_test_hq_input(stream, "G", 0), XQC_OK);
            fin = 1;
            CU_ASSERT_EQUAL(xqc_hq_request_recv_req(hqr, buf, sizeof(buf),
                                                   &fin), 0);
            CU_ASSERT_EQUAL(fin, 0);
        }
        CU_ASSERT_EQUAL(xqc_test_hq_input(stream, requests[i], i != 2), XQC_OK);
        memset(buf, '!', sizeof(buf));
        ssize_t read = xqc_hq_request_recv_req(hqr, buf, sizeof(buf), &fin);
        CU_ASSERT_EQUAL(read, strlen("/path"));
        CU_ASSERT_EQUAL(memcmp(buf, "/path", sizeof("/path")), 0);
        CU_ASSERT_EQUAL(fin, 1);

        fin = 1;
        read = xqc_hq_request_recv_req(hqr, buf, sizeof(buf), &fin);
        CU_ASSERT_EQUAL(read, 0);
        CU_ASSERT_EQUAL(fin, 0);
        if (i == 2) {
            CU_ASSERT_EQUAL(xqc_test_hq_input(stream, "", 1), XQC_OK);
            fin = 1;
            read = xqc_hq_request_recv_req(hqr, buf, sizeof(buf), &fin);
            CU_ASSERT_EQUAL(read, 0);
            CU_ASSERT_EQUAL(fin, 0);
            CU_ASSERT_EQUAL(stream->stream_state_recv,
                            XQC_RECV_STREAM_ST_DATA_READ);
        }
        xqc_engine_destroy(stream->stream_conn->engine);
    }
}


void
xqc_test_hq_request_recv_errors(void)
{
    xqc_hq_conn_t hqc = {0};
    xqc_stream_t *stream = xqc_test_hq_stream(&hqc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    xqc_hq_request_t *hqr = stream->user_data;
    char buf[8];
    uint8_t fin;
    ssize_t read;

    CU_ASSERT_EQUAL(xqc_test_hq_input(stream, "GET /abcdef\r\n", 0), XQC_OK);
    for (size_t capacity = 0; capacity <= 1; capacity++) {
        memset(buf, '!', sizeof(buf));
        fin = 1;
        read = xqc_hq_request_recv_req(hqr, buf, capacity, &fin);
        CU_ASSERT_EQUAL(read, -XQC_ENOBUF);
        CU_ASSERT_EQUAL(fin, 0);
        CU_ASSERT_EQUAL(buf[capacity], '!');
    }

    const char *parts[] = {"/ab", "cde", "f"};
    for (size_t i = 0; i < 3; i++) {
        memset(buf, '!', sizeof(buf));
        fin = 1;
        read = xqc_hq_request_recv_req(hqr, buf, 4, &fin);
        CU_ASSERT_EQUAL(read, strlen(parts[i]));
        CU_ASSERT_EQUAL(memcmp(buf, parts[i], strlen(parts[i]) + 1), 0);
        CU_ASSERT_EQUAL(buf[4], '!');
        CU_ASSERT_EQUAL(fin, i == 2);
    }

    stream->stream_state_recv = XQC_RECV_STREAM_ST_RESET_RECVD;
    fin = 1;
    read = xqc_hq_request_recv_req(hqr, buf, sizeof(buf), &fin);
    CU_ASSERT_EQUAL(read, -XQC_ESTREAM_RESET);
    CU_ASSERT_EQUAL(fin, 0);
    xqc_engine_destroy(stream->stream_conn->engine);

    stream = xqc_test_hq_stream(&hqc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    CU_ASSERT_EQUAL(xqc_test_hq_input(stream, "GET", 1), XQC_OK);
    fin = 1;
    read = xqc_hq_request_recv_req(stream->user_data, buf, sizeof(buf), &fin);
    CU_ASSERT_EQUAL(read, -XQC_EPROTO);
    CU_ASSERT_EQUAL(fin, 0);
    xqc_engine_destroy(stream->stream_conn->engine);
}
