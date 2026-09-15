/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#include <limits.h>
#include <string.h>

#include <CUnit/CUnit.h>
#include <xquic/xqc_webtransport_msg.h>

#include "xqc_webtransport_msg_test.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_ctx.h"
#include "src/webtransport/xqc_webtransport_h3_stream.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "src/webtransport/xqc_webtransport_stream.h"

#define WT_MSG_TEST_OUTPUT_CAPACITY 1024
#define WT_MSG_TEST_RECORD_CAPACITY 8
#define WT_MSG_TEST_PAYLOAD_CAPACITY 128

typedef struct {
    xqc_wt_msg_type_t type;
    size_t             len;
    unsigned char      data[WT_MSG_TEST_PAYLOAD_CAPACITY];
} wt_msg_test_record_t;

typedef struct {
    xqc_wt_ctx_t        wt_ctx;
    xqc_h3_conn_t       h3_conn;
    xqc_wt_conn_t      *wt_conn;
    xqc_wt_session_t   *session;
    xqc_h3_stream_t     h3_stream;
    xqc_wt_stream_base_t *stream;
    xqc_wt_msg_stream_t *msg_stream;
    unsigned char       output[WT_MSG_TEST_OUTPUT_CAPACITY];
    size_t              output_len;
    size_t              send_limit;
    xqc_bool_t          send_blocked;
    xqc_int_t           send_error;
    size_t              fin_calls;
    xqc_bool_t          recursive_flush;
    xqc_int_t           recursive_flush_result;
    xqc_bool_t          recursive_recv;
    xqc_int_t           recursive_recv_result;
    xqc_bool_t          destroy_on_send;
    xqc_bool_t          destroy_on_notify;
    wt_msg_test_record_t records[WT_MSG_TEST_RECORD_CAPACITY];
    size_t              record_count;
} wt_msg_test_t;

static ssize_t wt_msg_test_send(xqc_h3_stream_t *stream,
    const unsigned char *data, size_t len, uint8_t fin);
static xqc_int_t wt_msg_test_cancel(xqc_h3_stream_t *stream,
    uint64_t error);
static xqc_int_t wt_msg_test_pause(xqc_h3_stream_t *stream,
    xqc_bool_t paused);
static void wt_msg_test_detach(xqc_h3_stream_t *stream);
static void wt_msg_test_notify(xqc_wt_msg_stream_t *msg_stream,
    xqc_wt_msg_type_t type, const void *data, size_t data_len,
    void *user_data);
static xqc_bool_t wt_msg_test_init(wt_msg_test_t *test,
    size_t max_message_size);
static void wt_msg_test_destroy(wt_msg_test_t *test);

static const xqc_wt_stream_io_ops_t wt_msg_test_io = {
    wt_msg_test_send,
    wt_msg_test_cancel,
    wt_msg_test_cancel,
    wt_msg_test_pause,
    wt_msg_test_detach,
};

static ssize_t
wt_msg_test_send(xqc_h3_stream_t *stream, const unsigned char *data,
    size_t len, uint8_t fin)
{
    wt_msg_test_t *test = stream->user_data;
    if (test->recursive_flush) {
        test->recursive_flush = XQC_FALSE;
        test->recursive_flush_result =
            xqc_wt_msg_stream_flush(test->msg_stream);
    }
    if (test->destroy_on_send) {
        test->destroy_on_send = XQC_FALSE;
        xqc_wt_msg_stream_destroy(test->msg_stream);
        test->msg_stream = NULL;
    }
    if (fin) {
        test->fin_calls++;
    }
    if (test->send_error != XQC_OK) {
        return test->send_error;
    }
    if (test->send_blocked && len != 0) {
        return -XQC_EAGAIN;
    }

    size_t sent = len < test->send_limit ? len : test->send_limit;
    CU_ASSERT(test->output_len + sent <= sizeof(test->output));
    if (test->output_len + sent > sizeof(test->output)) {
        return -XQC_ENOBUF;
    }
    if (sent != 0) {
        memcpy(test->output + test->output_len, data, sent);
        test->output_len += sent;
    }
    return sent == 0 && len != 0 ? -XQC_EAGAIN : (ssize_t)sent;
}

static xqc_int_t
wt_msg_test_cancel(xqc_h3_stream_t *stream, uint64_t error)
{
    return XQC_OK;
}

static xqc_int_t
wt_msg_test_pause(xqc_h3_stream_t *stream, xqc_bool_t paused)
{
    return XQC_OK;
}

static void
wt_msg_test_detach(xqc_h3_stream_t *stream)
{
    xqc_wt_h3_stream_detach(stream);
    xqc_wt_h3_stream_close(stream);
}

static void
wt_msg_test_notify(xqc_wt_msg_stream_t *msg_stream,
    xqc_wt_msg_type_t type, const void *data, size_t data_len,
    void *user_data)
{
    wt_msg_test_t *test = user_data;
    CU_ASSERT_PTR_EQUAL(msg_stream, test->msg_stream);
    CU_ASSERT(test->record_count < WT_MSG_TEST_RECORD_CAPACITY);
    CU_ASSERT(data_len <= WT_MSG_TEST_PAYLOAD_CAPACITY);
    if (test->record_count >= WT_MSG_TEST_RECORD_CAPACITY
        || data_len > WT_MSG_TEST_PAYLOAD_CAPACITY)
    {
        return;
    }

    wt_msg_test_record_t *record = &test->records[test->record_count++];
    record->type = type;
    record->len = data_len;
    if (data_len != 0) {
        memcpy(record->data, data, data_len);
    }
    if (test->recursive_recv) {
        test->recursive_recv = XQC_FALSE;
        test->recursive_recv_result =
            xqc_wt_msg_stream_recv_msg(msg_stream, NULL, 0);
    }
    if (test->destroy_on_notify) {
        test->destroy_on_notify = XQC_FALSE;
        xqc_wt_msg_stream_destroy(msg_stream);
        test->msg_stream = NULL;
    }
}

static xqc_bool_t
wt_msg_test_init(wt_msg_test_t *test, size_t max_message_size)
{
    memset(test, 0, sizeof(*test));
    test->send_limit = SIZE_MAX;
    test->h3_stream.stream_id = 8;
    test->h3_stream.h3c = &test->h3_conn;
    test->h3_stream.user_data = test;

    test->wt_conn = xqc_wt_conn_create(&test->h3_conn);
    if (test->wt_conn == NULL) {
        return XQC_FALSE;
    }
    test->wt_conn->ctx = &test->wt_ctx;
    test->wt_conn->negotiated_version =
        XQC_WEBTRANSPORT_DRAFT_VERSION_16;

    test->session = xqc_wt_session_init(4, test->wt_conn, NULL);
    if (test->session == NULL) {
        xqc_wt_conn_destroy(test->wt_conn);
        test->wt_conn = NULL;
        return XQC_FALSE;
    }
    test->session->open = XQC_TRUE;

    test->stream = xqc_wt_stream_bind(test->session, &test->h3_stream,
                                      XQC_TRUE, XQC_TRUE, NULL);
    if (test->stream == NULL) {
        xqc_wt_conn_destroy(test->wt_conn);
        test->wt_conn = NULL;
        return XQC_FALSE;
    }
    test->stream->io = &wt_msg_test_io;

    int err = -XQC_ESTATE;
    test->msg_stream = xqc_wt_msg_stream_create(
        (xqc_wt_bidistream_t *)test->stream, max_message_size,
        wt_msg_test_notify, test, &err);
    if (test->msg_stream == NULL || err != XQC_OK) {
        xqc_wt_msg_stream_destroy(test->msg_stream);
        test->msg_stream = NULL;
        xqc_wt_conn_destroy(test->wt_conn);
        test->wt_conn = NULL;
        return XQC_FALSE;
    }
    return XQC_TRUE;
}

static void
wt_msg_test_destroy(wt_msg_test_t *test)
{
    if (test->msg_stream != NULL) {
        xqc_wt_msg_stream_destroy(test->msg_stream);
    }
    test->msg_stream = NULL;
    xqc_wt_conn_destroy(test->wt_conn);
    test->wt_conn = NULL;
}

void
xqc_test_wt_msg_send(void)
{
    wt_msg_test_t test;
    CU_ASSERT_FATAL(wt_msg_test_init(&test, 128));

    CU_ASSERT(xqc_wt_msg_stream_send_msg(test.msg_stream,
              XQC_WT_MSG_BINARY, "bin", 3) == XQC_OK);
    CU_ASSERT(xqc_wt_msg_stream_send_msg(test.msg_stream,
              XQC_WT_MSG_TEXT, "text", 4) == XQC_OK);
    CU_ASSERT(xqc_wt_msg_stream_send_msg(test.msg_stream,
              XQC_WT_MSG_BINARY, NULL, 0) == XQC_OK);

    static const unsigned char expected[] = {
        0x40, 0x41, 0x04,
        0x00, 0x00, 0x03, 'b', 'i', 'n',
        0x00, 0x01, 0x04, 't', 'e', 'x', 't',
        0x00, 0x00, 0x00,
    };
    CU_ASSERT(test.output_len == sizeof(expected));
    CU_ASSERT(memcmp(test.output, expected, sizeof(expected)) == 0);

    test.output_len = 0;
    unsigned char payload[64];
    memset(payload, 'd', sizeof(payload));
    CU_ASSERT(xqc_wt_msg_stream_send_msg(test.msg_stream,
              XQC_WT_MSG_BINARY, payload, 63) == XQC_OK);
    CU_ASSERT(test.output_len == 66);
    CU_ASSERT(test.output[0] == 0x00);
    CU_ASSERT(test.output[1] == 0x00);
    CU_ASSERT(test.output[2] == 0x3f);
    CU_ASSERT(memcmp(test.output + 3, payload, 63) == 0);

    test.output_len = 0;
    CU_ASSERT(xqc_wt_msg_stream_send_msg(test.msg_stream,
              XQC_WT_MSG_TEXT, payload, 64) == XQC_OK);
    CU_ASSERT(test.output_len == 68);
    CU_ASSERT(test.output[0] == 0x00);
    CU_ASSERT(test.output[1] == 0x01);
    CU_ASSERT(test.output[2] == 0x40);
    CU_ASSERT(test.output[3] == 0x40);
    CU_ASSERT(memcmp(test.output + 4, payload, 64) == 0);

    wt_msg_test_destroy(&test);
}

void
xqc_test_wt_msg_receive(void)
{
    wt_msg_test_t test;
    CU_ASSERT_FATAL(wt_msg_test_init(&test, 128));

    unsigned char split[68] = {0x00, 0x00, 0x40, 0x40};
    memset(split + 4, 'd', 64);
    for (size_t i = 0; i < sizeof(split); i++) {
        CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream,
                                             split + i, 1) == XQC_OK);
        CU_ASSERT(test.record_count == (i + 1 == sizeof(split) ? 1 : 0));
    }
    CU_ASSERT(test.records[0].type == XQC_WT_MSG_BINARY);
    CU_ASSERT(test.records[0].len == 64);
    CU_ASSERT(memcmp(test.records[0].data, split + 4, 64) == 0);

    static const unsigned char coalesced[] = {
        0x00, 0x00, 0x01, 'a',
        0x00, 0xff, 0x02, 'o', 'k',
        0x00, 0x00, 0x00,
    };
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream, coalesced,
                                         sizeof(coalesced)) == XQC_OK);
    CU_ASSERT(test.record_count == 4);
    CU_ASSERT(test.records[1].type == XQC_WT_MSG_BINARY);
    CU_ASSERT(test.records[1].len == 1);
    CU_ASSERT(test.records[1].data[0] == 'a');
    CU_ASSERT(test.records[2].type == XQC_WT_MSG_TEXT);
    CU_ASSERT(test.records[2].len == 2);
    CU_ASSERT(memcmp(test.records[2].data, "ok", 2) == 0);
    CU_ASSERT(test.records[3].type == XQC_WT_MSG_BINARY);
    CU_ASSERT(test.records[3].len == 0);

    /* RFC 9000 Section 16 permits a value to use a longer encoding. */
    static const unsigned char non_minimal[] = {
        0x00, 0x00, 0x40, 0x01, 'z',
    };
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream, non_minimal,
                                         sizeof(non_minimal)) == XQC_OK);
    CU_ASSERT(test.record_count == 5);
    CU_ASSERT(test.records[4].type == XQC_WT_MSG_BINARY);
    CU_ASSERT(test.records[4].len == 1);
    CU_ASSERT(test.records[4].data[0] == 'z');

    static const unsigned char extended_lengths[] = {
        0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        0x00, 0x01, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream, extended_lengths,
                                         sizeof(extended_lengths)) == XQC_OK);
    CU_ASSERT(test.record_count == 7);
    CU_ASSERT(test.records[5].type == XQC_WT_MSG_BINARY);
    CU_ASSERT(test.records[5].len == 0);
    CU_ASSERT(test.records[6].type == XQC_WT_MSG_TEXT);
    CU_ASSERT(test.records[6].len == 0);

    wt_msg_test_destroy(&test);
}

void
xqc_test_wt_msg_backpressure(void)
{
    wt_msg_test_t test;
    CU_ASSERT_FATAL(wt_msg_test_init(&test, 16));

    unsigned char payload[] = "abc";
    test.send_blocked = XQC_TRUE;
    CU_ASSERT(xqc_wt_msg_stream_send_msg(test.msg_stream,
              XQC_WT_MSG_BINARY, payload, 3) == XQC_OK);
    memcpy(payload, "xyz", 3);
    CU_ASSERT(test.output_len == 0);
    CU_ASSERT(xqc_wt_msg_stream_send_msg(test.msg_stream,
              XQC_WT_MSG_TEXT, "x", 1) == -XQC_EAGAIN);
    CU_ASSERT(xqc_wt_msg_stream_finish(test.msg_stream) == XQC_OK);
    CU_ASSERT(xqc_wt_msg_stream_finish(test.msg_stream) == XQC_OK);
    CU_ASSERT(xqc_wt_msg_stream_send_msg(test.msg_stream,
              XQC_WT_MSG_TEXT, "x", 1) == -XQC_ESTATE);
    CU_ASSERT(test.fin_calls == 0);
    CU_ASSERT(xqc_wt_msg_stream_flush(test.msg_stream) == XQC_OK);
    CU_ASSERT(test.output_len == 0);

    test.send_blocked = XQC_FALSE;
    test.send_limit = 1;
    for (size_t i = 0; i < 16 && test.output_len < 9; i++) {
        CU_ASSERT(xqc_wt_msg_stream_flush(test.msg_stream) == XQC_OK);
    }
    static const unsigned char first[] = {
        0x40, 0x41, 0x04, 0x00, 0x00, 0x03, 'a', 'b', 'c',
    };
    CU_ASSERT(test.output_len == sizeof(first));
    CU_ASSERT(memcmp(test.output, first, sizeof(first)) == 0);
    CU_ASSERT(test.fin_calls == 1);
    CU_ASSERT(xqc_wt_msg_stream_flush(test.msg_stream) == XQC_OK);
    CU_ASSERT(test.output_len == sizeof(first));
    CU_ASSERT(test.fin_calls == 1);
    CU_ASSERT(xqc_wt_msg_stream_finish(test.msg_stream) == XQC_OK);
    CU_ASSERT(test.fin_calls == 1);
    CU_ASSERT(xqc_wt_msg_stream_send_msg(test.msg_stream,
              XQC_WT_MSG_BINARY, NULL, 0) == -XQC_ESTATE);

    wt_msg_test_destroy(&test);

    CU_ASSERT_FATAL(wt_msg_test_init(&test, 16));
    CU_ASSERT(xqc_wt_msg_stream_finish(test.msg_stream) == XQC_OK);
    static const unsigned char prefix[] = {0x40, 0x41, 0x04};
    CU_ASSERT(test.output_len == sizeof(prefix));
    CU_ASSERT(memcmp(test.output, prefix, sizeof(prefix)) == 0);
    CU_ASSERT(test.fin_calls == 1);
    CU_ASSERT(xqc_wt_msg_stream_finish(test.msg_stream) == XQC_OK);
    CU_ASSERT(xqc_wt_msg_stream_flush(test.msg_stream) == XQC_OK);
    CU_ASSERT(test.fin_calls == 1);
    CU_ASSERT(xqc_wt_msg_stream_send_msg(test.msg_stream,
              XQC_WT_MSG_BINARY, "x", 1) == -XQC_ESTATE);
    wt_msg_test_destroy(&test);
}

void
xqc_test_wt_msg_errors(void)
{
    int err = XQC_OK;
    CU_ASSERT_PTR_NULL(xqc_wt_msg_stream_create(NULL, 16,
                       wt_msg_test_notify, NULL, &err));
    CU_ASSERT(err == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(xqc_wt_msg_stream_create(NULL, 16,
                       wt_msg_test_notify, NULL, NULL));

    wt_msg_test_t test;
    CU_ASSERT_FATAL(wt_msg_test_init(&test, 4));
    CU_ASSERT_PTR_NULL(xqc_wt_msg_stream_create(
        (xqc_wt_bidistream_t *)test.stream, 0,
        wt_msg_test_notify, &test, &err));
    CU_ASSERT(err == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(xqc_wt_msg_stream_create(
        (xqc_wt_bidistream_t *)test.stream, 4, NULL, &test, &err));
    CU_ASSERT(err == -XQC_EPARAM);
    CU_ASSERT(xqc_wt_msg_stream_send_msg(NULL, XQC_WT_MSG_BINARY,
                                         NULL, 0) == -XQC_EPARAM);
    CU_ASSERT(xqc_wt_msg_stream_send_msg(test.msg_stream,
              (xqc_wt_msg_type_t)2, NULL, 0) == -XQC_EPARAM);
    CU_ASSERT(xqc_wt_msg_stream_send_msg(test.msg_stream,
              XQC_WT_MSG_BINARY, NULL, 1) == -XQC_EPARAM);
    CU_ASSERT(xqc_wt_msg_stream_send_msg(test.msg_stream,
              XQC_WT_MSG_BINARY, "12345", 5) == -XQC_ELIMIT);
    CU_ASSERT(xqc_wt_msg_stream_flush(NULL) == -XQC_EPARAM);
    CU_ASSERT(xqc_wt_msg_stream_finish(NULL) == -XQC_EPARAM);
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(NULL, NULL, 0) == -XQC_EPARAM);
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream,
                                         NULL, 1) == -XQC_EPARAM);

    static const unsigned char oversized[] = {0x00, 0x00, 0x05};
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream, oversized,
                                         sizeof(oversized)) == -XQC_ELIMIT);
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream, "\0\0\0",
                                         3) == -XQC_ELIMIT);
    CU_ASSERT(test.record_count == 0);
    wt_msg_test_destroy(&test);

    CU_ASSERT_FATAL(wt_msg_test_init(&test, 16));
    static const unsigned char unknown[] = {0x01, 0x00, 0x00};
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream, unknown,
                                         sizeof(unknown)) == -XQC_EVERSION);
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream, "\0\0\0",
                                         3) == -XQC_EVERSION);
    CU_ASSERT(test.record_count == 0);
    wt_msg_test_destroy(&test);

    CU_ASSERT_FATAL(wt_msg_test_init(&test, 16));
    test.stream->recv_fin = XQC_TRUE;
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream, "\0",
                                         1) == -XQC_EPROTO);
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream, "\0\0",
                                         2) == -XQC_EPROTO);
    CU_ASSERT(test.record_count == 0);
    wt_msg_test_destroy(&test);

    CU_ASSERT_FATAL(wt_msg_test_init(&test, 16));
    test.stream->recv_fin = XQC_TRUE;
    static const unsigned char truncated_varint[] = {
        0x00, 0x00, 0x40,
    };
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream, truncated_varint,
              sizeof(truncated_varint)) == -XQC_EPROTO);
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream, "\0",
                                         1) == -XQC_EPROTO);
    CU_ASSERT(test.record_count == 0);
    wt_msg_test_destroy(&test);

    CU_ASSERT_FATAL(wt_msg_test_init(&test, 16));
    test.stream->recv_fin = XQC_TRUE;
    static const unsigned char truncated_payload[] = {
        0x00, 0x00, 0x02, 'a',
    };
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream, truncated_payload,
              sizeof(truncated_payload)) == -XQC_EPROTO);
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream, "b",
                                         1) == -XQC_EPROTO);
    CU_ASSERT(test.record_count == 0);
    wt_msg_test_destroy(&test);

    CU_ASSERT_FATAL(wt_msg_test_init(&test, 16));
    test.stream->recv_fin = XQC_TRUE;
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream, "\0\1\0",
                                         3) == XQC_OK);
    CU_ASSERT(test.record_count == 1);
    CU_ASSERT(test.records[0].type == XQC_WT_MSG_TEXT);
    CU_ASSERT(test.records[0].len == 0);
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream,
                                         NULL, 0) == -XQC_ESTATE);
    wt_msg_test_destroy(&test);

    CU_ASSERT_FATAL(wt_msg_test_init(&test, 16));
    test.send_error = -XQC_ESYS;
    CU_ASSERT(xqc_wt_msg_stream_send_msg(test.msg_stream,
              XQC_WT_MSG_BINARY, "x", 1) == -XQC_ESYS);
    test.send_error = XQC_OK;
    CU_ASSERT(xqc_wt_msg_stream_flush(test.msg_stream) == -XQC_ESYS);
    CU_ASSERT(xqc_wt_msg_stream_finish(test.msg_stream) == -XQC_ESYS);
    CU_ASSERT(xqc_wt_msg_stream_send_msg(test.msg_stream,
              XQC_WT_MSG_BINARY, "x", 1) == -XQC_ESYS);
    wt_msg_test_destroy(&test);

    CU_ASSERT_FATAL(wt_msg_test_init(&test, 16));
    test.recursive_flush = XQC_TRUE;
    test.recursive_flush_result = XQC_OK;
    CU_ASSERT(xqc_wt_msg_stream_send_msg(test.msg_stream,
              XQC_WT_MSG_TEXT, "x", 1) == XQC_OK);
    CU_ASSERT(test.recursive_flush_result == -XQC_ESTATE);
    wt_msg_test_destroy(&test);

    CU_ASSERT_FATAL(wt_msg_test_init(&test, 16));
    test.send_blocked = XQC_TRUE;
    CU_ASSERT(xqc_wt_msg_stream_send_msg(test.msg_stream,
              XQC_WT_MSG_BINARY, "x", 1) == XQC_OK);
    CU_ASSERT(xqc_wt_msg_stream_finish(test.msg_stream) == XQC_OK);
    test.send_blocked = XQC_FALSE;
    test.destroy_on_send = XQC_TRUE;
    CU_ASSERT(xqc_wt_msg_stream_flush(test.msg_stream) == XQC_OK);
    CU_ASSERT_PTR_NULL(test.msg_stream);
    CU_ASSERT(test.fin_calls == 0);
    wt_msg_test_destroy(&test);

    CU_ASSERT_FATAL(wt_msg_test_init(&test, 16));
    test.recursive_recv = XQC_TRUE;
    test.recursive_recv_result = XQC_OK;
    test.destroy_on_notify = XQC_TRUE;
    static const unsigned char destroy_input[] = {
        0x00, 0x00, 0x01, 'a',
        0x00, 0x00, 0x01, 'b',
    };
    CU_ASSERT(xqc_wt_msg_stream_recv_msg(test.msg_stream, destroy_input,
                                         sizeof(destroy_input)) == XQC_OK);
    CU_ASSERT_PTR_NULL(test.msg_stream);
    CU_ASSERT(test.recursive_recv_result == -XQC_ESTATE);
    CU_ASSERT(test.record_count == 1);
    CU_ASSERT(test.records[0].data[0] == 'a');
    wt_msg_test_destroy(&test);
}
