/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include <CUnit/CUnit.h>
#include "xqc_common_test.h"
#include "xqc_webtransport_h3_stream_test.h"
#include "src/webtransport/xqc_webtransport_h3_stream.h"
#include "src/webtransport/xqc_webtransport_ctx.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/common/xqc_priority_q.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_request.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_datagram.h"
#include "demo/xqc_wt_echo_server.h"

typedef struct {
    xqc_engine_t      *engine;
    xqc_h3_conn_t     *h3c;
    xqc_h3_stream_t   *h3s;
    xqc_wt_conn_t     *wt_conn;
    unsigned           creates;
    unsigned           closes;
    unsigned           writes;
    xqc_bool_t         close_on_create;
    xqc_bool_t         close_on_write;
    unsigned           reads;
    unsigned           fins;
    unsigned           drains;
    unsigned           stops;
    unsigned           resets;
    xqc_bool_t         closing_error_valid;
    uint32_t           closing_error;
    xqc_bool_t         blocked;
    xqc_bool_t         destroy_on_stop;
    size_t             received;
    unsigned char      data[16];
} xqc_wt_h3_test_t;

static xqc_int_t wt_h3_test_bidi_create(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *ctx);
static xqc_int_t wt_h3_test_uni_create(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *ctx);
static xqc_int_t wt_h3_test_bidi_write(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *ctx);
static xqc_int_t wt_h3_test_bidi_read(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t len, void *ctx);
static xqc_int_t wt_h3_test_uni_read(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t len, void *ctx);
static xqc_int_t wt_h3_test_bidi_close(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *ctx);
static xqc_int_t wt_h3_test_uni_close(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *ctx);
static xqc_int_t wt_h3_test_uni_closing(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *ctx);
static xqc_int_t wt_h3_test_read(xqc_wt_h3_test_t *test,
    const void *data, size_t len, xqc_bool_t fin);
static xqc_int_t wt_h3_test_init(xqc_wt_h3_test_t *test, xqc_bool_t bidi);
static xqc_int_t wt_h3_test_init_echo(xqc_wt_h3_test_t *test,
    xqc_bool_t bidi, xqc_bool_t echo);
static void wt_h3_test_schedule(void *data);
static xqc_int_t wt_h3_test_input(xqc_wt_h3_test_t *test,
    unsigned char *data, size_t len, uint8_t fin);
static void wt_h3_test_close(xqc_wt_h3_test_t *test);
static xqc_int_t wt_h3_test_queue(xqc_wt_h3_test_t *test,
    const unsigned char *data, size_t len, uint8_t fin);
static void wt_h3_test_drain(xqc_wt_session_t *session, void *ctx);
static xqc_wt_unistream_t *wt_h3_test_outgoing(xqc_wt_h3_test_t *test);
static unsigned wt_h3_test_reset_count(xqc_stream_t *stream);
static void wt_h3_test_sent_prefix(xqc_stream_t *stream,
    const unsigned char *expected, size_t length);
static void wt_h3_test_client(xqc_wt_h3_test_t *test,
    xqc_webtransport_draft_version_t version);
static xqc_int_t wt_h3_test_server_stream(xqc_wt_h3_test_t *test);

typedef struct {
    xqc_h3_stream_t h3s;
    unsigned resets;
    unsigned stops;
    unsigned detached;
    uint64_t error;
} xqc_wt_pending_test_t;

static xqc_int_t wt_pending_reset(xqc_h3_stream_t *h3s, uint64_t error);
static xqc_int_t wt_pending_stop(xqc_h3_stream_t *h3s, uint64_t error);
static void wt_pending_detach(xqc_h3_stream_t *h3s);
static xqc_int_t wt_pending_fill(xqc_wt_conn_t *conn,
    xqc_wt_pending_test_t *entries, size_t count, xqc_bool_t bidi);
static size_t wt_pending_count(xqc_wt_conn_t *conn);

static xqc_int_t
wt_pending_reset(xqc_h3_stream_t *h3s, uint64_t error)
{
    xqc_wt_pending_test_t *entry = h3s->user_data;
    entry->resets++;
    entry->error = error;
    return XQC_OK;
}

static xqc_int_t
wt_pending_stop(xqc_h3_stream_t *h3s, uint64_t error)
{
    xqc_wt_pending_test_t *entry = h3s->user_data;
    entry->stops++;
    entry->error = error;
    return XQC_OK;
}

static void
wt_pending_detach(xqc_h3_stream_t *h3s)
{
    ((xqc_wt_pending_test_t *)h3s->user_data)->detached++;
}

static xqc_int_t
wt_pending_fill(xqc_wt_conn_t *conn, xqc_wt_pending_test_t *entries,
    size_t count, xqc_bool_t bidi)
{
    static const xqc_wt_stream_io_ops_t io = {
        .reset = wt_pending_reset,
        .stop = wt_pending_stop,
        .detach = wt_pending_detach,
    };
    /* Seed local queue state without creating peer traffic. */
    memset(entries, 0, count * sizeof(*entries));
    for (size_t i = 0; i < count; i++) {
        xqc_wt_stream_base_t *stream = xqc_calloc(1, sizeof(*stream));
        if (!stream) {
            return -XQC_EMALLOC;
        }
        entries[i].h3s.user_data = &entries[i];
        stream->h3_stream = &entries[i].h3s;
        stream->io = &io;
        stream->session_id = 1024;
        stream->session_id_complete = XQC_TRUE;
        stream->can_send = bidi;
        stream->can_recv = XQC_TRUE;
        stream->listed = XQC_TRUE;
        xqc_list_add_tail(&stream->list, &conn->pending_streams);
    }
    return XQC_OK;
}

static size_t
wt_pending_count(xqc_wt_conn_t *conn)
{
    size_t count = 0;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &conn->pending_streams) {
        count++;
    }
    return count;
}

void
xqc_test_wt_pending_session_admission(void)
{
    /* Draft-16 §4.6 / draft-07 §4.5 limit only streams needing buffering. */
    for (unsigned variant = 0; variant < 4; variant++) {
        xqc_bool_t bidi = variant & 1;
        xqc_wt_h3_test_t test;
        CU_ASSERT_FATAL(wt_h3_test_init(&test, bidi) == XQC_OK);
        test.wt_conn->negotiated_version = variant < 2
            ? XQC_WEBTRANSPORT_DRAFT_VERSION_7
            : XQC_WEBTRANSPORT_DRAFT_VERSION_16;
        xqc_wt_pending_test_t pending[64];
        CU_ASSERT_FATAL(wt_pending_fill(test.wt_conn, pending, 64, bidi)
                        == XQC_OK);
        unsigned char wire[] = {0x40, bidi ? 0x41 : 0x54, 4, 'a', 'b', 'c'};
        CU_ASSERT(wt_h3_test_input(&test, wire, sizeof(wire), 1) == XQC_OK);
        CU_ASSERT(test.creates == 1 && test.received == 3 && test.fins == 1);
        CU_ASSERT(memcmp(test.data, "abc", 3) == 0);
        CU_ASSERT(wt_pending_count(test.wt_conn) == 64);
        CU_ASSERT(pending[0].detached == 0 && pending[63].detached == 0);
        CU_ASSERT(test.h3c->conn->conn_err == 0);
        wt_h3_test_close(&test);
        CU_ASSERT(test.closes == 1);
        for (size_t i = 0; i < 64; i++) {
            CU_ASSERT(pending[i].detached == 1);
        }
    }
}

void
xqc_test_wt_pending_eviction_resume(void)
{
    /* Draft-16 §4.6 / draft-07 §4.5 allow discarding the oldest waiter. */
    for (unsigned variant = 0; variant < 4; variant++) {
        xqc_bool_t bidi = variant & 1;
        xqc_wt_h3_test_t test;
        CU_ASSERT_FATAL(wt_h3_test_init(&test, bidi) == XQC_OK);
        test.wt_conn->negotiated_version = variant < 2
            ? XQC_WEBTRANSPORT_DRAFT_VERSION_7
            : XQC_WEBTRANSPORT_DRAFT_VERSION_16;
        xqc_wt_pending_test_t pending[64];
        CU_ASSERT_FATAL(wt_pending_fill(test.wt_conn, pending, 64, bidi)
                        == XQC_OK);
        unsigned char wire[] = {0x40, bidi ? 0x41 : 0x54, 20, 'x'};
        CU_ASSERT(wt_h3_test_input(&test, wire, sizeof(wire), 1) == XQC_OK);
        CU_ASSERT(wt_pending_count(test.wt_conn) == 64);
        CU_ASSERT(pending[0].detached == 1 && pending[1].detached == 0);
        CU_ASSERT(pending[0].resets == bidi && pending[0].stops == 1);
        CU_ASSERT(pending[0].error == UINT64_C(0x3994bd84));
        CU_ASSERT(test.creates == 0 && test.reads == 0 && test.closes == 0);
        xqc_wt_session_t *session =
            xqc_wt_session_init(20, test.wt_conn, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(session);
        session->open = XQC_TRUE;
        xqc_wt_conn_resume_streams(test.wt_conn);
        CU_ASSERT(xqc_wt_h3_stream_prepare_read(test.h3s) == XQC_OK);
        CU_ASSERT(test.creates == 1 && test.received == 1 && test.fins == 1);
        CU_ASSERT(test.data[0] == 'x');
        CU_ASSERT(wt_pending_count(test.wt_conn) == 63);
        CU_ASSERT(test.h3c->conn->conn_err == 0);
        wt_h3_test_close(&test);
        CU_ASSERT(test.closes == 1);
        for (size_t i = 0; i < 64; i++) {
            CU_ASSERT(pending[i].detached == 1);
        }
    }
}

void
xqc_test_wt_pending_fragmented_prefix(void)
{
    for (unsigned variant = 0; variant < 8; variant++) {
        xqc_bool_t bidi = variant & 1;
        xqc_bool_t truncated = variant & 4;
        xqc_wt_h3_test_t test;
        CU_ASSERT_FATAL(wt_h3_test_init(&test, bidi) == XQC_OK);
        test.wt_conn->negotiated_version = variant & 2
            ? XQC_WEBTRANSPORT_DRAFT_VERSION_16
            : XQC_WEBTRANSPORT_DRAFT_VERSION_7;
        xqc_wt_pending_test_t pending[64];
        CU_ASSERT_FATAL(wt_pending_fill(test.wt_conn, pending, 64, bidi)
                        == XQC_OK);
        /* RFC 9000 §16: a Session ID may use a nonminimal varint. */
        unsigned char prefix[] = {0x40, bidi ? 0x41 : 0x54, 0x80, 0, 0, 4};
        CU_ASSERT(wt_h3_test_input(&test, prefix, 3, 0) == XQC_OK);
        CU_ASSERT(wt_pending_count(test.wt_conn) == 64);
        CU_ASSERT(pending[0].detached == 1);
        CU_ASSERT(wt_h3_test_input(&test, prefix + 3, 1, 0) == XQC_OK);
        CU_ASSERT(wt_pending_count(test.wt_conn) == 64);
        CU_ASSERT(pending[1].detached == 0);
        CU_ASSERT(wt_h3_test_input(&test, prefix + 4,
                                   truncated ? 1 : 2, 1) == XQC_OK);
        CU_ASSERT(wt_pending_count(test.wt_conn) == 63);
        CU_ASSERT(test.creates == !truncated && test.fins == !truncated);
        CU_ASSERT(pending[1].detached == 0 && test.received == 0);
        CU_ASSERT(test.h3c->conn->conn_err == 0);
        wt_h3_test_close(&test);
        CU_ASSERT(test.closes == !truncated);
    }
}

static xqc_int_t
wt_h3_test_bidi_create(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *ctx)
{
    xqc_wt_h3_test_t *test = ctx;
    test->creates++;
    if (test->close_on_create) {
        /* CONNECT I/O is omitted; closure still frees the bound streams. */
        CU_ASSERT(xqc_wt_session_close_with_error(session, 0, NULL, 0)
                  == -XQC_ESTATE);
    }
    return XQC_OK;
}

static xqc_int_t
wt_h3_test_bidi_write(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *ctx)
{
    xqc_wt_h3_test_t *test = ctx;
    test->writes++;
    if (test->close_on_write) {
        CU_ASSERT(xqc_wt_session_close_with_error(session, 0, NULL, 0)
                  == -XQC_ESTATE);
    }
    return XQC_OK;
}

static xqc_int_t
wt_h3_test_uni_create(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *ctx)
{
    ((xqc_wt_h3_test_t *)ctx)->creates++;
    return XQC_OK;
}

static xqc_int_t
wt_h3_test_read(xqc_wt_h3_test_t *test, const void *data, size_t len,
    xqc_bool_t fin)
{
    test->reads++;
    if (test->blocked) {
        return -XQC_EAGAIN;
    }
    if (len > sizeof(test->data) - test->received) {
        return -XQC_EPARAM;
    }
    if (len) {
        memcpy(test->data + test->received, data, len);
    }
    test->received += len;
    test->fins += fin;
    return XQC_OK;
}

static xqc_int_t
wt_h3_test_bidi_read(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t len, void *ctx)
{
    return wt_h3_test_read(ctx, data, len,
                           xqc_wt_bidistream_get_recv_fin(stream));
}

static xqc_int_t
wt_h3_test_uni_read(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t len, void *ctx)
{
    return wt_h3_test_read(ctx, data, len,
                           xqc_wt_unistream_get_recv_fin(stream));
}

static xqc_int_t
wt_h3_test_bidi_close(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *ctx)
{
    ((xqc_wt_h3_test_t *)ctx)->closes++;
    return XQC_OK;
}

static xqc_int_t
wt_h3_test_uni_close(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *ctx)
{
    ((xqc_wt_h3_test_t *)ctx)->closes++;
    return XQC_OK;
}

static xqc_int_t
wt_h3_test_uni_closing(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *ctx)
{
    xqc_wt_h3_test_t *test = ctx;
    xqc_bool_t stop = xqc_wt_unistream_closing_is_stop_sending(stream);
    test->closing_error_valid = xqc_wt_unistream_get_recv_error_code(
        stream, &test->closing_error);
    if (stop) {
        test->stops++;
    } else {
        test->resets++;
    }
    if (stop && test->destroy_on_stop) {
        xqc_wt_session_destroy(session);
    }
    return XQC_OK;
}

static void
wt_h3_test_drain(xqc_wt_session_t *session, void *ctx)
{
    ((xqc_wt_h3_test_t *)ctx)->drains++;
}

static xqc_int_t
wt_h3_test_init(xqc_wt_h3_test_t *test, xqc_bool_t bidi)
{
    return wt_h3_test_init_echo(test, bidi, XQC_FALSE);
}

static void
wt_h3_test_schedule(void *data)
{
}

static xqc_int_t
wt_h3_test_init_echo(xqc_wt_h3_test_t *test, xqc_bool_t bidi, xqc_bool_t echo)
{
    memset(test, 0, sizeof(*test));
    xqc_connection_t *conn = test_engine_connect();
    if (!conn) {
        return XQC_ERROR;
    }
    test->engine = conn->engine;
    xqc_webtransport_stream_callbacks_t cbs = {
        .wt_bidistream_create_notify = wt_h3_test_bidi_create,
        .wt_bidistream_read_notify = wt_h3_test_bidi_read,
        .wt_bidistream_write_notify = wt_h3_test_bidi_write,
        .wt_bidistream_close_notify = wt_h3_test_bidi_close,
        .wt_unistream_create_notify = wt_h3_test_uni_create,
        .wt_unistream_read_notify = wt_h3_test_uni_read,
        .wt_unistream_closing_notify = wt_h3_test_uni_closing,
        .wt_unistream_close_notify = wt_h3_test_uni_close,
    };
    xqc_webtransport_session_callbacks_t session_cbs = {
        .webtransport_session_drain_notify = wt_h3_test_drain,
    };
    xqc_int_t ret = echo
        ? xqc_wt_echo_server_init(test->engine, wt_h3_test_schedule, NULL)
        : xqc_wt_ctx_init(test->engine, NULL, &session_cbs, &cbs);
    if (ret != XQC_OK) {
        return ret;
    }
    xqc_webtransport_conn_settings_t settings =
        xqc_wt_ctx_get(test->engine)->settings;
    settings.draft_version = XQC_WEBTRANSPORT_DRAFT_VERSION_16;
    settings.max_sessions_count = 16;
    if (xqc_wt_engine_set_default_settings(test->engine, &settings) != XQC_OK) {
        return XQC_ERROR;
    }
    xqc_free(conn->alpn);
    conn->alpn = xqc_malloc(3);
    if (!conn->alpn) {
        return XQC_ERROR;
    }
    memcpy(conn->alpn, "h3", 3);
    conn->alpn_len = 2;
    if (xqc_engine_get_alpn_callbacks(test->engine, "h3", 2,
                                      &conn->app_proto_cbs) != XQC_OK)
    {
        return XQC_ERROR;
    }
    conn->conn_type = XQC_CONN_TYPE_SERVER;
    test->h3c = xqc_h3_conn_create(conn, test);
    if (!test->h3c) {
        return XQC_ERROR;
    }
    conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST
        | XQC_CONN_FLAG_TLS_HSK_COMPLETED;
    conn->local_settings.reset_stream_at = XQC_TRUE;
    conn->remote_settings.reset_stream_at = XQC_TRUE;
    conn->conn_flow_ctl.fc_max_streams_bidi_can_recv = 16;
    conn->conn_flow_ctl.fc_max_streams_uni_can_recv = 16;
    conn->conn_flow_ctl.fc_max_streams_bidi_can_send = 16;
    conn->conn_flow_ctl.fc_max_streams_uni_can_send = 16;
    test->engine->config->manually_triggered_send = 1;
    test->wt_conn = xqc_wt_get_conn_from_h3(test->h3c);
    test->wt_conn->negotiated_version = XQC_WEBTRANSPORT_DRAFT_VERSION_16;
    xqc_wt_session_t *session = xqc_wt_session_init(4,
                                                    test->wt_conn, NULL);
    if (!session) {
        return XQC_ERROR;
    }
    session->open = XQC_TRUE;
    xqc_stream_t *stream = xqc_create_stream_with_conn(
        conn, bidi ? 8 : 10, 0, NULL, NULL);
    if (!stream) {
        return XQC_ERROR;
    }
    test->h3s = xqc_h3_stream_create(test->h3c, stream,
                                     XQC_H3_STREAM_TYPE_UNKNOWN, NULL);
    return test->h3s ? XQC_OK : XQC_ERROR;
}

static xqc_int_t
wt_h3_test_input(xqc_wt_h3_test_t *test, unsigned char *data,
    size_t len, uint8_t fin)
{
    return xqc_wt_h3_stream_read(test->h3s,
                                 test->wt_conn, data, len, fin);
}

static xqc_int_t
wt_h3_test_queue(xqc_wt_h3_test_t *test, const unsigned char *data,
    size_t len, uint8_t fin)
{
    xqc_stream_t *stream = test->h3s->stream;
    xqc_stream_frame_t *frame = xqc_calloc(1, sizeof(*frame));
    if (!frame) {
        return -XQC_EMALLOC;
    }
    frame->data = xqc_malloc(len ? len : 1);
    if (!frame->data) {
        xqc_free(frame);
        return -XQC_EMALLOC;
    }
    if (len) {
        memcpy(frame->data, data, len);
    }
    frame->data_length = len;
    frame->data_offset = stream->stream_data_in.merged_offset_end;
    frame->fin = fin;
    xqc_int_t ret = xqc_insert_stream_frame(stream->stream_conn,
                                            stream, frame);
    if (ret != XQC_OK) {
        xqc_destroy_stream_frame(frame);
        return ret;
    }
    if (fin) {
        stream->stream_data_in.stream_determined = 1;
        stream->stream_data_in.stream_length = frame->data_offset + len;
        stream->stream_state_recv = XQC_RECV_STREAM_ST_DATA_RECVD;
    }
    return stream->stream_if->stream_read_notify(stream, stream->user_data);
}

static void
wt_h3_test_close(xqc_wt_h3_test_t *test)
{
    xqc_wt_h3_stream_close(test->h3s);
    CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_context(test->h3s));
    xqc_wt_h3_stream_close(test->h3s);
    CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_context(test->h3s));
    xqc_engine_destroy(test->engine);
}

static void
wt_h3_test_client(xqc_wt_h3_test_t *test,
    xqc_webtransport_draft_version_t version)
{
    xqc_connection_t *conn = test->h3c->conn;
    conn->conn_type = XQC_CONN_TYPE_CLIENT;
    conn->local_settings.max_datagram_frame_size = 65535;
    conn->remote_settings.max_datagram_frame_size = 65535;
    conn->local_settings.reset_stream_at = XQC_TRUE;
    conn->remote_settings.reset_stream_at = XQC_TRUE;
    test->wt_conn->settings_received = XQC_TRUE;
    test->wt_conn->negotiated_version = version;
    test->wt_conn->peer_datagram = XQC_TRUE;
    test->wt_conn->peer_connect = XQC_TRUE;
}

static xqc_int_t
wt_h3_test_server_stream(xqc_wt_h3_test_t *test)
{
    xqc_stream_t *stream = xqc_create_stream_with_conn(test->h3c->conn,
                                                       1, 0, NULL, NULL);
    if (!stream || (stream->stream_flag & XQC_STREAM_FLAG_DISCARDED)) {
        return XQC_ERROR;
    }
    test->h3s = xqc_h3_stream_create(test->h3c, stream,
                                     XQC_H3_STREAM_TYPE_UNKNOWN, NULL);
    return test->h3s ? XQC_OK : XQC_ERROR;
}

void
xqc_test_wt_h3_server_bidi(void)
{
    /* Draft-07 §4.2 and draft-16 §§4.3, 4.6 allow server bidi streams. */
    for (unsigned draft16 = 0; draft16 < 2; draft16++) {
        xqc_wt_h3_test_t test;
        CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_TRUE) == XQC_OK);
        wt_h3_test_client(&test, draft16 ? XQC_WEBTRANSPORT_DRAFT_VERSION_16
                                       : XQC_WEBTRANSPORT_DRAFT_VERSION_16);
        CU_ASSERT_FATAL(wt_h3_test_server_stream(&test) == XQC_OK);
        xqc_wt_session_t *session = xqc_wt_conn_find_session(test.wt_conn, 4);
        session->open = !draft16;
        unsigned char wire[] = {0x40, 0x41, 4, 'a', 'b', 'c'};
        CU_ASSERT(wt_h3_test_queue(&test, wire, 1, 0) == XQC_OK);
        CU_ASSERT(test.creates == 0 && test.reads == 0);
        CU_ASSERT(wt_h3_test_queue(&test, wire + 1, sizeof(wire) - 1, 1)
                  == XQC_OK);
        if (draft16) {
            CU_ASSERT(test.creates == 0 && test.received == 0);
            session->open = XQC_TRUE;
            xqc_wt_conn_resume_streams(test.wt_conn);
            CU_ASSERT(xqc_wt_h3_stream_prepare_read(test.h3s) == XQC_OK);
        }
        CU_ASSERT(test.creates == 1 && test.fins == 1);
        CU_ASSERT(test.received == 3 && memcmp(test.data, "abc", 3) == 0);
        CU_ASSERT(test.h3c->conn->conn_err == 0);
        wt_h3_test_close(&test);
        CU_ASSERT(test.closes == 1);
    }

    /* RFC 9114 §6.1: ordinary H3 and unnegotiated WT retain rejection. */
    for (unsigned missing = 0; missing < 4; missing++) {
        xqc_wt_h3_test_t test;
        CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_TRUE) == XQC_OK);
        wt_h3_test_client(&test, XQC_WEBTRANSPORT_DRAFT_VERSION_16);
        if (missing == 0) {
            test.h3c->conn->app_proto_cbs.stream_cbs = h3_stream_callbacks;
        } else if (missing == 1) {
            test.wt_conn->settings_received = XQC_FALSE;
        } else if (missing == 2) {
            test.wt_conn->peer_connect = XQC_FALSE;
        } else {
            test.h3c->conn->remote_settings.reset_stream_at = XQC_FALSE;
        }
        xqc_stream_t *stream = xqc_create_stream_with_conn(test.h3c->conn,
                                                           1, 0, NULL, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
        CU_ASSERT(stream->stream_flag & XQC_STREAM_FLAG_DISCARDED);
        CU_ASSERT(test.creates == 0 && test.reads == 0);
        wt_h3_test_close(&test);
    }

    for (unsigned invalid = 0; invalid < 4; invalid++) {
        xqc_wt_h3_test_t test;
        CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_TRUE) == XQC_OK);
        wt_h3_test_client(&test, XQC_WEBTRANSPORT_DRAFT_VERSION_16);
        CU_ASSERT_FATAL(wt_h3_test_server_stream(&test) == XQC_OK);
        unsigned char wire[] = {0x40, 0x41, 1};
        size_t length = invalid == 0 ? 0 : invalid == 3 ? 3 : 1;
        if (invalid == 1) {
            wire[0] = XQC_H3_FRM_HEADERS;
        }
        xqc_int_t ret = wt_h3_test_queue(&test, wire, length, 1);
        CU_ASSERT(ret == (invalid == 3 ? XQC_OK : -XQC_H3_EPROC_REQUEST));
        CU_ASSERT(XQC_CONN_ERR_CODE(test.h3c->conn->conn_err)
                  == (invalid == 3 ? H3_ID_ERROR : H3_FRAME_ERROR));
        CU_ASSERT(test.creates == 0 && test.reads == 0);
        CU_ASSERT_PTR_NULL(test.h3s->h3r);
        wt_h3_test_close(&test);
    }
}

static xqc_wt_unistream_t *
wt_h3_test_outgoing(xqc_wt_h3_test_t *test)
{
    xqc_connection_t *conn = test->h3c->conn;
    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT
        | XQC_CONN_FLAG_TLS_HSK_COMPLETED;
    conn->local_settings.reset_stream_at = XQC_TRUE;
    conn->remote_settings.reset_stream_at = XQC_TRUE;
    test->wt_conn->negotiated_version = XQC_WEBTRANSPORT_DRAFT_VERSION_16;
    xqc_wt_session_t *session = xqc_wt_conn_find_session(test->wt_conn, 4);
    int err = 0;
    return xqc_wt_session_create_uni_stream(session, test, &err);
}

static unsigned
wt_h3_test_reset_count(xqc_stream_t *stream)
{
    unsigned count = 0;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos,
                      &stream->stream_conn->conn_send_queue->sndq_send_packets)
    {
        xqc_packet_out_t *packet = xqc_list_entry(pos, xqc_packet_out_t,
                                                  po_list);
        for (unsigned i = 0; i < packet->po_stream_frames_idx; i++) {
            xqc_po_stream_frame_t *frame = &packet->po_stream_frames[i];
            count += frame->ps_is_used && frame->ps_is_reset_at
                && frame->ps_stream_id == stream->stream_id;
        }
    }
    return count;
}

static void
wt_h3_test_sent_prefix(xqc_stream_t *stream, const unsigned char *expected,
    size_t length)
{
    unsigned seen = 0;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos,
                      &stream->stream_conn->conn_send_queue->sndq_send_packets)
    {
        xqc_packet_out_t *packet = xqc_list_entry(pos, xqc_packet_out_t,
                                                  po_list);
        for (unsigned i = 0; i < packet->po_stream_frames_idx; i++) {
            xqc_po_stream_frame_t *frame = &packet->po_stream_frames[i];
            if (!frame->ps_is_used || frame->ps_is_reset_at
                || frame->ps_is_reset
                || frame->ps_stream_id != stream->stream_id
                || frame->ps_offset >= length || !frame->ps_length)
            {
                continue;
            }
            CU_ASSERT_FATAL(frame->ps_length_offset > 0);
            size_t offset = frame->ps_length_offset;
            CU_ASSERT_FATAL(offset < packet->po_used_size);
            offset += (size_t)1 << (packet->po_buf[offset] >> 6);
            size_t count = xqc_min(frame->ps_length,
                                   length - frame->ps_offset);
            CU_ASSERT_FATAL(offset + count <= packet->po_used_size);
            CU_ASSERT(memcmp(packet->po_buf + offset,
                             expected + frame->ps_offset, count) == 0);
            for (size_t j = 0; j < count; j++) {
                seen |= 1U << (frame->ps_offset + j);
            }
        }
    }
    CU_ASSERT(seen == (1U << length) - 1);
}

void
xqc_test_wt_h3_stream_reliable_reset(void)
{
    /* draft-ietf-webtrans-http3-16 Section 4.4: reliable stream headers. */
    xqc_wt_h3_test_t test;
    CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_FALSE) == XQC_OK);
    xqc_wt_unistream_t *wt = wt_h3_test_outgoing(&test);
    CU_ASSERT_PTR_NOT_NULL_FATAL(wt);
    xqc_h3_stream_t *h3s = wt->base.h3_stream;
    xqc_stream_t *stream = h3s->stream;
    unsigned char prefix[] = {0x40, 0x54, 4};
    CU_ASSERT(stream->reset_at.send_size == sizeof(prefix));
    unsigned char payload = 'x';
    CU_ASSERT(xqc_wt_unistream_send(wt, &payload, 1, 0) == 1);
    CU_ASSERT(wt->base.prefix_sent == sizeof(prefix));
    CU_ASSERT(stream->stream_send_offset == sizeof(prefix) + 1);
    CU_ASSERT(wt_h3_test_reset_count(stream) == 0);

    xqc_wt_session_destroy(wt->base.session);
    CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_get(h3s));
    CU_ASSERT(stream->reset_at.send_state == XQC_RESET_AT_SENT);
    CU_ASSERT(wt_h3_test_reset_count(stream) == 1);
    CU_ASSERT(stream->reset_at.send_error == UINT64_C(0x170d7b68));
    wt_h3_test_sent_prefix(stream, prefix, sizeof(prefix));
    CU_ASSERT(stream->stream_if->stream_write_notify(stream, h3s) == XQC_OK);
    CU_ASSERT(wt_h3_test_reset_count(stream) == 1);
    CU_ASSERT(test.closes == 1);
    wt_h3_test_close(&test);
    CU_ASSERT(test.closes == 1);
}

void
xqc_test_wt_h3_stream_conn_close_cleanup(void)
{
    /* RFC 9000 Section 10.2: closing discards open streams without I/O. */
    for (unsigned version = 0; version < 2; version++) {
        for (unsigned closing = 0; closing < 2; closing++) {
            xqc_wt_h3_test_t test;
            CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_TRUE) == XQC_OK);
            test.wt_conn->negotiated_version = version
                ? XQC_WEBTRANSPORT_DRAFT_VERSION_7
                : XQC_WEBTRANSPORT_DRAFT_VERSION_16;
            unsigned char prefix[] = {0x40, 0x41, 4, 'x'};
            CU_ASSERT(wt_h3_test_input(&test, prefix, sizeof(prefix), 0)
                      == XQC_OK);
            CU_ASSERT(test.creates == 1 && test.closes == 0);
            xqc_stream_t *stream = test.h3s->stream;
            xqc_connection_t *conn = stream->stream_conn;
            conn->conn_state = closing ? XQC_CONN_STATE_CLOSING
                                       : XQC_CONN_STATE_ESTABED;
            xqc_engine_remove_active_queue(test.engine, conn);
            CU_ASSERT(xqc_pq_empty(test.engine->conns_active_pq));

            xqc_wt_session_t *session = xqc_wt_conn_find_session(
                test.wt_conn, 4);
            xqc_wt_session_destroy(session);
            CU_ASSERT(test.closes == 1);
            CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_get(test.h3s));
            CU_ASSERT(xqc_pq_empty(test.engine->conns_active_pq) == closing);
            CU_ASSERT(!!(stream->stream_flag
                & XQC_STREAM_FLAG_STOP_SENDING_SENT) == !closing);
            CU_ASSERT((stream->stream_state_send
                == XQC_SEND_STREAM_ST_RESET_SENT) == !closing);
            wt_h3_test_close(&test);
        }
    }
}

void
xqc_test_wt_h3_stream_reset_after_detach(void)
{
    /* The required header outlives the session that initiated its reset. */
    for (unsigned sent = 0; sent < 2; sent++) {
        xqc_wt_h3_test_t test;
        CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_FALSE) == XQC_OK);
        xqc_wt_unistream_t *wt = wt_h3_test_outgoing(&test);
        CU_ASSERT_PTR_NOT_NULL_FATAL(wt);
        xqc_h3_stream_t *h3s = wt->base.h3_stream;
        xqc_stream_t *stream = h3s->stream;
        unsigned char prefix[] = {0x40, 0x54, 4};
        if (sent) {
            CU_ASSERT(xqc_stream_send(stream, wt->base.prefix, sent, 0)
                == sent);
            wt->base.prefix_sent = sent;
        }
        stream->stream_flow_ctl.fc_max_stream_data_can_send = sent;
        unsigned char payload = 'x';
        CU_ASSERT(xqc_wt_unistream_send(wt, &payload, 1, 0) == -XQC_EAGAIN);
        CU_ASSERT(wt->base.prefix_sent == sent);
        CU_ASSERT(stream->stream_flag & XQC_STREAM_FLAG_DATA_BLOCKED);

        xqc_wt_session_destroy(wt->base.session);
        CU_ASSERT_PTR_NULL(xqc_wt_conn_find_session(test.wt_conn, 4));
        CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_get(h3s));
        CU_ASSERT_PTR_NOT_NULL(xqc_wt_h3_stream_context(h3s));
        CU_ASSERT(stream->reset_at.send_state != XQC_RESET_AT_SENT);
        CU_ASSERT(stream->stream_send_offset == sent);
        CU_ASSERT(test.closes == 1);
        CU_ASSERT(stream->stream_if->stream_write_notify(stream, h3s)
            == XQC_OK);
        CU_ASSERT(wt_h3_test_reset_count(stream) == 0);

        stream->stream_flow_ctl.fc_max_stream_data_can_send = 65536;
        stream->stream_flag &= ~XQC_STREAM_FLAG_DATA_BLOCKED;
        CU_ASSERT(stream->stream_if->stream_write_notify(stream, h3s)
            == XQC_OK);
        CU_ASSERT(stream->reset_at.send_state == XQC_RESET_AT_SENT);
        CU_ASSERT(stream->stream_send_offset == sizeof(prefix));
        CU_ASSERT(stream->reset_at.send_error == UINT64_C(0x170d7b68));
        CU_ASSERT(wt_h3_test_reset_count(stream) == 1);
        wt_h3_test_sent_prefix(stream, prefix, sizeof(prefix));
        CU_ASSERT(stream->stream_if->stream_write_notify(stream, h3s)
            == XQC_OK);
        CU_ASSERT(wt_h3_test_reset_count(stream) == 1);
        wt_h3_test_close(&test);
        CU_ASSERT(test.closes == 1);
    }
}

void
xqc_test_wt_h3_stream_stop_sending(void)
{
    /* RFC 9000 Section 3.5 and webtrans-http3-16 Section 4.4. */
    for (unsigned deferred = 0; deferred < 3; deferred++) {
        xqc_wt_h3_test_t test;
        CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_FALSE) == XQC_OK);
        test.destroy_on_stop = deferred == 1;
        xqc_wt_unistream_t *wt = wt_h3_test_outgoing(&test);
        CU_ASSERT_PTR_NOT_NULL_FATAL(wt);
        xqc_h3_stream_t *h3s = wt->base.h3_stream;
        xqc_stream_t *stream = h3s->stream;
        CU_ASSERT_PTR_NOT_NULL(stream->stream_if->stream_stop_sending_notify);
        if (deferred) {
            stream->stream_flow_ctl.fc_max_stream_data_can_send = 0;
        }
        CU_ASSERT(xqc_wt_unistream_send(wt, NULL, 0, 0)
            == (deferred ? -XQC_EAGAIN : 0));
        unsigned char wire[32] = {0x05};
        uint64_t error = UINT64_C(0x52e4a40fa8db) + 7;
        size_t n = 1;
        n += xqc_wt_put_varint(stream->stream_id, wire + n,
                               sizeof(wire) - n);
        n += xqc_wt_put_varint(error, wire + n, sizeof(wire) - n);
        xqc_packet_in_t packet;
        xqc_memzero(&packet, sizeof(packet));
        packet.pos = wire;
        packet.last = wire + n;
        packet.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
        CU_ASSERT(xqc_process_stop_sending_frame(test.h3c->conn, &packet)
            == XQC_OK);
        if (!deferred) {
            CU_ASSERT(stream->reset_at.send_error == error);
        }
        CU_ASSERT(test.stops == !deferred);
        if (!deferred) {
            CU_ASSERT(test.closing_error_valid && test.closing_error == 7);
        }
        CU_ASSERT((stream->reset_at.send_state == XQC_RESET_AT_READY)
                  == !!deferred);
        /*
         * WT suppresses repeated STOP notifications, including while blocked.
         */
        wire[n - 1]++;
        packet.pos = wire;
        CU_ASSERT(xqc_process_stop_sending_frame(test.h3c->conn, &packet)
            == XQC_OK);
        CU_ASSERT(test.stops == !deferred);
        if (!deferred) {
            CU_ASSERT(stream->reset_at.send_error == error);
        }
        if (deferred) {
            if (deferred == 2) {
                /* A local close must preserve the pending peer reset. */
                xqc_wt_session_destroy(wt->base.session);
                CU_ASSERT(test.closes == 1 && test.stops == 0);
            }
            stream->stream_flow_ctl.fc_max_stream_data_can_send = 65536;
            stream->stream_flag &= ~XQC_STREAM_FLAG_DATA_BLOCKED;
            CU_ASSERT(stream->stream_if->stream_write_notify(stream, h3s)
                == XQC_OK);
            CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_get(h3s));
            CU_ASSERT_PTR_NULL(xqc_wt_conn_find_session(test.wt_conn, 4));
            CU_ASSERT(test.closes == 1);
        } else {
            CU_ASSERT(xqc_wt_unistream_closing_is_stop_sending(wt));
            CU_ASSERT(xqc_wt_unistream_send(wt, NULL, 0, 0) == -XQC_ESTATE);
        }
        CU_ASSERT(test.stops == (deferred == 2 ? 0 : 1));
        CU_ASSERT(stream->reset_at.send_state == XQC_RESET_AT_SENT);
        if (!deferred) {
            CU_ASSERT(stream->reset_at.send_error == error);
        }
        CU_ASSERT(wt_h3_test_reset_count(stream) == 1);
        unsigned char prefix[] = {0x40, 0x54, 4};
        wt_h3_test_sent_prefix(stream, prefix, sizeof(prefix));
        packet.pos = wire;
        CU_ASSERT(xqc_process_stop_sending_frame(test.h3c->conn, &packet)
            == XQC_OK);
        CU_ASSERT(test.stops == (deferred == 2 ? 0 : 1));
        CU_ASSERT(wt_h3_test_reset_count(stream) == 1);
        CU_ASSERT(stream->stream_if->stream_write_notify(stream, h3s)
            == XQC_OK);
        CU_ASSERT(wt_h3_test_reset_count(stream) == 1);
        wt_h3_test_close(&test);
        CU_ASSERT(test.closes == 1);
    }
}

void
xqc_test_wt_h3_stream_recv_reset_error(void)
{
    /* draft-ietf-webtrans-http3-16 §4.4: full wire code reaches the app. */
    for (unsigned variant = 0; variant < 4; variant++) {
        xqc_wt_h3_test_t test;
        CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_FALSE) == XQC_OK);
        unsigned char prefix[] = {0x40, 0x54, 4};
        CU_ASSERT(wt_h3_test_input(&test, prefix, sizeof(prefix), 0)
                  == XQC_OK);
        xqc_wt_stream_base_t *wt = xqc_wt_h3_stream_get(test.h3s);
        CU_ASSERT_PTR_NOT_NULL_FATAL(wt);
        uint32_t code = 0;
        CU_ASSERT(!xqc_wt_unistream_get_recv_error_code((void *)wt, &code));
        xqc_stream_t *raw = test.h3s->stream;
        uint64_t first = UINT64_C(0x52e4a40fa8db);
        uint64_t last = first + UINT32_MAX + UINT32_MAX / 30;
        raw->stream_err = variant == 0 ? first + 31
            : variant == 1 ? first + 30
            : variant == 2 ? last : last + 1;
        raw->stream_if->stream_closing_notify(
            raw, (xqc_int_t)raw->stream_err, test.h3s);
        CU_ASSERT(test.resets == 1 && test.stops == 0);
        CU_ASSERT(test.closing_error_valid == (variant == 0 || variant == 2));
        if (variant == 0 || variant == 2) {
            CU_ASSERT(test.closing_error
                      == (variant == 0 ? 30 : UINT32_MAX));
        }
        wt_h3_test_close(&test);
    }
}

void
xqc_test_wt_h3_reset_flow_accounting(void)
{
    /* Draft-16 Section 5.4 excludes both varints from reset final size. */
    for (size_t width = 2; width <= 8; width *= 2) {
        for (int overflow = 0; overflow < 4; overflow++) {
            xqc_wt_h3_test_t test;
            CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_FALSE) == XQC_OK);
            unsigned char prefix[9] = {0};
            prefix[0] = width == 2 ? 0x40 : width == 4 ? 0x80 : 0xc0;
            prefix[width - 1] = 0x54;
            prefix[width] = 4;
            CU_ASSERT(wt_h3_test_input(&test, prefix, width + 1, 0)
                == XQC_OK);
            xqc_wt_stream_base_t *wt = xqc_wt_h3_stream_get(test.h3s);
            CU_ASSERT_PTR_NOT_NULL_FATAL(wt);
            xqc_wt_session_t *session = wt->session;
            session->flow_control = XQC_TRUE;
            session->recv_data_limit = 3;
            if (overflow >= 2) {
                CU_ASSERT(xqc_wt_unistream_stop_sending((void *)wt, 0)
                          == XQC_OK);
                CU_ASSERT(wt->recv_reset);
            }
            xqc_stream_t *raw = test.h3s->stream;
            raw->stream_data_in.stream_determined = XQC_TRUE;
            raw->stream_data_in.stream_length = width + 1 + 3 + (overflow & 1);
            xqc_wt_stream_notify_closing(wt, XQC_FALSE,
                                         UINT64_C(0x52e4a40fa8db));
            CU_ASSERT(session->closed == (overflow & 1));
            if (overflow & 1) {
                CU_ASSERT(session->close_error == XQC_WT_FLOW_CONTROL_ERROR);
            } else {
                CU_ASSERT(session->recv_data == 3 && wt->recv_accounted == 3);
                xqc_wt_stream_notify_closing(wt, XQC_FALSE,
                                             UINT64_C(0x52e4a40fa8db));
                CU_ASSERT(session->recv_data == 3);
            }
            wt_h3_test_close(&test);
        }
    }
}

void
xqc_test_wt_h3_reset_after_short_read(void)
{
    /* Draft-16 Section 4.4: deliver RESET once its header has been read. */
    for (unsigned reset = 0; reset < 2; reset++) {
        for (unsigned split = 0; split < 2; split++) {
            xqc_wt_h3_test_t test;
            CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_FALSE) == XQC_OK);
            unsigned char prefix[] = {0x40, 0x54, 4};
            xqc_stream_t *raw = test.h3s->stream;
            if (reset) {
                raw->reset_at.recv_state = XQC_RESET_AT_RELIABLE;
                raw->reset_at.recv_size = sizeof(prefix);
                raw->reset_at.recv_error = UINT64_C(0x52e4a40fa8db);
                raw->stream_data_in.stream_determined = XQC_TRUE;
                raw->stream_data_in.stream_length = sizeof(prefix) + 4;
            }
            size_t offset = split ? 2 : 0;
            if (split) {
                CU_ASSERT(wt_h3_test_queue(&test, prefix, offset, 0)
                          == XQC_OK);
                CU_ASSERT(test.resets == 0 && test.creates == 0);
            }
            CU_ASSERT(wt_h3_test_queue(&test, prefix + offset,
                sizeof(prefix) - offset, 0) == XQC_OK);
            CU_ASSERT(test.creates == 1 && test.resets == reset);
            CU_ASSERT(test.received == 0 && test.fins == 0);
            CU_ASSERT(!(raw->stream_flag & XQC_STREAM_FLAG_READY_TO_READ));
            wt_h3_test_close(&test);
        }
    }
}

void
xqc_test_wt_draft07_reset_dispatch(void)
{
    /* Draft-07 Section 4.3: only an unambiguous application reset is bound. */
    for (unsigned mode = 0; mode < 11; mode++) {
        xqc_wt_h3_test_t test;
        CU_ASSERT_FATAL(wt_h3_test_init(&test, mode == 8) == XQC_OK);
        test.close_on_create = mode == 8;
        test.wt_conn->negotiated_version = mode == 7
            ? XQC_WEBTRANSPORT_DRAFT_VERSION_16
            : XQC_WEBTRANSPORT_DRAFT_VERSION_7;
        test.wt_conn->ctx->settings.max_sessions_count = mode == 2 ? 2 : 1;
        xqc_wt_session_t *session = xqc_wt_conn_find_session(test.wt_conn, 4);
        if (mode == 1 || mode == 6) {
            unsigned char prefix[] = {0x40, 0x54, 8};
            CU_ASSERT(wt_h3_test_input(&test, prefix, mode == 1 ? 2 : 3, 0)
                      == XQC_OK);
        }
        if (mode == 3) {
            test.h3s->type = XQC_H3_STREAM_TYPE_REQUEST;
        }
        if (mode == 5 || mode == 10) {
            session->closed = XQC_TRUE;
        }
        if (mode == 10) {
            session = xqc_wt_session_init(8, test.wt_conn, NULL);
            CU_ASSERT_PTR_NOT_NULL_FATAL(session);
            session->open = XQC_TRUE;
        }
        xqc_stream_t *raw = test.h3s->stream;
        if (mode == 9) {
            raw = xqc_create_stream_with_conn(test.h3c->conn,
                                                14, 0, NULL, NULL);
            CU_ASSERT_PTR_NOT_NULL_FATAL(raw);
            CU_ASSERT_PTR_NULL(raw->user_data);
        }
        raw->stream_err = UINT64_C(0x52e4a40fa8db) + (mode == 4 ? 30 : 43);
        xqc_wt_h3_stream_callbacks.stream_closing_notify(raw, -XQC_ESTATE,
                                                         raw->user_data);
        CU_ASSERT(test.creates == (mode < 2 || mode >= 8));
        CU_ASSERT(test.resets == (mode < 2 || mode >= 9));
        if (mode < 2 || mode >= 9) {
            CU_ASSERT(test.closing_error_valid && test.closing_error == 42);
        } else if (mode == 8) {
            CU_ASSERT(test.closes == 1);
            CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_get(test.h3s));
        }
        wt_h3_test_close(&test);
    }
}

void
xqc_test_wt_draft07_stream_rules(void)
{
    for (unsigned invalid = 0; invalid < 2; invalid++) {
        xqc_wt_h3_test_t test;
        CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_FALSE) == XQC_OK);
        test.wt_conn->negotiated_version = XQC_WEBTRANSPORT_DRAFT_VERSION_7;
        /* Draft-07 Section 4 requires client-bidirectional Session IDs. */
        unsigned char prefix[] = {0x40, 0x54, invalid ? 5 : 4};
        CU_ASSERT(wt_h3_test_input(&test, prefix, sizeof(prefix), 0) == XQC_OK);
        CU_ASSERT(test.creates == !invalid);
        CU_ASSERT(XQC_CONN_ERR_CODE(test.h3c->conn->conn_err)
                  == (invalid ? H3_ID_ERROR : 0));
        wt_h3_test_close(&test);
    }
    xqc_wt_h3_test_t test;
    CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_FALSE) == XQC_OK);
    test.wt_conn->negotiated_version = XQC_WEBTRANSPORT_DRAFT_VERSION_7;
    test.h3c->conn->local_settings.reset_stream_at = XQC_FALSE;
    test.h3c->conn->remote_settings.reset_stream_at = XQC_FALSE;
    xqc_wt_session_t *session = xqc_wt_conn_find_session(test.wt_conn, 4);
    int err;
    xqc_wt_unistream_t *stream = xqc_wt_session_create_uni_stream(
        session, &test, &err);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    xqc_stream_t *raw = stream->base.h3_stream->stream;
    CU_ASSERT(stream->base.prefix_sent == 0);
    /* Unlike draft-16, draft-07 STOP does not defer RESET for a prefix. */
    CU_ASSERT(raw->stop_sending_prepare(raw, 42) == XQC_OK);
    CU_ASSERT(stream->base.prefix_sent == 0);
    CU_ASSERT(xqc_wt_unistream_reset(stream, 42) == XQC_OK);
    CU_ASSERT(wt_h3_test_reset_count(raw) == 0);
    wt_h3_test_close(&test);
}

void
xqc_test_wt_h3_reset_credit(void)
{
    /* Draft-16 Sections 5.4, 5.6: RESET must not strand session credit. */
    for (unsigned scenario = 0; scenario < 5; scenario++) {
        xqc_wt_h3_test_t test;
        CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_TRUE) == XQC_OK);
        unsigned char prefix[] = {0x40, 0x41, 4};
        CU_ASSERT_FATAL(wt_h3_test_input(&test, prefix, sizeof(prefix), 0)
                        == XQC_OK);
        xqc_wt_stream_base_t *wt = xqc_wt_h3_stream_get(test.h3s);
        CU_ASSERT_PTR_NOT_NULL_FATAL(wt);
        xqc_wt_session_t *session = wt->session;
        session->flow_control = scenario != 0;
        session->recv_data_limit = 4;
        test.wt_conn->ctx->settings.init_recv_window = 4;
        test.h3c->conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;

        xqc_stream_t *connect = xqc_create_stream_with_conn(test.h3c->conn,
                                                           4, 0, NULL, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(connect);
        xqc_h3_stream_t *h3s = xqc_h3_stream_create(test.h3c, connect,
                                                    XQC_H3_STREAM_TYPE_REQUEST,
                                                    NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(h3s);
        h3s->h3r = xqc_h3_request_create_inner(test.h3c, h3s, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(h3s->h3r);
        session->request = h3s->h3r;
        session->h3_stream = h3s;
        xqc_stream_shutdown_write(connect);
        if (scenario == 3) {
            CU_ASSERT(xqc_wt_bidistream_stop_sending((void *)wt, 0)
                      == XQC_OK);
        }

        xqc_stream_t *raw = test.h3s->stream;
        raw->stream_data_in.stream_determined = XQC_TRUE;
        raw->stream_data_in.stream_length = sizeof(prefix)
            + (scenario == 1 ? 1 : scenario == 4 ? 5 : 4);
        raw->stream_err = UINT64_C(0x52e4a40fa8db);
        raw->stream_if->stream_closing_notify(raw, (xqc_int_t)raw->stream_err,
                                              test.h3s);
        xqc_process_write_streams(test.h3c->conn);
        if (scenario == 4) {
            CU_ASSERT(session->closed);
            CU_ASSERT(session->close_error == XQC_WT_FLOW_CONTROL_ERROR);
            CU_ASSERT(session->recv_data_limit == 4);
        } else {
            uint64_t expected = scenario >= 2 ? 8 : 4;
            CU_ASSERT(!session->closed && !wt->closed && !wt->send_reset);
            CU_ASSERT(session->recv_data_limit == expected);
            CU_ASSERT((session->request->body_sent > 0) == (scenario >= 2));
            size_t sent = session->request->body_sent;
            uint64_t accounted = session->recv_data;
            raw->stream_if->stream_closing_notify(raw,
                (xqc_int_t)raw->stream_err, test.h3s);
            CU_ASSERT(session->recv_data == accounted);
            CU_ASSERT(session->recv_data_limit == expected);
            CU_ASSERT(session->request->body_sent == sent);
        }
        /* This send-only CONNECT fixture has no session-close callback. */
        session->request = NULL;
        session->h3_stream = NULL;
        wt_h3_test_close(&test);
    }
}

void
xqc_test_wt_h3_stream_closed_session(void)
{
    /* draft-ietf-webtrans-http3-16 §6: no pending stream survives CLOSE. */
    xqc_wt_h3_test_t test;
    CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_TRUE) == XQC_OK);
    xqc_wt_session_t *session = xqc_wt_conn_find_session(test.wt_conn, 4);
    session->open = XQC_FALSE;
    unsigned char prefix[] = {0x40, 0x41, 4};
    CU_ASSERT(wt_h3_test_input(&test, prefix, sizeof(prefix), 0) == XQC_OK);
    CU_ASSERT_PTR_NOT_NULL(xqc_wt_h3_stream_get(test.h3s));
    CU_ASSERT(!xqc_list_empty(&test.wt_conn->pending_streams));
    session->closed = XQC_TRUE;
    xqc_wt_session_close_streams(session);
    CU_ASSERT(xqc_list_empty(&test.wt_conn->pending_streams));
    CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_get(test.h3s));
    CU_ASSERT(test.h3s->stream->stream_state_send
              >= XQC_SEND_STREAM_ST_RESET_SENT);
    CU_ASSERT(test.creates == 0);

    xqc_stream_t *raw = xqc_create_stream_with_conn(test.h3c->conn,
                                                    12, 0, NULL, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(raw);
    test.h3s = xqc_h3_stream_create(test.h3c, raw,
                                    XQC_H3_STREAM_TYPE_UNKNOWN, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(test.h3s);
    CU_ASSERT(wt_h3_test_input(&test, prefix, sizeof(prefix), 0) == XQC_OK);
    CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_get(test.h3s));
    CU_ASSERT(xqc_list_empty(&test.wt_conn->pending_streams));
    CU_ASSERT(test.creates == 0);
    wt_h3_test_close(&test);
}

void
xqc_test_wt_h3_stream_frame_position(void)
{
    /* Draft-07 Section 4.2 / draft-16 Section 4.3: 0x41 is not a frame. */
    for (unsigned negotiated = 0; negotiated < 3; negotiated++) {
        xqc_wt_h3_test_t test;
        CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_FALSE) == XQC_OK);
        unsigned char settings[] = {0, 4, 0};
        CU_ASSERT(wt_h3_test_queue(&test, settings, sizeof(settings), 0)
                  == XQC_OK);
        test.h3c->flags &= ~XQC_H3_CONN_FLAG_WEBTRANSPORT;
        if (negotiated) {
            test.h3c->flags |= XQC_H3_CONN_FLAG_WEBTRANSPORT;
        }
        unsigned char misplaced[] = {0x40, 0x41, 0};
        xqc_int_t ret = wt_h3_test_queue(&test, misplaced,
                                         sizeof(misplaced), 0);
        CU_ASSERT((ret == XQC_OK) == !negotiated);
        CU_ASSERT(XQC_CONN_ERR_CODE(test.h3c->conn->conn_err)
                  == (negotiated ? H3_FRAME_ERROR : 0));
        wt_h3_test_close(&test);
    }

    xqc_wt_h3_test_t test;
    CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_TRUE) == XQC_OK);
    test.h3c->flags |= XQC_H3_CONN_FLAG_WEBTRANSPORT;
    unsigned char unknown[] = {0x21, 0};
    CU_ASSERT(wt_h3_test_queue(&test, unknown, sizeof(unknown), 0)
              == XQC_OK);
    CU_ASSERT(test.h3s->type == XQC_H3_STREAM_TYPE_REQUEST);
    unsigned char misplaced[] = {0x40, 0x41, 0};
    CU_ASSERT(wt_h3_test_queue(&test, misplaced, sizeof(misplaced), 0)
              != XQC_OK);
    CU_ASSERT(XQC_CONN_ERR_CODE(test.h3c->conn->conn_err) == H3_FRAME_ERROR);
    wt_h3_test_close(&test);

    /*
     * Section 4.3: reject at the type boundary on every H3 parser path.
     * RFC 9000 Section 16 permits non-minimal varint encodings.
     */
    const xqc_h3_stream_type_t types[] = {
        XQC_H3_STREAM_TYPE_CONTROL, XQC_H3_STREAM_TYPE_PUSH,
        XQC_H3_STREAM_TYPE_REQUEST, XQC_H3_STREAM_TYPE_BYTESTEAM,
        XQC_H3_STREAM_TYPE_UNKNOWN,
    };
    for (size_t path = 0; path < sizeof(types) / sizeof(types[0]); path++) {
        for (size_t width = 2; width <= 8; width *= 2) {
            for (unsigned enabled = 0; enabled < 2; enabled++) {
                CU_ASSERT_FATAL(wt_h3_test_init(&test, path >= 2) == XQC_OK);
                test.h3s->type = types[path];
                test.h3s->flags |= XQC_HTTP3_STREAM_FLAG_TYPE_IDENTIFIED;
                test.h3c->flags |= XQC_H3_CONN_FLAG_SETTINGS_RECVED
                    | XQC_H3_CONN_FLAG_EXT_ENABLED;
                if (enabled) {
                    test.h3c->flags |= XQC_H3_CONN_FLAG_WEBTRANSPORT;
                }
                /* Unknown-frame payload is opaque, even if it contains 0x41. */
                if (path != 4) {
                    unsigned char opaque[] = {0x21, 2, 0x40, 0x41};
                    CU_ASSERT(xqc_h3_stream_process_in(
                        test.h3s, opaque, sizeof(opaque), 0) == XQC_OK);
                }
                unsigned char marker[8] = {0};
                marker[0] = width == 2 ? 0x40 : width == 4 ? 0x80 : 0xc0;
                marker[width - 1] = 0x41;
                for (size_t i = 0; i < width; i++) {
                    xqc_int_t ret = xqc_h3_stream_process_in(
                        test.h3s, marker + i, 1, 0);
                    CU_ASSERT((ret != XQC_OK) == (enabled && i == width - 1));
                }
                if (!enabled) {
                    unsigned char length = 0;
                    CU_ASSERT(xqc_h3_stream_process_in(
                        test.h3s, &length, 1, 0) == XQC_OK);
                }
                CU_ASSERT(XQC_CONN_ERR_CODE(test.h3c->conn->conn_err)
                          == (enabled ? H3_FRAME_ERROR : 0));
                wt_h3_test_close(&test);
            }
        }
    }

    /* Legal stream-start signals and marker-looking WT payload still pass. */
    for (size_t width = 2; width <= 8; width *= 2) {
        CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_TRUE) == XQC_OK);
        test.h3c->flags |= XQC_H3_CONN_FLAG_WEBTRANSPORT;
        unsigned char wire[11] = {0};
        wire[0] = width == 2 ? 0x40 : width == 4 ? 0x80 : 0xc0;
        wire[width - 1] = 0x41;
        wire[width] = 4;
        wire[width + 1] = 0x40;
        wire[width + 2] = 0x41;
        for (size_t i = 0; i < width + 3; i++) {
            CU_ASSERT(wt_h3_test_queue(&test, wire + i, 1, 0) == XQC_OK);
        }
        CU_ASSERT(test.creates == 1 && test.received == 2);
        CU_ASSERT(memcmp(test.data, wire + width + 1, 2) == 0);
        CU_ASSERT(test.h3c->conn->conn_err == 0);
        wt_h3_test_close(&test);
    }
}

void
xqc_test_wt_h3_stream_goaway(void)
{
    /* draft-ietf-webtrans-http3-16 Section 4.7: existing sessions drain. */
    xqc_wt_h3_test_t test;
    CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_FALSE) == XQC_OK);
    xqc_wt_session_t *session = xqc_wt_conn_find_session(test.wt_conn, 4);
    unsigned char settings[] = {0, 4, 0};
    unsigned char goaway[] = {7, 1, 0};
    CU_ASSERT(wt_h3_test_queue(&test, settings, sizeof(settings), 0)
        == XQC_OK);
    CU_ASSERT(test.h3s->type == XQC_H3_STREAM_TYPE_CONTROL);
    CU_ASSERT_PTR_EQUAL(test.h3s->stream->stream_if,
                        &xqc_wt_h3_stream_callbacks);
    CU_ASSERT(test.drains == 0);
    CU_ASSERT(wt_h3_test_queue(&test, goaway, sizeof(goaway), 0) == XQC_OK);
    CU_ASSERT(test.h3c->flags & XQC_H3_CONN_FLAG_GOAWAY_RECVD);
    CU_ASSERT(session->draining && session->open && !session->closed);
    CU_ASSERT(test.drains == 1);
    xqc_wt_conn_notify_goaway(test.wt_conn);
    CU_ASSERT(test.drains == 1);

    int err = 0;
    xqc_wt_unistream_t *outgoing = xqc_wt_session_create_uni_stream(
        session, &test, &err);
    CU_ASSERT_PTR_NOT_NULL_FATAL(outgoing);
    CU_ASSERT(err == XQC_OK);
    xqc_stream_t *incoming = xqc_create_stream_with_conn(test.h3c->conn,
                                                         14, 0, NULL, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(incoming);
    test.h3s = xqc_h3_stream_create(test.h3c, incoming,
                                    XQC_H3_STREAM_TYPE_UNKNOWN, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(test.h3s);
    unsigned char data[] = {0x40, 0x54, 4, 'x'};
    CU_ASSERT(wt_h3_test_queue(&test, data, sizeof(data), 1) == XQC_OK);
    CU_ASSERT(test.received == 1 && test.data[0] == 'x' && test.fins == 1);
    CU_ASSERT(test.creates == 2 && test.drains == 1);
    wt_h3_test_close(&test);
    CU_ASSERT(test.closes == 2);
}

void
xqc_test_wt_h3_stream_demux(void)
{
    /* draft-ietf-webtrans-http3-16 Sections 4.2 and 4.3. */
    for (unsigned bidi = 0; bidi < 2; bidi++) {
        xqc_wt_h3_test_t test;
        CU_ASSERT_FATAL(wt_h3_test_init(&test, bidi) == XQC_OK);
        unsigned char wire[] = {0x40, bidi ? 0x41 : 0x54,
                                0x40, 0x04, 'a', 'b', 'c'};
        for (size_t i = 0; i < sizeof(wire); i++) {
            CU_ASSERT(wt_h3_test_input(&test, wire + i, 1,
                                       i == sizeof(wire) - 1) == XQC_OK);
            CU_ASSERT(test.creates == (i >= 3));
        }
        CU_ASSERT(xqc_wt_h3_stream_is_raw(test.h3s));
        CU_ASSERT(test.received == 3 && test.fins == 1);
        CU_ASSERT(memcmp(test.data, "abc", 3) == 0);
        CU_ASSERT_PTR_NOT_NULL(xqc_wt_h3_stream_get(test.h3s));
        wt_h3_test_close(&test);
        CU_ASSERT(test.closes == 1);

        CU_ASSERT_FATAL(wt_h3_test_init(&test, bidi) == XQC_OK);
        CU_ASSERT(wt_h3_test_queue(&test, wire, 1, 0) == XQC_OK);
        CU_ASSERT(test.creates == 0 && test.reads == 0);
        CU_ASSERT(wt_h3_test_queue(&test, wire + 1, sizeof(wire) - 1, 1)
                  == XQC_OK);
        CU_ASSERT(xqc_wt_h3_stream_is_raw(test.h3s));
        CU_ASSERT(test.creates == 1 && test.fins == 1);
        CU_ASSERT(test.received == 3 && memcmp(test.data, "abc", 3) == 0);
        CU_ASSERT(test.h3s->stream->stream_data_in.next_read_offset
                  == sizeof(wire));
        wt_h3_test_close(&test);
        CU_ASSERT(test.closes == 1);
    }
}

void
xqc_test_wt_h3_stream_passthrough(void)
{
    xqc_wt_h3_test_t test;
    CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_FALSE) == XQC_OK);
    /* RFC 9114 Section 6.2: unknown uni streams remain ignorable. */
    unsigned char wire[] = {0x40, 0x21, 'a', 'b'};
    CU_ASSERT(wt_h3_test_input(&test, wire, 1, 0) == XQC_OK);
    CU_ASSERT_PTR_NOT_NULL(xqc_wt_h3_stream_context(test.h3s));
    CU_ASSERT(wt_h3_test_input(&test, wire + 1, 3, 1) == XQC_OK);
    CU_ASSERT(test.h3s->type == 0x21);
    CU_ASSERT(test.h3s->flags & XQC_HTTP3_STREAM_FLAG_TYPE_IDENTIFIED);
    CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_context(test.h3s));
    CU_ASSERT(test.creates == 0 && test.reads == 0);
    CU_ASSERT(test.h3c->conn->conn_err == 0);
    wt_h3_test_close(&test);
    CU_ASSERT(test.closes == 0);

    CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_FALSE) == XQC_OK);
    CU_ASSERT(wt_h3_test_queue(&test, wire, 1, 0) == XQC_OK);
    CU_ASSERT_PTR_NOT_NULL(xqc_wt_h3_stream_context(test.h3s));
    CU_ASSERT(wt_h3_test_queue(&test, wire + 1, sizeof(wire) - 1, 1)
              == XQC_OK);
    CU_ASSERT(test.h3s->type == 0x21);
    CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_context(test.h3s));
    CU_ASSERT_PTR_EQUAL(test.h3s->stream->stream_if, &h3_stream_callbacks);
    CU_ASSERT(test.h3s->stream->stream_data_in.next_read_offset
              == sizeof(wire));
    CU_ASSERT(test.creates == 0 && test.reads == 0);
    wt_h3_test_close(&test);
    CU_ASSERT(test.closes == 0);

    CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_FALSE) == XQC_OK);
    /* Unknown uni-stream input stays with H3 after classification. */
    unsigned char unknown_type[] = {0x40, 0x40};
    unsigned char unknown_payload[] = {0x04, 'x'};
    CU_ASSERT(wt_h3_test_input(&test, unknown_type, 2, 0) == XQC_OK);
    CU_ASSERT(test.h3s->flags & XQC_HTTP3_STREAM_FLAG_TYPE_IDENTIFIED);
    CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_context(test.h3s));
    CU_ASSERT(wt_h3_test_input(&test, unknown_payload, 2, 1) == XQC_OK);
    CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_context(test.h3s));
    CU_ASSERT(test.creates == 0 && test.reads == 0);
    CU_ASSERT(test.h3c->conn->conn_err == 0);
    wt_h3_test_close(&test);
    CU_ASSERT(test.closes == 0);

    CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_TRUE) == XQC_OK);
    test.h3c->flags |= XQC_H3_CONN_FLAG_EXT_ENABLED;
    unsigned char native_type = XQC_H3_EXT_FRM_BIDI_STREAM_TYPE;
    CU_ASSERT(wt_h3_test_input(&test, &native_type, 1, 0) == XQC_OK);
    CU_ASSERT(test.h3s->type == XQC_H3_STREAM_TYPE_UNKNOWN);
    CU_ASSERT(test.h3s->pctx.frame_pctx.state == XQC_H3_FRM_STATE_LEN);
    CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_context(test.h3s));
    /* These bytes encode the ordinary frame length, not a WT prefix. */
    unsigned char native_length[] = {0x40, 0x41};
    CU_ASSERT(wt_h3_test_input(&test, native_length, 2, 0) == XQC_OK);
    CU_ASSERT(test.h3s->type == XQC_H3_STREAM_TYPE_UNKNOWN);
    CU_ASSERT(test.h3s->pctx.frame_pctx.state == XQC_H3_FRM_STATE_PAYLOAD);
    CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_context(test.h3s));
    CU_ASSERT(test.creates == 0 && test.reads == 0);
    CU_ASSERT(test.h3c->conn->conn_err == 0);
    wt_h3_test_close(&test);

    CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_TRUE) == XQC_OK);
    /* RFC 9114 Section 4.1: DATA before HEADERS keeps the H3 error. */
    unsigned char invalid_http[] = {0, 0};
    CU_ASSERT(wt_h3_test_input(&test, invalid_http, 2, 0)
              == -XQC_H3_EPROC_REQUEST);
    CU_ASSERT(XQC_CONN_ERR_CODE(test.h3c->conn->conn_err)
              == H3_FRAME_UNEXPECTED);
    CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_context(test.h3s));
    CU_ASSERT(test.creates == 0 && test.reads == 0);
    wt_h3_test_close(&test);

    CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_TRUE) == XQC_OK);
    /* RFC 9114 Section 5.2: H3 rejects the request after classification. */
    test.h3c->flags |= XQC_H3_CONN_FLAG_GOAWAY_RECVD;
    test.h3c->goaway_stream_id = test.h3s->stream_id;
    CU_ASSERT(wt_h3_test_queue(&test, invalid_http, sizeof(invalid_http), 0)
              == XQC_OK);
    CU_ASSERT(test.h3c->conn->conn_err == 0);
    CU_ASSERT(test.h3s->stream->stream_data_in.next_read_offset == 1);
    CU_ASSERT_PTR_EQUAL(test.h3s->stream->stream_if, &h3_stream_callbacks);
    CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_context(test.h3s));
    CU_ASSERT(test.creates == 0 && test.reads == 0);
    wt_h3_test_close(&test);
}

void
xqc_test_wt_h3_stream_prefix_errors(void)
{
    for (unsigned bidi = 0; bidi < 2; bidi++) {
        xqc_wt_h3_test_t test;
        unsigned char prefix = 0x40;
        CU_ASSERT_FATAL(wt_h3_test_init(&test, bidi) == XQC_OK);
        CU_ASSERT(wt_h3_test_input(&test, &prefix, 1, 0) == XQC_OK);
        CU_ASSERT_PTR_NOT_NULL(xqc_wt_h3_stream_context(test.h3s));
        CU_ASSERT(wt_h3_test_input(&test, NULL, 0, 1)
                  == (bidi ? -XQC_H3_EPROC_REQUEST : XQC_OK));
        CU_ASSERT(XQC_CONN_ERR_CODE(test.h3c->conn->conn_err)
                  == (bidi ? H3_FRAME_ERROR : 0));
        if (!bidi) {
            CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_context(test.h3s));
        }
        wt_h3_test_close(&test);
        CU_ASSERT(test.creates == 0 && test.closes == 0);
    }
}

void
xqc_test_wt_h3_stream_backpressure(void)
{
    for (unsigned variant = 0; variant < 4; variant++) {
        xqc_bool_t bidi = variant & 1;
        size_t len = variant < 2 ? 0 : 3;
        xqc_wt_h3_test_t test;
        CU_ASSERT_FATAL(wt_h3_test_init(&test, bidi) == XQC_OK);
        unsigned char prefix[] = {0x40, bidi ? 0x41 : 0x54, 4};
        CU_ASSERT(wt_h3_test_input(&test, prefix, sizeof(prefix), 0)
                  == XQC_OK);
        xqc_wt_stream_base_t *stream = xqc_wt_h3_stream_get(test.h3s);
        CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
        test.blocked = XQC_TRUE;
        CU_ASSERT(wt_h3_test_input(&test, (void *)"abc", len, 1) == XQC_OK);
        CU_ASSERT(test.received == 0 && !stream->recv_fin);
        CU_ASSERT(xqc_wt_h3_stream_prepare_read(test.h3s) == -XQC_EAGAIN);
        test.blocked = XQC_FALSE;
        CU_ASSERT((bidi ? xqc_wt_bidistream_set_read_paused((void *)stream, 0)
            : xqc_wt_unistream_set_read_paused((void *)stream, 0)) == XQC_OK);
        CU_ASSERT(xqc_wt_h3_stream_prepare_read(test.h3s) == XQC_OK);
        CU_ASSERT(test.received == len && test.fins == 1 && stream->recv_fin);
        CU_ASSERT(memcmp(test.data, "abc", len) == 0);
        unsigned reads = test.reads;
        CU_ASSERT(xqc_wt_h3_stream_prepare_read(test.h3s) == XQC_OK);
        CU_ASSERT(test.reads == reads);
        wt_h3_test_close(&test);
        CU_ASSERT(test.closes == 1);
    }

    xqc_wt_h3_test_t test;
    CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_TRUE) == XQC_OK);
    unsigned char pending[] = {0x40, 0x41, 8};
    CU_ASSERT(wt_h3_test_input(&test, pending, sizeof(pending), 1) == XQC_OK);
    CU_ASSERT(test.creates == 0 && test.reads == 0);
    xqc_wt_stream_base_t *stream = xqc_wt_h3_stream_get(test.h3s);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    CU_ASSERT(!stream->recv_fin);
    xqc_wt_session_t *session = xqc_wt_session_init(8, test.wt_conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    session->open = XQC_TRUE;
    xqc_wt_conn_resume_streams(test.wt_conn);
    CU_ASSERT(test.creates == 1);
    CU_ASSERT_PTR_EQUAL(stream->session, session);
    CU_ASSERT(xqc_wt_h3_stream_prepare_read(test.h3s) == XQC_OK);
    CU_ASSERT(test.received == 0 && test.fins == 1 && stream->recv_fin);
    CU_ASSERT(xqc_wt_h3_stream_prepare_read(test.h3s) == XQC_OK);
    CU_ASSERT(test.reads == 1);
    xqc_wt_stream_notify_close(stream);
    CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_get(test.h3s));
    CU_ASSERT(wt_h3_test_input(&test, (void *)"\x00\x01x", 3, 0)
              == XQC_OK);
    CU_ASSERT(xqc_wt_h3_stream_is_raw(test.h3s));
    CU_ASSERT(test.reads == 1 && test.h3c->conn->conn_err == 0);
    wt_h3_test_close(&test);
    CU_ASSERT(test.closes == 1);
}

void
xqc_test_wt_h3_stream_buffer_limit(void)
{
    xqc_wt_h3_test_t test;
    CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_TRUE) == XQC_OK);
    test.h3c->max_blocked_buf_per_stream = 4;
    unsigned char prefix[] = {0x40, 0x41, 4};
    CU_ASSERT(wt_h3_test_input(&test, prefix, sizeof(prefix), 0) == XQC_OK);
    test.blocked = XQC_TRUE;
    CU_ASSERT(wt_h3_test_input(&test, (void *)"abcd", 4, 0) == XQC_OK);
    CU_ASSERT(wt_h3_test_input(&test, (void *)"e", 1, 0)
              == -XQC_H3_EPROC_REQUEST);
    CU_ASSERT(XQC_CONN_ERR_CODE(test.h3c->conn->conn_err) == H3_FRAME_ERROR);
    CU_ASSERT(test.received == 0 && test.creates == 1);
    wt_h3_test_close(&test);
    CU_ASSERT(test.closes == 1);

    for (unsigned bidi = 0; bidi < 2; bidi++) {
        CU_ASSERT_FATAL(wt_h3_test_init(&test, bidi) == XQC_OK);
        unsigned char wire[] = {0x40, bidi ? 0x41 : 0x54, 4};
        CU_ASSERT(wt_h3_test_input(&test, wire, sizeof(wire), 0) == XQC_OK);
        CU_ASSERT(wt_h3_test_input(&test, (void *)"abcdefghijklmnopq", 17, 0)
                  == (bidi ? -XQC_H3_EPROC_REQUEST : -XQC_H3_EPROC_CONTROL));
        CU_ASSERT(XQC_CONN_ERR_CODE(test.h3c->conn->conn_err)
                  == H3_FRAME_ERROR);
        CU_ASSERT(test.received == 0 && test.reads == 1);
        wt_h3_test_close(&test);
        CU_ASSERT(test.closes == 1);
    }
}

void
xqc_test_wt_callback_close_iteration(void)
{
    for (unsigned mode = 0; mode < 4; mode++) {
        xqc_wt_h3_test_t test;
        CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_TRUE) == XQC_OK);
        xqc_wt_session_t *session = xqc_wt_conn_find_session(test.wt_conn, 4);
        xqc_h3_stream_t *first = test.h3s;
        session->open = XQC_FALSE;
        unsigned char prefix[] = {0x40, 0x41, 4};
        CU_ASSERT(wt_h3_test_input(&test, prefix, sizeof(prefix), 0) == XQC_OK);
        xqc_stream_t *raw = xqc_create_stream_with_conn(test.h3c->conn,
                                                        12, 0, NULL, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(raw);
        test.h3s = xqc_h3_stream_create(test.h3c, raw,
                                        XQC_H3_STREAM_TYPE_UNKNOWN, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(test.h3s);
        CU_ASSERT(wt_h3_test_input(&test, prefix, sizeof(prefix), 0) == XQC_OK);
        CU_ASSERT(test.creates == 0);
        test.close_on_create = mode == 1;
        session->open = XQC_TRUE;
        xqc_wt_conn_resume_streams(test.wt_conn);
        CU_ASSERT(test.creates == (mode == 1 ? 1 : 2));
        CU_ASSERT(xqc_list_empty(&test.wt_conn->pending_streams));
        if (mode >= 2) {
            /* draft-16 §5.6.4: restoring credit can close the whole session. */
            session->flow_control = XQC_TRUE;
            test.close_on_write = mode == 3;
            unsigned char capsule[16];
            size_t n = xqc_wt_put_varint(0x190b4d3d, capsule, sizeof(capsule));
            capsule[n++] = 1;
            capsule[n++] = 33;
            CU_ASSERT(xqc_wt_session_recv_capsules(session, capsule, n, 0)
                      == XQC_OK);
            CU_ASSERT(test.writes == (mode == 3 ? 1 : 2));
        }
        if (mode == 1 || mode == 3) {
            CU_ASSERT(session->closed);
            CU_ASSERT(xqc_list_empty(&session->stream_list));
            CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_get(first));
            CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_get(test.h3s));
        }
        wt_h3_test_close(&test);
    }
}

static unsigned wt_mss_notifications;
static size_t wt_mss_value;
static size_t wt_echo_sent;
static size_t wt_echo_send_limit;

static void wt_h3_test_mss(xqc_wt_session_t *session, size_t mss, void *data);
static ssize_t wt_h3_test_echo_send(xqc_h3_stream_t *stream,
    const unsigned char *data, size_t len, uint8_t fin);

static void
wt_h3_test_mss(xqc_wt_session_t *session, size_t mss, void *data)
{
    wt_mss_notifications++;
    wt_mss_value = mss;
}

void
xqc_test_wt_transport_mss_notify(void)
{
    xqc_wt_h3_test_t test;
    CU_ASSERT_FATAL(wt_h3_test_init(&test, XQC_TRUE) == XQC_OK);
    xqc_connection_t *conn = test.h3c->conn;
    CU_ASSERT_PTR_NOT_NULL(xqc_datagram_get_user_data(conn));
    test.wt_conn->ctx->dgram_cbs.dgram_mss_updated_notify = wt_h3_test_mss;
    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    conn->remote_settings.max_datagram_frame_size = 1200;
    conn->remote_settings.max_udp_payload_size = 1500;
    conn->dgram_mss = 0;
    wt_mss_notifications = 0;
    xqc_datagram_record_mss(conn);
    CU_ASSERT(wt_mss_notifications == 1);
    CU_ASSERT(wt_mss_value == conn->dgram_mss - 1);
    xqc_datagram_record_mss(conn);
    CU_ASSERT(wt_mss_notifications == 1);
    xqc_wt_conn_find_session(test.wt_conn, 4)->closed = XQC_TRUE;
    conn->dgram_mss = 0;
    xqc_datagram_record_mss(conn);
    CU_ASSERT(wt_mss_notifications == 1);
    wt_h3_test_close(&test);
}

static ssize_t
wt_h3_test_echo_send(xqc_h3_stream_t *stream, const unsigned char *data,
    size_t len, uint8_t fin)
{
    size_t sent = xqc_min(len, wt_echo_send_limit);
    for (size_t i = 0; i < sent; i++) {
        CU_ASSERT(data[i] == (wt_echo_sent + i) % 251);
    }
    wt_echo_sent += sent;
    return sent == 0 && len ? -XQC_EAGAIN : (ssize_t)sent;
}

void
xqc_test_wt_demo_echo_backpressure(void)
{
    for (int blocked = 0; blocked < 2; blocked++) {
        xqc_wt_h3_test_t test;
        CU_ASSERT_FATAL(wt_h3_test_init_echo(&test, XQC_TRUE, XQC_TRUE)
                        == XQC_OK);
        unsigned char prefix[] = {0x40, 0x41, 4};
        CU_ASSERT(wt_h3_test_input(&test, prefix, sizeof(prefix), 0)
                  == XQC_OK);
        xqc_wt_stream_base_t *wt = xqc_wt_h3_stream_get(test.h3s);
        CU_ASSERT_PTR_NOT_NULL_FATAL(wt);
        xqc_wt_stream_io_ops_t io = *wt->io;
        io.send = wt_h3_test_echo_send;
        wt->io = &io;
        wt_echo_sent = 0;
        wt_echo_send_limit = blocked ? 0 : 4096;
        unsigned char data[4096];
        for (size_t chunk = 0; chunk < 17; chunk++) {
            for (size_t i = 0; i < sizeof(data); i++) {
                data[i] = (chunk * sizeof(data) + i) % 251;
            }
            ssize_t ret = xqc_wt_stream_notify_read(wt, data, sizeof(data),
                                                     chunk == 16);
            if (blocked && chunk == 16) {
                CU_ASSERT(ret == -XQC_EAGAIN);
                CU_ASSERT(wt->read_paused && !wt->recv_fin);
                CU_ASSERT(!wt->recv_reset && !wt->send_reset);
                wt_echo_send_limit = sizeof(data);
                for (unsigned write = 0; write < 16; write++) {
                    CU_ASSERT(xqc_wt_stream_write(test.h3s, wt) == XQC_OK);
                }
                CU_ASSERT(!wt->read_paused);
                ret = xqc_wt_stream_notify_read(wt, data, sizeof(data), 1);
            }
            CU_ASSERT(ret == sizeof(data));
        }
        CU_ASSERT(wt_echo_sent == 17 * sizeof(data));
        CU_ASSERT(wt->recv_fin && wt->send_fin && !wt->closed);
        wt_h3_test_close(&test);
    }
}

void
xqc_test_wt_demo_datagram_retry(void)
{
    xqc_wt_h3_test_t test;
    CU_ASSERT_FATAL(wt_h3_test_init_echo(&test, XQC_TRUE, XQC_TRUE)
                    == XQC_OK);
    xqc_wt_session_t *session = xqc_wt_conn_find_session(test.wt_conn, 4);
    xqc_connection_t *conn = test.h3c->conn;
    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    conn->remote_settings.max_datagram_frame_size = 1200;
    conn->dgram_mss = 1200;
    test.engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
    xqc_webtransport_dgram_callbacks_t *cbs = &test.wt_conn->ctx->dgram_cbs;
    uint64_t limit = conn->conn_send_queue->sndq_packets_used_max;
    conn->conn_send_queue->sndq_packets_used_max = 0;
    for (unsigned i = 0; i < 65; i++) {
        cbs->dgram_read_notify(session, "echo", 4, NULL, 0);
    }
    CU_ASSERT(test.wt_conn->sent_count == 0);
    cbs->dgram_write_notify(session, NULL);
    CU_ASSERT(test.wt_conn->sent_count == 0);
    conn->conn_send_queue->sndq_packets_used_max = limit;
    cbs->dgram_write_notify(session, NULL);
    CU_ASSERT(test.wt_conn->sent_count == 64);
    cbs->dgram_write_notify(session, NULL);
    CU_ASSERT(test.wt_conn->sent_count == 64);
    cbs->dgram_read_notify(session, "echo", 4, NULL, 0);
    CU_ASSERT(test.wt_conn->sent_count == 65);
    conn->conn_send_queue->sndq_packets_used_max = 0;
    cbs->dgram_read_notify(session, "echo", 4, NULL, 0);
    conn->conn_send_queue->sndq_packets_used_max = limit;
    xqc_wt_session_notify_closed(session);
    cbs->dgram_write_notify(session, NULL);
    CU_ASSERT(test.wt_conn->sent_count == 65);
    test.engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
    wt_h3_test_close(&test);
}
