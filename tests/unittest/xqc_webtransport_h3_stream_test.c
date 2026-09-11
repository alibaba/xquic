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
#include "src/webtransport/xqc_webtransport_wire.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_send_queue.h"

typedef struct {
    xqc_engine_t       *engine;
    xqc_h3_conn_t      *h3c;
    xqc_h3_stream_t    *h3s;
    xqc_wt_conn_t      *wt_conn;
    unsigned           creates;
    unsigned           closes;
    unsigned           reads;
    unsigned           fins;
    unsigned           drains;
    unsigned           stops;
    xqc_bool_t         blocked;
    xqc_bool_t         destroy_on_stop;
    size_t             received;
    unsigned char      data[16];
} xqc_wt_h3_test_t;

static xqc_int_t wt_h3_test_bidi_create(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *ctx);
static xqc_int_t wt_h3_test_uni_create(xqc_wt_unistream_t *stream,
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

static xqc_int_t
wt_h3_test_bidi_create(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *ctx)
{
    ((xqc_wt_h3_test_t *)ctx)->creates++;
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
    CU_ASSERT(xqc_wt_unistream_closing_is_stop_sending(stream));
    test->stops++;
    if (test->destroy_on_stop) {
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
    memset(test, 0, sizeof(*test));
    xqc_connection_t *conn = test_engine_connect();
    if (!conn) {
        return XQC_ERROR;
    }
    test->engine = conn->engine;
    xqc_webtransport_stream_callbacks_t cbs = {
        .wt_bidistream_create_notify = wt_h3_test_bidi_create,
        .wt_bidistream_read_notify = wt_h3_test_bidi_read,
        .wt_bidistream_close_notify = wt_h3_test_bidi_close,
        .wt_unistream_create_notify = wt_h3_test_uni_create,
        .wt_unistream_read_notify = wt_h3_test_uni_read,
        .wt_unistream_closing_notify = wt_h3_test_uni_closing,
        .wt_unistream_close_notify = wt_h3_test_uni_close,
    };
    xqc_webtransport_session_callbacks_t session_cbs = {
        .webtransport_session_drain_notify = wt_h3_test_drain,
    };
    if (xqc_wt_ctx_init(test->engine, NULL, &session_cbs, &cbs) != XQC_OK) {
        return XQC_ERROR;
    }
    xqc_webtransport_conn_settings_t settings =
        xqc_wt_ctx_get(test->engine)->settings;
    settings.draft_version = XQC_WEBTRANSPORT_DRAFT_VERSION_7;
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
    conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST;
    conn->conn_flow_ctl.fc_max_streams_bidi_can_recv = 16;
    conn->conn_flow_ctl.fc_max_streams_uni_can_recv = 16;
    conn->conn_flow_ctl.fc_max_streams_bidi_can_send = 16;
    conn->conn_flow_ctl.fc_max_streams_uni_can_send = 16;
    test->engine->config->manually_triggered_send = 1;
    test->wt_conn = xqc_wt_create_conn(test->h3c);
    test->wt_conn->negotiated_version = XQC_WEBTRANSPORT_DRAFT_VERSION_7;
    xqc_wt_session_t *session = xqc_wt_session_init(4,
        test->wt_conn, NULL);
    if (!session) {
        return XQC_ERROR;
    }
    session->open = XQC_TRUE;
    xqc_stream_t *stream = xqc_create_stream_with_conn(conn,
        bidi ? 8 : 10, 0, NULL, NULL);
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
    CU_ASSERT(stream->reset_at.sent);
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
        CU_ASSERT(!stream->reset_at.sent);
        CU_ASSERT(stream->stream_send_offset == sent);
        CU_ASSERT(test.closes == 1);
        CU_ASSERT(stream->stream_if->stream_write_notify(stream, h3s)
            == XQC_OK);
        CU_ASSERT(wt_h3_test_reset_count(stream) == 0);

        stream->stream_flow_ctl.fc_max_stream_data_can_send = 65536;
        stream->stream_flag &= ~XQC_STREAM_FLAG_DATA_BLOCKED;
        CU_ASSERT(stream->stream_if->stream_write_notify(stream, h3s)
            == XQC_OK);
        CU_ASSERT(stream->reset_at.sent);
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
        n += xqc_wt_encode_session_id(stream->stream_id, wire + n,
                                      sizeof(wire) - n);
        n += xqc_wt_encode_session_id(error, wire + n, sizeof(wire) - n);
        xqc_packet_in_t packet = {0};
        packet.pos = wire;
        packet.last = wire + n;
        packet.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
        CU_ASSERT(xqc_process_stop_sending_frame(test.h3c->conn, &packet)
            == XQC_OK);
        CU_ASSERT(stream->reset_at.send_error == error);
        CU_ASSERT(test.stops == !deferred);
        CU_ASSERT(stream->reset_at.pending == !!deferred);
        /* WT suppresses repeated STOP notifications, including while blocked. */
        wire[n - 1]++;
        packet.pos = wire;
        CU_ASSERT(xqc_process_stop_sending_frame(test.h3c->conn, &packet)
            == XQC_OK);
        CU_ASSERT(test.stops == !deferred);
        CU_ASSERT(stream->reset_at.send_error == error);
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
        CU_ASSERT(stream->reset_at.sent);
        CU_ASSERT(stream->reset_at.send_error == error);
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
    xqc_wt_unistream_t *outgoing = xqc_wt_session_create_uni_stream(session,
        &test, &err);
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
    /* draft-ietf-webtrans-http3-07 Sections 4.1 and 4.2. */
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
