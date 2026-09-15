/* Copyright (c) 2026, Alibaba Group Holding Limited. */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "xqc_webtrans_test_cases.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_h3_stream.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/webtransport/xqc_webtransport_wire.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_request.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_stream.h"

/* Private access is confined to demo-only malformed input and observation. */
static const unsigned char wt_case_uni_payload[] = "WT uni payload";
static const unsigned char wt_case_unknown[] = {
    0x44, 0x00, 'w', 't', '-', 'u', 'n', 'a', 's', 's', 'o', 'c', 'i',
    'a', 't', 'e', 'd'
};
static xqc_webtransport_stream_callbacks_t wt_case_stream_cbs;
static xqc_webtransport_session_callbacks_t wt_case_session_cbs;
static xqc_webtransport_dgram_callbacks_t wt_case_dgram_cbs;
static xqc_h3_conn_callbacks_t wt_case_conn_cbs;
static xqc_datagram_read_notify_pt wt_case_raw_read;
static int wt_case_server_id;
static size_t wt_case_uni_received;
static int wt_case_uni_match;
static int wt_case_message_sent;
static unsigned wt_case_datagram_deliveries;

static xqc_int_t wt_case_send_stream(xqc_wt_session_t *session,
    xqc_bool_t bidi, xqc_bool_t invalid);
static xqc_int_t wt_case_send_capsule(xqc_wt_session_t *session,
    uint64_t type, const unsigned char *body, size_t len);
static int wt_case_session_ready(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data);
static int wt_case_session_closed(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data);
static xqc_int_t wt_case_uni_read(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t len, void *user_data);
static xqc_int_t wt_case_message_length_read(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t len, void *user_data);
static xqc_int_t wt_case_bidi_closing(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data);
static void wt_case_datagram_read(xqc_wt_session_t *session,
    const void *data, size_t len, void *user_data, uint64_t recv_time);
static void wt_case_raw_datagram(xqc_connection_t *conn, void *user_data,
    const void *data, size_t len, uint64_t recv_time);
static int wt_case_conn_closed(xqc_h3_conn_t *h3c, const xqc_cid_t *cid,
    void *user_data);

static xqc_int_t
wt_case_send_stream(xqc_wt_session_t *session, xqc_bool_t bidi,
    xqc_bool_t invalid)
{
    if (invalid) {
        /* draft-16 §4: send an invalid Session ID on an unbound raw stream. */
        unsigned char data[3 + sizeof(wt_case_uni_payload)] = {0x40, 0, 1};
        xqc_h3_stream_t *raw = xqc_wt_h3_stream_create(
            session->wt_conn->h3_conn, bidi);
        if (raw == NULL) {
            return XQC_ERROR;
        }
        data[1] = bidi ? 0x41 : 0x54;
        memcpy(data + 3, wt_case_uni_payload, sizeof(wt_case_uni_payload));
        if (xqc_stream_send(raw->stream, data, sizeof(data), 1)
            != sizeof(data))
        {
            return XQC_ERROR;
        }
        printf("WT case stream sent: bidi=%d session_id=1 bytes=%zu\n",
               bidi, sizeof(wt_case_uni_payload));
        return 1;
    }
    int err;
    xqc_wt_stream_base_t *stream = bidi
        ? (void *) xqc_wt_session_create_bidi_stream(session, NULL, &err)
        : (void *) xqc_wt_session_create_uni_stream(session, NULL, &err);
    if (stream == NULL) {
        return err;
    }
    xqc_int_t sent = bidi
        ? xqc_wt_bidistream_send((void *) stream,
            (void *) wt_case_uni_payload, sizeof(wt_case_uni_payload), 1)
        : xqc_wt_unistream_send((void *) stream,
            (void *) wt_case_uni_payload, sizeof(wt_case_uni_payload), 1);
    if (sent != sizeof(wt_case_uni_payload)) {
        return XQC_ERROR;
    }
    printf("WT case stream sent: bidi=%d session_id=%d bytes=%zu\n",
           bidi, 0, sizeof(wt_case_uni_payload));
    return XQC_OK;
}

static xqc_int_t
wt_case_send_capsule(xqc_wt_session_t *session, uint64_t type,
    const unsigned char *body, size_t len)
{
    unsigned char capsule[32];
    size_t offset = xqc_wt_encode_session_id(type, capsule, sizeof(capsule));
    offset += xqc_wt_encode_session_id(len, capsule + offset,
                                       sizeof(capsule) - offset);
    memcpy(capsule + offset, body, len);
    ssize_t sent = xqc_h3_request_send_body(session->request, capsule,
                                            offset + len, 0);
    if (sent != (ssize_t) (offset + len)) {
        return XQC_ERROR;
    }
    printf("WT case capsule sent: type=%" PRIu64 " length=%zu\n", type, len);
    return 1;
}

xqc_int_t
xqc_wt_case_prepare(xqc_wt_session_t *session, int case_id)
{
    uint64_t id;
    switch (case_id) {
    case 1806:
        return wt_case_send_stream(session, XQC_TRUE, XQC_TRUE);
    case 1807:
        return wt_case_send_stream(session, XQC_FALSE, XQC_FALSE);
    case 1808:
        return wt_case_send_stream(session, XQC_FALSE, XQC_TRUE);
    case 1810:
        /* RFC 9297 §2.1; draft-16 §§4.5–4.6. Quarter ID 1024 is unbound. */
        if (xqc_datagram_send(session->wt_conn->h3_conn->conn,
                (void *) wt_case_unknown, sizeof(wt_case_unknown), &id,
                XQC_DATA_QOS_HIGHEST) != XQC_OK)
        {
            return XQC_ERROR;
        }
        printf("WT case datagram sent: quarter=1024 bytes=%zu\n",
               sizeof(wt_case_unknown));
        return XQC_OK;
    case 1812: {
        /* draft-16 §6: the CLOSE reason must be valid UTF-8. */
        const unsigned char body[] = {0, 0, 0, 0, 0xff};
        return wt_case_send_capsule(session, 0x2843, body, sizeof(body));
    }
    case 1813:
        /* draft-16 §4.7: DRAIN has no body and does not close the session. */
        return xqc_wt_session_drain(session);
    case 1814: {
        const unsigned char body[] = {0};
        return wt_case_send_capsule(session, 0x78ae, body, sizeof(body));
    }
    case 1816: {
        /*
         * draft-16 §5.1: exercise the peer's no-pooling rejection. Bypass
         * only the sender's local admission limit; wire SETTINGS stay intact.
         */
        xqc_wt_conn_t *conn = session->wt_conn;
        uint64_t limit = conn->ctx->settings.max_sessions_count;
        int err;
        conn->ctx->settings.max_sessions_count = 2;
        xqc_wt_session_t *second = xqc_wt_client_open_session(conn->h3_conn,
            "test.xquic.com", "/wt", "http://127.0.0.1:8080", &err);
        conn->ctx->settings.max_sessions_count = limit;
        if (second == NULL) {
            return XQC_ERROR;
        }
        printf("WT case second CONNECT sent: session=%" PRIu64 "\n",
               second->sessionID);
        return 1;
    }
    default:
        return XQC_OK;
    }
}

static int
wt_case_session_ready(xqc_wt_session_t *session, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *user_data)
{
    if (wt_case_server_id == 1810) {
        xqc_connection_t *conn = session->wt_conn->h3_conn->conn;
        wt_case_raw_read = conn->app_proto_cbs.dgram_cbs.datagram_read_notify;
        conn->app_proto_cbs.dgram_cbs.datagram_read_notify =
            wt_case_raw_datagram;
    }
    return wt_case_session_cbs.webtransport_session_create_notify
        ? wt_case_session_cbs.webtransport_session_create_notify(session,
            headers, cid, user_data) : XQC_OK;
}

static xqc_int_t
wt_case_uni_read(xqc_wt_unistream_t *stream, xqc_wt_session_t *session,
    void *data, size_t len, void *user_data)
{
    if (wt_case_uni_received > sizeof(wt_case_uni_payload)
        || len > sizeof(wt_case_uni_payload) - wt_case_uni_received
        || (len && memcmp(data,
            wt_case_uni_payload + wt_case_uni_received, len)))
    {
        wt_case_uni_match = 0;
    }
    wt_case_uni_received += len;
    if (xqc_wt_unistream_get_recv_fin(stream)) {
        printf("WT case uni: bytes=%zu fin=1 match=%d\n", wt_case_uni_received,
               wt_case_uni_match
               && wt_case_uni_received == sizeof(wt_case_uni_payload));
    }
    return wt_case_stream_cbs.wt_unistream_read_notify
        ? wt_case_stream_cbs.wt_unistream_read_notify(stream, session,
            data, len, user_data) : XQC_OK;
}

static xqc_int_t
wt_case_message_length_read(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t len, void *user_data)
{
    /* Message-framing Syntax: Length 6 exceeds the peer's bound of 5. */
    unsigned char oversized[] = {0x00, 0x01, 0x06};
    xqc_int_t sent;

    if (wt_case_message_sent) {
        return XQC_OK;
    }
    sent = xqc_wt_bidistream_send(stream, oversized, sizeof(oversized), 1);
    if (sent != (xqc_int_t) sizeof(oversized)) {
        return XQC_ERROR;
    }
    wt_case_message_sent = 1;
    printf("WT case message oversized: declared=6 bytes=%zu fin=1\n",
           sizeof(oversized));
    return XQC_OK;
}

static int
wt_case_session_closed(xqc_wt_session_t *session, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *user_data)
{
    const char *reason = xqc_wt_session_get_close_reason(session);
    printf("WT case close: code=%" PRIu32 " reason_len=%zu match=%d\n",
           xqc_wt_session_get_close_error_code(session), strlen(reason),
           strcmp(reason, "echo complete") == 0);
    return wt_case_session_cbs.webtransport_session_close_notify
        ? wt_case_session_cbs.webtransport_session_close_notify(session,
            headers, cid, user_data) : XQC_OK;
}

static xqc_int_t
wt_case_bidi_closing(xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *user_data)
{
    xqc_stream_t *raw = stream->base.h3_stream->stream;
    if (!xqc_wt_bidistream_closing_is_stop_sending(stream)
        && raw->reset_at.recv_state == XQC_RESET_AT_RELIABLE)
    {
        /* draft-16 §4.4: the complete three-byte WT header is reliable. */
        printf("WT case reset: reliable=%" PRIu64 " error=%" PRIu64 "\n",
               raw->reset_at.recv_size, raw->reset_at.recv_error);
    }
    return wt_case_stream_cbs.wt_bidistream_closing_notify
        ? wt_case_stream_cbs.wt_bidistream_closing_notify(stream, session,
            user_data) : XQC_OK;
}

static void
wt_case_datagram_read(xqc_wt_session_t *session, const void *data, size_t len,
    void *user_data, uint64_t recv_time)
{
    wt_case_datagram_deliveries++;
    if (wt_case_dgram_cbs.dgram_read_notify) {
        wt_case_dgram_cbs.dgram_read_notify(session, data, len, user_data,
                                           recv_time);
    }
}

static void
wt_case_raw_datagram(xqc_connection_t *transport, void *user_data,
    const void *data, size_t len, uint64_t recv_time)
{
    xqc_wt_conn_t *conn = xqc_wt_create_conn(transport->proto_data);
    size_t before = conn->pending_count;
    unsigned delivered = wt_case_datagram_deliveries;
    int unknown = len == sizeof(wt_case_unknown)
        && memcmp(data, wt_case_unknown, len) == 0;
    wt_case_raw_read(transport, user_data, data, len, recv_time);
    if (unknown) {
        printf("WT case datagram unknown: received=1 delivered=%u buffered=%d\n",
               wt_case_datagram_deliveries - delivered,
               conn->pending_count != before);
    }
}

static int
wt_case_conn_closed(xqc_h3_conn_t *h3c, const xqc_cid_t *cid, void *user_data)
{
    printf("WT case connection: error=%" PRIu64 "\n",
           XQC_CONN_ERR_CODE(h3c->conn->conn_err));
    return wt_case_conn_cbs.h3_conn_close_notify
        ? wt_case_conn_cbs.h3_conn_close_notify(h3c, cid, user_data) : XQC_OK;
}

xqc_int_t
xqc_wt_case_server_init(xqc_engine_t *engine, int case_id)
{
    if (case_id == 0) {
        return XQC_OK;
    }
    xqc_wt_ctx_t *ctx = xqc_wt_ctx_get(engine);
    if (ctx == NULL
        || ((case_id < 1801 || case_id > 1816) && case_id != 1834))
    {
        return -XQC_EPARAM;
    }
    wt_case_server_id = case_id;
    wt_case_uni_match = 1;
    wt_case_message_sent = 0;
    wt_case_stream_cbs = ctx->stream_cbs;
    wt_case_session_cbs = ctx->session_cbs;
    wt_case_dgram_cbs = ctx->dgram_cbs;
    wt_case_conn_cbs = ctx->app_conn_callbacks;
    ctx->session_cbs.webtransport_session_create_notify = wt_case_session_ready;
    ctx->session_cbs.webtransport_session_close_notify = wt_case_session_closed;
    ctx->stream_cbs.wt_unistream_read_notify = wt_case_uni_read;
    if (case_id == 1834) {
        ctx->stream_cbs.wt_bidistream_read_notify =
            wt_case_message_length_read;
    }
    ctx->stream_cbs.wt_bidistream_closing_notify = wt_case_bidi_closing;
    ctx->dgram_cbs.dgram_read_notify = wt_case_datagram_read;
    ctx->app_conn_callbacks.h3_conn_close_notify = wt_case_conn_closed;
    return XQC_OK;
}
