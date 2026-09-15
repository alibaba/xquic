/* Copyright (c) 2026, Alibaba Group Holding Limited. */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xquic/xqc_webtransport_msg.h>
#include "xqc_wt_echo_client.h"
#include "case_test/webtransport/xqc_webtrans_test_cases.h"

#define XQC_DEMO_WT_TRANSFER_SIZE (1024 * 1024)
#define XQC_DEMO_WT_SEND_WINDOW (16 * 1024)
#define XQC_DEMO_WT_MSG_ERROR 1

static unsigned char xqc_demo_wt_payload[] = "xquic WebTransport\0echo";
static const unsigned char xqc_demo_wt_datagram[] = "xquic datagram";

typedef struct {
    xqc_engine_t       *engine;
    xqc_wt_session_t    *session;
    xqc_wt_bidistream_t *stream;
    xqc_wt_msg_stream_t *msg_stream;
    size_t              payload_len;
    size_t              sent;
    size_t              received;
    int                 case_id;
    int                 message_mode;
    int                 print_response;
    int                 ready;
    int                 echo_enabled;
    int                 fin_sent;
    int                 fin_received;
    int                 message_received;
    int                 datagram_sent;
    int                 datagram_received;
    int                 close_sent;
    int                 session_closed;
    int                 failed;
    int                 stopped;
    int                 result;
    void              (*schedule_send)(void *user_data);
    void              (*finished)(void *user_data);
    void               *user_data;
} xqc_demo_wt_client_t;

/* The demo runs one connection and one WebTransport session. */
static xqc_demo_wt_client_t xqc_demo_wt_client;

static void xqc_demo_wt_client_fail(const char *operation, int error);
static int xqc_demo_wt_client_blocked(int error);
static unsigned char xqc_demo_wt_client_payload_byte(size_t offset);
static void xqc_demo_wt_client_print_data(const char *source,
    xqc_stream_id_t stream_id, int has_stream_id, const void *data,
    size_t len);
static void xqc_demo_wt_client_recv_msg(xqc_wt_msg_stream_t *msg_stream,
    xqc_wt_msg_type_t type, const void *data, size_t len, void *user_data);
static void xqc_demo_wt_client_flush(void);
static void xqc_demo_wt_client_maybe_close(void);
static int xqc_demo_wt_client_ready(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data);
static int xqc_demo_wt_client_closed(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data);
static xqc_int_t xqc_demo_wt_client_stream_notify(
    xqc_wt_bidistream_t *stream, xqc_wt_session_t *session, void *user_data);
static xqc_int_t xqc_demo_wt_client_stream_close(
    xqc_wt_bidistream_t *stream, xqc_wt_session_t *session, void *user_data);
static xqc_int_t xqc_demo_wt_client_stream_write(
    xqc_wt_bidistream_t *stream, xqc_wt_session_t *session, void *user_data);
static xqc_int_t xqc_demo_wt_client_stream_read(
    xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *data, size_t len, void *user_data);
static xqc_int_t xqc_demo_wt_client_unistream_notify(
    xqc_wt_unistream_t *stream, xqc_wt_session_t *session, void *user_data);
static xqc_int_t xqc_demo_wt_client_unistream_read(
    xqc_wt_unistream_t *stream, xqc_wt_session_t *session,
    void *data, size_t len, void *user_data);
static void xqc_demo_wt_client_datagram_read(xqc_wt_session_t *session,
    const void *data, size_t len, void *user_data, uint64_t recv_time);
static void xqc_demo_wt_client_datagram_write(xqc_wt_session_t *session,
    void *user_data);

static void
xqc_demo_wt_client_fail(const char *operation, int error)
{
    xqc_demo_wt_client_t *ctx = &xqc_demo_wt_client;

    if (!ctx->failed) {
        printf("WT FAIL: %s error=%d\n", operation, error);
        ctx->failed = 1;
        ctx->finished(ctx->user_data);
    }
}

static int
xqc_demo_wt_client_blocked(int error)
{
    return error == -XQC_EAGAIN || error == -XQC_ECONN_BLOCKED
        || error == -XQC_ESTREAM_BLOCKED;
}

static unsigned char
xqc_demo_wt_client_payload_byte(size_t offset)
{
    if (xqc_demo_wt_client.payload_len == sizeof(xqc_demo_wt_payload)) {
        return xqc_demo_wt_payload[offset];
    }
    /* Each four-byte word identifies its offset, including across chunks. */
    uint32_t word = (uint32_t) (offset / 4) * UINT32_C(2654435761)
        ^ UINT32_C(0x6d2b79f5);
    return (unsigned char) (word >> ((offset % 4) * 8));
}

static void
xqc_demo_wt_client_print_data(const char *source,
    xqc_stream_id_t stream_id, int has_stream_id, const void *data,
    size_t len)
{
    const unsigned char *bytes = data;

    printf("WT recv %s", source);
    if (has_stream_id) {
        printf(": id=%" PRIu64, (uint64_t) stream_id);
    }
    printf(" bytes=%zu data=\"", len);
    for (size_t i = 0; i < len; i++) {
        switch (bytes[i]) {
        case '\\':
            printf("\\\\");
            break;
        case '"':
            printf("\\\"");
            break;
        case '\n':
            printf("\\n");
            break;
        case '\r':
            printf("\\r");
            break;
        case '\t':
            printf("\\t");
            break;
        default:
            if (bytes[i] >= 0x20 && bytes[i] <= 0x7e) {
                putchar(bytes[i]);

            } else {
                printf("\\x%02x", bytes[i]);
            }
        }
    }
    printf("\"\n");
}

static void
xqc_demo_wt_client_recv_msg(xqc_wt_msg_stream_t *msg_stream,
    xqc_wt_msg_type_t type, const void *data, size_t len, void *user_data)
{
    xqc_demo_wt_client_t *ctx = user_data;
    xqc_stream_id_t stream_id = 0;
    int has_stream_id = ctx->stream != NULL;

    if (has_stream_id) {
        stream_id = xqc_wt_bidistream_id(ctx->stream);
    }
    if (ctx->print_response) {
        xqc_demo_wt_client_print_data(type == XQC_WT_MSG_TEXT
            ? "message text" : "message binary", stream_id,
            has_stream_id, data, len);
    }
    if (msg_stream != ctx->msg_stream || ctx->message_received
        || type != XQC_WT_MSG_TEXT || len != ctx->payload_len)
    {
        xqc_demo_wt_client_fail("message echo mismatch", XQC_ERROR);
        return;
    }
    for (size_t i = 0; i < len; i++) {
        if (((const unsigned char *) data)[i] != 'd') {
            xqc_demo_wt_client_fail("message echo mismatch", XQC_ERROR);
            return;
        }
    }

    ctx->received = len;
    ctx->message_received = 1;
    printf("WT message verified: type=text bytes=%zu\n", len);
}

static void
xqc_demo_wt_client_flush(void)
{
    xqc_demo_wt_client_t *ctx = &xqc_demo_wt_client;
    xqc_int_t ret;
    uint64_t id;

    if (!ctx->ready || !ctx->echo_enabled || ctx->failed || ctx->close_sent) {
        return;
    }
    if (ctx->message_mode) {
        if (ctx->msg_stream != NULL) {
            ret = xqc_wt_msg_stream_flush(ctx->msg_stream);
            if (ret != XQC_OK) {
                xqc_demo_wt_client_fail("message flush", ret);
                return;
            }
            ctx->schedule_send(ctx->user_data);
        }
        return;
    }
    if (ctx->stream && !ctx->fin_sent) {
        unsigned char data[XQC_DEMO_WT_SEND_WINDOW];
        size_t len = ctx->payload_len - ctx->sent;
        size_t available = sizeof(data) - (ctx->sent - ctx->received);

        /* Bound server echo buffering while retaining every short write. */
        if (len > available) {
            len = available;
        }
        if (len || ctx->sent == ctx->payload_len) {
            int fin = ctx->sent + len == ctx->payload_len;

            for (size_t i = 0; i < len; i++) {
                data[i] = xqc_demo_wt_client_payload_byte(ctx->sent + i);
            }
            ret = xqc_wt_bidistream_send(ctx->stream, data, len, fin);
            if (ret >= 0) {
                if ((size_t) ret > len) {
                    xqc_demo_wt_client_fail("invalid stream write", ret);
                    return;
                }
                ctx->sent += ret;
                ctx->fin_sent = fin && (size_t) ret == len;

            } else if (!xqc_demo_wt_client_blocked(ret)) {
                xqc_demo_wt_client_fail("stream send", ret);
                return;
            }
        }
    }
    if (!ctx->datagram_sent) {
        ret = xqc_wt_session_datagram_send(ctx->session,
            xqc_demo_wt_datagram, sizeof(xqc_demo_wt_datagram), &id);
        if (ret == XQC_OK) {
            ctx->datagram_sent = 1;

        } else if (!xqc_demo_wt_client_blocked(ret)) {
            xqc_demo_wt_client_fail("datagram send", ret);
            return;
        }
    }
    ctx->schedule_send(ctx->user_data);
}

static void
xqc_demo_wt_client_maybe_close(void)
{
    xqc_demo_wt_client_t *ctx = &xqc_demo_wt_client;
    const char *reason;
    xqc_int_t ret;

    if (ctx->failed || ctx->close_sent
        || (ctx->message_mode && !ctx->message_received)
        || (!ctx->message_mode
            && (!ctx->fin_received || !ctx->datagram_received)))
    {
        return;
    }
    ctx->close_sent = 1;
    reason = ctx->message_mode ? "message echo complete" : "echo complete";

    ret = xqc_wt_session_close_with_error(ctx->session, 0, reason,
                                          strlen(reason));
    if (ret != XQC_OK) {
        xqc_demo_wt_client_fail("session close", ret);
        return;
    }
    printf("WT close sent\n");
    ctx->schedule_send(ctx->user_data);
}

static int
xqc_demo_wt_client_ready(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data)
{
    xqc_demo_wt_client_t *ctx = &xqc_demo_wt_client;
    xqc_wt_bidistream_t *reset_stream;
    unsigned char *payload;
    xqc_int_t ret;
    int err;

    ctx->session = session;
    ctx->ready = 1;
    printf("WT ready: draft=%d status=%u\n",
           xqc_wt_session_get_draft_version(session)
               == XQC_WEBTRANSPORT_DRAFT_VERSION_16 ? 16 : 7,
           xqc_wt_session_get_response_status(session));

    err = xqc_wt_case_prepare(session, ctx->case_id);
    if (err < 0) {
        xqc_demo_wt_client_fail("case prepare", err);
        return XQC_ERROR;
    }
    if (err > 0) {
        ctx->schedule_send(ctx->user_data);
        return XQC_OK;
    }
    if (ctx->message_mode
        && xqc_wt_session_get_draft_version(session)
            != XQC_WEBTRANSPORT_DRAFT_VERSION_16)
    {
        xqc_demo_wt_client_fail("message framing requires draft 16",
                                XQC_ERROR);
        return XQC_ERROR;
    }
    ctx->echo_enabled = 1;

    if (!ctx->message_mode) {
        reset_stream = xqc_wt_session_create_bidi_stream(session, NULL, &err);
        if (!reset_stream) {
            xqc_demo_wt_client_fail("reset stream create", err);
            return XQC_ERROR;
        }
        err = xqc_wt_bidistream_reset(reset_stream, 42);
        if (err != XQC_OK) {
            xqc_demo_wt_client_fail("stream reset", err);
            return XQC_ERROR;
        }
        printf("WT reset sent: id=%" PRIu64 " code=42\n",
               (uint64_t) xqc_wt_bidistream_id(reset_stream));
    }

    ctx->stream = xqc_wt_session_create_bidi_stream(session, NULL, &err);
    if (!ctx->stream) {
        xqc_demo_wt_client_fail("bidirectional stream create", err);
        return XQC_ERROR;
    }
    if (ctx->message_mode) {
        ctx->msg_stream = xqc_wt_msg_stream_create(ctx->stream,
            ctx->payload_len, xqc_demo_wt_client_recv_msg, ctx, &err);
        if (ctx->msg_stream == NULL) {
            xqc_demo_wt_client_fail("message stream create", err);
            return XQC_ERROR;
        }
        payload = malloc(ctx->payload_len);
        if (payload == NULL) {
            xqc_demo_wt_client_fail("message payload allocate", -XQC_EMALLOC);
            return XQC_ERROR;
        }
        memset(payload, 'd', ctx->payload_len);
        ret = xqc_wt_msg_stream_send_msg(ctx->msg_stream,
            XQC_WT_MSG_TEXT, payload, ctx->payload_len);
        free(payload);
        if (ret != XQC_OK) {
            xqc_demo_wt_client_fail("message send", ret);
            return XQC_ERROR;
        }
        ret = xqc_wt_msg_stream_finish(ctx->msg_stream);
        if (ret != XQC_OK) {
            xqc_demo_wt_client_fail("message finish", ret);
            return XQC_ERROR;
        }
        printf("WT message queued: type=text bytes=%zu fill=d\n",
               ctx->payload_len);
    }
    xqc_demo_wt_client_flush();
    return XQC_OK;
}

static int
xqc_demo_wt_client_closed(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data)
{
    xqc_demo_wt_client_t *ctx = &xqc_demo_wt_client;

    if (ctx->stopped) {
        return XQC_OK;
    }
    ctx->session_closed = 1;
    printf("WT closed: ready=%d status=%u code=%" PRIu32 "\n", ctx->ready,
           xqc_wt_session_get_response_status(session),
           xqc_wt_session_get_close_error_code(session));
    if (!ctx->failed && ctx->ready && ctx->close_sent
        && ((ctx->message_mode && ctx->message_received)
            || (!ctx->message_mode && ctx->fin_received
                && ctx->datagram_received))
        && xqc_wt_session_get_close_error_code(session) == 0)
    {
        ctx->result = 0;
    }
    ctx->session = NULL;
    if (ctx->msg_stream != NULL) {
        xqc_wt_msg_stream_destroy(ctx->msg_stream);
        ctx->msg_stream = NULL;
    }
    ctx->stream = NULL;
    if (!ctx->failed) {
        xqc_int_t ret = xqc_h3_conn_close(ctx->engine, cid);

        if (ret != XQC_OK) {
            ctx->result = 1;
            xqc_demo_wt_client_fail("connection close", ret);
        }
    }
    if (ctx->result == 0) {
        if (ctx->message_mode) {
            printf("WT PASS: exact framed message echo, close\n");

        } else {
            printf("WT PASS: bidi exact echo + FIN, datagram, close\n");
        }
    }
    ctx->finished(ctx->user_data);
    return XQC_OK;
}

static xqc_int_t
xqc_demo_wt_client_stream_notify(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    return XQC_OK;
}

static xqc_int_t
xqc_demo_wt_client_stream_close(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    xqc_demo_wt_client_t *ctx = &xqc_demo_wt_client;
    int incomplete = 0;

    if (stream == ctx->stream) {
        incomplete = ctx->message_mode && !ctx->message_received
            && !ctx->failed && !ctx->stopped;
        if (ctx->msg_stream != NULL) {
            xqc_wt_msg_stream_destroy(ctx->msg_stream);
            ctx->msg_stream = NULL;
        }
        ctx->stream = NULL;
        if (incomplete) {
            xqc_demo_wt_client_fail("message stream closed before echo",
                                    XQC_ERROR);
        }
    }
    return XQC_OK;
}

static xqc_int_t
xqc_demo_wt_client_stream_write(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    if (stream == xqc_demo_wt_client.stream) {
        xqc_demo_wt_client_flush();
    }
    return XQC_OK;
}

static xqc_int_t
xqc_demo_wt_client_stream_read(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t len, void *user_data)
{
    xqc_demo_wt_client_t *ctx = &xqc_demo_wt_client;
    xqc_int_t ret;

    if (stream != ctx->stream) {
        if (ctx->print_response) {
            xqc_demo_wt_client_print_data("bidi",
                xqc_wt_bidistream_id(stream), 1, data, len);
        }
        return XQC_OK;
    }
    if (ctx->message_mode) {
        if (ctx->msg_stream == NULL) {
            xqc_demo_wt_client_fail("message stream unavailable", XQC_ERROR);
            return XQC_OK;
        }
        ret = xqc_wt_msg_stream_recv_msg(ctx->msg_stream, data, len);
        if (ret != XQC_OK) {
            (void) xqc_wt_bidistream_stop_sending(stream,
                                                  XQC_DEMO_WT_MSG_ERROR);
            (void) xqc_wt_bidistream_reset(stream, XQC_DEMO_WT_MSG_ERROR);
            ctx->schedule_send(ctx->user_data);
            xqc_demo_wt_client_fail("message parse", ret);
        }
        xqc_demo_wt_client_maybe_close();
        return XQC_OK;
    }
    if (ctx->print_response) {
        xqc_demo_wt_client_print_data("bidi",
            xqc_wt_bidistream_id(stream), 1, data, len);
    }
    if (len > ctx->sent - ctx->received) {
        xqc_demo_wt_client_fail("stream echo mismatch", XQC_ERROR);
        return XQC_ERROR;
    }
    for (size_t i = 0; i < len; i++) {
        if (((unsigned char *) data)[i]
            != xqc_demo_wt_client_payload_byte(ctx->received + i))
        {
            xqc_demo_wt_client_fail("stream echo mismatch", XQC_ERROR);
            return XQC_ERROR;
        }
    }
    ctx->received += len;
    if (xqc_wt_bidistream_get_recv_fin(stream)) {
        if (ctx->received != ctx->payload_len || !ctx->fin_sent) {
            xqc_demo_wt_client_fail("short stream echo", XQC_ERROR);
            return XQC_ERROR;
        }
        ctx->fin_received = 1;
        printf("WT bidi verified: bytes=%zu fin=1\n", ctx->received);
        if (ctx->case_id == 1801 || ctx->case_id == 1802) {
            printf("WT transfer: sent=%zu received=%zu\n",
                   ctx->sent, ctx->received);
        }
        xqc_demo_wt_client_maybe_close();

    } else {
        xqc_demo_wt_client_flush();
    }
    return XQC_OK;
}

static xqc_int_t
xqc_demo_wt_client_unistream_notify(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    return XQC_OK;
}

static xqc_int_t
xqc_demo_wt_client_unistream_read(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t len, void *user_data)
{
    if (xqc_demo_wt_client.print_response) {
        xqc_demo_wt_client_print_data("uni", xqc_wt_unistream_id(stream),
            1, data, len);
    }
    return XQC_OK;
}

static void
xqc_demo_wt_client_datagram_read(xqc_wt_session_t *session,
    const void *data, size_t len, void *user_data, uint64_t recv_time)
{
    xqc_demo_wt_client_t *ctx = &xqc_demo_wt_client;

    if (ctx->print_response) {
        xqc_demo_wt_client_print_data("datagram", 0, 0, data, len);
    }
    if (ctx->message_mode) {
        return;
    }
    if (len != sizeof(xqc_demo_wt_datagram)
        || memcmp(data, xqc_demo_wt_datagram, len))
    {
        xqc_demo_wt_client_fail("datagram echo mismatch", XQC_ERROR);
        return;
    }
    ctx->datagram_received = 1;
    printf("WT datagram verified: bytes=%zu\n", len);
    xqc_demo_wt_client_maybe_close();
}

static void
xqc_demo_wt_client_datagram_write(xqc_wt_session_t *session, void *user_data)
{
    xqc_demo_wt_client_flush();
}

xqc_int_t
xqc_demo_wt_client_init(xqc_engine_t *engine, int draft_version,
    int case_id, size_t payload_len, int print_response,
    void (*schedule_send)(void *user_data),
    void (*finished)(void *user_data), void *user_data)
{
    xqc_webtransport_dgram_callbacks_t dgram_cbs = {
        .dgram_read_notify = xqc_demo_wt_client_datagram_read,
        .dgram_write_notify = xqc_demo_wt_client_datagram_write,
    };
    xqc_webtransport_session_callbacks_t session_cbs = {
        .webtransport_session_create_notify = xqc_demo_wt_client_ready,
        .webtransport_session_close_notify = xqc_demo_wt_client_closed,
    };
    xqc_webtransport_stream_callbacks_t stream_cbs = {
        .wt_unistream_create_notify = xqc_demo_wt_client_unistream_notify,
        .wt_unistream_read_notify = xqc_demo_wt_client_unistream_read,
        .wt_unistream_write_notify = xqc_demo_wt_client_unistream_notify,
        .wt_unistream_close_notify = xqc_demo_wt_client_unistream_notify,
        .wt_unistream_closing_notify = xqc_demo_wt_client_unistream_notify,
        .wt_bidistream_create_notify = xqc_demo_wt_client_stream_notify,
        .wt_bidistream_read_notify = xqc_demo_wt_client_stream_read,
        .wt_bidistream_write_notify = xqc_demo_wt_client_stream_write,
        .wt_bidistream_close_notify = xqc_demo_wt_client_stream_close,
        .wt_bidistream_closing_notify = xqc_demo_wt_client_stream_notify,
    };
    xqc_webtransport_conn_settings_t settings = {
        .max_sessions_count = 1,
        .draft_version = draft_version == 7
            ? XQC_WEBTRANSPORT_DRAFT_VERSION_7
            : XQC_WEBTRANSPORT_DRAFT_VERSION_16,
        .max_bidi_streams = 16,
        .max_uni_streams = 16,
        .init_recv_window = 1024 * 1024,
        .enable_datagram = 1,
    };
    xqc_int_t ret;

    memset(&xqc_demo_wt_client, 0, sizeof(xqc_demo_wt_client));
    xqc_demo_wt_client.engine = engine;
    xqc_demo_wt_client.case_id = case_id;
    xqc_demo_wt_client.message_mode = payload_len != 0;
    xqc_demo_wt_client.print_response = print_response;
    xqc_demo_wt_client.payload_len = payload_len ? payload_len
        : case_id == 1801 || case_id == 1802
            ? XQC_DEMO_WT_TRANSFER_SIZE : sizeof(xqc_demo_wt_payload);
    xqc_demo_wt_client.result = 1;
    xqc_demo_wt_client.schedule_send = schedule_send;
    xqc_demo_wt_client.finished = finished;
    xqc_demo_wt_client.user_data = user_data;
    ret = xqc_wt_ctx_init(engine, &dgram_cbs, &session_cbs, &stream_cbs);
    return ret == XQC_OK
        ? xqc_wt_engine_set_default_settings(engine, &settings) : ret;
}

xqc_int_t
xqc_demo_wt_client_open(xqc_h3_conn_t *h3_conn,
    const char *authority, const char *path, const char *origin)
{
    int err;

    xqc_demo_wt_client.session = xqc_wt_client_open_session(h3_conn,
        authority, path, origin, &err);
    if (!xqc_demo_wt_client.session) {
        xqc_demo_wt_client_fail("session open", err);
        return err;
    }
    xqc_demo_wt_client.schedule_send(xqc_demo_wt_client.user_data);
    return XQC_OK;
}

int
xqc_demo_wt_client_finish(void)
{
    /* Engine destruction is cleanup, not a peer close acknowledgement. */
    xqc_demo_wt_client.stopped = 1;
    if (xqc_demo_wt_client.msg_stream != NULL) {
        xqc_wt_msg_stream_destroy(xqc_demo_wt_client.msg_stream);
        xqc_demo_wt_client.msg_stream = NULL;
    }
    return xqc_demo_wt_client.result;
}

xqc_int_t
xqc_demo_wt_client_conn_closing(xqc_connection_t *conn,
    const xqc_cid_t *cid, xqc_int_t error, void *user_data)
{
    if (!xqc_demo_wt_client.stopped && !xqc_demo_wt_client.session_closed) {
        xqc_demo_wt_client_fail("connection closed before session close",
                                error);
    }
    return XQC_OK;
}
