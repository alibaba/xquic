/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include <CUnit/CUnit.h>
#include "xqc_common_test.h"
#include "xqc_webtransport_test.h"
#include "src/webtransport/xqc_webtransport_ctx.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/webtransport/xqc_webtransport_h3_stream.h"
#include "src/webtransport/xqc_webtransport_dgram.h"
#include "src/http3/xqc_h3_ctx.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_request.h"
#include "src/transport/xqc_stream.h"
#include "src/http3/frame/xqc_h3_frame.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_packet_out.h"

static int wt_reads, wt_closes, wt_fin, wt_block;
static size_t wt_sent, wt_send_limit;
static unsigned char wt_output[64];
static xqc_wt_session_t *wt_last_session;
static void *wt_last_context;

static xqc_int_t wt_select_protocol(const char *value,
    const char *const *protocols, size_t count, const char **selected);

static xqc_int_t
wt_select_protocol(const char *value, const char *const *protocols,
    size_t count, const char **selected)
{
    xqc_http_header_t header = {
        .name = {(void *)"wt-available-protocols",
                 sizeof("wt-available-protocols") - 1},
        .value = {(void *)value, strlen(value)},
    };
    xqc_http_headers_t headers = {.headers = &header, .count = 1};
    return xqc_wt_select_application_protocol(&headers, protocols, count,
                                              selected);
}

void
xqc_test_wt_protocol_selection(void)
{
    const char *protocols[] = {"server-first", "client-first", "a\"b\\c"};
    const char *valid[] = {"\"client-first\", \"server-first\"",
        " \"client-first\";ignored=\"x,y\", \"server-first\" ",
        "\"client-first\";flag;version=7;raw=:YQ==:",
        ("\"client-first\";display=%\"caf%c3%a9\";flag=?0;date=@-5"
         ";decimal=-1.25;token=*a:/;raw=:AQI:;empty=::;text=\"a\\\"b\""),
        "\"other\",\t\"client-first\"\t"};
    const char *selected;

    /* draft-16 Section 3.3: String List, client order, ignored parameters. */
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        CU_ASSERT(wt_select_protocol(valid[i], protocols, 3, &selected) == 1);
        CU_ASSERT_PTR_EQUAL(selected, protocols[1]);
    }
    CU_ASSERT(wt_select_protocol("\"a\\\"b\\\\c\"", protocols, 3,
                                 &selected) == 1);
    CU_ASSERT_PTR_EQUAL(selected, protocols[2]);

    /* RFC 9651 Section 4.2 combines List field lines in received order. */
    char offer[] = "\"client-first\"";
    xqc_http_header_t fields[] = {
        {.name = {(void *)"wt-available-protocols",
                 sizeof("wt-available-protocols") - 1},
         .value = {(void *)"\"other\"", sizeof("\"other\"") - 1}},
        {.name = {(void *)"x-unrelated", sizeof("x-unrelated") - 1},
         .value = {(void *)"ignored", sizeof("ignored") - 1}},
        {.name = {(void *)"WT-Available-Protocols",
                  sizeof("WT-Available-Protocols") - 1},
         .value = {offer, sizeof(offer) - 1}},
        {.name = {(void *)"wt-available-protocols",
                 sizeof("wt-available-protocols") - 1},
         .value = {(void *)"\"server-first\"", sizeof("\"server-first\"") - 1}},
    };
    xqc_http_headers_t headers = {.headers = fields, .count = 4};
    CU_ASSERT(xqc_wt_select_application_protocol(&headers, protocols, 3,
                                                 &selected) == 1);
    CU_ASSERT_PTR_EQUAL(selected, protocols[1]);
    memset(offer, 'x', sizeof(offer) - 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(selected);
    CU_ASSERT_STRING_EQUAL(selected, "client-first");

    char long_protocol[1025], long_list[1027];
    memset(long_protocol, 'a', sizeof(long_protocol) - 1);
    long_protocol[sizeof(long_protocol) - 1] = '\0';
    long_list[0] = '"';
    memcpy(long_list + 1, long_protocol, sizeof(long_protocol) - 1);
    long_list[1025] = '"';
    long_list[1026] = '\0';
    const char *long_offered[] = {long_protocol};
    /* RFC 9651 Section 3.3.3 requires support for 1024-character Strings. */
    CU_ASSERT(wt_select_protocol(long_list, long_offered, 1, &selected) == 1);
    CU_ASSERT_PTR_EQUAL(selected, long_protocol);

    const char *empty[] = {""};
    CU_ASSERT(wt_select_protocol("\"\"", empty, 1, &selected) == 1);
    CU_ASSERT_PTR_EQUAL(selected, empty[0]);
    CU_ASSERT(wt_select_protocol("\"other\"", protocols, 3, &selected) == 0);
    CU_ASSERT_PTR_NULL(selected);
    CU_ASSERT(wt_select_protocol("", protocols, 3, &selected) == 0);
    CU_ASSERT_PTR_NULL(selected);
    CU_ASSERT(wt_select_protocol("   ", protocols, 3, &selected) == 0);
    CU_ASSERT_PTR_NULL(selected);
}

void
xqc_test_wt_protocol_selection_errors(void)
{
    const char *protocols[] = {"server-first", "client-first", "a\"b\\c"};
    const char *invalid[] = {"client-first", "\"client-first\",",
        "\"client-first\" garbage", "\"client-first\";=1",
        "\"client-first\";value=", "\"unterminated",
        "\"bad\\escape\"", "\"client-first\", unquoted",
        "\"client-first\";bad=?7", "\"client-first\";bad=1.1234",
        "\"client-first\";bad=-", "\"client-first\";bad=@",
        "\"client-first\";bad=:a:", "\"client-first\";bad=:AQ=I:",
        "\"client-first\";bad=:AQI===:", "\"client-first\";bad=:AQI",
        "\"client-first\";bad=%\"%ff\"",
        "\"client-first\";bad=%\"%e2%82\"",
        "\"client-first\";bad=%\"%gg\"",
        "\"client-first\";bad=%\"%\"",
        "\"client-first\";bad=%oops",
        "\"client-first\";bad=%\"unterminated",
        "\t\"client-first\"", "\"client-first\", (\"nested\")"};
    const char *selected;

    /* RFC 9651 Section 4.2: a matching prefix cannot hide invalid suffixes. */
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        selected = protocols[0];
        CU_ASSERT(wt_select_protocol(invalid[i], protocols, 3,
                                     &selected) == -XQC_EPARAM);
        CU_ASSERT_PTR_NULL(selected);
    }
    xqc_http_header_t fields[] = {
        {.name = {(void *)"wt-available-protocols",
                 sizeof("wt-available-protocols") - 1},
         .value = {(void *)"\"client-first\"", sizeof("\"client-first\"") - 1}},
        {.name = {(void *)"wt-available-protocols",
                 sizeof("wt-available-protocols") - 1},
         .value = {(void *)"invalid", sizeof("invalid") - 1}},
    };
    xqc_http_headers_t headers = {.headers = fields, .count = 2};
    CU_ASSERT(xqc_wt_select_application_protocol(&headers, protocols, 3,
                                                 &selected) == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(selected);
    fields[1].value.iov_base = NULL;
    fields[1].value.iov_len = 0;
    CU_ASSERT(xqc_wt_select_application_protocol(&headers, protocols, 3,
                                                 &selected) == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(selected);

    char long_list[1028];
    memset(long_list, 'a', sizeof(long_list));
    long_list[0] = '"';
    long_list[1026] = '"';
    long_list[1027] = '\0';
    CU_ASSERT(wt_select_protocol(long_list, protocols, 3,
                                 &selected) == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(selected);

    char large[4097];
    memset(large, ' ', sizeof(large));
    memcpy(large, "\"client-first\"", sizeof("\"client-first\"") - 1);
    fields[0].value.iov_base = large;
    fields[0].value.iov_len = 4092;
    fields[1].value.iov_base = (void *)"\"\"";
    fields[1].value.iov_len = sizeof("\"\"") - 1;
    CU_ASSERT(xqc_wt_select_application_protocol(&headers, protocols, 3,
                                                 &selected) == 1);
    CU_ASSERT_PTR_EQUAL(selected, protocols[1]);
    fields[0].value.iov_len++;
    CU_ASSERT(xqc_wt_select_application_protocol(&headers, protocols, 3,
                                                 &selected) == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(selected);
    headers.count = 1;
    fields[0].value.iov_len = sizeof(large);
    CU_ASSERT(xqc_wt_select_application_protocol(&headers, protocols, 3,
                                                 &selected) == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(selected);
    fields[0].value.iov_len = 4096;
    large[sizeof("\"client-first\"") - 1] = '\0';
    CU_ASSERT(xqc_wt_select_application_protocol(&headers, protocols, 3,
                                                 &selected) == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(selected);
}

void
xqc_test_wt_protocol_selection_inputs(void)
{
    const char *protocols[] = {"valid"};
    const char *selected = protocols[0];
    xqc_http_headers_t headers = {0};

    CU_ASSERT(xqc_wt_select_application_protocol(NULL, protocols, 1,
                                                 &selected) == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(selected);
    CU_ASSERT(xqc_wt_select_application_protocol(&headers, protocols, 1,
                                                 NULL) == -XQC_EPARAM);
    CU_ASSERT(xqc_wt_select_application_protocol(&headers, protocols, 1,
                                                 &selected) == 0);
    CU_ASSERT_PTR_NULL(selected);
    CU_ASSERT(wt_select_protocol("\"valid\"", NULL, 0, &selected) == 0);
    CU_ASSERT_PTR_NULL(selected);
    CU_ASSERT(wt_select_protocol("invalid", NULL, 0,
                                 &selected) == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(selected);
    CU_ASSERT(wt_select_protocol("\"valid\"", NULL, 1,
                                 &selected) == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(selected);
    CU_ASSERT(wt_select_protocol("\"valid\"", protocols, 1025,
                                 &selected) == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(selected);

    const char *invalid[] = {NULL, "bad\nvalue", "bad\x80"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        CU_ASSERT(wt_select_protocol("\"valid\"", &invalid[i], 1,
                                     &selected) == -XQC_EPARAM);
        CU_ASSERT_PTR_NULL(selected);
    }
    char long_protocol[1026];
    memset(long_protocol, 'a', sizeof(long_protocol) - 1);
    long_protocol[sizeof(long_protocol) - 1] = '\0';
    const char *too_long[] = {long_protocol};
    CU_ASSERT(wt_select_protocol("\"valid\"", too_long, 1,
                                 &selected) == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(selected);
    long_protocol[1024] = '\0';
    const char *too_many[] = {
        long_protocol, long_protocol, long_protocol, long_protocol
    };
    CU_ASSERT(wt_select_protocol("\"valid\"", too_many, 4,
                                 &selected) == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(selected);

    headers.count = 1;
    CU_ASSERT(xqc_wt_select_application_protocol(&headers, protocols, 1,
                                                 &selected) == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(selected);
    xqc_http_header_t header = {
        .name = {NULL, sizeof("wt-available-protocols") - 1},
        .value = {(void *)"\"valid\"", sizeof("\"valid\"") - 1},
    };
    headers.headers = &header;
    CU_ASSERT(xqc_wt_select_application_protocol(&headers, protocols, 1,
                                                 &selected) == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(selected);
    header.name.iov_base = (void *)"wt-available-protocols";
    header.value.iov_base = NULL;
    CU_ASSERT(xqc_wt_select_application_protocol(&headers, protocols, 1,
                                                 &selected) == -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(selected);
    header.value.iov_len = 0;
    CU_ASSERT(xqc_wt_select_application_protocol(&headers, protocols, 1,
                                                 &selected) == 0);
    CU_ASSERT_PTR_NULL(selected);
}

static xqc_int_t
wt_read(xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *data, size_t len, void *ctx)
{
    wt_reads++;
    wt_last_context = ctx;
    wt_fin = xqc_wt_bidistream_get_recv_fin(stream);
    return wt_block ? -XQC_EAGAIN : XQC_OK;
}

static xqc_int_t
wt_close(xqc_wt_bidistream_t *stream, xqc_wt_session_t *session, void *ctx)
{
    wt_closes++;
    CU_ASSERT_PTR_NOT_NULL(session);
    return XQC_OK;
}

static ssize_t
wt_send(xqc_h3_stream_t *stream, const unsigned char *data,
    size_t len, uint8_t fin)
{
    size_t n = xqc_min(len, wt_send_limit);
    if (n) {
        memcpy(wt_output + wt_sent, data, n);
        wt_sent += n;
    }
    return n == 0 && len ? -XQC_EAGAIN : (ssize_t)n;
}

static xqc_int_t
wt_cancel(xqc_h3_stream_t *stream, uint64_t error)
{
    return XQC_OK;
}

static xqc_int_t
wt_pause(xqc_h3_stream_t *stream, xqc_bool_t paused)
{
    return XQC_OK;
}

static void
wt_detach(xqc_h3_stream_t *stream)
{
    xqc_wt_h3_stream_detach(stream);
    xqc_wt_h3_stream_close(stream);
}

static const xqc_wt_stream_io_ops_t wt_io = {
    wt_send, wt_cancel, wt_cancel, wt_pause, wt_detach
};

static void
wt_dgram(xqc_wt_session_t *session, const void *data,
    size_t len, void *ctx, uint64_t time)
{
    wt_reads++;
    wt_last_session = session;
    CU_ASSERT(len == 1);
    CU_ASSERT(*(const unsigned char *)data == 'x');
}

void
xqc_test_wt_context(void)
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    CU_ASSERT_PTR_NULL(xqc_wt_ctx_get(engine));
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, NULL) == -XQC_ESTATE);
    int marker;
    engine->user_data = &marker;
    xqc_webtransport_stream_callbacks_t cbs = {
        .wt_bidistream_read_notify = wt_read,
    };
    CU_ASSERT(xqc_wt_ctx_init(engine, NULL, NULL, &cbs) == XQC_OK);
    cbs.wt_bidistream_read_notify = NULL;
    xqc_wt_ctx_t *ctx = xqc_wt_ctx_get(engine);
    CU_ASSERT_PTR_EQUAL(engine->user_data, &marker);
    CU_ASSERT(ctx->stream_cbs.wt_bidistream_read_notify == wt_read);
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, NULL) == XQC_OK);
    CU_ASSERT(ctx->settings.draft_version
              == XQC_WEBTRANSPORT_DRAFT_VERSION_16);
    CU_ASSERT(ctx->settings.max_sessions_count == 1);
    CU_ASSERT(engine->default_conn_settings.max_datagram_frame_size > 0);
    CU_ASSERT(engine->default_conn_settings.enable_reset_stream_at);
    CU_ASSERT(ctx->pending_count_max
              == XQC_WEBTRANSPORT_DEFAULT_PENDING_DGRAM_COUNT_MAX);
    CU_ASSERT(ctx->pending_bytes_max
              == XQC_WEBTRANSPORT_DEFAULT_PENDING_DGRAM_BYTES_MAX);
    CU_ASSERT(xqc_wt_ctx_set_pending_datagram_policy(engine, 8, 2, 16)
              == XQC_OK);
    CU_ASSERT(ctx->pending_count_max == 2);
    xqc_h3_ctx_destroy(engine);
    CU_ASSERT_PTR_NULL(xqc_wt_ctx_get(engine));
    xqc_engine_destroy(engine);
}

void
xqc_test_wt_context_errors(void)
{
    CU_ASSERT(xqc_wt_ctx_init(NULL, NULL, NULL, NULL) == -XQC_EPARAM);
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    CU_ASSERT(xqc_wt_ctx_init(engine, NULL, NULL, NULL) == XQC_OK);
    CU_ASSERT(xqc_wt_ctx_init(engine, NULL, NULL, NULL) == -XQC_ESTATE);
    xqc_wt_ctx_t *ctx = xqc_wt_ctx_get(engine);
    xqc_webtransport_conn_settings_t settings = ctx->settings;
    settings.draft_version = (xqc_webtransport_draft_version_t)0;
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, &settings)
              == -XQC_EPARAM);
    settings = ctx->settings;
    settings.max_sessions_count = 2;
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, &settings)
              == XQC_OK);
    CU_ASSERT(ctx->settings.max_sessions_count == 2);
    settings.max_bidi_streams = (UINT64_C(1) << 60) + 1;
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, &settings)
              == -XQC_EPARAM);
    settings.max_bidi_streams = ctx->settings.max_bidi_streams;
    settings.max_uni_streams = (UINT64_C(1) << 60) + 1;
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, &settings)
              == -XQC_EPARAM);
    settings.max_uni_streams = ctx->settings.max_uni_streams;
    settings.max_sessions_count = 1025;
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, &settings)
              == -XQC_EPARAM);
    ctx->started = XQC_TRUE;
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, NULL) == -XQC_ESTATE);
    CU_ASSERT(xqc_wt_ctx_set_pending_datagram_policy(engine, 1, 1, 1)
              == -XQC_ESTATE);
    xqc_h3_ctx_destroy(engine);
    xqc_engine_destroy(engine);
}

static xqc_wt_session_t *
wt_session(xqc_wt_ctx_t *ctx, xqc_h3_conn_t *h3c)
{
    xqc_wt_conn_t *conn = xqc_wt_conn_create(h3c);
    if (!conn) {
        return NULL;
    }
    ctx->settings.draft_version = XQC_WEBTRANSPORT_DRAFT_VERSION_16;
    ctx->settings.max_sessions_count = 16;
    conn->ctx = ctx;
    conn->negotiated_version = XQC_WEBTRANSPORT_DRAFT_VERSION_16;
    xqc_wt_session_t *session = xqc_wt_session_init(4, conn, NULL);
    if (session) {
        session->open = XQC_TRUE;
    }
    return session;
}

void
xqc_test_wt_stream_io(void)
{
    xqc_wt_ctx_t ctx;
    xqc_memzero(&ctx, sizeof(ctx));
    ctx.stream_cbs.wt_bidistream_read_notify = wt_read;
    ctx.stream_cbs.wt_bidistream_close_notify = wt_close;
    int marker;
    xqc_h3_conn_t h3c = {.user_data = &marker};
    xqc_wt_session_t *session = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    xqc_h3_stream_t h3s = {.stream_id = 8, .h3c = &h3c};
    xqc_wt_stream_base_t *stream = xqc_wt_stream_bind(session, &h3s,
                                                      XQC_TRUE, XQC_TRUE, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    stream->io = &wt_io;
    wt_sent = 0;
    wt_send_limit = 1;
    /* draft-ietf-webtrans-http3-16 Section 4.3: prefix is not payload. */
    CU_ASSERT(xqc_wt_bidistream_send((void *)stream, "abc", 3, 1)
              == -XQC_EAGAIN);
    wt_send_limit = 2;
    CU_ASSERT(xqc_wt_bidistream_send((void *)stream, "abc", 3, 1) == 2);
    CU_ASSERT(!stream->send_fin);
    CU_ASSERT(xqc_wt_bidistream_send((void *)stream, "c", 1, 1) == 1);
    CU_ASSERT(stream->send_fin);
    CU_ASSERT(wt_sent == 6);
    CU_ASSERT(memcmp(wt_output, "\x40\x41\x04" "abc", 6) == 0);
    wt_reads = wt_fin = wt_block = wt_closes = 0;
    CU_ASSERT(xqc_wt_stream_notify_read(stream, NULL, 0, 1) == 0);
    CU_ASSERT(wt_reads == 1 && wt_fin == 1);
    CU_ASSERT_PTR_EQUAL(wt_last_context, &marker);
    xqc_wt_conn_destroy(session->wt_conn);
    CU_ASSERT(wt_closes == 1);
    CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_context(&h3s));
}

void
xqc_test_wt_stream_errors(void)
{
    xqc_wt_ctx_t ctx;
    xqc_memzero(&ctx, sizeof(ctx));
    ctx.stream_cbs.wt_bidistream_read_notify = wt_read;
    xqc_h3_conn_t h3c = {0};
    xqc_wt_session_t *session = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    xqc_h3_stream_t h3s = {.stream_id = 8, .h3c = &h3c};
    xqc_wt_stream_base_t *stream = xqc_wt_stream_bind(
        session, &h3s, XQC_TRUE, XQC_FALSE, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    stream->io = &wt_io;
    wt_block = 1;
    CU_ASSERT(xqc_wt_stream_notify_read(stream, (void *)"x", 1, 1)
              == -XQC_EAGAIN);
    CU_ASSERT(!stream->recv_fin && stream->read_paused);
    CU_ASSERT(xqc_wt_bidistream_set_read_paused((void *)stream, 0) == XQC_OK);
    wt_block = 0;
    CU_ASSERT(xqc_wt_stream_notify_read(stream, (void *)"x", 1, 1) == 1);
    CU_ASSERT(stream->recv_fin);
    CU_ASSERT(xqc_wt_bidistream_send((void *)stream, NULL, 1, 0)
              == -XQC_EPARAM);
    session->closed = XQC_TRUE;
    CU_ASSERT(xqc_wt_bidistream_send((void *)stream, "x", 1, 0)
              == -XQC_ESTATE);
    xqc_wt_conn_destroy(session->wt_conn);
}

void
xqc_test_wt_pooled_stream_credit(void)
{
    /* draft-ietf-webtrans-http3-16 §§5.3-5.4: stream and byte credit. */
    xqc_wt_ctx_t ctx;
    xqc_memzero(&ctx, sizeof(ctx));
    ctx.stream_cbs.wt_bidistream_read_notify = wt_read;
    xqc_h3_conn_t h3c = {0};
    xqc_wt_session_t *first = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(first);
    xqc_wt_conn_t *conn = first->wt_conn;
    ctx.settings.draft_version = XQC_WEBTRANSPORT_DRAFT_VERSION_16;
    ctx.settings.max_sessions_count = 2;
    ctx.settings.max_bidi_streams = 1;
    ctx.settings.max_uni_streams = 1;
    ctx.settings.init_recv_window = 2;
    conn->negotiated_version = XQC_WEBTRANSPORT_DRAFT_VERSION_16;
    conn->flow_control_enabled = XQC_TRUE;
    conn->peer_initial_max_streams_bidi = 1;
    conn->peer_initial_max_streams_uni = 1;
    conn->peer_initial_max_data = 2;
    xqc_wt_session_init_flow_control(first);
    xqc_wt_session_t *second = xqc_wt_session_init(8, conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(second);
    second->open = XQC_TRUE;

    xqc_h3_stream_t h3a = {.stream_id = 12, .h3c = &h3c};
    xqc_h3_stream_t h3b = {.stream_id = 16, .h3c = &h3c};
    xqc_wt_stream_base_t *a = xqc_wt_stream_bind(first, &h3a,
                                                 XQC_TRUE, XQC_TRUE, NULL);
    xqc_wt_stream_base_t *b = xqc_wt_stream_bind(second, &h3b,
                                                 XQC_TRUE, XQC_TRUE, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(b);
    xqc_h3_stream_t h3extra = {.stream_id = 20, .h3c = &h3c};
    CU_ASSERT_PTR_NULL(xqc_wt_stream_bind(first, &h3extra,
                                          XQC_TRUE, XQC_TRUE, NULL));
    CU_ASSERT(!first->closed && !second->closed);
    a->io = b->io = &wt_io;
    wt_sent = 0;
    wt_send_limit = sizeof(wt_output);
    CU_ASSERT(xqc_wt_bidistream_send((void *)a, "abc", 3, 0) == 2);
    CU_ASSERT(first->sent_data == 2 && second->sent_data == 0);
    CU_ASSERT(xqc_wt_bidistream_send((void *)a, "c", 1, 0)
              == -XQC_EAGAIN);
    CU_ASSERT(xqc_wt_bidistream_send((void *)b, "xy", 2, 0) == 2);
    CU_ASSERT(second->sent_data == 2);
    CU_ASSERT(first->sent_streams[1] == 1 && second->sent_streams[1] == 1);
    wt_block = 0;
    CU_ASSERT(xqc_wt_stream_notify_read(a, (void *)"abc", 3, 0) == 3);
    CU_ASSERT(first->closed);
    CU_ASSERT(first->close_error == XQC_WT_FLOW_CONTROL_ERROR);
    CU_ASSERT(!second->closed && second->send_data_limit == 2);
    xqc_wt_conn_destroy(conn);
}

void
xqc_test_wt_capsules(void)
{
    xqc_wt_ctx_t ctx;
    xqc_memzero(&ctx, sizeof(ctx));
    xqc_h3_conn_t h3c = {0};
    xqc_wt_session_t *session = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    /* draft-ietf-webtrans-http3-16 Section 6: split CLOSE header/body. */
    unsigned char capsule[] = {0x68, 0x43, 6, 0, 0, 0, 7, 'o', 'k'};
    for (size_t i = 0; i < sizeof(capsule); i++) {
        CU_ASSERT(xqc_wt_session_recv_capsules(
            session, capsule + i, 1, i == sizeof(capsule) - 1) == XQC_OK);
    }
    CU_ASSERT(session->closed);
    CU_ASSERT(xqc_wt_session_get_close_error_code(session) == 7);
    CU_ASSERT_STRING_EQUAL(xqc_wt_session_get_close_reason(session), "ok");
    xqc_wt_conn_t *conn = session->wt_conn;
    xqc_wt_session_destroy(session);
    CU_ASSERT_PTR_NULL(xqc_wt_conn_find_session(conn, 4));
    CU_ASSERT_PTR_NULL(conn->wt_session);
    xqc_wt_conn_destroy(conn);
}

void
xqc_test_wt_capsule_errors(void)
{
    xqc_wt_ctx_t ctx;
    xqc_memzero(&ctx, sizeof(ctx));
    xqc_h3_conn_t h3c = {0};
    xqc_wt_session_t *session = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    unsigned char short_close[] = {0x68, 0x43, 3};
    CU_ASSERT(xqc_wt_session_recv_capsules(
        session, short_close, sizeof(short_close), 0) == -XQC_H3_DECODE_ERROR);
    xqc_wt_conn_destroy(session->wt_conn);
    session = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    unsigned char truncated[] = {0x68};
    CU_ASSERT(xqc_wt_session_recv_capsules(session, truncated, 1, 1)
              == -XQC_H3_DECODE_ERROR);
    CU_ASSERT(xqc_wt_session_close_with_error(session, 0, "x", 1025)
              == -XQC_EPARAM);
    xqc_wt_conn_destroy(session->wt_conn);
}

void
xqc_test_wt_capsule_header_bounds(void)
{
    /* RFC 9297 Section 3.2: two varints, each at most eight bytes. */
    xqc_wt_ctx_t ctx;
    xqc_memzero(&ctx, sizeof(ctx));
    xqc_h3_conn_t h3c = {0};
    xqc_wt_session_t *session = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    unsigned char header[XQC_WT_CAPSULE_HEADER_MAX] = {0xc0};
    header[XQC_WT_VARINT_MAX_LEN] = 0xc0;
    /* Unknown type zero with length zero, both encoded in eight bytes. */
    for (unsigned repeat = 0; repeat < 2; repeat++) {
        for (size_t i = 0; i < sizeof(header); i++) {
            CU_ASSERT(xqc_wt_session_recv_capsules(session, header + i, 1, 0)
                      == XQC_OK);
            CU_ASSERT(session->recv_header_len < sizeof(header));
        }
        CU_ASSERT(session->recv_header_len == 0);
    }
    /* A maximal header with invalid DRAIN length fails without appending. */
    header[6] = 0x78;
    header[7] = 0xae;
    header[sizeof(header) - 1] = 1;
    CU_ASSERT(xqc_wt_session_recv_capsules(session, header, sizeof(header), 0)
              == -XQC_H3_DECODE_ERROR);
    CU_ASSERT(session->recv_header_len == sizeof(header));
    xqc_wt_conn_destroy(session->wt_conn);
}

void
xqc_test_wt_datagram_association(void)
{
    xqc_wt_ctx_t ctx;
    xqc_memzero(&ctx, sizeof(ctx));
    ctx.dgram_cbs.dgram_read_notify = wt_dgram;
    ctx.pending_window = 8;
    ctx.pending_count_max = 1;
    ctx.pending_bytes_max = 8;
    xqc_connection_t transport;
    xqc_memzero(&transport, sizeof(transport));
    xqc_log_t log = {0};
    xqc_h3_conn_t h3c = {.conn = &transport, .log = &log};
    xqc_wt_session_t *session = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    transport.proto_data = &h3c;
    xqc_datagram_callbacks_t cbs = {0};
    xqc_wt_dgram_callbacks(&cbs);
    wt_reads = 0;
    /* RFC 9297 Section 2.1: Quarter Stream ID 1 identifies session 4. */
    cbs.datagram_read_notify(&transport, NULL, "\x01x", 2, 1);
    CU_ASSERT(wt_reads == 1);
    CU_ASSERT_PTR_EQUAL(wt_last_session, session);
    cbs.datagram_read_notify(&transport, NULL, "\x02x", 2, 1);
    cbs.datagram_read_notify(&transport, NULL, "\x03x", 2, 1);
    CU_ASSERT(wt_reads == 1);
    CU_ASSERT(session->wt_conn->pending_count == 1);
    xqc_wt_session_t *second = xqc_wt_session_init(8, session->wt_conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(second);
    second->open = XQC_TRUE;
    xqc_wt_dgram_resume(second);
    CU_ASSERT(wt_reads == 2);
    CU_ASSERT_PTR_EQUAL(wt_last_session, second);
    CU_ASSERT(session->wt_conn->pending_count == 0);
    cbs.datagram_read_notify(&transport, NULL, "\xff", 1, 1);
    CU_ASSERT(wt_reads == 2);
    second->open = XQC_FALSE;
    ctx.pending_count_max = 256;
    ctx.pending_bytes_max = 256 * 1200;
    for (size_t i = 0; i < 256; i++) {
        cbs.datagram_read_notify(&transport, NULL, "\x02x", 2, 1);
    }
    CU_ASSERT(session->wt_conn->pending_count == 256);
    CU_ASSERT(session->wt_conn->pending_bytes == 256);
    cbs.datagram_read_notify(&transport, NULL, "\x02x", 2, 1);
    CU_ASSERT(session->wt_conn->pending_count == 256);
    CU_ASSERT(session->wt_conn->pending_bytes == 256);
    CU_ASSERT(wt_reads == 2);
    second->open = XQC_TRUE;
    xqc_wt_dgram_resume(second);
    CU_ASSERT(wt_reads == 258);
    CU_ASSERT(!session->wt_conn->pending_count);
    CU_ASSERT(!session->wt_conn->pending_bytes);
    xqc_wt_conn_destroy(session->wt_conn);
}

void
xqc_test_wt_datagram_send_errors(void)
{
    xqc_wt_ctx_t ctx;
    xqc_memzero(&ctx, sizeof(ctx));
    xqc_connection_t transport;
    xqc_memzero(&transport, sizeof(transport));
    xqc_h3_conn_t h3c = {.conn = &transport};
    xqc_wt_session_t *session = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);

    CU_ASSERT(xqc_wt_session_datagram_send(NULL, "x", 1, NULL)
              == -XQC_EPARAM);
    CU_ASSERT(xqc_wt_session_datagram_send(session, NULL, 1, NULL)
              == -XQC_EPARAM);
    /* RFC 9297 Section 2.1: the session ID consumes datagram space. */
    transport.dgram_mss = 1;
    CU_ASSERT(xqc_wt_session_datagram_send(session, "x", 1, NULL)
              == -XQC_EDGRAM_TOO_LARGE);
    transport.dgram_mss = 1200;
    session->wt_conn->sent_count = 1024;
    CU_ASSERT(xqc_wt_session_datagram_send(session, "x", 1, NULL)
              == -XQC_EAGAIN);
    session->wt_conn->sent_count = 0;
    session->closed = XQC_TRUE;
    CU_ASSERT(xqc_wt_session_datagram_send(session, "x", 1, NULL)
              == -XQC_ESTATE);
    xqc_wt_conn_destroy(session->wt_conn);
}

void
xqc_test_wt_extension_settings(void)
{
    xqc_list_head_t buffers;
    xqc_init_list_head(&buffers);
    xqc_h3_conn_t h3c = {0};
    /* draft-ietf-webtrans-http3-16 Sections 3.1 and 9.2. */
    const unsigned char expected[] = {
        0x04, 0x0f, 0x06, 0x00, 0x01, 0x00, 0x07, 0x00,
        0x08, 0x01, 0x33, 0x01,
        0xac, 0x7c, 0xf0, 0x00, 0x01,
    };
    CU_ASSERT(xqc_h3_conn_settings_add_extern(&h3c.local_h3_conn_settings,
                                              0x08, 1) == XQC_OK);
    CU_ASSERT(xqc_h3_conn_settings_add_extern(&h3c.local_h3_conn_settings,
                                              0x33, 1) == XQC_OK);
    CU_ASSERT(xqc_h3_conn_settings_add_extern(&h3c.local_h3_conn_settings,
                                              0x2c7cf000, 1) == XQC_OK);
    CU_ASSERT_FATAL(xqc_h3_frm_write_settings(
        &buffers, &h3c.local_h3_conn_settings, 0) == XQC_OK);
    CU_ASSERT_FALSE_FATAL(xqc_list_empty(&buffers));
    xqc_list_buf_t *encoded = xqc_list_entry(buffers.next,
                                             xqc_list_buf_t, list_head);
    CU_ASSERT_EQUAL_FATAL(encoded->buf->data_len, sizeof(expected));
    CU_ASSERT(memcmp(encoded->buf->data, expected, sizeof(expected)) == 0);
    while (!xqc_list_empty(&buffers)) {
        xqc_list_buf_t *item = xqc_list_entry(buffers.next,
                                              xqc_list_buf_t, list_head);
        xqc_list_del(&item->list_head);
        xqc_var_buf_free(item->buf);
        xqc_free(item);
    }
    CU_ASSERT(xqc_h3_conn_settings_add_extern(&h3c.local_h3_conn_settings,
                                              1, 1) == -XQC_EPARAM);
    CU_ASSERT(h3c.local_h3_conn_settings.extern_settings_count == 3);
    CU_ASSERT(xqc_list_empty(&buffers));
}

static int wt_session_creates, wt_session_closes;
static int wt_app_creates, wt_app_reads, wt_app_writes;
static int wt_app_create_fail;
static int wt_app_closings, wt_app_closes, wt_request_marker;
static int wt_app_handshakes, wt_handshakes;
static int wt_app_conn_creates, wt_app_conn_closes, wt_app_conn_fail;
static int wt_conn_marker;
static void *wt_app_conn_context;

static int wt_app_conn_create(xqc_h3_conn_t *conn, const xqc_cid_t *cid,
    void *ctx);
static int wt_app_conn_close(xqc_h3_conn_t *conn, const xqc_cid_t *cid,
    void *ctx);

static void
wt_app_init_settings(xqc_h3_conn_t *conn,
    xqc_h3_conn_settings_t *settings, void *data)
{
    if (wt_app_conn_fail == 2) {
        for (size_t i = 0; i < XQC_H3_MAX_EXTERN_SETTINGS - 2; i++) {
            CU_ASSERT(xqc_h3_conn_settings_add_extern(settings,
                                                      0x100 + i, 1) == XQC_OK);
        }
    }
}

static int
wt_app_conn_create(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *ctx)
{
    wt_app_conn_creates++;
    CU_ASSERT_PTR_EQUAL(ctx, wt_app_conn_context);
    CU_ASSERT_PTR_EQUAL(xqc_h3_conn_get_user_data(conn), wt_app_conn_context);
    if (wt_app_conn_fail == 1) {
        return -XQC_EPARAM;
    }
    wt_app_conn_context = &wt_conn_marker;
    xqc_h3_conn_set_user_data(conn, wt_app_conn_context);
    return XQC_OK;
}

static int
wt_app_conn_close(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *ctx)
{
    wt_app_conn_closes++;
    CU_ASSERT_PTR_EQUAL(ctx, wt_app_conn_context);
    CU_ASSERT_PTR_EQUAL(xqc_h3_conn_get_user_data(conn), wt_app_conn_context);
    return XQC_OK;
}

static void
wt_app_handshake(xqc_h3_conn_t *conn, void *ctx)
{
    wt_app_handshakes++;
    CU_ASSERT_PTR_EQUAL(ctx, wt_app_conn_context);
}

static void
wt_handshake(xqc_h3_conn_t *conn, void *ctx)
{
    wt_handshakes++;
    CU_ASSERT_PTR_EQUAL(ctx, wt_app_conn_context);
}

static int
wt_app_create(xqc_h3_request_t *request, void *ctx)
{
    wt_app_creates++;
    CU_ASSERT_PTR_EQUAL(xqc_h3_get_conn_user_data_by_request(request),
                        wt_app_conn_context);
    xqc_h3_request_set_user_data(request, &wt_request_marker);
    return wt_app_create_fail ? -XQC_ESTATE : XQC_OK;
}

static int
wt_app_read(xqc_h3_request_t *request, xqc_request_notify_flag_t flags,
    void *ctx)
{
    unsigned char fin = 0;
    wt_app_reads++;
    CU_ASSERT_PTR_EQUAL(ctx, &wt_request_marker);
    CU_ASSERT_PTR_NOT_NULL(xqc_h3_request_recv_headers(request, &fin));
    return XQC_OK;
}

static int
wt_app_write(xqc_h3_request_t *request, void *ctx)
{
    wt_app_writes++;
    CU_ASSERT_PTR_EQUAL(ctx, &wt_request_marker);
    return XQC_OK;
}

static void
wt_app_closing(xqc_h3_request_t *request, xqc_int_t error, void *ctx)
{
    wt_app_closings++;
    CU_ASSERT_PTR_EQUAL(ctx, &wt_request_marker);
}

static int
wt_app_close(xqc_h3_request_t *request, void *ctx)
{
    wt_app_closes++;
    CU_ASSERT_PTR_EQUAL(ctx, &wt_request_marker);
    return XQC_OK;
}

static int
wt_accept(xqc_http_headers_t *headers, xqc_http_headers_t *response, void *data)
{
    CU_ASSERT_PTR_EQUAL(data, wt_app_conn_context);
    xqc_http_header_t *origin = &headers->headers[5];
    return origin->value.iov_len == 7
        && memcmp(origin->value.iov_base, "allowed", 7) == 0;
}

static int
wt_session_created(xqc_wt_session_t *session, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *ctx)
{
    wt_session_creates++;
    return XQC_OK;
}

static int
wt_session_closed(xqc_wt_session_t *session, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *ctx)
{
    CU_ASSERT_PTR_NULL(headers);
    wt_session_closes++;
    return XQC_OK;
}

static void
wt_test_connect_request(int scenario)
{
    xqc_bool_t accepted = scenario == 1 || scenario == 9 || scenario >= 12;
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    xqc_engine_t *engine = conn->engine;
    xqc_h3_callbacks_t app = {
        .h3c_cbs = {
            .h3_conn_create_notify = wt_app_conn_create,
            .h3_conn_close_notify = wt_app_conn_close,
            .h3_conn_init_settings = wt_app_init_settings,
            .h3_conn_handshake_finished = wt_app_handshake,
        },
        .h3r_cbs = {
            .h3_request_create_notify = wt_app_create,
            .h3_request_read_notify = wt_app_read,
            .h3_request_write_notify = wt_app_write,
            .h3_request_closing_notify = wt_app_closing,
            .h3_request_close_notify = wt_app_close,
        },
    };
    if (scenario == 6) {
        app.h3c_cbs.h3_conn_create_notify = NULL;
    }
    CU_ASSERT(xqc_h3_ctx_init(engine, &app) == XQC_OK);
    xqc_webtransport_session_callbacks_t cbs = {
        .webtransport_will_create_session_notify = wt_accept,
        .webtransport_session_create_notify = wt_session_created,
        .webtransport_session_close_notify = wt_session_closed,
        .webtransport_conn_handshake_finished_notify = wt_handshake,
    };
    CU_ASSERT(xqc_wt_ctx_init(engine, NULL, &cbs, NULL) == XQC_OK);
    xqc_webtransport_conn_settings_t settings =
        xqc_wt_ctx_get(engine)->settings;
    settings.draft_version = XQC_WEBTRANSPORT_DRAFT_VERSION_16;
    settings.max_sessions_count = 16;
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, &settings) == XQC_OK);
    xqc_free(conn->alpn);
    conn->alpn = xqc_malloc(3);
    memcpy(conn->alpn, "h3", 3);
    conn->alpn_len = 2;
    CU_ASSERT(xqc_engine_get_alpn_callbacks(engine, "h3", 2,
                                            &conn->app_proto_cbs) == XQC_OK);
    conn->conn_type = XQC_CONN_TYPE_SERVER;
    int marker;
    wt_app_conn_context = &marker;
    wt_app_creates = wt_app_reads = wt_app_writes = 0;
    wt_app_create_fail = scenario == 8;
    wt_app_closings = wt_app_closes = 0;
    wt_app_handshakes = wt_handshakes = 0;
    wt_app_conn_creates = wt_app_conn_closes = 0;
    wt_app_conn_fail = scenario == 7 ? 2 : scenario == 5;
    xqc_h3_conn_t *h3c = xqc_h3_conn_create(conn, &marker);
    CU_ASSERT(wt_app_conn_creates == (scenario == 6 ? 0 : 1));
    if (scenario == 5) {
        CU_ASSERT_PTR_NULL(h3c);
        CU_ASSERT(wt_app_conn_closes == 0);
        xqc_engine_destroy(engine);
        CU_ASSERT(wt_app_conn_closes == 0);
        return;
    }
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c);
    if (scenario == 7) {
        CU_ASSERT_PTR_NULL(xqc_wt_get_conn_from_h3(h3c));
        CU_ASSERT(h3c->local_h3_conn_settings.extern_settings_count
                  == XQC_H3_MAX_EXTERN_SETTINGS - 2);
        CU_ASSERT(h3c->h3_conn_callbacks.h3_conn_create_notify
                  == wt_app_conn_create);
        CU_ASSERT(conn->conn_err == 0);
        conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST;
        xqc_engine_destroy(engine);
        CU_ASSERT(wt_app_conn_closes == 1);
        return;
    }
    xqc_wt_conn_t *wt_conn = xqc_wt_get_conn_from_h3(h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(wt_conn);
    CU_ASSERT(h3c->local_h3_conn_settings.extern_settings_count == 7);
    if (scenario == 6) {
        xqc_wt_session_t *session = xqc_wt_session_init(4, wt_conn, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(session);
        session->open = XQC_TRUE;
        wt_session_closes = 0;
        conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST
            | XQC_CONN_FLAG_TLS_HSK_COMPLETED;
        conn->local_settings.reset_stream_at = XQC_TRUE;
        conn->remote_settings.reset_stream_at = XQC_TRUE;
        xqc_engine_destroy(engine);
        CU_ASSERT(wt_session_closes == 1);
        CU_ASSERT(wt_app_conn_closes == 0);
        return;
    }
    xqc_wt_ctx_t *engine_ctx = xqc_wt_ctx_get(engine);
    CU_ASSERT_PTR_NOT_EQUAL(wt_conn->ctx, engine_ctx);
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, NULL) == -XQC_ESTATE);
    conn->conn_flow_ctl.fc_max_streams_uni_can_send = 16;
    h3c->qenc_stream = xqc_h3_conn_create_uni_stream(
        h3c, XQC_H3_STREAM_TYPE_QPACK_ENCODER);
    h3c->qdec_stream = xqc_h3_conn_create_uni_stream(
        h3c, XQC_H3_STREAM_TYPE_QPACK_DECODER);
    h3c->control_stream_out = xqc_h3_conn_create_uni_stream(
        h3c, XQC_H3_STREAM_TYPE_CONTROL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c->qenc_stream);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c->qdec_stream);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3c->control_stream_out);
    conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST
        | XQC_CONN_FLAG_TLS_HSK_COMPLETED;
    conn->local_settings.reset_stream_at = XQC_TRUE;
    conn->remote_settings.reset_stream_at = XQC_TRUE;
    conn->local_settings.max_datagram_frame_size = 1200;
    conn->remote_settings.max_datagram_frame_size = 1200;
    engine->config->manually_triggered_send = 1;
    xqc_stream_t *stream = xqc_create_stream_with_conn(
        conn, XQC_UNDEFINE_STREAM_ID, XQC_CLI_BID, NULL, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    xqc_h3_stream_t *h3s = xqc_h3_stream_create(
        h3c, stream, XQC_H3_STREAM_TYPE_REQUEST, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3s);
    xqc_h3_request_t *request = xqc_h3_request_create_inner(h3c, h3s, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(request);
    h3s->h3r = request;
    CU_ASSERT(wt_app_creates == 0);
    if (scenario == 3) {
        xqc_h3_request_closing(request, -XQC_EPARAM);
        xqc_engine_destroy(engine);
        CU_ASSERT(wt_app_creates == 0 && wt_app_closes == 0);
        CU_ASSERT(wt_app_closings == 0);
        CU_ASSERT(wt_app_conn_closes == 1);
        return;
    }
    if (scenario == 4) {
        wt_conn->ctx->settings.max_sessions_count = 1;
        xqc_wt_session_t *first = xqc_wt_session_init(4, wt_conn, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(first);
        first->open = XQC_TRUE;
    }
    const char *names[] = {":method", ":protocol", ":scheme", ":authority",
                           ":path", "origin"};
    const char *values[] = {"CONNECT", "webtransport-h3", "https", "localhost",
                            "/wt", accepted ? "allowed" : "denied"};
    if (scenario == 2 || scenario == 8) {
        values[0] = "GET";
        names[1] = ":scheme";
        values[1] = "https";
        names[2] = ":authority";
        values[2] = "localhost";
        names[3] = ":path";
        values[3] = "/";
        names[4] = "user-agent";
        values[4] = "test";
    }
    if (scenario >= 9 && scenario <= 11) {
        const char *paths[] = {"/wt?x=1", "foo", "*"};
        values[4] = paths[scenario - 9];
        values[5] = "allowed";
    }
    xqc_http_headers_t *headers = &request->h3_header[0];
    headers->headers = xqc_calloc(6, sizeof(xqc_http_header_t));
    headers->capacity = headers->count = 6;
    for (size_t i = 0; i < 6; i++) {
        xqc_http_header_t *header = &headers->headers[i];
        header->name.iov_len = strlen(names[i]);
        header->value.iov_len = strlen(values[i]);
        header->name.iov_base = xqc_malloc(header->name.iov_len);
        header->value.iov_base = xqc_malloc(header->value.iov_len);
        memcpy(header->name.iov_base, names[i], header->name.iov_len);
        memcpy(header->value.iov_base, values[i], header->value.iov_len);
        headers->total_len += header->name.iov_len + header->value.iov_len;
    }
    wt_session_creates = wt_session_closes = 0;
    /* draft-ietf-webtrans-http3-16 Section 3.1: wait for peer SETTINGS. */
    if (scenario == 8) {
        CU_ASSERT(xqc_h3_request_on_recv_header(request) != XQC_OK);
        CU_ASSERT(wt_app_creates == 1 && wt_app_reads == 0);
        CU_ASSERT(wt_conn->session_count == 0);
        xqc_engine_destroy(engine);
        CU_ASSERT(wt_app_closes == 1);
        return;
    }
    CU_ASSERT_FATAL(xqc_h3_request_on_recv_header(request) == XQC_OK);
    if (scenario == 2) {
        CU_ASSERT(wt_app_creates == 1 && wt_app_reads == 1);
        CU_ASSERT(wt_conn->session_count == 0);
        CU_ASSERT(request->request_if->h3_request_write_notify(
            request, request->user_data) == XQC_OK);
        xqc_h3_request_closing(request, -XQC_EPARAM);
        /* QPACK-blocked H3 requests can outlive the WT connection state. */
        xqc_wt_conn_destroy(wt_conn);
        CU_ASSERT_PTR_NULL(xqc_wt_get_conn_from_h3(h3c));
        CU_ASSERT(h3c->local_h3_conn_settings.extern_settings_count == 7);
        CU_ASSERT_PTR_NULL(h3c->extension_data);
        xqc_engine_destroy(engine);
        CU_ASSERT(wt_app_writes == 1 && wt_app_closings == 1);
        CU_ASSERT(wt_app_closes == 1);
        CU_ASSERT(wt_app_conn_closes == 1);
        return;
    }
    CU_ASSERT(wt_app_creates == 0 && wt_app_reads == 0);
    CU_ASSERT(wt_session_creates == 0);
    xqc_h3_setting_t peer[] = {{0x2c7cf000, 1}, {0x33, 1}};
    CU_ASSERT(xqc_wt_conn_peer_settings(h3c, peer, 2, h3c->user_data)
              == XQC_H3_SETTINGS_ACCEPT);
    if (scenario == 4) {
        CU_ASSERT(h3s->stream->stream_err == H3_REQUEST_REJECTED);
        CU_ASSERT(wt_session_creates == 0 && wt_app_creates == 0);
        xqc_engine_destroy(engine);
        CU_ASSERT(wt_app_conn_closes == 1);
        return;
    }
    CU_ASSERT(wt_session_creates == (accepted ? 1 : 0));
    xqc_wt_session_t *session = xqc_wt_conn_find_session(wt_conn,
                                                         h3s->stream_id);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    CU_ASSERT(session->closed == !accepted);
    if (scenario == 10 || scenario == 11) {
        /* RFC 9114 Section 4.3.1: '*' is only valid for OPTIONS. */
        CU_ASSERT(h3s->stream->stream_err == H3_MESSAGE_ERROR);
    }
    if (scenario >= 12) {
        uint32_t expected = scenario == 15 ? H3_REQUEST_CANCELLED
            : scenario == 12 ? 0 : 7;
        if (scenario == 14) {
            unsigned char close[] = {0x68, 0x43, 4, 0, 0, 0, 7};
            CU_ASSERT(xqc_wt_session_recv_capsules(
                session, close, sizeof(close), 0) == XQC_OK);
        } else if (scenario != 15) {
            CU_ASSERT(xqc_wt_session_close_with_error(
                session, expected, NULL, 0) == XQC_OK);
        }
        xqc_h3_request_closing(request, H3_REQUEST_CANCELLED);
        CU_ASSERT(xqc_wt_session_get_close_error_code(session) == expected);
    }
    /* Connection snapshots survive ALPN context release by the engine. */
    memset(&engine_ctx->session_cbs, 0, sizeof(engine_ctx->session_cbs));
    memset(&engine_ctx->app_conn_callbacks, 0,
           sizeof(engine_ctx->app_conn_callbacks));
    conn->app_proto_cbs.conn_cbs.conn_handshake_finished(conn, NULL, h3c);
    CU_ASSERT(wt_app_handshakes == 1 && wt_handshakes == 1);
    xqc_engine_destroy(engine);
    CU_ASSERT(wt_session_closes == (accepted ? 1 : 0));
    CU_ASSERT(wt_app_closes == 0);
    CU_ASSERT(wt_app_conn_closes == 1);
}

void
xqc_test_wt_connect_accept(void)
{
    wt_test_connect_request(XQC_TRUE);
    wt_test_connect_request(9);
}

void
xqc_test_wt_connect_reject(void)
{
    wt_test_connect_request(XQC_FALSE);
    wt_test_connect_request(10);
    wt_test_connect_request(11);
    wt_test_connect_request(5);
    wt_test_connect_request(6);
    wt_test_connect_request(7);
}

void
xqc_test_wt_close_error_retained(void)
{
    /* Draft-16 Section 6: retain the application code through final close. */
    for (int scenario = 12; scenario <= 15; scenario++) {
        wt_test_connect_request(scenario);
    }
}

void
xqc_test_wt_request_passthrough(void)
{
    wt_test_connect_request(2);
    wt_test_connect_request(8);
}

void
xqc_test_wt_session_id_wire(void)
{
    /* RFC 9000 Section 16: variable integers are limited to 62 bits. */
    uint64_t values[] = {0, 63, 64, 16383, 16384,
        (UINT64_C(1) << 30) - 1, UINT64_C(1) << 30,
        (UINT64_C(1) << 62) - 1};
    unsigned char wire[8];
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        uint64_t decoded = UINT64_MAX;
        size_t len = xqc_wt_put_varint(values[i], wire, sizeof(wire));
        CU_ASSERT_FATAL(len > 0);
        CU_ASSERT(xqc_wt_get_varint(wire, len, &decoded) == len);
        CU_ASSERT(decoded == values[i]);
        CU_ASSERT(xqc_wt_put_varint(values[i], wire, len - 1) == 0);
        CU_ASSERT(xqc_wt_get_varint(wire, len - 1, &decoded) < 0);
    }
    CU_ASSERT(xqc_wt_put_varint(UINT64_C(1) << 62, wire, 8) == 0);
    CU_ASSERT(xqc_wt_put_varint(0, NULL, 8) == 0);
    CU_ASSERT(xqc_wt_get_varint(wire, 1, NULL) == -XQC_EPARAM);
}

void
xqc_test_wt_request_incomplete(void)
{
    wt_test_connect_request(3);
}

void
xqc_test_wt_session_limit(void)
{
    wt_test_connect_request(4);
}

static size_t wt_error_logs;

static void wt_error_log(xqc_log_level_t level, const void *buf,
    size_t size, void *data);

static void
wt_error_log(xqc_log_level_t level, const void *buf, size_t size, void *data)
{
    CU_ASSERT(level == XQC_LOG_ERROR);
    wt_error_logs++;
}

void
xqc_test_wt_settings_capacity(void)
{
    /* Draft-16 Sections 3.1, 5.5: advertise all required settings or none. */
    const uint64_t ids[] = {
        XQC_WT_SETTING_DATAGRAM, XQC_WT_SETTING_MAX_SESSIONS,
        XQC_WT_SETTING_CONNECT, XQC_WT_SETTING_ENABLED_16,
        XQC_WT_SETTING_INITIAL_MAX_STREAMS_UNI,
        XQC_WT_SETTING_INITIAL_MAX_STREAMS_BIDI,
        XQC_WT_SETTING_INITIAL_MAX_DATA,
    };
    for (unsigned client = 0; client < 2; client++) {
        for (unsigned pooled = 0; pooled < 2; pooled++) {
            for (unsigned mode = 0; mode < 4; mode++) {
                xqc_engine_t *engine = test_create_engine();
                CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
                CU_ASSERT(xqc_wt_ctx_init(engine, NULL, NULL, NULL) == XQC_OK);
                xqc_wt_ctx_t *ctx = xqc_wt_ctx_get(engine);
                ctx->settings.max_sessions_count = pooled ? 2 : 1;
                xqc_h3_ctx_t *h3 = xqc_engine_get_alpn_ctx(engine, "h3", 2);
                xqc_connection_t transport;
                xqc_memzero(&transport, sizeof(transport));
                transport.engine = engine;
                transport.conn_type = client ? XQC_CONN_TYPE_CLIENT
                    : XQC_CONN_TYPE_SERVER;
                xqc_log_callbacks_t callbacks = {
                    .xqc_log_write_err = wt_error_log,
                };
                xqc_log_t log = {
                    .log_level = XQC_LOG_ERROR, .log_callbacks = &callbacks,
                };
                xqc_h3_conn_t conn = {.conn = &transport, .log = &log};
                conn.h3_conn_callbacks = h3->h3_cbs.h3c_cbs;
                xqc_h3_conn_settings_t settings =
                    default_local_h3_conn_settings;
                size_t count = (pooled ? 7 : 4) - client;
                if (mode == 2) {
                    for (size_t i = 0; i < (pooled ? 7 : 4); i++) {
                        if (client && ids[i] == XQC_WT_SETTING_CONNECT) {
                            continue;
                        }
                        CU_ASSERT(xqc_h3_conn_settings_add_extern(
                            &settings, ids[i], 0) == XQC_OK);
                    }
                }
                if (mode == 3) {
                    CU_ASSERT(xqc_h3_conn_settings_add_extern(
                        &settings,
                        XQC_WT_SETTING_ENABLED_16, 1) == XQC_OK);
                }
                size_t fill = mode >= 2 ? XQC_H3_MAX_EXTERN_SETTINGS
                    : XQC_H3_MAX_EXTERN_SETTINGS - count + mode;
                while (settings.extern_settings_count < fill) {
                    uint64_t id = 0x100 + settings.extern_settings_count;
                    CU_ASSERT(xqc_h3_conn_settings_add_extern(
                        &settings, id, 7) == XQC_OK);
                }
                xqc_h3_conn_settings_t before = settings;
                wt_error_logs = 0;
                conn.h3_conn_callbacks.h3_conn_init_settings(
                    &conn, &settings, NULL);
                CU_ASSERT(xqc_h3_conn_settings_validate(&settings, NULL)
                          == XQC_OK);
                if (mode == 1 || mode == 3) {
                    if (mode == 3) {
                        before.extern_settings[0].value = 0;
                    }
                    CU_ASSERT(memcmp(&before, &settings, sizeof(settings))
                              == 0);
                    CU_ASSERT(wt_error_logs == 1 && ctx->started);
                    CU_ASSERT(conn.h3_conn_callbacks.h3_conn_create_notify
                              == ctx->app_conn_callbacks.h3_conn_create_notify);
                    xqc_stream_callbacks_t *stream_callbacks =
                        &transport.app_proto_cbs.stream_cbs;
                    CU_ASSERT(stream_callbacks->stream_read_notify
                              == h3_stream_callbacks.stream_read_notify);
                } else {
                    CU_ASSERT(settings.extern_settings_count
                              == XQC_H3_MAX_EXTERN_SETTINGS);
                    CU_ASSERT(wt_error_logs == 0);
                    for (size_t i = 0; i < settings.extern_settings_count; i++)
                    {
                        xqc_h3_setting_t *entry = &settings.extern_settings[i];
                        if (entry->identifier == XQC_WT_SETTING_ENABLED_16
                            || entry->identifier == XQC_WT_SETTING_MAX_SESSIONS)
                        {
                            CU_ASSERT(entry->value == (entry->identifier
                                == XQC_WT_SETTING_MAX_SESSIONS
                                ? pooled + 1 : 1));
                        } else if (entry->identifier >= 0x100
                                   && entry->identifier < 0x110)
                        {
                            CU_ASSERT(entry->value == 7);
                        }
                    }
                }
                xqc_h3_ctx_destroy(engine);
                xqc_engine_destroy(engine);
            }
        }
    }
}

static unsigned wt_drop_normal, wt_drop_limit;
static unsigned wt_track_acks, wt_track_losses;
static int wt_track_retransmit;

static void wt_drop_log(xqc_log_level_t level, const void *buf,
    size_t size, void *data);
static void wt_dgram_destroy_on_read(xqc_wt_session_t *session,
    const void *data, size_t len, void *ctx, uint64_t time);
static void wt_track_ack(xqc_wt_session_t *session, uint64_t id, void *ctx);
static int wt_track_loss(xqc_wt_session_t *session, uint64_t id, void *ctx);

static void
wt_drop_log(xqc_log_level_t level, const void *buf, size_t size, void *data)
{
    wt_drop_normal += level == XQC_LOG_DEBUG;
    wt_drop_limit += level == XQC_LOG_WARN;
}

static void
wt_dgram_destroy_on_read(xqc_wt_session_t *session,
    const void *data, size_t len, void *ctx, uint64_t time)
{
    wt_dgram(session, data, len, ctx, time);
    xqc_wt_session_destroy(session);
}

void
xqc_test_wt_datagram_retirement(void)
{
    /* Draft-16 Sections 4.5 and 6: closed sessions retain no early data. */
    xqc_wt_ctx_t ctx;
    xqc_memzero(&ctx, sizeof(ctx));
    ctx.dgram_cbs.dgram_read_notify = wt_dgram;
    ctx.pending_window = 8;
    ctx.pending_count_max = 3;
    ctx.pending_bytes_max = 3;
    xqc_connection_t transport;
    xqc_memzero(&transport, sizeof(transport));
    xqc_log_callbacks_t logs = {.xqc_log_write_err = wt_drop_log};
    xqc_log_t log = {.log_level = XQC_LOG_DEBUG, .log_callbacks = &logs};
    xqc_h3_conn_t h3c = {.conn = &transport, .log = &log};
    xqc_wt_session_t *first = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(first);
    xqc_wt_conn_t *conn = first->wt_conn;
    transport.proto_data = &h3c;
    xqc_datagram_callbacks_t cbs = {0};
    xqc_wt_dgram_callbacks(&cbs);
    first->open = XQC_FALSE;
    wt_reads = wt_drop_normal = wt_drop_limit = 0;
    cbs.datagram_read_notify(&transport, NULL, "\x01x", 2, 1);
    cbs.datagram_read_notify(&transport, NULL, "\x01x", 2, 1);
    cbs.datagram_read_notify(&transport, NULL, "\x02x", 2, 1);
    CU_ASSERT(conn->pending_count == 3 && conn->pending_bytes == 3);
    cbs.datagram_read_notify(&transport, NULL, "\x02x", 2, 1);
    CU_ASSERT(wt_drop_limit == 1 && conn->pending_count == 3);
    xqc_wt_session_notify_closed(first);
    CU_ASSERT(conn->pending_count == 1 && conn->pending_bytes == 1);
    cbs.datagram_read_notify(&transport, NULL, "\x01x", 2, 1);
    CU_ASSERT(wt_drop_normal == 1 && wt_drop_limit == 1);
    cbs.datagram_read_notify(&transport, NULL, "\x3fx", 2, 1);
    CU_ASSERT(wt_drop_limit == 2 && conn->pending_count == 1);
    xqc_wt_session_t *second = xqc_wt_session_init(8, conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(second);
    second->open = XQC_TRUE;
    xqc_wt_dgram_resume(second);
    CU_ASSERT(wt_reads == 1 && conn->pending_count == 0);
    CU_ASSERT(conn->pending_bytes == 0);

    /* A callback can destroy its session and purge remaining queued items. */
    second->open = XQC_FALSE;
    cbs.datagram_read_notify(&transport, NULL, "\x02x", 2, 1);
    cbs.datagram_read_notify(&transport, NULL, "\x02x", 2, 1);
    cbs.datagram_read_notify(&transport, NULL, "\x03x", 2, 1);
    ctx.dgram_cbs.dgram_read_notify = wt_dgram_destroy_on_read;
    second->open = XQC_TRUE;
    xqc_wt_dgram_resume(second);
    CU_ASSERT_PTR_NULL(xqc_wt_conn_find_session(conn, 8));
    CU_ASSERT(wt_reads == 2 && conn->pending_count == 1);
    CU_ASSERT(conn->pending_bytes == 1);
    xqc_wt_session_t *third = xqc_wt_session_init(12, conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(third);
    xqc_wt_session_destroy(third);
    CU_ASSERT(conn->pending_count == 0 && conn->pending_bytes == 0);
    cbs.datagram_read_notify(&transport, NULL, "\x03x", 2, 1);
    CU_ASSERT(conn->pending_count == 0 && conn->pending_bytes == 0);
    cbs.datagram_read_notify(&transport, NULL, "\x04x", 2, 1);
    CU_ASSERT(conn->pending_count == 1);
    xqc_wt_conn_destroy(conn);

    /* ID zero is future on a new connection, stale only after retirement. */
    conn = xqc_wt_conn_create(&h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->ctx = &ctx;
    cbs.datagram_read_notify(&transport, NULL, "\x00x", 2, 1);
    CU_ASSERT(conn->pending_count == 1);
    first = xqc_wt_session_init(0, conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(first);
    xqc_wt_session_destroy(first);
    cbs.datagram_read_notify(&transport, NULL, "\x00x", 2, 1);
    CU_ASSERT(conn->pending_count == 0);
    xqc_wt_conn_destroy(conn);
}

static void
wt_track_ack(xqc_wt_session_t *session, uint64_t id, void *ctx)
{
    wt_track_acks++;
}

static int
wt_track_loss(xqc_wt_session_t *session, uint64_t id, void *ctx)
{
    wt_track_losses++;
    return wt_track_retransmit;
}

void
xqc_test_wt_datagram_tracking(void)
{
    xqc_connection_t *transport = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(transport);
    xqc_engine_t *engine = transport->engine;
    xqc_h3_conn_t h3c = {.conn = transport, .log = transport->log};
    xqc_wt_ctx_t ctx;
    xqc_memzero(&ctx, sizeof(ctx));
    ctx.dgram_cbs.dgram_acked_notify = wt_track_ack;
    ctx.dgram_cbs.dgram_lost_notify = wt_track_loss;
    xqc_wt_session_t *session = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    xqc_wt_conn_t *conn = session->wt_conn;
    transport->proto_data = &h3c;
    transport->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    transport->remote_settings.max_datagram_frame_size = 65535;
    transport->dgram_mss = 1200;
    engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
    xqc_datagram_callbacks_t cbs = {0};
    xqc_wt_dgram_callbacks(&cbs);
    wt_track_acks = wt_track_losses = 0;
    uint64_t id;
    transport->conn_flag &= ~XQC_CONN_FLAG_CAN_SEND_1RTT;
    CU_ASSERT(xqc_wt_session_datagram_send(session, "pending", 7, &id)
              == -XQC_EAGAIN);
    CU_ASSERT(conn->sent_count == 0);
    transport->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    CU_ASSERT(xqc_wt_session_datagram_send(session, "payload", 7, &id)
              == XQC_OK);
    CU_ASSERT(conn->sent_count == 1);
    cbs.datagram_acked_notify(transport, id, NULL);
    cbs.datagram_acked_notify(transport, id, NULL);
    CU_ASSERT(wt_track_acks == 1 && conn->sent_count == 0);
    CU_ASSERT(xqc_wt_session_datagram_send(session, "retry", 5, &id)
              == XQC_OK);
    wt_track_retransmit = XQC_DGRAM_RETX_ASKED_BY_APP;
    CU_ASSERT(cbs.datagram_lost_notify(transport, id, NULL)
              == XQC_DGRAM_RETX_ASKED_BY_APP);
    CU_ASSERT(wt_track_losses == 1 && conn->sent_count == 1);
    cbs.datagram_acked_notify(transport, id, NULL);
    CU_ASSERT(wt_track_acks == 2 && conn->sent_count == 0);
    CU_ASSERT(xqc_wt_session_datagram_send(session, "late", 4, &id)
              == XQC_OK);
    xqc_wt_session_destroy(session);
    cbs.datagram_acked_notify(transport, id, NULL);
    CU_ASSERT(wt_track_acks == 2 && conn->sent_count == 0);
    xqc_wt_conn_destroy(conn);
    transport->proto_data = NULL;
    engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
    xqc_engine_destroy(engine);
}

void
xqc_test_wt_stream_index(void)
{
    xqc_h3_conn_t h3c = {0};
    xqc_wt_ctx_t ctx;
    xqc_memzero(&ctx, sizeof(ctx));
    xqc_wt_session_t *session = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    xqc_wt_conn_t *conn = session->wt_conn;
    xqc_h3_stream_t streams[3];
    xqc_wt_stream_base_t *bound[3];
    xqc_memzero(streams, sizeof(streams));
    for (size_t i = 0; i < 3; i++) {
        streams[i].h3c = &h3c;
        streams[i].stream_id = 8 + i * XQC_WT_STREAM_HASH_BUCKETS;
        bound[i] = xqc_wt_stream_bind(session, &streams[i],
                                      XQC_TRUE, XQC_TRUE, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(bound[i]);
        bound[i]->send_fin = bound[i]->recv_fin = XQC_TRUE;
        CU_ASSERT_PTR_EQUAL(xqc_wt_h3_stream_get(&streams[i]), bound[i]);
    }
    /* Colliding IDs and removal must not alias another stream's adapter. */
    xqc_wt_h3_stream_close(&streams[1]);
    CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_context(&streams[1]));
    CU_ASSERT_PTR_EQUAL(xqc_wt_h3_stream_get(&streams[0]), bound[0]);
    CU_ASSERT_PTR_EQUAL(xqc_wt_h3_stream_get(&streams[2]), bound[2]);
    xqc_wt_session_destroy(session);
    CU_ASSERT(xqc_wt_h3_stream_is_raw(&streams[0]));
    CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_get(&streams[0]));
    xqc_wt_h3_stream_clear(conn);
    for (size_t i = 0; i < 3; i++) {
        CU_ASSERT_PTR_NULL(xqc_wt_h3_stream_context(&streams[i]));
    }
    xqc_wt_conn_destroy(conn);
}

void
xqc_test_wt_transport_bounds(void)
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    CU_ASSERT(xqc_wt_ctx_init(engine, NULL, NULL, NULL) == XQC_OK);
    xqc_webtransport_conn_settings_t settings =
        xqc_wt_ctx_get(engine)->settings;
    /* RFC 9000 Section 18.2: the bound also applies to single sessions. */
    settings.max_bidi_streams = settings.max_uni_streams = XQC_WT_MAX_STREAMS;
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, &settings) == XQC_OK);
    settings.max_bidi_streams++;
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, &settings)
              == -XQC_EPARAM);
    settings.max_bidi_streams--;
    settings.max_uni_streams++;
    CU_ASSERT(xqc_wt_engine_set_default_settings(engine, &settings)
              == -XQC_EPARAM);
    CU_ASSERT(xqc_wt_ctx_get(engine)->settings.max_uni_streams
              == XQC_WT_MAX_STREAMS);
    xqc_engine_destroy(engine);

    for (unsigned uni = 0; uni <= 3; uni++) {
        engine = test_create_engine();
        CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
        CU_ASSERT(xqc_wt_ctx_init(engine, NULL, NULL, NULL) == XQC_OK);
        xqc_conn_settings_t transport = {0};
        transport.proto_version = XQC_VERSION_V1;
        transport.max_streams_uni = uni;
        transport.init_recv_window = 8192;
        xqc_conn_ssl_config_t ssl = {0};
        const xqc_cid_t *cid = xqc_webtransport_connect(
            engine, &transport, NULL, 0, "", 0, &ssl, NULL, 0, NULL);
        if (uni == 1 || uni == 2) {
            CU_ASSERT_PTR_NULL(cid);
        } else {
            CU_ASSERT_PTR_NOT_NULL_FATAL(cid);
            xqc_connection_t *conn =
                xqc_engine_conns_hash_find(engine, cid, 's');
            CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
            CU_ASSERT(conn->local_settings.max_streams_uni >= 3);
            CU_ASSERT(conn->local_settings.max_streams_bidi > 0);
            CU_ASSERT(conn->conn_settings.init_recv_window == 8192);
        }
        xqc_engine_destroy(engine);
    }
}

static unsigned wt_quota_writes;
static size_t wt_notified_mss;
static void wt_quota_write(xqc_wt_session_t *session, void *data);
static void wt_quota_mss(xqc_wt_session_t *session, size_t mss, void *data);

static void
wt_quota_write(xqc_wt_session_t *session, void *data)
{
    wt_quota_writes++;
    CU_ASSERT(xqc_wt_session_datagram_send(session, "retry", 5, NULL)
              == XQC_OK);
}

static void
wt_quota_mss(xqc_wt_session_t *session, size_t mss, void *data)
{
    wt_notified_mss = mss;
}

void
xqc_test_wt_datagram_quota(void)
{
    xqc_connection_t *transport = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(transport);
    xqc_engine_t *engine = transport->engine;
    xqc_h3_conn_t h3c = {.conn = transport, .log = transport->log};
    xqc_wt_ctx_t ctx;
    xqc_memzero(&ctx, sizeof(ctx));
    ctx.dgram_cbs.dgram_write_notify = wt_quota_write;
    ctx.dgram_cbs.dgram_mss_updated_notify = wt_quota_mss;
    ctx.dgram_cbs.dgram_lost_notify = wt_track_loss;
    xqc_wt_session_t *session = wt_session(&ctx, &h3c);
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    xqc_wt_conn_t *conn = session->wt_conn;
    transport->proto_data = &h3c;
    transport->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    transport->remote_settings.max_datagram_frame_size = 65535;
    transport->dgram_mss = 1200;
    engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
    xqc_datagram_callbacks_t cbs = {0};
    xqc_wt_dgram_callbacks(&cbs);
    uint64_t ids[1024];
    wt_quota_writes = 0;
    for (size_t i = 0; i < 1024; i++) {
        CU_ASSERT_FATAL(xqc_wt_session_datagram_send(session, "x", 1, &ids[i])
                        == XQC_OK);
    }
    CU_ASSERT(conn->sent_count == 1024);
    CU_ASSERT(xqc_wt_session_datagram_send(session, "x", 1, NULL)
              == -XQC_EAGAIN);
    wt_track_retransmit = XQC_DGRAM_RETX_ASKED_BY_APP;
    CU_ASSERT(cbs.datagram_lost_notify(transport, ids[0], NULL)
              == XQC_DGRAM_RETX_ASKED_BY_APP);
    CU_ASSERT(wt_quota_writes == 0 && conn->sent_count == 1024);
    cbs.datagram_acked_notify(transport, ids[0], NULL);
    CU_ASSERT(wt_quota_writes == 1 && conn->sent_count == 1024);
    cbs.datagram_acked_notify(transport, ids[0], NULL);
    CU_ASSERT(wt_quota_writes == 1);
    CU_ASSERT(xqc_wt_session_datagram_send(session, "x", 1, NULL)
              == -XQC_EAGAIN);
    wt_track_retransmit = 0;
    CU_ASSERT(cbs.datagram_lost_notify(transport, ids[1], NULL) == 0);
    CU_ASSERT(wt_quota_writes == 2 && conn->sent_count == 1024);
    cbs.datagram_acked_notify(transport, ids[2], NULL);
    CU_ASSERT(wt_quota_writes == 2 && conn->sent_count == 1023);

    /* MSS must fit the WT prefix buffer, including after PMTU growth. */
    const size_t sizes[] = {0, 1, 1200, XQC_MAX_PACKET_OUT_SIZE + 100};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        cbs.datagram_mss_updated_notify(transport, sizes[i], NULL);
        size_t capped = xqc_min(sizes[i], XQC_MAX_PACKET_OUT_SIZE);
        CU_ASSERT(wt_notified_mss == (capped ? capped - 1 : 0));
    }
    xqc_wt_conn_destroy(conn);
    transport->proto_data = NULL;
    engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
    xqc_engine_destroy(engine);
}
