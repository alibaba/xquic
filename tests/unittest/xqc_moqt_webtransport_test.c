/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include <CUnit/CUnit.h>
#include "xqc_common_test.h"
#include "xqc_moqt_webtransport_test.h"
#include "include/moq/xqc_moqt_webtransport.h"
#include "moq/moqt/xqc_moqt_session.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_request.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_stream.h"

typedef struct {
    xqc_connection_t *conn;
    xqc_h3_conn_t h3;
    xqc_wt_ctx_t ctx;
    xqc_wt_conn_t connection;
    xqc_wt_session_t wt[2];
    xqc_moqt_session_t *session[2];
    xqc_moqt_config_t config;
    unsigned setups, ready, closed;
    uint64_t error, reset_error;
    size_t sent;
    uint8_t bytes[64];
} moqt_wt_fixture_t;

static uint64_t
moqt_wt_setup(xqc_moqt_session_t *s, const xqc_moqt_setup_t *setup, void *data)
{
    ((moqt_wt_fixture_t *)data)->setups++;
    return 0;
}

static void
moqt_wt_ready(xqc_moqt_session_t *s, void *data)
{
    ((moqt_wt_fixture_t *)data)->ready++;
}

static void
moqt_wt_closed(xqc_moqt_session_t *s, uint64_t error, void *data)
{
    moqt_wt_fixture_t *f = data;
    f->closed++;
    f->error = error;
}

static const xqc_moqt_callbacks_t moqt_wt_callbacks = {
    .on_setup = moqt_wt_setup,
    .on_ready = moqt_wt_ready,
    .on_closed = moqt_wt_closed,
};

static void
moqt_wt_init(moqt_wt_fixture_t *f)
{
    memset(f, 0, sizeof(*f));
    f->conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(f->conn);
    f->conn->engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
    f->h3.conn = f->conn;
    f->h3.user_data = f;
    f->connection.h3_conn = &f->h3;
    f->connection.ctx = &f->ctx;
    f->connection.negotiated_version = XQC_WEBTRANSPORT_DRAFT_VERSION_16;
    xqc_init_list_head(&f->connection.pending_streams);
    xqc_init_list_head(&f->connection.pending_datagrams);
    for (unsigned i = 0; i < 2; i++) {
        f->wt[i].wt_conn = &f->connection;
        f->wt[i].session_id = 4 * i;
        f->wt[i].open = XQC_TRUE;
        f->wt[i].application_protocol = (char *)"moqt-22";
        xqc_init_list_head(&f->wt[i].stream_list);
    }
    f->conn->proto_data = &f->h3;
    f->conn->dgram_data = &f->ctx;
    xqc_moqt_config_init(&f->config, XQC_MOQT_VERSION_DRAFT_22);
}

static void
moqt_wt_destroy(moqt_wt_fixture_t *f)
{
    for (unsigned i = 0; i < 2; i++) {
        xqc_moqt_session_t *s = f->session[i];
        if (!s) {
            continue;
        }
        f->wt[i].closed = XQC_TRUE;
        const xqc_wt_session_binding_t *binding = f->wt[i].binding;
        if (binding) {
            binding->closed(&f->wt[i], s);
        }
        while (s->streams) {
            xqc_wt_stream_base_t *wt = s->streams->wt_stream;
            const xqc_webtransport_stream_callbacks_t *cbs =
                &binding->stream_cbs;
            if (wt->bidi) {
                cbs->wt_bidistream_close_notify((void *)wt, &f->wt[i], NULL);
            } else {
                cbs->wt_unistream_close_notify((void *)wt, &f->wt[i], NULL);
            }
        }
        f->wt[i].binding = NULL;
        f->wt[i].binding_data = NULL;
        xqc_moqt_session_destroy(s);
        CU_ASSERT_PTR_NULL(f->wt[i].binding);
    }
    CU_ASSERT_PTR_EQUAL(f->conn->proto_data, &f->h3);
    CU_ASSERT_PTR_EQUAL(f->conn->dgram_data, &f->ctx);
    f->conn->proto_data = NULL;
    f->conn->dgram_data = NULL;
    f->conn->engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
    xqc_engine_destroy(f->conn->engine);
}

static xqc_moqt_session_t *
moqt_wt_create(moqt_wt_fixture_t *f, unsigned i)
{
    f->session[i] = xqc_moqt_session_create_webtransport(&f->wt[i],
        &f->config, &moqt_wt_callbacks, f);
    return f->session[i];
}

void
xqc_test_moqt_webtransport(void)
{
    moqt_wt_fixture_t f;
    moqt_wt_init(&f);
    CU_ASSERT_PTR_NOT_NULL_FATAL(moqt_wt_create(&f, 0));
    CU_ASSERT_PTR_NOT_NULL_FATAL(moqt_wt_create(&f, 1));
    CU_ASSERT_PTR_EQUAL(f.session[0]->conn, f.session[1]->conn);
    CU_ASSERT(f.session[0]->timer != f.session[1]->timer);
    CU_ASSERT_PTR_EQUAL(xqc_wt_session_get_binding_user_data(&f.wt[0]),
                       f.session[0]);
    CU_ASSERT_PTR_EQUAL(xqc_wt_session_get_binding_user_data(&f.wt[1]),
                       f.session[1]);
    CU_ASSERT_PTR_EQUAL(xqc_wt_session_get_callback_user_data(&f.wt[0]), &f);
    /* A queued WT capsule delays CLOSE without losing its error code. */
    f.session[0]->wt_close_pending = 1;
    f.session[0]->wt_close_error = XQC_MOQT_UNAUTHORIZED;
    f.wt[0].send_len = 1;
    f.wt[0].binding->writable(&f.wt[0], f.session[0]);
    CU_ASSERT(f.session[0]->wt_close_pending && !f.wt[0].closed);
    CU_ASSERT_EQUAL(f.closed, 0);
    f.wt[0].send_len = 0;
    /* Draft-22 6.6: a WT close leaves the shared H3 connection usable. */
    f.wt[0].close_error = XQC_MOQT_UNAUTHORIZED;
    f.wt[0].closed = XQC_TRUE;
    xqc_wt_session_close_streams(&f.wt[0]);
    CU_ASSERT_PTR_NULL(f.wt[0].binding);
    CU_ASSERT_PTR_NULL(f.session[0]->wt_session);
    CU_ASSERT(f.session[0]->closed && !f.session[1]->closed);
    CU_ASSERT_EQUAL(f.error, XQC_MOQT_UNAUTHORIZED);
    CU_ASSERT_EQUAL(xqc_conn_get_errno(f.conn), 0);
    /* A hard capsule write failure releases the binding and its timer. */
    xqc_h3_stream_t h3 = {.flags = XQC_HTTP3_STREAM_FLAG_FIN_SENT};
    xqc_h3_request_t request = {.h3_stream = &h3};
    f.wt[1].request = &request;
    f.wt[1].send_len = 1;
    xqc_moqt_session_close(f.session[1], XQC_MOQT_INTERNAL_ERROR);
    CU_ASSERT(f.wt[1].closed && f.wt[1].close_notified);
    CU_ASSERT_EQUAL(f.wt[1].close_error, H3_INTERNAL_ERROR);
    CU_ASSERT_PTR_NULL(f.wt[1].binding);
    CU_ASSERT_EQUAL(f.session[1]->timer, -1);
    CU_ASSERT_EQUAL(xqc_conn_get_errno(f.conn), 0);
    moqt_wt_destroy(&f);
}

void
xqc_test_moqt_webtransport_errors(void)
{
    moqt_wt_fixture_t f;
    moqt_wt_init(&f);
    CU_ASSERT_PTR_NULL(xqc_moqt_session_create_webtransport(NULL, &f.config,
        &moqt_wt_callbacks, &f));
    for (unsigned i = 0; i < 8; i++) {
        xqc_wt_session_t *wt = &f.wt[0];
        wt->closed = i == 0;
        wt->open = i != 1;
        wt->application_protocol = i == 2 ? NULL
            : i == 3 ? (char *)"moqt-18" : (char *)"moqt-22";
        f.connection.negotiated_version = i == 4
            ? XQC_WEBTRANSPORT_DRAFT_VERSION_7
            : XQC_WEBTRANSPORT_DRAFT_VERSION_16;
        xqc_list_head_t stream;
        if (i == 7) {
            xqc_list_add_tail(&stream, &wt->stream_list);
        }
        CU_ASSERT_PTR_NULL(xqc_moqt_session_create_webtransport(wt,
            i == 5 ? NULL : &f.config, i == 6 ? NULL : &moqt_wt_callbacks, &f));
        CU_ASSERT_PTR_NULL(wt->binding);
        xqc_init_list_head(&wt->stream_list);
    }
    CU_ASSERT_PTR_NOT_NULL_FATAL(moqt_wt_create(&f, 0));
    CU_ASSERT_PTR_NULL(xqc_moqt_session_create_webtransport(&f.wt[0], &f.config,
        &moqt_wt_callbacks, &f));
    moqt_wt_destroy(&f);
}

static ssize_t
moqt_wt_send(xqc_h3_stream_t *h3, const unsigned char *bytes,
    size_t len, uint8_t fin)
{
    moqt_wt_fixture_t *f = h3->user_data;
    size_t amount = xqc_min(len, 1);
    memcpy(f->bytes + f->sent, bytes, amount);
    f->sent += amount;
    h3->stream->stream_send_offset += amount;
    return amount;
}

static xqc_int_t
moqt_wt_reset(xqc_h3_stream_t *h3, uint64_t error)
{
    ((moqt_wt_fixture_t *)h3->user_data)->reset_error = error;
    return XQC_OK;
}

static void
moqt_wt_stream(moqt_wt_fixture_t *f, xqc_wt_stream_base_t *wt,
    xqc_h3_stream_t *h3, xqc_stream_t *raw, xqc_bool_t receive)
{
    *raw = (xqc_stream_t){.stream_conn = f->conn,
        .stream_id = receive ? 3 : 2, .user_data = h3};
    *h3 = (xqc_h3_stream_t){.stream = raw, .user_data = f};
    *wt = (xqc_wt_stream_base_t){.session = &f->wt[0], .h3_stream = h3,
        .can_recv = receive, .can_send = !receive};
    CU_ASSERT_EQUAL(f->wt[0].binding->stream_cbs.wt_unistream_create_notify(
        (void *)wt, &f->wt[0], NULL), XQC_OK);
}

void
xqc_test_moqt_webtransport_streams(void)
{
    moqt_wt_fixture_t f;
    moqt_wt_init(&f);
    CU_ASSERT_PTR_NOT_NULL_FATAL(moqt_wt_create(&f, 0));
    CU_ASSERT_PTR_NOT_NULL_FATAL(moqt_wt_create(&f, 1));
    xqc_stream_t raw[3];
    xqc_h3_stream_t h3[3];
    xqc_wt_stream_base_t wt[3];
    const xqc_wt_stream_io_ops_t io = {.send = moqt_wt_send,
        .reset = moqt_wt_reset, .stop = moqt_wt_reset};
    raw[2] = (xqc_stream_t){.stream_conn = f.conn, .stream_id = 1,
                              .user_data = &h3[2]};
    h3[2] = (xqc_h3_stream_t){.stream = &raw[2], .user_data = &f};
    wt[2] = (xqc_wt_stream_base_t){.session = &f.wt[0], .h3_stream = &h3[2],
        .bidi = 1, .can_recv = 1, .can_send = 1, .io = &io};
    /* Draft-22 6.3 / WT 4.4: pre-SETUP rejection is a mapped stream reset. */
    CU_ASSERT_EQUAL(f.wt[0].binding->stream_cbs.wt_bidistream_create_notify(
        (void *)&wt[2], &f.wt[0], NULL), XQC_OK);
    CU_ASSERT(((xqc_moqt_stream_t *)wt[2].user_data)->discarded);
    CU_ASSERT_EQUAL(f.reset_error, UINT64_C(0x52e4a40fa8db));
    CU_ASSERT_PTR_EQUAL(raw[2].user_data, &h3[2]);
    CU_ASSERT(!f.session[0]->closed && !f.session[1]->closed);
    moqt_wt_stream(&f, &wt[0], &h3[0], &raw[0], XQC_FALSE);
    wt[0].io = &io;
    wt[0].prefix_len = 2;
    memcpy(wt[0].prefix, "WT", 2);
    const char payload[] = "abc";
    size_t offset = 0;
    for (unsigned i = 0; i < 8 && offset < 3; i++) {
        ssize_t n = xqc_moqt_transport_send(wt[0].user_data, payload + offset,
                                             3 - offset, 0);
        CU_ASSERT_FATAL(n >= 0 || n == -XQC_EAGAIN);
        if (n > 0) {
            offset += n;
        }
    }
    CU_ASSERT_EQUAL(offset, 3);
    CU_ASSERT_EQUAL(f.sent, 5);
    CU_ASSERT_NSTRING_EQUAL(f.bytes, "WTabc", 5);
    CU_ASSERT_EQUAL(xqc_moqt_transport_offset(wt[0].user_data), 3);
    CU_ASSERT_PTR_EQUAL(raw[0].user_data, &h3[0]);
    xqc_moqt_stream_t *sent = wt[0].user_data;
    sent->kind = XQC_MOQT_STREAM_SUBGROUP;
    sent->state.data.prefix_length = 3;
    f.conn->conn_flag |= XQC_CONN_FLAG_TLS_HSK_COMPLETED;
    f.conn->remote_settings.reset_stream_at = 1;
    xqc_moqt_transport_reset(sent, XQC_MOQT_RESET_CANCELLED);
    /* WT 4.4 maps error 1; MoQT 11.3.2 retains WT + identifying payload. */
    CU_ASSERT_EQUAL(f.reset_error, UINT64_C(0x52e4a40fa8db) + 1);
    CU_ASSERT_EQUAL(raw[0].reset_at.send_size, 5);
    f.reset_error = 0;
    wt[0].send_reset = XQC_FALSE;
    f.session[0]->closed = 1;
    xqc_moqt_transport_reset(sent, XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_EQUAL(f.reset_error, 0);
    f.session[0]->closed = 0;
    sent->kind = XQC_MOQT_STREAM_UNCLASSIFIED;
    moqt_wt_stream(&f, &wt[1], &h3[1], &raw[1], XQC_TRUE);
    uint8_t wire[8];
    xqc_moqt_message_t setup = {.type = XQC_MOQT_MSG_SETUP};
    int len = xqc_moqt_frame_encode(&setup, wire, sizeof(wire));
    f.session[0]->started = f.session[0]->setup_sent = 1;
    for (int i = 0; i < len; i++) {
        CU_ASSERT_EQUAL(f.wt[0].binding->stream_cbs.wt_unistream_read_notify(
            (void *)&wt[1], &f.wt[0], wire + i, 1, NULL), XQC_OK);
        CU_ASSERT_EQUAL(f.ready, i == len - 1);
    }
    CU_ASSERT_EQUAL(f.setups, 1);
    /* An unfinished raw stream disappears when its transport is destroyed. */
    CU_ASSERT_EQUAL(f.wt[0].binding->stream_cbs.wt_unistream_close_notify(
        (void *)&wt[1], &f.wt[0], NULL), XQC_OK);
    CU_ASSERT(f.session[0]->closed && !f.session[1]->closed);
    CU_ASSERT_PTR_NULL(f.session[0]->wt_session);
    moqt_wt_destroy(&f);
}

void
xqc_test_moqt_webtransport_setup_errors(void)
{
    /* Draft-22 9.1.1/9.1.2 forbid both options on a WT session. */
    for (unsigned i = 0; i < 2; i++) {
        moqt_wt_fixture_t f;
        moqt_wt_init(&f);
        xqc_moqt_kv_t option = {.type = i ? XQC_MOQT_OPT_AUTHORITY
                                         : XQC_MOQT_OPT_PATH};
        option.value.bytes = i ? (struct iovec){"localhost", 9}
                               : (struct iovec){"/", 1};
        f.config.setup_options = &option;
        f.config.setup_option_count = 1;
        CU_ASSERT_PTR_NULL(moqt_wt_create(&f, 0));
        f.config.setup_option_count = 0;
        CU_ASSERT_PTR_NOT_NULL_FATAL(moqt_wt_create(&f, 0));
        CU_ASSERT_PTR_NOT_NULL_FATAL(moqt_wt_create(&f, 1));
        xqc_stream_t raw;
        xqc_h3_stream_t h3;
        xqc_wt_stream_base_t wt;
        moqt_wt_stream(&f, &wt, &h3, &raw, XQC_TRUE);
        uint8_t body[32], wire[64];
        int len = xqc_moqt_kv_encode(&option, 0, body, sizeof(body));
        xqc_moqt_message_t setup = {.type = XQC_MOQT_MSG_SETUP,
            .body = {body, len}};
        len = xqc_moqt_frame_encode(&setup, wire, sizeof(wire));
        /* The fixture tests parsing; real CLOSE capsules are endpoint tests. */
        f.wt[0].closed = XQC_TRUE;
        CU_ASSERT_EQUAL(f.wt[0].binding->stream_cbs.wt_unistream_read_notify(
            (void *)&wt, &f.wt[0], wire, len, NULL), XQC_OK);
        CU_ASSERT_EQUAL(f.error, i ? XQC_MOQT_INVALID_AUTHORITY
                                   : XQC_MOQT_INVALID_PATH);
        CU_ASSERT(f.session[0]->closed && !f.session[1]->closed);
        CU_ASSERT_EQUAL(f.setups, 0);
        CU_ASSERT_EQUAL(xqc_conn_get_errno(f.conn), 0);
        moqt_wt_destroy(&f);
    }
}
