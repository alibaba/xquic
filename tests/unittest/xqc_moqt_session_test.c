/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include <CUnit/CUnit.h>
#include "xqc_common_test.h"
#include "moq/moqt/xqc_moqt_session.h"
#include "moq/moqt/xqc_moqt_codec.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_datagram.h"
#include "src/transport/xqc_send_queue.h"

#define XQC_MOQT_TEST_CAPACITY 4096

typedef struct {
    xqc_engine_t           *engine;
    xqc_connection_t       *conn;
    xqc_moqt_session_t     *session;
    xqc_moqt_config_t       config;
    unsigned                setups;
    unsigned                ready;
    unsigned                closed;
    unsigned                goaways;
    unsigned                tokens;
    uint64_t                reject;
    uint64_t                error;
    uint64_t                timeout;
    xqc_int_t               close_in_setup;
    xqc_int_t               close_in_ready;
    unsigned                messages;
    unsigned                authorized;
    unsigned                request_closed;
    unsigned                stream_closed;
    unsigned                subscription_closed;
    unsigned                fetch_ready;
    unsigned                fetch_closed;
    uint64_t                fetch_error;
    uint64_t                subscription_error;
    uint64_t                request_reject;
    uint64_t                last_type;
    uint64_t                last_id;
    uint64_t                last_code;
    uint64_t                last_normalized;
    xqc_int_t               reply;
    xqc_int_t               cancel_in_message;
    xqc_int_t               cancel_in_authorize;
    xqc_int_t               reject_request;
    xqc_moqt_request_t     *request;
    char                    candidate_prefix;
    unsigned                namespace_adds;
    unsigned                namespace_removes;
    size_t                  namespace_fields;
    char                    namespace_first;
    xqc_int_t               cancel_in_namespace;
    unsigned                objects;
    unsigned                object_bytes;
    unsigned                priority_sum;
    unsigned                writable;
    xqc_moqt_object_t       object;
    xqc_int_t               cancel_in_object;
    xqc_int_t               close_in_object;
} moqt_fixture_t;

static uint64_t
xqc_test_moqt_setup_notify(xqc_moqt_session_t *s, const xqc_moqt_setup_t *setup,
    void *data)
{
    moqt_fixture_t *f = data;
    f->setups++;
    f->tokens = setup->token_count;
    if (f->close_in_setup) {
        xqc_moqt_session_close(s, XQC_MOQT_UNAUTHORIZED);
    }
    return f->reject;
}

static void
xqc_test_moqt_ready_notify(xqc_moqt_session_t *s, void *data)
{
    moqt_fixture_t *f = data;
    f->ready++;
    if (f->close_in_ready) {
        xqc_moqt_session_close(s, XQC_MOQT_NO_ERROR);
    }
}

static void
xqc_test_moqt_closed_notify(xqc_moqt_session_t *s, uint64_t error, void *data)
{
    moqt_fixture_t *f = data;
    f->closed++;
    f->error = error;
}

static void
xqc_test_moqt_goaway_notify(xqc_moqt_session_t *s, const struct iovec *uri,
    uint64_t timeout, void *data)
{
    moqt_fixture_t *f = data;
    f->goaways++;
    f->timeout = timeout;
}

static const xqc_moqt_callbacks_t moqt_callbacks = {
    .on_setup = xqc_test_moqt_setup_notify,
    .on_ready = xqc_test_moqt_ready_notify,
    .on_closed = xqc_test_moqt_closed_notify,
    .on_goaway = xqc_test_moqt_goaway_notify,
};

static void
xqc_test_moqt_init(moqt_fixture_t *f, xqc_int_t server)
{
    xqc_memzero(f, sizeof(*f));
    xqc_conn_callbacks_t callbacks = {0};
    xqc_conn_ssl_config_t ssl = {0};
    xqc_conn_settings_t settings = {.proto_version = XQC_VERSION_V1,
        .max_datagram_frame_size = XQC_MAX_PACKET_OUT_SIZE,
        .max_pkt_out_size = XQC_MAX_PACKET_OUT_SIZE};
    xqc_moqt_config_init(&f->config, XQC_MOQT_VERSION_DRAFT_22);
    f->engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(f->engine);
    CU_ASSERT_EQUAL(xqc_moqt_init_alpn(f->engine, &f->config, &callbacks),
                    XQC_OK);
    const xqc_cid_t *cid = xqc_moqt_connect(
        f->engine, &f->config, &settings,
        NULL, 0, "localhost", &ssl, NULL, 0, f);
    CU_ASSERT_PTR_NOT_NULL_FATAL(cid);
    f->conn = xqc_engine_conns_hash_find(f->engine, cid, 's');
    /* Unit I/O runs as an engine callback; real TLS/socket I/O is in demos. */
    f->engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
    f->conn->conn_type = server ? XQC_CONN_TYPE_SERVER : XQC_CONN_TYPE_CLIENT;
    f->conn->remote_settings.max_datagram_frame_size = XQC_MAX_PACKET_OUT_SIZE;
    f->conn->remote_settings.max_stream_data_uni = XQC_MOQT_TEST_CAPACITY;
    f->conn->remote_settings.max_stream_data_bidi_local
        = XQC_MOQT_TEST_CAPACITY;
    f->conn->remote_settings.max_stream_data_bidi_remote
        = XQC_MOQT_TEST_CAPACITY;
    f->conn->conn_flow_ctl.fc_max_data_can_send = XQC_MOQT_TEST_CAPACITY;
    f->conn->conn_flow_ctl.fc_max_streams_uni_can_send
        = XQC_MOQT_DEFAULT_STREAMS;
    f->session = xqc_moqt_session_create(f->conn, &f->config,
                                         &moqt_callbacks, f);
    CU_ASSERT_PTR_NOT_NULL_FATAL(f->session);
}

static void
xqc_test_moqt_destroy(moqt_fixture_t *f)
{
    xqc_moqt_session_destroy(f->session);
    CU_ASSERT_PTR_NULL(f->conn->proto_data);
    CU_ASSERT_PTR_NULL(f->conn->dgram_data);
    CU_ASSERT_EQUAL(f->closed, 1);
    f->engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
    xqc_engine_destroy(f->engine);
}

static xqc_moqt_stream_t *
xqc_test_moqt_incoming(moqt_fixture_t *f)
{
    xqc_stream_type_t type = f->conn->conn_type == XQC_CONN_TYPE_SERVER
                             ? XQC_CLI_UNI : XQC_SVR_UNI;
    xqc_stream_id_t id = type + f->session->stream_count * 4;
    xqc_stream_t *stream = xqc_create_stream_with_conn(f->conn, id, type,
                                                       NULL, NULL);
    CU_ASSERT_PTR_NOT_NULL(stream);
    return stream == NULL ? NULL : stream->user_data;
}

static void
xqc_test_moqt_start(moqt_fixture_t *f)
{
    f->conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED
                          | XQC_CONN_FLAG_CAN_SEND_1RTT;
    CU_ASSERT_EQUAL(xqc_moqt_session_start(f->session), XQC_OK);
}

static xqc_int_t
xqc_test_moqt_options(xqc_moqt_stream_t *st, const xqc_moqt_kv_t *options,
    size_t count)
{
    uint8_t body[XQC_MOQT_TEST_CAPACITY], wire[XQC_MOQT_TEST_CAPACITY];
    size_t len = 0;
    uint64_t previous = 0;
    for (size_t i = 0; i < count; i++) {
        xqc_int_t n = xqc_moqt_kv_encode(&options[i], previous,
                                         body + len, sizeof(body) - len);
        CU_ASSERT(n > 0);
        len += n;
        previous = options[i].type;
    }
    xqc_moqt_message_t msg = {XQC_MOQT_MSG_SETUP, {body, len}};
    xqc_int_t n = xqc_moqt_frame_encode(&msg, wire, sizeof(wire));
    return xqc_moqt_stream_input(st, wire, n, 0);
}

void
xqc_test_moqt_setup(void)
{
    /* Draft-22 sections 6.3/9.1: independent streams, no stream-type prefix. */
    const uint8_t setup[] = {0xaf, 0x00, 0, 2, 8, 16};
    for (xqc_int_t server = 0; server <= 1; server++) {
        moqt_fixture_t f;
        xqc_test_moqt_init(&f, server);
        CU_ASSERT_EQUAL(f.session->setup->data_len, sizeof(setup));
        CU_ASSERT_EQUAL(xqc_memcmp(f.session->setup->data, setup,
                                   sizeof(setup)), 0);
        CU_ASSERT_EQUAL(xqc_moqt_session_start(f.session), -XQC_EPARAM);
        xqc_moqt_stream_t *rx = xqc_test_moqt_incoming(&f);
        CU_ASSERT_PTR_NOT_NULL_FATAL(rx);
        for (size_t i = 0; i < sizeof(setup); i++) {
            CU_ASSERT_EQUAL(xqc_moqt_stream_input(rx, setup + i, 1, 0), XQC_OK);
            CU_ASSERT_EQUAL(f.ready, 0);
        }
        CU_ASSERT_EQUAL(f.setups, 1);
        xqc_test_moqt_start(&f);
        CU_ASSERT_TRUE(f.session->setup_sent);
        CU_ASSERT_EQUAL(f.ready, 1);
        CU_ASSERT_EQUAL(f.session->peer_limits.max_request_updates, 16);
        CU_ASSERT_EQUAL(xqc_moqt_session_start(f.session), -XQC_EPARAM);
        CU_ASSERT_EQUAL(xqc_moqt_stream_flush(f.session->control_tx), XQC_OK);
        CU_ASSERT_EQUAL(f.ready, 1);
        xqc_test_moqt_destroy(&f);
    }
    moqt_fixture_t f;
    xqc_test_moqt_init(&f, 1);
    xqc_test_moqt_start(&f);
    const uint8_t token[] = {1, 9, 0, 't'};
    const xqc_moqt_kv_t options[] = {
        {.type = XQC_MOQT_OPT_PATH, .value.bytes = {"/?q=a%20b", 9}},
        {.type = XQC_MOQT_OPT_AUTHORIZATION_TOKEN,
         .value.bytes = {(void *)token, sizeof(token)}},
        {.type = XQC_MOQT_OPT_MAX_AUTH_TOKEN_CACHE, .value.integer = 128},
        {.type = XQC_MOQT_OPT_AUTHORITY, .value.bytes = {"[::1]:443", 9}},
        {.type = XQC_MOQT_OPT_MAX_FILTER_RANGES, .value.integer = 8},
        {.type = XQC_MOQT_OPT_MAX_REQUEST_UPDATES, .value.integer = 2},
        {.type = 100, .value.integer = 1},
        {.type = 100, .value.integer = 2},
    };
    CU_ASSERT_EQUAL(
        xqc_test_moqt_options(xqc_test_moqt_incoming(&f), options,
                              sizeof(options) / sizeof(options[0])), XQC_OK);
    CU_ASSERT_EQUAL(f.ready, 1);
    CU_ASSERT_EQUAL(f.tokens, 1);
    CU_ASSERT_EQUAL(f.session->local_limits.max_auth_token_cache, 0);
    CU_ASSERT_EQUAL(f.session->local_limits.max_filter_ranges, 0);
    CU_ASSERT_EQUAL(f.session->local_limits.max_request_updates, 16);
    CU_ASSERT_EQUAL(f.session->peer_limits.max_auth_token_cache, 128);
    CU_ASSERT_EQUAL(f.session->peer_limits.max_filter_ranges, 8);
    CU_ASSERT_EQUAL(f.session->peer_limits.max_request_updates, 2);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_setup_errors(void)
{
    const struct {
        uint8_t     wire[12];
        size_t      len;
        uint64_t    error;
    } cases[] = {
        {{0xaf, 0, 0, 4, 8, 1, 0, 2}, 8, XQC_MOQT_PROTOCOL_VIOLATION},
        {{0xaf, 0, 0, 1, 8}, 5, XQC_MOQT_KEY_VALUE_FORMATTING_ERROR},
        {{0xaf, 0, 0, 4, 3, 2, 0, 1}, 8, XQC_MOQT_PROTOCOL_VIOLATION},
        {{0xaf, 0, 0, 4, 3, 2, 2, 1}, 8, XQC_MOQT_PROTOCOL_VIOLATION},
        {{0xaf, 0, 0, 3, 3, 1, 3}, 7, XQC_MOQT_KEY_VALUE_FORMATTING_ERROR},
        {{0xaf, 0, 0, 3, 3, 1, 7}, 7, XQC_MOQT_KEY_VALUE_FORMATTING_ERROR},
        {{0xaf, 0, 0, 3, 1, 1, 'x'}, 7, XQC_MOQT_MALFORMED_PATH},
        {{0xaf, 0, 0, 4, 1, 2, '/', '%'}, 8, XQC_MOQT_MALFORMED_PATH},
        {{0xaf, 0, 0, 4, 5, 2, 'a', '/'}, 8, XQC_MOQT_MALFORMED_AUTHORITY},
        {{0xaf, 0, 0, 4, 5, 2, '[', ']'}, 8, XQC_MOQT_MALFORMED_AUTHORITY},
        {{0x02, 0, 2, 0, 0}, 5, XQC_MOQT_PROTOCOL_VIOLATION},
        {{0}, 1, XQC_MOQT_PROTOCOL_VIOLATION},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        moqt_fixture_t f;
        xqc_test_moqt_init(&f, 1);
        CU_ASSERT(
            xqc_moqt_stream_input(xqc_test_moqt_incoming(&f), cases[i].wire,
                                  cases[i].len, 0) < 0);
        CU_ASSERT_EQUAL(f.error, cases[i].error);
        CU_ASSERT_EQUAL(f.ready, 0);
        xqc_test_moqt_destroy(&f);
    }
    for (xqc_int_t behavior = 0; behavior < 5; behavior++) {
        moqt_fixture_t f;
        xqc_test_moqt_init(&f, behavior != 0);
        xqc_test_moqt_start(&f);
        f.reject = behavior == 1 ? XQC_MOQT_UNAUTHORIZED : 0;
        f.close_in_setup = behavior == 2;
        f.close_in_ready = behavior == 3;
        xqc_moqt_kv_t path = {.type = XQC_MOQT_OPT_PATH,
                              .value.bytes = {"/", 1}};
        xqc_test_moqt_options(xqc_test_moqt_incoming(&f), &path, 1);
        if (behavior == 0) {
            CU_ASSERT_EQUAL(f.error, XQC_MOQT_INVALID_PATH);
        } else if (behavior == 1 || behavior == 2) {
            CU_ASSERT_EQUAL(f.error, XQC_MOQT_UNAUTHORIZED);
            CU_ASSERT_EQUAL(f.ready, 0);
        } else if (behavior == 3) {
            CU_ASSERT_EQUAL(f.ready, 1);
            CU_ASSERT_TRUE(f.session->closed);
        } else {
            CU_ASSERT_EQUAL(
                xqc_test_moqt_options(xqc_test_moqt_incoming(&f), NULL, 0),
                -XQC_EILLEGAL_FRAME);
            CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
        }
        xqc_moqt_session_close(f.session, XQC_MOQT_INTERNAL_ERROR);
        CU_ASSERT_EQUAL(f.closed, 1);
        xqc_test_moqt_destroy(&f);
    }
}

void
xqc_test_moqt_session_limits(void)
{
    for (xqc_int_t scenario = 0; scenario < 8; scenario++) {
        moqt_fixture_t f;
        xqc_test_moqt_init(&f, 0);
        if (scenario == 0) {
            f.conn->remote_settings.max_datagram_frame_size = 0;
            f.conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED;
            CU_ASSERT_EQUAL(xqc_moqt_session_start(f.session), -XQC_EPARAM);
            CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
        } else if (scenario == 1) {
            xqc_moqt_session_timeout(f.session->timer,
                                     f.session->setup_deadline, f.session);
            CU_ASSERT_EQUAL(f.error, XQC_MOQT_CONTROL_MESSAGE_TIMEOUT);
        } else {
            xqc_test_moqt_start(&f);
            xqc_moqt_stream_t *rx = xqc_test_moqt_incoming(&f);
            CU_ASSERT_PTR_NOT_NULL_FATAL(rx);
            if (scenario == 2) {
                f.session->config.max_buffered_bytes
                    = f.session->buffered_bytes;
                const uint8_t first = 0xaf;
                CU_ASSERT(xqc_moqt_stream_input(rx, &first, 1, 0) < 0);
                CU_ASSERT_EQUAL(f.error, XQC_MOQT_INTERNAL_ERROR);
            } else if (scenario == 3) {
                CU_ASSERT_EQUAL(xqc_test_moqt_options(rx, NULL, 0), XQC_OK);
                CU_ASSERT_EQUAL(f.session->peer_limits.max_request_updates, 0);
                const uint8_t first = XQC_MOQT_MSG_GOAWAY;
                CU_ASSERT_EQUAL(xqc_moqt_stream_input(rx, &first, 1, 0),
                                XQC_OK);
                xqc_moqt_session_timeout(f.session->timer, rx->deadline,
                                         f.session);
                CU_ASSERT_EQUAL(f.error, XQC_MOQT_CONTROL_MESSAGE_TIMEOUT);
            } else if (scenario == 4) {
                CU_ASSERT_EQUAL(xqc_test_moqt_options(rx, NULL, 0), XQC_OK);
                CU_ASSERT(xqc_moqt_stream_input(rx, NULL, 0, 1) < 0);
                CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
            } else if (scenario == 5) {
                CU_ASSERT_EQUAL(xqc_test_moqt_options(rx, NULL, 0), XQC_OK);
                xqc_moqt_stream_callbacks.stream_close_notify(
                    rx->transport_stream, rx);
                CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
            } else {
                CU_ASSERT_EQUAL(xqc_test_moqt_options(rx, NULL, 0), XQC_OK);
                if (scenario == 6) {
                    xqc_moqt_stream_callbacks.stream_closing_notify(
                        rx->transport_stream, 0, rx);
                } else {
                    xqc_moqt_stream_t *tx = f.session->control_tx;
                    xqc_moqt_stream_callbacks.stream_stop_sending_notify(
                        tx->transport_stream, 0, tx);
                }
                CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
            }
        }
        xqc_test_moqt_destroy(&f);
    }
}

void
xqc_test_moqt_goaway(void)
{
    const uint8_t goaway[] = {0x10, 0, 2, 0, 25};
    const struct iovec empty = {NULL, 0}, uri = {"moqt://localhost/", 17};
    for (xqc_int_t server = 0; server <= 1; server++) {
        moqt_fixture_t f;
        xqc_test_moqt_init(&f, server);
        CU_ASSERT_EQUAL(xqc_moqt_session_goaway(f.session, &empty, 0),
                        -XQC_EPARAM);
        xqc_test_moqt_start(&f);
        xqc_moqt_stream_t *rx = xqc_test_moqt_incoming(&f);
        CU_ASSERT_EQUAL(xqc_test_moqt_options(rx, NULL, 0), XQC_OK);
        if (!server) {
            CU_ASSERT_EQUAL(xqc_moqt_session_goaway(f.session, &uri, 0),
                            -XQC_EPARAM);
        }
        CU_ASSERT_EQUAL(xqc_moqt_session_goaway(f.session, &empty, UINT64_MAX),
                        -XQC_EPARAM);
        CU_ASSERT_EQUAL(xqc_moqt_session_goaway(
            f.session, server ? &uri : &empty, 25), XQC_OK);
        CU_ASSERT_EQUAL(xqc_moqt_session_goaway(f.session, &empty, 0),
                        -XQC_EPARAM);
        CU_ASSERT_EQUAL(xqc_moqt_stream_input(rx, goaway, sizeof(goaway), 0),
                        XQC_OK);
        CU_ASSERT_EQUAL(f.goaways, 1);
        CU_ASSERT_EQUAL(f.timeout, 25);
        CU_ASSERT(xqc_moqt_stream_input(rx, goaway, sizeof(goaway), 0) < 0);
        CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
        xqc_test_moqt_destroy(&f);
    }
}

void
xqc_test_moqt_setup_validation(void)
{
    const struct {
        const char     *text;
        xqc_int_t       valid;
    } authorities[] = {
        {"localhost", 1}, {"a%20b:443", 1}, {"user:p@[::1]:443", 1},
        {"[v1.a:b]", 1}, {"[Vaf.a]", 1}, {"", 0}, {"[::1]", 1},
        {":443", 0}, {"user@", 0},
        {"user@@host", 0}, {"[::1", 0}, {"[v.bad]", 0}, {"[vg.a]", 0},
        {"[v1.]", 0}, {"[v1.%20]", 0}, {"[::1]x", 0}, {"host:x", 0},
        {"a%zz", 0}, {"[this-is-a-very-long-invalid-ipv6-literal-address]", 0},
    };
    for (size_t i = 0; i < sizeof(authorities) / sizeof(authorities[0]); i++) {
        moqt_fixture_t f;
        xqc_test_moqt_init(&f, 1);
        xqc_moqt_kv_t kv = {.type = XQC_MOQT_OPT_AUTHORITY,
            .value.bytes = {(void *)authorities[i].text,
                             strlen(authorities[i].text)}};
        xqc_int_t ret = xqc_test_moqt_options(xqc_test_moqt_incoming(&f),
                                              &kv, 1);
        CU_ASSERT_EQUAL(ret == XQC_OK, authorities[i].valid);
        if (!authorities[i].valid) {
            CU_ASSERT_EQUAL(f.error, XQC_MOQT_MALFORMED_AUTHORITY);
        }
        xqc_test_moqt_destroy(&f);
    }
    /* Section 8.9: repeated options may carry distinct resolved tokens. */
    for (xqc_int_t duplicate = 0; duplicate <= 1; duplicate++) {
        moqt_fixture_t f;
        xqc_test_moqt_init(&f, 1);
        uint8_t values[][3] = {{3, 0, 'a'}, {3, 0, 'b'}};
        if (duplicate) {
            values[1][2] = values[0][2];
        }
        xqc_moqt_kv_t tokens[] = {
            {.type = XQC_MOQT_OPT_AUTHORIZATION_TOKEN,
             .value.bytes = {values[0], sizeof(values[0])}},
            {.type = XQC_MOQT_OPT_AUTHORIZATION_TOKEN,
             .value.bytes = {values[1], sizeof(values[1])}},
        };
        xqc_int_t ret = xqc_test_moqt_options(
            xqc_test_moqt_incoming(&f),
            tokens, sizeof(tokens) / sizeof(tokens[0]));
        CU_ASSERT_EQUAL(ret == XQC_OK, !duplicate);
        if (duplicate) {
            CU_ASSERT_EQUAL(f.error, XQC_MOQT_MALFORMED_AUTH_TOKEN);
            CU_ASSERT_EQUAL(f.setups, 0);
        } else {
            CU_ASSERT_EQUAL(f.tokens, 2);
        }
        xqc_test_moqt_destroy(&f);
    }
    for (xqc_int_t scenario = 0; scenario < 4; scenario++) {
        moqt_fixture_t f;
        xqc_test_moqt_init(&f, scenario != 0);
        xqc_moqt_kv_t options[XQC_MOQT_MAX_OPTIONS + 1];
        xqc_memzero(options, sizeof(options));
        for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
            options[i].type = 100;
        }
        const uint8_t token[] = {1};
        size_t count = 1;
        uint64_t error = XQC_MOQT_KEY_VALUE_FORMATTING_ERROR;
        if (scenario == 0) {
            options[0].type = XQC_MOQT_OPT_AUTHORITY;
            options[0].value.bytes.iov_base = "a";
            options[0].value.bytes.iov_len = 1;
            error = XQC_MOQT_INVALID_AUTHORITY;
        } else if (scenario == 1) {
            count = XQC_MOQT_MAX_OPTIONS + 1;
            error = XQC_MOQT_INTERNAL_ERROR;
        } else {
            options[0].type = XQC_MOQT_OPT_AUTHORIZATION_TOKEN;
            options[0].value.bytes.iov_base = (void *)token;
            options[0].value.bytes.iov_len = scenario == 2 ? sizeof(token) : 0;
        }
        CU_ASSERT(
            xqc_test_moqt_options(xqc_test_moqt_incoming(&f), options,
                                  count) < 0);
        CU_ASSERT_EQUAL(f.error, error);
        xqc_test_moqt_destroy(&f);
    }
}

static void
xqc_test_moqt_param_log(xqc_log_level_t level, const void *data, size_t len,
    void *user)
{
    char *reason = user;
    if (level == XQC_LOG_ERROR) {
        size_t copied = xqc_min(len, XQC_MOQT_TEST_CAPACITY - 1);
        xqc_memcpy(reason, data, copied);
        reason[copied] = '\0';
    }
}

void
xqc_test_moqt_session_lifecycle(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_init(&f, 0);
    CU_ASSERT_PTR_NULL(xqc_moqt_session_create(f.conn, &f.config,
                                               &moqt_callbacks, &f));
    xqc_moqt_session_destroy(f.session);
    f.session = NULL;
    const xqc_moqt_callbacks_t empty_callbacks = {0};
    CU_ASSERT_PTR_NULL(xqc_moqt_session_create(f.conn, &f.config,
                                               &empty_callbacks, &f));
    CU_ASSERT_PTR_NULL(xqc_moqt_session_create(NULL, &f.config,
                                               &moqt_callbacks, &f));
    xqc_log_t saved_log = *f.conn->log;
    xqc_log_callbacks_t log_callbacks = {.xqc_log_write_err =
        xqc_test_moqt_param_log};
    char reason[XQC_MOQT_TEST_CAPACITY];
    f.conn->log->log_callbacks = &log_callbacks;
    f.conn->log->user_data = reason;
    f.conn->log->log_level = XQC_LOG_ERROR;
    const char *expected[] = {
        "config is NULL", "unsupported protocol version",
        "ALPN does not match", "application data", "on_setup callback",
        "max_streams", "max_buffered_bytes", "timeout must be nonzero",
        "timeout overflows", "too many SETUP", "options are NULL",
        "stream_read_notify", "stream_create_notify", "stream_close_notify",
        "stream_write_notify", "stream_closing_notify",
        "stream_stop_sending_notify", "datagram_read_notify",
    };
    for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
        xqc_moqt_config_t config = f.config;
        xqc_app_proto_callbacks_t saved = f.conn->app_proto_cbs;
        char *alpn = f.conn->alpn;
        reason[0] = '\0';
        switch (i) {
        case 1:
            config.version = XQC_MOQT_VERSION_DRAFT_22 + 1;
            break;
        case 2:
            f.conn->alpn = NULL;
            break;
        case 3:
            f.conn->dgram_data = &f;
            break;
        case 5:
            config.max_streams = 1;
            break;
        case 6:
            config.max_buffered_bytes = 0;
            break;
        case 7:
            config.timeout = 0;
            break;
        case 8:
            config.timeout = UINT64_MAX;
            break;
        case 9:
            config.setup_option_count = XQC_MOQT_MAX_OPTIONS + 1;
            break;
        case 10:
            config.setup_option_count = 1;
            break;
        case 11:
            f.conn->app_proto_cbs.stream_cbs.stream_read_notify = NULL;
            break;
        case 12:
            f.conn->app_proto_cbs.stream_cbs.stream_create_notify = NULL;
            break;
        case 13:
            f.conn->app_proto_cbs.stream_cbs.stream_close_notify = NULL;
            break;
        case 14:
            f.conn->app_proto_cbs.stream_cbs.stream_write_notify = NULL;
            break;
        case 15:
            f.conn->app_proto_cbs.stream_cbs.stream_closing_notify = NULL;
            break;
        case 16: f.conn->app_proto_cbs.stream_cbs.stream_stop_sending_notify
                     = NULL;
            break;
        case 17:
            f.conn->app_proto_cbs.dgram_cbs.datagram_read_notify = NULL;
            break;
        }
        CU_ASSERT_PTR_NULL(xqc_moqt_session_create(
            f.conn,
            i == 0 ? NULL : &config, i == 4 ? NULL : &moqt_callbacks, &f));
#ifndef XQC_DISABLE_LOG
        CU_ASSERT_PTR_NOT_NULL(strstr(reason, expected[i]));
#endif
        CU_ASSERT_PTR_NULL(f.conn->proto_data);
        f.conn->app_proto_cbs = saved;
        f.conn->alpn = alpn;
        f.conn->dgram_data = NULL;
    }
    *f.conn->log = saved_log;
    for (xqc_int_t scenario = 0; scenario < 5; scenario++) {
        xqc_moqt_config_t config = f.config;
        xqc_moqt_kv_t option = {.type = XQC_MOQT_OPT_MAX_AUTH_TOKEN_CACHE,
                                .value.integer = 1};
        if (scenario == 0) {
            config.max_streams = 1;
        } else if (scenario == 1) {
            config.timeout = UINT64_MAX;
        } else if (scenario == 2) {
            config.max_buffered_bytes = sizeof(xqc_var_buf_t)
                                        + sizeof(xqc_list_buf_t);
            option.type = XQC_MOQT_OPT_IMPLEMENTATION;
            option.value.bytes.iov_base
                = "test implementation longer than budget";
            option.value.bytes.iov_len = 38;
        } else if (scenario == 3) {
            option.type = XQC_MOQT_OPT_PATH;
            option.value.bytes.iov_base = "relative";
            option.value.bytes.iov_len = 8;
        }
        config.setup_options = &option;
        config.setup_option_count = 1;
        CU_ASSERT_PTR_NULL(xqc_moqt_session_create(f.conn, &config,
                                                   &moqt_callbacks, &f));
    }
    f.closed = 0;
    f.session = xqc_moqt_session_create(f.conn, &f.config, &moqt_callbacks, &f);
    CU_ASSERT_PTR_NOT_NULL_FATAL(f.session);
    f.conn->remote_settings.max_stream_data_uni = 3;
    f.conn->remote_settings.max_stream_data_bidi_local = 3;
    f.conn->remote_settings.max_stream_data_bidi_remote = 3;
    xqc_test_moqt_start(&f);
    CU_ASSERT_FALSE(f.session->setup_sent);
    CU_ASSERT_FALSE(xqc_list_empty(&f.session->control_tx->tx));
    xqc_moqt_stream_t *rx = xqc_test_moqt_incoming(&f);
    CU_ASSERT_EQUAL(xqc_test_moqt_options(rx, NULL, 0), XQC_OK);
    CU_ASSERT_EQUAL(f.ready, 0);
    xqc_moqt_stream_t *tx = f.session->control_tx;
    tx->transport_stream->stream_flow_ctl.fc_max_stream_data_can_send
        = XQC_MOQT_TEST_CAPACITY;
    CU_ASSERT_EQUAL(xqc_moqt_stream_callbacks.stream_write_notify(
        tx->transport_stream, tx), XQC_OK);
    CU_ASSERT_EQUAL(f.ready, 1);
    CU_ASSERT_TRUE(xqc_list_empty(&tx->tx));
    const struct iovec empty = {NULL, 0};
    CU_ASSERT_EQUAL(xqc_moqt_session_goaway(f.session, &empty, 1), XQC_OK);
    xqc_moqt_session_timeout(f.session->timer, f.session->goaway_deadline,
                             f.session);
    CU_ASSERT_EQUAL(f.error, XQC_MOQT_NO_ERROR);
    CU_ASSERT_EQUAL(f.closed, 1);
    xqc_moqt_session_timeout(f.session->timer, UINT64_MAX, f.session);
    xqc_test_moqt_destroy(&f);

    /* A blocked writer retains its frame; reset errors close exactly once. */
    xqc_test_moqt_init(&f, 0);
    xqc_test_moqt_start(&f);
    rx = xqc_test_moqt_incoming(&f);
    CU_ASSERT_EQUAL(xqc_test_moqt_options(rx, NULL, 0), XQC_OK);
    tx = f.session->control_tx;
    tx->transport_stream->stream_state_send = XQC_SEND_STREAM_ST_RESET_SENT;
    CU_ASSERT(xqc_moqt_session_goaway(f.session, &empty, 0) < 0);
    CU_ASSERT_EQUAL(f.error, XQC_MOQT_INTERNAL_ERROR);
    xqc_test_moqt_destroy(&f);

    xqc_test_moqt_init(&f, 0);
    f.session->config.max_streams = 2;
    xqc_test_moqt_start(&f);
    CU_ASSERT_PTR_NOT_NULL(xqc_test_moqt_incoming(&f));
    CU_ASSERT_PTR_NULL(xqc_test_moqt_incoming(&f));
    CU_ASSERT_EQUAL(f.error, XQC_MOQT_INTERNAL_ERROR);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_padding_and_goaway_errors(void)
{
    moqt_fixture_t f;
    /* Early data streams are reset without inventing request entities. */
    const uint8_t data_types[] = {XQC_MOQT_FETCH_STREAM,
                                  XQC_MOQT_SUBGROUP_FIXED_BITS};
    for (size_t i = 0; i < sizeof(data_types); i++) {
        xqc_test_moqt_init(&f, 0);
        xqc_moqt_stream_t *data = xqc_test_moqt_incoming(&f);
        CU_ASSERT_EQUAL(xqc_moqt_stream_input(data, &data_types[i], 1, 0),
                        XQC_OK);
        CU_ASSERT_TRUE(data->discarded);
        CU_ASSERT_FALSE(f.session->closed);
        xqc_test_moqt_destroy(&f);
    }
    xqc_test_moqt_init(&f, 0);
    uint8_t padding[XQC_VI64_MAX_LEN];
    xqc_int_t n = xqc_vi64_write(padding, padding + sizeof(padding),
                                 XQC_MOQT_PADDING_STREAM);
    xqc_moqt_stream_t *st = xqc_test_moqt_incoming(&f);
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, padding, n, 1), XQC_OK);
    CU_ASSERT_EQUAL(st->kind, XQC_MOQT_STREAM_PADDING);
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, padding, n, 0), XQC_OK);
    n = xqc_vi64_write(padding, padding + sizeof(padding),
                       XQC_MOQT_PADDING_DATAGRAM);
    size_t allocated = f.session->buffered_bytes;
    xqc_moqt_datagram_callbacks.datagram_read_notify(f.conn, f.session,
                                                     padding, n, 0);
    CU_ASSERT_FALSE(f.session->closed);
    CU_ASSERT_EQUAL(allocated, f.session->buffered_bytes);
    xqc_moqt_datagram_callbacks.datagram_read_notify(f.conn, f.session,
                                                     padding, 0, 0);
    CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
    xqc_test_moqt_destroy(&f);
    const struct {
        uint8_t     body[5];
        size_t      len;
    } malformed[] = {
        {{0}, 0}, {{1, 'x', 0}, 3}, {{0x80}, 1}, {{0, 0x80}, 2},
        {{0, 0, 0}, 3}, {{0xa0, 0x01}, 2}, {{2, 'x'}, 2},
    };
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
        xqc_test_moqt_init(&f, 1);
        xqc_test_moqt_start(&f);
        st = xqc_test_moqt_incoming(&f);
        CU_ASSERT_EQUAL(xqc_test_moqt_options(st, NULL, 0), XQC_OK);
        uint8_t wire[32];
        xqc_moqt_message_t msg = {XQC_MOQT_MSG_GOAWAY,
            {(void *)malformed[i].body, malformed[i].len}};
        n = xqc_moqt_frame_encode(&msg, wire, sizeof(wire));
        CU_ASSERT(xqc_moqt_stream_input(st, wire, n, 0) < 0);
        CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
        CU_ASSERT_EQUAL(f.goaways, 0);
        xqc_test_moqt_destroy(&f);
    }
}

static xqc_int_t
xqc_test_moqt_authorize_notify(xqc_moqt_request_t *r,
    const xqc_moqt_message_t *m,
    const xqc_moqt_message_t *candidate, uint64_t *error, void *data)
{
    moqt_fixture_t *f = data;
    f->authorized++;
    if (candidate->track_namespace.count) {
        f->candidate_prefix
            = *(char *)candidate->track_namespace.fields[0].iov_base;
    }
    if (f->cancel_in_authorize) {
        xqc_moqt_request_cancel(r, XQC_MOQT_RESET_CANCELLED);
    }
    *error = f->request_reject;
    return f->request_reject || f->reject_request ? XQC_ERROR : XQC_OK;
}

static void
xqc_test_moqt_message_notify(xqc_moqt_request_t *r, const xqc_moqt_message_t *m,
    void *data)
{
    moqt_fixture_t *f = data;
    f->request = r;
    f->messages++;
    f->last_type = m->type;
    f->last_id = m->request_id;
    f->last_code = m->error.code;
    f->last_normalized = m->error.normalized_code;
    if (f->cancel_in_message) {
        xqc_moqt_request_cancel(r, XQC_MOQT_RESET_CANCELLED);
    } else if (f->reply
               && (xqc_moqt_is_initial_request(m->type)
                   || m->type == XQC_MOQT_MSG_REQUEST_UPDATE))
    {
        xqc_moqt_message_t response = {0};
        response.type = m->type == XQC_MOQT_MSG_SUBSCRIBE
                        ? XQC_MOQT_MSG_SUBSCRIBE_OK : XQC_MOQT_MSG_REQUEST_OK;
        CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &response), XQC_OK);
    }
}

static void
xqc_test_moqt_request_closed_notify(xqc_moqt_request_t *r,
    const xqc_moqt_error_t *error,
    void *data)
{
    moqt_fixture_t *f = data;
    f->request_closed++;
    if (error != NULL) {
        f->last_code = error->code;
        f->last_normalized = error->normalized_code;
    }
}

static void
xqc_test_moqt_request_init(moqt_fixture_t *f, xqc_int_t server)
{
    xqc_test_moqt_init(f, server);
    f->session->callbacks.on_authorize = xqc_test_moqt_authorize_notify;
    f->session->callbacks.on_message = xqc_test_moqt_message_notify;
    f->session->callbacks.on_request_closed =
        xqc_test_moqt_request_closed_notify;
    f->conn->conn_flow_ctl.fc_max_streams_bidi_can_send
        = XQC_MOQT_DEFAULT_STREAMS;
    xqc_test_moqt_start(f);
    CU_ASSERT_EQUAL(
        xqc_test_moqt_options(xqc_test_moqt_incoming(f), NULL, 0), XQC_OK);
    CU_ASSERT_TRUE(f->session->ready);
}

static xqc_moqt_stream_t *
xqc_test_moqt_request_stream(moqt_fixture_t *f)
{
    xqc_stream_type_t type = f->conn->conn_type == XQC_CONN_TYPE_SERVER
                             ? XQC_CLI_BID : XQC_SVR_BID;
    xqc_stream_t *stream = xqc_create_stream_with_conn(
        f->conn,
        type + f->session->stream_count * 4, type, NULL, NULL);
    CU_ASSERT_PTR_NOT_NULL(stream);
    return stream == NULL ? NULL : stream->user_data;
}

static xqc_int_t
xqc_test_moqt_request_input(xqc_moqt_stream_t *st, xqc_moqt_message_t *m,
    uint64_t context, uint8_t fin)
{
    uint8_t wire[XQC_MOQT_TEST_CAPACITY];
    xqc_int_t n = xqc_moqt_message_encode(m, context, wire, sizeof(wire));
    CU_ASSERT(n > 0);
    return n < 0 ? n : xqc_moqt_stream_input(st, wire, n, fin);
}

void
xqc_test_moqt_messages(void)
{
    /* Draft-22 9.14: ID 0, empty namespace, zero parameters. */
    const uint8_t expected[] = {6, 0, 3, 0, 0, 0};
    uint8_t buf[XQC_MOQT_TEST_CAPACITY], short_buf[2] = {0xaa, 0xbb};
    xqc_moqt_message_t m = {0}, decoded;
    m.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
    CU_ASSERT_EQUAL(xqc_moqt_message_encode(&m, m.type, NULL, 0),
                    sizeof(expected));
    CU_ASSERT_EQUAL(xqc_moqt_message_encode(&m, m.type, buf, sizeof(buf)),
                    sizeof(expected));
    CU_ASSERT_EQUAL(xqc_memcmp(buf, expected, sizeof(expected)), 0);
    CU_ASSERT_EQUAL(xqc_moqt_message_encode(&m, m.type, short_buf,
                                            sizeof(short_buf)), -XQC_ENOBUF);
    CU_ASSERT_EQUAL(short_buf[0], 0xaa);
    for (size_t i = 0; i < sizeof(expected); i++) {
        CU_ASSERT_EQUAL(xqc_moqt_message_decode(expected, i, m.type, &decoded),
                        -XQC_EAGAIN);
    }
    /* Independent message/parameter wire identifiers, draft-22 section 16. */
    const uint64_t types[] = {
        3, 0x1d, 0x16, 0x0d, 6, 0x50, 0x51, 2, 4, 7, 0x18, 0x22, 0x0b, 0x10,
    };
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        xqc_memzero(&m, sizeof(m));
        m.type = types[i];
        m.request_id = UINT64_MAX;
        m.track_alias = UINT64_MAX;
        m.end_group = UINT64_MAX;
        m.end_object = UINT64_MAX;
        m.stream_count = UINT64_MAX;
        xqc_int_t n = xqc_moqt_message_encode(&m, XQC_MOQT_MSG_PUBLISH, buf,
                                              sizeof(buf));
        CU_ASSERT(n > 0);
        CU_ASSERT_EQUAL(xqc_moqt_message_decode(buf, n, XQC_MOQT_MSG_PUBLISH,
                                                &decoded), n);
        CU_ASSERT_EQUAL(decoded.type, m.type);
    }
    const struct {
        uint64_t    type;
        uint64_t    message;
        uint64_t    context;
        uint8_t     bytes[8];
        size_t      len;
    } parameters[] = {
        {2, 3, 3, {1}, 1}, {3, 3, 3, {3, 3, 0, 'a'}, 4}, {4, 3, 3, {1}, 1},
        {6, 3, 3, {1}, 1}, {8, 7, 0x1d, {1}, 1}, {9, 7, 0x0d, {1, 2}, 2},
        {0x0a, 0x16, 0x16, {1}, 1}, {0x10, 3, 3, {1}, 1},
        {0x20, 3, 3, {255}, 1}, {0x21, 3, 3, {4, 1, 2, 3, 4}, 5},
        {0x22, 3, 3, {2}, 1}, {0x23, 3, 3, {0}, 1},
        {0x25, 3, 3, {0}, 1}, {0x26, 3, 3, {0}, 1}, {0x27, 3, 3, {0}, 1},
        {0x28, 3, 3, {0}, 1}, {0x29, 0x51, 0x51, {0}, 1},
        {0x32, 3, 3, {1}, 1}, {0x34, 2, 0x50, {1, 1, 'a'}, 3},
        {0x35, 3, 3, {1}, 1},
    };
    for (size_t i = 0; i < sizeof(parameters) / sizeof(parameters[0]); i++) {
        xqc_memzero(&m, sizeof(m));
        m.type = parameters[i].message;
        m.parameter_count = 1;
        m.parameters[0].type = parameters[i].type;
        m.parameters[0].value = (uint8_t *)parameters[i].bytes;
        m.parameters[0].length = parameters[i].len;
        xqc_int_t n = xqc_moqt_message_encode(&m, parameters[i].context, buf,
                                              sizeof(buf));
        CU_ASSERT(n > 0);
        CU_ASSERT_EQUAL(xqc_moqt_message_decode(buf, n, parameters[i].context,
                                                &decoded), n);
        CU_ASSERT_EQUAL(decoded.parameters[0].length, parameters[i].len);
        m.parameters[0].length--;
        CU_ASSERT(xqc_moqt_message_encode(&m, parameters[i].context, NULL,
                                          0) < 0);
        m.parameters[0].length++;
        m.type = XQC_MOQT_MSG_FETCH_OK;
        CU_ASSERT(xqc_moqt_message_encode(&m, parameters[i].context, NULL,
                                          0) < 0);
    }
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_REQUEST_ERROR;
    m.error.code = XQC_MOQT_REQUEST_REDIRECT;
    m.track_namespace.count = 1;
    m.track_namespace.fields[0] = (struct iovec){"private", 7};
    m.track_name = (struct iovec){"camera", 6};
    m.uri = (struct iovec){"moqt://localhost/", 17};
    m.reason = (struct iovec){"moved", 5};
    xqc_int_t n = xqc_moqt_message_encode(&m, XQC_MOQT_MSG_SUBSCRIBE, buf,
                                          sizeof(buf));
    CU_ASSERT(n > 0);
    CU_ASSERT_EQUAL(xqc_moqt_message_decode(buf, n, XQC_MOQT_MSG_SUBSCRIBE,
                                            &decoded), n);
    CU_ASSERT_EQUAL(decoded.error.normalized_code, XQC_MOQT_REQUEST_REDIRECT);
    CU_ASSERT(xqc_moqt_message_decode(buf, n, XQC_MOQT_MSG_PUBLISH_NAMESPACE,
                                      &decoded) < 0);
    CU_ASSERT(xqc_moqt_message_encode(&m, XQC_MOQT_MSG_REQUEST_UPDATE, NULL,
                                      0) < 0);
    m.error.code = 0x9d;
    n = xqc_moqt_message_encode(&m, XQC_MOQT_MSG_SUBSCRIBE, buf, sizeof(buf));
    CU_ASSERT_EQUAL(xqc_moqt_message_decode(buf, n, XQC_MOQT_MSG_SUBSCRIBE,
                                            &decoded), n);
    CU_ASSERT_EQUAL(decoded.error.code, 0x9d);
    CU_ASSERT_EQUAL(decoded.error.normalized_code,
                    XQC_MOQT_REQUEST_INTERNAL_ERROR);
    /* Track Properties remain borrowed KVP bytes until their entity step. */
    uint8_t properties[] = {2, 1, 1, 1, 'x'};
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_PUBLISH;
    m.properties = (struct iovec){properties, sizeof(properties)};
    n = xqc_moqt_message_encode(&m, m.type, buf, sizeof(buf));
    CU_ASSERT(n > 0);
    CU_ASSERT_EQUAL(xqc_moqt_message_decode(buf, n, m.type, &decoded), n);
    CU_ASSERT_EQUAL(decoded.properties.iov_len, sizeof(properties));
    CU_ASSERT_EQUAL(xqc_memcmp(decoded.properties.iov_base, properties,
                               sizeof(properties)), 0);
    m.properties.iov_len--;
    CU_ASSERT(xqc_moqt_message_encode(&m, m.type, NULL, 0) < 0);
    CU_ASSERT_EQUAL(xqc_moqt_message_encode(NULL, m.type, NULL, 0),
                    -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_message_decode(buf, n, m.type, NULL), -XQC_EPARAM);
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_SUBSCRIBE;
    uint8_t enabled = 1;
    m.parameter_count = 2;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FORWARD, sizeof(enabled), &enabled};
    m.parameters[1] = m.parameters[0];
    CU_ASSERT(xqc_moqt_message_encode(&m, m.type, NULL, 0) < 0);
    m.parameter_count = 1;
    m.parameters[0].type = UINT64_MAX;
    CU_ASSERT(xqc_moqt_message_encode(&m, m.type, NULL, 0) < 0);
    m.parameter_count = XQC_MOQT_MAX_PARAMETERS + 1;
    CU_ASSERT(xqc_moqt_message_encode(&m, m.type, NULL, 0) < 0);
    m.parameter_count = 0;
    m.track_namespace.count = XQC_MOQT_NAMESPACE_MAX_FIELDS + 1;
    CU_ASSERT(xqc_moqt_message_encode(&m, m.type, NULL, 0) < 0);
    /* Draft-22 9.3-9.19: complete frames with truncated required fields. */
    const struct {
        uint64_t    type;
        uint8_t     body[8];
        size_t      len;
    } bodies[] = {
        {XQC_MOQT_MSG_SUBSCRIBE, {0, 0, 0, 0}, 4},
        {XQC_MOQT_MSG_PUBLISH, {0, 0, 0, 0, 0}, 5},
        {XQC_MOQT_MSG_REQUEST_UPDATE, {0, 0}, 2},
        {XQC_MOQT_MSG_SUBSCRIBE_OK, {0, 0}, 2},
        {XQC_MOQT_MSG_REQUEST_OK, {0}, 1},
        {XQC_MOQT_MSG_FETCH_OK, {0, 0, 0, 0}, 4},
        {XQC_MOQT_MSG_REQUEST_ERROR, {0, 0, 0}, 3},
        {XQC_MOQT_MSG_REQUEST_ERROR, {0x34, 0, 0, 0, 0, 0}, 6},
        {XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY, {0}, 1},
        {XQC_MOQT_MSG_PUBLISH_DONE, {0, 0, 0}, 3},
        {XQC_MOQT_MSG_GOAWAY, {0, 0}, 2},
    };
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++) {
        xqc_memzero(&m, sizeof(m));
        m.type = bodies[i].type;
        m.body.iov_base = (void *)bodies[i].body;
        m.body.iov_len = bodies[i].len;
        n = xqc_moqt_frame_encode(&m, buf, sizeof(buf));
        CU_ASSERT(n > 0);
        CU_ASSERT_EQUAL(xqc_moqt_message_decode(
            buf, n,
            XQC_MOQT_MSG_SUBSCRIBE, &decoded), n);
        uint8_t encoded[XQC_MOQT_TEST_CAPACITY];
        CU_ASSERT_EQUAL(xqc_moqt_message_encode(
            &decoded,
            XQC_MOQT_MSG_SUBSCRIBE, encoded, sizeof(encoded)), n);
        CU_ASSERT_EQUAL(xqc_memcmp(buf, encoded, n), 0);
        xqc_moqt_message_t saved = decoded;
        for (size_t cut = 0; cut < bodies[i].len; cut++) {
            m.body.iov_len = cut;
            n = xqc_moqt_frame_encode(&m, buf, sizeof(buf));
            CU_ASSERT_EQUAL(xqc_moqt_message_decode(
                buf, n,
                XQC_MOQT_MSG_SUBSCRIBE, &decoded), -XQC_EILLEGAL_FRAME);
            CU_ASSERT_EQUAL(xqc_memcmp(&decoded, &saved, sizeof(saved)), 0);
        }
    }
    /* Required values cannot be hidden by a later valid field. */
    const struct {
        uint64_t    type;
        uint8_t     body[12];
        size_t      len;
    } malformed[] = {
        {XQC_MOQT_MSG_FETCH_OK, {2, 0, 0, 0}, 4},
        {XQC_MOQT_MSG_REQUEST_UPDATE, {0, 65}, 2},
        {XQC_MOQT_MSG_REQUEST_UPDATE, {0, 1, 0x10}, 3},
        {XQC_MOQT_MSG_REQUEST_UPDATE, {0, 1, 0x10, 2}, 4},
        {XQC_MOQT_MSG_REQUEST_UPDATE, {0, 1, 0x21, 6}, 4},
        {XQC_MOQT_MSG_REQUEST_UPDATE, {0, 1, 0x21, 4, 1}, 5},
        {XQC_MOQT_MSG_REQUEST_UPDATE, {0, 1, 0x03, 5, 1}, 5},
        {XQC_MOQT_MSG_SUBSCRIBE_OK, {0, 1, 9, 1}, 4},
        {XQC_MOQT_MSG_SUBSCRIBE_OK, {0, 1, 9, 1, 0xff}, 5},
        {XQC_MOQT_MSG_SUBSCRIBE_OK, {0, 0, 1, 1}, 4},
        {XQC_MOQT_MSG_REQUEST_OK, {0, 0}, 2},
        {XQC_MOQT_MSG_GOAWAY, {2, 'a'}, 2},
        {XQC_MOQT_MSG_SETUP, {0}, 1},
    };
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
        xqc_memzero(&m, sizeof(m));
        m.type = malformed[i].type;
        m.body = (struct iovec){(void *)malformed[i].body, malformed[i].len};
        n = xqc_moqt_frame_encode(&m, buf, sizeof(buf));
        CU_ASSERT(n > 0);
        CU_ASSERT_EQUAL(xqc_moqt_message_decode(
            buf, n,
            XQC_MOQT_MSG_SUBSCRIBE, &decoded), -XQC_EILLEGAL_FRAME);
    }
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_GOAWAY;
    m.uri.iov_len = 1;
    short_buf[0] = 0xaa;
    CU_ASSERT_EQUAL(xqc_moqt_message_encode(&m, m.type, short_buf,
                                            sizeof(short_buf)), -XQC_EPARAM);
    CU_ASSERT_EQUAL(short_buf[0], 0xaa);
    m.uri.iov_len = XQC_MOQT_GOAWAY_MAX_URI + 1;
    CU_ASSERT_EQUAL(xqc_moqt_message_encode(&m, m.type, NULL, 0), -XQC_EPARAM);
    m.type = XQC_MOQT_MSG_FETCH_OK;
    m.end_of_track = 2;
    CU_ASSERT_EQUAL(xqc_moqt_message_encode(&m, m.type, NULL, 0), -XQC_EPARAM);
    m.type = XQC_MOQT_MSG_SETUP;
    CU_ASSERT_EQUAL(xqc_moqt_message_encode(&m, m.type, NULL, 0), -XQC_EPARAM);
    xqc_usec_t deadline = 123;
    CU_ASSERT_EQUAL(xqc_moqt_retry_deadline(0, 100, &deadline), -XQC_EPARAM);
    CU_ASSERT_EQUAL(deadline, 123);
    CU_ASSERT_EQUAL(xqc_moqt_retry_deadline(1, 100, &deadline), XQC_OK);
    CU_ASSERT_EQUAL(deadline, 100);
    CU_ASSERT_EQUAL(xqc_moqt_retry_deadline(501, 100, &deadline), XQC_OK);
    CU_ASSERT_EQUAL(deadline, 500100);
    CU_ASSERT_EQUAL(xqc_moqt_retry_deadline(UINT64_MAX, 100, &deadline),
                    -XQC_ELIMIT);
}

void
xqc_test_moqt_early_request(void)
{
    /* Draft-22 section 6.3: the request may overtake peer SETUP. */
    for (unsigned fin = 0; fin <= 1; fin++) {
        moqt_fixture_t f;
        xqc_test_moqt_init(&f, 1);
        f.session->callbacks.on_authorize = xqc_test_moqt_authorize_notify;
        f.session->callbacks.on_message = xqc_test_moqt_message_notify;
        xqc_test_moqt_start(&f);
        xqc_moqt_stream_t *st = xqc_test_moqt_request_stream(&f);
        CU_ASSERT_PTR_NOT_NULL_FATAL(st);
        CU_ASSERT_FALSE(st->discarded);
        xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE};
        CU_ASSERT_EQUAL(xqc_test_moqt_request_input(st, &m, m.type, fin),
                        XQC_OK);
        CU_ASSERT_EQUAL(f.messages, 0);
        CU_ASSERT(st->rx.data_len > 0);
        CU_ASSERT_EQUAL(xqc_test_moqt_options(xqc_test_moqt_incoming(&f),
                                              NULL, 0), XQC_OK);
        CU_ASSERT_EQUAL(f.ready, 1);
        CU_ASSERT_EQUAL(f.messages, 1);
        CU_ASSERT_EQUAL(st->rx.data_len, 0);
        CU_ASSERT_EQUAL(st->rx_fin, fin);
        xqc_test_moqt_destroy(&f);
    }
}

void
xqc_test_moqt_early_request_errors(void)
{
    for (unsigned reject = 0; reject < 3; reject++) {
        moqt_fixture_t f;
        xqc_test_moqt_init(&f, 1);
        f.session->callbacks.on_authorize = xqc_test_moqt_authorize_notify;
        f.session->callbacks.on_message = xqc_test_moqt_message_notify;
        xqc_test_moqt_start(&f);
        xqc_moqt_stream_t *st = xqc_test_moqt_request_stream(&f);
        CU_ASSERT_PTR_NOT_NULL_FATAL(st);
        xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE};
        CU_ASSERT_EQUAL(xqc_test_moqt_request_input(st, &m, m.type, 0),
                        XQC_OK);
        CU_ASSERT_EQUAL(f.messages, 0);
        if (reject == 0) {
            f.reject = XQC_MOQT_UNAUTHORIZED;
            xqc_test_moqt_options(xqc_test_moqt_incoming(&f), NULL, 0);
            CU_ASSERT_EQUAL(f.error, XQC_MOQT_UNAUTHORIZED);
        } else if (reject == 1) {
            xqc_moqt_session_timeout(f.session->timer,
                                      f.session->setup_deadline, f.session);
            CU_ASSERT_EQUAL(f.error, XQC_MOQT_CONTROL_MESSAGE_TIMEOUT);
        } else {
            f.close_in_ready = 1;
            xqc_test_moqt_options(xqc_test_moqt_incoming(&f), NULL, 0);
            CU_ASSERT_TRUE(f.session->closed);
        }
        CU_ASSERT_EQUAL(f.messages, 0);
        xqc_test_moqt_destroy(&f);
    }
}

void
xqc_test_moqt_request_ids(void)
{
    for (xqc_int_t server = 0; server <= 1; server++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, server);
        xqc_moqt_message_t m = {0};
        m.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
        xqc_moqt_request_t *a = xqc_moqt_request_open(f.session, &m);
        xqc_moqt_request_t *b = xqc_moqt_request_open(f.session, &m);
        CU_ASSERT_PTR_NOT_NULL_FATAL(a);
        CU_ASSERT_PTR_NOT_NULL_FATAL(b);
        CU_ASSERT_EQUAL(xqc_moqt_request_id(a), server);
        CU_ASSERT_EQUAL(xqc_moqt_request_id(b), server + 2);
        uint64_t ids[] = {6, 0, 4, 2};
        for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
            m.request_id = ids[i] + !server;
            CU_ASSERT_EQUAL(
                xqc_test_moqt_request_input(xqc_test_moqt_request_stream(&f),
                                            &m, m.type, 0), XQC_OK);
        }
        CU_ASSERT_EQUAL(f.messages, 4);
        CU_ASSERT_EQUAL(f.session->request_id_ranges, 1);
        CU_ASSERT(
            xqc_test_moqt_request_input(xqc_test_moqt_request_stream(&f), &m,
                                        m.type, 0) < 0);
        CU_ASSERT_EQUAL(f.error, XQC_MOQT_INVALID_REQUEST_ID);
        xqc_test_moqt_destroy(&f);
        CU_ASSERT_EQUAL(f.request_closed, 6);
    }
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 1);
    xqc_moqt_message_t m = {0};
    m.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
    m.request_id = 1;
    CU_ASSERT(
        xqc_test_moqt_request_input(xqc_test_moqt_request_stream(&f), &m,
                                    m.type, 0) < 0);
    CU_ASSERT_EQUAL(f.error, XQC_MOQT_INVALID_REQUEST_ID);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_request_updates(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    f.session->peer_limits.max_request_updates = 2;
    xqc_moqt_message_t m = {0}, reply = {0};
    m.type = XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE;
    m.track_namespace.count = 1;
    m.track_namespace.fields[0] = (struct iovec){"a", 1};
    xqc_moqt_request_t *r = xqc_moqt_request_open(f.session, &m);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    reply.type = XQC_MOQT_MSG_REQUEST_OK;
    CU_ASSERT_EQUAL(
        xqc_test_moqt_request_input(r->stream, &reply, m.type, 0), XQC_OK);
    m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
    uint8_t prefix[] = {1, 1, 'b'};
    m.parameter_count = 1;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_TRACK_NAMESPACE_PREFIX, sizeof(prefix), prefix};
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &m), XQC_OK);
    prefix[2] = 'c';
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &m), XQC_OK);
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &m), -XQC_EAGAIN);
    CU_ASSERT_EQUAL(r->pending_sent_updates, 2);
    for (unsigned i = 0; i < 2; i++) {
        CU_ASSERT_EQUAL(
            xqc_test_moqt_request_input(r->stream, &reply, m.type, 0), XQC_OK);
        CU_ASSERT_EQUAL(f.last_id, 2 + i * 2);
        xqc_moqt_message_t *state = (void *)r->state->data;
        CU_ASSERT_EQUAL(*(char *)state->track_namespace.fields[0].iov_base,
                        'b' + i);
    }
    CU_ASSERT_EQUAL(xqc_moqt_request_id(r), 0);
    CU_ASSERT_EQUAL(r->pending_sent_updates, 0);
    CU_ASSERT_EQUAL(r->response_deadline, 0);
    CU_ASSERT_EQUAL(xqc_moqt_request_finish(r), XQC_OK);
    CU_ASSERT_TRUE(r->stream->tx_fin_sent);
    CU_ASSERT_FALSE(r->stream->rx_fin);
    xqc_moqt_request_cancel(r, XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_TRUE(r->stream->transport_stream->stream_flag
                   & XQC_STREAM_FLAG_STOP_SENDING_SENT);
    xqc_test_moqt_destroy(&f);
    CU_ASSERT_EQUAL(f.request_closed, 1);

    xqc_test_moqt_request_init(&f, 1);
    f.session->local_limits.max_request_updates = 1;
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE;
    m.track_namespace.count = 1;
    m.track_namespace.fields[0] = (struct iovec){"a", 1};
    xqc_moqt_stream_t *st = xqc_test_moqt_request_stream(&f);
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(st, &m, m.type, 0), XQC_OK);
    r = &st->state.request;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &reply), XQC_OK);
    m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
    m.request_id = 2;
    m.parameter_count = 1;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_TRACK_NAMESPACE_PREFIX, sizeof(prefix), prefix};
    CU_ASSERT_EQUAL(
        xqc_test_moqt_request_input(st, &m, r->initial_type, 0), XQC_OK);
    CU_ASSERT_EQUAL(f.candidate_prefix, 'c');
    CU_ASSERT_EQUAL(r->pending_received_updates, 1);
    xqc_moqt_message_t *state = (void *)r->state->data;
    CU_ASSERT_EQUAL(*(char *)state->track_namespace.fields[0].iov_base, 'a');
    m.request_id = 4;
    CU_ASSERT(xqc_test_moqt_request_input(st, &m, r->initial_type, 0) < 0);
    CU_ASSERT_EQUAL(f.error, XQC_MOQT_TOO_MANY_REQUEST_UPDATES);
    xqc_test_moqt_destroy(&f);

    /* Authorization sees all queued deltas; ACK commits them FIFO. */
    xqc_test_moqt_request_init(&f, 1);
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE;
    m.track_namespace.count = 1;
    m.track_namespace.fields[0] = (struct iovec){"a", 1};
    st = xqc_test_moqt_request_stream(&f);
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(st, &m, m.type, 0), XQC_OK);
    r = &st->state.request;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &reply), XQC_OK);
    m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
    m.parameter_count = 1;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_TRACK_NAMESPACE_PREFIX, sizeof(prefix), prefix};
    m.request_id = 2;
    CU_ASSERT_EQUAL(
        xqc_test_moqt_request_input(st, &m, r->initial_type, 0), XQC_OK);
    uint8_t token[] = {3, 3, 0, 't'};
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_AUTHORIZATION_TOKEN, sizeof(token), token};
    m.request_id = 4;
    CU_ASSERT_EQUAL(
        xqc_test_moqt_request_input(st, &m, r->initial_type, 0), XQC_OK);
    CU_ASSERT_EQUAL(f.candidate_prefix, 'c');
    CU_ASSERT_EQUAL(r->pending_received_updates, 2);
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &reply), XQC_OK);
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &reply), XQC_OK);
    CU_ASSERT_EQUAL(r->pending_received_updates, 0);
    state = (void *)r->state->data;
    CU_ASSERT_EQUAL(*(char *)state->track_namespace.fields[0].iov_base, 'c');
    CU_ASSERT_EQUAL(state->parameter_count, 1);
    CU_ASSERT_EQUAL(state->parameters[0].type,
                    XQC_MOQT_PARAM_AUTHORIZATION_TOKEN);
    xqc_test_moqt_destroy(&f);

}

void
xqc_test_moqt_request_errors(void)
{
    for (xqc_int_t scenario = 0; scenario < 7; scenario++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 1);
        xqc_moqt_message_t m = {0};
        m.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
        if (scenario == 0) {
            f.session->callbacks.on_authorize = NULL;
        } else if (scenario == 1) {
            f.session->callbacks.on_message = NULL;
        } else if (scenario == 2) {
            m.track_namespace.count = 1;
            m.track_namespace.fields[0] = (struct iovec){".session", 8};
        } else if (scenario == 3) {
            f.request_reject = XQC_MOQT_REQUEST_UNAUTHORIZED;
        } else if (scenario == 4) {
            f.cancel_in_authorize = 1;
        } else if (scenario == 5) {
            f.cancel_in_message = 1;
        } else {
            f.reject_request = 1;
            f.request_reject = XQC_MOQT_REQUEST_INTERNAL_ERROR;
        }
        xqc_moqt_stream_t *st = xqc_test_moqt_request_stream(&f);
        CU_ASSERT_EQUAL(xqc_test_moqt_request_input(st, &m, m.type, 0), XQC_OK);
        CU_ASSERT_FALSE(f.session->closed);
        CU_ASSERT_TRUE(st->state.request.failed);
        CU_ASSERT_EQUAL(f.messages, scenario == 5);
        xqc_test_moqt_destroy(&f);
        CU_ASSERT_EQUAL(f.request_closed, 1);
    }
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_message_t m = {0}, error = {0};
    m.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
    xqc_moqt_request_t *camera = xqc_moqt_request_open(f.session, &m);
    xqc_moqt_request_t *audio = xqc_moqt_request_open(f.session, &m);
    CU_ASSERT_PTR_NOT_NULL_FATAL(camera);
    CU_ASSERT_PTR_NOT_NULL_FATAL(audio);
    error.type = XQC_MOQT_MSG_REQUEST_ERROR;
    error.error.code = 0x9d;
    error.retry_interval = 501;
    CU_ASSERT_EQUAL(
        xqc_test_moqt_request_input(camera->stream, &error, m.type, 1), XQC_OK);
    CU_ASSERT_EQUAL(f.last_code, 0x9d);
    CU_ASSERT_EQUAL(f.last_normalized, XQC_MOQT_REQUEST_INTERNAL_ERROR);
    CU_ASSERT_FALSE(f.session->closed);
    m.type = XQC_MOQT_MSG_REQUEST_OK;
    CU_ASSERT_EQUAL(
        xqc_test_moqt_request_input(audio->stream, &m, audio->initial_type, 0),
        XQC_OK);
    CU_ASSERT_TRUE(audio->established);
    CU_ASSERT_FALSE(audio->failed);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_request_lifecycle(void)
{
    /* Draft-22 6.4.2.2, 9.9 and 12.4: FIN, DONE and reset are distinct. */
    moqt_fixture_t f;
    xqc_moqt_message_t message = {0}, reply = {0};
    xqc_test_moqt_request_init(&f, 0);
    message.type = XQC_MOQT_MSG_SUBSCRIBE;
    xqc_moqt_request_t *r = xqc_moqt_request_open(f.session, &message);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    reply.type = XQC_MOQT_MSG_SUBSCRIBE_OK;
    CU_ASSERT_EQUAL(
        xqc_test_moqt_request_input(r->stream, &reply, message.type, 0),
        XQC_OK);
    reply.type = XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY;
    CU_ASSERT_EQUAL(
        xqc_test_moqt_request_input(r->stream, &reply, message.type, 0),
        XQC_OK);
    CU_ASSERT_EQUAL(r->pending_sent_updates, 0);
    reply.type = XQC_MOQT_MSG_PUBLISH_DONE;
    /* Independent GREASE value, draft-22 section 13. */
    reply.error.code = 0x9d;
    CU_ASSERT_EQUAL(
        xqc_test_moqt_request_input(r->stream, &reply, message.type, 1),
        XQC_OK);
    CU_ASSERT_TRUE(r->done_received);
    CU_ASSERT_TRUE(r->stream->tx_fin_sent);
    CU_ASSERT_EQUAL(r->error.context, XQC_MOQT_ERROR_PUBLISH_DONE);
    CU_ASSERT_EQUAL(r->error.code, 0x9d);
    CU_ASSERT_EQUAL(r->error.normalized_code, XQC_MOQT_PUBLISH_INTERNAL_ERROR);
    CU_ASSERT_FALSE(f.session->closed);
    xqc_test_moqt_destroy(&f);

    for (xqc_int_t scenario = 0; scenario < 4; scenario++) {
        xqc_test_moqt_request_init(&f, 0);
        message.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
        r = xqc_moqt_request_open(f.session, &message);
        CU_ASSERT_PTR_NOT_NULL_FATAL(r);
        if (scenario == 0) {
            xqc_moqt_session_timeout(f.session->timer, r->response_deadline,
                                     f.session);
        } else if (scenario == 1) {
            CU_ASSERT_EQUAL(xqc_moqt_stream_input(r->stream, NULL, 0, 1),
                            XQC_OK);
        } else if (scenario == 2) {
            uint8_t partial = XQC_MOQT_MSG_REQUEST_OK;
            CU_ASSERT_EQUAL(xqc_moqt_stream_input(r->stream, &partial, 1, 1),
                            XQC_OK);
        } else {
            xqc_moqt_stream_callbacks.stream_stop_sending_notify(
                r->stream->transport_stream, 0x9d, r->stream);
            CU_ASSERT_EQUAL(r->error.normalized_code,
                            XQC_MOQT_RESET_INTERNAL_ERROR);
        }
        CU_ASSERT_TRUE(r->stream->discarded);
        CU_ASSERT_EQUAL(xqc_moqt_stream_flush(r->stream), XQC_OK);
        CU_ASSERT_FALSE(f.session->closed);
        xqc_test_moqt_destroy(&f);
    }

    /* A failed update terminates the publisher with UPDATE_FAILED + FIN. */
    xqc_test_moqt_request_init(&f, 1);
    f.reply = 1;
    message.type = XQC_MOQT_MSG_SUBSCRIBE;
    xqc_moqt_stream_t *st = xqc_test_moqt_request_stream(&f);
    CU_ASSERT_EQUAL(
        xqc_test_moqt_request_input(st, &message, message.type, 0), XQC_OK);
    r = &st->state.request;
    CU_ASSERT_EQUAL(xqc_moqt_request_finish(r), -XQC_EPARAM);
    reply.type = XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &reply), XQC_OK);
    f.request_reject = XQC_MOQT_REQUEST_UNAUTHORIZED;
    message.type = XQC_MOQT_MSG_REQUEST_UPDATE;
    message.request_id = 2;
    CU_ASSERT_EQUAL(
        xqc_test_moqt_request_input(st, &message, r->initial_type, 0), XQC_OK);
    CU_ASSERT_TRUE(r->failed && r->done_sent && st->tx_fin_sent);
    CU_ASSERT_FALSE(f.session->closed);
    xqc_test_moqt_destroy(&f);

    /* Request GOAWAY drains only this request, and prevents more updates. */
    xqc_test_moqt_request_init(&f, 1);
    f.reply = 1;
    message.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
    message.request_id = 0;
    st = xqc_test_moqt_request_stream(&f);
    CU_ASSERT_EQUAL(
        xqc_test_moqt_request_input(st, &message, message.type, 0), XQC_OK);
    r = &st->state.request;
    xqc_memzero(&reply, sizeof(reply));
    reply.type = XQC_MOQT_MSG_GOAWAY;
    reply.timeout_ms = UINT64_MAX;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &reply), -XQC_ELIMIT);
    reply.timeout_ms = 1;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &reply), XQC_OK);
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &reply), -XQC_EPARAM);
    xqc_moqt_session_timeout(f.session->timer, r->goaway_deadline, f.session);
    CU_ASSERT_TRUE(st->discarded);
    CU_ASSERT_FALSE(f.session->closed);
    xqc_test_moqt_destroy(&f);

    xqc_test_moqt_request_init(&f, 0);
    message.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
    r = xqc_moqt_request_open(f.session, &message);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    reply.type = XQC_MOQT_MSG_REQUEST_OK;
    CU_ASSERT_EQUAL(
        xqc_test_moqt_request_input(r->stream, &reply, message.type, 0),
        XQC_OK);
    reply.type = XQC_MOQT_MSG_GOAWAY;
    CU_ASSERT_EQUAL(
        xqc_test_moqt_request_input(r->stream, &reply, message.type, 0),
        XQC_OK);
    CU_ASSERT_TRUE(r->goaway_received);
    message.type = XQC_MOQT_MSG_REQUEST_UPDATE;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &message), -XQC_EAGAIN);
    CU_ASSERT(
        xqc_test_moqt_request_input(r->stream, &reply, r->initial_type, 0) < 0);
    CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
    xqc_test_moqt_destroy(&f);

}

void
xqc_test_moqt_request_validation(void)
{
    /* Token errors precede application policy; zero filter credit rejects. */
    const struct {
        uint64_t    parameter;
        uint8_t     value[5];
        size_t      len;
        uint64_t    session_error;
        uint64_t    request_error;
    } cases[] = {
        {XQC_MOQT_PARAM_AUTHORIZATION_TOKEN, {0}, 1,
         XQC_MOQT_KEY_VALUE_FORMATTING_ERROR, 0},
        {XQC_MOQT_PARAM_AUTHORIZATION_TOKEN, {4, 1, 0, 0, 'x'}, 5,
         XQC_MOQT_AUTH_TOKEN_CACHE_OVERFLOW, 0},
        {XQC_MOQT_PARAM_AUTHORIZATION_TOKEN, {2, 2, 0}, 3,
         XQC_MOQT_UNKNOWN_AUTH_TOKEN_ALIAS, 0},
        {XQC_MOQT_PARAM_SUBGROUP_FILTER, {0}, 1, 0,
         XQC_MOQT_REQUEST_INVALID_FILTER},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 1);
        xqc_moqt_message_t m = {0};
        m.type = XQC_MOQT_MSG_SUBSCRIBE;
        m.parameter_count = 1;
        m.parameters[0] = (xqc_moq_message_parameter_t){cases[i].parameter,
            cases[i].len, (uint8_t *)cases[i].value};
        xqc_moqt_stream_t *st = xqc_test_moqt_request_stream(&f);
        xqc_int_t ret = xqc_test_moqt_request_input(st, &m, m.type, 0);
        CU_ASSERT_EQUAL(ret == XQC_OK, cases[i].session_error == 0);
        CU_ASSERT_EQUAL(f.error, cases[i].session_error);
        CU_ASSERT_EQUAL(st->state.request.error.code, cases[i].request_error);
        CU_ASSERT_EQUAL(f.authorized, 0);
        CU_ASSERT_EQUAL(f.messages, 0);
        xqc_test_moqt_destroy(&f);
    }
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 1);
    xqc_moqt_message_t m = {0};
    uint8_t token[] = {3, 3, 0, 'a'};
    m.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
    m.parameter_count = 2;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_AUTHORIZATION_TOKEN, sizeof(token), token};
    m.parameters[1] = m.parameters[0];
    xqc_moqt_stream_t *st = xqc_test_moqt_request_stream(&f);
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(st, &m, m.type, 0), XQC_OK);
    CU_ASSERT_EQUAL(st->state.request.error.code,
                    XQC_MOQT_REQUEST_MALFORMED_AUTH_TOKEN);
    CU_ASSERT_FALSE(f.session->closed);
    m.parameter_count = 1;
    m.request_id = 2;
    CU_ASSERT_EQUAL(
        xqc_test_moqt_request_input(xqc_test_moqt_request_stream(&f), &m,
                                    m.type, 0), XQC_OK);
    CU_ASSERT_EQUAL(f.authorized, 1);
    CU_ASSERT_EQUAL(f.messages, 1);
    xqc_test_moqt_destroy(&f);

    xqc_test_moqt_request_init(&f, 0);
    m.parameter_count = 0;
    size_t used = f.session->buffered_bytes;
    f.session->config.max_buffered_bytes = used;
    CU_ASSERT_PTR_NULL(xqc_moqt_request_open(f.session, &m));
    CU_ASSERT_EQUAL(f.session->buffered_bytes, used);
    f.session->config.max_buffered_bytes = XQC_MOQT_DEFAULT_BUFFERED_BYTES;
    xqc_moqt_request_t *r = xqc_moqt_request_open(f.session, &m);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    xqc_moqt_message_t reply = {0};
    reply.type = XQC_MOQT_MSG_REQUEST_OK;
    CU_ASSERT_EQUAL(
        xqc_test_moqt_request_input(r->stream, &reply, m.type, 0), XQC_OK);
    used = f.session->buffered_bytes;
    f.session->config.max_buffered_bytes = used;
    m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &m), -XQC_EMALLOC);
    CU_ASSERT_EQUAL(r->pending_sent_updates, 0);
    CU_ASSERT_EQUAL(xqc_moqt_request_finish(r), -XQC_EMALLOC);
    CU_ASSERT_FALSE(f.session->closed);
    f.session->config.max_buffered_bytes = XQC_MOQT_DEFAULT_BUFFERED_BYTES;
    m.track_namespace.count = SIZE_MAX;
    m.track_name = (struct iovec){NULL, SIZE_MAX};
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &m), XQC_OK);
    r->stream->transport_stream->stream_state_send
        = XQC_SEND_STREAM_ST_RESET_SENT;
    CU_ASSERT(xqc_moqt_request_send(r, &m) < 0);
    CU_ASSERT_TRUE(r->stream->discarded);
    CU_ASSERT_FALSE(f.session->closed);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_tracks(void)
{
    /* Draft-22 3.1/3.1.3: shared Track, independent subscriptions/aliases. */
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    uint8_t namespace[] = {'a', 0, 'b'};
    xqc_moqt_message_t m = {0}, ok = {0};
    m.type = XQC_MOQT_MSG_PUBLISH;
    m.track_namespace.count = 1;
    m.track_namespace.fields[0] = (struct iovec){namespace, sizeof(namespace)};
    m.track_name = (struct iovec){"camera", 6};
    m.track_alias = UINT64_MAX;
    xqc_moqt_request_t *a = xqc_moqt_request_open(f.session, &m);
    xqc_moqt_request_t *b = xqc_moqt_request_open(f.session, &m);
    CU_ASSERT_PTR_NOT_NULL_FATAL(a);
    CU_ASSERT_PTR_NOT_NULL_FATAL(b);
    xqc_moqt_subscription_t *sa = xqc_moqt_request_subscription(a);
    xqc_moqt_subscription_t *sb = xqc_moqt_request_subscription(b);
    CU_ASSERT_PTR_NOT_NULL_FATAL(sa);
    CU_ASSERT_PTR_NOT_NULL_FATAL(sb);
    CU_ASSERT_PTR_EQUAL(sa->track, sb->track);
    CU_ASSERT_EQUAL(sa->track->references, 2);
    CU_ASSERT_NOT_EQUAL(sa->track_alias, sb->track_alias);
    CU_ASSERT_EQUAL(sa->track_alias, 0);
    CU_ASSERT_EQUAL(sb->track_alias, 1);
    CU_ASSERT_EQUAL(m.track_alias, UINT64_MAX);
    CU_ASSERT_EQUAL(((xqc_moqt_message_t *)a->state->data)->track_alias, 0);
    ok.type = XQC_MOQT_MSG_REQUEST_OK;
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(a->stream, &ok, m.type, 0),
                    XQC_OK);
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(b->stream, &ok, m.type, 0),
                    XQC_OK);
    xqc_moqt_location_t location = {0};
    CU_ASSERT_TRUE(xqc_moqt_subscription_is_matching(sa, &location));
    CU_ASSERT_TRUE(xqc_moqt_subscription_is_matching(sb, &location));
    CU_ASSERT_EQUAL(sa->subscriber_priority, XQC_MOQT_DEFAULT_PRIORITY);
    CU_ASSERT_EQUAL(sa->group_order, XQC_MOQT_GROUP_ASCENDING);
    /* Opposite publisher direction is a distinct Track, even with same name. */
    m.request_id = 1;
    m.track_alias = sa->track_alias;
    xqc_moqt_stream_t *st = xqc_test_moqt_request_stream(&f);
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(st, &m, m.type, 0), XQC_OK);
    CU_ASSERT_PTR_NOT_EQUAL(st->state.request.subscription->track, sa->track);
    CU_ASSERT_EQUAL(xqc_moqt_request_send(&st->state.request, &ok), XQC_OK);
    CU_ASSERT_FALSE(f.session->closed);
    xqc_moqt_request_cancel(a, XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_PTR_NULL(a->subscription);
    CU_ASSERT_TRUE(xqc_moqt_subscription_is_matching(sb, &location));
    xqc_moqt_subscription_release(a);
    CU_ASSERT_EQUAL(sb->track->references, 1);
    CU_ASSERT_PTR_NULL(xqc_moqt_request_subscription(a));
    CU_ASSERT_PTR_NULL(xqc_moqt_request_subscription(NULL));
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_track_errors(void)
{
    for (xqc_int_t publish = 0; publish <= 1; publish++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 0);
        xqc_moqt_message_t m = {0}, ok = {0};
        m.type = publish ? XQC_MOQT_MSG_PUBLISH : XQC_MOQT_MSG_SUBSCRIBE;
        m.track_name = (struct iovec){"a", 1};
        m.track_alias = 7;
        ok.type = publish ? XQC_MOQT_MSG_REQUEST_OK : XQC_MOQT_MSG_SUBSCRIBE_OK;
        ok.track_alias = 7;
        xqc_moqt_track_t *track = NULL;
        for (unsigned i = 0; i < 3; i++) {
            if (i == 2) {
                m.track_name = (struct iovec){"b", 1};
            }
            xqc_moqt_request_t *r;
            xqc_int_t ret;
            if (publish) {
                m.request_id = 1 + i * XQC_MOQT_REQUEST_ID_STEP;
                xqc_moqt_stream_t *st = xqc_test_moqt_request_stream(&f);
                ret = xqc_test_moqt_request_input(st, &m, m.type, 0);
                r = &st->state.request;
                if (i != 2) {
                    CU_ASSERT_EQUAL(ret, XQC_OK);
                    ret = xqc_moqt_request_send(r, &ok);
                }
            } else {
                r = xqc_moqt_request_open(f.session, &m);
                CU_ASSERT_PTR_NOT_NULL_FATAL(r);
                ret = xqc_test_moqt_request_input(r->stream, &ok, m.type, 0);
            }
            if (i == 2) {
                CU_ASSERT(ret < 0);
                CU_ASSERT_EQUAL(f.error, XQC_MOQT_DUPLICATE_TRACK_ALIAS);
            } else {
                CU_ASSERT_EQUAL(ret, XQC_OK);
                CU_ASSERT_PTR_NOT_NULL_FATAL(r->subscription);
                if (track != NULL) {
                    CU_ASSERT_PTR_EQUAL(track, r->subscription->track);
                }
                track = r->subscription->track;
            }
        }
        xqc_test_moqt_destroy(&f);
    }
    /* Exhaustion/resource failure must not publish or retain an alias. */
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_message_t m = {0};
    m.type = XQC_MOQT_MSG_PUBLISH;
    f.session->next_track_alias = UINT64_MAX;
    xqc_moqt_request_t *r = xqc_moqt_request_open(f.session, &m);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    CU_ASSERT_EQUAL(r->subscription->track_alias, UINT64_MAX);
    CU_ASSERT_TRUE(f.session->track_aliases_exhausted);
    CU_ASSERT_PTR_NULL(xqc_moqt_request_open(f.session, &m));
    xqc_test_moqt_destroy(&f);

    xqc_test_moqt_request_init(&f, 0);
    size_t budget = f.session->config.max_buffered_bytes;
    f.session->config.max_buffered_bytes = f.session->buffered_bytes
        + sizeof(xqc_moqt_message_t) + sizeof(xqc_var_buf_t);
    CU_ASSERT_PTR_NULL(xqc_moqt_request_open(f.session, &m));
    CU_ASSERT_PTR_NULL(f.session->tracks);
    CU_ASSERT_PTR_NULL(f.session->subscriptions);
    f.session->config.max_buffered_bytes = budget;
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_subscription_filters(void)
{
    /* Independent section 9.20.9 values; Largest Object is {5,7}. */
    const struct {
        uint8_t                wire[5];
        size_t                 len;
        xqc_moqt_location_t    start;
        xqc_moqt_location_t    end;
        xqc_int_t              exclusive;
    } cases[] = {
        {{0}, 1, {0, 0}, {UINT64_MAX, UINT64_MAX}, 0},
        {{1, 2}, 2, {4, 0}, {UINT64_MAX, UINT64_MAX}, 0},
        {{1, 10}, 2, {0, 0}, {UINT64_MAX, UINT64_MAX}, 0},
        {{2, 3, 4}, 3, {3, 4}, {UINT64_MAX, UINT64_MAX}, 0},
        {{3, 3, 4, 2}, 4, {3, 4}, {5, UINT64_MAX}, 0},
        {{4, 3, 4, 2, 9}, 5, {3, 4}, {5, 9}, 0},
        {{5}, 1, {5, 7}, {UINT64_MAX, UINT64_MAX}, 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 0);
        uint8_t largest[] = {5, 7}, order = XQC_MOQT_GROUP_ASCENDING;
        xqc_moqt_message_t m = {0}, ok = {0};
        m.type = XQC_MOQT_MSG_SUBSCRIBE;
        m.parameter_count = 1;
        m.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_LOCATION_FILTER, cases[i].len,
            (uint8_t *)cases[i].wire};
        m.parameter_count = 2;
        m.parameters[1] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_GROUP_ORDER, sizeof(order), &order};
        xqc_moqt_request_t *r = xqc_moqt_request_open(f.session, &m);
        CU_ASSERT_PTR_NOT_NULL_FATAL(r);
        ok.type = XQC_MOQT_MSG_SUBSCRIBE_OK;
        ok.parameter_count = 1;
        ok.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_LARGEST_OBJECT, sizeof(largest), largest};
        CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &ok, m.type, 0),
                        XQC_OK);
        xqc_moqt_subscription_t *sub = r->subscription;
        CU_ASSERT_EQUAL(sub->start.group_id, cases[i].start.group_id);
        CU_ASSERT_EQUAL(sub->start.object_id, cases[i].start.object_id);
        CU_ASSERT_EQUAL(sub->end.group_id, cases[i].end.group_id);
        CU_ASSERT_EQUAL(sub->end.object_id, cases[i].end.object_id);
        CU_ASSERT_EQUAL(sub->start_exclusive, cases[i].exclusive);
        CU_ASSERT_EQUAL(sub->group_order, order);
        CU_ASSERT_EQUAL(xqc_moqt_subscription_is_matching(sub, &sub->start),
                        !cases[i].exclusive);
        /* Largest updates do not move an already committed relative filter. */
        largest[0] = 10;
        ok.type = XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY;
        CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &ok, m.type, 0),
                        XQC_OK);
        CU_ASSERT_EQUAL(sub->track->largest.group_id, 10);
        CU_ASSERT_EQUAL(sub->start.group_id, cases[i].start.group_id);
        CU_ASSERT_EQUAL(r->pending_sent_updates, 0);
        xqc_test_moqt_destroy(&f);
    }
}

void
xqc_test_moqt_subscription_updates(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_message_t m = {0}, ok = {0};
    m.type = XQC_MOQT_MSG_PUBLISH;
    /* 10.7: default priority/group order inside Immutable Properties. */
    uint8_t properties[] = {0x02, 1, 0x09, 4, 0x0e, 7, 0x14, 2};
    m.properties = (struct iovec){properties, sizeof(properties)};
    xqc_moqt_request_t *r = xqc_moqt_request_open(f.session, &m);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    ok.type = XQC_MOQT_MSG_REQUEST_OK;
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &ok, m.type, 0),
                    XQC_OK);
    xqc_moqt_subscription_t *sub = r->subscription;
    CU_ASSERT_EQUAL(sub->track->publisher_priority, 7);
    CU_ASSERT_EQUAL(sub->group_order, XQC_MOQT_GROUP_DESCENDING);
    uint8_t pause = 0, resume = 1;
    xqc_moqt_message_t update = {0};
    update.type = XQC_MOQT_MSG_REQUEST_UPDATE;
    update.parameter_count = 1;
    update.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FORWARD, sizeof(pause), &pause};
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &update), XQC_OK);
    update.parameters[0].value = &resume;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &update), XQC_OK);
    CU_ASSERT_TRUE(sub->forward);
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &ok,
                                                XQC_MOQT_MSG_REQUEST_UPDATE, 0),
                    XQC_OK);
    CU_ASSERT_FALSE(sub->forward);
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &ok,
                                                XQC_MOQT_MSG_REQUEST_UPDATE, 0),
                    XQC_OK);
    CU_ASSERT_TRUE(sub->forward);
    /* Only the new filter is resolved using the OK's latest location. */
    uint8_t filter[] = {1, 2}, largest[] = {9, 4}, priority = 3;
    update.parameter_count = 2;
    update.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_SUBSCRIBER_PRIORITY, sizeof(priority), &priority};
    update.parameters[1] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_LOCATION_FILTER, sizeof(filter), filter};
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &update), XQC_OK);
    ok.parameter_count = 1;
    ok.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_LARGEST_OBJECT, sizeof(largest), largest};
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &ok,
                                                XQC_MOQT_MSG_REQUEST_UPDATE, 0),
                    XQC_OK);
    CU_ASSERT_EQUAL(sub->start.group_id, 8);
    CU_ASSERT_EQUAL(sub->subscriber_priority, priority);
    /* Group Order is immutable after establishment, unlike priority/filter. */
    update.parameter_count = 1;
    update.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_GROUP_ORDER, sizeof(resume), &resume};
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &update), -XQC_EPARAM);
    CU_ASSERT_EQUAL(sub->group_order, XQC_MOQT_GROUP_DESCENDING);
    update.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FORWARD, sizeof(pause), &pause};
    ok.parameter_count = 0;
    update.request_id = 1;
    update.parameters[0].value = &pause;
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &update, m.type, 0),
                    XQC_OK);
    CU_ASSERT_TRUE(sub->forward);
    /* REQUEST_OK cannot carry Track Properties or change committed state. */
    ok.properties = (struct iovec){properties, sizeof(properties)};
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &ok), -XQC_EPARAM);
    CU_ASSERT_TRUE(sub->forward);
    ok.properties.iov_len = 0;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &ok), XQC_OK);
    CU_ASSERT_FALSE(sub->forward);
    CU_ASSERT_EQUAL(sub->track->publisher_priority, 7);
    m.type = XQC_MOQT_MSG_PUBLISH_DONE;
    m.properties.iov_len = 0;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &m), XQC_OK);
    CU_ASSERT_PTR_NULL(r->subscription);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_subscription_boundaries(void)
{
    /* Sections 3.1.3/9.8: two pending PUBLISHes must be checked again at OK. */
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_message_t m = {0}, ok = {0};
    m.type = XQC_MOQT_MSG_PUBLISH;
    m.request_id = 1;
    m.track_name = (struct iovec){"a", 1};
    xqc_moqt_stream_t *a = xqc_test_moqt_request_stream(&f);
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(a, &m, m.type, 0), XQC_OK);
    m.request_id = 3;
    m.track_name.iov_base = "b";
    xqc_moqt_stream_t *b = xqc_test_moqt_request_stream(&f);
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(b, &m, m.type, 0), XQC_OK);
    ok.type = XQC_MOQT_MSG_REQUEST_OK;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(&a->state.request, &ok), XQC_OK);
    CU_ASSERT_EQUAL(xqc_moqt_request_send(&b->state.request, &ok), -XQC_EPARAM);
    CU_ASSERT_EQUAL(f.error, XQC_MOQT_DUPLICATE_TRACK_ALIAS);
    xqc_test_moqt_destroy(&f);

    /* Sections 10.4/10.5/10.7: invalid mutable and immutable preferences. */
    const struct {
        uint8_t     bytes[6];
        size_t      len;
    } properties[] = {
        {{0x0e, 0x81, 0}, 3},
        {{0x22, 0}, 2},
        {{0x0b, 2, 0x22, 3}, 4},
        {{0x0b, 1, 0x22}, 3},
    };
    for (size_t i = 0; i < sizeof(properties) / sizeof(properties[0]); i++) {
        xqc_test_moqt_request_init(&f, 0);
        m.request_id = 1;
        m.properties = (struct iovec){(void *)properties[i].bytes,
                                      properties[i].len};
        CU_ASSERT_PTR_NULL(xqc_moqt_request_open(f.session, &m));
        CU_ASSERT_FALSE(f.session->closed);
        a = xqc_test_moqt_request_stream(&f);
        CU_ASSERT(xqc_test_moqt_request_input(a, &m, m.type, 0) < 0);
        CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
        xqc_test_moqt_destroy(&f);
    }

    /* Section 9.20.9: saturating Next Group and exclusive Next Object. */
    for (xqc_int_t next_object = 0; next_object <= 1; next_object++) {
        xqc_test_moqt_request_init(&f, 0);
        xqc_memzero(&m, sizeof(m));
        xqc_memzero(&ok, sizeof(ok));
        uint8_t filter[] = {next_object ? 5 : 1, 0};
        m.type = XQC_MOQT_MSG_SUBSCRIBE;
        m.parameter_count = 1;
        m.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_LOCATION_FILTER, next_object ? 1 : 2, filter};
        xqc_moqt_request_t *r = xqc_moqt_request_open(f.session, &m);
        CU_ASSERT_PTR_NOT_NULL_FATAL(r);
        uint8_t largest[XQC_VI64_MAX_LEN * 2];
        xqc_int_t n = xqc_vi64_write(largest, largest + sizeof(largest),
                                     UINT64_MAX);
        n += xqc_vi64_write(largest + n, largest + sizeof(largest),
                            UINT64_MAX);
        ok.type = XQC_MOQT_MSG_SUBSCRIBE_OK;
        ok.parameter_count = 1;
        ok.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_LARGEST_OBJECT, n, largest};
        CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &ok, m.type, 0),
                        XQC_OK);
        xqc_moqt_subscription_t *sub = r->subscription;
        CU_ASSERT_EQUAL(sub->start.group_id, UINT64_MAX);
        CU_ASSERT_EQUAL(sub->start.object_id, next_object ? UINT64_MAX : 0);
        CU_ASSERT_EQUAL(xqc_moqt_subscription_is_matching(sub, &sub->end),
                        !next_object);
        /* A lower Largest Object notification cannot move Track backwards. */
        largest[0] = largest[1] = 0;
        ok.type = XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY;
        ok.parameters[0].length = 2;
        CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &ok, m.type, 0),
                        XQC_OK);
        CU_ASSERT_EQUAL(sub->track->largest.group_id, UINT64_MAX);
        CU_ASSERT_EQUAL(sub->track->largest.object_id, UINT64_MAX);
        xqc_test_moqt_destroy(&f);
    }
}

static void
xqc_test_moqt_object_notify(xqc_moqt_subscription_t *sub,
    xqc_moqt_stream_t *stream, const xqc_moqt_object_t *o, void *data)
{
    moqt_fixture_t *f = data;
    CU_ASSERT_PTR_NULL(stream);
    CU_ASSERT_TRUE(o->datagram);
    f->objects++;
    f->object = *o;
    f->object_bytes += o->payload.iov_len;
    f->priority_sum += o->priority;
    if (o->payload.iov_len) {
        CU_ASSERT_EQUAL(*(uint8_t *)o->payload.iov_base, 'x');
    }
    if (f->cancel_in_object) {
        xqc_moqt_request_t *requests[] = {sub->request, f->request};
        for (size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); i++) {
            xqc_moqt_stream_t *st = requests[i]->stream;
            xqc_moqt_request_cancel(requests[i], XQC_MOQT_RESET_CANCELLED);
            xqc_moqt_stream_callbacks.stream_close_notify(
                st->transport_stream, st);
        }
    }
    if (f->close_in_object) {
        xqc_moqt_session_close(f->session, XQC_MOQT_NO_ERROR);
    }
}

static void
xqc_test_moqt_writable(xqc_moqt_session_t *s, xqc_moqt_stream_t *stream,
    void *data)
{
    moqt_fixture_t *f = data;
    CU_ASSERT_PTR_EQUAL(s, f->session);
    CU_ASSERT_PTR_NULL(stream);
    f->writable++;
}

static xqc_moqt_subscription_t *
xqc_test_moqt_object_subscription(moqt_fixture_t *f, const char *name,
    uint64_t alias, xqc_int_t publisher, uint8_t priority)
{
    xqc_moqt_message_t m = {0}, ok = {0};
    uint8_t properties[16];
    xqc_moqt_kv_t kv = {XQC_MOQT_PROPERTY_PUBLISHER_PRIORITY,
                        {.integer = priority}};
    xqc_int_t n = xqc_moqt_kv_encode(&kv, 0, properties, sizeof(properties));
    m.type = publisher ? XQC_MOQT_MSG_PUBLISH : XQC_MOQT_MSG_SUBSCRIBE;
    m.track_name = (struct iovec){(void *)name, strlen(name)};
    if (publisher) {
        m.properties = (struct iovec){properties, n};
    }
    xqc_moqt_request_t *r = xqc_moqt_request_open(f->session, &m);
    CU_ASSERT_PTR_NOT_NULL(r);
    if (r == NULL) {
        return NULL;
    }
    ok.type = publisher ? XQC_MOQT_MSG_REQUEST_OK : XQC_MOQT_MSG_SUBSCRIBE_OK;
    ok.track_alias = alias;
    if (!publisher) {
        ok.properties = (struct iovec){properties, n};
    }
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &ok, m.type, 0),
                    XQC_OK);
    f->session->callbacks.on_object = xqc_test_moqt_object_notify;
    f->session->callbacks.on_writable = xqc_test_moqt_writable;
    return r->subscription;
}

static void
xqc_test_moqt_object_input(moqt_fixture_t *f, uint64_t alias,
    const xqc_moqt_object_t *o)
{
    uint8_t wire[XQC_MOQT_TEST_CAPACITY];
    xqc_int_t n = xqc_moqt_datagram_encode(alias, o, wire, sizeof(wire));
    CU_ASSERT(n > 0);
    if (n > 0) {
        xqc_moqt_datagram_callbacks.datagram_read_notify(f->conn, f->session,
                                                         wire, n, 0);
    }
}

void
xqc_test_moqt_datagram_receive(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_subscription_t *a = xqc_test_moqt_object_subscription(&f, "v", 3,
                                                                   0, 7);
    xqc_moqt_subscription_t *b = xqc_test_moqt_object_subscription(&f, "v", 3,
                                                                   0, 9);
    xqc_test_moqt_object_subscription(&f, "v", 0, 1, 1);
    xqc_test_moqt_object_subscription(&f, "a", 4, 0, 1);
    CU_ASSERT_PTR_EQUAL(a->track, b->track);
    CU_ASSERT_EQUAL(a->publisher_priority, 7);
    CU_ASSERT_EQUAL(b->publisher_priority, 9);
    /* Default priority is per establishing subscription, not mutable Track. */
    const uint8_t wire[] = {0x80, 0x0c, 3, 2, 'x', 0, 'y'};
    size_t streams = f.session->stream_count, used = f.session->buffered_bytes;
    xqc_moqt_datagram_input(f.session, wire, sizeof(wire));
    CU_ASSERT_EQUAL(f.objects, 2);
    CU_ASSERT_EQUAL(f.object_bytes, 6);
    CU_ASSERT_EQUAL(f.priority_sum, 16);
    CU_ASSERT_EQUAL(a->track->largest.group_id, 2);
    CU_ASSERT_EQUAL(a->track->largest.object_id, 0);
    CU_ASSERT_EQUAL(f.session->stream_count, streams);
    CU_ASSERT_EQUAL(f.session->buffered_bytes, used);
    b->forward = 0;
    xqc_moqt_datagram_input(f.session, wire, sizeof(wire));
    CU_ASSERT_EQUAL(f.objects, 3);
    a->start = (xqc_moqt_location_t){2, 1};
    xqc_moqt_datagram_input(f.session, wire, sizeof(wire));
    CU_ASSERT_EQUAL(f.objects, 3);
    a->start.object_id = 0;
    a->start_exclusive = 1;
    xqc_moqt_datagram_input(f.session, wire, sizeof(wire));
    CU_ASSERT_EQUAL(f.objects, 3);
    a->start_exclusive = 0;
    a->established = 0;
    b->stopped = 1;
    xqc_moqt_datagram_input(f.session, wire, sizeof(wire));
    CU_ASSERT_EQUAL(f.objects, 3);
    a->established = 1;
    f.session->callbacks.on_object = NULL;
    xqc_moqt_datagram_input(f.session, wire, sizeof(wire));
    CU_ASSERT_EQUAL(f.objects, 3);
    const uint8_t unknown[] = {0x0c, 99, 2, 'x'};
    const uint8_t padding[] = {0xf0, 0x13, 0x2b, 0x3e, 0x29, 0xff};
    xqc_moqt_datagram_input(f.session, unknown, sizeof(unknown));
    xqc_moqt_datagram_input(f.session, padding, sizeof(padding));
    f.session->ready = 0;
    xqc_moqt_datagram_input(f.session, wire, sizeof(wire));
    CU_ASSERT_FALSE(f.session->closed);
    xqc_moqt_datagram_input(NULL, wire, sizeof(wire));
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_datagram_properties(void)
{
    /* 3.7, 10.7-10.9: malformed properties cancel every same-Track request. */
    const struct {
        uint8_t     bytes[16];
        size_t      len;
    } bad[] = {
        {{0x80}, 1}, {{0xc0, 0x40, 0, 0}, 4},
        {{0x0b, 2, 0x0b, 0}, 4}, {{0x0b, 0, 0, 0}, 4},
        {{0x0b, 1, 0x80}, 3}, {{0x3c, 3}, 2}, {{0x3e, 4}, 2},
        {{0x3c, 0, 0, 0}, 4}, {{0x3e, 0, 0, 0}, 4},
        {{0x0b, 2, 0x3e, 0, 0x33, 0}, 6},
    };
    for (size_t i = 0; i <= sizeof(bad) / sizeof(bad[0]); i++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 0);
        xqc_moqt_subscription_t *a = xqc_test_moqt_object_subscription(
            &f, "v", 1, 0, 7);
        xqc_moqt_subscription_t *b = xqc_test_moqt_object_subscription(
            &f, "v", 2, 0, 7);
        xqc_moqt_subscription_t *other = xqc_test_moqt_object_subscription(
            &f, "a", 3, 0, 7);
        xqc_moqt_request_t *ar = a->request, *br = b->request;
        uint8_t many[(XQC_MOQT_MAX_OPTIONS + 1) * 2] = {0};
        xqc_moqt_object_t o = {.group_id = 2, .object_id = 3, .datagram = 1};
        o.properties = i < sizeof(bad) / sizeof(bad[0])
            ? (struct iovec){(void *)bad[i].bytes, bad[i].len}
            : (struct iovec){many, sizeof(many)};
        xqc_test_moqt_object_input(&f, 1, &o);
        CU_ASSERT_PTR_NULL(ar->subscription);
        CU_ASSERT_PTR_NULL(br->subscription);
        CU_ASSERT_EQUAL(ar->error.code, XQC_MOQT_RESET_MALFORMED_TRACK);
        CU_ASSERT_EQUAL(br->error.code, XQC_MOQT_RESET_MALFORMED_TRACK);
        CU_ASSERT_FALSE(other->stopped);
        CU_ASSERT_FALSE(f.session->closed);
        CU_ASSERT_EQUAL(f.objects, 0);
        o.properties.iov_len = 0;
        xqc_test_moqt_object_input(&f, 3, &o);
        CU_ASSERT_EQUAL(f.objects, 1);
        xqc_test_moqt_destroy(&f);
    }
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_subscription_t *a = xqc_test_moqt_object_subscription(&f, "v", 1,
                                                                   0, 7);
    /* Unknown bytes, timeouts, and immutable KVP stay in the borrowed view. */
    uint8_t props[] = {2, 9, 4, 8, 5, 2, 0x78, 7, 0x31, 1, 2, 0};
    xqc_moqt_object_t o = {.group_id = 2, .object_id = 3, .datagram = 1,
        .properties = {props, sizeof(props)}};
    xqc_test_moqt_object_input(&f, 1, &o);
    CU_ASSERT_EQUAL(f.objects, 1);
    CU_ASSERT_FALSE(a->stopped);
    CU_ASSERT_EQUAL(f.object.properties.iov_len, sizeof(props));
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_datagram_boundaries(void)
{
    for (unsigned scenario = 0; scenario < 10; scenario++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 0);
        xqc_moqt_subscription_t *a = xqc_test_moqt_object_subscription(
            &f, "v", 1, 0, 7);
        xqc_moqt_request_t *r = a->request;
        xqc_moqt_track_t *track = a->track;
        track->references++;
        xqc_moqt_object_t o = {.group_id = 2, .object_id = 3, .datagram = 1};
        uint8_t gap[] = {0x3c, 1}, object_gap[] = {0x3e, 1};
        xqc_test_moqt_object_input(&f, 1, &o);
        switch (scenario) {
        case 0:
            o.status = XQC_MOQT_OBJECT_END_GROUP;
            break;
        case 1:
            o.status = XQC_MOQT_OBJECT_END_TRACK;
            break;
        case 2:
            o.object_id--;
            o.end_of_group = 1;
            break;
        case 3:
            o.group_id++;
            o.properties = (struct iovec){gap, sizeof(gap)};
            break;
        case 4:
            o.object_id++;
            o.properties = (struct iovec){object_gap, sizeof(object_gap)};
            break;
        case 5:
            o.properties = (struct iovec){gap, sizeof(gap)};
            xqc_test_moqt_object_input(&f, 1, &o);
            gap[1] = 0;
            break;
        case 6:
            o.properties = (struct iovec){gap, sizeof(gap)};
            xqc_test_moqt_object_input(&f, 1, &o);
            o.properties.iov_len = 0;
            o.group_id--;
            break;
        case 7:
            o.object_id = 5;
            o.properties = (struct iovec){object_gap, sizeof(object_gap)};
            xqc_test_moqt_object_input(&f, 1, &o);
            o.properties.iov_len = 0;
            o.object_id--;
            break;
        case 8:
            o.end_of_group = 1;
            xqc_test_moqt_object_input(&f, 1, &o);
            o.end_of_group = 0;
            o.object_id++;
            break;
        case 9:
            o.object_id++;
            o.status = XQC_MOQT_OBJECT_END_TRACK;
            xqc_test_moqt_object_input(&f, 1, &o);
            o.status = XQC_MOQT_OBJECT_NORMAL;
            break;
        }
        unsigned delivered = f.objects;
        xqc_test_moqt_object_input(&f, 1, &o);
        CU_ASSERT_EQUAL(f.objects, delivered);
        CU_ASSERT_EQUAL(r->subscription == NULL, scenario < 8);
        CU_ASSERT_FALSE(f.session->closed);
        CU_ASSERT_EQUAL(track->largest.object_id, scenario == 7 ? 5 : 3);
        xqc_moqt_track_release(f.session, track);
        xqc_test_moqt_destroy(&f);
    }
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_subscription_t *a = xqc_test_moqt_object_subscription(&f, "v", 1,
                                                                   0, 7);
    xqc_moqt_object_t o = {.group_id = UINT64_MAX, .object_id = UINT64_MAX,
        .end_of_group = 1, .datagram = 1};
    xqc_test_moqt_object_input(&f, 1, &o);
    CU_ASSERT_EQUAL(f.objects, 1);
    CU_ASSERT_EQUAL(a->track->group.end_object, UINT64_MAX);
    CU_ASSERT_TRUE(a->track->group.end_inclusive);
    o.end_of_group = 0;
    o.group_id = 0;
    o.object_id = 1;
    o.status = XQC_MOQT_OBJECT_END_GROUP;
    xqc_test_moqt_object_input(&f, 1, &o);
    CU_ASSERT_EQUAL(f.objects, 2);
    CU_ASSERT_FALSE(a->track->group.end_inclusive);
    CU_ASSERT_EQUAL(a->track->largest.group_id, UINT64_MAX);
    CU_ASSERT_EQUAL(a->track->largest.object_id, UINT64_MAX);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_datagram_send(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_subscription_t *a = xqc_test_moqt_object_subscription(&f, "v", 0,
                                                                   1, 7);
    xqc_moqt_subscription_t *rx = xqc_test_moqt_object_subscription(&f, "v", 1,
                                                                    0, 7);
    xqc_datagram_record_mss(f.conn);
    xqc_moqt_object_t o = {.group_id = 2, .object_id = 3, .datagram = 1,
        .priority = 7, .payload = {"x", 1}, .payload_length = 1};
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(NULL, &o), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(a, NULL), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(rx, &o), -XQC_EPARAM);
    a->forward = 0;
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(a, &o), -XQC_EPARAM);
    a->forward = 1;
    o.datagram = 0;
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(a, &o), -XQC_EPARAM);
    o.datagram = 1;
    uint8_t bad[] = {0x0b, 1, 0xff};
    o.properties = (struct iovec){bad, sizeof(bad)};
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(a, &o), -XQC_EPARAM);
    o.properties.iov_len = 0;
    size_t mss = f.conn->dgram_mss;
    f.conn->dgram_mss = 1;
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(a, &o), -XQC_EDGRAM_TOO_LARGE);
    f.conn->dgram_mss = mss;
    size_t used = f.session->buffered_bytes;
    f.session->config.max_buffered_bytes = used;
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(a, &o), -XQC_EMALLOC);
    f.session->config.max_buffered_bytes = XQC_MOQT_DEFAULT_BUFFERED_BYTES;
    xqc_var_buf_t *pending = xqc_moqt_buffer_create(f.session, 1,
                                                    sizeof(*pending));
    CU_ASSERT_PTR_NOT_NULL_FATAL(pending);
    pending->data[0] = 0;
    pending->data_len = 1;
    CU_ASSERT_EQUAL(xqc_moqt_queue(f.session, &a->request->stream->tx,
                                   pending), XQC_OK);
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(a, &o), -XQC_EAGAIN);
    CU_ASSERT_FALSE(a->track->has_largest);
    /* Section 5.1.1: blocked control candidates do not stall Datagrams. */
    a->request->stream->transport_stream->stream_flag
        |= XQC_STREAM_FLAG_DATA_BLOCKED;
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(a, &o), XQC_OK);
    a->request->stream->transport_stream->stream_flag
        &= ~XQC_STREAM_FLAG_DATA_BLOCKED;
    f.conn->conn_flag |= XQC_CONN_FLAG_DATA_BLOCKED;
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(a, &o), XQC_OK);
    f.conn->conn_flag &= ~XQC_CONN_FLAG_DATA_BLOCKED;
    xqc_moqt_datagram_writable(f.session);
    CU_ASSERT_EQUAL(f.writable, 0);
    CU_ASSERT_EQUAL(xqc_moqt_stream_flush(a->request->stream), XQC_OK);
    CU_ASSERT_EQUAL(f.writable, 1);
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(a, &o), XQC_OK);
    CU_ASSERT_EQUAL(a->track->largest.object_id, 3);
    CU_ASSERT_EQUAL(f.session->buffered_bytes, used);
    unsigned packets = f.conn->conn_send_queue->sndq_packets_used;
    f.conn->conn_send_queue->sndq_packets_used =
        f.conn->conn_send_queue->sndq_packets_used_max;
    o.object_id++;
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(a, &o), -XQC_EAGAIN);
    CU_ASSERT_EQUAL(a->track->largest.object_id, 3);
    f.conn->conn_send_queue->sndq_packets_used = packets;
    xqc_moqt_datagram_callbacks.datagram_write_notify(f.conn, f.session);
    CU_ASSERT_EQUAL(f.writable, 2);
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(a, &o), XQC_OK);
    o.payload.iov_len = o.payload_length = 0;
    o.status = XQC_MOQT_OBJECT_END_TRACK;
    o.object_id++;
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(a, &o), XQC_OK);
    o.status = XQC_MOQT_OBJECT_NORMAL;
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(a, &o), -XQC_EPARAM);
    f.session->datagram_blocked = 1;
    f.session->callbacks.on_writable = NULL;
    xqc_moqt_datagram_writable(f.session);
    CU_ASSERT_FALSE(f.session->datagram_blocked);
    xqc_moqt_datagram_writable(NULL);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_datagram_lifecycle(void)
{
    for (unsigned close = 0; close <= 1; close++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 0);
        xqc_moqt_subscription_t *a = xqc_test_moqt_object_subscription(
            &f, "v", 1, 0, 7);
        xqc_test_moqt_object_subscription(&f, "v", 1, 0, 7);
        f.request = a->request;
        f.cancel_in_object = !close;
        f.close_in_object = close;
        const uint8_t wire[] = {0x0c, 1, 2, 'x'};
        xqc_moqt_datagram_input(f.session, wire, sizeof(wire));
        CU_ASSERT_EQUAL(f.objects, 1);
        if (!close) {
            CU_ASSERT_EQUAL(f.request_closed, 2);
            CU_ASSERT_PTR_NULL(f.session->subscriptions);
            CU_ASSERT_PTR_NULL(f.session->tracks);
        } else {
            CU_ASSERT_TRUE(f.session->closed);
            xqc_moqt_datagram_input(f.session, wire, sizeof(wire));
            CU_ASSERT_EQUAL(f.objects, 1);
        }
        xqc_test_moqt_destroy(&f);
    }
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_subscription_t *sub = xqc_test_moqt_object_subscription(
        &f, "v", 1, 0, 7);
    xqc_moqt_request_t *r = sub->request;
    xqc_stream_t *transport = r->stream->transport_stream;
    xqc_moqt_request_cancel(r, XQC_MOQT_RESET_MALFORMED_TRACK);
    transport->stream_state_recv = XQC_RECV_STREAM_ST_RESET_RECVD;
    transport->stream_err = XQC_MOQT_RESET_MALFORMED_TRACK;
    xqc_moqt_stream_callbacks.stream_closing_notify(
        transport, XQC_MOQT_RESET_MALFORMED_TRACK, r->stream);
    CU_ASSERT_EQUAL(transport->stream_state_recv,
                    XQC_RECV_STREAM_ST_RESET_READ);
    CU_ASSERT_EQUAL(r->error.code, XQC_MOQT_RESET_MALFORMED_TRACK);
    const uint8_t invalid[] = {0x10};
    xqc_moqt_datagram_input(f.session, invalid, sizeof(invalid));
    CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
    xqc_test_moqt_destroy(&f);
}

static void
xqc_test_moqt_subgroup_object(xqc_moqt_subscription_t *sub,
    xqc_moqt_stream_t *st, const xqc_moqt_object_t *o, void *data)
{
    moqt_fixture_t *f = data;
    CU_ASSERT_PTR_NOT_NULL(st);
    CU_ASSERT_FALSE(o->datagram);
    CU_ASSERT_EQUAL(o->payload_offset, f->object_bytes);
    f->objects++;
    f->object_bytes += o->payload.iov_len;
    f->object = *o;
    for (size_t i = 0; i < o->payload.iov_len; i++) {
        CU_ASSERT_EQUAL(((uint8_t *)o->payload.iov_base)[i], 'x');
    }
    if (f->cancel_in_object) {
        xqc_moqt_request_cancel(sub->request, XQC_MOQT_RESET_CANCELLED);
    }
    if (f->close_in_object) {
        xqc_moqt_session_close(f->session, XQC_MOQT_NO_ERROR);
    }
}

static void
xqc_test_moqt_subgroup_closed(xqc_moqt_stream_t *st,
    const xqc_moqt_object_t *last, const xqc_moqt_error_t *error, void *data)
{
    moqt_fixture_t *f = data;
    f->stream_closed++;
    if (last != NULL) {
        CU_ASSERT_PTR_NULL(last->properties.iov_base);
        CU_ASSERT_PTR_NULL(last->payload.iov_base);
        f->object = *last;
    }
    f->last_code = error == NULL ? UINT64_MAX : error->code;
    if (f->cancel_in_object && f->request != NULL) {
        xqc_moqt_request_cancel(f->request, XQC_MOQT_RESET_CANCELLED);
    }
}

void
xqc_test_moqt_subgroup_receive(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_subscription_t *sub = xqc_test_moqt_object_subscription(
        &f, "v", 1, 0, 7);
    f.session->callbacks.on_object = xqc_test_moqt_subgroup_object;
    f.session->callbacks.on_stream_closed = xqc_test_moqt_subgroup_closed;
    xqc_moqt_stream_t *st = xqc_test_moqt_incoming(&f);
    /* First object, explicit Subgroup, properties, and EOG inferred at FIN. */
    const uint8_t wire[] = {0x5d, 1, 2, 3, 7, 5, 2, 2, 9, 3, 'x', 'x', 'x'};
    for (size_t i = 0; i < sizeof(wire); i++) {
        CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, wire + i, 1,
                                              i == sizeof(wire) - 1), XQC_OK);
    }
    CU_ASSERT_EQUAL(f.objects, 3);
    CU_ASSERT_EQUAL(f.object_bytes, 3);
    CU_ASSERT_EQUAL(f.object.object_id, 5);
    CU_ASSERT_EQUAL(f.object.subgroup_id, 3);
    CU_ASSERT_TRUE(f.object.first_in_subgroup);
    CU_ASSERT_TRUE(f.object.end_of_group);
    CU_ASSERT_EQUAL(f.stream_closed, 1);
    CU_ASSERT_EQUAL(f.last_code, UINT64_MAX);
    CU_ASSERT_EQUAL(sub->track->references, 2);
    CU_ASSERT_PTR_NOT_NULL(sub->track->groups);
    CU_ASSERT_EQUAL(sub->track->groups->subgroups->last, 5);
    xqc_moqt_stream_callbacks.stream_close_notify(st->transport_stream, st);
    CU_ASSERT_EQUAL(sub->track->references, 1);
    CU_ASSERT_PTR_NULL(sub->track->groups);
    CU_ASSERT_EQUAL(f.stream_closed, 1);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_subgroup_errors(void)
{
    /* Draft-22 11.3.2: FIN cannot truncate an Object payload/header. */
    for (unsigned cut = 0; cut < 3; cut++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 0);
        xqc_test_moqt_object_subscription(&f, "v", 1, 0, 7);
        f.session->callbacks.on_object = xqc_test_moqt_subgroup_object;
        xqc_moqt_stream_t *st = xqc_test_moqt_incoming(&f);
        const uint8_t wire[] = {0x10, 1, 2, 7, 0, 2, 'x', 'x'};
        CU_ASSERT_EQUAL(xqc_moqt_stream_input(
            st, wire,
            sizeof(wire) - 1 - cut, 1), -XQC_EILLEGAL_FRAME);
        CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
        xqc_test_moqt_destroy(&f);
    }
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    f.session->callbacks.on_stream_closed = xqc_test_moqt_subgroup_closed;
    xqc_moqt_stream_t *st = xqc_test_moqt_incoming(&f);
    const uint8_t unknown[] = {0x10, 1, 2, 7};
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, unknown, sizeof(unknown), 0),
                    XQC_OK);
    CU_ASSERT_TRUE(st->discarded);
    CU_ASSERT_EQUAL(f.last_code, XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_FALSE(f.session->closed);
    xqc_test_moqt_destroy(&f);
}

static void
xqc_test_moqt_subgroup_writable(xqc_moqt_session_t *s,
    xqc_moqt_stream_t *stream, void *data)
{
    moqt_fixture_t *f = data;
    CU_ASSERT_PTR_NOT_NULL(stream);
    f->writable++;
}

void
xqc_test_moqt_subgroup_send(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_subscription_t *sub = xqc_test_moqt_object_subscription(
        &f, "v", 1, 1, 7);
    f.session->callbacks.on_stream_closed = xqc_test_moqt_subgroup_closed;
    f.session->callbacks.on_writable = xqc_test_moqt_subgroup_writable;
    CU_ASSERT_PTR_NULL(xqc_moqt_subgroup_open(NULL, 1, 2, 7, 1, 1));
    xqc_moqt_stream_t *st = xqc_moqt_subgroup_open(sub, 1, 2, 7, 1, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(st);
    CU_ASSERT_PTR_NULL(sub->track->groups);
    st->transport_stream->stream_flow_ctl.fc_max_stream_data_can_send = 0;
    xqc_moqt_object_t o = {.group_id = 1, .subgroup_id = 2, .priority = 7,
        .payload = {"xx", 2}, .payload_length = 4, .first_in_subgroup = 1};
    CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), XQC_OK);
    CU_ASSERT_EQUAL(st->state.data.object.payload_offset, 2);
    CU_ASSERT_EQUAL(xqc_moqt_stream_finish(st), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), -XQC_EPARAM);
    o.payload_offset = 2;
    size_t budget = f.session->config.max_buffered_bytes;
    f.session->config.max_buffered_bytes = f.session->buffered_bytes;
    CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), -XQC_EAGAIN);
    CU_ASSERT_EQUAL(st->state.data.object.payload_offset, 2);
    f.session->config.max_buffered_bytes = budget;
    st->transport_stream->stream_flow_ctl.fc_max_stream_data_can_send
        = XQC_MOQT_TEST_CAPACITY;
    CU_ASSERT_EQUAL(xqc_moqt_stream_flush(st), XQC_OK);
    CU_ASSERT_EQUAL(f.writable, 1);
    CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), XQC_OK);
    o.object_id = 1;
    o.first_in_subgroup = 0;
    o.payload_offset = o.payload_length = o.payload.iov_len = 0;
    o.payload.iov_base = NULL;
    CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), XQC_OK);
    CU_ASSERT_EQUAL(xqc_moqt_stream_finish(st), XQC_OK);
    CU_ASSERT_EQUAL(f.stream_closed, 1);
    CU_ASSERT_EQUAL(f.last_code, UINT64_MAX);
    /* Sender does not infer receive FIN. */
    CU_ASSERT_FALSE(f.object.end_of_group);
    CU_ASSERT_EQUAL(xqc_moqt_stream_finish(st), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), -XQC_EPARAM);
    xqc_moqt_stream_callbacks.stream_close_notify(st->transport_stream, st);
    CU_ASSERT_EQUAL(sub->track->references, 1);
    st = xqc_moqt_subgroup_open(sub, 2, 0, 7, 0, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(st);
    CU_ASSERT_EQUAL(xqc_moqt_stream_finish(st), XQC_OK);
    CU_ASSERT_PTR_NULL(st->state.data.subgroup);
    CU_ASSERT_EQUAL(f.stream_closed, 2);
    xqc_moqt_stream_callbacks.stream_close_notify(st->transport_stream, st);
    st = xqc_moqt_subgroup_open(sub, 3, 0, 7, 0, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(st);
    xqc_moqt_stream_cancel(st, XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_EQUAL(f.last_code, XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_EQUAL(f.stream_closed, 3);
    xqc_moqt_stream_cancel(st, XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_EQUAL(f.stream_closed, 3);
    xqc_moqt_stream_cancel(NULL, XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_EQUAL(xqc_moqt_stream_finish(NULL), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(NULL, &o), -XQC_EPARAM);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_subgroup_shared(void)
{
    /* Section 12.1: priority and first/last IDs span stream instances. */
    for (unsigned scenario = 0; scenario < 5; scenario++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 0);
        xqc_moqt_subscription_t *sub = xqc_test_moqt_object_subscription(
            &f, "v", 1, 0, 7);
        xqc_test_moqt_object_subscription(&f, "audio", 2, 0, 7);
        xqc_moqt_request_t *r = sub->request;
        f.session->callbacks.on_object = xqc_test_moqt_subgroup_object;
        f.session->callbacks.on_stream_closed = xqc_test_moqt_subgroup_closed;
        xqc_moqt_stream_t *a = xqc_test_moqt_incoming(&f);
        xqc_moqt_stream_t *b = xqc_test_moqt_incoming(&f);
        uint8_t wire[] = {0x54, 1, 2, 3, 7, 5, 0, 0};
        CU_ASSERT_EQUAL(xqc_moqt_stream_input(a, wire, sizeof(wire),
                                              scenario >= 3), XQC_OK);
        xqc_moqt_subgroup_t *sg = a->state.data.subgroup;
        CU_ASSERT_PTR_NOT_NULL_FATAL(sg);
        if (scenario == 0) {
            /* Same summary survives cancellation/release of one reference. */
            CU_ASSERT_EQUAL(xqc_moqt_stream_input(b, wire, sizeof(wire), 0),
                            XQC_OK);
            CU_ASSERT_PTR_EQUAL(b->state.data.subgroup, sg);
            CU_ASSERT_EQUAL(sg->references, 2);
            xqc_moqt_stream_cancel(a, XQC_MOQT_RESET_CANCELLED);
            xqc_moqt_stream_callbacks.stream_close_notify(a->transport_stream,
                                                          a);
            CU_ASSERT_EQUAL(sg->references, 1);
            CU_ASSERT_EQUAL(sg->first, 5);
            CU_ASSERT_EQUAL(xqc_moqt_stream_input(b, NULL, 0, 1), XQC_OK);
            CU_ASSERT_EQUAL(sg->last, 5);
        } else {
            if (scenario == 1) {
                wire[4] = 8; /* Priority mismatch. */
            } else if (scenario == 2) {
                wire[5] = 6; /* Two different FIRST_OBJECT claims. */
            } else if (scenario == 3) {
                wire[0] = 0x14;
                wire[5] = 6; /* Object past authoritative last ID. */
            } else {
                wire[0] = 0x14;
                wire[5] = 4; /* First/last below an observed object. */
            }
            CU_ASSERT_EQUAL(xqc_moqt_stream_input(b, wire, sizeof(wire), 1),
                            XQC_OK);
            CU_ASSERT_TRUE(r->failed);
            CU_ASSERT_EQUAL(r->error.code,
                            XQC_MOQT_RESET_MALFORMED_TRACK);
            CU_ASSERT_FALSE(f.session->closed);
            CU_ASSERT_FALSE(f.session->subscriptions->request->failed);
            xqc_moqt_stream_t *other = xqc_test_moqt_incoming(&f);
            const uint8_t audio[] = {0x10, 2, 9, 7, 0, 0, 0};
            CU_ASSERT_EQUAL(xqc_moqt_stream_input(other, audio, sizeof(audio),
                                                  1), XQC_OK);
            CU_ASSERT_EQUAL(f.objects, 2);
        }
        xqc_test_moqt_destroy(&f);
    }
    /* Section 10.8: retained Groups constrain later streams in both orders. */
    for (unsigned gap_first = 0; gap_first < 2; gap_first++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 0);
        xqc_moqt_subscription_t *sub = xqc_test_moqt_object_subscription(
            &f, "v", 1, 0, 7);
        xqc_moqt_request_t *r = sub->request;
        f.session->callbacks.on_object = xqc_test_moqt_subgroup_object;
        const uint8_t gap[] = {0x11, 1, 10, 7, 0, 2, 0x3c, 3, 0, 0};
        const uint8_t object[] = {0x10, 1, 8, 7, 0, 0, 0};
        xqc_moqt_stream_t *st = xqc_test_moqt_incoming(&f);
        CU_ASSERT_EQUAL(xqc_moqt_stream_input(
            st,
            gap_first ? gap : object, gap_first ? sizeof(gap) : sizeof(object),
            0), XQC_OK);
        if (!gap_first) {
            /* Largest alone cannot remember the earlier Group 8 evidence. */
            const uint8_t later[] = {0x10, 1, 11, 7, 0, 0, 0};
            st = xqc_test_moqt_incoming(&f);
            CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, later, sizeof(later), 0),
                            XQC_OK);
        }
        CU_ASSERT_FALSE(r->failed);
        st = xqc_test_moqt_incoming(&f);
        CU_ASSERT_EQUAL(xqc_moqt_stream_input(
            st,
            gap_first ? object : gap, gap_first ? sizeof(object) : sizeof(gap),
            0), XQC_OK);
        CU_ASSERT_TRUE(r->failed);
        CU_ASSERT_EQUAL(r->error.code,
                        XQC_MOQT_RESET_MALFORMED_TRACK);
        CU_ASSERT_FALSE(f.session->closed);
        xqc_test_moqt_destroy(&f);
    }
}

void
xqc_test_moqt_subgroup_lifecycle(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_subscription_t *sub = xqc_test_moqt_object_subscription(
        &f, "v", 1, 1, 7);
    xqc_moqt_stream_t *st = xqc_moqt_subgroup_open(sub, 1, 0, 7, 0, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(st);
    sub->forward = 0;
    xqc_moqt_subscription_data_update(sub);
    CU_ASSERT_TRUE(st->discarded);
    CU_ASSERT_PTR_NULL(st->state.data.subscription);
    sub->forward = 1;
    st = xqc_moqt_subgroup_open(sub, 1, 0, 7, 0, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(st);
    xqc_moqt_request_cancel(sub->request, XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_TRUE(st->discarded);
    xqc_test_moqt_destroy(&f);

    xqc_test_moqt_request_init(&f, 0);
    sub = xqc_test_moqt_object_subscription(&f, "v", 1, 0, 7);
    f.session->callbacks.on_stream_closed = xqc_test_moqt_subgroup_closed;
    st = xqc_test_moqt_incoming(&f);
    const uint8_t empty[] = {0x10, 1, 2, 7};
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, empty, sizeof(empty), 1), XQC_OK);
    CU_ASSERT_PTR_NULL(sub->track->groups);
    CU_ASSERT_EQUAL(f.stream_closed, 1);
    xqc_moqt_stream_t *next = xqc_test_moqt_incoming(&f);
    CU_ASSERT_PTR_NOT_NULL_FATAL(next);
    xqc_moqt_stream_callbacks.stream_close_notify(st->transport_stream, st);
    st = next;
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, empty, sizeof(empty), 0), XQC_OK);
    xqc_moqt_request_cancel(sub->request, XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_TRUE(st->discarded);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_subgroup_scheduling(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_subscription_t *a = xqc_test_moqt_object_subscription(
        &f, "v", 1, 1, 7);
    xqc_moqt_subscription_t *b = xqc_test_moqt_object_subscription(
        &f, "audio", 2, 1, 7);
    a->group_order = XQC_MOQT_GROUP_DESCENDING;
    a->subscriber_priority = 1;
    b->subscriber_priority = 2;
    xqc_moqt_object_t o = {.group_id = 1, .priority = 7};
    xqc_moqt_object_t later = o;
    later.group_id = 2;
    CU_ASSERT(xqc_moqt_data_compare(a, &later, NULL, a, &o, NULL) < 0);
    a->group_order = XQC_MOQT_GROUP_ASCENDING;
    CU_ASSERT(xqc_moqt_data_compare(a, &later, NULL, a, &o, NULL) > 0);
    a->group_order = XQC_MOQT_GROUP_DESCENDING;
    CU_ASSERT(xqc_moqt_data_compare(a, &o, NULL, b, &o, NULL) < 0);
    CU_ASSERT(xqc_moqt_data_compare(b, &o, NULL, a, &o, NULL) > 0);
    b->subscriber_priority = 1;
    CU_ASSERT_EQUAL(xqc_moqt_data_compare(a, &o, NULL, b, &later, NULL), 0);
    later.priority = 8;
    CU_ASSERT(xqc_moqt_data_compare(a, &o, NULL, b, &later, NULL) < 0);
    later = o;
    later.subgroup_id = 1;
    CU_ASSERT(xqc_moqt_data_compare(a, &o, NULL, a, &later, NULL) < 0);
    later.datagram = 1;
    CU_ASSERT(xqc_moqt_data_compare(a, &o, NULL, a, &later, NULL) > 0);

    xqc_moqt_stream_t *first = xqc_moqt_subgroup_open(a, 1, 0, 7, 0, 0);
    xqc_moqt_stream_t *second = xqc_moqt_subgroup_open(a, 2, 0, 7, 0, 0);
    xqc_moqt_stream_t *third = xqc_moqt_subgroup_open(b, 1, 0, 7, 0, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(first);
    CU_ASSERT_PTR_NOT_NULL_FATAL(second);
    CU_ASSERT_PTR_NOT_NULL_FATAL(third);
    b->subscriber_priority = 2;
    f.session->flushing = 1; /* Queue candidates in one application callback. */
    CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(first, &o), XQC_OK);
    CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(third, &o), XQC_OK);
    o.group_id = 2;
    CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(second, &o), XQC_OK);
    f.session->flushing = 0;
    o.datagram = 1;
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(b, &o), -XQC_EAGAIN);
    f.session->datagram_blocked = 0;
    second->transport_stream->stream_flow_ctl.fc_max_stream_data_can_send = 0;
    CU_ASSERT_EQUAL(xqc_moqt_stream_flush(first), XQC_OK);
    CU_ASSERT_FALSE(xqc_list_empty(&second->tx));
    CU_ASSERT_TRUE(xqc_list_empty(&first->tx));
    CU_ASSERT_TRUE(xqc_list_empty(&third->tx));
    CU_ASSERT(first->tx_order < third->tx_order);
    second->transport_stream->stream_flow_ctl.fc_max_stream_data_can_send
        = XQC_MOQT_TEST_CAPACITY;
    f.session->tx_order = UINT64_MAX;
    CU_ASSERT_EQUAL(xqc_moqt_stream_flush(second), XQC_OK);
    CU_ASSERT_TRUE(xqc_list_empty(&second->tx));
    CU_ASSERT(f.session->tx_order < UINT64_MAX);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_subgroup_limits(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_subscription_t *sub = xqc_test_moqt_object_subscription(
        &f, "v", 1, 0, 7);
    f.session->callbacks.on_object = xqc_test_moqt_subgroup_object;
    f.session->callbacks.on_stream_closed = xqc_test_moqt_subgroup_closed;
    xqc_moqt_stream_t *st = xqc_test_moqt_incoming(&f);
    uint8_t *properties = xqc_malloc(XQC_MOQT_KV_MAX_VALUE);
    uint8_t *wire = xqc_malloc(XQC_MOQT_RX_LIMIT);
    CU_ASSERT_PTR_NOT_NULL_FATAL(properties);
    CU_ASSERT_PTR_NOT_NULL_FATAL(wire);
    xqc_memzero(properties, XQC_MOQT_KV_MAX_VALUE);
    xqc_moqt_kv_t kv = {1, {.bytes = {properties,
        XQC_MOQT_KV_MAX_VALUE - 1 - xqc_vi64_len(XQC_MOQT_KV_MAX_VALUE)}}};
    xqc_int_t props = xqc_moqt_kv_encode(&kv, 0, wire, XQC_MOQT_RX_LIMIT);
    CU_ASSERT_EQUAL(props, XQC_MOQT_KV_MAX_VALUE);
    xqc_memcpy(properties, wire, props);
    xqc_moqt_object_t o = {.group_id = 2, .priority = 7,
        .object_id = UINT64_MAX, .payload_length = 1,
        .properties = {properties, props}};
    xqc_int_t len = xqc_moqt_subgroup_header_encode(1, 0x31, &o, wire,
                                                    XQC_MOQT_RX_LIMIT);
    len += xqc_moqt_object_header_encode(0x31, NULL, &o, wire + len,
                                         XQC_MOQT_RX_LIMIT - len);
    wire[len++] = 'x';
    for (size_t pos = 0; pos < (size_t)len;) {
        size_t chunk = xqc_min(XQC_MOQT_READ_CHUNK, len - pos);
        CU_ASSERT_EQUAL(xqc_moqt_stream_input(
            st, wire + pos, chunk,
            pos + chunk == (size_t)len), XQC_OK);
        pos += chunk;
    }
    CU_ASSERT_EQUAL(f.objects, 1);
    CU_ASSERT_EQUAL(f.object.object_id, UINT64_MAX);
    CU_ASSERT_EQUAL(f.object_bytes, 1);
    CU_ASSERT_EQUAL(f.object.priority, 7);
    CU_ASSERT(st->rx.buf_len <= XQC_MOQT_RX_LIMIT);
    xqc_free(properties);
    xqc_free(wire);
    xqc_test_moqt_destroy(&f);

    for (unsigned mode = 0; mode < 4; mode++) {
        xqc_test_moqt_request_init(&f, 0);
        sub = xqc_test_moqt_object_subscription(&f, "v", 1, 0, 7);
        f.session->callbacks.on_stream_closed = xqc_test_moqt_subgroup_closed;
        st = xqc_test_moqt_incoming(&f);
        const uint8_t header[] = {0x10, 1, 2, 7};
        CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, header, sizeof(header), 0),
                        XQC_OK);
        if (mode == 0) {
            f.session->config.max_buffered_bytes = f.session->buffered_bytes;
            const uint8_t object[] = {0, 0, 0};
            CU_ASSERT_EQUAL(
                xqc_moqt_stream_input(st, object, sizeof(object), 0), XQC_OK);
            CU_ASSERT_EQUAL(f.last_code, XQC_MOQT_RESET_EXCESSIVE_LOAD);
            CU_ASSERT_PTR_NULL(sub->track->groups);
        } else if (mode == 1) {
            const uint8_t partial[] = {0, 3, 'x'};
            f.session->callbacks.on_object = xqc_test_moqt_subgroup_object;
            CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, partial, sizeof(partial),
                                                  0), XQC_OK);
            xqc_moqt_session_timeout(f.session->timer, st->deadline, f.session);
            CU_ASSERT_EQUAL(f.last_code, XQC_MOQT_RESET_CANCELLED);
        } else {
            st->transport_stream->stream_err = XQC_MOQT_RESET_TOO_FAR_BEHIND;
            if (mode == 2) {
                st->transport_stream->stream_state_recv
                    = XQC_RECV_STREAM_ST_RESET_RECVD;
                xqc_moqt_stream_callbacks.stream_closing_notify(
                    st->transport_stream, 0, st);
            } else {
                xqc_moqt_stream_callbacks.stream_stop_sending_notify(
                    st->transport_stream, XQC_MOQT_RESET_TOO_FAR_BEHIND, st);
            }
            CU_ASSERT_EQUAL(f.last_code, XQC_MOQT_RESET_TOO_FAR_BEHIND);
        }
        CU_ASSERT_EQUAL(f.stream_closed, 1);
        CU_ASSERT_FALSE(f.session->closed);
        xqc_test_moqt_destroy(&f);
    }
    for (unsigned close = 0; close < 2; close++) {
        xqc_test_moqt_request_init(&f, 0);
        xqc_test_moqt_object_subscription(&f, "v", 1, 0, 7);
        f.session->callbacks.on_object = xqc_test_moqt_subgroup_object;
        f.cancel_in_object = !close;
        f.close_in_object = close;
        st = xqc_test_moqt_incoming(&f);
        const uint8_t wire[] = {0x10, 1, 2, 7, 0, 3, 'x'};
        CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, wire, sizeof(wire), 0),
                        XQC_OK);
        CU_ASSERT_EQUAL(f.objects, 1);
        CU_ASSERT(st->discarded || f.session->closed);
        xqc_test_moqt_destroy(&f);
    }
}

static void
xqc_test_moqt_subscription_closed(xqc_moqt_subscription_t *sub,
    const xqc_moqt_error_t *error, void *data)
{
    moqt_fixture_t *f = data;
    f->subscription_closed++;
    CU_ASSERT_PTR_NULL(sub->request);
    CU_ASSERT_TRUE(sub->closed);
    f->subscription_error = error->code;
    /* Reentrant cancellation must not notify twice. */
    xqc_moqt_subscription_cancel(sub, XQC_MOQT_RESET_CANCELLED);
}

void
xqc_test_moqt_delivery_done(void)
{
    /* Draft-22 9.9: request closure precedes delayed Subgroup delivery. */
    for (unsigned cancel = 0; cancel < 2; cancel++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 0);
        xqc_moqt_subscription_t *sub = xqc_test_moqt_object_subscription(
            &f, "video", 1, 0, 7);
        xqc_moqt_subscription_t *other = xqc_test_moqt_object_subscription(
            &f, "audio", 2, 0, 7);
        CU_ASSERT_FALSE(sub->shared_alias);
        CU_ASSERT_FALSE(other->shared_alias);
        f.session->callbacks.on_subscription_closed =
            xqc_test_moqt_subscription_closed;
        f.session->callbacks.on_object = xqc_test_moqt_subgroup_object;
        f.session->callbacks.on_stream_closed = xqc_test_moqt_subgroup_closed;
        xqc_moqt_request_t *r = sub->request;
        xqc_moqt_stream_t *request_stream = r->stream;
        xqc_moqt_message_t done = {.type = XQC_MOQT_MSG_PUBLISH_DONE,
            .stream_count = 1, .error = {.code = XQC_MOQT_PUBLISH_TRACK_ENDED}};
        CU_ASSERT_EQUAL(xqc_test_moqt_request_input(request_stream, &done,
                            XQC_MOQT_MSG_SUBSCRIBE, 1), XQC_OK);
        xqc_moqt_stream_callbacks.stream_close_notify(
            request_stream->transport_stream, request_stream);
        CU_ASSERT_PTR_NULL(sub->request);
        CU_ASSERT_EQUAL(f.subscription_closed, 0);
        if (cancel) {
            xqc_moqt_subscription_cancel(sub, XQC_MOQT_RESET_CANCELLED);
        }
        xqc_moqt_stream_t *st = xqc_test_moqt_incoming(&f);
        const uint8_t wire[] = {0x10, 1, 2, 7, 0, 1, 'x'};
        CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, wire, sizeof(wire), 1),
                        XQC_OK);
        CU_ASSERT_EQUAL(f.objects, !cancel);
        CU_ASSERT_EQUAL(f.subscription_closed, 1);
        CU_ASSERT_EQUAL(f.subscription_error, cancel
            ? XQC_MOQT_RESET_CANCELLED : XQC_MOQT_PUBLISH_TRACK_ENDED);
        CU_ASSERT_FALSE(other->stopped);
        CU_ASSERT_FALSE(f.session->closed);
        xqc_test_moqt_destroy(&f);
    }
}

void
xqc_test_moqt_delivery_counts(void)
{
    /* Empty and shared-Alias streams still have bounded completion. */
    for (unsigned shared = 0; shared < 2; shared++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 0);
        xqc_moqt_subscription_t *sub = xqc_test_moqt_object_subscription(
            &f, "v", 0, 0, 7);
        xqc_moqt_subscription_t *other = xqc_test_moqt_object_subscription(
            &f, "v", shared ? 0 : 2, 0, 7);
        CU_ASSERT_EQUAL(sub->shared_alias, shared);
        CU_ASSERT_EQUAL(other->shared_alias, shared);
        f.session->callbacks.on_subscription_closed =
            xqc_test_moqt_subscription_closed;
        xqc_moqt_message_t done = {.type = XQC_MOQT_MSG_PUBLISH_DONE,
            .stream_count = shared ? 1 : UINT64_MAX};
        xqc_moqt_subscription_done(sub, &done);
        xqc_moqt_subscription_release(sub->request);
        xqc_moqt_stream_t *st = xqc_test_moqt_incoming(&f);
        const uint8_t header[] = {0x10, 0, 2, 7};
        CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, header, sizeof(header), 1),
                        XQC_OK);
        CU_ASSERT_EQUAL(sub->stream_count, 1);
        CU_ASSERT_EQUAL(sub->finished_streams, 1);
        CU_ASSERT_EQUAL(f.subscription_closed, 0);
        xqc_moqt_session_timeout(f.session->timer, sub->close_deadline,
                                 f.session);
        CU_ASSERT_EQUAL(f.subscription_closed, 1);
        CU_ASSERT_FALSE(f.session->closed);
        xqc_test_moqt_destroy(&f);
    }
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_subscription_t *sub = xqc_test_moqt_object_subscription(
        &f, "v", 1, 1, 7);
    f.session->callbacks.on_subscription_closed =
        xqc_test_moqt_subscription_closed;
    xqc_moqt_request_t *r = sub->request;
    xqc_moqt_stream_t *st = xqc_moqt_subgroup_open(sub, 0, 0, 7, 0, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(st);
    xqc_moqt_message_t done = {.type = XQC_MOQT_MSG_PUBLISH_DONE,
        .stream_count = UINT64_MAX};
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &done), -XQC_EAGAIN);
    CU_ASSERT_EQUAL(xqc_moqt_stream_finish(st), XQC_OK);
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &done), XQC_OK);
    CU_ASSERT_EQUAL(sub->expected_streams, 1);
    CU_ASSERT_EQUAL(done.stream_count, UINT64_MAX);
    CU_ASSERT_PTR_NULL(xqc_moqt_subgroup_open(sub, 1, 0, 7, 0, 0));
    CU_ASSERT_EQUAL(f.subscription_closed, 0);
    xqc_moqt_subscription_release(r);
    CU_ASSERT_PTR_NULL(sub->request);
    xqc_moqt_stream_callbacks.stream_close_notify(st->transport_stream, st);
    CU_ASSERT_EQUAL(f.subscription_closed, 1);
    xqc_moqt_subscription_cancel(NULL, XQC_MOQT_RESET_CANCELLED);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_delivery_timeout(void)
{
    /* Section 5.2: FIN accepted is not equivalent to FIN acknowledged. */
    for (unsigned acknowledged = 0; acknowledged < 2; acknowledged++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 0);
        xqc_moqt_subscription_t *sub = xqc_test_moqt_object_subscription(
            &f, "v", 1, 1, 7);
        sub->track->subgroup_timeout = 100;
        sub->subgroup_timeout = 10;
        xqc_moqt_stream_t *st = xqc_moqt_subgroup_open(sub, 0, 0, 7, 0, 0);
        CU_ASSERT_PTR_NOT_NULL_FATAL(st);
        size_t budget = f.session->config.max_buffered_bytes;
        f.session->config.max_buffered_bytes = f.session->buffered_bytes;
        CU_ASSERT_EQUAL(xqc_moqt_stream_finish(st), -XQC_EAGAIN);
        xqc_usec_t origin = st->state.data.finish_time;
        CU_ASSERT_NOT_EQUAL(origin, 0);
        f.session->config.max_buffered_bytes = budget;
        CU_ASSERT_EQUAL(xqc_moqt_stream_finish(st), XQC_OK);
        CU_ASSERT_TRUE(st->tx_fin_sent);
        CU_ASSERT_EQUAL(st->state.data.finish_time, origin);
        CU_ASSERT_EQUAL(xqc_moqt_subgroup_deadline(st), origin + 10000);
        /* UPDATE changes the bound without moving its origin. */
        uint8_t value[] = {1};
        xqc_moqt_message_t update = {.type = XQC_MOQT_MSG_REQUEST_UPDATE,
            .parameter_count = 1};
        update.parameters[0] = (xqc_moq_message_parameter_t){
            .type = XQC_MOQT_PARAM_SUBGROUP_DELIVERY_TIMEOUT,
            .value = value, .length = sizeof(value)};
        CU_ASSERT_EQUAL(xqc_moqt_subscription_apply(sub->request, &update),
                        XQC_MOQT_NO_ERROR);
        CU_ASSERT_EQUAL(xqc_moqt_subgroup_deadline(st), origin + 1000);
        if (acknowledged) {
            st->transport_stream->stream_state_send
                = XQC_SEND_STREAM_ST_DATA_RECVD;
        } else {
            f.conn->conn_flag |= XQC_CONN_FLAG_TLS_HSK_COMPLETED;
            f.conn->remote_settings.reset_stream_at = 1;
        }
        xqc_moqt_session_timeout(f.session->timer, origin + 1000, f.session);
        CU_ASSERT_EQUAL(st->discarded, !acknowledged);
        if (!acknowledged) {
            CU_ASSERT_EQUAL(st->state.data.error,
                            XQC_MOQT_RESET_DELIVERY_TIMEOUT);
            CU_ASSERT_EQUAL(st->transport_stream->reset_at.send_size,
                            st->state.data.prefix_length);
        }
        CU_ASSERT_EQUAL(xqc_moqt_subgroup_deadline(st), 0);
        CU_ASSERT_FALSE(f.session->closed);
        xqc_test_moqt_destroy(&f);
    }
}

void
xqc_test_moqt_object_expiry(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_subscription_t *sub = xqc_test_moqt_object_subscription(
        &f, "v", 1, 1, 7);
    sub->track->object_timeout = 100;
    sub->object_timeout = 1;
    xqc_moqt_stream_t *st = xqc_moqt_subgroup_open(sub, 0, 0, 7, 0, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(st);
    xqc_moqt_object_t o = {.priority = 7, .payload = {"xx", 2},
        .payload_length = 4};
    st->transport_stream->stream_flow_ctl.fc_max_stream_data_can_send = 0;
    CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), XQC_OK);
    xqc_usec_t origin = st->state.data.object_time;
    xqc_list_buf_t *partial = xqc_list_entry(st->tx.prev,
                                             xqc_list_buf_t, list_head);
    /* A previously accepted prefix does not give the remainder a new origin. */
    partial->buf->consumed_len = 1;
    o.payload_offset = 2;
    CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), XQC_OK);
    xqc_list_buf_t *entry = xqc_list_entry(st->tx.prev,
                                           xqc_list_buf_t, list_head);
    CU_ASSERT_EQUAL(entry->timestamp, origin);
    CU_ASSERT_FALSE(xqc_moqt_object_is_expired(st, origin, origin + 999));
    CU_ASSERT_TRUE(xqc_moqt_object_is_expired(st, origin, origin + 1000));
    CU_ASSERT_FALSE(xqc_moqt_object_is_expired(st, 0, origin + 1000));
    CU_ASSERT_FALSE(xqc_moqt_object_is_expired(st, origin, origin - 1));
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &st->tx) {
        entry = xqc_list_entry(pos, xqc_list_buf_t, list_head);
        if (entry->timestamp) {
            entry->timestamp -= 1000;
        }
    }
    st->transport_stream->stream_flow_ctl.fc_max_stream_data_can_send
        = XQC_MOQT_TEST_CAPACITY;
    CU_ASSERT_EQUAL(xqc_moqt_stream_flush(st), -XQC_EEXPIRED);
    CU_ASSERT_TRUE(st->discarded);
    CU_ASSERT_EQUAL(st->state.data.error, XQC_MOQT_RESET_DELIVERY_TIMEOUT);
    CU_ASSERT_FALSE(f.session->closed);
    xqc_test_moqt_destroy(&f);
}

static xqc_usec_t xqc_test_moqt_clock_value;

static xqc_usec_t
xqc_test_moqt_clock(void)
{
    xqc_test_moqt_clock_value += XQC_MOQT_MICROS_PER_MILLISECOND;
    return xqc_test_moqt_clock_value;
}

void
xqc_test_moqt_delivery_policy(void)
{
    for (unsigned immutable = 0; immutable < 2; immutable++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 0);
        xqc_moqt_subscription_t *sub = xqc_test_moqt_object_subscription(
            &f, "v", 1, 1, 7);
        /* Sections 5.2/10.7: mutable and immutable defaults are equivalent. */
        uint8_t properties[] = {0x0b, 4, 2, 20, 4, 30};
        xqc_moqt_message_t policy = {.type = XQC_MOQT_MSG_PUBLISH,
            .properties = {properties + (immutable ? 0 : 2),
                            immutable ? sizeof(properties) : 4}};
        CU_ASSERT_EQUAL(xqc_moqt_subscription_apply(sub->request, &policy),
                        XQC_MOQT_NO_ERROR);
        CU_ASSERT_EQUAL(sub->track->object_timeout, 20);
        CU_ASSERT_EQUAL(sub->track->subgroup_timeout, 30);
        uint8_t value[] = {10};
        policy = (xqc_moqt_message_t){.type = XQC_MOQT_MSG_REQUEST_UPDATE,
            .parameter_count = 1};
        policy.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_OBJECT_DELIVERY_TIMEOUT, sizeof(value), value};
        CU_ASSERT_EQUAL(xqc_moqt_subscription_apply(sub->request, &policy),
                        XQC_MOQT_NO_ERROR);
        CU_ASSERT_EQUAL(sub->object_timeout, 10);
        policy.parameters[0].length = 0;
        CU_ASSERT_EQUAL(xqc_moqt_subscription_apply(sub->request, &policy),
                        XQC_MOQT_PROTOCOL_VIOLATION);
        CU_ASSERT_EQUAL(sub->object_timeout, 10);
        xqc_moqt_stream_t *st = xqc_moqt_subgroup_open(sub, 0, 0, 7, 1, 0);
        CU_ASSERT_PTR_NOT_NULL_FATAL(st);
        uint8_t override[] = {0x0b, 4, 2, 0, 4, 2};
        xqc_moqt_object_t o = {.priority = 7, .first_in_subgroup = 1,
            .properties = {override + (immutable ? 0 : 2),
                            immutable ? sizeof(override) : 4}};
        CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), XQC_OK);
        CU_ASSERT_TRUE(st->state.data.has_object_timeout);
        CU_ASSERT_EQUAL(st->state.data.object_timeout, 0);
        CU_ASSERT_EQUAL(st->state.data.subgroup_timeout, 2);
        xqc_usec_t origin = st->state.data.object_time;
        CU_ASSERT_FALSE(xqc_moqt_object_is_expired(st, origin, origin + 9999));
        CU_ASSERT_TRUE(xqc_moqt_object_is_expired(st, origin, origin + 10000));
        sub->object_timeout = 0;
        CU_ASSERT_FALSE(xqc_moqt_object_is_expired(st, origin, UINT64_MAX));
        /* A later object's timeout properties cannot replace FIRST_OBJECT. */
        override[3] = override[5] = 1;
        o.first_in_subgroup = 0;
        o.object_id = 1;
        CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), XQC_OK);
        CU_ASSERT_EQUAL(st->state.data.object_timeout, 0);
        CU_ASSERT_EQUAL(st->state.data.subgroup_timeout, 2);
        CU_ASSERT_EQUAL(xqc_moqt_stream_finish(st), XQC_OK);
        CU_ASSERT_EQUAL(xqc_moqt_subgroup_deadline(st),
                        st->state.data.finish_time + 2000);
        st->state.data.has_subgroup_timeout = 0;
        sub->track->subgroup_timeout = UINT64_MAX;
        CU_ASSERT_EQUAL(xqc_moqt_subgroup_deadline(st), UINT64_MAX);
        sub->track->subgroup_timeout = 0;
        CU_ASSERT_EQUAL(xqc_moqt_subgroup_deadline(st), 0);
        xqc_test_moqt_destroy(&f);
    }
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_subscription_t *sub = xqc_test_moqt_object_subscription(
        &f, "v", 1, 1, 7);
    xqc_moqt_object_t o = {.priority = 7, .datagram = 1};
    sub->object_timeout = 1;
    xqc_timestamp_pt clock = xqc_monotonic_timestamp;
    xqc_test_moqt_clock_value = clock();
    xqc_monotonic_timestamp = xqc_test_moqt_clock;
    xqc_int_t ret = xqc_moqt_datagram_send(sub, &o);
    xqc_monotonic_timestamp = clock;
    CU_ASSERT_EQUAL(ret, -XQC_EEXPIRED);
    CU_ASSERT_FALSE(sub->track->has_largest);
    sub->object_timeout = 0;
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(sub, &o), XQC_OK);
    xqc_test_moqt_destroy(&f);
}

static void
xqc_test_moqt_fetch_ready_notify(xqc_moqt_fetch_t *fetch,
    xqc_moqt_subscription_t *subscription, void *data)
{
    moqt_fixture_t *f = data;
    f->fetch_ready++;
    CU_ASSERT_PTR_NOT_NULL(xqc_moqt_fetch_info(fetch));
    if (f->cancel_in_message) {
        xqc_moqt_fetch_cancel(fetch, XQC_MOQT_RESET_CANCELLED);
    }
}

static void
xqc_test_moqt_fetch_closed_notify(xqc_moqt_fetch_t *fetch,
    const xqc_moqt_error_t *error, void *data)
{
    moqt_fixture_t *f = data;
    f->fetch_closed++;
    f->fetch_error = f->last_code = error == NULL
        ? XQC_MOQT_NO_ERROR : error->code;
    /* A final callback may reenter cancellation without a second callback. */
    xqc_moqt_fetch_cancel(fetch, XQC_MOQT_RESET_CANCELLED);
}

static void
xqc_test_moqt_fetch_object(xqc_moqt_subscription_t *sub,
    xqc_moqt_stream_t *st, const xqc_moqt_object_t *o, void *data)
{
    moqt_fixture_t *f = data;
    CU_ASSERT_PTR_NOT_NULL(xqc_moqt_stream_fetch(st));
    CU_ASSERT_PTR_EQUAL(sub, st->state.data.fetch->subscription);
    f->objects++;
    f->object_bytes += o->payload.iov_len;
    f->object = *o;
    if (f->cancel_in_object) {
        xqc_moqt_fetch_cancel(xqc_moqt_stream_fetch(st),
                              XQC_MOQT_RESET_CANCELLED);
    }
}

static xqc_moqt_request_t *
xqc_test_moqt_fetch_request(moqt_fixture_t *f, xqc_int_t publisher,
    uint8_t order)
{
    xqc_test_moqt_request_init(f, publisher);
    f->session->callbacks.on_fetch_ready = xqc_test_moqt_fetch_ready_notify;
    f->session->callbacks.on_fetch_closed = xqc_test_moqt_fetch_closed_notify;
    f->session->callbacks.on_object = xqc_test_moqt_fetch_object;
    f->session->callbacks.on_stream_closed = xqc_test_moqt_subgroup_closed;
    uint8_t range[] = {XQC_MOQT_FILTER_ABSOLUTE_RANGE, 1, 0, 2, 9};
    uint8_t timeout[] = {0}, priority[] = {7};
    xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_FETCH,
        .track_name = {"video", 5}, .parameter_count = 4};
    m.parameters[0] = (xqc_moq_message_parameter_t){XQC_MOQT_PARAM_FILL_TIMEOUT,
        sizeof(timeout), timeout};
    m.parameters[1] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_SUBSCRIBER_PRIORITY, sizeof(priority), priority};
    m.parameters[2] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_LOCATION_FILTER, sizeof(range), range};
    m.parameters[3] = (xqc_moq_message_parameter_t){XQC_MOQT_PARAM_GROUP_ORDER,
        sizeof(order), &order};
    if (publisher) {
        xqc_moqt_stream_t *st = xqc_test_moqt_request_stream(f);
        CU_ASSERT_EQUAL(xqc_test_moqt_request_input(st, &m, m.type, 0), XQC_OK);
        return &st->state.request;
    }
    return xqc_moqt_request_open(f->session, &m);
}

static xqc_int_t
xqc_test_moqt_fetch_response(xqc_moqt_request_t *r, uint64_t group,
    uint64_t object)
{
    xqc_moqt_message_t ok = {.type = XQC_MOQT_MSG_FETCH_OK,
        .end_group = group, .end_object = object};
    return r->local ? xqc_test_moqt_request_input(r->stream, &ok,
        XQC_MOQT_MSG_FETCH, 0) : xqc_moqt_request_send(r, &ok);
}

void
xqc_test_moqt_fetch_receive(void)
{
    /* Sections 3.2.2/11.4: retain early data across native physical close. */
    for (unsigned early = 0; early < 2; early++) {
        moqt_fixture_t f;
        xqc_moqt_request_t *r = xqc_test_moqt_fetch_request(
            &f, 0, XQC_MOQT_GROUP_ASCENDING);
        CU_ASSERT_PTR_NOT_NULL_FATAL(r);
        xqc_moqt_fetch_t *fetch = xqc_moqt_request_fetch(r);
        CU_ASSERT_PTR_NOT_NULL_FATAL(fetch);
        CU_ASSERT_PTR_NULL(xqc_moqt_fetch_open(fetch));
        xqc_moqt_stream_t *st = xqc_test_moqt_incoming(&f);
        const uint8_t wire[] = {5, 0, 0x1f, 1, 0, 0, 7, 3, 'a', 'b', 'c',
            0x80, 0x8c, 1, 2, 0x81, 0x0c, 1, 3, 0x82, 0x0c, 1, 4,
            0x54, 1, 8, 0};
        if (early) {
            for (size_t i = 0; i < sizeof(wire); i++) {
                CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, wire + i, 1,
                    i + 1 == sizeof(wire)), XQC_OK);
            }
            CU_ASSERT_EQUAL(f.objects, 0);
            xqc_moqt_stream_callbacks.stream_close_notify(
                st->transport_stream, st);
            CU_ASSERT_PTR_NULL(st->transport_stream);
            CU_ASSERT_PTR_EQUAL(fetch->stream, st);
        }
        CU_ASSERT_EQUAL(xqc_test_moqt_fetch_response(r, 3, 9), XQC_OK);
        CU_ASSERT_EQUAL(f.fetch_ready, 1);
        if (!early) {
            CU_ASSERT_EQUAL(xqc_moqt_request_finish(r), XQC_OK);
            xqc_moqt_stream_callbacks.stream_close_notify(
                r->stream->transport_stream, r->stream);
            CU_ASSERT_PTR_NULL(fetch->request);
            CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, wire, sizeof(wire), 1),
                            XQC_OK);
        }
        CU_ASSERT_EQUAL(f.objects, 5);
        CU_ASSERT_EQUAL(f.object_bytes, 3);
        CU_ASSERT_EQUAL(f.fetch_closed, 1);
        CU_ASSERT_EQUAL(f.stream_closed, 1);
        CU_ASSERT_EQUAL(f.object.object_id, 5);
        CU_ASSERT_TRUE(f.object.datagram);
        CU_ASSERT_FALSE(f.session->closed);
        xqc_test_moqt_destroy(&f);
    }
    CU_ASSERT_PTR_NULL(xqc_moqt_request_fetch(NULL));
    CU_ASSERT_PTR_NULL(xqc_moqt_fetch_info(NULL));
    CU_ASSERT_PTR_NULL(xqc_moqt_stream_fetch(NULL));
    CU_ASSERT_PTR_NULL(xqc_moqt_fetch_open(NULL));
    xqc_moqt_fetch_cancel(NULL, 0);
}

void
xqc_test_moqt_fetch_send(void)
{
    for (uint8_t order = XQC_MOQT_GROUP_ASCENDING;
         order <= XQC_MOQT_GROUP_DESCENDING; order++)
    {
        moqt_fixture_t f;
        xqc_moqt_request_t *r = xqc_test_moqt_fetch_request(&f, 1, order);
        xqc_moqt_fetch_t *fetch = r->fetch;
        CU_ASSERT_PTR_NULL(xqc_moqt_fetch_open(fetch));
        CU_ASSERT_EQUAL(xqc_test_moqt_fetch_response(r, 3, 10), -XQC_EPARAM);
        CU_ASSERT_FALSE(fetch->ready);
        CU_ASSERT_EQUAL(xqc_test_moqt_fetch_response(r, 3, 9), XQC_OK);
        CU_ASSERT_EQUAL(fetch->info.group_order, order);
        CU_ASSERT_TRUE(fetch->info.has_fill_timeout);
        xqc_moqt_stream_t *st = xqc_moqt_fetch_open(fetch);
        CU_ASSERT_PTR_NOT_NULL_FATAL(st);
        CU_ASSERT_PTR_NULL(xqc_moqt_fetch_open(fetch));
        CU_ASSERT_EQUAL(xqc_moqt_request_finish(r), XQC_OK);
        xqc_moqt_stream_callbacks.stream_close_notify(
            r->stream->transport_stream, r->stream);
        CU_ASSERT_PTR_NULL(fetch->request);
        xqc_moqt_object_t o = {.group_id = order == 1 ? 1 : 3,
            .priority = 7, .payload_length = 3, .payload = {"a", 1}};
        CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), XQC_OK);
        CU_ASSERT_EQUAL(xqc_moqt_stream_finish(st), -XQC_EPARAM);
        o.payload_offset = 1;
        o.group_id = 0;
        CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), -XQC_EPARAM);
        o.group_id = order == 1 ? 1 : 3;
        o.payload = (struct iovec){"bc", 2};
        CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), XQC_OK);
        o.payload_length = o.payload_offset = 0;
        o.payload = (struct iovec){NULL, 0};
        o.object_id = 1;
        o.subgroup_id = 1;
        CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), XQC_OK);
        o.object_id = 2;
        o.subgroup_id = 0;
        CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), XQC_OK);
        o.group_id = 2;
        o.object_id = 0;
        o.datagram = 1;
        CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), XQC_OK);
        o.object_id = 1;
        o.range = XQC_MOQT_RANGE_UNKNOWN;
        CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), XQC_OK);
        CU_ASSERT_FALSE(fetch->track->has_largest);
        CU_ASSERT_FALSE(fetch->track->has_end);
        CU_ASSERT_EQUAL(xqc_moqt_stream_finish(st), XQC_OK);
        CU_ASSERT_EQUAL(f.fetch_closed, 1);
        CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &o), -XQC_EPARAM);
        xqc_moqt_stream_callbacks.stream_close_notify(st->transport_stream, st);
        CU_ASSERT_PTR_NULL(f.session->fetches);
        CU_ASSERT_PTR_NULL(f.session->tracks);
        xqc_test_moqt_destroy(&f);
    }
}

void
xqc_test_moqt_fetch_errors(void)
{
    for (unsigned scenario = 0; scenario < 9; scenario++) {
        moqt_fixture_t f;
        xqc_moqt_request_t *r = xqc_test_moqt_fetch_request(
            &f, 0, XQC_MOQT_GROUP_ASCENDING);
        xqc_moqt_fetch_t *fetch = r->fetch;
        xqc_moqt_stream_t *st = xqc_test_moqt_incoming(&f);
        const uint8_t prefix[] = {5, 0};
        CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, prefix, sizeof(prefix), 0),
                        XQC_OK);
        if (scenario < 2) {
            CU_ASSERT_EQUAL(xqc_test_moqt_fetch_response(r,
                scenario ? 0 : 4, 0), -XQC_EILLEGAL_FRAME);
        } else if (scenario == 2) {
            xqc_moqt_stream_t *duplicate = xqc_test_moqt_incoming(&f);
            CU_ASSERT_EQUAL(xqc_moqt_stream_input(duplicate, prefix,
                sizeof(prefix), 0), -XQC_EILLEGAL_FRAME);
        } else if (scenario == 3) {
            f.session->config.max_buffered_bytes = f.session->buffered_bytes;
            uint8_t bytes[XQC_MOQT_TEST_CAPACITY] = {0};
            CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, bytes, sizeof(bytes), 0),
                            -XQC_EMALLOC);
            CU_ASSERT_EQUAL(f.fetch_closed, 1);
            CU_ASSERT_FALSE(f.session->closed);
        } else if (scenario == 4) {
            xqc_moqt_message_t error = {.type = XQC_MOQT_MSG_REQUEST_ERROR,
                .error = {.code = XQC_MOQT_REQUEST_INVALID_RANGE}};
            CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &error,
                XQC_MOQT_MSG_FETCH, 0), XQC_OK);
            CU_ASSERT_EQUAL(f.last_code, XQC_MOQT_REQUEST_INVALID_RANGE);
            CU_ASSERT_TRUE(st->discarded);
        } else {
            CU_ASSERT_EQUAL(xqc_test_moqt_fetch_response(r, 3, 9), XQC_OK);
            if (scenario == 5) {
                xqc_moqt_session_timeout(f.session->timer, fetch->deadline,
                                         f.session);
                CU_ASSERT_EQUAL(f.fetch_closed, 1);
                CU_ASSERT_FALSE(f.session->closed);
            } else {
                uint8_t object[] = {0x1f, 1, 0, 0, 7, 1, 'x'};
                if (scenario == 6) {
                    object[0] = 0; /* First Object cannot inherit location. */
                } else if (scenario == 7) {
                    object[1] = 4; /* Beyond the inclusive End Location. */
                } else {
                    f.cancel_in_object = 1;
                }
                xqc_int_t ret = xqc_moqt_stream_input(st, object,
                    sizeof(object), 1);
                CU_ASSERT_EQUAL(ret, scenario == 8 ? XQC_OK
                                                   : -XQC_EILLEGAL_FRAME);
                CU_ASSERT_EQUAL(f.fetch_closed, scenario == 8);
            }
        }
        if (scenario < 3 || scenario == 6 || scenario == 7) {
            CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
        }
        xqc_test_moqt_destroy(&f);
    }
}

void
xqc_test_moqt_fetch_lifecycle(void)
{
    moqt_fixture_t f;
    xqc_moqt_request_t *r = xqc_test_moqt_fetch_request(
        &f, 0, XQC_MOQT_GROUP_ASCENDING);
    xqc_moqt_fetch_t *fetch = r->fetch;
    fetch->track->has_largest = 1;
    fetch->track->largest = (xqc_moqt_location_t){2, 7};
    xqc_moqt_message_t ok = {.type = XQC_MOQT_MSG_FETCH_OK,
        .end_group = 3, .end_object = 9, .end_of_track = 1};
    fetch->track->has_end = fetch->track->end_inclusive = 1;
    fetch->track->end = (xqc_moqt_location_t){3, 8};
    CU_ASSERT_EQUAL(xqc_moqt_fetch_apply(r, &ok), XQC_MOQT_NO_ERROR);
    CU_ASSERT_EQUAL(fetch->track->end.object_id, 8);
    fetch->track->has_end = 0;
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &ok,
        XQC_MOQT_MSG_FETCH, 0), XQC_OK);
    CU_ASSERT_TRUE(fetch->track->end_inclusive);
    CU_ASSERT_EQUAL(fetch->track->largest.group_id, 2);
    uint8_t priority[] = {3};
    xqc_moqt_message_t update = {.type = XQC_MOQT_MSG_REQUEST_UPDATE,
        .parameter_count = 1};
    update.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_SUBSCRIBER_PRIORITY, 1, priority};
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &update), XQC_OK);
    CU_ASSERT_EQUAL(fetch->info.subscriber_priority, 7);
    ok = (xqc_moqt_message_t){.type = XQC_MOQT_MSG_REQUEST_OK};
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &ok,
        XQC_MOQT_MSG_REQUEST_UPDATE, 0), XQC_OK);
    CU_ASSERT_EQUAL(fetch->info.subscriber_priority, 3);
    xqc_moqt_stream_t *st = xqc_test_moqt_incoming(&f);
    const uint8_t end[] = {5, 0, 0x1f, 3, 0, 9, 7, 0};
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, end, sizeof(end), 1), XQC_OK);
    CU_ASSERT_EQUAL(f.objects, 1);
    CU_ASSERT_EQUAL(f.fetch_closed, 1);
    CU_ASSERT_EQUAL(fetch->track->largest.group_id, 2);
    CU_ASSERT_EQUAL(fetch->track->largest.object_id, 7);
    CU_ASSERT_FALSE(st->state.data.subgroup->has_last);
    CU_ASSERT_FALSE(st->state.data.subgroup->group->has_end);
    xqc_test_moqt_destroy(&f);

    /* Local capacity failures cancel only this Fetch, not the Session. */
    for (unsigned scenario = 0; scenario < 4; scenario++) {
        r = xqc_test_moqt_fetch_request(&f, 1, XQC_MOQT_GROUP_ASCENDING);
        CU_ASSERT_EQUAL(xqc_test_moqt_fetch_response(r, 3, 9), XQC_OK);
        size_t budget = f.session->config.max_buffered_bytes;
        if (scenario < 2) {
            xqc_moqt_request_t candidate = *r;
            candidate.fetch = NULL;
            f.session->config.max_buffered_bytes = f.session->buffered_bytes
                + (scenario ? sizeof(xqc_moqt_fetch_t) : 0);
            CU_ASSERT_EQUAL(xqc_moqt_fetch_create(
                &candidate, (void *)candidate.state->data),
                            XQC_MOQT_INTERNAL_ERROR);
            CU_ASSERT_PTR_NULL(candidate.fetch);
        } else {
            f.session->config.max_buffered_bytes = f.session->buffered_bytes
                + (scenario == 3 ? sizeof(xqc_var_buf_t) + 2 : 0);
            CU_ASSERT_PTR_NULL(xqc_moqt_fetch_open(r->fetch));
        }
        f.session->config.max_buffered_bytes = budget;
        CU_ASSERT_FALSE(f.session->closed);
        xqc_test_moqt_destroy(&f);
    }
    /* Orphaned Fetch waiting for its stream has a bounded deadline. */
    r = xqc_test_moqt_fetch_request(&f, 0, XQC_MOQT_GROUP_ASCENDING);
    CU_ASSERT_EQUAL(xqc_test_moqt_fetch_response(r, 3, 9), XQC_OK);
    fetch = r->fetch;
    xqc_moqt_stream_callbacks.stream_close_notify(r->stream->transport_stream,
                                                  r->stream);
    CU_ASSERT_PTR_NULL(fetch->request);
    xqc_moqt_session_timeout(f.session->timer, fetch->deadline, f.session);
    CU_ASSERT_EQUAL(f.fetch_closed, 1);
    CU_ASSERT_PTR_NULL(f.session->fetches);
    CU_ASSERT_FALSE(f.session->closed);
    xqc_test_moqt_destroy(&f);

    /* Pending FIN must not be reported as success if FETCH_OK never arrives. */
    r = xqc_test_moqt_fetch_request(&f, 0, XQC_MOQT_GROUP_ASCENDING);
    st = xqc_test_moqt_incoming(&f);
    const uint8_t prefix[] = {5, 0};
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, prefix, sizeof(prefix), 1),
                    XQC_OK);
    xqc_moqt_stream_callbacks.stream_close_notify(st->transport_stream, st);
    CU_ASSERT_EQUAL(f.fetch_closed, 0);
    xqc_test_moqt_destroy(&f);
    CU_ASSERT_EQUAL(f.fetch_closed, 1);
    CU_ASSERT_EQUAL(f.fetch_error, XQC_MOQT_RESET_SESSION_CLOSED);
}

void
xqc_test_moqt_fetch_track_error(void)
{
    moqt_fixture_t f;
    xqc_moqt_request_t *r = xqc_test_moqt_fetch_request(
        &f, 0, XQC_MOQT_GROUP_ASCENDING);
    CU_ASSERT_EQUAL(xqc_test_moqt_fetch_response(r, 3, 9), XQC_OK);
    xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_FETCH,
        .track_name = {"video", 5}};
    xqc_moqt_request_t *same = xqc_moqt_request_open(f.session, &m);
    CU_ASSERT_PTR_NOT_NULL_FATAL(same);
    CU_ASSERT_PTR_EQUAL(same->fetch->track, r->fetch->track);
    m.track_name = (struct iovec){"other", 5};
    xqc_moqt_request_t *other = xqc_moqt_request_open(f.session, &m);
    CU_ASSERT_PTR_NOT_NULL_FATAL(other);
    uint8_t wire[128] = {5, 0}, properties[32];
    xqc_moqt_kv_t mandatory = {.type = 0x4000, .value.integer = 1};
    xqc_int_t len = xqc_moqt_kv_encode(&mandatory, 0, properties,
                                       sizeof(properties));
    xqc_moqt_fetch_history_t history;
    xqc_memzero(&history, sizeof(history));
    xqc_moqt_object_t o = {.group_id = 1, .priority = 7,
        .properties = {properties, len}};
    len = xqc_moqt_fetch_header_encode(XQC_MOQT_GROUP_ASCENDING, &history,
                                       &o, wire + 2, sizeof(wire) - 2);
    CU_ASSERT(len > 0);
    xqc_moqt_stream_t *st = xqc_test_moqt_incoming(&f);
    /* Section 3.7: malformed Track properties terminate related Fetches. */
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, wire, len + 2, 0), XQC_OK);
    CU_ASSERT_EQUAL(f.objects, 0);
    CU_ASSERT_EQUAL(f.fetch_closed, 2);
    CU_ASSERT_EQUAL(f.fetch_error, XQC_MOQT_RESET_MALFORMED_TRACK);
    CU_ASSERT_FALSE(other->failed);
    CU_ASSERT_FALSE(f.session->closed);
    CU_ASSERT_EQUAL(xqc_test_moqt_fetch_response(other, 3, 9), XQC_OK);
    xqc_moqt_request_cancel(other, XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_EQUAL(f.fetch_closed, 3);
    CU_ASSERT_FALSE(f.session->closed);
    xqc_test_moqt_destroy(&f);
}

static xqc_moqt_request_t *
xqc_test_moqt_fill_request(moqt_fixture_t *f, xqc_int_t publisher,
    uint8_t *fill, size_t len, uint8_t forward, uint8_t filter)
{
    xqc_test_moqt_request_init(f, publisher);
    f->session->callbacks.on_fetch_ready = xqc_test_moqt_fetch_ready_notify;
    f->session->callbacks.on_fetch_closed = xqc_test_moqt_fetch_closed_notify;
    uint8_t priority = 7;
    xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_SUBSCRIBE,
        .track_name = {"video", 5}, .parameter_count = 4};
    m.parameters[0] = (xqc_moq_message_parameter_t){XQC_MOQT_PARAM_FORWARD,
        1, &forward};
    m.parameters[1] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_SUBSCRIBER_PRIORITY, 1, &priority};
    m.parameters[2] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_LOCATION_FILTER, 1, &filter};
    m.parameters[3] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FILL_PARAMETERS, len, fill};
    if (publisher) {
        xqc_moqt_stream_t *st = xqc_test_moqt_request_stream(f);
        CU_ASSERT_EQUAL(xqc_test_moqt_request_input(st, &m, m.type, 0), XQC_OK);
        return &st->state.request;
    }
    return xqc_moqt_request_open(f->session, &m);
}

static xqc_int_t
xqc_test_moqt_fill_response(xqc_moqt_request_t *r, xqc_int_t has_largest)
{
    uint8_t largest[] = {5, 7};
    xqc_int_t initial = !r->responded;
    xqc_moqt_message_t ok = {.type = initial ? XQC_MOQT_MSG_SUBSCRIBE_OK
                                            : XQC_MOQT_MSG_REQUEST_OK};
    if (has_largest) {
        ok.parameter_count = 1;
        ok.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_LARGEST_OBJECT, sizeof(largest), largest};
    }
    if (xqc_moqt_is_local_publisher(r)) {
        return xqc_moqt_request_send(r, &ok);
    }
    return xqc_test_moqt_request_input(r->stream, &ok,
        initial ? XQC_MOQT_MSG_SUBSCRIBE : XQC_MOQT_MSG_REQUEST_UPDATE, 0);
}

void
xqc_test_moqt_fill_parameters(void)
{
    /* Section 9.20.15: length-delimited parameters form a separate scope. */
    uint8_t values[] = {12, 0x0a, 0, 0x16, 3, 1, 4, 1, 2, 2, 5, 1, 2};
    xqc_moq_message_parameter_t p = {XQC_MOQT_PARAM_FILL_PARAMETERS,
        sizeof(values), values};
    xqc_moqt_message_t inner;
    CU_ASSERT_EQUAL(xqc_moqt_fill_parameters_decode(&p, &inner), XQC_OK);
    CU_ASSERT_EQUAL(inner.parameter_count, 4);
    CU_ASSERT_EQUAL(inner.parameters[0].type, XQC_MOQT_PARAM_FILL_TIMEOUT);
    CU_ASSERT_EQUAL(inner.parameters[3].type, XQC_MOQT_PARAM_GROUP_ORDER);
    uint8_t priority = 8, wire[128];
    xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_SUBSCRIBE,
        .parameter_count = 2};
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_SUBSCRIBER_PRIORITY, 1, &priority};
    m.parameters[1] = p;
    xqc_int_t n = xqc_moqt_message_encode(&m, m.type, wire, sizeof(wire));
    CU_ASSERT(n > 0);
    CU_ASSERT_EQUAL(xqc_moqt_message_decode(wire, n, m.type, &inner), n);
    /* Mutating a legal inner type to FORWARD is a peer protocol violation. */
    wire[n - sizeof(values) + 1] = XQC_MOQT_PARAM_FORWARD;
    CU_ASSERT_EQUAL(xqc_moqt_message_decode(wire, n, m.type, &inner),
                    -XQC_EILLEGAL_FRAME);
    for (size_t i = 0; i < sizeof(values); i++) {
        p.length = i;
        CU_ASSERT_EQUAL(xqc_moqt_fill_parameters_decode(&p, &inner), XQC_ERROR);
    }
    const uint8_t invalid[][6] = {
        {2, 0x10, 1}, {2, 0x23, 0}, {4, 0x20, 1, 0, 2},
        {2, 0x22, 0}, {3, 0x20, 1, 0}, {2, 0x35, 1},
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        p.value = (uint8_t *)invalid[i];
        p.length = invalid[i][0] + 1;
        m.parameters[1] = p;
        CU_ASSERT_EQUAL(xqc_moqt_fill_parameters_decode(&p, &inner), XQC_ERROR);
        CU_ASSERT_EQUAL(xqc_moqt_message_encode(&m, m.type, NULL, 0),
                        -XQC_EPARAM);
    }
    /* Range filters are well-formed inside Fill but exceed our zero budget. */
    uint8_t ranges[] = {8, 0x25, 0, 1, 0, 1, 0, 1, 0};
    p.value = ranges;
    p.length = sizeof(ranges);
    CU_ASSERT_EQUAL(xqc_moqt_fill_parameters_decode(&p, &inner), XQC_OK);
    CU_ASSERT_EQUAL(inner.parameter_count, 4);
    moqt_fixture_t f;
    xqc_moqt_request_t *r = xqc_test_moqt_fill_request(&f, 1, ranges,
        sizeof(ranges), 1, XQC_MOQT_FILTER_NONE);
    CU_ASSERT_TRUE(r->failed);
    CU_ASSERT_EQUAL(r->error.code, XQC_MOQT_REQUEST_INVALID_FILTER);
    CU_ASSERT_EQUAL(f.fetch_ready, 0);
    CU_ASSERT_PTR_NULL(f.session->fetches);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_fill_snapshots(void)
{
    for (xqc_int_t publisher = 0; publisher <= 1; publisher++) {
        moqt_fixture_t f;
        uint8_t values[] = {12, 0x0a, 0, 0x16, 3, 1, 4, 1, 2, 2, 5, 1, 2};
        xqc_moqt_request_t *r = xqc_test_moqt_fill_request(&f, publisher,
            values, sizeof(values), 1, XQC_MOQT_FILTER_NEXT_OBJECT);
        CU_ASSERT_PTR_NOT_NULL_FATAL(r);
        xqc_moqt_fetch_t *first = f.session->fetches;
        xqc_moqt_subscription_t *sub = r->subscription;
        CU_ASSERT_PTR_EQUAL(first->subscription, sub);
        CU_ASSERT_PTR_NULL(first->request);
        CU_ASSERT_EQUAL(f.fetch_ready, 0);
        CU_ASSERT_EQUAL(xqc_test_moqt_fill_response(r, 1), XQC_OK);
        CU_ASSERT_EQUAL(f.fetch_ready, 1);
        CU_ASSERT_EQUAL(first->info.start.group_id, 1);
        CU_ASSERT_EQUAL(first->info.start.object_id, 2);
        CU_ASSERT_EQUAL(first->info.end.group_id, 3);
        CU_ASSERT_EQUAL(first->info.end.object_id, 5);
        CU_ASSERT_EQUAL(first->info.subscriber_priority, 3);
        CU_ASSERT_EQUAL(first->info.group_order, XQC_MOQT_GROUP_DESCENDING);
        CU_ASSERT_TRUE(first->info.has_fill_timeout);
        CU_ASSERT_EQUAL(first->info.fill_timeout, 0);
        CU_ASSERT_EQUAL(sub->subscriber_priority, 7);
        CU_ASSERT_TRUE(sub->start_exclusive);
        uint8_t empty = 0, filter = XQC_MOQT_FILTER_NONE, priority = 9;
        xqc_moqt_message_t update = {.type = XQC_MOQT_MSG_REQUEST_UPDATE,
            .request_id = 2, .parameter_count = 3};
        update.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_SUBSCRIBER_PRIORITY, 1, &priority};
        update.parameters[1] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_LOCATION_FILTER, 1, &filter};
        update.parameters[2] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_FILL_PARAMETERS, 1, &empty};
        CU_ASSERT_EQUAL(publisher ? xqc_test_moqt_request_input(r->stream,
            &update, r->initial_type, 0) : xqc_moqt_request_send(r, &update),
            XQC_OK);
        xqc_moqt_fetch_t *second = f.session->fetches;
        CU_ASSERT_PTR_NOT_EQUAL(first, second);
        CU_ASSERT_EQUAL(xqc_test_moqt_fill_response(r, 1), XQC_OK);
        CU_ASSERT_EQUAL(f.fetch_ready, 2);
        CU_ASSERT_EQUAL(second->info.request_id, 2);
        CU_ASSERT_EQUAL(second->info.start.group_id, 0);
        CU_ASSERT_EQUAL(second->info.end.group_id, 5);
        CU_ASSERT_EQUAL(second->info.end.object_id, 7);
        CU_ASSERT_EQUAL(second->info.subscriber_priority, 9);
        CU_ASSERT_FALSE(second->info.has_fill_timeout);
        CU_ASSERT_EQUAL(first->info.subscriber_priority, 3);
        CU_ASSERT_EQUAL(first->info.end.group_id, 3);
        CU_ASSERT_TRUE(xqc_list_empty(&r->sent_updates));
        CU_ASSERT_TRUE(xqc_list_empty(&r->received_updates));
        sub->track->largest.group_id = 20;
        CU_ASSERT_EQUAL(second->info.end.group_id, 5);
        update.parameter_count = 0;
        update.request_id = 4;
        CU_ASSERT_EQUAL(publisher ? xqc_test_moqt_request_input(r->stream,
            &update, r->initial_type, 0) : xqc_moqt_request_send(r, &update),
            XQC_OK);
        CU_ASSERT_EQUAL(xqc_test_moqt_fill_response(r, 0), XQC_OK);
        CU_ASSERT_EQUAL(f.fetch_ready, 2);
        CU_ASSERT_PTR_EQUAL(f.session->fetches, second);
        xqc_moqt_fetch_cancel(second, XQC_MOQT_RESET_CANCELLED);
        CU_ASSERT_FALSE(r->failed);
        CU_ASSERT_FALSE(sub->stopped);
        CU_ASSERT_FALSE(first->closed);
        xqc_moqt_subscription_cancel(sub, XQC_MOQT_RESET_CANCELLED);
        CU_ASSERT_EQUAL(f.fetch_closed, 2);
        CU_ASSERT_FALSE(f.session->closed);
        xqc_test_moqt_destroy(&f);
    }
}

void
xqc_test_moqt_fill_suppressed(void)
{
    for (unsigned scenario = 0; scenario < 5; scenario++) {
        moqt_fixture_t f;
        uint8_t values[] = {0};
        xqc_moqt_request_t *r = xqc_test_moqt_fill_request(&f, 0, values,
            sizeof(values), scenario != 0, scenario == 2
                ? XQC_MOQT_FILTER_NEXT_OBJECT : XQC_MOQT_FILTER_NONE);
        CU_ASSERT_PTR_NOT_NULL_FATAL(r);
        if (scenario == 3) {
            /* A later live Largest must not supply an omitted OK Largest. */
            r->subscription->track->has_largest = 1;
            r->subscription->track->largest.group_id = 8;
        }
        if (scenario == 4) {
            xqc_moqt_fetch_cancel(f.session->fetches,
                                  XQC_MOQT_RESET_CANCELLED);
        }
        CU_ASSERT_EQUAL(xqc_test_moqt_fill_response(r,
            scenario == 0 || scenario == 2 || scenario == 4), XQC_OK);
        CU_ASSERT_EQUAL(f.fetch_ready, 0);
        CU_ASSERT_PTR_NULL(f.session->fetches);
        CU_ASSERT_FALSE(r->failed);
        xqc_test_moqt_destroy(&f);
    }
    moqt_fixture_t f;
    uint8_t empty = 0, forward = 1;
    xqc_moqt_request_t *r = xqc_test_moqt_fill_request(&f, 0, &empty, 1, 0,
        XQC_MOQT_FILTER_NONE);
    CU_ASSERT_EQUAL(xqc_test_moqt_fill_response(r, 1), XQC_OK);
    xqc_moqt_message_t update = {.type = XQC_MOQT_MSG_REQUEST_UPDATE,
        .parameter_count = 1};
    update.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FORWARD, 1, &forward};
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &update), XQC_OK);
    CU_ASSERT_EQUAL(xqc_test_moqt_fill_response(r, 1), XQC_OK);
    CU_ASSERT_EQUAL(f.fetch_ready, 0);
    update.parameter_count = 2;
    update.parameters[1] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FILL_PARAMETERS, 1, &empty};
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &update), XQC_OK);
    CU_ASSERT_EQUAL(xqc_test_moqt_fill_response(r, 1), XQC_OK);
    CU_ASSERT_EQUAL(f.fetch_ready, 1);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_fill_lifecycle(void)
{
    for (unsigned early = 0; early < 2; early++) {
        moqt_fixture_t f;
        uint8_t empty = 0;
        xqc_moqt_request_t *r = xqc_test_moqt_fill_request(&f, 0, &empty, 1, 1,
            XQC_MOQT_FILTER_NONE);
        CU_ASSERT_PTR_NOT_NULL_FATAL(r);
        f.session->callbacks.on_object = xqc_test_moqt_fetch_object;
        f.session->callbacks.on_stream_closed = xqc_test_moqt_subgroup_closed;
        xqc_moqt_fetch_t *fetch = f.session->fetches;
        xqc_moqt_subscription_t *sub = r->subscription;
        xqc_moqt_stream_t *st = xqc_test_moqt_incoming(&f);
        const uint8_t wire[] = {5, 0, 0x1f, 1, 0, 0, 7, 1, 'a'};
        if (early) {
            CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, wire, sizeof(wire), 1),
                            XQC_OK);
            xqc_moqt_stream_callbacks.stream_close_notify(
                st->transport_stream, st);
            CU_ASSERT_EQUAL(f.objects, 0);
            CU_ASSERT_PTR_NULL(st->transport_stream);
        }
        CU_ASSERT_EQUAL(xqc_test_moqt_fill_response(r, 1), XQC_OK);
        CU_ASSERT_EQUAL(f.fetch_ready, 1);
        xqc_moqt_message_t done = {.type = XQC_MOQT_MSG_PUBLISH_DONE,
            .stream_count = 1};
        if (!early) {
            CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &done,
                r->initial_type, 0), XQC_OK);
            xqc_moqt_stream_callbacks.stream_close_notify(
                r->stream->transport_stream, r->stream);
            CU_ASSERT_PTR_NULL(sub->request);
            CU_ASSERT_PTR_NULL(fetch->request);
            CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, wire, sizeof(wire), 1),
                            XQC_OK);
            CU_ASSERT_TRUE(sub->closed);
            xqc_moqt_stream_callbacks.stream_close_notify(
                st->transport_stream, st);
        } else {
            CU_ASSERT_EQUAL(sub->stream_count, 1);
            CU_ASSERT_EQUAL(sub->finished_streams, 1);
            CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &done,
                r->initial_type, 0), XQC_OK);
        }
        CU_ASSERT_EQUAL(f.fetch_closed, 1);
        CU_ASSERT_EQUAL(f.fetch_error, XQC_MOQT_NO_ERROR);
        CU_ASSERT_EQUAL(f.objects, 1);
        CU_ASSERT_EQUAL(f.object_bytes, 1);
        CU_ASSERT_PTR_NULL(f.session->fetches);
        CU_ASSERT_PTR_NULL(f.session->subscriptions);
        xqc_test_moqt_destroy(&f);
    }
    /* A default source failure must write the header before reliable reset. */
    for (unsigned blocked = 0; blocked < 2; blocked++) {
        moqt_fixture_t f;
        uint8_t empty = 0;
        xqc_moqt_request_t *r = xqc_test_moqt_fill_request(&f, 1, &empty, 1, 1,
            XQC_MOQT_FILTER_NONE);
        f.conn->remote_settings.reset_stream_at = 1;
        f.conn->conn_flag |= XQC_CONN_FLAG_TLS_HSK_COMPLETED;
        if (!blocked) {
            f.session->callbacks.on_fetch_ready = NULL;
        }
        CU_ASSERT_EQUAL(xqc_test_moqt_fill_response(r, 1), XQC_OK);
        xqc_moqt_fetch_t *fetch = f.session->fetches;
        CU_ASSERT_PTR_NOT_NULL_FATAL(fetch);
        xqc_moqt_stream_t *st = blocked ? xqc_moqt_fetch_open(fetch)
                                        : fetch->stream;
        CU_ASSERT_PTR_NOT_NULL_FATAL(st);
        if (blocked) {
            xqc_list_buf_t *entry = xqc_list_entry(st->tx.next,
                xqc_list_buf_t, list_head);
            CU_ASSERT_EQUAL(xqc_stream_send(st->transport_stream,
                entry->buf->data, 1, 0), 1);
            entry->buf->consumed_len = 1;
            st->transport_stream->stream_flow_ctl.fc_max_stream_data_can_send
                = 0;
            xqc_moqt_fetch_cancel(fetch, XQC_MOQT_RESET_INTERNAL_ERROR);
        }
        CU_ASSERT_EQUAL(r->subscription->stream_count, 1);
        xqc_moqt_message_t done = {.type = XQC_MOQT_MSG_PUBLISH_DONE};
        if (blocked) {
            CU_ASSERT_TRUE(st->state.data.reset_pending);
            CU_ASSERT_FALSE(st->discarded);
            CU_ASSERT_EQUAL(st->transport_stream->stream_send_offset, 1);
            CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &done), -XQC_EAGAIN);
            st->transport_stream->stream_flow_ctl.fc_max_stream_data_can_send
                = XQC_MOQT_TEST_CAPACITY;
            CU_ASSERT_EQUAL(xqc_moqt_stream_callbacks.stream_write_notify(
                st->transport_stream, st), XQC_OK);
        }
        CU_ASSERT_TRUE(st->discarded);
        CU_ASSERT_EQUAL(st->transport_stream->stream_send_offset, 2);
        CU_ASSERT_EQUAL(st->transport_stream->reset_at.send_size, 2);
        CU_ASSERT_EQUAL(f.fetch_closed, 1);
        CU_ASSERT_EQUAL(f.fetch_error, XQC_MOQT_RESET_INTERNAL_ERROR);
        CU_ASSERT_FALSE(r->failed);
        CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &done), XQC_OK);
        xqc_test_moqt_destroy(&f);
    }
}

void
xqc_test_moqt_fill_scheduling(void)
{
    moqt_fixture_t f;
    uint8_t empty = 0;
    xqc_moqt_request_t *r = xqc_test_moqt_fill_request(&f, 1, &empty, 1, 1,
        XQC_MOQT_FILTER_NONE);
    CU_ASSERT_EQUAL(xqc_test_moqt_fill_response(r, 1), XQC_OK);
    xqc_moqt_fetch_t *fetch = f.session->fetches;
    xqc_moqt_subscription_t *sub = r->subscription;
    xqc_datagram_record_mss(f.conn);
    xqc_moqt_object_t history = {.group_id = 1, .priority = 7};
    xqc_moqt_object_t live = history;
    live.group_id = 2;
    CU_ASSERT(xqc_moqt_data_compare(sub, &history, fetch,
                                    sub, &live, NULL) < 0);
    fetch->info.group_order = XQC_MOQT_GROUP_DESCENDING;
    CU_ASSERT(xqc_moqt_data_compare(sub, &history, fetch,
                                    sub, &live, NULL) > 0);
    CU_ASSERT(xqc_moqt_data_compare(sub, &live, NULL,
                                    sub, &history, fetch) < 0);
    live.group_id = 1;
    live.datagram = 1;
    CU_ASSERT(xqc_moqt_data_compare(sub, &history, fetch,
                                    sub, &live, NULL) < 0);
    CU_ASSERT(xqc_moqt_data_compare(sub, &live, NULL,
                                    sub, &history, fetch) > 0);
    fetch->info.subscriber_priority++;
    CU_ASSERT(xqc_moqt_data_compare(sub, &history, fetch,
                                    sub, &live, NULL) > 0);
    fetch->info.subscriber_priority = sub->subscriber_priority;
    history.priority++;
    CU_ASSERT(xqc_moqt_data_compare(sub, &history, fetch,
                                    sub, &live, NULL) > 0);
    history.priority = live.priority;
    xqc_moqt_stream_t *st = xqc_moqt_fetch_open(fetch);
    CU_ASSERT_PTR_NOT_NULL_FATAL(st);
    f.session->flushing = 1;
    CU_ASSERT_EQUAL(xqc_moqt_stream_send_object(st, &history), XQC_OK);
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(sub, &live), -XQC_EAGAIN);
    f.session->flushing = 0;
    CU_ASSERT_EQUAL(xqc_moqt_stream_finish(st), XQC_OK);
    st->transport_stream->stream_flow_ctl.fc_max_stream_data_can_send
        = XQC_MOQT_TEST_CAPACITY;
    CU_ASSERT_EQUAL(xqc_moqt_stream_callbacks.stream_write_notify(
        st->transport_stream, st), XQC_OK);
    CU_ASSERT_EQUAL(xqc_moqt_datagram_send(sub, &live), XQC_OK);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_fill_errors(void)
{
    moqt_fixture_t f;
    uint8_t empty = 0;
    xqc_moqt_request_t *r = xqc_test_moqt_fill_request(&f, 0, &empty, 1, 1,
        XQC_MOQT_FILTER_NONE);
    size_t budget = f.session->config.max_buffered_bytes;
    xqc_moqt_message_t update = {.type = XQC_MOQT_MSG_REQUEST_UPDATE,
        .request_id = 2, .parameter_count = 1};
    update.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FILL_PARAMETERS, 1, &empty};
    f.session->config.max_buffered_bytes = f.session->buffered_bytes;
    CU_ASSERT_EQUAL(xqc_moqt_fetch_create(r, &update), XQC_MOQT_INTERNAL_ERROR);
    f.session->config.max_buffered_bytes = budget;
    CU_ASSERT_EQUAL(xqc_test_moqt_fill_response(r, 1), XQC_OK);
    xqc_moqt_stream_t *st = xqc_test_moqt_incoming(&f);
    const uint8_t prefix[] = {5, 0};
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, prefix, sizeof(prefix), 0),
                    XQC_OK);
    xqc_moqt_stream_t *duplicate = xqc_test_moqt_incoming(&f);
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(duplicate, prefix, sizeof(prefix), 0),
                    -XQC_EILLEGAL_FRAME);
    CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
    xqc_test_moqt_destroy(&f);

    /* An early peer stream cannot make an empty range deliver Objects. */
    uint8_t range[] = {4, XQC_MOQT_PARAM_LOCATION_FILTER,
        XQC_MOQT_FILTER_ABSOLUTE_START, 6, 0};
    r = xqc_test_moqt_fill_request(&f, 0, range, sizeof(range), 1,
        XQC_MOQT_FILTER_NONE);
    st = xqc_test_moqt_incoming(&f);
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, prefix, sizeof(prefix), 1),
                    XQC_OK);
    CU_ASSERT_EQUAL(xqc_test_moqt_fill_response(r, 1), XQC_OK);
    CU_ASSERT_TRUE(st->discarded);
    CU_ASSERT_EQUAL(f.fetch_ready, 0);
    xqc_moqt_stream_callbacks.stream_close_notify(st->transport_stream, st);
    CU_ASSERT_PTR_NULL(f.session->fetches);
    xqc_test_moqt_destroy(&f);

    /* A PUBLISH subscriber can request Fill on its reverse update direction. */
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_subscription_t *sub = xqc_test_moqt_object_subscription(
        &f, "video", 0, 1, 7);
    r = sub->request;
    f.session->callbacks.on_fetch_ready = xqc_test_moqt_fetch_ready_notify;
    f.session->callbacks.on_fetch_closed = xqc_test_moqt_fetch_closed_notify;
    update.request_id = 1;
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &update,
        XQC_MOQT_MSG_PUBLISH, 0), XQC_OK);
    CU_ASSERT_EQUAL(xqc_test_moqt_fill_response(r, 1), XQC_OK);
    xqc_moqt_fetch_t *fetch = f.session->fetches;
    CU_ASSERT_PTR_NOT_NULL_FATAL(fetch);
    CU_ASSERT_EQUAL(fetch->info.request_id, 1);
    CU_ASSERT_PTR_EQUAL(fetch->subscription, sub);
    xqc_moqt_message_t done = {.type = XQC_MOQT_MSG_PUBLISH_DONE};
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &done), -XQC_EAGAIN);
    st = xqc_moqt_fetch_open(fetch);
    CU_ASSERT_PTR_NOT_NULL_FATAL(st);
    st->transport_stream->stream_flow_ctl.fc_max_stream_data_can_send = 0;
    xqc_moqt_fetch_cancel(fetch, XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_TRUE(st->state.data.reset_pending);
    xqc_usec_t deadline = st->deadline;
    CU_ASSERT_NOT_EQUAL(deadline, 0);
    xqc_moqt_stream_cancel(st, XQC_MOQT_RESET_INTERNAL_ERROR);
    CU_ASSERT_EQUAL(st->deadline, deadline);
    CU_ASSERT_EQUAL(st->state.data.error, XQC_MOQT_RESET_CANCELLED);
    /* A permanently blocked reliable prefix is bounded by the stream timer. */
    xqc_moqt_session_timeout(f.session->timer, st->deadline, f.session);
    CU_ASSERT_TRUE(f.session->closed);
    CU_ASSERT_EQUAL(f.error, XQC_MOQT_INTERNAL_ERROR);
    xqc_test_moqt_destroy(&f);
}

static void
xqc_test_moqt_namespace_event(xqc_moqt_request_t *r,
    const xqc_moqt_namespace_t *name, xqc_bool_t available, void *data)
{
    moqt_fixture_t *f = data;
    f->namespace_adds += available;
    f->namespace_removes += !available;
    f->namespace_fields = name->count;
    f->namespace_first = name->count
        ? *(char *)name->fields[0].iov_base : 0;
    char first = f->namespace_first;
    if (f->cancel_in_namespace) {
        xqc_moqt_request_cancel(r, XQC_MOQT_RESET_CANCELLED);
        if (name->count) {
            CU_ASSERT_EQUAL(*(char *)name->fields[0].iov_base, first);
        }
    }
}

static xqc_moqt_request_t *
xqc_test_moqt_namespace_request(moqt_fixture_t *f, xqc_bool_t local,
    uint64_t type, const char *prefix)
{
    xqc_moqt_message_t m = {0};
    m.type = type;
    if (prefix != NULL) {
        m.track_namespace.count = 1;
        m.track_namespace.fields[0] = (struct iovec){(void *)prefix,
                                                    strlen(prefix)};
    }
    f->session->callbacks.on_namespace = xqc_test_moqt_namespace_event;
    if (local) {
        return xqc_moqt_request_open(f->session, &m);
    }
    m.request_id = f->session->stream_count * XQC_MOQT_REQUEST_ID_STEP;
    xqc_moqt_stream_t *st = xqc_test_moqt_request_stream(f);
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(st, &m, type, 0), XQC_OK);
    return &st->state.request;
}

static void
xqc_test_moqt_namespace_ok(xqc_moqt_request_t *r)
{
    xqc_moqt_message_t ok = {.type = XQC_MOQT_MSG_REQUEST_OK};
    CU_ASSERT_EQUAL(r->local
        ? xqc_test_moqt_request_input(r->stream, &ok, r->initial_type, 0)
        : xqc_moqt_request_send(r, &ok), XQC_OK);
}

void
xqc_test_moqt_namespace_codec(void)
{
    /* Draft-22 sections 9.16/9.17: only a suffix, no request ID or name. */
    const uint8_t wire[] = {8, 0, 7, 2, 1, 'a', 3, 0, 0xff, 'b'};
    xqc_moqt_message_t m;
    uint8_t encoded[sizeof(wire)];
    uint64_t context = XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE;
    CU_ASSERT_EQUAL(xqc_moqt_message_decode(wire, sizeof(wire), context, &m),
                    sizeof(wire));
    CU_ASSERT_EQUAL(m.track_namespace.count, 2);
    CU_ASSERT_EQUAL(m.track_namespace.fields[1].iov_len, 3);
    CU_ASSERT_EQUAL(m.request_id, 0);
    CU_ASSERT_EQUAL(xqc_moqt_message_encode(&m, context, encoded,
                                            sizeof(encoded)), sizeof(wire));
    CU_ASSERT_EQUAL(xqc_memcmp(encoded, wire, sizeof(wire)), 0);
    m.type = XQC_MOQT_MSG_NAMESPACE_DONE;
    m.track_namespace.count = 0;
    const uint8_t empty[] = {14, 0, 1, 0};
    CU_ASSERT_EQUAL(xqc_moqt_message_encode(&m, context, encoded,
                                            sizeof(encoded)), sizeof(empty));
    CU_ASSERT_EQUAL(xqc_memcmp(encoded, empty, sizeof(empty)), 0);
    CU_ASSERT_EQUAL(xqc_moqt_message_decode(empty, sizeof(empty), context, &m),
                    sizeof(empty));
}

void
xqc_test_moqt_namespace_codec_errors(void)
{
    xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_NAMESPACE};
    uint8_t wire[] = {8, 0, 3, 1, 1, 'a'};
    uint8_t out[sizeof(wire)];
    uint64_t context = XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE;
    CU_ASSERT(xqc_moqt_message_encode(&m, XQC_MOQT_MSG_PUBLISH_NAMESPACE,
                                      out, sizeof(out)) < 0);
    CU_ASSERT(xqc_moqt_message_decode(wire, sizeof(wire),
                                      XQC_MOQT_MSG_PUBLISH_NAMESPACE, &m) < 0);
    for (size_t n = 0; n < sizeof(wire); n++) {
        CU_ASSERT(xqc_moqt_message_decode(wire, n, context, &m) < 0);
    }
    wire[4] = 0;
    CU_ASSERT(xqc_moqt_message_decode(wire, sizeof(wire), context, &m) < 0);
    m.track_namespace.count = 1;
    m.track_namespace.fields[0] = (struct iovec){NULL, 0};
    CU_ASSERT(xqc_moqt_message_encode(&m, context, NULL, 0) < 0);
}

void
xqc_test_moqt_namespace_discovery(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_request_t *r = xqc_test_moqt_namespace_request(&f, XQC_TRUE,
        XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE, "a");
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    xqc_test_moqt_namespace_ok(r);
    xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_NAMESPACE};
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &m,
                    r->initial_type, 0), XQC_OK);
    size_t used = f.session->buffered_bytes;
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &m,
                    r->initial_type, 0), XQC_OK);
    CU_ASSERT_EQUAL(f.namespace_adds, 1);
    CU_ASSERT_EQUAL(f.session->buffered_bytes, used);
    CU_ASSERT_EQUAL(f.namespace_fields, 1);
    CU_ASSERT_EQUAL(f.namespace_first, 'a');

    /* Section 9.5.2: pre-OK notification still uses a, post-OK uses b. */
    uint8_t prefix[] = {1, 1, 'b'};
    xqc_moqt_message_t update = {.type = XQC_MOQT_MSG_REQUEST_UPDATE,
        .parameter_count = 1};
    update.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_TRACK_NAMESPACE_PREFIX, sizeof(prefix), prefix};
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &update), XQC_OK);
    m.track_namespace.count = 1;
    uint8_t suffix[] = {0, 0xff};
    m.track_namespace.fields[0] = (struct iovec){suffix, sizeof(suffix)};
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &m,
                    r->initial_type, 0), XQC_OK);
    CU_ASSERT_EQUAL(f.namespace_fields, 2);
    CU_ASSERT_EQUAL(f.namespace_first, 'a');
    xqc_test_moqt_namespace_ok(r);
    m.track_namespace.count = 0;
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &m,
                    r->initial_type, 0), XQC_OK);
    CU_ASSERT_EQUAL(f.namespace_first, 'b');
    CU_ASSERT_EQUAL(f.namespace_adds, 3);
    m.type = XQC_MOQT_MSG_NAMESPACE_DONE;
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &m,
                    r->initial_type, 0), XQC_OK);
    CU_ASSERT_EQUAL(f.namespace_removes, 1);
    /* Names already observed under a survive the prefix update. */
    CU_ASSERT_FALSE(xqc_list_empty(&r->namespaces));
    CU_ASSERT_EQUAL(xqc_moqt_request_finish(r), XQC_OK);
    m.type = XQC_MOQT_MSG_NAMESPACE;
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &m,
                    r->initial_type, 0), XQC_OK);
    CU_ASSERT_EQUAL(f.namespace_adds, 4);
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(r->stream, NULL, 0, 1), XQC_OK);
    CU_ASSERT_EQUAL(f.namespace_removes, 4);
    CU_ASSERT_TRUE(xqc_list_empty(&r->namespaces));
    xqc_test_moqt_destroy(&f);
    CU_ASSERT_EQUAL(f.namespace_removes, 4);
}

void
xqc_test_moqt_namespace_overlap(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 1);
    xqc_moqt_request_t *a = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE, "a");
    xqc_moqt_request_t *pending = xqc_test_moqt_namespace_request(&f,
        XQC_FALSE, XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE, "a");
    xqc_test_moqt_namespace_ok(a);
    /* Both requests entered the application before either was established. */
    xqc_test_moqt_namespace_ok(pending);
    CU_ASSERT_TRUE(pending->failed);
    CU_ASSERT_EQUAL(pending->error.code, XQC_MOQT_REQUEST_PREFIX_OVERLAP);
    xqc_moqt_request_t *other = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE, NULL);
    CU_ASSERT_TRUE(other->failed);
    CU_ASSERT_EQUAL(other->error.code, XQC_MOQT_REQUEST_PREFIX_OVERLAP);
    other = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE, "ab");
    xqc_test_moqt_namespace_ok(other);
    CU_ASSERT_TRUE(other->established);
    /* Publishing the same prefix is independent of discovery and publishers. */
    for (unsigned i = 0; i < 2; i++) {
        xqc_moqt_request_t *pub = xqc_test_moqt_namespace_request(&f,
            XQC_FALSE, XQC_MOQT_MSG_PUBLISH_NAMESPACE, "a");
        xqc_test_moqt_namespace_ok(pub);
        CU_ASSERT_TRUE(pub->established);
        xqc_moqt_request_cancel(pub, XQC_MOQT_RESET_CANCELLED);
        CU_ASSERT_FALSE(a->failed);
    }
    xqc_moqt_request_t *reverse = xqc_test_moqt_namespace_request(&f,
        XQC_TRUE, XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE, "a");
    xqc_test_moqt_namespace_ok(reverse);
    CU_ASSERT_TRUE(reverse->established);

    uint8_t prefix[] = {1, 1, 'a'};
    xqc_moqt_message_t update = {.type = XQC_MOQT_MSG_REQUEST_UPDATE,
        .request_id = 100, .parameter_count = 1};
    update.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_TRACK_NAMESPACE_PREFIX, sizeof(prefix), prefix};
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(other->stream, &update,
                    other->initial_type, 0), XQC_OK);
    CU_ASSERT_TRUE(other->failed);
    CU_ASSERT_TRUE(other->stream->tx_fin);
    CU_ASSERT_EQUAL(other->error.code, XQC_MOQT_REQUEST_PREFIX_OVERLAP);
    CU_ASSERT_FALSE(a->failed);
    xqc_moqt_request_cancel(a, XQC_MOQT_RESET_CANCELLED);
    other = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE, "a");
    xqc_test_moqt_namespace_ok(other);
    CU_ASSERT_TRUE(other->established);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_namespace_lifecycle(void)
{
    /* Section 4.2.2: FIN/reset discovery without touching concrete delivery. */
    for (unsigned mode = 0; mode < 4; mode++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 0);
        xqc_moqt_message_t sub = {.type = XQC_MOQT_MSG_SUBSCRIBE};
        xqc_moqt_request_t *camera = xqc_moqt_request_open(f.session, &sub);
        xqc_moqt_message_t ok = {.type = XQC_MOQT_MSG_SUBSCRIBE_OK};
        CU_ASSERT_EQUAL(xqc_test_moqt_request_input(camera->stream, &ok,
                        sub.type, 0), XQC_OK);
        xqc_moqt_request_t *r = xqc_test_moqt_namespace_request(&f, XQC_TRUE,
            XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE, NULL);
        xqc_test_moqt_namespace_ok(r);
        xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_NAMESPACE};
        m.track_namespace.count = 1;
        m.track_namespace.fields[0] = (struct iovec){"a", 1};
        CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &m,
                        r->initial_type, 0), XQC_OK);
        if (mode == 0) {
            f.cancel_in_namespace = 1;
            m.track_namespace.fields[0].iov_base = "b";
            CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &m,
                            r->initial_type, 0), XQC_OK);
            CU_ASSERT_EQUAL(f.namespace_adds, 2);
            CU_ASSERT_EQUAL(f.namespace_removes, 2);
        } else if (mode == 1) {
            xqc_moqt_request_cancel(r, XQC_MOQT_RESET_CANCELLED);
            CU_ASSERT_EQUAL(f.namespace_removes, 1);
        } else if (mode == 2) {
            CU_ASSERT_EQUAL(xqc_moqt_stream_input(r->stream, NULL, 0, 1),
                            XQC_OK);
            CU_ASSERT_EQUAL(f.namespace_removes, 1);
        }
        CU_ASSERT_FALSE(camera->failed);
        CU_ASSERT_FALSE(camera->subscription->stopped);
        xqc_test_moqt_destroy(&f);
        CU_ASSERT_EQUAL(f.namespace_removes, mode == 0 ? 2 : 1);
    }

    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 1);
    xqc_moqt_request_t *r = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE, NULL);
    xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_NAMESPACE};
    CU_ASSERT(xqc_moqt_request_send(r, &m) < 0);
    xqc_test_moqt_namespace_ok(r);
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(r->stream, NULL, 0, 1), XQC_OK);
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &m), XQC_OK);
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &m), XQC_OK);
    m.type = XQC_MOQT_MSG_NAMESPACE_DONE;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &m), XQC_OK);
    CU_ASSERT(xqc_moqt_request_send(r, &m) < 0);
    m.type = XQC_MOQT_MSG_NAMESPACE;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &m), XQC_OK);
    CU_ASSERT_EQUAL(xqc_moqt_request_finish(r), XQC_OK);
    CU_ASSERT_TRUE(xqc_list_empty(&r->namespaces));
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_namespace_errors(void)
{
    for (unsigned mode = 0; mode < 4; mode++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 0);
        xqc_moqt_request_t *r = xqc_test_moqt_namespace_request(&f, XQC_TRUE,
            XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE, "a");
        if (mode != 0) {
            xqc_test_moqt_namespace_ok(r);
        }
        xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_NAMESPACE_DONE};
        if (mode >= 2) {
            m.type = XQC_MOQT_MSG_NAMESPACE;
            m.track_namespace.count = mode == 2
                ? XQC_MOQT_NAMESPACE_MAX_FIELDS : 1;
            char bytes[XQC_MOQT_NAME_MAX_LEN];
            xqc_memset(bytes, 'x', sizeof(bytes));
            for (size_t i = 0; i < m.track_namespace.count; i++) {
                m.track_namespace.fields[i] = (struct iovec){bytes,
                    mode == 2 ? 1 : sizeof(bytes)};
            }
            uint8_t wire[2 * XQC_MOQT_TEST_CAPACITY];
            xqc_int_t n = xqc_moqt_message_encode(&m, r->initial_type,
                                                  wire, sizeof(wire));
            CU_ASSERT(n > 0);
            CU_ASSERT(xqc_moqt_stream_input(r->stream, wire, n, 0) < 0);
        } else {
            CU_ASSERT(xqc_test_moqt_request_input(r->stream, &m,
                                                r->initial_type, 0) < 0);
        }
        CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
        CU_ASSERT_EQUAL(f.namespace_adds, 0);
        xqc_test_moqt_destroy(&f);
    }

    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 1);
    xqc_moqt_request_t *r = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE, NULL);
    xqc_test_moqt_namespace_ok(r);
    xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_NAMESPACE};
    CU_ASSERT(xqc_test_moqt_request_input(r->stream, &m,
                                        r->initial_type, 0) < 0);
    CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_namespace_budget(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 1);
    xqc_moqt_request_t *r = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE, "a");
    xqc_test_moqt_namespace_ok(r);
    size_t used = f.session->buffered_bytes;
    size_t limit = f.session->config.max_buffered_bytes;
    xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_NAMESPACE};
    /* Prepare succeeds, wire allocation fails: the set must roll back. */
    f.session->config.max_buffered_bytes = used + 3 + XQC_MOQT_TX_OVERHEAD;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &m), -XQC_EMALLOC);
    CU_ASSERT_TRUE(xqc_list_empty(&r->namespaces));
    CU_ASSERT_EQUAL(f.session->buffered_bytes, used);
    f.session->config.max_buffered_bytes = used;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &m), -XQC_EMALLOC);
    CU_ASSERT_EQUAL(f.session->buffered_bytes, used);
    f.session->config.max_buffered_bytes = used + 3 + sizeof(xqc_var_buf_t);
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &m), -XQC_EMALLOC);
    CU_ASSERT_EQUAL(f.session->buffered_bytes, used);
    f.session->config.max_buffered_bytes = limit;
    r->stream->writing = 1;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &m), XQC_OK);
    CU_ASSERT_FALSE(xqc_list_empty(&r->namespaces));
    m.type = XQC_MOQT_MSG_NAMESPACE_DONE;
    f.session->config.max_buffered_bytes = f.session->buffered_bytes;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &m), -XQC_EMALLOC);
    CU_ASSERT_FALSE(xqc_list_empty(&r->namespaces));
    f.session->config.max_buffered_bytes = limit;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &m), XQC_OK);
    CU_ASSERT_TRUE(xqc_list_empty(&r->namespaces));
    r->stream->writing = 0;
    CU_ASSERT_EQUAL(xqc_moqt_stream_flush(r->stream), XQC_OK);
    xqc_test_moqt_destroy(&f);

    xqc_test_moqt_request_init(&f, 0);
    r = xqc_test_moqt_namespace_request(&f, XQC_TRUE,
        XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE, NULL);
    xqc_test_moqt_namespace_ok(r);
    /* Direct request input avoids RX allocation masking the set budget. */
    uint8_t wire[] = {8, 0, 1, 0};
    f.session->config.max_buffered_bytes = f.session->buffered_bytes;
    CU_ASSERT_EQUAL(xqc_moqt_request_input(r->stream, wire, sizeof(wire)),
                    XQC_MOQT_NO_ERROR);
    CU_ASSERT_TRUE(r->failed);
    CU_ASSERT_EQUAL(r->error.code, XQC_MOQT_RESET_EXCESSIVE_LOAD);
    CU_ASSERT_FALSE(f.session->closed);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_track_status(void)
{
    /* Section 9.13: one metadata response and FIN, no delivery state. */
    for (unsigned include = 0; include <= 2; include++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 1);
        uint8_t value = include;
        xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_TRACK_STATUS,
            .parameter_count = 1};
        m.track_name = (struct iovec){"camera", 6};
        m.parameter_count = include == 2 ? 0 : 1;
        m.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_INCLUDE_PROPERTIES, sizeof(value), &value};
        xqc_moqt_stream_t *st = xqc_test_moqt_request_stream(&f);
        CU_ASSERT_EQUAL(xqc_test_moqt_request_input(st, &m, m.type, 1),
                        XQC_OK);
        xqc_moqt_request_t *r = &st->state.request;
        st->writing = 1;
        uint8_t properties[] = {0x78, 37}, largest[] = {100, 2};
        xqc_moqt_message_t ok = {.type = XQC_MOQT_MSG_REQUEST_OK,
            .parameter_count = 1};
        ok.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_LARGEST_OBJECT, sizeof(largest), largest};
        ok.properties = (struct iovec){properties, sizeof(properties)};
        CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &ok), XQC_OK);
        CU_ASSERT_TRUE(st->tx_fin);
        xqc_list_buf_t *entry = xqc_list_entry(st->tx.next, xqc_list_buf_t,
                                               list_head);
        xqc_moqt_message_t decoded;
        CU_ASSERT(xqc_moqt_message_decode(entry->buf->data,
                    entry->buf->data_len, m.type, &decoded) > 0);
        CU_ASSERT_EQUAL(decoded.properties.iov_len,
                        include ? sizeof(properties) : 0);
        CU_ASSERT_EQUAL(decoded.parameter_count, 1);
        CU_ASSERT_PTR_NULL(r->subscription);
        CU_ASSERT_PTR_NULL(r->fetch);
        CU_ASSERT_PTR_NULL(f.session->tracks);
        CU_ASSERT_PTR_NULL(f.session->subscriptions);
        st->writing = 0;
        xqc_test_moqt_destroy(&f);
    }
}

void
xqc_test_moqt_track_status_errors(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_request_t *r = xqc_test_moqt_namespace_request(&f, XQC_TRUE,
        XQC_MOQT_MSG_TRACK_STATUS, "a");
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_REQUEST_UPDATE};
    CU_ASSERT(xqc_moqt_request_send(r, &m) < 0);
    m.type = XQC_MOQT_MSG_NAMESPACE;
    CU_ASSERT(xqc_moqt_request_send(r, &m) < 0);
    m.type = XQC_MOQT_MSG_REQUEST_OK;
    uint8_t expires[] = {1};
    m.parameter_count = 1;
    m.parameters[0] = (xqc_moq_message_parameter_t){XQC_MOQT_PARAM_EXPIRES,
                                                sizeof(expires), expires};
    CU_ASSERT(xqc_moqt_message_encode(&m, r->initial_type, NULL, 0) < 0);
    /* Sections 9.13/9.20.16 disagree: retain the conservative RX vector. */
    const uint8_t ambiguous[] = {7, 0, 3, 1, 8, 1};
    xqc_moqt_message_t decoded;
    CU_ASSERT(xqc_moqt_message_decode(ambiguous, sizeof(ambiguous),
                                      r->initial_type, &decoded) < 0);
    m.type = XQC_MOQT_MSG_REQUEST_ERROR;
    m.parameter_count = 0;
    m.error.code = XQC_MOQT_REQUEST_DOES_NOT_EXIST;
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &m,
                    r->initial_type, 1), XQC_OK);
    CU_ASSERT_TRUE(r->failed);
    CU_ASSERT_FALSE(f.session->closed);
    CU_ASSERT_PTR_NULL(f.session->tracks);
    xqc_test_moqt_destroy(&f);

    xqc_test_moqt_request_init(&f, 1);
    r = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_TRACK_STATUS, "a");
    m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
    m.request_id = 100;
    CU_ASSERT(xqc_test_moqt_request_input(r->stream, &m,
                                        r->initial_type, 0) < 0);
    CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_namespace_update_races(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 1);
    xqc_moqt_request_t *a = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE, "a");
    xqc_test_moqt_namespace_ok(a);
    uint8_t prefix[] = {1, 1, 'b'};
    xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_REQUEST_UPDATE,
        .request_id = 100, .parameter_count = 1};
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_TRACK_NAMESPACE_PREFIX, sizeof(prefix), prefix};
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(a->stream, &m,
                    a->initial_type, 0), XQC_OK);
    xqc_moqt_request_t *b = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE, "b");
    xqc_test_moqt_namespace_ok(b);
    xqc_test_moqt_namespace_ok(a);
    CU_ASSERT_TRUE(a->failed);
    CU_ASSERT_EQUAL(a->error.code, XQC_MOQT_REQUEST_PREFIX_OVERLAP);
    CU_ASSERT_TRUE(a->stream->tx_fin);
    CU_ASSERT_FALSE(b->failed);

    prefix[2] = 'c';
    m.request_id += XQC_MOQT_REQUEST_ID_STEP;
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(b->stream, &m,
                    b->initial_type, 0), XQC_OK);
    size_t limit = f.session->config.max_buffered_bytes;
    f.session->config.max_buffered_bytes = f.session->buffered_bytes;
    xqc_moqt_message_t ok = {.type = XQC_MOQT_MSG_REQUEST_OK};
    CU_ASSERT_EQUAL(xqc_moqt_request_send(b, &ok), -XQC_EMALLOC);
    CU_ASSERT_EQUAL(b->pending_received_updates, 1);
    const xqc_moqt_message_t *state = (void *)b->state->data;
    CU_ASSERT_EQUAL(*(char *)state->track_namespace.fields[0].iov_base, 'b');
    f.session->config.max_buffered_bytes = limit;
    m.type = XQC_MOQT_MSG_NAMESPACE;
    m.parameter_count = 0;
    b->stream->writing = 1;
    CU_ASSERT_EQUAL(xqc_moqt_request_send(b, &m), XQC_OK);
    xqc_test_moqt_namespace_ok(b);
    CU_ASSERT_EQUAL(xqc_moqt_request_send(b, &m), XQC_OK);
    xqc_list_head_t *pos;
    unsigned i = 0;
    xqc_list_for_each(pos, &b->namespaces) {
        xqc_list_buf_t *entry = xqc_list_entry(pos, xqc_list_buf_t, list_head);
        xqc_moqt_namespace_t name;
        CU_ASSERT(xqc_moqt_name_decode(entry->buf->data, entry->buf->data_len,
                                       &name, NULL) > 0);
        CU_ASSERT_EQUAL(*(char *)name.fields[0].iov_base, 'b' + i);
        i++;
    }
    CU_ASSERT_EQUAL(i, 2);
    CU_ASSERT_EQUAL(b->pending_received_updates, 0);
    b->stream->writing = 0;
    CU_ASSERT_EQUAL(xqc_moqt_stream_flush(b->stream), XQC_OK);
    xqc_test_moqt_destroy(&f);
}

static xqc_moqt_message_t
xqc_test_moqt_publication(const char *prefix, const char *track)
{
    xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_PUBLISH};
    m.track_namespace.count = 1;
    m.track_namespace.fields[0] = (struct iovec){(void *)prefix,
                                                strlen(prefix)};
    m.track_name = (struct iovec){(void *)track, strlen(track)};
    return m;
}

static void
xqc_test_moqt_skipped_event(xqc_moqt_request_t *r,
    const xqc_moqt_namespace_t *name, const struct iovec *track, void *data)
{
    moqt_fixture_t *f = data;
    f->namespace_adds++;
    f->namespace_fields = name->count;
    f->namespace_first = name->count ? *(char *)name->fields[0].iov_base : 0;
    CU_ASSERT_EQUAL(track->iov_len, 2);
    CU_ASSERT_EQUAL(xqc_memcmp(track->iov_base, "\0x", 2), 0);
    if (f->cancel_in_namespace) {
        xqc_moqt_request_cancel(r, XQC_MOQT_RESET_CANCELLED);
        CU_ASSERT_EQUAL(xqc_memcmp(track->iov_base, "\0x", 2), 0);
    }
}

void
xqc_test_moqt_tracks_codec(void)
{
    /* Draft-22 section 9.19: suffix + binary name, no ID/parameters. */
    const uint8_t wire[] = {15, 0, 6, 1, 1, 'a', 2, 0, 0xff};
    uint8_t encoded[sizeof(wire)];
    xqc_moqt_message_t m;
    uint64_t context = XQC_MOQT_MSG_SUBSCRIBE_TRACKS;
    CU_ASSERT_EQUAL(xqc_moqt_message_decode(wire, sizeof(wire), context, &m),
                    sizeof(wire));
    CU_ASSERT_EQUAL(m.type, XQC_MOQT_MSG_PUBLISH_SKIPPED);
    CU_ASSERT_EQUAL(m.request_id, 0);
    CU_ASSERT_EQUAL(m.parameter_count, 0);
    CU_ASSERT_EQUAL(m.track_name.iov_len, 2);
    CU_ASSERT_EQUAL(xqc_moqt_message_encode(&m, context, encoded,
                                            sizeof(encoded)), sizeof(wire));
    CU_ASSERT_EQUAL(xqc_memcmp(encoded, wire, sizeof(wire)), 0);
    for (size_t i = 0; i < sizeof(wire); i++) {
        CU_ASSERT(xqc_moqt_message_decode(wire, i, context, &m) < 0);
    }
    CU_ASSERT(xqc_moqt_message_decode(wire, sizeof(wire),
                XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE, &m) < 0);
    CU_ASSERT(xqc_moqt_message_encode(&m, XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE,
                                      NULL, 0) < 0);
    m.type = XQC_MOQT_MSG_PUBLISH_SKIPPED;
    m.track_namespace.count = 1;
    m.track_namespace.fields[0] = (struct iovec){NULL, 0};
    CU_ASSERT(xqc_moqt_message_encode(&m, context, NULL, 0) < 0);
    uint8_t malformed[] = {15, 0, 3, 0, 2, 'x'};
    CU_ASSERT(xqc_moqt_message_decode(malformed, sizeof(malformed), context,
                                      &m) < 0);
}

void
xqc_test_moqt_tracks_overlap(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 1);
    xqc_moqt_request_t *a = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_SUBSCRIBE_TRACKS, "a");
    xqc_moqt_request_t *pending = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_SUBSCRIBE_TRACKS, "a");
    xqc_test_moqt_namespace_ok(a);
    xqc_test_moqt_namespace_ok(pending);
    CU_ASSERT_TRUE(a->established);
    CU_ASSERT_TRUE(pending->failed);
    CU_ASSERT_EQUAL(pending->error.code, XQC_MOQT_REQUEST_PREFIX_OVERLAP);
    xqc_moqt_request_t *other = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_SUBSCRIBE_TRACKS, NULL);
    CU_ASSERT_TRUE(other->failed);
    CU_ASSERT_EQUAL(other->error.code, XQC_MOQT_REQUEST_PREFIX_OVERLAP);
    /* Same prefix across types and directions is permitted (3.6/4.2). */
    other = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE, "a");
    xqc_test_moqt_namespace_ok(other);
    CU_ASSERT_TRUE(other->established);
    other = xqc_test_moqt_namespace_request(&f, XQC_TRUE,
        XQC_MOQT_MSG_SUBSCRIBE_TRACKS, "a");
    xqc_test_moqt_namespace_ok(other);
    CU_ASSERT_TRUE(other->established);
    other = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_SUBSCRIBE_TRACKS, "b");
    xqc_test_moqt_namespace_ok(other);
    uint8_t prefix[] = {1, 1, 'a'};
    xqc_moqt_message_t update = {.type = XQC_MOQT_MSG_REQUEST_UPDATE,
        .request_id = 100, .parameter_count = 1};
    update.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_TRACK_NAMESPACE_PREFIX, sizeof(prefix), prefix};
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(other->stream, &update,
                    other->initial_type, 0), XQC_OK);
    CU_ASSERT_TRUE(other->failed);
    CU_ASSERT_EQUAL(other->error.code, XQC_MOQT_REQUEST_PREFIX_OVERLAP);
    CU_ASSERT_FALSE(a->failed);
    xqc_moqt_request_cancel(a, XQC_MOQT_RESET_CANCELLED);
    other = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_SUBSCRIBE_TRACKS, "a");
    xqc_test_moqt_namespace_ok(other);
    CU_ASSERT_TRUE(other->established);
    f.request_reject = XQC_MOQT_REQUEST_UNAUTHORIZED;
    prefix[2] = 'p';
    update.request_id += 2;
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(other->stream, &update,
                    other->initial_type, 0), XQC_OK);
    CU_ASSERT_EQUAL(f.candidate_prefix, 'p');
    CU_ASSERT_EQUAL(other->error.code, XQC_MOQT_REQUEST_UNAUTHORIZED);
    CU_ASSERT_TRUE(other->stream->tx_fin);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_tracks_publish(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 1);
    uint8_t token[] = {3, 3, 0, 'x'}, paused = 0, order = 2;
    xqc_moqt_message_t interest = {.type = XQC_MOQT_MSG_SUBSCRIBE_TRACKS,
        .parameter_count = 4};
    interest.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_AUTHORIZATION_TOKEN, sizeof(token), token};
    interest.parameters[1] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FORWARD, 1, &paused};
    interest.parameters[2] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_GROUP_ORDER, 1, &order};
    interest.parameters[3] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_INCLUDE_PROPERTIES, 1, &paused};
    xqc_moqt_stream_t *st = xqc_test_moqt_request_stream(&f);
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(st, &interest,
                                                interest.type, 0), XQC_OK);
    xqc_moqt_request_t *r = &st->state.request, *pc = NULL, *duplicate = NULL;
    xqc_moqt_message_t pub = xqc_test_moqt_publication("a", "camera");
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(r, 7, &pub, &pc), -XQC_EPARAM);
    xqc_test_moqt_namespace_ok(r);
    uint8_t priority[] = {0x0e, 7}, active = 1;
    pub.properties = (struct iovec){priority, sizeof(priority)};
    pub.parameter_count = 1;
    pub.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FORWARD, 1, &active};
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(r, 7, &pub, &pc), XQC_OK);
    CU_ASSERT_PTR_NOT_NULL_FATAL(pc);
    CU_ASSERT_NOT_EQUAL(pc->initial_request_id, r->initial_request_id);
    const xqc_moqt_message_t *state = (void *)pc->state->data;
    CU_ASSERT_EQUAL(state->parameter_count, 2);
    CU_ASSERT_EQUAL(state->parameters[0].type, XQC_MOQT_PARAM_FORWARD);
    CU_ASSERT_EQUAL(state->parameters[1].type, XQC_MOQT_PARAM_GROUP_ORDER);
    CU_ASSERT_EQUAL(state->properties.iov_len, 0);
    xqc_test_moqt_namespace_ok(pc);
    CU_ASSERT_FALSE(pc->subscription->forward);
    CU_ASSERT_EQUAL(pc->subscription->group_order, XQC_MOQT_GROUP_DESCENDING);
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(r, 7, &pub, &duplicate), XQC_OK);
    CU_ASSERT_PTR_NULL(duplicate);
    CU_ASSERT_EQUAL(xqc_moqt_request_skip(r, 7, &pub), XQC_OK);

    /* Only subsequent publications see committed St updates (9.5.2). */
    uint8_t prefix[] = {1, 1, 'b'};
    xqc_moqt_message_t update = {.type = XQC_MOQT_MSG_REQUEST_UPDATE,
        .request_id = 2, .parameter_count = 2};
    update.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FORWARD, 1, &active};
    update.parameters[1] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_TRACK_NAMESPACE_PREFIX, sizeof(prefix), prefix};
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(st, &update, interest.type, 0),
                    XQC_OK);
    pub.track_name = (struct iovec){"audio", 5};
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(r, 8, &pub, &duplicate), XQC_OK);
    CU_ASSERT_PTR_NOT_NULL_FATAL(duplicate);
    CU_ASSERT_FALSE(duplicate->subscription->forward);
    xqc_test_moqt_namespace_ok(r);
    pub.track_name = (struct iovec){"screen", 6};
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(r, 9, &pub, &duplicate), XQC_OK);
    CU_ASSERT_PTR_NULL(duplicate);
    pub.track_namespace.fields[0].iov_base = "b";
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(r, 9, &pub, &duplicate), XQC_OK);
    CU_ASSERT_PTR_NOT_NULL_FATAL(duplicate);
    CU_ASSERT_TRUE(duplicate->subscription->forward);
    CU_ASSERT_FALSE(pc->subscription->forward);
    xqc_moqt_request_fin(r);
    CU_ASSERT_FALSE(r->failed);
    pub.track_name = (struct iovec){"later", 5};
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(r, 10, &pub, &duplicate), XQC_OK);
    CU_ASSERT_PTR_NOT_NULL(duplicate);
    CU_ASSERT_EQUAL(xqc_moqt_request_finish(r), XQC_OK);
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(r, 11, &pub, &duplicate),
                    -XQC_EPARAM);
    xqc_moqt_request_cancel(r, XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_FALSE(pc->failed);
    CU_ASSERT_FALSE(pc->subscription->stopped);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_tracks_skipped(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 1);
    xqc_moqt_request_t *r = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_SUBSCRIBE_TRACKS, "a");
    xqc_test_moqt_namespace_ok(r);
    xqc_moqt_message_t pub = xqc_test_moqt_publication("a", "camera");
    xqc_moqt_request_t *pc;
    f.conn->conn_flow_ctl.fc_max_streams_bidi_can_send = 0;
    r->stream->writing = 1;
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(r, 1, &pub, &pc), XQC_OK);
    CU_ASSERT_PTR_NULL(pc);
    CU_ASSERT_FALSE(xqc_list_empty(&r->stream->tx));
    xqc_list_buf_t *entry = xqc_list_entry(r->stream->tx.prev,
                                            xqc_list_buf_t, list_head);
    xqc_moqt_message_t skipped;
    CU_ASSERT(xqc_moqt_message_decode(entry->buf->data, entry->buf->data_len,
                                       r->initial_type, &skipped) > 0);
    CU_ASSERT_EQUAL(skipped.type, XQC_MOQT_MSG_PUBLISH_SKIPPED);
    CU_ASSERT_EQUAL(skipped.track_namespace.count, 0);
    CU_ASSERT_EQUAL(skipped.track_name.iov_len, 6);
    CU_ASSERT_EQUAL(r->pending_sent_updates, 0);
    uint64_t next_id = f.session->next_request_id;
    size_t used = f.session->buffered_bytes;
    f.conn->conn_flow_ctl.fc_max_streams_bidi_can_send
        = XQC_MOQT_DEFAULT_STREAMS;
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(r, 1, &pub, &pc), XQC_OK);
    CU_ASSERT_PTR_NULL(pc);
    CU_ASSERT_EQUAL(f.session->next_request_id, next_id);
    CU_ASSERT_EQUAL(f.session->buffered_bytes, used);
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(r, 2, &pub, &pc), XQC_OK);
    CU_ASSERT_PTR_NOT_NULL(pc);
    pub.track_name = (struct iovec){"audio", 5};
    next_id = f.session->next_request_id;
    CU_ASSERT_EQUAL(xqc_moqt_request_skip(r, 1, &pub), XQC_OK);
    CU_ASSERT_EQUAL(f.session->next_request_id, next_id);
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(r, 1, &pub, &pc), XQC_OK);
    CU_ASSERT_PTR_NULL(pc);
    pub.track_name = (struct iovec){"capacity", 8};
    f.session->config.max_streams = f.session->stream_count;
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(r, 3, &pub, &pc), XQC_OK);
    CU_ASSERT_PTR_NULL(pc);
    CU_ASSERT_FALSE(f.session->closed);
    f.session->config.max_streams = XQC_MOQT_DEFAULT_STREAMS;
    uint8_t active = 1, token[] = {3, 3, 0, 'x'};
    xqc_moqt_message_t update = {.type = XQC_MOQT_MSG_REQUEST_UPDATE,
        .request_id = 100, .parameter_count = 1};
    update.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FORWARD, 1, &active};
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &update,
                    r->initial_type, 0), XQC_OK);
    xqc_test_moqt_namespace_ok(r);
    pub.track_name = (struct iovec){"parameters", 10};
    pub.parameter_count = XQC_MOQT_MAX_PARAMETERS;
    for (size_t i = 0; i < pub.parameter_count; i++) {
        pub.parameters[i] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_AUTHORIZATION_TOKEN, sizeof(token), token};
    }
    /* Inheritance exceeding the local parameter budget also sends SKIPPED. */
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(r, 4, &pub, &pc), XQC_OK);
    CU_ASSERT_PTR_NULL(pc);
    CU_ASSERT_FALSE(r->failed);
    r->stream->writing = 0;
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_tracks_skipped_receive(void)
{
    for (unsigned mode = 0; mode < 5; mode++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 0);
        f.session->callbacks.on_publish_skipped = xqc_test_moqt_skipped_event;
        xqc_moqt_request_t *r = xqc_test_moqt_namespace_request(&f, XQC_TRUE,
            XQC_MOQT_MSG_SUBSCRIBE_TRACKS, "a");
        if (mode != 0) {
            xqc_test_moqt_namespace_ok(r);
        }
        xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_PUBLISH_SKIPPED,
            .track_name = {"\0x", 2}};
        if (mode == 2) {
            m.track_namespace.count = XQC_MOQT_NAMESPACE_MAX_FIELDS;
            for (size_t i = 0; i < m.track_namespace.count; i++) {
                m.track_namespace.fields[i] = (struct iovec){"a", 1};
            }
        }
        f.cancel_in_namespace = mode == 3;
        if (mode == 4) {
            uint8_t prefix[] = {1, 1, 'b'};
            xqc_moqt_message_t update = {.type = XQC_MOQT_MSG_REQUEST_UPDATE,
                .parameter_count = 1};
            update.parameters[0] = (xqc_moq_message_parameter_t){
                XQC_MOQT_PARAM_TRACK_NAMESPACE_PREFIX, sizeof(prefix), prefix};
            CU_ASSERT_EQUAL(xqc_moqt_request_send(r, &update), XQC_OK);
            CU_ASSERT_EQUAL(xqc_test_moqt_request_input(r->stream, &m,
                            r->initial_type, 0), XQC_OK);
            CU_ASSERT_EQUAL(f.namespace_first, 'a');
            CU_ASSERT_EQUAL(r->pending_sent_updates, 1);
            xqc_test_moqt_namespace_ok(r);
        }
        xqc_int_t ret = xqc_test_moqt_request_input(r->stream, &m,
                                                    r->initial_type, 0);
        if (mode == 0 || mode == 2) {
            CU_ASSERT(ret < 0);
            CU_ASSERT_EQUAL(f.error, XQC_MOQT_PROTOCOL_VIOLATION);
            CU_ASSERT_EQUAL(f.namespace_adds, 0);
        } else {
            CU_ASSERT_EQUAL(ret, XQC_OK);
            CU_ASSERT_EQUAL(f.namespace_fields, 1);
            CU_ASSERT_EQUAL(f.namespace_first, mode == 4 ? 'b' : 'a');
            CU_ASSERT_EQUAL(f.namespace_adds, mode == 4 ? 2 : 1);
            CU_ASSERT_FALSE(f.session->closed);
        }
        xqc_test_moqt_destroy(&f);
    }
}

void
xqc_test_moqt_tracks_exclusion(void)
{
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 1);
    xqc_moqt_request_t *r = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
        XQC_MOQT_MSG_SUBSCRIBE_TRACKS, NULL);
    xqc_test_moqt_namespace_ok(r);
    xqc_moqt_message_t pub = xqc_test_moqt_publication("a", "camera");
    pub.request_id = 100;
    xqc_moqt_stream_t *source = xqc_test_moqt_request_stream(&f);
    CU_ASSERT_EQUAL(xqc_test_moqt_request_input(source, &pub, pub.type, 0),
                    XQC_OK);
    xqc_test_moqt_namespace_ok(&source->state.request);
    xqc_moqt_request_t *pc;
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(r, 1, &pub, &pc), XQC_OK);
    CU_ASSERT_PTR_NULL(pc);
    CU_ASSERT_TRUE(xqc_list_empty(&r->publications));
    xqc_moqt_request_cancel(&source->state.request, XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(r, 2, &pub, &pc), XQC_OK);
    CU_ASSERT_PTR_NOT_NULL(pc);
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(NULL, 1, &pub, &pc), -XQC_EPARAM);
    CU_ASSERT_PTR_NULL(pc);
    CU_ASSERT_EQUAL(xqc_moqt_request_publish(r, 1, &pub, NULL), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_request_skip(r, 1, NULL), -XQC_EPARAM);
    xqc_test_moqt_destroy(&f);
}

void
xqc_test_moqt_tracks_budget(void)
{
    for (unsigned mode = 0; mode < 3; mode++) {
        moqt_fixture_t f;
        xqc_test_moqt_request_init(&f, 1);
        xqc_moqt_request_t *r = xqc_test_moqt_namespace_request(&f, XQC_FALSE,
            XQC_MOQT_MSG_SUBSCRIBE_TRACKS, NULL);
        xqc_test_moqt_namespace_ok(r);
        xqc_moqt_message_t pub = xqc_test_moqt_publication("a", "camera");
        size_t key_length = sizeof(uint64_t)
            + xqc_moqt_name_encode(&pub.track_namespace, &pub.track_name,
                                     NULL, 0);
        f.session->config.max_buffered_bytes = f.session->buffered_bytes;
        if (mode > 0) {
            f.session->config.max_buffered_bytes += key_length
                + sizeof(xqc_var_buf_t);
        }
        if (mode > 1) {
            f.session->config.max_buffered_bytes += sizeof(xqc_list_buf_t);
        }
        CU_ASSERT_EQUAL(xqc_moqt_request_skip(r, 1, &pub), -XQC_EMALLOC);
        CU_ASSERT_TRUE(r->failed);
        CU_ASSERT_EQUAL(r->error.code, XQC_MOQT_RESET_EXCESSIVE_LOAD);
        CU_ASSERT_FALSE(f.session->closed);
        xqc_test_moqt_destroy(&f);
    }
    moqt_fixture_t f;
    xqc_test_moqt_request_init(&f, 0);
    xqc_moqt_request_t *r = xqc_test_moqt_namespace_request(&f, XQC_TRUE,
        XQC_MOQT_MSG_SUBSCRIBE_TRACKS, NULL);
    xqc_test_moqt_namespace_ok(r);
    uint8_t wire[] = {15, 0, 4, 0, 2, 0, 'x'};
    f.session->config.max_buffered_bytes = f.session->buffered_bytes;
    CU_ASSERT_EQUAL(xqc_moqt_request_input(r->stream, wire, sizeof(wire)),
                    XQC_MOQT_NO_ERROR);
    CU_ASSERT_FALSE(r->failed);
    f.session->callbacks.on_publish_skipped = xqc_test_moqt_skipped_event;
    CU_ASSERT_EQUAL(xqc_moqt_request_input(r->stream, wire, sizeof(wire)),
                    XQC_MOQT_NO_ERROR);
    CU_ASSERT_TRUE(r->failed);
    CU_ASSERT_EQUAL(r->error.code, XQC_MOQT_RESET_EXCESSIVE_LOAD);
    CU_ASSERT_FALSE(f.session->closed);
    xqc_test_moqt_destroy(&f);
}
