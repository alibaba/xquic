/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include "complex_case_common.h"
#include "include/moq/xqc_moqt_webtransport.h"
#include "moq/moqt/xqc_moqt_codec.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/webtransport/xqc_webtransport_session.h"

#define MOQT_WT_PAYLOAD 8192
#define CHECK(expr) do {                                                      \
    if (!(expr)) {                                                           \
        fprintf(stderr, "line %d: %s\n", __LINE__, #expr);                    \
        goto fail;                                                          \
    }                                                                       \
} while (0)

typedef struct moqt_wt_endpoint_s moqt_wt_endpoint_t;
typedef struct {
    moqt_wt_endpoint_t *endpoint;
    xqc_wt_session_t *wt;
    xqc_moqt_session_t *session;
    xqc_moqt_request_t *request;
    xqc_moqt_subscription_t *subscription;
    unsigned ready, ok, objects, datagrams, bytes, history, history_bytes;
    unsigned fin, fetch_fin, done, errors, closed, wt_closed, wt_ready, setups;
    uint64_t error, request_error;
} moqt_wt_channel_t;

struct moqt_wt_endpoint_s {
    xqc_complex_case_engine_t base;
    xqc_h3_conn_t *h3;
    moqt_wt_channel_t channel[2];
    unsigned server, bad_setup, failed, conn_closed;
};

static uint64_t
moqt_setup(xqc_moqt_session_t *session, const xqc_moqt_setup_t *setup, void *data)
{
    ((moqt_wt_channel_t *)data)->setups++;
    return 0;
}

static void
moqt_ready(xqc_moqt_session_t *session, void *data)
{
    ((moqt_wt_channel_t *)data)->ready++;
}

static void
moqt_closed(xqc_moqt_session_t *session, uint64_t error, void *data)
{
    moqt_wt_channel_t *c = data;
    c->closed++;
    c->error = error;
}

static xqc_int_t
moqt_authorize(xqc_moqt_request_t *request, const xqc_moqt_message_t *message,
    const xqc_moqt_message_t *candidate, uint64_t *error, void *data)
{
    /* Explicit allow-all policy for the bounded loopback test fixture. */
    return XQC_OK;
}

static void
moqt_message(xqc_moqt_request_t *request, const xqc_moqt_message_t *message,
    void *data)
{
    moqt_wt_channel_t *c = data;
    if (!c->endpoint->server) {
        c->ok += message->type == XQC_MOQT_MSG_SUBSCRIBE_OK
            || message->type == XQC_MOQT_MSG_FETCH_OK
            || message->type == XQC_MOQT_MSG_REQUEST_OK;
        c->done += message->type == XQC_MOQT_MSG_PUBLISH_DONE
            && message->error.code == XQC_MOQT_PUBLISH_TRACK_ENDED;
        return;
    }
    xqc_moqt_message_t reply = {0};
    if (message->type == XQC_MOQT_MSG_SUBSCRIBE) {
        reply.type = XQC_MOQT_MSG_SUBSCRIBE_OK;
    } else if (message->type == XQC_MOQT_MSG_FETCH) {
        reply.type = XQC_MOQT_MSG_FETCH_OK;
    } else if (message->type == XQC_MOQT_MSG_PUBLISH_NAMESPACE) {
        reply.type = XQC_MOQT_MSG_REQUEST_OK;
    } else {
        return;
    }
    if (xqc_moqt_request_send(request, &reply) != XQC_OK) {
        c->endpoint->failed = 1;
    }
    if (message->type == XQC_MOQT_MSG_SUBSCRIBE) {
        c->request = request;
        c->subscription = xqc_moqt_request_subscription(request);
    }
}

static void
moqt_request_closed(xqc_moqt_request_t *request,
    const xqc_moqt_error_t *error, void *data)
{
    moqt_wt_channel_t *c = data;
    if (error) {
        c->errors++;
        c->request_error = error->code;
    }
    if (c->request == request) {
        c->request = NULL;
        c->subscription = NULL;
    }
}

static void
moqt_object(xqc_moqt_subscription_t *subscription, xqc_moqt_stream_t *stream,
    const xqc_moqt_object_t *object, void *data)
{
    moqt_wt_channel_t *c = data;
    int history = stream && xqc_moqt_stream_fetch(stream);
    if (object->priority != 128 || object->object_id != 0
        || object->group_id != (object->datagram ? 1u : 0u)
        || object->payload_length != (object->datagram ? 2 : MOQT_WT_PAYLOAD))
    {
        c->endpoint->failed = 1;
    }
    if (object->datagram) {
        c->endpoint->failed |= object->payload.iov_len != 2
            || memcmp(object->payload.iov_base, "dg", 2);
        c->datagrams++;
    } else {
        for (size_t i = 0; i < object->payload.iov_len; i++) {
            c->endpoint->failed |= ((char *)object->payload.iov_base)[i] != 'm';
        }
        if (history) {
            c->history_bytes += object->payload.iov_len;
            c->history += object->payload_offset + object->payload.iov_len
                == object->payload_length;
        } else {
            c->bytes += object->payload.iov_len;
            c->objects += object->payload_offset + object->payload.iov_len
                == object->payload_length;
        }
    }
}

static void
moqt_stream_closed(xqc_moqt_stream_t *stream, const xqc_moqt_object_t *last,
    const xqc_moqt_error_t *error, void *data)
{
    if (!error) {
        ((moqt_wt_channel_t *)data)->fin++;
    }
}

static void
moqt_fetch_ready(xqc_moqt_fetch_t *fetch, xqc_moqt_subscription_t *subscription,
    void *data)
{
    moqt_wt_channel_t *c = data;
    if (!c->endpoint->server) {
        return;
    }
    char payload[MOQT_WT_PAYLOAD];
    memset(payload, 'm', sizeof(payload));
    xqc_moqt_object_t object = {.priority = 128,
        .payload = {payload, sizeof(payload)}, .payload_length = sizeof(payload)};
    xqc_moqt_stream_t *stream = xqc_moqt_fetch_open(fetch);
    if (!stream || xqc_moqt_stream_send_object(stream, &object) != XQC_OK
        || xqc_moqt_stream_finish(stream) != XQC_OK)
    {
        c->endpoint->failed = 1;
    }
}

static void
moqt_fetch_closed(xqc_moqt_fetch_t *fetch, const xqc_moqt_error_t *error,
    void *data)
{
    if (!error) {
        ((moqt_wt_channel_t *)data)->fetch_fin++;
    }
}

static int
wt_accept(xqc_http_headers_t *headers, xqc_http_headers_t *response, void *data)
{
    const char *protocols[] = {"moqt-22"}, *selected = NULL;
    if (xqc_wt_select_application_protocol(headers, protocols, 1, &selected)
        != 1)
    {
        return 0;
    }
    static xqc_http_header_t fields[] = {
        {.name = {":status", 7}, .value = {"200", 3}},
        {.name = {"wt-protocol", 11}, .value = {"\"moqt-22\"", 9}},
    };
    response->headers = fields;
    response->count = 2;
    return 1;
}

static int
wt_ready(xqc_wt_session_t *wt, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *data)
{
    moqt_wt_endpoint_t *ep = data;
    unsigned index = wt->session_id / 4;
    const char *protocol = xqc_wt_session_get_application_protocol(wt);
    if (index >= 2 || !protocol || strcmp(protocol, "moqt-22"))
    {
        ep->failed = 1;
        return -XQC_EPARAM;
    }
    moqt_wt_channel_t *c = &ep->channel[index];
    c->wt = wt;
    c->wt_ready++;
    if (!ep->server && !index && ep->bad_setup) {
        return XQC_OK;
    }
    xqc_moqt_config_t config;
    xqc_moqt_config_init(&config, XQC_MOQT_VERSION_DRAFT_22);
    config.timeout = ep->bad_setup == 3 && !index ? 200000 : 5000000;
    const xqc_moqt_callbacks_t cbs = {
        .on_setup = moqt_setup, .on_ready = moqt_ready,
        .on_closed = moqt_closed, .on_message = moqt_message,
        .on_authorize = moqt_authorize,
        .on_request_closed = moqt_request_closed, .on_object = moqt_object,
        .on_stream_closed = moqt_stream_closed,
        .on_fetch_ready = moqt_fetch_ready, .on_fetch_closed = moqt_fetch_closed,
    };
    void *protocol_data = ep->h3->conn->proto_data;
    void *datagram_data = ep->h3->conn->dgram_data;
    c->session = xqc_moqt_session_create_webtransport(wt, &config, &cbs, c);
    if (!c->session || xqc_moqt_session_start(c->session) != XQC_OK
        || protocol_data != ep->h3->conn->proto_data
        || datagram_data != ep->h3->conn->dgram_data)
    {
        ep->failed = 1;
        return -XQC_EPARAM;
    }
    return XQC_OK;
}

static int
wt_closed(xqc_wt_session_t *wt, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *data)
{
    moqt_wt_endpoint_t *ep = data;
    unsigned index = wt->session_id / 4;
    if (index < 2) {
        moqt_wt_channel_t *c = &ep->channel[index];
        c->wt_closed++;
        c->error = xqc_wt_session_get_close_error_code(wt);
        xqc_moqt_session_destroy(c->session);
        c->session = NULL;
        c->wt = NULL;
    }
    return XQC_OK;
}

static int
conn_accept(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *data)
{
    xqc_conn_set_transport_user_data(conn, data);
    return XQC_OK;
}

static int
conn_create(xqc_h3_conn_t *h3, const xqc_cid_t *cid, void *data)
{
    ((moqt_wt_endpoint_t *)data)->h3 = h3;
    return XQC_OK;
}

static int
conn_close(xqc_h3_conn_t *h3, const xqc_cid_t *cid, void *data)
{
    moqt_wt_endpoint_t *ep = data;
    ep->conn_closed++;
    ep->h3 = NULL;
    return XQC_OK;
}

static int
engine_init(moqt_wt_endpoint_t *ep, int server, unsigned bad)
{
    memset(ep, 0, sizeof(*ep));
    ep->server = server;
    ep->bad_setup = bad;
    ep->base.socket.fd = -1;
    ep->base.user_data = ep;
    for (unsigned i = 0; i < 2; i++) {
        ep->channel[i].endpoint = ep;
    }
    struct sockaddr_in address = {.sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (xqc_complex_case_make_socket(&ep->base,
        (struct sockaddr *)&address, sizeof(address)))
    {
        return -1;
    }
    xqc_engine_type_t type = server ? XQC_ENGINE_SERVER : XQC_ENGINE_CLIENT;
    xqc_config_t config;
    xqc_engine_get_default_config(&config, type);
    config.cfg_log_level = XQC_LOG_ERROR;
    xqc_engine_ssl_config_t ssl = {.ciphers = XQC_TLS_CIPHERS,
        .groups = XQC_TLS_GROUPS, .private_key_file = "./server.key",
        .cert_file = "./server.crt"};
    xqc_engine_callback_t engine_cbs;
    xqc_transport_callbacks_t transport_cbs;
    xqc_complex_case_init_engine_callbacks(&engine_cbs);
    xqc_complex_case_init_transport_callbacks(&transport_cbs);
    transport_cbs.server_accept = conn_accept;
    ep->base.engine = xqc_engine_create(type, &config, &ssl, &engine_cbs,
                                        &transport_cbs, ep);
    if (!ep->base.engine) {
        return -1;
    }
    xqc_h3_callbacks_t h3 = {.h3c_cbs = {
        .h3_conn_create_notify = conn_create, .h3_conn_close_notify = conn_close}};
    xqc_webtransport_session_callbacks_t sessions = {
        .webtransport_will_create_session_notify = wt_accept,
        .webtransport_session_create_notify = wt_ready,
        .webtransport_session_close_notify = wt_closed,
    };
    if (xqc_h3_ctx_init(ep->base.engine, &h3)
        || xqc_wt_ctx_init(ep->base.engine, NULL, &sessions, NULL))
    {
        return -1;
    }
    xqc_webtransport_conn_settings_t settings = {.max_sessions_count = 2,
        .draft_version = XQC_WEBTRANSPORT_DRAFT_VERSION_16,
        .max_bidi_streams = 64, .max_uni_streams = 64,
        .init_recv_window = 1024, .enable_datagram = XQC_TRUE};
    return xqc_wt_engine_set_default_settings(ep->base.engine, &settings);
}

static int
wait_for(moqt_wt_endpoint_t *client, moqt_wt_endpoint_t *server,
    unsigned *value, unsigned target)
{
    xqc_complex_case_engine_t *engines[] = {&client->base, &server->base};
    xqc_usec_t end = xqc_complex_case_now_us() + 6000000;
    while (*value < target && xqc_complex_case_now_us() < end
           && !client->failed && !server->failed
           && !client->conn_closed && !server->conn_closed)
    {
        xqc_complex_case_pump(engines, 2, 2);
    }
    if (*value < target || client->failed || server->failed) {
        fprintf(stderr, "wait got=%u target=%u failed=%u/%u H3_closed=%u/%u\n",
            *value, target, client->failed, server->failed,
            client->conn_closed, server->conn_closed);
        return -1;
    }
    return 0;
}

static xqc_moqt_request_t *
request_open(moqt_wt_channel_t *c, uint64_t type, const char *track)
{
    xqc_moqt_message_t message = {.type = type,
        .track_namespace = {.count = 1, .fields = {{"wt-test", 7}}},
        .track_name = {(void *)track, track ? strlen(track) : 0}};
    unsigned char range[] = {XQC_MOQT_FILTER_ABSOLUTE_RANGE, 0, 0, 0, 0};
    if (type == XQC_MOQT_MSG_FETCH) {
        message.parameters[message.parameter_count++] =
            (xqc_moq_message_parameter_t){XQC_MOQT_PARAM_LOCATION_FILTER,
                                          sizeof(range), range};
    }
    return xqc_moqt_request_open(c->session, &message);
}

static int
exercise(moqt_wt_endpoint_t *client, moqt_wt_endpoint_t *server, unsigned index)
{
    moqt_wt_channel_t *c = &client->channel[index];
    moqt_wt_channel_t *s = &server->channel[index];
    unsigned ok = c->ok;
    xqc_moqt_request_t *request = request_open(c, XQC_MOQT_MSG_SUBSCRIBE, "track");
    CHECK(request && xqc_moqt_request_id(request) == 0);
    CHECK(!wait_for(client, server, &c->ok, ok + 1));
    CHECK(s->subscription && s->request);
    xqc_moqt_request_t *source = s->request;
    char payload[MOQT_WT_PAYLOAD];
    memset(payload, 'm', sizeof(payload));
    xqc_moqt_object_t object = {.priority = 128, .first_in_subgroup = 1,
        .payload = {payload, sizeof(payload)}, .payload_length = sizeof(payload)};
    xqc_moqt_stream_t *stream = xqc_moqt_subgroup_open(s->subscription,
                                                        0, 0, 128, 1, 1);
    CHECK(stream && xqc_moqt_stream_send_object(stream, &object) == XQC_OK);
    CHECK(xqc_moqt_stream_finish(stream) == XQC_OK);
    CHECK(!wait_for(client, server, &c->objects, 1));
    CHECK(!wait_for(client, server, &c->fin, 1));
    CHECK(c->bytes == MOQT_WT_PAYLOAD);
    xqc_moqt_object_t datagram = {.group_id = 1, .priority = 128, .datagram = 1,
        .payload = {"dg", 2}, .payload_length = 2};
    CHECK(xqc_moqt_datagram_send(s->subscription, &datagram) == XQC_OK);
    CHECK(!wait_for(client, server, &c->datagrams, 1));
    CHECK(request_open(c, XQC_MOQT_MSG_FETCH, "track") != NULL);
    CHECK(!wait_for(client, server, &c->fetch_fin, 1));
    CHECK(c->history == 1 && c->history_bytes == MOQT_WT_PAYLOAD);
    xqc_moqt_message_t done = {.type = XQC_MOQT_MSG_PUBLISH_DONE,
        .error.code = XQC_MOQT_PUBLISH_TRACK_ENDED, .stream_count = 1};
    CHECK(xqc_moqt_request_send(source, &done) == XQC_OK);
    CHECK(!wait_for(client, server, &c->done, 1));
    ok = c->ok;
    request = request_open(c, XQC_MOQT_MSG_SUBSCRIBE, "cancel");
    CHECK(request && !wait_for(client, server, &c->ok, ok + 1));
    stream = xqc_moqt_subgroup_open(s->subscription, 0, 0, 128, 1, 0);
    CHECK(stream && xqc_moqt_stream_send_object(stream, &object) == XQC_OK);
    /* Draft-22 12.5 and WT 4.4: request reset codes survive WT mapping. */
    unsigned errors = s->errors;
    xqc_moqt_request_cancel(request, XQC_MOQT_RESET_CANCELLED);
    CHECK(!wait_for(client, server, &s->errors, errors + 1));
    CHECK(s->request_error == XQC_MOQT_RESET_CANCELLED);
    return 0;
fail:
    return -1;
}

static int
run(unsigned bad)
{
    moqt_wt_endpoint_t client = {.base.socket.fd = -1};
    moqt_wt_endpoint_t server = {.base.socket.fd = -1};
    int rc = 1, error;
    CHECK(!engine_init(&server, 1, bad));
    CHECK(!engine_init(&client, 0, bad));
    xqc_conn_ssl_config_t ssl = {0};
    CHECK(xqc_webtransport_connect(client.base.engine,
        &client.base.engine->default_conn_settings, NULL, 0,
        "localhost", 0, &ssl, (struct sockaddr *)&server.base.local,
        server.base.locallen, &client) != NULL);
    const char *protocols[] = {"moqt-22"};
    for (unsigned i = 0; i < 2; i++) {
        CHECK(xqc_wt_client_open_session_with_protocols(client.h3,
            "localhost", i ? "/moqt/b" : "/moqt/a", NULL,
            protocols, 1, &error) != NULL);
        /* Peer transport parameters supply credit for a second CONNECT. */
        CHECK(!wait_for(&client, &server, &client.channel[i].wt_ready, 1));
    }
    CHECK(!wait_for(&client, &server, &client.channel[1].ready, 1));
    CHECK(!wait_for(&client, &server, &server.channel[1].ready, 1));
    if (bad) {
        moqt_wt_channel_t *c = &client.channel[0];
        uint64_t expected = bad == 1 ? XQC_MOQT_INVALID_PATH
            : bad == 2 ? XQC_MOQT_INVALID_AUTHORITY
            : bad == 3 ? XQC_MOQT_CONTROL_MESSAGE_TIMEOUT
                       : XQC_MOQT_PROTOCOL_VIOLATION;
        CHECK(c->wt != NULL);
        if (bad != 3) {
            uint8_t body[32], wire[64];
            xqc_moqt_kv_t option = {.type = bad == 1 ? XQC_MOQT_OPT_PATH
                                                     : XQC_MOQT_OPT_AUTHORITY};
            option.value.bytes = bad == 1 ? (struct iovec){"/", 1}
                                         : (struct iovec){"localhost", 9};
            int len = bad == 4 ? 0
                : xqc_moqt_kv_encode(&option, 0, body, sizeof(body));
            xqc_moqt_message_t message = {.type = XQC_MOQT_MSG_SETUP,
                .body = {body, len}};
            len = xqc_moqt_frame_encode(&message, wire, sizeof(wire));
            xqc_wt_unistream_t *stream = xqc_wt_session_create_uni_stream(
                c->wt, NULL, &error);
            CHECK(stream && xqc_wt_unistream_send(stream, wire, len, bad == 4)
                               == len);
        }
        CHECK(!wait_for(&client, &server, &c->wt_closed, 1));
        CHECK(!wait_for(&client, &server, &server.channel[0].wt_closed, 1));
        CHECK(c->error == expected && server.channel[0].error == expected);
        CHECK(server.channel[0].closed == 1);
        CHECK(!exercise(&client, &server, 1));
    } else {
        CHECK(!wait_for(&client, &server, &client.channel[0].ready, 1));
        CHECK(!wait_for(&client, &server, &server.channel[0].ready, 1));
        CHECK(!exercise(&client, &server, 0));
        CHECK(!exercise(&client, &server, 1));
        xqc_moqt_session_close(client.channel[0].session, XQC_MOQT_NO_ERROR);
        CHECK(!wait_for(&client, &server, &server.channel[0].wt_closed, 1));
    }
    unsigned ok = client.channel[1].ok;
    CHECK(request_open(&client.channel[1], XQC_MOQT_MSG_PUBLISH_NAMESPACE,
                          NULL) != NULL);
    CHECK(!wait_for(&client, &server, &client.channel[1].ok, ok + 1));
    CHECK(client.h3 && server.h3 && !client.conn_closed && !server.conn_closed);
    CHECK(xqc_h3_conn_get_user_data(client.h3) == &client);
    CHECK(xqc_h3_conn_get_user_data(server.h3) == &server);
    printf("MoQT WT mode=%u passed: request/object/datagram/FETCH, "
           "same-H3 session isolation\n", bad);
    rc = 0;
fail:
    xqc_complex_case_engine_release(&client.base);
    xqc_complex_case_engine_release(&server.base);
    return rc;
}

int
main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "errors")) {
        for (unsigned i = 1; i <= 4; i++) {
            if (run(i)) {
                return 1;
            }
        }
        return 0;
    }
    return run(0);
}
