/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <xquic/xqc_http3.h>
#include <moq/xqc_moqt_webtransport.h>
#include "complex_case_common.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/tls/xqc_tls.h"
#include "src/http3/xqc_h3_request.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/transport/xqc_packet_out.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "moq/moqt/xqc_moqt_session.h"
#include "moq/moqt/xqc_moqt_codec.h"

#define DEMO_RELAY_BYTES (64 * 1024)
#define CHECK(value)                                                          \
    do {                                                                     \
        if (!(value)) {                                                       \
            fprintf(stderr, "line %d: %s\n", __LINE__, #value);               \
            goto done;                                                       \
        }                                                                    \
    } while (0)

typedef struct fixture_s fixture_t;
typedef struct {
    xqc_complex_case_socket_ctx_t socket;
    fixture_t                   *fixture;
    xqc_h3_conn_t               *h3;
    xqc_moqt_session_t          *session;
    xqc_moqt_subscription_t     *subscription;
    xqc_moqt_config_t           config;
    xqc_moqt_kv_t               options[2];
    xqc_cid_t                   cid;
    unsigned                    transport;
    unsigned                    ready, responses, upstream, subscribed;
    unsigned                    errors, objects, datagrams, closed, wt_closed;
    unsigned                    connection_closed;
    unsigned                    fetches, fill_ready, fill_closed, fill_objects;
    size_t                      bytes;
    size_t                      fill_bytes;
    uint64_t                    request_error, close_error;
    uint64_t                    expected_close;
    uint32_t                    wt_error;
} client_t;

struct fixture_s {
    xqc_complex_case_engine_t base;
    xqc_moqt_config_t         config;
    client_t                 clients[2];
    const char              *hostname;
    const char              *ca;
    unsigned                 failed;
    unsigned                 wt_configured;
    unsigned char            certificate[8192];
    size_t                   certificate_length;
    unsigned                 fill;
    char                     namespace[64];
};

static int trust(SSL *ssl, fixture_t *f);
static ssize_t write_packet(const unsigned char *bytes, size_t size,
    const struct sockaddr *peer, socklen_t length, void *data);
static ssize_t write_packet_ex(uint64_t path, const unsigned char *bytes,
    size_t size, const struct sockaddr *peer, socklen_t length, void *data);
static int verify(const unsigned char **certs, const size_t *sizes,
    size_t count, void *data);
static uint64_t setup(xqc_moqt_session_t *session,
    const xqc_moqt_setup_t *peer, void *data);
static void ready(xqc_moqt_session_t *session, void *data);
static void closed(xqc_moqt_session_t *session, uint64_t error, void *data);
static xqc_int_t authorize(xqc_moqt_request_t *request,
    const xqc_moqt_message_t *message, const xqc_moqt_message_t *candidate,
    uint64_t *error, void *data);
static void message(xqc_moqt_request_t *request,
    const xqc_moqt_message_t *value, void *data);
static void object(xqc_moqt_subscription_t *subscription,
    xqc_moqt_stream_t *stream, const xqc_moqt_object_t *value, void *data);
static xqc_int_t native_create(xqc_connection_t *conn,
    const xqc_cid_t *cid, void *data, void *protocol);
static void native_handshake(xqc_connection_t *conn, void *data,
    void *protocol);
static xqc_int_t native_close(xqc_connection_t *conn,
    const xqc_cid_t *cid, void *data, void *protocol);
static xqc_int_t h3_create(xqc_h3_conn_t *h3, const xqc_cid_t *cid, void *data);
static xqc_int_t h3_close(xqc_h3_conn_t *h3, const xqc_cid_t *cid, void *data);
static void wt_handshake(xqc_h3_conn_t *h3, void *data);
static int wt_ready(xqc_wt_session_t *wt, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *data);
static int wt_closed(xqc_wt_session_t *wt, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *data);
static int wait_for(fixture_t *f, unsigned *counter, unsigned target);
static xqc_moqt_request_t *request(client_t *client, uint64_t type,
    const char *name);
static int initialize(fixture_t *f);
static int connect_client(client_t *c, unsigned port, const char *address);
static void fetch_ready(xqc_moqt_fetch_t *fetch,
    xqc_moqt_subscription_t *subscription, void *data);
static void fetch_closed(xqc_moqt_fetch_t *fetch,
    const xqc_moqt_error_t *error, void *data);
static int malformed_fill(client_t *c);

static const xqc_moqt_callbacks_t callbacks = {.on_setup = setup,
    .on_ready = ready, .on_closed = closed, .on_authorize = authorize,
    .on_message = message, .on_object = object, .on_fetch_ready = fetch_ready,
    .on_fetch_closed = fetch_closed};

static int
trust(SSL *ssl, fixture_t *f)
{
    if (!f->ca) {
        return 1;
    }
    X509_STORE *store = X509_STORE_new();
    int ok = store && X509_STORE_load_locations(store, f->ca, NULL) == 1
        && SSL_set1_verify_cert_store(ssl, store) == 1;
    X509_STORE_free(store);
    return ok;
}

static ssize_t
write_packet(const unsigned char *bytes, size_t size,
    const struct sockaddr *peer, socklen_t length, void *data)
{
    struct sockaddr_storage address;
    if (!peer || length > sizeof(address)) {
        return XQC_SOCKET_ERROR;
    }
    memcpy(&address, peer, length);
#ifdef __APPLE__
    ((struct sockaddr *)&address)->sa_len = length;
#endif
    return xqc_complex_case_write_socket(bytes, size,
        (struct sockaddr *)&address, length, data);
}

static ssize_t
write_packet_ex(uint64_t path, const unsigned char *bytes, size_t size,
    const struct sockaddr *peer, socklen_t length, void *data)
{
    return write_packet(bytes, size, peer, length, data);
}

static int
verify(const unsigned char **certs, const size_t *sizes, size_t count,
    void *data)
{
    fixture_t *f = ((client_t *)data)->fixture;
    return count && sizes[0] == f->certificate_length
        && !memcmp(certs[0], f->certificate, sizes[0]) ? XQC_OK : XQC_ERROR;
}

static uint64_t
setup(xqc_moqt_session_t *session, const xqc_moqt_setup_t *peer, void *data)
{
    return XQC_MOQT_NO_ERROR;
}

static void
ready(xqc_moqt_session_t *session, void *data)
{
    ((client_t *)data)->ready++;
}

static void
closed(xqc_moqt_session_t *session, uint64_t error, void *data)
{
    client_t *c = data;
    c->closed++;
    c->close_error = error;
    c->fixture->failed |= error != c->expected_close;
}

static xqc_int_t
authorize(xqc_moqt_request_t *request, const xqc_moqt_message_t *message,
    const xqc_moqt_message_t *candidate, uint64_t *error, void *data)
{
    return XQC_OK;
}

static void
message(xqc_moqt_request_t *req, const xqc_moqt_message_t *m, void *data)
{
    client_t *c = data;
    if (m->type == XQC_MOQT_MSG_REQUEST_OK) {
        c->responses++;
        xqc_moqt_subscription_t *sub = xqc_moqt_request_subscription(req);
        if (sub) {
            c->subscription = sub;
        }
    } else if (m->type == XQC_MOQT_MSG_SUBSCRIBE_OK) {
        c->subscribed++;
    } else if (m->type == XQC_MOQT_MSG_REQUEST_ERROR) {
        c->errors++;
        c->request_error = m->error.code;
    } else if (m->type == XQC_MOQT_MSG_SUBSCRIBE) {
        /* Draft-22 sections 7.6/9.14: a registration must route upstream. */
        c->upstream++;
        xqc_moqt_message_t response = {.type = XQC_MOQT_MSG_SUBSCRIBE_OK};
        uint8_t largest[] = {5, 0};
        if (c->fixture->fill) {
            response.parameter_count = 1;
            response.parameters[0] = (xqc_moq_message_parameter_t){
                XQC_MOQT_PARAM_LARGEST_OBJECT, sizeof(largest), largest};
        }
        if (m->track_name.iov_len != 13
            || memcmp(m->track_name.iov_base, "interop-track", 13))
        {
            response.type = XQC_MOQT_MSG_REQUEST_ERROR;
            response.error.code = XQC_MOQT_REQUEST_DOES_NOT_EXIST;
        }
        if (xqc_moqt_request_send(req, &response) != XQC_OK) {
            c->fixture->failed = 1;
        }
        if (response.type == XQC_MOQT_MSG_SUBSCRIBE_OK) {
            c->subscription = xqc_moqt_request_subscription(req);
        }
    } else if (m->type == XQC_MOQT_MSG_FETCH) {
        c->fetches++;
        xqc_moqt_message_t response = {.type = XQC_MOQT_MSG_FETCH_OK,
            .end_group = 5, .end_object = 0};
        c->fixture->failed |= xqc_moqt_request_send(req, &response) != XQC_OK;
    } else if (m->type == XQC_MOQT_MSG_REQUEST_UPDATE) {
        xqc_moqt_message_t response = {.type = XQC_MOQT_MSG_REQUEST_OK};
        c->fixture->failed |= xqc_moqt_request_send(req, &response) != XQC_OK;
    }
}

static void
object(xqc_moqt_subscription_t *subscription, xqc_moqt_stream_t *stream,
    const xqc_moqt_object_t *value, void *data)
{
    client_t *c = data;
    if (c != &c->fixture->clients[1] || value->object_id != 0) {
        c->fixture->failed = 1;
        return;
    }
    if (xqc_moqt_stream_fetch(stream)) {
        const char payload[] = "fill22";
        c->fixture->failed |= value->group_id != 5
            || value->payload_length != sizeof(payload) - 1
            || value->payload_offset > sizeof(payload) - 1
            || value->payload.iov_len
                > sizeof(payload) - 1 - value->payload_offset;
        if (!c->fixture->failed) {
            c->fixture->failed |= memcmp(value->payload.iov_base,
                payload + value->payload_offset, value->payload.iov_len) != 0;
        }
        c->fill_bytes += value->payload.iov_len;
        c->fill_objects += value->payload_offset + value->payload.iov_len
            == value->payload_length;
        return;
    }
    if (value->datagram) {
        c->fixture->failed |= value->group_id != 102
            || value->payload.iov_len != 3
            || memcmp(value->payload.iov_base, "d22", 3);
        c->datagrams++;
    } else {
        c->fixture->failed |= value->group_id != 101
            || value->payload_length != DEMO_RELAY_BYTES;
        for (size_t i = 0; i < value->payload.iov_len; i++) {
            c->fixture->failed |= ((unsigned char *)value->payload.iov_base)[i]
                != (unsigned char)((value->payload_offset + i) % 251);
        }
        c->bytes += value->payload.iov_len;
        c->objects += value->payload_offset + value->payload.iov_len
            == value->payload_length;
    }
}

static void
fetch_ready(xqc_moqt_fetch_t *fetch, xqc_moqt_subscription_t *subscription,
    void *data)
{
    client_t *c = data;
    const xqc_moqt_fetch_info_t *info = xqc_moqt_fetch_info(fetch);
    c->fill_ready++;
    c->fixture->failed |= !info || info->start.group_id != 5
        || info->start.object_id != 0 || info->end.group_id != 5
        || info->end.object_id != 0;
    if (c == &c->fixture->clients[1]) {
        c->fixture->failed |= subscription == NULL;
        return;
    }
    xqc_moqt_stream_t *stream = xqc_moqt_fetch_open(fetch);
    xqc_moqt_object_t value = {.group_id = 5, .priority = 128,
        .payload_length = 6, .payload = {"fill22", 6}};
    c->fixture->failed |= !stream;
    if (stream) {
        c->fixture->failed |= xqc_moqt_stream_send_object(stream, &value)
            != XQC_OK || xqc_moqt_stream_finish(stream) != XQC_OK;
    }
}

static void
fetch_closed(xqc_moqt_fetch_t *fetch, const xqc_moqt_error_t *error, void *data)
{
    client_t *c = data;
    c->fill_closed++;
    c->fixture->failed |= error && error->code != XQC_MOQT_NO_ERROR;
}

static xqc_int_t
native_create(xqc_connection_t *conn, const xqc_cid_t *cid, void *data,
    void *protocol)
{
    client_t *c = data;
    if (!trust(xqc_tls_get_ssl(conn->tls), c->fixture)) {
        return XQC_ERROR;
    }
    c->session = xqc_moqt_session_create(conn, &c->config,
        &callbacks, c);
    return c->session ? XQC_OK : XQC_ERROR;
}

static void
native_handshake(xqc_connection_t *conn, void *data, void *protocol)
{
    client_t *c = data;
    c->fixture->failed |= xqc_moqt_session_start(c->session) != XQC_OK;
}

static xqc_int_t
native_close(xqc_connection_t *conn, const xqc_cid_t *cid, void *data,
    void *protocol)
{
    client_t *c = data;
    xqc_moqt_session_destroy(c->session);
    c->session = NULL;
    c->connection_closed++;
    return XQC_OK;
}

static xqc_int_t
h3_create(xqc_h3_conn_t *h3, const xqc_cid_t *cid, void *data)
{
    client_t *c = data;
    c->h3 = h3;
    return trust(xqc_h3_conn_get_ssl(h3), c->fixture) ? XQC_OK : XQC_ERROR;
}

static xqc_int_t
h3_close(xqc_h3_conn_t *h3, const xqc_cid_t *cid, void *data)
{
    client_t *c = data;
    c->h3 = NULL;
    c->connection_closed++;
    return XQC_OK;
}

static void
wt_handshake(xqc_h3_conn_t *h3, void *data)
{
    client_t *c = data;
    const char *protocols[] = {"moqt-22"};
    int error;
    c->fixture->failed |= xqc_wt_client_open_session_with_protocols_compat(
        h3, c->fixture->hostname, "/moqt", "http://localhost:8080",
        protocols, 1, &error) == NULL;
}

static int
wt_ready(xqc_wt_session_t *wt, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *data)
{
    client_t *c = data;
    c->session = xqc_moqt_session_create_webtransport_compat(wt,
        &c->config, &callbacks, c);
    return c->session ? xqc_moqt_session_start(c->session) : XQC_ERROR;
}

static int
wt_closed(xqc_wt_session_t *wt, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *data)
{
    client_t *c = data;
    c->wt_closed++;
    c->wt_error = xqc_wt_session_get_close_error_code(wt);
    c->fixture->failed |= c->wt_error != c->expected_close;
    xqc_moqt_session_destroy(c->session);
    c->session = NULL;
    return XQC_OK;
}

static int
wait_for(fixture_t *f, unsigned *counter, unsigned target)
{
    xqc_complex_case_engine_t *engines[] = {&f->base};
    xqc_usec_t deadline = xqc_complex_case_now_us() + 10000000;
    while (*counter < target && !f->failed
           && xqc_complex_case_now_us() < deadline)
    {
        xqc_complex_case_pump(engines, 1, 2);
    }
    if (*counter < target || f->failed) {
        fprintf(stderr, "wait got=%u expected=%u failed=%u errors=%u/%u "
            "last_request=%llu/%llu closed=%llu/%llu\n", *counter, target,
            f->failed, f->clients[0].errors, f->clients[1].errors,
            (unsigned long long)f->clients[0].request_error,
            (unsigned long long)f->clients[1].request_error,
            (unsigned long long)f->clients[0].close_error,
            (unsigned long long)f->clients[1].close_error);
        return -1;
    }
    return 0;
}

static xqc_moqt_request_t *
request(client_t *c, uint64_t type, const char *name)
{
    xqc_moqt_message_t m = {.type = type, .track_alias = 7,
        .track_namespace = {.count = 2,
            .fields = {{"moq-test", 8}, {"interop", 7}}},
        .track_name = {(void *)name, name ? strlen(name) : 0}};
    uint8_t next = XQC_MOQT_FILTER_NEXT_OBJECT;
    uint8_t fill[] = {4, 1, 0x21, 1, 1};
    if (c->fixture->fill) {
        m.track_namespace.fields[1] = (struct iovec){c->fixture->namespace,
            strlen(c->fixture->namespace)};
        if (type == XQC_MOQT_MSG_SUBSCRIBE) {
            /* Draft-22 3.5/9.20.15: current-group Fill and next-object live. */
            m.parameter_count = 2;
            m.parameters[0] = (xqc_moq_message_parameter_t){
                XQC_MOQT_PARAM_LOCATION_FILTER, 1, &next};
            m.parameters[1] = (xqc_moq_message_parameter_t){
                XQC_MOQT_PARAM_FILL_PARAMETERS, sizeof(fill), fill};
        }
    }
    return xqc_moqt_request_open(c->session, &m);
}

static int
malformed_fill(client_t *c)
{
    /* Bypass TX validation to inject an inner count/body mismatch. */
    uint8_t fill[] = {4, 1, 0x21, 1, 1}, wire[256];
    xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_SUBSCRIBE,
        .request_id = c->session->next_request_id,
        .track_namespace = {.count = 2, .fields = {{"moq-test", 8},
            {c->fixture->namespace, strlen(c->fixture->namespace)}}},
        .track_name = {"interop-track", 13}, .parameter_count = 1};
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FILL_PARAMETERS, sizeof(fill), fill};
    xqc_int_t n = xqc_moqt_message_encode(&m, m.type, wire, sizeof(wire));
    if (n <= 4) {
        return -1;
    }
    wire[n - 4] = 2;
    xqc_moqt_stream_t *stream = xqc_moqt_transport_open(c->session,
                                                       XQC_STREAM_BIDI);
    return stream && xqc_moqt_transport_send(stream, wire, n, 0) == n
        ? 0 : -1;
}

static int
initialize(fixture_t *f)
{
    f->base.socket.fd = -1;
    f->base.user_data = f;
    struct sockaddr_in local = {.sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (xqc_complex_case_make_socket(&f->base, (void *)&local, sizeof(local))) {
        return -1;
    }
    xqc_config_t config;
    xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT);
    config.cfg_log_level = XQC_LOG_ERROR;
    xqc_engine_ssl_config_t ssl = {.ciphers = XQC_TLS_CIPHERS,
        .groups = XQC_TLS_GROUPS};
    xqc_engine_callback_t engine;
    xqc_transport_callbacks_t transport;
    xqc_complex_case_init_engine_callbacks(&engine);
    xqc_complex_case_init_transport_callbacks(&transport);
    transport.write_socket = write_packet;
    transport.write_socket_ex = write_packet_ex;
    transport.cert_verify_cb = verify;
    f->base.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &config, &ssl,
        &engine, &transport, f);
    if (!f->base.engine) {
        return -1;
    }
    xqc_moqt_config_init(&f->config, XQC_MOQT_VERSION_DRAFT_22);
    xqc_conn_callbacks_t native = {.conn_create_notify = native_create,
        .conn_handshake_finished = native_handshake,
        .conn_close_notify = native_close};
    xqc_h3_callbacks_t h3 = {.h3c_cbs = {.h3_conn_create_notify = h3_create,
        .h3_conn_close_notify = h3_close}};
    xqc_webtransport_session_callbacks_t wt = {
        .webtransport_session_create_notify = wt_ready,
        .webtransport_session_close_notify = wt_closed,
        .webtransport_conn_handshake_finished_notify = wt_handshake};
    return xqc_moqt_init_alpn(f->base.engine, &f->config, &native)
        || xqc_h3_ctx_init(f->base.engine, &h3)
        || xqc_wt_ctx_init(f->base.engine, NULL, &wt, NULL);
}

static int
connect_client(client_t *c, unsigned port, const char *address)
{
    fixture_t *f = c->fixture;
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, address, &peer.sin_addr) != 1) {
        return -1;
    }
    xqc_conn_ssl_config_t ssl = {.cert_verify_flag =
        XQC_TLS_CERT_FLAG_NEED_VERIFY
        | (f->ca ? 0 : XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED)};
    xqc_conn_settings_t settings = {.proto_version = XQC_VERSION_V1,
        .max_datagram_frame_size = 65535, .enable_reset_stream_at = 1};
    const xqc_cid_t *cid;
    c->config = f->config;
    if (!c->transport) {
        c->options[0] = (xqc_moqt_kv_t){.type = XQC_MOQT_OPT_PATH,
            .value.bytes = {"/moqt", 5}};
        c->options[1] = (xqc_moqt_kv_t){.type = XQC_MOQT_OPT_AUTHORITY,
            .value.bytes = {(void *)f->hostname, strlen(f->hostname)}};
        c->config.setup_options = c->options;
        c->config.setup_option_count = 2;
        cid = xqc_moqt_connect(f->base.engine, &c->config, &settings, NULL, 0,
            f->hostname, &ssl, (void *)&peer, sizeof(peer), c);
    } else {
        xqc_webtransport_conn_settings_t wt = {.max_sessions_count = 2,
            .draft_version = c->transport == 1
                ? XQC_WEBTRANSPORT_DRAFT_VERSION_7
                : XQC_WEBTRANSPORT_DRAFT_VERSION_16,
            .max_bidi_streams = 128, .max_uni_streams = 128,
            .init_recv_window = 1048576, .enable_datagram = XQC_TRUE};
        if (!f->wt_configured) {
            if (xqc_wt_engine_set_default_settings(f->base.engine, &wt)) {
                return -1;
            }
            f->wt_configured = 1;
        }
        cid = xqc_webtransport_connect(f->base.engine, &settings, NULL, 0,
            f->hostname, 0, &ssl, (void *)&peer, sizeof(peer), c);
    }
    if (!cid) {
        return -1;
    }
    c->cid = *cid;
    return 0;
}

int
main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
    fixture_t f = {.base.socket.fd = -1};
    int result = 1;
    if (argc < 2 || argc > 3) {
        return 2;
    }
    const char *mode = argv[1];
    unsigned publisher, subscriber;
    if (!strcmp(mode, "quic")) {
        publisher = subscriber = 0;

    } else if (!strcmp(mode, "wt07")) {
        publisher = subscriber = 1;

    } else if (!strcmp(mode, "wt")) {
        publisher = subscriber = 2;

    } else if (!strcmp(mode, "mixed")) {
        publisher = 0;
        subscriber = 1;

    } else if (!strcmp(mode, "mixed-reverse")) {
        publisher = 1;
        subscriber = 0;

    } else {
        return 2;
    }
    unsigned errors = argc == 3 && !strcmp(argv[2], "errors");
    unsigned direct = argc == 3 && !strcmp(argv[2], "direct");
    unsigned fill_errors = argc == 3 && !strcmp(argv[2], "fill-errors");
    unsigned close_errors = argc == 3 && !strcmp(argv[2], "close-errors");
    f.fill = fill_errors || (argc == 3 && !strcmp(argv[2], "fill"));
    if (argc == 3 && !errors && !direct && !f.fill && !close_errors) {
        return 2;
    }
    snprintf(f.namespace, sizeof(f.namespace), "fill-%llu",
             (unsigned long long)xqc_complex_case_now_us());
    f.hostname = getenv("MOQT_SERVER_NAME");
    if (!f.hostname) {
        f.hostname = "localhost";
    }
    f.ca = getenv("MOQT_CA_FILE");
    const char *certificate = getenv("MOQT_CERT_FILE");
    FILE *leaf = fopen(certificate ? certificate : "server.der", "rb");
    CHECK(leaf);
    f.certificate_length = fread(f.certificate, 1, sizeof(f.certificate), leaf);
    fclose(leaf);
    CHECK(f.certificate_length && f.certificate_length < sizeof(f.certificate));
    CHECK(!initialize(&f));
    const char *port_env = getenv("XQC_MOQT_DEMO_PORT");
    char *end;
    unsigned long port = port_env ? strtoul(port_env, &end, 10) : 8443;
    CHECK(!port_env || (*port_env && !*end));
    CHECK(port > 0 && port <= 65535);
    const char *address = getenv("MOQT_CONNECT_IP");
    if (!address) {
        address = "127.0.0.1";
    }
    for (unsigned i = 0; i < 2; i++) {
        client_t *c = &f.clients[i];
        c->fixture = &f;
        c->socket = f.base.socket;
        c->transport = i ? subscriber : publisher;
        CHECK(!connect_client(c, port, address));
        CHECK(!wait_for(&f, &c->ready, 1));
    }
    client_t *p = &f.clients[0], *s = &f.clients[1];
    CHECK(request(p, direct ? XQC_MOQT_MSG_PUBLISH
        : XQC_MOQT_MSG_PUBLISH_NAMESPACE, direct ? "interop-track" : NULL));
    CHECK(!wait_for(&f, &p->responses, 1));
    if (fill_errors || close_errors) {
        s->expected_close = close_errors && s->transport
            ? H3_REQUEST_CANCELLED : XQC_MOQT_PROTOCOL_VIOLATION;
        if (close_errors && s->transport) {
            /* WT draft-16 6: a failed CLOSE must not stall other sessions. */
            xqc_stream_t *connect = s->session->wt_session->request
                ->h3_stream->stream;
            f.base.engine->config->manually_triggered_send = 1;
            CHECK(xqc_write_stop_sending_to_packet(connect->stream_conn,
                connect, H3_REQUEST_CANCELLED) == XQC_OK);
        }
        CHECK(!malformed_fill(s));
        f.base.engine->config->manually_triggered_send = 0;
        CHECK(!wait_for(&f, &s->closed, 1));
        CHECK(s->close_error == s->expected_close);
        CHECK(p->upstream == 0 && p->fetches == 0 && !p->closed);
        if (s->transport) {
            CHECK(!wait_for(&f, &s->wt_closed, 1));
            CHECK(s->wt_error == s->expected_close);
            CHECK(xqc_h3_conn_close(f.base.engine, &s->cid) == XQC_OK);
        }
        CHECK(!wait_for(&f, &s->connection_closed, 1));
        /* The existing publisher must serve a replacement subscriber. */
        memset(s, 0, sizeof(*s));
        s->fixture = &f;
        s->socket = f.base.socket;
        s->transport = subscriber;
        CHECK(!connect_client(s, port, address));
        CHECK(!wait_for(&f, &s->ready, 1));
    }
    if (errors) {
        CHECK(request(s, XQC_MOQT_MSG_SUBSCRIBE, "missing"));
        CHECK(!wait_for(&f, &s->errors, 1));
        CHECK(s->request_error == XQC_MOQT_REQUEST_DOES_NOT_EXIST);
        CHECK(p->upstream == 1);
    }
    CHECK(request(s, XQC_MOQT_MSG_SUBSCRIBE, "interop-track"));
    CHECK(!wait_for(&f, &s->subscribed, 1));
    CHECK(p->subscription && (direct || p->upstream == 1 + errors));
    if (f.fill) {
        CHECK(!wait_for(&f, &s->fill_closed, 1));
        CHECK(p->fetches == 1 && p->fill_ready == 1);
        CHECK(s->fill_ready == 1 && s->fill_objects == 1 && s->fill_bytes == 6);
    }
    unsigned char payload[DEMO_RELAY_BYTES];
    for (size_t i = 0; i < sizeof(payload); i++) {
        payload[i] = i % 251;
    }
    xqc_moqt_stream_t *stream = xqc_moqt_subgroup_open(p->subscription,
        101, 0, 128, 1, 1);
    CHECK(stream);
    xqc_moqt_object_t value = {.group_id = 101, .priority = 128,
        .first_in_subgroup = 1, .payload = {payload, sizeof(payload)},
        .payload_length = sizeof(payload)};
    CHECK(xqc_moqt_stream_send_object(stream, &value) == XQC_OK);
    CHECK(xqc_moqt_stream_finish(stream) == XQC_OK);
    CHECK(!wait_for(&f, &s->objects, 1));
    CHECK(s->bytes == sizeof(payload));
    value.group_id = 102;
    value.datagram = 1;
    value.first_in_subgroup = 0;
    value.payload = (struct iovec){"d22", 3};
    value.payload_length = 3;
    CHECK(xqc_moqt_datagram_send(p->subscription, &value) == XQC_OK);
    CHECK(!wait_for(&f, &s->datagrams, 1));
    for (int i = 1; i >= 0; i--) {
        client_t *c = &f.clients[i];
        xqc_moqt_session_close(c->session, XQC_MOQT_NO_ERROR);
        CHECK(!wait_for(&f, &c->closed, 1));
        CHECK(!c->close_error);
        if (c->transport) {
            CHECK(!wait_for(&f, &c->wt_closed, 1));
            CHECK(!c->wt_error);
            CHECK(xqc_h3_conn_close(f.base.engine, &c->cid) == XQC_OK);
        }
    }
    for (unsigned i = 0; i < 2; i++) {
        CHECK(!wait_for(&f, &f.clients[i].connection_closed, 1));
    }
    printf("RELAY PROBE PASS mode=%s direct=%u errors=%u bytes=%zu "
           "objects=%u datagrams=%u upstream=%u fill=%u fill_bytes=%zu "
           "fetches=%u malformed_close=%u close=0/0 close_recovery=%u\n", mode,
           direct, errors, s->bytes, s->objects, s->datagrams, p->upstream,
           s->fill_objects, s->fill_bytes, p->fetches,
           fill_errors ? XQC_MOQT_PROTOCOL_VIOLATION : 0, close_errors);
    result = 0;
done:
    if (f.base.engine) {
        for (unsigned i = 0; i < 2; i++) {
            client_t *c = &f.clients[i];
            xqc_moqt_session_close(c->session, XQC_MOQT_NO_ERROR);
            if (c->h3) {
                xqc_h3_conn_close(f.base.engine, &c->cid);
            }
        }
        xqc_complex_case_engine_t *engines[] = {&f.base};
        xqc_complex_case_pump(engines, 1, 300);
    }
    xqc_complex_case_engine_release(&f.base);
    return result;
}
