/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include <stdio.h>
#include <netinet/in.h>
#include "complex_case_common.h"
#include <moq/xqc_moqt_relay.h>
#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str.h"
#include "src/common/xqc_time.h"

#define XQC_TEST_RELAY_CLIENTS 4
#define XQC_TEST_RELAY_DATAGRAM_SIZE 1500
#define XQC_TEST_RELAY_NODES (XQC_TEST_RELAY_CLIENTS + 2)
#define XQC_TEST_RELAY_REQUESTS 16
#define XQC_TEST_RELAY_WAIT_MS 2000
#define XQC_TEST_RELAY_PUMP_MS 10
#define XQC_TEST_RELAY_SETTLE_MS 100
#define XQC_TEST_RELAY_OBJECT_SIZE (128 * 1024)
#define XQC_TEST_RELAY_FRAGMENT 2048
#define XQC_TEST_RELAY_SMALL_OBJECT 16
#define XQC_TEST_RELAY_SLOW_OBJECT (4 * 1024 * 1024)
#define XQC_TEST_RELAY_SEND_BATCH (64 * 1024)
#define XQC_TEST_RELAY_GROUPS 64
#define XQC_TEST_RELAY_PRIORITY 7
#define XQC_TEST_RELAY_DIRECT_ALIAS 42

#define xqc_test_relay_check(expr)                                           \
    do {                                                                    \
        if (!(expr)) {                                                      \
            fprintf(stderr, "line %d: %s\n", __LINE__, #expr);                \
            goto done;                                                      \
        }                                                                   \
    } while (0)

typedef struct xqc_test_relay_node_s xqc_test_relay_node_t;

typedef struct {
    xqc_complex_case_socket_ctx_t  socket;
    xqc_test_relay_node_t         *node;
    xqc_moqt_relay_peer_t         *peer;
    xqc_moqt_session_t            *session;
} xqc_test_relay_connection_t;

struct xqc_test_relay_node_s {
    xqc_complex_case_engine_t    base;
    xqc_test_relay_connection_t  connection;
    xqc_moqt_relay_t            *relay;
    xqc_moqt_config_t            config;
    xqc_moqt_request_t          *incoming[XQC_TEST_RELAY_REQUESTS];
    xqc_moqt_request_t          *tracks;
    xqc_moqt_stream_t           *sending;
    xqc_moqt_fetch_t            *pending_fetch;
    size_t                       incoming_count;
    unsigned                     ready;
    unsigned                     responses;
    unsigned                     publications;
    unsigned                     skipped;
    unsigned                     errors;
    unsigned                     objects;
    unsigned                     history_objects;
    unsigned                     ranges;
    unsigned                     namespace_adds;
    unsigned                     namespace_removes;
    unsigned                     subscription_closed;
    unsigned                     fetch_closed;
    unsigned                     invalid;
    uint64_t                     last_error;
    uint64_t                     groups;
    size_t                       bytes;
    xqc_bool_t                   defer;
    xqc_bool_t                   reject_fetch;
    xqc_bool_t                   allow_cancel;
};

typedef struct {
    xqc_test_relay_node_t       server;
    xqc_test_relay_node_t       clients[XQC_TEST_RELAY_CLIENTS];
    xqc_test_relay_node_t       replacement;
    xqc_complex_case_engine_t  *engines[XQC_TEST_RELAY_NODES];
    xqc_complex_case_engine_t  *paused;
} xqc_test_relay_fixture_t;

static xqc_int_t xqc_test_relay_rendezvous_run(xqc_test_relay_fixture_t *f,
    xqc_bool_t cancel);

static uint64_t
xqc_test_relay_setup(xqc_moqt_session_t *session,
    const xqc_moqt_setup_t *setup, void *data)
{
    return XQC_MOQT_NO_ERROR;
}

static void
xqc_test_relay_ready(xqc_moqt_session_t *session, void *data)
{
    xqc_test_relay_node_t *node = data;
    node->ready++;
}

static xqc_int_t
xqc_test_relay_authorize(xqc_moqt_request_t *request,
    const xqc_moqt_message_t *m, const xqc_moqt_message_t *candidate,
    uint64_t *error, void *data)
{
    return XQC_OK;
}

static xqc_moqt_message_t
xqc_test_relay_message_create(uint64_t type)
{
    xqc_moqt_message_t m;
    xqc_memzero(&m, sizeof(m));
    m.type = type;
    m.track_namespace.count = 2;
    m.track_namespace.fields[0] = (struct iovec){(void *)"media", 5};
    m.track_namespace.fields[1] = (struct iovec){(void *)"a\0b", 3};
    m.track_name = (struct iovec){(void *)"video", 5};
    return m;
}

static void
xqc_test_relay_reply(xqc_test_relay_node_t *node, xqc_moqt_request_t *request,
    uint64_t type)
{
    xqc_moqt_message_t m;
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_REQUEST_OK;
    uint8_t largest[] = {2, 1};
    uint8_t properties[] = {0x0b, 4, 0x80, 0x78, 0x80, 9, 0x6f, 5};
    if (type == XQC_MOQT_MSG_SUBSCRIBE || type == XQC_MOQT_MSG_TRACK_STATUS) {
        if (type == XQC_MOQT_MSG_SUBSCRIBE) {
            m.type = XQC_MOQT_MSG_SUBSCRIBE_OK;
        }
        m.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_LARGEST_OBJECT, sizeof(largest), largest};
        m.parameter_count = 1;
        m.properties = (struct iovec){properties, sizeof(properties)};
    } else if (type == XQC_MOQT_MSG_FETCH) {
        m.type = XQC_MOQT_MSG_FETCH_OK;
        m.end_group = 2;
        m.end_object = 1;
        m.properties = (struct iovec){properties, sizeof(properties)};
        if (node->reject_fetch) {
            m.type = XQC_MOQT_MSG_REQUEST_ERROR;
            m.error.code = XQC_MOQT_REQUEST_TIMEOUT;
            m.properties.iov_len = 0;
        }
    }
    if (xqc_moqt_request_send(request, &m) != XQC_OK) {
        node->invalid++;
    }
}

static void
xqc_test_relay_offer(xqc_test_relay_node_t *node, const char *name,
    uint64_t instance, xqc_bool_t skip)
{
    uint8_t properties[] = {0x0b, 4, 0x80, 0x78, 0x80, 9, 0x6f, 5};
    xqc_moqt_message_t m = xqc_test_relay_message_create(XQC_MOQT_MSG_PUBLISH);
    m.track_name = (struct iovec){(void *)name, strlen(name)};
    m.properties = (struct iovec){properties, sizeof(properties)};
    if (skip) {
        if (xqc_moqt_request_skip(node->tracks, instance, &m) != XQC_OK) {
            node->invalid++;
        }
        return;
    }
    xqc_moqt_request_t *publication = NULL;
    if (xqc_moqt_request_publish(node->tracks, instance, &m, &publication)
        != XQC_OK)
    {
        node->invalid++;
    } else if (publication != NULL) {
        if (node->incoming_count < XQC_TEST_RELAY_REQUESTS) {
            node->incoming[node->incoming_count++] = publication;
        } else {
            node->invalid++;
        }
    }
}

static void
xqc_test_relay_message(xqc_moqt_request_t *request,
    const xqc_moqt_message_t *m, void *data)
{
    xqc_test_relay_node_t *node = data;
    switch (m->type) {
    case XQC_MOQT_MSG_SUBSCRIBE_TRACKS:
        node->tracks = request;
        xqc_test_relay_reply(node, request, m->type);
        xqc_test_relay_offer(node, "video", 1, XQC_FALSE);
        return;
    case XQC_MOQT_MSG_PUBLISH:
        node->publications++;
        xqc_test_relay_reply(node, request, m->type);
        return;
    case XQC_MOQT_MSG_PUBLISH_SKIPPED:
        node->skipped++;
        return;
    case XQC_MOQT_MSG_REQUEST_OK:
    case XQC_MOQT_MSG_SUBSCRIBE_OK:
    case XQC_MOQT_MSG_FETCH_OK:
        node->responses++;
        return;
    case XQC_MOQT_MSG_REQUEST_ERROR:
        node->errors++;
        node->last_error = m->error.code;
        return;
    case XQC_MOQT_MSG_REQUEST_UPDATE:
        xqc_test_relay_reply(node, request, m->type);
        return;
    case XQC_MOQT_MSG_SUBSCRIBE:
        if (node->incoming_count == XQC_TEST_RELAY_REQUESTS) {
            node->invalid++;
            return;
        }
        node->incoming[node->incoming_count++] = request;
        if (!node->defer) {
            xqc_test_relay_reply(node, request, m->type);
        }
        return;
    case XQC_MOQT_MSG_FETCH:
    case XQC_MOQT_MSG_TRACK_STATUS:
        xqc_test_relay_reply(node, request, m->type);
        return;
    default:
        return;
    }
}

static void
xqc_test_relay_request_closed(xqc_moqt_request_t *request,
    const xqc_moqt_error_t *error, void *data)
{
    xqc_test_relay_node_t *node = data;
    if (node->tracks == request) {
        node->tracks = NULL;
    }
    for (size_t i = 0; i < node->incoming_count; i++) {
        if (node->incoming[i] == request) {
            node->incoming[i] = NULL;
        }
    }
}

static void
xqc_test_relay_namespace(xqc_moqt_request_t *request,
    const xqc_moqt_namespace_t *name, xqc_bool_t available, void *data)
{
    xqc_test_relay_node_t *node = data;
    if (name->count != 2 || name->fields[1].iov_len != 3
        || xqc_memcmp(name->fields[1].iov_base, "a\0b", 3))
    {
        node->invalid++;
    }
    if (available) {
        node->namespace_adds++;
    } else {
        node->namespace_removes++;
    }
}

static void
xqc_test_relay_object(xqc_moqt_subscription_t *subscription,
    xqc_moqt_stream_t *stream, const xqc_moqt_object_t *object, void *data)
{
    xqc_test_relay_node_t *node = data;
    if (object->range != XQC_MOQT_RANGE_NONE) {
        node->ranges |= 1u << object->range;
        return;
    }
    const uint8_t properties[] = {0x0b, 4, 0x80, 0x78, 0x80, 9, 0x6f, 5};
    if (object->priority != XQC_TEST_RELAY_PRIORITY
        || object->properties.iov_len != sizeof(properties)
        || xqc_memcmp(object->properties.iov_base, properties,
                      sizeof(properties)))
    {
        node->invalid++;
    }
    for (size_t i = 0; i < object->payload.iov_len; i++) {
        uint8_t expected = (object->payload_offset + i + object->group_id)
                           & UINT8_MAX;
        if (((uint8_t *)object->payload.iov_base)[i] != expected) {
            node->invalid++;
            break;
        }
    }
    node->bytes += object->payload.iov_len;
    if (object->payload_offset + object->payload.iov_len
        == object->payload_length)
    {
        if (xqc_moqt_stream_fetch(stream) != NULL) {
            node->history_objects++;
        } else {
            node->objects++;
        }
        if (object->group_id < XQC_TEST_RELAY_GROUPS) {
            node->groups |= UINT64_C(1) << object->group_id;
        }
    }
}

static void
xqc_test_relay_subscription_closed(xqc_moqt_subscription_t *subscription,
    const xqc_moqt_error_t *error, void *data)
{
    xqc_test_relay_node_t *node = data;
    node->subscription_closed++;
    if (error != NULL) {
        node->last_error = error->code;
    }
}

static void
xqc_test_relay_stream_closed(xqc_moqt_stream_t *stream,
    const xqc_moqt_object_t *last, const xqc_moqt_error_t *error, void *data)
{
    xqc_test_relay_node_t *node = data;
    if (node->sending == stream) {
        node->sending = NULL;
    }
}

static void
xqc_test_relay_fetch_closed(xqc_moqt_fetch_t *fetch,
    const xqc_moqt_error_t *error, void *data)
{
    xqc_test_relay_node_t *node = data;
    if (node->pending_fetch == fetch) {
        node->pending_fetch = NULL;
    }
    node->fetch_closed++;
    if (error != NULL) {
        node->last_error = error->code;
    }
}

static void
xqc_test_relay_fetch_ready(xqc_moqt_fetch_t *fetch,
    xqc_moqt_subscription_t *subscription, void *data)
{
    xqc_test_relay_node_t *node = data;
    /* Only publisher fixtures have upstream SUBSCRIBEs and serve history. */
    if (!node->incoming_count) {
        return;
    }
    if (node->defer) {
        node->pending_fetch = fetch;
        return;
    }
    node->pending_fetch = NULL;
    xqc_moqt_stream_t *stream = xqc_moqt_fetch_open(fetch);
    if (stream == NULL) {
        node->invalid++;
        return;
    }
    uint8_t payload[XQC_TEST_RELAY_SMALL_OBJECT];
    uint8_t properties[] = {0x0b, 4, 0x80, 0x78, 0x80, 9, 0x6f, 5};
    xqc_moqt_object_t object;
    xqc_memzero(&object, sizeof(object));
    object.group_id = 2;
    object.subgroup_id = 1;
    object.priority = XQC_TEST_RELAY_PRIORITY;
    object.payload_length = sizeof(payload);
    object.payload = (struct iovec){payload, sizeof(payload)};
    object.properties = (struct iovec){properties, sizeof(properties)};
    for (size_t i = 0; i < sizeof(payload); i++) {
        payload[i] = i + object.group_id;
    }
    for (object.object_id = 0; object.object_id <= 1; object.object_id++) {
        if (xqc_moqt_stream_send_object(stream, &object) != XQC_OK) {
            node->invalid++;
        }
    }
    if (xqc_moqt_stream_finish(stream) != XQC_OK) {
        node->invalid++;
    }
}

static uint64_t
xqc_test_relay_policy_setup(xqc_moqt_relay_peer_t *peer,
    const xqc_moqt_setup_t *setup, void *data)
{
    return XQC_MOQT_NO_ERROR;
}

static xqc_int_t
xqc_test_relay_policy_authorize(xqc_moqt_relay_peer_t *peer,
    const xqc_moqt_message_t *m, const xqc_moqt_message_t *candidate,
    uint64_t *error, void *data)
{
    if (candidate->track_name.iov_len == 6
        && !xqc_memcmp(candidate->track_name.iov_base, "denied", 6))
    {
        *error = XQC_MOQT_REQUEST_UNAUTHORIZED;
        return XQC_ERROR;
    }
    return XQC_OK;
}

static xqc_int_t
xqc_test_relay_policy_forward(xqc_moqt_relay_peer_t *peer,
    xqc_moqt_message_t *m, void *data)
{
    if (m->track_name.iov_len == 7
        && !xqc_memcmp(m->track_name.iov_base, "private", 7))
    {
        return XQC_ERROR;
    }
    return XQC_OK;
}

static xqc_int_t
xqc_test_relay_accept(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *data)
{
    xqc_test_relay_node_t *node = data;
    xqc_test_relay_connection_t *c = xqc_calloc(1, sizeof(*c));
    if (c == NULL) {
        return XQC_ERROR;
    }
    c->node = node;
    c->socket = node->base.socket;
    xqc_conn_set_transport_user_data(conn, c);
    return XQC_OK;
}

static xqc_int_t
xqc_test_relay_created(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *data, void *proto_data)
{
    xqc_test_relay_connection_t *c = data;
    xqc_test_relay_node_t *node = c->node;
    if (node->relay != NULL) {
        struct iovec scope = {(void *)"example/moq", 11};
        c->peer = xqc_moqt_relay_peer_create(node->relay, conn, &node->config,
                                             &scope, c);
        c->session = xqc_moqt_relay_peer_session(c->peer);
    } else {
        const xqc_moqt_callbacks_t callbacks = {
            .on_setup = xqc_test_relay_setup,
            .on_ready = xqc_test_relay_ready,
            .on_authorize = xqc_test_relay_authorize,
            .on_message = xqc_test_relay_message,
            .on_request_closed = xqc_test_relay_request_closed,
            .on_subscription_closed = xqc_test_relay_subscription_closed,
            .on_fetch_ready = xqc_test_relay_fetch_ready,
            .on_fetch_closed = xqc_test_relay_fetch_closed,
            .on_stream_closed = xqc_test_relay_stream_closed,
            .on_object = xqc_test_relay_object,
            .on_namespace = xqc_test_relay_namespace,
        };
        c->session = xqc_moqt_session_create(conn, &node->config, &callbacks,
                                             node);
    }
    return c->session == NULL ? XQC_ERROR : XQC_OK;
}

static void
xqc_test_relay_handshake(xqc_connection_t *conn, void *data,
    void *proto_data)
{
    xqc_test_relay_connection_t *c = data;
    if (xqc_moqt_session_start(c->session) != XQC_OK) {
        c->node->invalid++;
    }
}

static xqc_int_t
xqc_test_relay_connection_closed(xqc_connection_t *conn,
    const xqc_cid_t *cid, void *data, void *proto_data)
{
    xqc_test_relay_connection_t *c = data;
    if (c->peer != NULL) {
        xqc_moqt_relay_peer_destroy(c->peer);
        xqc_free(c);
    } else {
        xqc_moqt_session_destroy(c->session);
        c->session = NULL;
    }
    return XQC_OK;
}

static xqc_int_t
xqc_test_relay_engine(xqc_test_relay_node_t *node, xqc_engine_type_t type)
{
    xqc_config_t config;
    xqc_engine_ssl_config_t ssl;
    xqc_memzero(&ssl, sizeof(ssl));
    xqc_engine_callback_t engine_callbacks;
    xqc_transport_callbacks_t transport_callbacks;
    xqc_conn_callbacks_t callbacks = {
        .conn_create_notify = xqc_test_relay_created,
        .conn_close_notify = xqc_test_relay_connection_closed,
        .conn_handshake_finished = xqc_test_relay_handshake,
    };
    xqc_moqt_config_init(&node->config, XQC_MOQT_VERSION_DRAFT_22);
    node->base.socket.fd = -1;
    node->base.user_data = node;
    struct sockaddr_in address;
    xqc_memzero(&address, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (xqc_complex_case_make_socket(&node->base,
        (struct sockaddr *)&address, sizeof(address)) != 0)
    {
        return XQC_ERROR;
    }
    node->connection.node = node;
    node->connection.socket = node->base.socket;
    xqc_engine_get_default_config(&config, type);
    config.cfg_log_level = XQC_LOG_ERROR;
    ssl.ciphers = XQC_TLS_CIPHERS;
    ssl.groups = XQC_TLS_GROUPS;
    if (type == XQC_ENGINE_SERVER) {
        ssl.private_key_file = "./server.key";
        ssl.cert_file = "./server.crt";
    }
    xqc_complex_case_init_engine_callbacks(&engine_callbacks);
    xqc_complex_case_init_transport_callbacks(&transport_callbacks);
    transport_callbacks.server_accept = xqc_test_relay_accept;
    node->base.engine = xqc_engine_create(type, &config, &ssl,
        &engine_callbacks, &transport_callbacks, node);
    if (node->base.engine == NULL) {
        return XQC_ERROR;
    }
    if (type == XQC_ENGINE_SERVER) {
        xqc_conn_settings_t settings = {
            .max_datagram_frame_size = XQC_TEST_RELAY_DATAGRAM_SIZE,
            .enable_reset_stream_at = 1};
        xqc_server_set_conn_settings(node->base.engine, &settings);
    }
    return xqc_moqt_init_alpn(node->base.engine, &node->config, &callbacks);
}

static xqc_int_t
xqc_test_relay_connect(xqc_test_relay_node_t *node,
    xqc_test_relay_node_t *server)
{
    if (xqc_test_relay_engine(node, XQC_ENGINE_CLIENT) != XQC_OK) {
        return XQC_ERROR;
    }
    xqc_conn_settings_t settings = {.proto_version = XQC_VERSION_V1,
        .is_interop_mode = 1,
        .max_datagram_frame_size = XQC_TEST_RELAY_DATAGRAM_SIZE,
        .enable_reset_stream_at = 1};
    xqc_conn_ssl_config_t ssl;
    xqc_memzero(&ssl, sizeof(ssl));
    const xqc_cid_t *cid = xqc_moqt_connect(node->base.engine,
        &node->config, &settings, NULL, 0, "localhost", &ssl,
        (struct sockaddr *)&server->base.local, server->base.locallen,
        &node->connection);
    if (cid == NULL) {
        return XQC_ERROR;
    }
    node->base.cid = *cid;
    return XQC_OK;
}

static void
xqc_test_relay_pump(xqc_test_relay_fixture_t *f, unsigned milliseconds)
{
    for (unsigned elapsed = 0; elapsed < milliseconds;
         elapsed += XQC_TEST_RELAY_PUMP_MS)
    {
        xqc_complex_case_engine_t *active[XQC_TEST_RELAY_NODES];
        size_t count = 0;
        for (size_t i = 0; i < XQC_TEST_RELAY_NODES; i++) {
            if (f->engines[i] != NULL && f->engines[i] != f->paused) {
                active[count++] = f->engines[i];
            }
        }
        xqc_complex_case_pump(active, count, XQC_TEST_RELAY_PUMP_MS);
        xqc_moqt_relay_process(f->server.relay, xqc_monotonic_timestamp());
    }
}

static xqc_int_t
xqc_test_relay_init(xqc_test_relay_fixture_t *f)
{
    xqc_memzero(f, sizeof(*f));
    f->replacement.base.socket.fd = -1;
    f->engines[XQC_TEST_RELAY_NODES - 1] = &f->replacement.base;
    f->server.base.socket.fd = -1;
    for (size_t i = 0; i < XQC_TEST_RELAY_CLIENTS; i++) {
        f->clients[i].base.socket.fd = -1;
    }
    xqc_moqt_relay_config_t config;
    xqc_moqt_relay_config_init(&config);
    const xqc_moqt_relay_callbacks_t callbacks = {
        .on_setup = xqc_test_relay_policy_setup,
        .on_authorize = xqc_test_relay_policy_authorize,
        .on_forward = xqc_test_relay_policy_forward,
    };
    f->server.relay = xqc_moqt_relay_create(&config, &callbacks);
    if (f->server.relay == NULL
        || xqc_test_relay_engine(&f->server, XQC_ENGINE_SERVER) != XQC_OK)
    {
        return XQC_ERROR;
    }
    f->engines[0] = &f->server.base;
    for (size_t i = 0; i < XQC_TEST_RELAY_CLIENTS; i++) {
        xqc_test_relay_node_t *node = &f->clients[i];
        if (xqc_test_relay_connect(node, &f->server) != XQC_OK) {
            return XQC_ERROR;
        }
        f->engines[i + 1] = &node->base;
    }
    xqc_test_relay_pump(f, XQC_TEST_RELAY_WAIT_MS);
    for (size_t i = 0; i < XQC_TEST_RELAY_CLIENTS; i++) {
        if (f->clients[i].ready != 1 || f->clients[i].invalid) {
            return XQC_ERROR;
        }
    }
    return XQC_OK;
}

static void
xqc_test_relay_release(xqc_test_relay_fixture_t *f)
{
    /* Close protocol sessions before destroying their event-loop engines. */
    for (size_t i = 0; i < XQC_TEST_RELAY_CLIENTS; i++) {
        xqc_moqt_session_close(f->clients[i].connection.session,
                               XQC_MOQT_NO_ERROR);
    }
    xqc_moqt_session_close(f->replacement.connection.session,
                           XQC_MOQT_NO_ERROR);
    xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
    xqc_complex_case_engine_release(&f->replacement.base);
    for (size_t i = 0; i < XQC_TEST_RELAY_CLIENTS; i++) {
        xqc_complex_case_engine_release(&f->clients[i].base);
    }
    xqc_complex_case_engine_release(&f->server.base);
    xqc_moqt_relay_destroy(f->server.relay);
}

static xqc_int_t
xqc_test_relay_send(xqc_test_relay_fixture_t *f, size_t publisher,
    uint64_t group, size_t payload_size, xqc_bool_t corrupt)
{
    xqc_test_relay_node_t *node = &f->clients[publisher];
    uint8_t payload[XQC_TEST_RELAY_FRAGMENT];
    const uint8_t properties[] = {0x0b, 4, 0x80, 0x78, 0x80, 9, 0x6f, 5};
    xqc_moqt_object_t object;
    xqc_memzero(&object, sizeof(object));
    object.group_id = group;
    object.subgroup_id = 1;
    object.priority = XQC_TEST_RELAY_PRIORITY;
    object.payload_length = payload_size;
    object.first_in_subgroup = 1;
    for (size_t i = 0; i < node->incoming_count; i++) {
        xqc_moqt_subscription_t *subscription =
            xqc_moqt_request_subscription(node->incoming[i]);
        xqc_moqt_location_t location = {group, 0};
        if (!xqc_moqt_subscription_is_matching(subscription, &location)) {
            continue;
        }
        xqc_moqt_stream_t *stream = xqc_moqt_subgroup_open(subscription,
            group, object.subgroup_id, object.priority, 1, 1);
        if (stream == NULL) {
            return XQC_ERROR;
        }
        node->sending = stream;
        for (size_t offset = 0; offset < payload_size;) {
            if (node->sending == NULL && node->allow_cancel) {
                break;
            }
            size_t count = xqc_min(sizeof(payload), payload_size - offset);
            for (size_t j = 0; j < count; j++) {
                payload[j] = (offset + j + group) & UINT8_MAX;
            }
            if (corrupt) {
                payload[0] ^= UINT8_MAX;
            }
            object.payload_offset = offset;
            object.payload = (struct iovec){payload, count};
            object.properties = (struct iovec){(void *)properties,
                offset == 0 ? sizeof(properties) : 0};
            xqc_int_t ret = xqc_moqt_stream_send_object(node->sending, &object);
            if (ret == -XQC_EAGAIN) {
                xqc_test_relay_pump(f, XQC_TEST_RELAY_PUMP_MS);
                continue;
            }
            if (ret != XQC_OK) {
                if (node->allow_cancel && ret == -XQC_EPARAM) {
                    node->sending = NULL;
                    break;
                }
                return XQC_ERROR;
            }
            offset += count;
            /* Service healthy peers while the slow peer remains paused. */
            if (node->allow_cancel && offset % XQC_TEST_RELAY_SEND_BATCH == 0) {
                xqc_test_relay_pump(f, XQC_TEST_RELAY_PUMP_MS);
            }
        }
        if (node->sending != NULL
            && xqc_moqt_stream_finish(node->sending) != XQC_OK)
        {
            return XQC_ERROR;
        }
    }
    node->sending = NULL;
    xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
    return XQC_OK;
}

static xqc_int_t
xqc_test_relay_run(xqc_test_relay_fixture_t *f, const char *mode)
{
    xqc_int_t result = XQC_ERROR;
    xqc_moqt_message_t m = xqc_test_relay_message_create(
        XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE);
    xqc_moqt_request_t *watch = xqc_moqt_request_open(
        f->clients[2].connection.session, &m);
    xqc_test_relay_check(watch != NULL);
    m.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
    xqc_moqt_request_t *registrations[2];
    for (size_t i = 0; i < 2; i++) {
        registrations[i] = xqc_moqt_request_open(
            f->clients[i].connection.session, &m);
        xqc_test_relay_check(registrations[i] != NULL);
        f->clients[i].defer = 1;
    }
    xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
    xqc_test_relay_check(f->clients[2].namespace_adds == 1);
    m = xqc_test_relay_message_create(XQC_MOQT_MSG_SUBSCRIBE);
    xqc_moqt_request_t *subscriptions[2];
    for (size_t i = 0; i < 2; i++) {
        subscriptions[i] = xqc_moqt_request_open(
            f->clients[i + 2].connection.session, &m);
        xqc_test_relay_check(subscriptions[i] != NULL);
    }
    xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
    xqc_test_relay_check(f->clients[2].responses == 1);
    xqc_test_relay_check(f->clients[3].responses == 0);
    for (size_t i = 0; i < 2; i++) {
        xqc_test_relay_node_t *publisher = &f->clients[i];
        xqc_test_relay_check(publisher->incoming_count == 2);
        publisher->defer = 0;
        for (size_t j = 0; j < publisher->incoming_count; j++) {
            xqc_test_relay_reply(publisher, publisher->incoming[j],
                                 XQC_MOQT_MSG_SUBSCRIBE);
        }
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
    }
    xqc_test_relay_check(f->clients[2].responses == 2);
    xqc_test_relay_check(f->clients[3].responses == 1);
    xqc_test_relay_check(xqc_test_relay_send(f, 0, 3,
        XQC_TEST_RELAY_OBJECT_SIZE, 0) == XQC_OK);
    xqc_test_relay_check(xqc_test_relay_send(f, 1, 4,
        XQC_TEST_RELAY_SMALL_OBJECT, 0) == XQC_OK);
    for (size_t i = 2; i < XQC_TEST_RELAY_CLIENTS; i++) {
        xqc_test_relay_check(f->clients[i].objects == 2);
        xqc_test_relay_check(f->clients[i].bytes
            == XQC_TEST_RELAY_OBJECT_SIZE + XQC_TEST_RELAY_SMALL_OBJECT);
        xqc_test_relay_check(f->clients[i].invalid == 0);
    }
    if (!strcmp(mode, "routes")) {
        uint8_t paused = 0;
        xqc_memzero(&m, sizeof(m));
        m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
        m.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_FORWARD, 1, &paused};
        m.parameter_count = 1;
        xqc_test_relay_check(xqc_moqt_request_send(subscriptions[0], &m)
                             == XQC_OK);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        xqc_test_relay_check(xqc_test_relay_send(f, 0, 5,
            XQC_TEST_RELAY_SMALL_OBJECT, 0) == XQC_OK);
        xqc_test_relay_check(f->clients[2].objects == 2);
        xqc_test_relay_check(f->clients[3].objects == 3);
        paused = 1;
        xqc_test_relay_check(f->clients[2].subscription_closed == 0);
        xqc_test_relay_check(xqc_moqt_request_send(subscriptions[0], &m)
                             == XQC_OK);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        xqc_test_relay_check(xqc_test_relay_send(f, 1, 6,
            XQC_TEST_RELAY_SMALL_OBJECT, 0) == XQC_OK);
        xqc_test_relay_check(f->clients[2].objects == 3);
        xqc_test_relay_check(f->clients[3].objects == 4);
        paused = 0;
        for (size_t i = 0; i < 2; i++) {
            xqc_test_relay_check(xqc_moqt_request_send(subscriptions[i], &m)
                                 == XQC_OK);
        }
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        xqc_test_relay_check(xqc_test_relay_send(f, 0, 10,
            XQC_TEST_RELAY_SMALL_OBJECT, 0) == XQC_OK);
        xqc_test_relay_check(f->clients[2].objects == 3);
        xqc_test_relay_check(f->clients[3].objects == 4);
        paused = 1;
        for (size_t i = 0; i < 2; i++) {
            xqc_test_relay_check(xqc_moqt_request_send(subscriptions[i], &m)
                                 == XQC_OK);
        }
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        /* Section 7.4.1: establish a new Session before cancelling the old. */
        xqc_test_relay_check(xqc_test_relay_connect(&f->replacement,
                                                    &f->server) == XQC_OK);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        xqc_test_relay_check(f->replacement.ready == 1);
        m = xqc_test_relay_message_create(XQC_MOQT_MSG_SUBSCRIBE);
        xqc_test_relay_check(xqc_moqt_request_open(
            f->replacement.connection.session, &m) != NULL);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        xqc_test_relay_check(f->replacement.responses == 1);
        xqc_test_relay_check(xqc_test_relay_send(f, 1, 7,
            XQC_TEST_RELAY_SMALL_OBJECT, 0) == XQC_OK);
        xqc_test_relay_check(f->replacement.objects == 1);
        xqc_test_relay_check(f->clients[2].objects == 4);
        xqc_test_relay_check(f->clients[3].objects == 5);
        xqc_moqt_request_cancel(subscriptions[0], XQC_MOQT_RESET_CANCELLED);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        xqc_test_relay_check(xqc_test_relay_send(f, 1, 8,
            XQC_TEST_RELAY_SMALL_OBJECT, 0) == XQC_OK);
        xqc_test_relay_check(f->replacement.objects == 2);
        xqc_test_relay_check(f->clients[2].objects == 4);
        xqc_test_relay_check(f->clients[3].objects == 6);
        /* Section 7.6.1: new demand still receives overlapping source data. */
        xqc_test_relay_check(xqc_test_relay_send(f, 1, 3,
            XQC_TEST_RELAY_OBJECT_SIZE, 0) == XQC_OK);
        xqc_test_relay_check(f->replacement.objects == 3);
        xqc_test_relay_check(f->clients[3].objects == 6);
        xqc_test_relay_check(xqc_moqt_relay_stats(f->server.relay)->duplicates
                             > 0);
        xqc_moqt_request_cancel(registrations[0], XQC_MOQT_RESET_CANCELLED);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        xqc_test_relay_check(f->clients[2].namespace_removes == 0);
        xqc_moqt_request_cancel(registrations[1], XQC_MOQT_RESET_CANCELLED);
        for (unsigned waited = 0;
             waited < XQC_TEST_RELAY_WAIT_MS
                 && f->clients[2].namespace_removes == 0;
             waited += XQC_TEST_RELAY_PUMP_MS)
        {
            xqc_test_relay_pump(f, XQC_TEST_RELAY_PUMP_MS);
        }
        xqc_test_relay_check(f->clients[2].namespace_removes == 1);
        xqc_moqt_session_close(f->clients[0].connection.session,
                               XQC_MOQT_NO_ERROR);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        xqc_test_relay_check(xqc_test_relay_send(f, 1, 9,
            XQC_TEST_RELAY_SMALL_OBJECT, 0) == XQC_OK);
        xqc_test_relay_check(f->replacement.objects == 4);
        xqc_test_relay_check(f->clients[3].objects == 7);
        xqc_test_relay_check(f->replacement.invalid == 0);
        /* Rendezvous waits for a new namespace source before Established. */
        uint8_t rendezvous[] = {0x83, 0xe8};
        m = xqc_test_relay_message_create(XQC_MOQT_MSG_SUBSCRIBE);
        m.track_namespace.count = 1;
        m.track_namespace.fields[0] = (struct iovec){(void *)"late", 4};
        m.parameter_count = 1;
        m.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_RENDEZVOUS_TIMEOUT, sizeof(rendezvous), rendezvous};
        unsigned responses = f->replacement.responses;
        xqc_test_relay_check(xqc_moqt_request_open(
            f->replacement.connection.session, &m) != NULL);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        xqc_test_relay_check(f->replacement.responses == responses);
        xqc_moqt_message_t publication = m;
        publication.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
        publication.parameter_count = 0;
        xqc_test_relay_check(xqc_moqt_request_open(
            f->clients[1].connection.session, &publication) != NULL);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        xqc_test_relay_check(f->replacement.responses == responses + 1);

        m.track_namespace.fields[0] = (struct iovec){(void *)"cancelled", 9};
        xqc_moqt_request_t *pending = xqc_moqt_request_open(
            f->replacement.connection.session, &m);
        xqc_test_relay_check(pending != NULL);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        size_t incoming = f->clients[1].incoming_count;
        xqc_moqt_request_cancel(pending, XQC_MOQT_RESET_CANCELLED);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        publication.track_namespace = m.track_namespace;
        xqc_test_relay_check(xqc_moqt_request_open(
            f->clients[1].connection.session, &publication) != NULL);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        xqc_test_relay_check(f->clients[1].incoming_count == incoming);
        xqc_test_relay_check(f->replacement.responses == responses + 1);

        /* Independent filters and Datagram delivery survive both hops. */
        uint8_t filter[] = {XQC_MOQT_FILTER_ABSOLUTE_START, 20, 0};
        xqc_memzero(&m, sizeof(m));
        m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
        m.parameter_count = 1;
        m.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_LOCATION_FILTER, sizeof(filter), filter};
        xqc_test_relay_check(xqc_moqt_request_send(subscriptions[1], &m)
                             == XQC_OK);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        unsigned received = f->clients[3].objects;
        unsigned replaced = f->replacement.objects;
        uint8_t properties[] = {0x0b, 4, 0x80, 0x78, 0x80, 9, 0x6f, 5};
        uint8_t payload[XQC_TEST_RELAY_SMALL_OBJECT];
        xqc_moqt_object_t object;
        xqc_memzero(&object, sizeof(object));
        object.datagram = 1;
        object.priority = XQC_TEST_RELAY_PRIORITY;
        object.properties = (struct iovec){properties, sizeof(properties)};
        object.payload = (struct iovec){payload, sizeof(payload)};
        object.payload_length = sizeof(payload);
        for (object.group_id = 19; object.group_id <= 20; object.group_id++) {
            for (size_t j = 0; j < sizeof(payload); j++) {
                payload[j] = (object.group_id + j) & UINT8_MAX;
            }
            /* First three interests are the two original and replacement. */
            for (size_t i = 0; i < 3; i++) {
                xqc_moqt_subscription_t *sub = xqc_moqt_request_subscription(
                    f->clients[1].incoming[i]);
                xqc_moqt_location_t location = {object.group_id, 0};
                if (xqc_moqt_subscription_is_matching(sub, &location)) {
                    xqc_test_relay_check(xqc_moqt_datagram_send(sub, &object)
                                         == XQC_OK);
                }
            }
            xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        }
        xqc_test_relay_check(f->clients[3].objects == received + 1);
        xqc_test_relay_check(f->replacement.objects == replaced + 2);
        xqc_test_relay_check(f->clients[3].invalid == 0);
        xqc_test_relay_check(f->replacement.invalid == 0);
        /* A direct PUBLISH fans out without a namespace registration. */
        m = xqc_test_relay_message_create(XQC_MOQT_MSG_PUBLISH);
        m.track_namespace.count = 1;
        m.track_namespace.fields[0] = (struct iovec){(void *)"push", 4};
        m.track_alias = XQC_TEST_RELAY_DIRECT_ALIAS;
        m.properties = (struct iovec){properties, sizeof(properties)};
        xqc_moqt_request_t *publish = xqc_moqt_request_open(
            f->clients[1].connection.session, &m);
        xqc_test_relay_check(publish != NULL);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        m.type = XQC_MOQT_MSG_SUBSCRIBE;
        m.properties.iov_len = 0;
        xqc_test_relay_check(xqc_moqt_request_open(
            f->clients[3].connection.session, &m) != NULL);
        xqc_test_relay_check(xqc_moqt_request_open(
            f->replacement.connection.session, &m) != NULL);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        object.group_id = 21;
        for (size_t j = 0; j < sizeof(payload); j++) {
            payload[j] = (object.group_id + j) & UINT8_MAX;
        }
        xqc_test_relay_check(xqc_moqt_datagram_send(
            xqc_moqt_request_subscription(publish), &object) == XQC_OK);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        xqc_test_relay_check(f->clients[3].objects == received + 2);
        xqc_test_relay_check(f->replacement.objects == replaced + 3);
        xqc_test_relay_check(f->clients[3].invalid == 0);
        xqc_test_relay_check(f->replacement.invalid == 0);

    } else if (!strcmp(mode, "errors")) {
        /* Stop reading one real UDP peer; the healthy peer must still drain. */
        f->paused = &f->clients[2].base;
        f->clients[0].allow_cancel = 1;
        xqc_test_relay_check(xqc_test_relay_send(f, 0, 12,
            XQC_TEST_RELAY_SLOW_OBJECT, 0) == XQC_OK);
        f->clients[0].allow_cancel = 0;
        /* Enqueue success does not mean the relay has received every byte. */
        for (unsigned waited = 0; waited < XQC_TEST_RELAY_WAIT_MS;
             waited += XQC_TEST_RELAY_PUMP_MS)
        {
            if (xqc_moqt_relay_stats(f->server.relay)->slow_subscribers
                && f->clients[3].objects == 3)
            {
                break;
            }
            xqc_test_relay_pump(f, XQC_TEST_RELAY_PUMP_MS);
        }
        f->paused = NULL;
        /* The resumed peer still has to receive and acknowledge the reset. */
        for (unsigned waited = 0;
             waited < XQC_TEST_RELAY_WAIT_MS
                 && f->clients[2].subscription_closed == 0;
             waited += XQC_TEST_RELAY_PUMP_MS)
        {
            xqc_test_relay_pump(f, XQC_TEST_RELAY_PUMP_MS);
        }
        printf("slow isolation: slow=%llu closed=%u/%u objects=%u/%u\n",
            (unsigned long long)xqc_moqt_relay_stats(f->server.relay)
                ->slow_subscribers,
            f->clients[2].subscription_closed,
            f->clients[3].subscription_closed,
            f->clients[2].objects, f->clients[3].objects);
        xqc_test_relay_check(xqc_moqt_relay_stats(f->server.relay)
                             ->slow_subscribers == 1);
        xqc_test_relay_check(f->clients[2].subscription_closed == 1);
        xqc_test_relay_check(f->clients[3].subscription_closed == 0);
        xqc_test_relay_check(f->clients[2].last_error
                             == XQC_MOQT_RESET_TOO_FAR_BEHIND);
        xqc_test_relay_check(f->clients[3].objects == 3);
        m = xqc_test_relay_message_create(XQC_MOQT_MSG_SUBSCRIBE);
        m.track_name = (struct iovec){(void *)"denied", 6};
        xqc_test_relay_check(xqc_moqt_request_open(
            f->clients[3].connection.session, &m) != NULL);
        for (unsigned waited = 0;
             waited < XQC_TEST_RELAY_WAIT_MS && f->clients[3].errors == 0;
             waited += XQC_TEST_RELAY_PUMP_MS)
        {
            xqc_test_relay_pump(f, XQC_TEST_RELAY_PUMP_MS);
        }
        xqc_test_relay_check(f->clients[3].errors == 1);
        xqc_test_relay_check(f->clients[3].last_error
                             == XQC_MOQT_REQUEST_UNAUTHORIZED);
        xqc_test_relay_check(xqc_test_relay_send(f, 1, 3,
            XQC_TEST_RELAY_OBJECT_SIZE, 1) == XQC_OK);
        xqc_test_relay_check(xqc_moqt_relay_stats(f->server.relay)->malformed
                             == 1);
        xqc_test_relay_check(f->clients[2].objects == 2);
        for (unsigned waited = 0;
             waited < XQC_TEST_RELAY_WAIT_MS
                 && f->clients[3].subscription_closed < 2;
             waited += XQC_TEST_RELAY_PUMP_MS)
        {
            xqc_test_relay_pump(f, XQC_TEST_RELAY_PUMP_MS);
        }
        /* Slow delivery closes once; denied and malformed grants each close. */
        xqc_test_relay_check(f->clients[2].subscription_closed == 1);
        xqc_test_relay_check(f->clients[3].subscription_closed == 2);
        m = xqc_test_relay_message_create(XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE);
        xqc_test_relay_check(xqc_moqt_request_open(
            f->clients[3].connection.session, &m) != NULL);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        xqc_test_relay_check(f->clients[3].namespace_adds == 1);
    } else {
        xqc_bool_t errors = !strcmp(mode, "history-errors");
        xqc_moqt_request_t *publish = NULL;
        if (!errors) {
            m = xqc_test_relay_message_create(XQC_MOQT_MSG_PUBLISH);
            m.track_alias = XQC_TEST_RELAY_DIRECT_ALIAS;
            publish = xqc_moqt_request_open(
                f->clients[1].connection.session, &m);
            xqc_test_relay_check(publish != NULL);
            xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
            f->clients[0].defer = f->clients[1].defer = XQC_TRUE;
        }
        uint8_t filter[] = {XQC_MOQT_FILTER_ABSOLUTE_RANGE, 2, 0, 0, 1};
        m = xqc_test_relay_message_create(XQC_MOQT_MSG_FETCH);
        m.parameter_count = 1;
        m.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_LOCATION_FILTER, sizeof(filter), filter};
        f->clients[0].reject_fetch = f->clients[1].reject_fetch = errors;
        xqc_test_relay_check(xqc_moqt_request_open(
            f->clients[2].connection.session, &m) != NULL);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        if (errors) {
            xqc_test_relay_check(f->clients[2].errors == 1);
        } else {
            /* Section 9.10: live state and cancellation leave FETCH intact. */
            xqc_test_relay_check(f->clients[2].history_objects == 0);
            xqc_test_relay_check(f->clients[2].fetch_closed == 0);
            xqc_memzero(&m, sizeof(m));
            uint8_t largest[] = {5, 0};
            m.type = XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY;
            m.parameter_count = 1;
            m.parameters[0] = (xqc_moq_message_parameter_t){
                XQC_MOQT_PARAM_LARGEST_OBJECT, sizeof(largest), largest};
            xqc_test_relay_check(xqc_moqt_request_send(publish, &m) == XQC_OK);
            xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
            xqc_moqt_location_t location;
            xqc_test_relay_check(xqc_moqt_subscription_largest(
                xqc_moqt_request_subscription(subscriptions[0]), &location)
                                 == XQC_OK);
            xqc_test_relay_check(location.group_id == 5);
            xqc_moqt_request_cancel(publish, XQC_MOQT_RESET_CANCELLED);
            xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
            xqc_test_relay_check(f->clients[2].fetch_closed == 0);
            unsigned pending = 0;
            for (size_t i = 0; i < 2; i++) {
                xqc_test_relay_node_t *node = &f->clients[i];
                node->defer = XQC_FALSE;
                if (node->pending_fetch != NULL) {
                    pending++;
                    xqc_test_relay_fetch_ready(node->pending_fetch, NULL, node);
                }
            }
            xqc_test_relay_check(pending == 1);
            xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
            xqc_test_relay_check(f->clients[2].history_objects == 2);
            xqc_test_relay_check(f->clients[2].fetch_closed == 1);
        }
        /* A Fill update and live objects share only the subscription. */
        uint8_t fill[] = {6, XQC_MOQT_PARAM_LOCATION_FILTER,
            XQC_MOQT_FILTER_ABSOLUTE_RANGE, 2, 0, 0, 1};
        xqc_memzero(&m, sizeof(m));
        m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
        m.parameter_count = 1;
        m.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_FILL_PARAMETERS, sizeof(fill), fill};
        xqc_test_relay_check(xqc_moqt_request_send(subscriptions[1], &m)
                             == XQC_OK);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        if (errors) {
            xqc_test_relay_check(f->clients[3].fetch_closed == 1);
            xqc_test_relay_check(f->clients[3].history_objects == 0);
        } else {
            xqc_test_relay_check(f->clients[3].history_objects == 2);
            xqc_test_relay_check(f->clients[3].fetch_closed == 1);
        }
        xqc_test_relay_check(xqc_test_relay_send(f, 0, 8,
            XQC_TEST_RELAY_SMALL_OBJECT, 0) == XQC_OK);
        xqc_test_relay_check(f->clients[3].objects == 3);
    }
    for (size_t i = 0; i < XQC_TEST_RELAY_CLIENTS; i++) {
        xqc_test_relay_check(f->clients[i].invalid == 0);
    }
    printf("relay %s: two publishers/two subscribers, forwarded=%llu\n", mode,
           (unsigned long long)
           xqc_moqt_relay_stats(f->server.relay)->forwarded);
    result = XQC_OK;
done:
    return result;
}

static xqc_int_t
xqc_test_relay_rendezvous_run(xqc_test_relay_fixture_t *f, xqc_bool_t cancel)
{
    xqc_int_t result = XQC_ERROR;
    xqc_moqt_message_t m = xqc_test_relay_message_create(
        XQC_MOQT_MSG_SUBSCRIBE_TRACKS);
    xqc_moqt_request_t *watch = xqc_moqt_request_open(
        f->clients[2].connection.session, &m);
    xqc_test_relay_check(watch != NULL);
    xqc_test_relay_check(xqc_moqt_request_open(
        f->clients[3].connection.session, &m) != NULL);
    xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
    unsigned responses = f->clients[2].responses;
    m.type = XQC_MOQT_MSG_SUBSCRIBE;
    uint8_t wait[] = {0x83, 0xe8}; /* Rendezvous budget: 1000 ms. */
    m.parameter_count = 1;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_RENDEZVOUS_TIMEOUT, sizeof(wait), wait};
    xqc_moqt_request_t *pending = xqc_moqt_request_open(
        f->clients[2].connection.session, &m);
    xqc_test_relay_check(pending != NULL);
    xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
    xqc_test_relay_check(f->clients[2].responses == responses);
    if (cancel) {
        xqc_moqt_request_cancel(pending, XQC_MOQT_RESET_CANCELLED);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
    }
    m.type = XQC_MOQT_MSG_PUBLISH;
    m.parameter_count = 0;
    xqc_moqt_request_t *publish = xqc_moqt_request_open(
        f->clients[0].connection.session, &m);
    xqc_test_relay_check(publish != NULL);
    f->clients[0].incoming[f->clients[0].incoming_count++] = publish;
    xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
    /* Section 7.6: pending SUB wins only for its own subscriber. */
    xqc_test_relay_check(f->clients[2].responses == responses + !cancel);
    xqc_test_relay_check(f->clients[2].publications == cancel);
    xqc_test_relay_check(f->clients[2].skipped == !cancel);
    xqc_test_relay_check(f->clients[3].publications == 1);
    xqc_test_relay_check(f->clients[3].skipped == 0);
    xqc_test_relay_check(xqc_test_relay_send(f, 0, 3,
        XQC_TEST_RELAY_SMALL_OBJECT, 0) == XQC_OK);
    for (size_t i = 2; i < XQC_TEST_RELAY_CLIENTS; i++) {
        xqc_test_relay_check(f->clients[i].objects == 1);
        xqc_test_relay_check(f->clients[i].bytes
                            == XQC_TEST_RELAY_SMALL_OBJECT);
    }
    if (!cancel) {
        xqc_moqt_request_cancel(pending, XQC_MOQT_RESET_CANCELLED);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
    }
    /* Updating St must not retry the publication already handled by SUB. */
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
    xqc_test_relay_check(xqc_moqt_request_send(watch, &m) == XQC_OK);
    xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
    xqc_test_relay_check(f->clients[2].publications == cancel);
    xqc_test_relay_check(f->clients[2].skipped == !cancel);
    for (size_t i = 0; i < XQC_TEST_RELAY_CLIENTS; i++) {
        xqc_test_relay_check(f->clients[i].invalid == 0);
        xqc_test_relay_check(f->clients[i].errors == 0);
    }
    printf("relay rendezvous%s: Pc=%u/%u, objects=%u/%u\n",
           cancel ? "-cancel" : "", f->clients[2].publications,
           f->clients[3].publications, f->clients[2].objects,
           f->clients[3].objects);
    result = XQC_OK;
done:
    return result;
}

static xqc_int_t
xqc_test_relay_tracks_run(xqc_test_relay_fixture_t *f, xqc_bool_t errors)
{
    xqc_int_t result = XQC_ERROR;
    xqc_moqt_message_t m = xqc_test_relay_message_create(
        XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE);
    xqc_moqt_request_t *watch = xqc_moqt_request_open(
        f->clients[2].connection.session, &m);
    xqc_test_relay_check(watch != NULL);
    m.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
    for (size_t i = 0; i < 2; i++) {
        xqc_test_relay_check(xqc_moqt_request_open(
            f->clients[i].connection.session, &m) != NULL);
    }
    xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
    xqc_test_relay_check(f->clients[2].namespace_adds == 1);
    m.type = XQC_MOQT_MSG_SUBSCRIBE_TRACKS;
    xqc_moqt_request_t *interests[2];
    for (size_t i = 0; i < 2; i++) {
        interests[i] = xqc_moqt_request_open(
            f->clients[i + 2].connection.session, &m);
        xqc_test_relay_check(interests[i] != NULL);
    }
    xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
    for (size_t i = 0; i < 2; i++) {
        xqc_test_relay_check(f->clients[i].incoming_count == 1);
        xqc_test_relay_check(f->clients[i + 2].publications == 2);
    }
    /* Names alone produce Pc; neither subscriber sends SUBSCRIBE. */
    xqc_test_relay_check(xqc_test_relay_send(f, 0, 3,
        XQC_TEST_RELAY_SMALL_OBJECT, 0) == XQC_OK);
    xqc_test_relay_check(xqc_test_relay_send(f, 1, 4,
        XQC_TEST_RELAY_SMALL_OBJECT, 0) == XQC_OK);
    xqc_test_relay_check(f->clients[2].objects == 2);
    xqc_test_relay_check(f->clients[3].objects == 2);
    if (errors) {
        xqc_test_relay_offer(&f->clients[0], "skipped", 2, XQC_TRUE);
        xqc_test_relay_offer(&f->clients[1], "private", 2, XQC_FALSE);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        for (size_t i = 2; i < XQC_TEST_RELAY_CLIENTS; i++) {
            xqc_test_relay_check(f->clients[i].skipped == 1);
            xqc_test_relay_check(f->clients[i].publications == 2);
            xqc_test_relay_check(f->clients[i].subscription_closed == 0);
        }
        /* Repeating this publication cannot turn SKIPPED into PUBLISH. */
        xqc_test_relay_offer(&f->clients[0], "skipped", 2, XQC_FALSE);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        xqc_test_relay_check(f->clients[2].publications == 2);
        xqc_test_relay_check(f->clients[2].skipped == 1);
        xqc_test_relay_offer(&f->clients[0], "skipped", 3, XQC_FALSE);
        xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
        xqc_test_relay_check(f->clients[2].publications == 3);
        xqc_test_relay_check(f->clients[3].publications == 3);
    }
    xqc_moqt_request_cancel(interests[0], XQC_MOQT_RESET_CANCELLED);
    xqc_moqt_request_cancel(watch, XQC_MOQT_RESET_CANCELLED);
    xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
    unsigned before = f->clients[2].publications;
    unsigned active = f->clients[3].publications;
    xqc_test_relay_offer(&f->clients[1], "extra", 4, XQC_FALSE);
    xqc_test_relay_pump(f, XQC_TEST_RELAY_SETTLE_MS);
    xqc_test_relay_check(f->clients[2].publications == before);
    xqc_test_relay_check(f->clients[3].publications == active + 1);
    unsigned objects = f->clients[2].objects;
    xqc_test_relay_check(xqc_test_relay_send(f, 1, 5,
        XQC_TEST_RELAY_SMALL_OBJECT, 0) == XQC_OK);
    xqc_test_relay_check(f->clients[2].objects == objects + 1);
    xqc_test_relay_check(f->clients[2].subscription_closed == 0);
    xqc_moqt_request_cancel(interests[1], XQC_MOQT_RESET_CANCELLED);
    for (unsigned waited = 0; waited < XQC_TEST_RELAY_WAIT_MS;
         waited += XQC_TEST_RELAY_PUMP_MS)
    {
        if (f->clients[0].tracks == NULL && f->clients[1].tracks == NULL) {
            break;
        }
        xqc_test_relay_pump(f, XQC_TEST_RELAY_PUMP_MS);
    }
    xqc_test_relay_check(f->clients[0].tracks == NULL);
    xqc_test_relay_check(f->clients[1].tracks == NULL);
    for (size_t i = 0; i < XQC_TEST_RELAY_CLIENTS; i++) {
        xqc_test_relay_check(f->clients[i].invalid == 0);
    }
    printf("relay tracks%s: Pc=%u/%u, objects=%u/%u, skipped=%u/%u\n",
           errors ? "-errors" : "", f->clients[2].publications,
           f->clients[3].publications, f->clients[2].objects,
           f->clients[3].objects, f->clients[2].skipped, f->clients[3].skipped);
    result = XQC_OK;
done:
    return result;
}

int
main(int argc, char **argv)
{
    if (argc != 2) {
        return 2;
    }
    xqc_test_relay_fixture_t fixture;
    xqc_int_t result = xqc_test_relay_init(&fixture);
    if (result == XQC_OK) {
        if (!strcmp(argv[1], "tracks") || !strcmp(argv[1], "tracks-errors")) {
            result = xqc_test_relay_tracks_run(&fixture,
                !strcmp(argv[1], "tracks-errors"));
        } else {
            result = xqc_test_relay_run(&fixture, argv[1]);
        }
    }
    xqc_test_relay_release(&fixture);
    if (result == XQC_OK
        && (!strcmp(argv[1], "tracks") || !strcmp(argv[1], "tracks-errors")))
    {
        result = xqc_test_relay_init(&fixture);
        if (result == XQC_OK) {
            result = xqc_test_relay_rendezvous_run(&fixture,
                !strcmp(argv[1], "tracks-errors"));
        }
        xqc_test_relay_release(&fixture);
    }
    return result == XQC_OK ? 0 : 1;
}
