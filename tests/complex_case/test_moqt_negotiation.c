/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include <stdio.h>
#include <netinet/in.h>
#include "complex_case_common.h"
#include "include/moq/xqc_moq.h"
#include "include/moq/xqc_moqt.h"
#include "src/common/xqc_str.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_stream.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moqt/xqc_moqt_session.h"
#include "moq/moqt/xqc_moqt_codec.h"

#define XQC_MOQT_HANDSHAKE_WAIT_MS 2000
#define XQC_MOQT_PUMP_STEP_MS 10
#define XQC_MOQT_TEST_DELIVERY_MS 100
#define XQC_MOQT_TEST_UNKNOWN_ERROR 0x1234
#define XQC_MOQT_TEST_OBJECT_SIZE (128 * 1024)
#define XQC_MOQT_TEST_FRAGMENT_SIZE 2048

static void moqt_error_log(xqc_log_level_t level, const void *buf,
    size_t size, void *data);

static void
moqt_error_log(xqc_log_level_t level, const void *buf, size_t size, void *data)
{
    fwrite(buf, 1, size, stderr);
    fputc('\n', stderr);
}

#define xqc_moqt_check(expr)                                                 \
    do {                                                                    \
        if (!(expr)) {                                                      \
            fprintf(stderr, "line %d: %s\n", __LINE__, #expr);                \
            goto done;                                                      \
        }                                                                   \
    } while (0)

typedef enum {
    XQC_MOQT_TEST_REQUESTS,
    XQC_MOQT_TEST_SUBSCRIPTIONS,
    XQC_MOQT_TEST_DATAGRAMS,
    XQC_MOQT_TEST_SUBGROUPS,
    XQC_MOQT_TEST_DELIVERY,
    XQC_MOQT_TEST_FETCH,
    XQC_MOQT_TEST_FILL,
    XQC_MOQT_TEST_NAMESPACES,
} moqt_test_mode_t;

typedef struct {
    xqc_complex_case_engine_t   base;
    unsigned                    created;
    unsigned                    handshakes;
    unsigned                    invalid_handshakes;
    unsigned                    closed;
    xqc_int_t                   error;
    xqc_bool_t                  application_error;
    const char                 *expected_alpn;
    unsigned                    setup;
    size_t                      control_bytes;
    const uint8_t              *setup_wire;
    size_t                      setup_len;
    uint8_t                     setup_fin;
    xqc_moq_user_session_t      legacy;
    xqc_int_t                   requests;
    xqc_moqt_session_t         *session;
    xqc_moqt_request_t         *request;
    unsigned                    ready;
    unsigned                    messages;
    unsigned                    updates;
    unsigned                    responses;
    unsigned                    request_errors;
    unsigned                    request_goaways;
    unsigned                    request_closed;
    uint64_t                    last_id;
    uint64_t                    last_error;
    uint64_t                    normalized_error;
    char                        candidate_prefix;
    unsigned                    objects;
    xqc_moqt_object_t           object;
    size_t                      payload_bytes;
    unsigned                    empty_objects;
    unsigned                    status_objects;
    unsigned                    data_closed;
    unsigned                    group_ends;
    unsigned                    subscription_closed;
    unsigned                    dropped_packets;
    xqc_int_t                   defer_data;
    xqc_int_t                   defer_response;
    unsigned                    ranges;
    unsigned                    datagram_objects;
    unsigned                    fetch_closed;
    unsigned                    fill_ready;
    unsigned                    fill_objects;
    unsigned                    namespace_adds;
    unsigned                    namespace_removes;
    size_t                      namespace_fields;
    xqc_moqt_fetch_t           *fill;
    xqc_int_t                   drop_packets;
} moqt_endpoint_t;

static xqc_int_t
moqt_accept(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *data)
{
    moqt_endpoint_t *ep = data;
    xqc_conn_set_transport_user_data(conn, &ep->legacy);
    return XQC_OK;
}

static ssize_t
moqt_write(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *data)
{
    moqt_endpoint_t *ep = container_of((xqc_moq_user_session_t *) data,
                                       moqt_endpoint_t, legacy);
    if (ep->drop_packets) {
        ep->dropped_packets++;
        return size;
    }
    return xqc_complex_case_write_socket(buf, size, peer_addr, peer_addrlen,
                                         &ep->base);
}

static void
moqt_legacy_setup(xqc_moq_user_session_t *user, char *extdata)
{
    moqt_endpoint_t *ep = container_of(user, moqt_endpoint_t, legacy);
    ep->setup++;
}

static void
moqt_legacy_datachannel(xqc_moq_user_session_t *user)
{
    moqt_endpoint_t *ep = container_of(user, moqt_endpoint_t, legacy);
    if (!user->session->datachannel.ready) {
        ep->invalid_handshakes++;
    }
}

static void
moqt_legacy_catalog(xqc_moq_user_session_t *user,
    xqc_moq_track_info_t **tracks, xqc_int_t count)
{
    moqt_endpoint_t *ep = container_of(user, moqt_endpoint_t, legacy);
    /* These endpoints subscribe without publishing media tracks. */
    if (count != 0) {
        ep->invalid_handshakes++;
    }
}

static uint64_t
moqt_setup(xqc_moqt_session_t *s, const xqc_moqt_setup_t *setup, void *data)
{
    moqt_endpoint_t *ep = data;
    ep->setup++;
    return XQC_MOQT_NO_ERROR;
}

static void
moqt_ready(xqc_moqt_session_t *s, void *data)
{
    moqt_endpoint_t *ep = data;
    ep->ready++;
}

static xqc_int_t
moqt_authorize(xqc_moqt_request_t *r, const xqc_moqt_message_t *m,
    const xqc_moqt_message_t *candidate, uint64_t *error, void *data)
{
    moqt_endpoint_t *ep = data;
    if (candidate->track_namespace.count) {
        ep->candidate_prefix = *(char *)candidate->track_namespace.fields[0]
            .iov_base;
        if (ep->candidate_prefix == '!') {
            *error = XQC_MOQT_REQUEST_UNAUTHORIZED;
            return XQC_ERROR;
        }
    }
    return XQC_OK;
}

static void
moqt_message(xqc_moqt_request_t *r, const xqc_moqt_message_t *m, void *data)
{
    moqt_endpoint_t *ep = data;
    ep->last_id = m->request_id;
    if (m->type == XQC_MOQT_MSG_PUBLISH_DONE
        || m->type == XQC_MOQT_MSG_NAMESPACE
        || m->type == XQC_MOQT_MSG_NAMESPACE_DONE)
    {
        return;
    }
    if (m->type == XQC_MOQT_MSG_GOAWAY) {
        ep->request_goaways++;
        return;
    }
    if (m->type == XQC_MOQT_MSG_REQUEST_OK
        || m->type == XQC_MOQT_MSG_SUBSCRIBE_OK
        || m->type == XQC_MOQT_MSG_FETCH_OK)
    {
        ep->responses++;
        return;
    }
    if (m->type == XQC_MOQT_MSG_REQUEST_ERROR) {
        ep->request_errors++;
        ep->last_error = m->error.code;
        ep->normalized_error = m->error.normalized_code;
        return;
    }
    ep->messages++;
    ep->updates += m->type == XQC_MOQT_MSG_REQUEST_UPDATE;
    ep->request = r;
    xqc_moqt_message_t response;
    xqc_memzero(&response, sizeof(response));
    response.type = XQC_MOQT_MSG_REQUEST_OK;
    uint8_t largest[] = {5, 7};
    uint8_t properties[] = {0x0e, 7, 0x14, 2};
    if (m->type == XQC_MOQT_MSG_SUBSCRIBE
        || m->type == XQC_MOQT_MSG_TRACK_STATUS)
    {
        response.type = m->type == XQC_MOQT_MSG_SUBSCRIBE
            ? XQC_MOQT_MSG_SUBSCRIBE_OK : XQC_MOQT_MSG_REQUEST_OK;
        response.parameter_count = 1;
        response.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_LARGEST_OBJECT, sizeof(largest), largest};
        response.properties = (struct iovec){properties, sizeof(properties)};
    }
    if (m->type == XQC_MOQT_MSG_FETCH) {
        response.type = XQC_MOQT_MSG_FETCH_OK;
        response.end_group = 3;
        response.end_object = 9;
    }
    if (ep->candidate_prefix == '?') {
        response.type = XQC_MOQT_MSG_REQUEST_ERROR;
        response.error.code = XQC_MOQT_TEST_UNKNOWN_ERROR;
    }
    if (xqc_moqt_request_send(r, &response) != XQC_OK) {
        ep->invalid_handshakes++;
    }
}

static void
moqt_request_closed(xqc_moqt_request_t *r, const xqc_moqt_error_t *error,
    void *data)
{
    moqt_endpoint_t *ep = data;
    ep->request_closed++;
    if (ep->request == r) {
        ep->request = NULL;
    }
}

static void
moqt_object(xqc_moqt_subscription_t *sub, xqc_moqt_stream_t *stream,
    const xqc_moqt_object_t *object, void *data)
{
    moqt_endpoint_t *ep = data;
    ep->objects++;
    ep->object = *object;
    if (stream != NULL
        || !object->datagram
        || object->payload_offset
        || object->payload_length != object->payload.iov_len
        || (object->payload.iov_len
            && *(uint8_t *)object->payload.iov_base != 'x'))
    {
        ep->invalid_handshakes++;
    }
}

static void
moqt_subgroup_object(xqc_moqt_subscription_t *sub, xqc_moqt_stream_t *stream,
    const xqc_moqt_object_t *o, void *data)
{
    moqt_endpoint_t *ep = data;
    if (stream == NULL
        || o->datagram
        || o->subgroup_id != 3
        || o->priority != 7)
    {
        ep->invalid_handshakes++;
    }
    if (o->payload_length) {
        const uint8_t properties[] = {0x78, 9};
        if (o->object_id != 0
            || o->payload_length != XQC_MOQT_TEST_OBJECT_SIZE
            || o->payload_offset != ep->payload_bytes
            || !o->first_in_subgroup
            || o->properties.iov_len != sizeof(properties)
            || xqc_memcmp(o->properties.iov_base, properties,
                          sizeof(properties)) != 0)
        {
            ep->invalid_handshakes++;
        }
        for (size_t i = 0; i < o->payload.iov_len; i++) {
            if (((uint8_t *)o->payload.iov_base)[i] != 'x') {
                ep->invalid_handshakes++;
            }
        }
        ep->payload_bytes += o->payload.iov_len;
    } else if (o->status == XQC_MOQT_OBJECT_NORMAL) {
        ep->empty_objects++;
    } else {
        ep->status_objects++;
    }
}

static void
moqt_data_closed(xqc_moqt_stream_t *stream, const xqc_moqt_object_t *last,
    const xqc_moqt_error_t *error, void *data)
{
    moqt_endpoint_t *ep = data;
    ep->data_closed++;
    if (last != NULL) {
        if (last->payload.iov_base != NULL
            || last->properties.iov_base != NULL)
        {
            ep->invalid_handshakes++;
        }
        ep->group_ends += last->end_of_group;
    }
}

static xqc_int_t
moqt_created(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *data, void *proto_data)
{
    moqt_endpoint_t *ep = container_of((xqc_moq_user_session_t *) data,
                                       moqt_endpoint_t, legacy);
    xqc_moq_session_callbacks_t cbs = {
        .on_session_setup = moqt_legacy_setup,
        .on_datachannel = moqt_legacy_datachannel,
        .on_catalog = moqt_legacy_catalog,
    };
    ep->created++;
    if (strcmp(ep->expected_alpn, XQC_ALPN_MOQ_QUIC) == 0) {
        return xqc_moq_session_create(
            conn, &ep->legacy,
            XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_PUBSUB, cbs, NULL) == NULL
            ? -XQC_EPARAM : XQC_OK;
    }
    if (ep->requests) {
        xqc_moqt_config_t config;
        xqc_moqt_config_init(&config, XQC_MOQT_VERSION_DRAFT_22);
        xqc_moqt_callbacks_t callbacks = {
            .on_setup = moqt_setup,
            .on_ready = moqt_ready,
            .on_authorize = moqt_authorize,
            .on_message = moqt_message,
            .on_request_closed = moqt_request_closed,
            .on_object = moqt_object,
        };
        ep->session = xqc_moqt_session_create(conn, &config, &callbacks, ep);
        return ep->session != NULL ? XQC_OK : -XQC_EPARAM;
    }
    return XQC_OK;
}

static void
moqt_handshake(xqc_connection_t *conn, void *data, void *proto_data)
{
    moqt_endpoint_t *ep = container_of((xqc_moq_user_session_t *) data,
                                       moqt_endpoint_t, legacy);
    xqc_conn_stats_t stats = xqc_conn_get_stats(ep->base.engine,
                                                &conn->scid_set.user_scid);
    ep->handshakes++;
    if (strcmp(conn->alpn, ep->expected_alpn) != 0
        || conn->remote_settings.max_datagram_frame_size == 0
        || stats.early_data_flag != XQC_0RTT_NONE)
    {
        ep->invalid_handshakes++;
    }
    if (ep->requests && xqc_moqt_session_start(ep->session) != XQC_OK) {
        ep->invalid_handshakes++;
    }
}

static xqc_int_t
moqt_read(xqc_stream_t *stream, void *data)
{
    moqt_endpoint_t *ep = container_of((xqc_moq_user_session_t *)
        xqc_get_conn_user_data_by_stream(stream), moqt_endpoint_t, legacy);
    uint8_t buf[XQC_MAX_PACKET_OUT_SIZE], fin = 0;
    ssize_t n;

    do {
        n = xqc_stream_recv(stream, buf, sizeof(buf), &fin);
        if (n > 0) {
            ep->control_bytes += n;
        }
    } while (n > 0 && !fin);
    if (fin || (n < 0 && n != -XQC_EAGAIN)) {
        return -XQC_EPARAM;
    }

    /* Draft-22 section 6.3 allows server-first control data. */
    if (ep->control_bytes && ep->setup_wire != NULL) {
        xqc_stream_t *control = xqc_stream_create_with_direction(
            stream->stream_conn, XQC_STREAM_UNI, NULL);
        if (control == NULL || xqc_stream_send(control,
                (uint8_t *)ep->setup_wire, ep->setup_len, ep->setup_fin)
            != (ssize_t)ep->setup_len)
        {
            return -XQC_EPARAM;
        }
        ep->setup_wire = NULL;
    }
    return XQC_OK;
}

static xqc_int_t
moqt_closed(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *data, void *proto_data)
{
    moqt_endpoint_t *ep = container_of((xqc_moq_user_session_t *) data,
                                       moqt_endpoint_t, legacy);
    ep->closed++;
    if (ep->session != NULL) {
        xqc_moqt_session_destroy(ep->session);
        ep->session = NULL;
    }
    if (ep->legacy.session != NULL) {
        xqc_moq_session_destroy(ep->legacy.session);
        ep->legacy.session = NULL;
    }
    return XQC_OK;
}

static xqc_int_t
moqt_closing(xqc_connection_t *conn, const xqc_cid_t *cid,
    xqc_int_t error, void *data)
{
    moqt_endpoint_t *ep = container_of((xqc_moq_user_session_t *) data,
                                       moqt_endpoint_t, legacy);
    ep->error = error;
    ep->application_error = XQC_CONN_ERR_IS_APPLICATION(conn->conn_err);
    return XQC_OK;
}

static xqc_int_t
moqt_engine_init(moqt_endpoint_t *ep, xqc_engine_type_t type,
    xqc_int_t legacy_only)
{
    xqc_config_t              config;
    xqc_engine_ssl_config_t   ssl = {0};
    xqc_engine_callback_t     engine_cbs;
    xqc_transport_callbacks_t transport_cbs;
    xqc_conn_callbacks_t      cbs = {
        .conn_create_notify = moqt_created,
        .conn_close_notify = moqt_closed,
        .conn_handshake_finished = moqt_handshake,
    };
    xqc_moqt_config_t         moqt = {XQC_MOQT_VERSION_DRAFT_22};
    xqc_conn_settings_t       settings = {
        .max_datagram_frame_size = XQC_MAX_PACKET_OUT_SIZE,
    };
    struct sockaddr_in        addr = {0};

    ep->base.socket.fd = -1;
    ep->base.user_data = ep;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (xqc_complex_case_make_socket(&ep->base,
        (struct sockaddr *) &addr, sizeof(addr)) != 0)
    {
        return -1;
    }
    xqc_engine_get_default_config(&config, type);
    config.cfg_log_level = XQC_LOG_ERROR;
    ssl.ciphers = XQC_TLS_CIPHERS;
    ssl.groups = XQC_TLS_GROUPS;
    if (type == XQC_ENGINE_SERVER) {
        ssl.private_key_file = "./server.key";
        ssl.cert_file = "./server.crt";
    }
    xqc_complex_case_init_engine_callbacks(&engine_cbs);
    engine_cbs.log_callbacks.xqc_log_write_err = moqt_error_log;
    xqc_complex_case_init_transport_callbacks(&transport_cbs);
    transport_cbs.server_accept = moqt_accept;
    transport_cbs.write_socket = moqt_write;
    transport_cbs.write_socket_ex = NULL;
    transport_cbs.conn_closing = moqt_closing;
    ep->base.engine = xqc_engine_create(type, &config, &ssl, &engine_cbs,
                                        &transport_cbs, ep);
    if (ep->base.engine == NULL) {
        return -1;
    }
    if (type == XQC_ENGINE_SERVER) {
        xqc_server_set_conn_settings(ep->base.engine, &settings);
    }
    /* The old-only peer checks the compatibility boundary absent in demos. */
    if (type == XQC_ENGINE_SERVER || legacy_only) {
        xqc_moq_init_alpn(ep->base.engine, &cbs,
                          XQC_MOQ_TRANSPORT_QUIC);
    }
    return legacy_only ? XQC_OK
        : xqc_moqt_init_alpn(ep->base.engine, &moqt, &cbs);
}

static xqc_int_t
moqt_negotiate(xqc_int_t reject, xqc_int_t port, const uint8_t *wire,
    size_t len, uint8_t fin, uint64_t expected_error)
{
    moqt_endpoint_t       client = {.base.socket.fd = -1};
    moqt_endpoint_t       server = {.base.socket.fd = -1};
    xqc_complex_case_engine_t *peers[] = {&client.base, &server.base};
    xqc_moqt_config_t     config = {XQC_MOQT_VERSION_DRAFT_22};
    xqc_conn_settings_t   settings = {.proto_version = XQC_VERSION_V1,
        .max_datagram_frame_size = XQC_MAX_PACKET_OUT_SIZE};
    xqc_conn_ssl_config_t ssl = {0};
    const xqc_cid_t       *cid;
    const char           *alpn = wire ? XQC_MOQT_ALPN_DRAFT_22
        : port ? "unsupported"
        : (reject ? XQC_MOQT_ALPN_DRAFT_22 : XQC_ALPN_MOQ_QUIC);
    xqc_int_t             result = -1;

    client.expected_alpn = server.expected_alpn = alpn;
    client.setup_wire = wire;
    client.setup_len = len;
    client.setup_fin = fin;
    xqc_moqt_check(moqt_engine_init(&client, XQC_ENGINE_CLIENT, !reject)
        == XQC_OK);
    if (port != 0) {
        struct sockaddr_in *addr = (struct sockaddr_in *) &server.base.local;
        xqc_conn_callbacks_t cbs = {
            .conn_create_notify = moqt_created,
            .conn_close_notify = moqt_closed,
            .conn_handshake_finished = moqt_handshake,
        };
        xqc_app_proto_callbacks_t protocol;
        xqc_memzero(&protocol, sizeof(protocol));
        protocol.conn_cbs = cbs;
        protocol.stream_cbs.stream_read_notify = moqt_read;
        xqc_moqt_check(xqc_engine_register_alpn(
            client.base.engine, alpn,
            strlen(alpn), &protocol, NULL) == XQC_OK);
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr->sin_port = htons(port);
        server.base.locallen = sizeof(*addr);
    } else {
        xqc_moqt_check(moqt_engine_init(&server, XQC_ENGINE_SERVER,
                                        1) == XQC_OK);
    }
    if (reject && port == 0) {
        cid = xqc_moqt_connect(client.base.engine, &config, &settings,
                               NULL, 0, "localhost", &ssl,
            (struct sockaddr *) &server.base.local, server.base.locallen,
                               &client.legacy);
    } else {
        cid = xqc_connect(
            client.base.engine, &settings, NULL, 0,
            "localhost", 0, &ssl, (struct sockaddr *) &server.base.local,
            server.base.locallen, alpn, &client.legacy);
    }
    xqc_moqt_check(cid != NULL);
    client.base.cid = *cid;
    for (xqc_int_t waited = 0; waited < XQC_MOQT_HANDSHAKE_WAIT_MS;
         waited += XQC_MOQT_PUMP_STEP_MS)
    {
        xqc_complex_case_pump(peers, sizeof(peers) / sizeof(peers[0]),
                              XQC_MOQT_PUMP_STEP_MS);
        if ((client.handshakes
                && server.handshakes
                && (strcmp(alpn, XQC_ALPN_MOQ_QUIC) != 0
                    || (client.setup
                        && server.setup)))
            || (client.error
                && (port != 0
                    || server.error)))
        {
            break;
        }
    }
    /* RFC 7301 section 3.2: disjoint candidates cannot select a protocol. */
    if (wire != NULL) {
        xqc_moqt_check(client.handshakes == 1);
        xqc_moqt_check(client.invalid_handshakes == 0);
        xqc_moqt_check(client.control_bytes > 0 && client.setup_wire == NULL);
        xqc_moqt_check(client.application_error);
        xqc_moqt_check(client.error == expected_error);

    } else if (reject) {
        xqc_moqt_check(client.handshakes == 0 && server.handshakes == 0);
        xqc_moqt_check(server.created == 0);
        xqc_moqt_check(client.setup == 0);
        xqc_moqt_check(port != 0
                       || server.error == TRA_NO_APPLICATION_PROTOCOL);
        xqc_moqt_check(client.error == TRA_NO_APPLICATION_PROTOCOL);

    } else {
        xqc_moqt_check(client.handshakes == 1 && server.handshakes == 1);
        xqc_moqt_check(client.invalid_handshakes == 0
            && server.invalid_handshakes == 0);
        xqc_moqt_check(client.created == 1 && server.created == 1);
        xqc_moqt_check(client.error == 0 && server.error == 0);
        xqc_moqt_check(client.setup == 1 && server.setup == 1);
        xqc_moqt_check(client.legacy.session->version == XQC_MOQ_VERSION_5
            && server.legacy.session->version == XQC_MOQ_VERSION_5);
        xqc_moqt_check(client.legacy.session->session_setup_done
            && server.legacy.session->session_setup_done);
    }
    printf("ALPN client=%s server=%s selected=%s setup=%u/%u\n",
           alpn, port != 0 ? "demo" : "05",
           reject ? "none" : alpn, client.setup, server.setup);
    result = 0;

done:
    if (result != 0) {
        fprintf(stderr, "%s handshake client=%u server=%u, errors=%d/%d\n",
                alpn, client.handshakes, server.handshakes,
                client.error, server.error);
    }
    xqc_complex_case_engine_release(&client.base);
    xqc_complex_case_engine_release(&server.base);
    if (!reject && result == 0 && (client.closed != 1 || server.closed != 1)) {
        result = -1;
    }
    return result;
}

static xqc_int_t
moqt_subscriptions(moqt_endpoint_t *client, moqt_endpoint_t *server,
    xqc_int_t errors)
{
    xqc_complex_case_engine_t *peers[] = {&client->base, &server->base};
    xqc_moqt_request_t *first = NULL, *peer_first = NULL;
    xqc_moqt_track_t *track = NULL;
    xqc_moqt_message_t m;
    xqc_int_t result = -1;
    /* Section 9.20.9: every filter crosses actual QUIC streams. */
    const uint8_t filters[][5] = {
        {0}, {1, 2}, {2, 3, 4}, {3, 3, 4, 2}, {4, 3, 4, 2, 9}, {5}
    };
    const size_t lengths[] = {1, 2, 3, 4, 5, 1};
    const xqc_moqt_location_t starts[] = {
        {0, 0}, {4, 0}, {3, 4}, {3, 4}, {3, 4}, {5, 7}
    };
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        xqc_memzero(&m, sizeof(m));
        m.type = XQC_MOQT_MSG_SUBSCRIBE;
        m.track_name = (struct iovec){"camera", 6};
        m.parameter_count = 1;
        m.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_LOCATION_FILTER, lengths[i], (uint8_t *)filters[i]};
        xqc_moqt_request_t *r = xqc_moqt_request_open(client->session, &m);
        xqc_moqt_check(r != NULL);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_subscription_t *sub = xqc_moqt_request_subscription(r);
        xqc_moqt_subscription_t *peer =
            xqc_moqt_request_subscription(server->request);
        xqc_moqt_check(sub != NULL && peer != NULL);
        xqc_moqt_check(sub->established && peer->established);
        xqc_moqt_check(sub->track_alias == i && peer->track_alias == i);
        xqc_moqt_check(sub->start.group_id == starts[i].group_id
                       && sub->start.object_id == starts[i].object_id);
        xqc_moqt_check(sub->start.group_id == peer->start.group_id
                       && sub->start.object_id == peer->start.object_id);
        xqc_moqt_check(sub->group_order == XQC_MOQT_GROUP_DESCENDING);
        xqc_moqt_check(sub->track->publisher_priority == 7);
        xqc_moqt_check(sub->start_exclusive == (i == 5));
        if (first == NULL) {
            first = r;
            peer_first = server->request;
            track = sub->track;
        }
        xqc_moqt_check(sub->track == track);
    }
    xqc_moqt_check(client->responses == 6 && server->messages == 6);
    /* Independent subscription state and FIFO pause/resume. */
    uint8_t forward = 0;
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
    m.parameter_count = 1;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FORWARD, sizeof(forward), &forward};
    for (forward = 0; forward <= 1; forward++) {
        xqc_moqt_check(xqc_moqt_request_send(first, &m) == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(first->subscription->forward == forward);
        xqc_moqt_check(peer_first->subscription->forward == forward);
        xqc_moqt_check(client->session->subscriptions->forward);
    }
    /* Both directions with the same name have separate Track identities. */
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_PUBLISH;
    m.track_name = (struct iovec){"camera", 6};
    xqc_moqt_request_t *published = xqc_moqt_request_open(client->session, &m);
    xqc_moqt_check(published != NULL);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_check(published->subscription->established);
    xqc_moqt_check(published->subscription->track != track);
    xqc_moqt_check(published->subscription->track_alias == 0);
    if (errors) {
        /* Section 3.1.3: reuse an active alias for another Track. */
        xqc_connection_t *conn = xqc_engine_conns_hash_find(
            client->base.engine, &client->base.cid, 's');
        xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
                                                                XQC_STREAM_BIDI,
                                                                NULL);
        uint8_t wire[XQC_MAX_PACKET_OUT_SIZE];
        m.request_id = client->session->next_request_id;
        m.track_name = (struct iovec){"other", 5};
        m.track_alias = published->subscription->track_alias;
        xqc_int_t n = xqc_moqt_message_encode(&m, m.type, wire, sizeof(wire));
        xqc_moqt_check(stream != NULL && n > 0);
        xqc_moqt_check(xqc_stream_send(stream, wire, n, 0) == n);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->application_error && server->application_error);
        xqc_moqt_check(client->error == XQC_MOQT_DUPLICATE_TRACK_ALIAS
                       && server->error == XQC_MOQT_DUPLICATE_TRACK_ALIAS);
    } else {
        xqc_moqt_check(client->error == 0 && server->error == 0);
    }
    xqc_moqt_check(client->invalid_handshakes == 0
                   && server->invalid_handshakes == 0);
    printf("subscriptions filters=6 updates=%u errors=%d/%d\n",
           server->updates, client->error, server->error);
    result = 0;
done:
    return result;
}

static xqc_int_t
moqt_datagrams(moqt_endpoint_t *client, moqt_endpoint_t *server,
    xqc_int_t errors)
{
    xqc_complex_case_engine_t *peers[] = {&client->base, &server->base};
    xqc_moqt_request_t *requests[3], *senders[3];
    xqc_moqt_message_t m;
    xqc_int_t result = -1;
    for (size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); i++) {
        xqc_memzero(&m, sizeof(m));
        m.type = XQC_MOQT_MSG_SUBSCRIBE;
        m.track_name = (struct iovec){i < 2 ? "video" : "audio", 5};
        requests[i] = xqc_moqt_request_open(client->session, &m);
        xqc_moqt_check(requests[i] != NULL);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        senders[i] = server->request;
        xqc_moqt_check(requests[i]->subscription->established);
        xqc_moqt_check(senders[i]->subscription->established);
    }
    xqc_moqt_object_t o = {.group_id = 6, .datagram = 1, .priority = 7,
        .payload = {"x", 1}, .payload_length = 1};
    xqc_moqt_check(xqc_moqt_datagram_send(senders[0]->subscription, &o)
                   == XQC_OK);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_check(client->objects == 1);
    uint8_t wire[XQC_MAX_PACKET_OUT_SIZE];
    if (errors) {
        /* Sections 3.7/10.7/12.1: malformed Track, other Track still usable. */
        uint8_t nested[] = {0x0b, 2, 0x0b, 0};
        o.properties = (struct iovec){nested, sizeof(nested)};
        xqc_moqt_check(xqc_moqt_datagram_send(senders[0]->subscription, &o)
                       == -XQC_EPARAM);
        xqc_int_t n = xqc_moqt_datagram_encode(
            senders[0]->subscription->track_alias, &o, wire, sizeof(wire));
        xqc_moqt_check(n > 0);
        xqc_moqt_check(xqc_datagram_send(server->session->conn, wire, n,
                                         NULL, XQC_DATA_QOS_NORMAL) == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->request_closed == 2
                       && server->request_closed == 2);
        xqc_moqt_check(client->objects == 1);
        o.properties.iov_len = 0;
        xqc_moqt_check(xqc_moqt_datagram_send(senders[2]->subscription, &o)
                       == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->objects == 2);
        xqc_moqt_check(client->error == 0 && server->error == 0);
        /* Unknown flags are session-fatal, independently of Track alias. */
        wire[0] = 0x10;
        xqc_moqt_check(xqc_datagram_send(server->session->conn, wire, 1,
                                         NULL, XQC_DATA_QOS_NORMAL) == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->application_error && server->application_error);
        xqc_moqt_check(client->error == XQC_MOQT_PROTOCOL_VIOLATION
                       && server->error == XQC_MOQT_PROTOCOL_VIOLATION);
    } else {
        /* Independent byte vectors exercise every legal flags combination. */
        for (uint8_t flags = 0; flags <= 0x2f; flags++) {
            if ((flags & 0x10) || ((flags & 0x20) && (flags & 2))) {
                continue;
            }
            size_t n = 0;
            wire[n++] = 0x80;
            wire[n++] = flags;
            wire[n++] = senders[0]->subscription->track_alias;
            wire[n++] = 10 + flags;
            if (!(flags & 4)) {
                wire[n++] = 3;
            }
            if (!(flags & 8)) {
                wire[n++] = 9;
            }
            if (flags & 1) {
                wire[n++] = 2;
                wire[n++] = 0x78;
                wire[n++] = 9;
            }
            wire[n++] = flags & 0x20 ? 0 : 'x';
            unsigned received = client->objects;
            xqc_moqt_check(xqc_datagram_send(
                server->session->conn, wire, n,
                NULL, XQC_DATA_QOS_NORMAL) == XQC_OK);
            xqc_complex_case_pump(peers, 2, XQC_MOQT_PUMP_STEP_MS);
            xqc_moqt_check(client->objects == received + 1);
            xqc_moqt_check(client->object.priority == (flags & 8 ? 7 : 9));
            xqc_moqt_check(client->object.object_id == (flags & 4 ? 0 : 3));
            xqc_moqt_check(client->object.properties.iov_len
                           == (flags & 1 ? 2 : 0));
            xqc_moqt_check(client->object.payload.iov_len
                           == (flags & 0x20 ? 0 : 1));
            xqc_moqt_check(client->object.end_of_group == !!(flags & 2));
        }
        /* Real REQUEST_UPDATE controls the publisher's Datagram eligibility. */
        uint8_t forward = 0;
        xqc_memzero(&m, sizeof(m));
        m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
        m.parameter_count = 1;
        m.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_FORWARD, sizeof(forward), &forward};
        for (forward = 0; forward <= 1; forward++) {
            xqc_moqt_check(xqc_moqt_request_send(requests[0], &m) == XQC_OK);
            xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
            xqc_moqt_check(xqc_moqt_datagram_send(senders[0]->subscription, &o)
                           == (forward ? XQC_OK : -XQC_EPARAM));
        }
        /* Termination markers do not advance Largest Object. */
        o.payload.iov_len = o.payload_length = 0;
        o.group_id = 100;
        o.status = XQC_MOQT_OBJECT_END_GROUP;
        xqc_moqt_check(xqc_moqt_datagram_send(senders[0]->subscription, &o)
                       == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->object.status == XQC_MOQT_OBJECT_END_GROUP);
        o.status = XQC_MOQT_OBJECT_END_TRACK;
        xqc_moqt_check(xqc_moqt_datagram_send(senders[0]->subscription, &o)
                       == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->object.status == XQC_MOQT_OBJECT_END_TRACK);
        xqc_moqt_check(
            requests[0]->subscription->track->largest.group_id < 100);
        /* The opposite publisher direction is independent and uses PUBLISH. */
        xqc_memzero(&m, sizeof(m));
        m.type = XQC_MOQT_MSG_PUBLISH;
        m.track_name = (struct iovec){"video", 5};
        xqc_moqt_request_t *reverse = xqc_moqt_request_open(client->session,
                                                            &m);
        xqc_moqt_check(reverse != NULL);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        o.status = XQC_MOQT_OBJECT_NORMAL;
        xqc_moqt_check(xqc_moqt_datagram_send(reverse->subscription, &o)
                       == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(server->objects == 1
                       && server->object.payload_length == 0);
        xqc_moqt_check(client->error == 0 && server->error == 0);
    }
    xqc_moqt_check(client->invalid_handshakes == 0
                   && server->invalid_handshakes == 0);
    printf("datagrams objects=%u/%u closed=%u/%u errors=%d/%d\n",
           client->objects, server->objects, client->request_closed,
           server->request_closed, client->error, server->error);
    result = 0;
done:
    return result;
}

static xqc_int_t
moqt_subgroups(moqt_endpoint_t *client, moqt_endpoint_t *server,
    xqc_int_t errors)
{
    xqc_complex_case_engine_t *peers[] = {&client->base, &server->base};
    moqt_endpoint_t *endpoints[] = {client, server};
    xqc_moqt_request_t *senders[2];
    xqc_int_t result = -1;
    for (size_t i = 0; i < 2; i++) {
        moqt_endpoint_t *receiver = endpoints[i], *sender = endpoints[1 - i];
        receiver->session->callbacks.on_object = moqt_subgroup_object;
        receiver->session->callbacks.on_stream_closed = moqt_data_closed;
        xqc_moqt_message_t m = {0};
        m.type = XQC_MOQT_MSG_SUBSCRIBE;
        m.track_name = (struct iovec){"video", 5};
        xqc_moqt_request_t *r = xqc_moqt_request_open(receiver->session, &m);
        xqc_moqt_check(r != NULL);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        senders[i] = sender->request;
        xqc_moqt_check(r->subscription->established);
        xqc_moqt_check(senders[i]->subscription->established);
    }
    if (errors) {
        /* Section 11.3.2: wire FIN with two missing payload bytes. */
        size_t direction = errors - 1;
        xqc_moqt_subscription_t *sub = senders[direction]->subscription;
        xqc_moqt_stream_t *st = xqc_moqt_subgroup_open(sub, 6, 3, 7, 1, 0);
        xqc_moqt_check(st != NULL);
        uint8_t wire[64];
        xqc_moqt_object_t o = {.group_id = 6, .subgroup_id = 3, .priority = 7};
        xqc_int_t n = xqc_moqt_subgroup_header_encode(
            sub->track_alias,
            0x14, &o, wire, sizeof(wire));
        wire[n++] = 0;
        wire[n++] = 2;
        xqc_moqt_check(xqc_stream_send(st->transport_stream, wire, n, 1) == n);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->application_error && server->application_error);
        xqc_moqt_check(client->error == XQC_MOQT_PROTOCOL_VIOLATION
                       && server->error == XQC_MOQT_PROTOCOL_VIOLATION);
    } else {
        uint8_t payload[XQC_MOQT_TEST_FRAGMENT_SIZE];
        const uint8_t properties[] = {0x78, 9};
        xqc_memset(payload, 'x', sizeof(payload));
        for (size_t i = 0; i < 2; i++) {
            xqc_moqt_stream_t *st = xqc_moqt_subgroup_open(
                senders[i]->subscription, 6, 3, 7, 1, 1);
            xqc_moqt_check(st != NULL);
            xqc_moqt_object_t o = {.group_id = 6, .subgroup_id = 3,
                .priority = 7, .first_in_subgroup = 1,
                .payload_length = XQC_MOQT_TEST_OBJECT_SIZE,
                .properties = {(void *)properties, sizeof(properties)},
                .payload = {payload, sizeof(payload)}};
            unsigned waits = 0;
            while (o.payload_offset < o.payload_length) {
                xqc_int_t ret = xqc_moqt_stream_send_object(st, &o);
                if (ret == -XQC_EAGAIN) {
                    xqc_moqt_check(waits++ < XQC_MOQT_HANDSHAKE_WAIT_MS
                                            / XQC_MOQT_PUMP_STEP_MS);
                    xqc_complex_case_pump(peers, 2, XQC_MOQT_PUMP_STEP_MS);
                    continue;
                }
                xqc_moqt_check(ret == XQC_OK);
                o.payload_offset += o.payload.iov_len;
                o.properties.iov_len = 0;
                o.properties.iov_base = NULL;
            }
            o.object_id = 1;
            o.first_in_subgroup = 0;
            o.payload_offset = o.payload_length = o.payload.iov_len = 0;
            o.payload.iov_base = NULL;
            xqc_moqt_check(xqc_moqt_stream_send_object(st, &o) == XQC_OK);
            xqc_moqt_check(xqc_moqt_stream_finish(st) == XQC_OK);
            xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
            xqc_moqt_check(endpoints[i]->payload_bytes
                           == XQC_MOQT_TEST_OBJECT_SIZE);
            xqc_moqt_check(endpoints[i]->empty_objects == 1);
            xqc_moqt_check(endpoints[i]->group_ends == 1);
            st = xqc_moqt_subgroup_open(senders[i]->subscription,
                                        7, 3, 7, 1, 0);
            xqc_moqt_check(st != NULL);
            o.group_id = 7;
            o.object_id = 0;
            o.first_in_subgroup = 1;
            o.status = XQC_MOQT_OBJECT_END_TRACK;
            xqc_moqt_check(xqc_moqt_stream_send_object(st, &o) == XQC_OK);
            xqc_moqt_check(xqc_moqt_stream_finish(st) == XQC_OK);
            xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
            xqc_moqt_check(endpoints[i]->status_objects == 1);
        }
        xqc_moqt_check(client->data_closed == 4 && server->data_closed == 4);
        xqc_moqt_check(client->error == 0 && server->error == 0);
    }
    xqc_moqt_check(client->invalid_handshakes == 0
                   && server->invalid_handshakes == 0);
    printf("subgroups bytes=%zu/%zu close=%u/%u errors=%d/%d\n",
           client->payload_bytes, server->payload_bytes,
           client->data_closed, server->data_closed,
           client->error, server->error);
    result = 0;
done:
    return result;
}

/* Defer data reads, while native QUIC continues acknowledging request FIN. */
static xqc_int_t
moqt_delivery_read(xqc_stream_t *transport, void *data)
{
    xqc_moqt_stream_t *st = data;
    moqt_endpoint_t *ep = st->session->user_data;
    if (ep->defer_data
        && st != st->session->control_rx
        && xqc_stream_get_direction(transport) == XQC_STREAM_UNI)
    {
        return XQC_OK;
    }
    return xqc_moqt_stream_callbacks.stream_read_notify(transport, data);
}

static void
moqt_delivery_object(xqc_moqt_subscription_t *sub, xqc_moqt_stream_t *st,
    const xqc_moqt_object_t *o, void *data)
{
    moqt_endpoint_t *ep = data;
    ep->objects++;
    if (st == NULL || sub->request != NULL || o->payload.iov_len != 1) {
        ep->invalid_handshakes++;
    } else if (*(char *)o->payload.iov_base != 'x') {
        ep->invalid_handshakes++;
    }
}

static void
moqt_delivery_closed(xqc_moqt_subscription_t *sub,
    const xqc_moqt_error_t *error, void *data)
{
    moqt_endpoint_t *ep = data;
    ep->subscription_closed++;
    ep->last_error = error->code;
}

static xqc_int_t
moqt_delivery(moqt_endpoint_t *client, moqt_endpoint_t *server,
    xqc_int_t scenario)
{
    xqc_complex_case_engine_t *peers[] = {&client->base, &server->base};
    xqc_moqt_stream_t *held = NULL;
    xqc_int_t result = -1;
    xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_SUBSCRIBE,
        .track_name = {"video", 5}};
    uint8_t timeout[16];
    xqc_int_t n = xqc_vi64_write(timeout, timeout + sizeof(timeout),
                                  XQC_MOQT_TEST_DELIVERY_MS);
    m.parameter_count = 1;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_SUBGROUP_DELIVERY_TIMEOUT, n, timeout};
    xqc_moqt_request_t *r = xqc_moqt_request_open(client->session, &m);
    xqc_moqt_check(r != NULL);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_subscription_t *sub = r->subscription;
    xqc_moqt_request_t *publisher = server->request;
    xqc_moqt_check(sub != NULL && publisher != NULL);
    client->session->callbacks.on_subscription_closed = moqt_delivery_closed;
    client->session->callbacks.on_object = moqt_delivery_object;
    client->session->conn->app_proto_cbs.stream_cbs.stream_read_notify =
        moqt_delivery_read;
    client->defer_data = 1;
    xqc_moqt_stream_t *st = xqc_moqt_subgroup_open(
        publisher->subscription, 6, 0, 7, 0, 0);
    xqc_moqt_check(st != NULL);
    xqc_moqt_object_t o = {.group_id = 6, .priority = 7,
        .payload = {"x", 1}, .payload_length = 1};
    if (scenario == 2) {
        /* Drop real UDP ACKs; retain the stream for post-timer checks. */
        client->session->callbacks.on_object = NULL;
        held = xqc_moqt_streams_hold(server->session);
        client->drop_packets = 1;
    }
    xqc_moqt_check(xqc_moqt_stream_send_object(st, &o) == XQC_OK);
    xqc_moqt_check(xqc_moqt_stream_finish(st) == XQC_OK);
    xqc_moqt_check(st->tx_fin_sent);
    if (scenario == 2) {
        xqc_complex_case_pump(peers, 2, XQC_MOQT_TEST_DELIVERY_MS * 4);
        xqc_moqt_check(client->dropped_packets > 0);
        xqc_moqt_check(st->discarded);
        xqc_moqt_check(st->state.data.error == XQC_MOQT_RESET_DELIVERY_TIMEOUT);
        client->drop_packets = 0;
        client->defer_data = 0;
        xqc_moqt_streams_release(held);
        held = NULL;
    } else {
        m = (xqc_moqt_message_t){.type = XQC_MOQT_MSG_PUBLISH_DONE,
            .stream_count = UINT64_MAX,
            .error = {.code = XQC_MOQT_PUBLISH_TRACK_ENDED}};
        xqc_moqt_check(xqc_moqt_request_send(publisher, &m) == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->request_closed == 1);
        xqc_moqt_check(server->session->subscriptions == NULL);
        xqc_moqt_check(sub->request == NULL && sub->expected_streams == 1);
        xqc_moqt_check(client->objects == 0
                       && client->subscription_closed == 0);
        if (scenario == 1) {
            xqc_moqt_subscription_cancel(sub, XQC_MOQT_RESET_CANCELLED);
        }
        client->defer_data = 0;
        /* Resume the deferred native receive notification. */
        xqc_moqt_stream_t *pending = xqc_moqt_streams_hold(client->session);
        for (xqc_moqt_stream_t *data = pending; data != NULL;
             data = data->next)
        {
            if (data->kind == XQC_MOQT_STREAM_UNCLASSIFIED
                && data->transport_stream != NULL)
            {
                moqt_delivery_read(data->transport_stream, data);
            }
        }
        xqc_moqt_streams_release(pending);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->objects == (scenario == 0));
        xqc_moqt_check(client->subscription_closed == 1);
        xqc_moqt_check(client->last_error == (scenario == 0
            ? XQC_MOQT_PUBLISH_TRACK_ENDED : XQC_MOQT_RESET_CANCELLED));
    }
    /* An independent request still operates after completion/cancellation. */
    m = (xqc_moqt_message_t){.type = XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE};
    r = xqc_moqt_request_open(client->session, &m);
    xqc_moqt_check(r != NULL);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_check(r->established && client->responses == 2);
    xqc_moqt_check(!client->session->closed && !server->session->closed);
    xqc_moqt_check(client->invalid_handshakes == 0
                   && server->invalid_handshakes == 0);
    printf("delivery scenario=%d objects=%u final=%u dropped=%u\n", scenario,
           client->objects, client->subscription_closed,
           client->dropped_packets);
    result = 0;
done:
    if (held != NULL) {
        xqc_moqt_streams_release(held);
    }
    return result;
}

static xqc_int_t
moqt_fetch_read(xqc_stream_t *transport, void *data)
{
    xqc_moqt_stream_t *st = data;
    moqt_endpoint_t *ep = st->session->user_data;
    if (ep->defer_response && st->kind == XQC_MOQT_STREAM_REQUEST) {
        return XQC_OK;
    }
    return xqc_moqt_stream_callbacks.stream_read_notify(transport, data);
}

static void
moqt_fetch_object(xqc_moqt_subscription_t *sub, xqc_moqt_stream_t *st,
    const xqc_moqt_object_t *o, void *data)
{
    moqt_endpoint_t *ep = data;
    if (sub != NULL || xqc_moqt_stream_fetch(st) == NULL) {
        ep->invalid_handshakes++;
    }
    if (o->range) {
        ep->ranges |= 1u << o->range;
        if (o->payload_length || o->properties.iov_len) {
            ep->invalid_handshakes++;
        }
        return;
    }
    ep->objects++;
    ep->empty_objects += o->payload_length == 0;
    ep->datagram_objects += o->datagram;
    if (o->payload_length) {
        const uint8_t properties[] = {0x78, 9};
        if (o->payload_offset != ep->payload_bytes
            || o->properties.iov_len != sizeof(properties)
            || xqc_memcmp(o->properties.iov_base, properties,
                           sizeof(properties)))
        {
            ep->invalid_handshakes++;
        }
        for (size_t i = 0; i < o->payload.iov_len; i++) {
            if (((uint8_t *)o->payload.iov_base)[i] != 'x') {
                ep->invalid_handshakes++;
                break;
            }
        }
        ep->payload_bytes += o->payload.iov_len;
    }
}

static void
moqt_fetch_closed(xqc_moqt_fetch_t *fetch, const xqc_moqt_error_t *error,
    void *data)
{
    moqt_endpoint_t *ep = data;
    ep->fetch_closed++;
    ep->last_error = error == NULL ? XQC_MOQT_NO_ERROR : error->code;
}

static xqc_int_t
moqt_fetch(moqt_endpoint_t *client, moqt_endpoint_t *server, xqc_int_t errors)
{
    xqc_complex_case_engine_t *peers[] = {&client->base, &server->base};
    xqc_int_t result = -1;
    client->session->callbacks.on_object = moqt_fetch_object;
    client->session->callbacks.on_fetch_closed = moqt_fetch_closed;
    client->session->conn->app_proto_cbs.stream_cbs.stream_read_notify =
        moqt_fetch_read;
    if (errors) {
        /* Establish an independent request before the session-fatal probe. */
        xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE};
        xqc_moqt_request_t *r = xqc_moqt_request_open(client->session, &m);
        xqc_moqt_check(r != NULL);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(r->established && server->request != NULL);
        xqc_moqt_check(xqc_moqt_request_finish(r) == XQC_OK);
        xqc_moqt_check(xqc_moqt_request_finish(server->request) == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->request_closed == 1);
    }
    for (uint8_t order = XQC_MOQT_GROUP_ASCENDING;
         order <= XQC_MOQT_GROUP_DESCENDING; order++)
    {
        client->defer_response = order == XQC_MOQT_GROUP_DESCENDING;
        xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_FETCH,
            .track_name = {"video", 5}, .parameter_count = 1};
        m.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_GROUP_ORDER, 1, &order};
        xqc_moqt_request_t *r = xqc_moqt_request_open(client->session, &m);
        xqc_moqt_check(r != NULL);
        xqc_moqt_fetch_t *fetch = xqc_moqt_request_fetch(r);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(server->request != NULL);
        xqc_moqt_stream_t *st = xqc_moqt_fetch_open(
            xqc_moqt_request_fetch(server->request));
        xqc_moqt_check(st != NULL);
        if (errors) {
            /* Section 11.4: a first Object cannot inherit G/O or priority. */
            uint8_t invalid[2 * XQC_VI64_MAX_LEN + 2];
            uint8_t *end = invalid + sizeof(invalid);
            xqc_int_t len = xqc_vi64_write(invalid, end, XQC_MOQT_FETCH_STREAM);
            len += xqc_vi64_write(invalid + len, end,
                                  xqc_moqt_fetch_info(fetch)->request_id);
            invalid[len++] = 0; /* Missing first Group/Object and Priority. */
            invalid[len++] = 0;
            xqc_moqt_check(xqc_stream_send(st->transport_stream, invalid,
                                          len, 1) == len);
            xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
            xqc_moqt_check(client->error == XQC_MOQT_PROTOCOL_VIOLATION);
            xqc_moqt_check(server->error == XQC_MOQT_PROTOCOL_VIOLATION);
            xqc_moqt_check(client->application_error
                           && server->application_error);
            result = 0;
            goto done;
        }
        xqc_moqt_object_t o = {.group_id = order == XQC_MOQT_GROUP_ASCENDING
            ? 1 : 3, .priority = 7};
        uint8_t payload[XQC_MOQT_TEST_FRAGMENT_SIZE];
        xqc_memset(payload, 'x', sizeof(payload));
        uint8_t properties[] = {0x78, 9};
        if (!client->defer_response) {
            o.payload_length = XQC_MOQT_TEST_OBJECT_SIZE;
            o.properties = (struct iovec){properties, sizeof(properties)};
            while (o.payload_offset < o.payload_length) {
                o.payload = (struct iovec){payload, sizeof(payload)};
                xqc_int_t ret = xqc_moqt_stream_send_object(st, &o);
                xqc_moqt_check(ret == XQC_OK || ret == -XQC_EAGAIN);
                if (ret == XQC_OK) {
                    o.payload_offset += sizeof(payload);
                    o.properties = (struct iovec){NULL, 0};
                }
                xqc_complex_case_pump(peers, 2, XQC_MOQT_PUMP_STEP_MS);
            }
            o.object_id++;
        }
        o.payload_length = o.payload_offset = 0;
        o.payload = (struct iovec){NULL, 0};
        o.properties = (struct iovec){NULL, 0};
        o.subgroup_id = 1;
        xqc_moqt_check(xqc_moqt_stream_send_object(st, &o) == XQC_OK);
        o.object_id++;
        o.datagram = 1;
        xqc_moqt_check(xqc_moqt_stream_send_object(st, &o) == XQC_OK);
        for (unsigned range = XQC_MOQT_RANGE_NONEXISTENT;
             range <= XQC_MOQT_RANGE_TIMEOUT; range++)
        {
            o.object_id++;
            o.range = range;
            xqc_moqt_check(xqc_moqt_stream_send_object(st, &o) == XQC_OK);
        }
        o.range = XQC_MOQT_RANGE_NONE;
        o.datagram = 0;
        o.subgroup_id = 2;
        o.group_id = 2;
        o.object_id = 0;
        xqc_moqt_check(xqc_moqt_stream_send_object(st, &o) == XQC_OK);
        o.group_id = order == XQC_MOQT_GROUP_ASCENDING ? 3 : 1;
        xqc_moqt_check(xqc_moqt_stream_send_object(st, &o) == XQC_OK);
        xqc_moqt_check(xqc_moqt_stream_finish(st) == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        if (client->defer_response) {
            xqc_moqt_check(fetch->stream != NULL);
            xqc_moqt_check(fetch->stream->transport_stream == NULL);
            xqc_moqt_check(client->fetch_closed == 1);
            client->defer_response = 0;
            xqc_moqt_check(moqt_fetch_read(r->stream->transport_stream,
                                          r->stream) == XQC_OK);
        }
        xqc_moqt_check(xqc_moqt_request_finish(server->request) == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->fetch_closed == order);
        xqc_moqt_check(client->request_closed == order);
        xqc_moqt_check(client->last_error == XQC_MOQT_NO_ERROR);
    }
    /* A known non-existent valid range is represented by an empty stream. */
    xqc_moqt_message_t empty = {.type = XQC_MOQT_MSG_FETCH,
        .track_name = {"empty", 5}};
    xqc_moqt_check(xqc_moqt_request_open(client->session, &empty) != NULL);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_stream_t *empty_stream = xqc_moqt_fetch_open(
        xqc_moqt_request_fetch(server->request));
    xqc_moqt_check(empty_stream != NULL);
    xqc_moqt_check(xqc_moqt_stream_finish(empty_stream) == XQC_OK);
    xqc_moqt_check(xqc_moqt_request_finish(server->request) == XQC_OK);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_check(client->fetch_closed == 3 && client->request_closed == 3);
    xqc_moqt_check(client->payload_bytes == XQC_MOQT_TEST_OBJECT_SIZE);
    xqc_moqt_check(client->empty_objects == 8);
    xqc_moqt_check(client->datagram_objects == 2);
    xqc_moqt_check(client->ranges == ((1u << XQC_MOQT_RANGE_NONEXISTENT)
        | (1u << XQC_MOQT_RANGE_UNKNOWN) | (1u << XQC_MOQT_RANGE_TIMEOUT)));
    xqc_moqt_check(client->invalid_handshakes == 0
                   && server->invalid_handshakes == 0);
    xqc_moqt_check(!client->session->closed && !server->session->closed);
    printf("fetch objects=%u bytes=%zu empty=%u ranges=%u final=%u\n",
           client->objects, client->payload_bytes, client->empty_objects,
           client->ranges, client->fetch_closed);
    result = 0;
done:
    return result;
}

static void
moqt_fill_ready(xqc_moqt_fetch_t *fetch, xqc_moqt_subscription_t *sub,
    void *data)
{
    moqt_endpoint_t *ep = data;
    ep->fill_ready++;
    ep->fill = fetch;
    if (sub == NULL || xqc_moqt_fetch_info(fetch) == NULL) {
        ep->invalid_handshakes++;
    }
}

static void
moqt_fill_object(xqc_moqt_subscription_t *sub, xqc_moqt_stream_t *st,
    const xqc_moqt_object_t *o, void *data)
{
    moqt_endpoint_t *ep = data;
    xqc_moqt_fetch_t *fill = xqc_moqt_stream_fetch(st);
    if (sub == NULL || o->payload_length != 1 || o->payload.iov_len != 1) {
        ep->invalid_handshakes++;
        return;
    }
    if (*(uint8_t *)o->payload.iov_base != (fill != NULL ? 'f' : 'l')) {
        ep->invalid_handshakes++;
    }
    ep->fill_objects += fill != NULL;
    ep->objects += fill == NULL;
}

static xqc_int_t
moqt_fill(moqt_endpoint_t *client, moqt_endpoint_t *server, xqc_int_t errors)
{
    xqc_complex_case_engine_t *peers[] = {&client->base, &server->base};
    xqc_int_t result = -1;
    client->session->callbacks.on_fetch_ready = moqt_fill_ready;
    server->session->callbacks.on_fetch_ready = moqt_fill_ready;
    client->session->callbacks.on_fetch_closed = moqt_fetch_closed;
    server->session->callbacks.on_fetch_closed = moqt_fetch_closed;
    client->session->callbacks.on_object = moqt_fill_object;
    client->session->callbacks.on_subscription_closed = moqt_delivery_closed;
    uint8_t next = XQC_MOQT_FILTER_NEXT_OBJECT;
    uint8_t all[] = {2, XQC_MOQT_PARAM_LOCATION_FILTER, XQC_MOQT_FILTER_NONE};
    xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_SUBSCRIBE,
        .track_name = {"fill", 4}, .parameter_count = 2};
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_LOCATION_FILTER, 1, &next};
    m.parameters[1] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FILL_PARAMETERS, sizeof(all), all};
    xqc_moqt_request_t *r = xqc_moqt_request_open(client->session, &m);
    xqc_moqt_check(r != NULL);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_check(client->fill_ready == 1 && server->fill_ready == 1);
    xqc_moqt_fetch_t *first = server->fill;
    xqc_moqt_check(xqc_moqt_fetch_info(first)->end.group_id == 5);
    xqc_moqt_subscription_t *sub =
        xqc_moqt_request_subscription(server->request);
    xqc_moqt_stream_t *history = xqc_moqt_fetch_open(first);
    xqc_moqt_check(history != NULL);
    xqc_moqt_object_t object = {.group_id = 2, .priority = 7,
        .payload_length = 1, .payload = {"f", 1}};
    xqc_moqt_check(xqc_moqt_stream_send_object(history, &object) == XQC_OK);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_check(client->fill_objects == 1);
    if (errors) {
        /* Section 3.4.1: STOP_SENDING for this Fill leaves live active. */
        xqc_moqt_fetch_cancel(client->fill, XQC_MOQT_RESET_CANCELLED);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->fetch_closed == 1 && server->fetch_closed == 1);
        xqc_moqt_check(server->last_error == XQC_MOQT_RESET_CANCELLED);
    }
    object.group_id = 6;
    object.payload = (struct iovec){"l", 1};
    xqc_moqt_stream_t *live = xqc_moqt_subgroup_open(
        sub, object.group_id, 0, 7, 0, 0);
    xqc_moqt_check(live != NULL);
    xqc_moqt_check(xqc_moqt_stream_send_object(live, &object) == XQC_OK);
    xqc_moqt_check(xqc_moqt_stream_finish(live) == XQC_OK);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_check(client->objects == 1);
    uint8_t range[] = {6, XQC_MOQT_PARAM_LOCATION_FILTER,
        XQC_MOQT_FILTER_ABSOLUTE_RANGE, 1, 0, 0, 9};
    m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
    m.parameter_count = 1;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FILL_PARAMETERS, sizeof(range), range};
    xqc_moqt_check(xqc_moqt_request_send(r, &m) == XQC_OK);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_check(client->fill_ready == 2 && server->fill_ready == 2);
    xqc_moqt_check(xqc_moqt_fetch_info(server->fill)->request_id
                   != xqc_moqt_request_id(r));
    xqc_moqt_check(xqc_moqt_fetch_info(server->fill)->end.group_id == 1);
    if (errors) {
        /* Cancel the subscription before the second Fill opens its stream. */
        xqc_moqt_subscription_cancel(xqc_moqt_request_subscription(r),
                                      XQC_MOQT_RESET_CANCELLED);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->fetch_closed == 2 && server->fetch_closed == 2);
        xqc_moqt_check(client->subscription_closed == 1);
    } else {
        /* Live advancement and a new Fill cannot widen the first snapshot. */
        xqc_moqt_check(xqc_moqt_fetch_info(first)->end.group_id == 5);
        xqc_moqt_stream_t *second = xqc_moqt_fetch_open(server->fill);
        xqc_moqt_check(second != NULL);
        object.group_id = 1;
        object.payload = (struct iovec){"f", 1};
        xqc_moqt_check(xqc_moqt_stream_send_object(second, &object) == XQC_OK);
        xqc_moqt_check(xqc_moqt_stream_finish(second) == XQC_OK);
        xqc_moqt_check(xqc_moqt_stream_finish(history) == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->fill_objects == 2 && client->fetch_closed == 2);
        xqc_moqt_check(sub->stream_count == 3);
        xqc_moqt_message_t done = {.type = XQC_MOQT_MSG_PUBLISH_DONE};
        xqc_moqt_check(xqc_moqt_request_send(server->request, &done) == XQC_OK);
        xqc_moqt_check(xqc_moqt_request_finish(r) == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->subscription_closed == 1);
        xqc_moqt_check(client->request_closed == 1
                       && server->request_closed == 1);
        xqc_moqt_check(client->session->fetches == NULL);
        xqc_moqt_check(server->session->fetches == NULL);
    }
    xqc_moqt_check(!client->closed && !server->closed);
    xqc_moqt_check(!client->invalid_handshakes && !server->invalid_handshakes);
    xqc_moqt_message_t probe = {.type = XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE};
    xqc_moqt_check(xqc_moqt_request_open(client->session, &probe) != NULL);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_check(server->request != NULL && server->request->established);
    printf("fill ready=%u objects=%u live=%u closed=%u errors=%d\n",
           client->fill_ready, client->fill_objects, client->objects,
           client->fetch_closed, errors);
    result = 0;
done:
    return result;
}

static void
moqt_namespace_event(xqc_moqt_request_t *r, const xqc_moqt_namespace_t *name,
    xqc_bool_t available, void *data)
{
    moqt_endpoint_t *ep = data;
    ep->namespace_adds += available;
    ep->namespace_removes += !available;
    ep->namespace_fields = name->count;
    if (name->count == 0 || name->fields[0].iov_len != 4
        || xqc_memcmp(name->fields[0].iov_base, "live", 4))
    {
        ep->invalid_handshakes++;
    }
}

static xqc_int_t
moqt_namespaces(moqt_endpoint_t *client, moqt_endpoint_t *server,
    xqc_int_t errors)
{
    xqc_complex_case_engine_t *peers[] = {&client->base, &server->base};
    xqc_int_t result = -1;
    client->session->callbacks.on_namespace = moqt_namespace_event;
    xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_PUBLISH};
    m.track_namespace.count = 2;
    m.track_namespace.fields[0] = (struct iovec){"live", 4};
    m.track_namespace.fields[1] = (struct iovec){"room42", 6};
    m.track_name = (struct iovec){"camera", 6};
    xqc_moqt_request_t *pc = xqc_moqt_request_open(server->session, &m);
    xqc_moqt_check(pc != NULL);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_subscription_t *camera = xqc_moqt_request_subscription(pc);
    xqc_moqt_check(camera != NULL && camera->established);

    m.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
    m.track_namespace.count = 1;
    xqc_moqt_request_t *pn = xqc_moqt_request_open(server->session, &m);
    xqc_moqt_check(pn != NULL);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_check(pn->established);
    m.type = XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE;
    xqc_moqt_request_t *sns = xqc_moqt_request_open(client->session, &m);
    xqc_moqt_check(sns != NULL);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_request_t *publisher = server->request;
    xqc_moqt_check(sns->established && publisher != NULL);
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_NAMESPACE;
    xqc_moqt_check(xqc_moqt_request_send(publisher, &m) == XQC_OK);
    m.track_namespace.count = 1;
    m.track_namespace.fields[0] = (struct iovec){"room42", 6};
    xqc_moqt_check(xqc_moqt_request_send(publisher, &m) == XQC_OK);
    m.type = XQC_MOQT_MSG_NAMESPACE_DONE;
    xqc_moqt_check(xqc_moqt_request_send(publisher, &m) == XQC_OK);
    m.type = XQC_MOQT_MSG_NAMESPACE;
    xqc_moqt_check(xqc_moqt_request_send(publisher, &m) == XQC_OK);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_check(client->namespace_adds == 3);
    xqc_moqt_check(client->namespace_removes == 1);
    xqc_moqt_check(client->namespace_fields == 2);

    uint8_t prefix[] = {2, 4, 'l', 'i', 'v', 'e',
                       6, 'r', 'o', 'o', 'm', '4', '2'};
    xqc_moqt_message_t update = {.type = XQC_MOQT_MSG_REQUEST_UPDATE,
        .parameter_count = 1};
    update.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_TRACK_NAMESPACE_PREFIX, sizeof(prefix), prefix};
    xqc_moqt_check(xqc_moqt_request_send(sns, &update) == XQC_OK);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    m.track_namespace.count = 0;
    xqc_moqt_check(xqc_moqt_request_send(publisher, &m) == XQC_OK);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    /* Empty suffix after OK reconstructs the already known live/room42. */
    xqc_moqt_check(client->namespace_adds == 3);

    xqc_moqt_message_t status = {.type = XQC_MOQT_MSG_TRACK_STATUS};
    status.track_namespace.count = 2;
    status.track_namespace.fields[0] = (struct iovec){"live", 4};
    status.track_namespace.fields[1] = (struct iovec){"room42", 6};
    status.track_name = (struct iovec){"camera", 6};
    unsigned closed = client->request_closed;
    unsigned responses = client->responses;
    xqc_moqt_check(xqc_moqt_request_open(client->session, &status) != NULL);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_check(client->responses == responses + 1);
    xqc_moqt_check(client->request_closed == closed + 1);
    xqc_moqt_check(client->objects == 0 && server->objects == 0);

    if (errors) {
        status.type = XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE;
        xqc_moqt_check(xqc_moqt_request_open(client->session, &status) != NULL);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->request_errors == 1);
        xqc_moqt_check(client->last_error == XQC_MOQT_REQUEST_PREFIX_OVERLAP);
        uint8_t denied[] = {1, 1, '!'};
        update.parameters[0].value = denied;
        update.parameters[0].length = sizeof(denied);
        xqc_moqt_check(xqc_moqt_request_send(sns, &update) == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->request_errors == 2);
        xqc_moqt_check(client->last_error == XQC_MOQT_REQUEST_UNAUTHORIZED);
        xqc_moqt_check(client->namespace_removes == 3);
    } else {
        xqc_moqt_check(xqc_moqt_request_finish(sns) == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        m.track_namespace.count = 1;
        m.track_namespace.fields[0] = (struct iovec){"child", 5};
        xqc_moqt_check(xqc_moqt_request_send(publisher, &m) == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->namespace_adds == 4);
        xqc_moqt_check(client->namespace_fields == 3);
        xqc_moqt_check(xqc_moqt_request_finish(publisher) == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->namespace_removes == 4);
    }
    xqc_moqt_request_cancel(pn, XQC_MOQT_RESET_CANCELLED);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_object_t object = {.group_id = 6, .object_id = 0,
        .priority = XQC_MOQT_DEFAULT_PRIORITY,
        .payload_length = 1, .payload = {"x", 1}, .datagram = 1};
    xqc_moqt_check(!camera->stopped && !pc->failed);
    xqc_moqt_check(xqc_moqt_datagram_send(camera, &object)
                   == XQC_OK);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_check(client->objects == 1);
    xqc_moqt_check(!client->invalid_handshakes && !server->invalid_handshakes);
    xqc_moqt_check(!client->error && !server->error);
    if (errors) {
        status.type = XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE;
        xqc_moqt_check(xqc_moqt_request_open(client->session, &status) != NULL);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        publisher = server->request;
        xqc_moqt_check(publisher != NULL && publisher->established);
        m.type = XQC_MOQT_MSG_NAMESPACE_DONE;
        m.track_namespace.count = 0;
        xqc_moqt_check(xqc_moqt_request_send(publisher, &m) < 0);
        uint8_t wire[16];
        xqc_int_t n = xqc_moqt_message_encode(&m, publisher->initial_type,
                                              wire, sizeof(wire));
        xqc_moqt_check(n > 0);
        xqc_moqt_check(xqc_stream_send(publisher->stream->transport_stream,
                                       wire, n, 0) == n);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client->error == XQC_MOQT_PROTOCOL_VIOLATION);
        xqc_moqt_check(server->error == XQC_MOQT_PROTOCOL_VIOLATION);
    }
    printf("namespace add=%u remove=%u objects=%u errors=%u session=%d/%d\n",
           client->namespace_adds, client->namespace_removes, client->objects,
           client->request_errors, client->error, server->error);
    result = 0;
done:
    return result;
}

static xqc_int_t
moqt_requests(xqc_int_t errors, moqt_test_mode_t mode)
{
    moqt_endpoint_t client = {.base.socket.fd = -1, .requests = 1};
    moqt_endpoint_t server = {.base.socket.fd = -1, .requests = 1};
    xqc_complex_case_engine_t *peers[] = {&client.base, &server.base};
    xqc_moqt_config_t config;
    xqc_conn_settings_t settings = {.proto_version = XQC_VERSION_V1,
        .max_datagram_frame_size = XQC_MAX_PACKET_OUT_SIZE};
    xqc_conn_ssl_config_t ssl = {0};
    xqc_moqt_message_t message;
    xqc_moqt_request_t *request, *reverse;
    xqc_int_t result = -1;

    client.expected_alpn = server.expected_alpn = XQC_MOQT_ALPN_DRAFT_22;
    xqc_moqt_config_init(&config, XQC_MOQT_VERSION_DRAFT_22);
    xqc_moqt_check(moqt_engine_init(&client, XQC_ENGINE_CLIENT, 0) == XQC_OK);
    xqc_moqt_check(moqt_engine_init(&server, XQC_ENGINE_SERVER, 0) == XQC_OK);
    const xqc_cid_t *cid = xqc_moqt_connect(
        client.base.engine, &config,
        &settings, NULL, 0, "localhost", &ssl,
        (struct sockaddr *)&server.base.local, server.base.locallen,
        &client.legacy);
    xqc_moqt_check(cid != NULL);
    client.base.cid = *cid;
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_check(client.ready == 1 && server.ready == 1);
    xqc_moqt_check(client.handshakes == 1 && server.handshakes == 1);
    if (mode == XQC_MOQT_TEST_NAMESPACES) {
        result = moqt_namespaces(&client, &server, errors);
        goto done;
    }
    if (mode == XQC_MOQT_TEST_FILL) {
        result = moqt_fill(&client, &server, errors);
        goto done;
    }
    if (mode == XQC_MOQT_TEST_FETCH) {
        result = moqt_fetch(&client, &server, errors);
        goto done;
    }
    if (mode == XQC_MOQT_TEST_DELIVERY) {
        result = moqt_delivery(&client, &server, errors);
        goto done;
    }
    if (mode == XQC_MOQT_TEST_SUBGROUPS) {
        result = moqt_subgroups(&client, &server, errors);
        goto done;
    }
    if (mode == XQC_MOQT_TEST_DATAGRAMS) {
        result = moqt_datagrams(&client, &server, errors);
        goto done;
    }
    if (mode == XQC_MOQT_TEST_SUBSCRIPTIONS) {
        result = moqt_subscriptions(&client, &server, errors);
        goto done;
    }
    xqc_memzero(&message, sizeof(message));
    message.type = XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE;
    message.track_namespace.count = 1;
    message.track_namespace.fields[0] = (struct iovec){"a", 1};
    request = xqc_moqt_request_open(client.session, &message);
    xqc_moqt_check(request != NULL && xqc_moqt_request_id(request) == 0);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_check(client.responses == 1 && server.messages == 1);
    xqc_moqt_check(server.last_id == 0);

    /* Section 9.5.2: authorize the new prefix before applying an update. */
    uint8_t prefix[] = {1, 1, 'b'};
    message.type = XQC_MOQT_MSG_REQUEST_UPDATE;
    message.parameter_count = 1;
    message.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_TRACK_NAMESPACE_PREFIX, sizeof(prefix), prefix};
    xqc_moqt_check(xqc_moqt_request_send(request, &message) == XQC_OK);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_check(client.responses == 2 && server.updates == 1);
    xqc_moqt_check(client.last_id == 2 && server.last_id == 2);
    xqc_moqt_check(server.candidate_prefix == 'b');

    if (errors) {
        prefix[2] = '!';
        xqc_moqt_check(xqc_moqt_request_send(request, &message) == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client.request_errors == 1);
        xqc_moqt_check(client.last_error == XQC_MOQT_REQUEST_UNAUTHORIZED);
        xqc_moqt_check(server.updates == 1 && server.candidate_prefix == '!');
        message.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
        message.parameter_count = 0;
        message.track_namespace.fields[0].iov_base = "?";
        xqc_moqt_check(xqc_moqt_request_open(client.session, &message) != NULL);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client.request_errors == 2);
        xqc_moqt_check(client.last_error == XQC_MOQT_TEST_UNKNOWN_ERROR);
        xqc_moqt_check(client.normalized_error
                       == XQC_MOQT_REQUEST_INTERNAL_ERROR);
    } else {
        xqc_moqt_message_t goaway;
        xqc_memzero(&goaway, sizeof(goaway));
        goaway.type = XQC_MOQT_MSG_GOAWAY;
        xqc_moqt_check(xqc_moqt_request_send(server.request, &goaway)
                       == XQC_OK);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client.request_goaways == 1);
        xqc_moqt_check(xqc_moqt_request_send(request, &message) == -XQC_EAGAIN);
        xqc_moqt_check(xqc_moqt_request_finish(request) == XQC_OK);
        xqc_moqt_check(xqc_moqt_request_finish(server.request) == XQC_OK);
    }
    /* Request-level rejection must leave the reverse request usable. */
    message.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
    message.parameter_count = 0;
    message.track_namespace.fields[0].iov_base = "audio";
    message.track_namespace.fields[0].iov_len = sizeof("audio") - 1;
    reverse = xqc_moqt_request_open(server.session, &message);
    xqc_moqt_check(reverse != NULL && xqc_moqt_request_id(reverse) == 1);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    xqc_moqt_check(server.responses == 1 && client.messages == 1);
    xqc_moqt_check(client.last_id == 1 && server.last_id == 1);
    xqc_moqt_check(client.error == 0 && server.error == 0);
    xqc_moqt_check(client.invalid_handshakes == 0
                   && server.invalid_handshakes == 0);
    xqc_moqt_check(xqc_moqt_request_finish(reverse) == XQC_OK);
    xqc_moqt_check(xqc_moqt_request_finish(client.request) == XQC_OK);
    xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
    if (errors) {
        /* Section 6.4.2.1: reuse ID 0 on a new bidi stream is session-fatal. */
        xqc_connection_t *conn = xqc_engine_conns_hash_find(
            client.base.engine, &client.base.cid, 's');
        xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
                                                                XQC_STREAM_BIDI,
                                                                NULL);
        uint8_t wire[XQC_MAX_PACKET_OUT_SIZE];
        message.request_id = 0;
        xqc_int_t n = xqc_moqt_message_encode(&message, message.type,
                                              wire, sizeof(wire));
        xqc_moqt_check(stream != NULL && n > 0);
        xqc_moqt_check(xqc_stream_send(stream, wire, n, 0) == n);
        xqc_complex_case_pump(peers, 2, XQC_MOQT_HANDSHAKE_WAIT_MS);
        xqc_moqt_check(client.application_error && server.application_error);
        xqc_moqt_check(client.error == XQC_MOQT_INVALID_REQUEST_ID
                       && server.error == XQC_MOQT_INVALID_REQUEST_ID);
    }
    printf("requests updates=%u responses=%u/%u errors=%u session=%d/%d\n",
           server.updates, client.responses, server.responses,
           client.request_errors, client.error, server.error);
    result = 0;
done:
    xqc_complex_case_engine_release(&client.base);
    xqc_complex_case_engine_release(&server.base);
    if (result == 0
        && (client.closed != 1
            || server.closed != 1
            || client.request_closed < 2
            || server.request_closed < 2))
    {
        result = -1;
    }
    return result;
}

int
main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "namespaces") == 0) {
        return moqt_requests(0, XQC_MOQT_TEST_NAMESPACES);
    }
    if (argc == 2 && strcmp(argv[1], "namespace-errors") == 0) {
        return moqt_requests(1, XQC_MOQT_TEST_NAMESPACES);
    }
    if (argc == 2 && strcmp(argv[1], "fill") == 0) {
        return moqt_requests(0, XQC_MOQT_TEST_FILL);
    }
    if (argc == 2 && strcmp(argv[1], "fill-errors") == 0) {
        return moqt_requests(1, XQC_MOQT_TEST_FILL);
    }
    if (argc == 2 && strcmp(argv[1], "fetch") == 0) {
        return moqt_requests(0, XQC_MOQT_TEST_FETCH);
    }
    if (argc == 2 && strcmp(argv[1], "fetch-errors") == 0) {
        return moqt_requests(1, XQC_MOQT_TEST_FETCH);
    }
    if (argc == 2 && strcmp(argv[1], "delivery") == 0) {
        return moqt_requests(0, XQC_MOQT_TEST_DELIVERY);
    }
    if (argc == 2 && strcmp(argv[1], "delivery-cancel") == 0) {
        return moqt_requests(1, XQC_MOQT_TEST_DELIVERY);
    }
    if (argc == 2 && strcmp(argv[1], "delivery-timeout") == 0) {
        return moqt_requests(2, XQC_MOQT_TEST_DELIVERY);
    }
    if (argc == 2 && strcmp(argv[1], "requests") == 0) {
        return moqt_requests(0, XQC_MOQT_TEST_REQUESTS);
    }
    if (argc == 2 && strcmp(argv[1], "request-errors") == 0) {
        return moqt_requests(1, XQC_MOQT_TEST_REQUESTS);
    }
    if (argc == 2 && strcmp(argv[1], "subscriptions") == 0) {
        return moqt_requests(0, XQC_MOQT_TEST_SUBSCRIPTIONS);
    }
    if (argc == 2 && strcmp(argv[1], "subscription-errors") == 0) {
        return moqt_requests(1, XQC_MOQT_TEST_SUBSCRIPTIONS);
    }
    if (argc == 2 && strcmp(argv[1], "datagrams") == 0) {
        return moqt_requests(0, XQC_MOQT_TEST_DATAGRAMS);
    }
    if (argc == 2 && strcmp(argv[1], "datagram-errors") == 0) {
        return moqt_requests(1, XQC_MOQT_TEST_DATAGRAMS);
    }
    if (argc == 2 && strcmp(argv[1], "subgroups") == 0) {
        return moqt_requests(0, XQC_MOQT_TEST_SUBGROUPS);
    }
    if (argc == 2 && strcmp(argv[1], "subgroup-errors") == 0) {
        return moqt_requests(1, XQC_MOQT_TEST_SUBGROUPS)
               || moqt_requests(2, XQC_MOQT_TEST_SUBGROUPS);
    }
    if (argc == 2 && strcmp(argv[1], "legacy") == 0) {
        return moqt_negotiate(0, 0, NULL, 0, 0, 0);
    }
    if (argc == 2 && strcmp(argv[1], "reject") == 0) {
        return moqt_negotiate(1, 0, NULL, 0, 0, 0);
    }
    if (argc == 3 && strcmp(argv[1], "reject") == 0) {
        return moqt_negotiate(1, atoi(argv[2]), NULL, 0, 0, 0);
    }
    if (argc == 3 && strcmp(argv[1], "setup-errors") == 0) {
        /*
         * Draft-22 sections 6.3/9.1: framing and URI syntax rejection,
         * followed by the demo's authority/path/token policy rejection.
         */
        const struct {
            uint8_t     wire[32];
            size_t      len;
            uint8_t     fin;
            uint64_t    error;
        } cases[] = {
            {{0xaf, 0, 0, 4, 8, 1, 0, 2}, 8, 0,
             XQC_MOQT_PROTOCOL_VIOLATION},
            {{0xaf, 0, 0, 3, 1, 1, 'x'}, 7, 0,
             XQC_MOQT_MALFORMED_PATH},
            {{0xaf, 0, 0, 0}, 4, 1, XQC_MOQT_PROTOCOL_VIOLATION},
            {{0xaf, 0, 0, 3, 1, 1, '/'}, 7, 0,
             XQC_MOQT_INVALID_AUTHORITY},
            {{0xaf, 0, 0, 15, 1, 2, '/', 'x', 4, 9,
              'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't'}, 19, 0,
             XQC_MOQT_INVALID_PATH},
            {{0xaf, 0, 0, 5, 3, 3, 3, 0, 'x'}, 9, 0,
             XQC_MOQT_UNAUTHORIZED},
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            if (moqt_negotiate(1, atoi(argv[2]), cases[i].wire,
                               cases[i].len, cases[i].fin, cases[i].error) != 0)
            {
                return 1;
            }
        }
        return 0;
    }
    fprintf(stderr,
            "usage: %s legacy|reject|setup-errors|requests|request-errors "
            "subscriptions|subscription-errors|datagrams|datagram-errors "
            "subgroups|subgroup-errors|delivery|delivery-cancel|"
            "delivery-timeout|fetch|fetch-errors|fill|fill-errors "
            "namespaces|namespace-errors "
            "[demo-port]\n",
            argv[0]);
    return 1;
}
