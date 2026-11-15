/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "xqc_moqt_demo.h"
#include <arpa/inet.h>
#include <errno.h>
#include <event2/event.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xquic/xqc_http3.h>
#include <xquic/xqc_webtransport.h>
#include <moq/xqc_moqt_webtransport.h>
#include <moq/xqc_moqt_relay.h>
#include "tests/complex_case/complex_case_common.h"

typedef struct app_s app_t;
typedef struct channel_s channel_t;
typedef struct connection_s connection_t;

struct channel_s {
    connection_t          *connection;
    xqc_wt_session_t      *wt;
    xqc_moqt_session_t    *session;
    xqc_moqt_relay_peer_t *peer;
    channel_t            *next;
};

struct connection_s {
    xqc_complex_case_socket_ctx_t socket;
    app_t                        *app;
    xqc_h3_conn_t                *h3;
    channel_t                    *channels;
    channel_t                     native;
};

struct app_s {
    xqc_complex_case_engine_t base;
    struct event_base       *events;
    struct event            *timer;
    struct event            *reader;
    struct event            *term;
    struct event            *interrupt;
    struct event            *limit;
    struct event            *relay_timer;
    xqc_moqt_relay_t         *relay;
    xqc_usec_t               relay_log_time;
    xqc_moqt_config_t         config;
    xqc_conn_settings_t      settings;
    connection_t             client;
    unsigned                 connections;
    unsigned                 ready;
    unsigned                 replies;
    unsigned                 objects_sent;
    unsigned                 closed;
    uint64_t                 close_error;
    unsigned                 wt_closed;
    unsigned                 wt_status;
    uint32_t                 wt_error;
    int                      server;
    int                      failed;
    int                      probe;
    int                      draft07;
    const char              *origin;
    const char              *mode;
    char                     probe_mode[32];
    const char              *path;
    const char              *authority;
    unsigned char            certificate[8192];
    size_t                   certificate_length;
};

static void schedule(xqc_usec_t delay, void *data);
static void engine_tick(evutil_socket_t fd, short flags, void *data);
static void read_packets(evutil_socket_t fd, short flags, void *data);
static void stop(evutil_socket_t fd, short flags, void *data);
static void expired(evutil_socket_t fd, short flags, void *data);
static void relay_tick(evutil_socket_t fd, short flags, void *data);
static void process_relay(app_t *app);
static void release_channel(channel_t *channel);
static uint64_t relay_setup(xqc_moqt_relay_peer_t *peer,
    const xqc_moqt_setup_t *setup, void *data);
static xqc_int_t relay_authorize(xqc_moqt_relay_peer_t *peer,
    const xqc_moqt_message_t *message, const xqc_moqt_message_t *candidate,
    uint64_t *error, void *data);
static xqc_int_t relay_forward(xqc_moqt_relay_peer_t *peer,
    xqc_moqt_message_t *message, void *data);
static void relay_closed(xqc_moqt_relay_peer_t *peer, uint64_t error,
    void *data);
static void log_error(xqc_log_level_t level, const void *buf, size_t size,
    void *data);
static int verify(const unsigned char **certs, const size_t *lengths,
    size_t count, void *data);
static uint64_t setup(xqc_moqt_session_t *session,
    const xqc_moqt_setup_t *peer, void *data);
static void ready(xqc_moqt_session_t *session, void *data);
static void closed(xqc_moqt_session_t *session, uint64_t error, void *data);
static xqc_int_t authorize(xqc_moqt_request_t *request,
    const xqc_moqt_message_t *message, const xqc_moqt_message_t *candidate,
    uint64_t *error, void *data);
static void message(xqc_moqt_request_t *request,
    const xqc_moqt_message_t *m, void *data);
static void object(xqc_moqt_subscription_t *subscription,
    xqc_moqt_stream_t *stream, const xqc_moqt_object_t *value, void *data);
static xqc_int_t accept_connection(xqc_engine_t *engine,
    xqc_connection_t *conn, const xqc_cid_t *cid, void *data);
static void refuse_connection(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *data);
static xqc_int_t native_create(xqc_connection_t *conn,
    const xqc_cid_t *cid, void *data, void *protocol_data);
static void native_handshake(xqc_connection_t *conn, void *data,
    void *protocol_data);
static xqc_int_t native_close(xqc_connection_t *conn,
    const xqc_cid_t *cid, void *data, void *protocol_data);
static xqc_int_t h3_create(xqc_h3_conn_t *h3, const xqc_cid_t *cid,
    void *data);
static xqc_int_t h3_close(xqc_h3_conn_t *h3, const xqc_cid_t *cid,
    void *data);
static int wt_accept(xqc_http_headers_t *headers,
    xqc_http_headers_t *response, void *data);
static int wt_create(xqc_wt_session_t *wt, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *data);
static int wt_close(xqc_wt_session_t *wt, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *data);
static void wt_handshake(xqc_h3_conn_t *h3, void *data);
static int initialize(app_t *app, unsigned port);
static void print_bytes(const struct iovec *value);
static void release_connection(connection_t *connection);
static ssize_t demo_write(const unsigned char *bytes, size_t size,
    const struct sockaddr *peer, socklen_t peer_length, void *data);
static ssize_t demo_write_ex(uint64_t path, const unsigned char *bytes,
    size_t size, const struct sockaddr *peer, socklen_t peer_length,
    void *data);

static const xqc_moqt_callbacks_t callbacks = {
    .on_setup = setup, .on_ready = ready, .on_closed = closed,
    .on_authorize = authorize, .on_message = message, .on_object = object,
};

static ssize_t
demo_write(const unsigned char *bytes, size_t size, const struct sockaddr *peer,
    socklen_t peer_length, void *data)
{
    struct sockaddr_storage address;
    if (!peer || peer_length > sizeof(address)) {
        return XQC_SOCKET_ERROR;
    }
    memcpy(&address, peer, peer_length);
#ifdef __APPLE__
    ((struct sockaddr *)&address)->sa_len = peer_length;
#endif
    return xqc_complex_case_write_socket(bytes, size,
        (struct sockaddr *)&address, peer_length, data);
}

static ssize_t
demo_write_ex(uint64_t path, const unsigned char *bytes, size_t size,
    const struct sockaddr *peer, socklen_t peer_length, void *data)
{
    return demo_write(bytes, size, peer, peer_length, data);
}

static void
schedule(xqc_usec_t delay, void *data)
{
    app_t *app = data;
    struct timeval timeout = {delay / 1000000, delay % 1000000};
    evtimer_add(app->timer, &timeout);
}

static void
engine_tick(evutil_socket_t fd, short flags, void *data)
{
    app_t *app = data;
    xqc_engine_main_logic(app->base.engine);
    process_relay(app);
}

static void
relay_tick(evutil_socket_t fd, short flags, void *data)
{
    process_relay(data);
}

static void
process_relay(app_t *app)
{
    if (!app->relay) {
        return;
    }
    xqc_usec_t now = xqc_complex_case_now_us();
    xqc_usec_t next = xqc_moqt_relay_process(app->relay, now);
    evtimer_del(app->relay_timer);
    if (next) {
        xqc_usec_t delay = next > now ? next - now : 1;
        struct timeval timeout = {delay / 1000000, delay % 1000000};
        evtimer_add(app->relay_timer, &timeout);
    }
    if (now - app->relay_log_time >= 1000000) {
        const xqc_moqt_relay_stats_t *stats = xqc_moqt_relay_stats(app->relay);
        printf("RELAY peers=%zu requests=%zu streams=%zu bytes=%zu "
               "forwarded=%" PRIu64 " rejected=%" PRIu64 "\n",
               stats->peers, stats->requests, stats->streams, stats->bytes,
               stats->forwarded, stats->rejected);
        app->relay_log_time = now;
    }
}

static void
read_packets(evutil_socket_t fd, short flags, void *data)
{
    app_t *app = data;
    unsigned char bytes[65536];
    for (unsigned i = 0; i < 256; i++) {
        struct sockaddr_storage from;
        socklen_t length = sizeof(from);
        ssize_t n = recvfrom(fd, bytes, sizeof(bytes), 0,
                            (struct sockaddr *) &from, &length);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            break;
        }
        xqc_engine_packet_process(app->base.engine, bytes, n,
            (struct sockaddr *) &app->base.local, app->base.locallen,
            (struct sockaddr *) &from, length, xqc_complex_case_now_us(),
            app);
    }
    xqc_engine_finish_recv(app->base.engine);
    xqc_engine_main_logic(app->base.engine);
    process_relay(app);
}

static void
stop(evutil_socket_t fd, short flags, void *data)
{
    app_t *app = data;
    event_base_loopbreak(app->events);
}

static void
expired(evutil_socket_t fd, short flags, void *data)
{
    app_t *app = data;
    app->failed = 1;
    puts("PROBE TIMEOUT");
    stop(fd, flags, data);
}

static void
log_error(xqc_log_level_t level, const void *buf, size_t size, void *data)
{
    fwrite(buf, 1, size, stderr);
    fputc('\n', stderr);
}

static int
verify(const unsigned char **certs, const size_t *lengths, size_t count,
    void *data)
{
    connection_t *connection = data;
    app_t *app = connection->app;
    return count && lengths[0] == app->certificate_length
        && !memcmp(certs[0], app->certificate, lengths[0])
        ? XQC_OK : XQC_ERROR;
}

static void
print_bytes(const struct iovec *value)
{
    const unsigned char *p = value->iov_base;
    size_t length = value->iov_len < 64 ? value->iov_len : 64;
    for (size_t i = 0; i < length; i++) {
        printf("%02x", p[i]);
    }
    if (length < value->iov_len) {
        printf("...");
    }
}

static uint64_t
setup(xqc_moqt_session_t *session, const xqc_moqt_setup_t *peer, void *data)
{
    channel_t *channel = data;
    printf("MOQT SETUP transport=%s options=%zu tokens=%zu\n",
        channel->wt ? "webtransport" : "quic", peer->option_count,
        peer->token_count);
    /* Explicit public parser/sink policy: accept library-validated SETUP. */
    return XQC_MOQT_NO_ERROR;
}

static void
ready(xqc_moqt_session_t *session, void *data)
{
    channel_t *channel = data;
    app_t *app = channel->connection->app;
    printf("MOQT READY draft=22 transport=%s\n",
           channel->wt ? "webtransport" : "quic");
    app->ready++;
    if (app->probe) {
        xqc_moqt_message_t publish = {.type = XQC_MOQT_MSG_PUBLISH,
            .track_name = {"probe", 5}, .track_alias = 7};
        publish.track_namespace.count = 1;
        publish.track_namespace.fields[0] = (struct iovec){"demo", 4};
        if (!xqc_moqt_request_open(session, &publish)) {
            app->failed = 1;
        }
    }
}

static void
closed(xqc_moqt_session_t *session, uint64_t error, void *data)
{
    channel_t *channel = data;
    app_t *app = channel->connection->app;
    printf("MOQT CLOSED transport=%s error=%" PRIu64 "\n",
        channel->wt ? "webtransport" : "quic", error);
    app->closed++;
    app->close_error = error;
}

static xqc_int_t
authorize(xqc_moqt_request_t *request, const xqc_moqt_message_t *m,
    const xqc_moqt_message_t *candidate, uint64_t *error, void *data)
{
    /* No storage or forwarding; anonymous peers may submit parser input. */
    return XQC_OK;
}

static void
message(xqc_moqt_request_t *request, const xqc_moqt_message_t *m,
    void *data)
{
    channel_t *channel = data;
    app_t *app = channel->connection->app;
    printf("MOQT MESSAGE transport=%s type=0x%" PRIx64
           " request=%" PRIu64 " namespace_fields=%zu name_hex=",
           channel->wt ? "webtransport" : "quic", m->type,
           m->request_id, m->track_namespace.count);
    print_bytes(&m->track_name);
    putchar('\n');
    if (app->probe) {
        if (m->type == XQC_MOQT_MSG_REQUEST_OK) {
            app->replies++;
            xqc_moqt_subscription_t *sub =
                xqc_moqt_request_subscription(request);
            xqc_moqt_object_t value = {.priority = 128,
                .first_in_subgroup = 1,
                .payload = {"probe-object", 12}, .payload_length = 12};
            xqc_moqt_stream_t *stream = sub
                ? xqc_moqt_subgroup_open(sub, 0, 0, 128, 1, 1) : NULL;
            if (!stream
                || xqc_moqt_stream_send_object(stream, &value) != XQC_OK
                || xqc_moqt_stream_finish(stream) != XQC_OK)
            {
                app->failed = 1;
                return;
            }
            value.group_id = 1;
            value.datagram = 1;
            value.first_in_subgroup = 0;
            value.payload = (struct iovec){"dg", 2};
            value.payload_length = 2;
            if (xqc_moqt_datagram_send(sub, &value) != XQC_OK) {
                app->failed = 1;
            } else {
                app->objects_sent = 2;
            }
        } else if (m->type == XQC_MOQT_MSG_REQUEST_ERROR) {
            app->failed = 1;
        }
        return;
    }
    xqc_moqt_message_t reply = {0};
    switch (m->type) {
    case XQC_MOQT_MSG_PUBLISH:
    case XQC_MOQT_MSG_PUBLISH_NAMESPACE:
        reply.type = XQC_MOQT_MSG_REQUEST_OK;
        break;
    case XQC_MOQT_MSG_SUBSCRIBE:
    case XQC_MOQT_MSG_FETCH:
    case XQC_MOQT_MSG_TRACK_STATUS:
    case XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE:
    case XQC_MOQT_MSG_SUBSCRIBE_TRACKS:
    case XQC_MOQT_MSG_REQUEST_UPDATE:
        reply.type = XQC_MOQT_MSG_REQUEST_ERROR;
        reply.error.code = XQC_MOQT_REQUEST_NOT_SUPPORTED;
        break;
    default:
        return;
    }
    if (xqc_moqt_request_send(request, &reply) != XQC_OK) {
        puts("MOQT reply failed");
    }
}

static void
object(xqc_moqt_subscription_t *subscription, xqc_moqt_stream_t *stream,
    const xqc_moqt_object_t *value, void *data)
{
    channel_t *channel = data;
    printf("MOQT OBJECT transport=%s carrier=%s group=%" PRIu64
           " subgroup=%" PRIu64 " object=%" PRIu64
           " offset=%" PRIu64 " total=%" PRIu64 " chunk=%zu hex=",
           channel->wt ? "webtransport" : "quic",
           value->datagram ? "datagram" : "stream", value->group_id,
           value->subgroup_id, value->object_id, value->payload_offset,
           value->payload_length, value->payload.iov_len);
    print_bytes(&value->payload);
    putchar('\n');
}

static xqc_int_t
accept_connection(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *data)
{
    app_t *app = data;
    if (app->connections >= 64) {
        return XQC_ERROR;
    }
    connection_t *connection = calloc(1, sizeof(*connection));
    if (!connection) {
        return XQC_ERROR;
    }
    connection->socket = app->base.socket;
    connection->app = app;
    app->connections++;
    xqc_conn_set_transport_user_data(conn, connection);
    return XQC_OK;
}

static xqc_int_t
native_create(xqc_connection_t *conn, const xqc_cid_t *cid, void *data,
    void *protocol_data)
{
    connection_t *connection = data;
    channel_t *channel = &connection->native;
    channel->connection = connection;
    app_t *app = connection->app;
    if (app->relay) {
        struct iovec scope = {"moqt-demo", 9};
        channel->peer = xqc_moqt_relay_peer_create(app->relay, conn,
            &app->config, &scope, channel);
        channel->session = xqc_moqt_relay_peer_session(channel->peer);
    } else {
        channel->session = xqc_moqt_session_create(conn,
            &app->config, &callbacks, channel);
    }
    return channel->session ? XQC_OK : XQC_ERROR;
}

static void
refuse_connection(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *data)
{
    if (data) {
        release_connection(data);
    }
}

static void
native_handshake(xqc_connection_t *conn, void *data, void *protocol_data)
{
    connection_t *connection = data;
    if (xqc_moqt_session_start(connection->native.session) != XQC_OK) {
        connection->app->failed = 1;
    }
}

static void
release_channel(channel_t *channel)
{
    if (channel->peer) {
        xqc_moqt_relay_peer_destroy(channel->peer);
        channel->peer = NULL;
    } else {
        xqc_moqt_session_destroy(channel->session);
    }
    channel->session = NULL;
}

static void
release_connection(connection_t *connection)
{
    app_t *app = connection->app;
    release_channel(&connection->native);
    while (connection->channels) {
        channel_t *channel = connection->channels;
        connection->channels = channel->next;
        release_channel(channel);
        free(channel);
    }
    if (app->server) {
        app->connections--;
        free(connection);
    }
}

static xqc_int_t
native_close(xqc_connection_t *conn, const xqc_cid_t *cid, void *data,
    void *protocol_data)
{
    release_connection(data);
    return XQC_OK;
}

static xqc_int_t
h3_create(xqc_h3_conn_t *h3, const xqc_cid_t *cid, void *data)
{
    connection_t *connection = data;
    connection->h3 = h3;
    return XQC_OK;
}

static xqc_int_t
h3_close(xqc_h3_conn_t *h3, const xqc_cid_t *cid, void *data)
{
    connection_t *connection = data;
    connection->h3 = NULL;
    release_connection(connection);
    return XQC_OK;
}

static int
wt_accept(xqc_http_headers_t *headers, xqc_http_headers_t *response,
    void *data)
{
    int path = 0, origins = 0, origin_ok = 1;
    const char *allowed = getenv("XQC_MOQT_ALLOWED_ORIGIN");
    if (!allowed) {
        allowed = "http://localhost:8080";
    }
    for (size_t i = 0; i < headers->count; i++) {
        xqc_http_header_t *field = &headers->headers[i];
        if (field->name.iov_len == 6
            && !memcmp(field->name.iov_base, "origin", 6))
        {
            origins++;
            origin_ok = xqc_demo_moqt_origin_allowed(field->value.iov_base,
                field->value.iov_len, allowed);
        }
        if (field->name.iov_len == 5
            && !memcmp(field->name.iov_base, ":path", 5)
            && field->value.iov_len == 5
            && !memcmp(field->value.iov_base, "/moqt", 5))
        {
            path++;
        }
    }
    const char *supported[] = {"moqt-22"}, *selected = NULL;
    int protocol = xqc_wt_select_application_protocol(headers,
                                                     supported, 1, &selected);
    if (path != 1 || protocol != 1 || origins > 1 || !origin_ok) {
        printf("WT REJECT path=%d protocol=%d\n", path, protocol);
        return 0;
    }
    static xqc_http_header_t fields[] = {
        {.name = {":status", 7}, .value = {"200", 3}},
        {.name = {"wt-protocol", 11}, .value = {"\"moqt-22\"", 9}},
    };
    response->headers = fields;
    response->count = 2;
    puts("WT ACCEPT path=/moqt protocol=moqt-22");
    return 1;
}

static int
wt_create(xqc_wt_session_t *wt, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *data)
{
    connection_t *connection = data;
    app_t *app = connection->app;
    const char *selected = xqc_wt_session_get_application_protocol(wt);
    if (!selected || strcmp(selected, "moqt-22")) {
        return XQC_ERROR;
    }
    channel_t *channel = calloc(1, sizeof(*channel));
    if (!channel) {
        return XQC_ERROR;
    }
    channel->connection = connection;
    channel->wt = wt;
    channel->next = connection->channels;
    connection->channels = channel;
    if (app->relay) {
        struct iovec scope = {"moqt-demo", 9};
        channel->peer = xqc_moqt_relay_peer_create_webtransport_compat(
            app->relay, wt, &app->config, &scope, channel);
        channel->session = xqc_moqt_relay_peer_session(channel->peer);
    } else {
        channel->session = xqc_moqt_session_create_webtransport_compat(wt,
            &app->config, &callbacks, channel);
    }
    printf("WT READY status=%u protocol=%s compat_draft07=1\n",
        xqc_wt_session_get_response_status(wt), selected);
    if (!channel->session) {
        return XQC_ERROR;
    }
    return xqc_moqt_session_start(channel->session);
}

static int
wt_close(xqc_wt_session_t *wt, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *data)
{
    connection_t *connection = data;
    app_t *app = connection->app;
    printf("WT CLOSED status=%u error=%u\n",
        xqc_wt_session_get_response_status(wt),
        xqc_wt_session_get_close_error_code(wt));
    if (app->probe) {
        app->wt_closed++;
        app->wt_status = xqc_wt_session_get_response_status(wt);
        app->wt_error = xqc_wt_session_get_close_error_code(wt);
    }
    if (app->probe && (!strcmp(app->mode, "bad-path")
                       || !strcmp(app->mode, "bad-protocol")
                       || !strcmp(app->mode, "bad-origin"))
        && xqc_wt_session_get_response_status(wt) == 403 && !app->ready)
    {
        app->closed++;
    }
    channel_t **link = &connection->channels;
    while (*link) {
        channel_t *channel = *link;
        if (channel->wt == wt) {
            *link = channel->next;
            release_channel(channel);
            free(channel);
            break;
        }
        link = &channel->next;
    }
    return XQC_OK;
}

static void
wt_handshake(xqc_h3_conn_t *h3, void *data)
{
    connection_t *connection = data;
    app_t *app = connection->app;
    if (app->server) {
        return;
    }
    const char *protocols[] = {!strcmp(app->mode, "bad-protocol")
                             ? "unsupported" : "moqt-22"};
    int error;
    if (!xqc_wt_client_open_session_with_protocols_compat(h3, app->authority,
        app->path, app->origin, protocols, 1, &error))
    {
        app->failed = 1;
    }
}

static int
initialize(app_t *app, unsigned port)
{
    app->events = event_base_new();
    if (!app->events) {
        return -1;
    }
    if (app->relay) {
        app->relay_timer = evtimer_new(app->events, relay_tick, app);
        if (!app->relay_timer) {
            return -1;
        }
    }
    app->timer = evtimer_new(app->events, engine_tick, app);
    struct sockaddr_in local = {.sin_family = AF_INET,
        .sin_port = htons(app->server ? port : 0),
        .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (!app->timer || xqc_complex_case_make_socket(&app->base,
        (struct sockaddr *) &local, sizeof(local)))
    {
        return -1;
    }
    xqc_engine_type_t type = app->server
        ? XQC_ENGINE_SERVER : XQC_ENGINE_CLIENT;
    xqc_config_t config;
    xqc_engine_get_default_config(&config, type);
    config.cfg_log_level = getenv("XQC_DEMO_DEBUG")
        ? XQC_LOG_DEBUG : XQC_LOG_ERROR;
    xqc_engine_ssl_config_t tls = {.ciphers = XQC_TLS_CIPHERS,
        .groups = XQC_TLS_GROUPS};
    if (app->server) {
        tls.private_key_file = "server.key";
        tls.cert_file = "server.crt";
    }
    xqc_engine_callback_t engine_callbacks;
    xqc_transport_callbacks_t transport_callbacks;
    xqc_complex_case_init_engine_callbacks(&engine_callbacks);
    xqc_complex_case_init_transport_callbacks(&transport_callbacks);
    engine_callbacks.set_event_timer = schedule;
    engine_callbacks.log_callbacks.xqc_log_write_err = log_error;
    transport_callbacks.server_accept = accept_connection;
    transport_callbacks.server_refuse = refuse_connection;
    transport_callbacks.cert_verify_cb = verify;
    transport_callbacks.write_socket = demo_write;
    transport_callbacks.write_socket_ex = demo_write_ex;
    app->base.engine = xqc_engine_create(type, &config, &tls,
        &engine_callbacks, &transport_callbacks, app);
    if (!app->base.engine) {
        return -1;
    }
    xqc_moqt_config_init(&app->config, XQC_MOQT_VERSION_DRAFT_22);
    app->settings.proto_version = XQC_VERSION_V1;
    app->settings.max_datagram_frame_size = 65535;
    app->settings.enable_reset_stream_at = 1;
    if (app->server) {
        xqc_server_set_conn_settings(app->base.engine, &app->settings);
    }
    xqc_conn_callbacks_t native = {.conn_create_notify = native_create,
        .conn_handshake_finished = native_handshake,
        .conn_close_notify = native_close};
    xqc_h3_callbacks_t h3 = {.h3c_cbs = {
        .h3_conn_create_notify = h3_create, .h3_conn_close_notify = h3_close}};
    xqc_webtransport_session_callbacks_t wt = {
        .webtransport_will_create_session_notify = wt_accept,
        .webtransport_session_create_notify = wt_create,
        .webtransport_session_close_notify = wt_close,
        .webtransport_conn_handshake_finished_notify = wt_handshake,
    };
    if (xqc_moqt_init_alpn(app->base.engine, &app->config, &native)
        || xqc_h3_ctx_init(app->base.engine, &h3)
        || xqc_wt_ctx_init(app->base.engine, NULL, &wt, NULL))
    {
        return -1;
    }
    xqc_webtransport_conn_settings_t settings = {.max_sessions_count = 4,
        .draft_version = app->draft07 ? XQC_WEBTRANSPORT_DRAFT_VERSION_7
                                     : XQC_WEBTRANSPORT_DRAFT_VERSION_16,
        .max_bidi_streams = 128, .max_uni_streams = 128,
        .init_recv_window = 1048576, .enable_datagram = XQC_TRUE};
    if (xqc_wt_engine_set_default_settings(app->base.engine, &settings)) {
        return -1;
    }
    app->reader = event_new(app->events, app->base.socket.fd,
        EV_READ | EV_PERSIST, read_packets, app);
    app->term = evsignal_new(app->events, SIGTERM, stop, app);
    app->interrupt = evsignal_new(app->events, SIGINT, stop, app);
    if (!app->reader || !app->term || !app->interrupt) {
        return -1;
    }
    event_add(app->reader, NULL);
    event_add(app->term, NULL);
    event_add(app->interrupt, NULL);
    return 0;
}

int
xqc_demo_moqt_main(int argc, char **argv)
{
    app_t app = {.base.socket.fd = -1, .server = 1,
        .path = "/moqt", .authority = "localhost"};
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    if (!strcmp(argv[0], "--moqt-relay")) {
        xqc_moqt_relay_config_t config;
        xqc_moqt_relay_config_init(&config);
        const xqc_moqt_relay_callbacks_t policy = {.on_setup = relay_setup,
            .on_authorize = relay_authorize, .on_forward = relay_forward,
            .on_closed = relay_closed};
        app.relay = xqc_moqt_relay_create(&config, &policy);
        if (!app.relay) {
            return 1;
        }
    }
    unsigned port = 8443;
    const char *port_env = getenv("XQC_MOQT_DEMO_PORT");
    if (port_env) {
        char *end;
        unsigned long value = strtoul(port_env, &end, 10);
        if (!*port_env || *end || !value || value > 65535) {
            return 2;
        }
        port = value;
    }
    if (argc >= 3 && !strcmp(argv[1], "--probe")) {
        app.server = 0;
        app.probe = 1;
        app.mode = argv[2];
        size_t mode_len = strlen(app.mode);
        char *mode = app.probe_mode;
        if (mode_len >= sizeof(app.probe_mode)) {
            return 2;
        }
        memcpy(mode, app.mode, mode_len + 1);
        if (mode_len >= 2 && !strcmp(mode + mode_len - 2, "07")) {
            mode[mode_len - 2] = '\0';
            app.draft07 = 1;
        }
        app.mode = mode;
        app.origin = getenv("XQC_MOQT_PROBE_ORIGIN");
        if (strcmp(app.mode, "quic") && strcmp(app.mode, "wt")
            && strcmp(app.mode, "bad-path")
            && strcmp(app.mode, "bad-protocol")
            && strcmp(app.mode, "bad-origin"))
        {
            return 2;
        }
        if (!strcmp(app.mode, "bad-path")) {
            app.path = "/not-moqt";
        }
        if (!strcmp(app.mode, "bad-origin")) {
            app.origin = "https://untrusted.invalid";
        }
        FILE *cert = fopen("server.der", "rb");
        if (!cert) {
            perror("server.der");
            return 2;
        }
        app.certificate_length = fread(app.certificate, 1,
                                       sizeof(app.certificate), cert);
        fclose(cert);
    } else if (argc == 3 && !strcmp(argv[1], "-p")) {
        char *end;
        unsigned long value = strtoul(argv[2], &end, 10);
        if (*end || !value || value > 65535) {
            return 2;
        }
        port = value;
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [-p port] | --probe "
                "quic|wt|wt07|bad-path|bad-protocol|bad-origin [IPv4]\n",
                argv[0]);
        return 2;
    }
    if (initialize(&app, port)) {
        fputs("initialization failed\n", stderr);
        return 1;
    }
    if (app.probe) {
        app.client.socket = app.base.socket;
        app.client.app = &app;
        struct sockaddr_in peer = {.sin_family = AF_INET,
            .sin_port = htons(port)};
        const char *address = argc > 3 ? argv[3] : "127.0.0.1";
        if (inet_pton(AF_INET, address, &peer.sin_addr) != 1) {
            return 2;
        }
        xqc_conn_ssl_config_t tls = {.cert_verify_flag =
            XQC_TLS_CERT_FLAG_NEED_VERIFY
            | XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED};
        const xqc_cid_t *cid;
        if (!strcmp(app.mode, "quic")) {
            xqc_moqt_kv_t options[] = {
                {.type = XQC_MOQT_OPT_PATH,
                 .value.bytes = {"/moqt", 5}},
                {.type = XQC_MOQT_OPT_AUTHORITY,
                 .value.bytes = {"localhost", 9}},
            };
            app.config.setup_options = options;
            app.config.setup_option_count = 2;
            cid = xqc_moqt_connect(app.base.engine, &app.config,
                &app.settings, NULL, 0, "localhost", &tls,
                (struct sockaddr *) &peer, sizeof(peer), &app.client);
        } else {
            cid = xqc_webtransport_connect(app.base.engine, &app.settings,
                NULL, 0, "localhost", 0, &tls, (struct sockaddr *) &peer,
                sizeof(peer), &app.client);
        }
        if (!cid) {
            fputs("probe connect failed\n", stderr);
            return 1;
        }
        app.base.cid = *cid;
        app.limit = evtimer_new(app.events, expired, &app);
        struct timeval timeout = {12, 0};
        evtimer_add(app.limit, &timeout);
        xqc_engine_main_logic(app.base.engine);
        while (!app.failed && !app.closed
               && (!app.ready || !app.replies || !app.objects_sent))
        {
            event_base_loop(app.events, EVLOOP_ONCE);
        }
        int expected_reject = !strcmp(app.mode, "bad-path")
            || !strcmp(app.mode, "bad-protocol")
            || !strcmp(app.mode, "bad-origin");
        int success = !app.failed && (expected_reject ? app.closed != 0
            : app.ready && app.replies && app.objects_sent);
        if (success && !expected_reject) {
            struct timeval drain = {0, 300000};
            event_base_loopexit(app.events, &drain);
            event_base_dispatch(app.events);
        }
        if (app.client.native.session) {
            xqc_moqt_session_close(app.client.native.session,
                                   XQC_MOQT_NO_ERROR);
        }
        if (app.client.channels) {
            xqc_moqt_session_close(app.client.channels->session,
                                   XQC_MOQT_NO_ERROR);
        }
        xqc_engine_main_logic(app.base.engine);
        while (app.client.h3 && !app.wt_closed && !app.failed) {
            event_base_loop(app.events, EVLOOP_ONCE);
        }
        if (!expected_reject) {
            success = success && !app.failed && app.closed == 1
                && app.close_error == XQC_MOQT_NO_ERROR;
            if (app.client.h3) {
                success = success && app.wt_closed == 1
                    && app.wt_status == 200 && app.wt_error == 0;
            }
        } else {
            success = success && app.wt_closed == 1 && app.wt_status == 403;
        }
        if (app.client.h3) {
            xqc_h3_conn_close(app.base.engine, &app.base.cid);
            xqc_engine_main_logic(app.base.engine);
            struct timeval close_drain = {0, 300000};
            event_base_loopexit(app.events, &close_drain);
            event_base_dispatch(app.events);
        }
        printf("PROBE %s mode=%s ready=%u replies=%u objects_sent=%u "
               "moqt_error=%" PRIu64 " wt_closed=%u wt_error=%u\n",
            success ? "PASS" : "FAIL", app.mode, app.ready, app.replies,
            app.objects_sent, app.close_error, app.wt_closed, app.wt_error);
        app.failed = !success;
    } else {
        printf("LISTEN udp=0.0.0.0:%u native_alpn=moqt-22 "
               "wt_path=/moqt wt_protocol=moqt-22 draft=22 role=%s\n",
               port, app.relay ? "relay" : "parser");
        event_base_dispatch(app.events);
    }
    xqc_complex_case_engine_release(&app.base);
    if (app.relay) {
        process_relay(&app);
        xqc_moqt_relay_destroy(app.relay);
        event_free(app.relay_timer);
    }
    event_free(app.reader);
    event_free(app.timer);
    event_free(app.term);
    event_free(app.interrupt);
    if (app.limit) {
        event_free(app.limit);
    }
    event_base_free(app.events);
    return app.failed ? 1 : 0;
}

static uint64_t
relay_setup(xqc_moqt_relay_peer_t *peer, const xqc_moqt_setup_t *value,
    void *data)
{
    return setup(xqc_moqt_relay_peer_session(peer), value, data);
}

static xqc_int_t
relay_authorize(xqc_moqt_relay_peer_t *peer, const xqc_moqt_message_t *value,
    const xqc_moqt_message_t *candidate, uint64_t *error, void *data)
{
    /* Public test scope: anonymous namespace and Track grants are explicit. */
    printf("RELAY AUTHORIZE type=0x%" PRIx64 " namespace_fields=%zu\n",
        value->type, candidate->track_namespace.count);
    return XQC_OK;
}

static xqc_int_t
relay_forward(xqc_moqt_relay_peer_t *peer, xqc_moqt_message_t *value,
    void *data)
{
    /* Draft-22 section 7.6: the core owns registration/Track routing. */
    printf("RELAY FORWARD type=0x%" PRIx64 " namespace_fields=%zu\n",
        value->type, value->track_namespace.count);
    return XQC_OK;
}

static void
relay_closed(xqc_moqt_relay_peer_t *peer, uint64_t error, void *data)
{
    closed(xqc_moqt_relay_peer_session(peer), error, data);
}
