/* Copyright (c) 2026, Alibaba Group Holding Limited. */
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "tests/complex_case/complex_case_common.h"
#include "fixture.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

#define XQC_INTEROP_PHASE_MS 5000
#define XQC_INTEROP_DELIVERY_MS 10000
#define XQC_INTEROP_MAX_PEERS 64
#define XQC_INTEROP_DATAGRAM_SIZE 1200

typedef struct xqc_interop_app_s xqc_interop_app_t;
typedef struct xqc_interop_peer_s xqc_interop_peer_t;

struct xqc_interop_peer_s {
    int fd;
    xqc_interop_app_t *app;
    xqc_interop_peer_t *next;
    xqc_moqt_session_t *session;
    xqc_moqt_request_t *request, *sending;
    xqc_moqt_subscription_t *subscription;
    xqc_moqt_stream_t *streams[2];
    xqc_interop_fixture_t fixture;
    xqc_interop_oracle_t oracle;
    unsigned ready, response, response_type, incoming, error, closed;
    unsigned done, streams_closed, streams_reset, namespaces, removals;
    uint64_t response_error, done_code, stream_count, next_alias;
    unsigned group, object, sent_streams, generating, forward, basic;
    xqc_usec_t next_send;
    const char *role;
};

struct xqc_interop_app_s {
    xqc_complex_case_engine_t base;
    xqc_interop_peer_t *peers;
    unsigned peer_count, server, verify, verbose;
    struct sockaddr_storage remote;
    socklen_t remote_len;
    char host[256], authority[300], path[1024];
    const char *cert, *key;
};

static volatile sig_atomic_t xqc_interop_stop;
static const char *xqc_interop_cases[] = {
    "setup-only", "announce-only", "publish-namespace-done",
    "subscribe-error", "rendezvous-timeout", "announce-subscribe",
    "subscribe-before-announce", "data-subgroup-basic",
    "subscribe-namespace-lifecycle", "publish-track-only",
    "publish-track-subscribe", "moq-test-subgroup-per-group-eog",
    "moq-test-subgroup-per-object", "moq-test-two-subgroups-eog",
    "moq-test-datagram", "moq-test-datagram-eog", "moq-test-extensions",
    "moq-test-increments", "moq-test-forward-zero"
};

static void xqc_interop_generate(xqc_interop_peer_t *p);
static void xqc_interop_pump(xqc_interop_app_t *app, unsigned ms);
static int xqc_interop_request(xqc_interop_peer_t *p, uint64_t type,
    const xqc_moqt_namespace_t *ns, const char *track, int rendezvous,
    int forward_zero);
static void xqc_interop_signal(int signo);
static void xqc_interop_log(xqc_log_level_t level, const void *buf,
    size_t size, void *data);
static xqc_interop_peer_t *xqc_interop_peer(xqc_interop_app_t *app);
static xqc_int_t xqc_interop_accept(xqc_engine_t *engine,
    xqc_connection_t *conn, const xqc_cid_t *cid, void *data);
static int xqc_interop_verify(const unsigned char **certs,
    const size_t *lengths, size_t count, void *data);
static uint64_t xqc_interop_setup(xqc_moqt_session_t *session,
    const xqc_moqt_setup_t *setup, void *data);
static void xqc_interop_ready(xqc_moqt_session_t *session, void *data);
static xqc_int_t xqc_interop_authorize(xqc_moqt_request_t *r,
    const xqc_moqt_message_t *m, const xqc_moqt_message_t *candidate,
    uint64_t *error, void *data);
static void xqc_interop_message(xqc_moqt_request_t *r,
    const xqc_moqt_message_t *m, void *data);
static void xqc_interop_request_closed(xqc_moqt_request_t *r,
    const xqc_moqt_error_t *error, void *data);
static void xqc_interop_subscription_closed(xqc_moqt_subscription_t *sub,
    const xqc_moqt_error_t *error, void *data);
static void xqc_interop_object(xqc_moqt_subscription_t *sub,
    xqc_moqt_stream_t *stream, const xqc_moqt_object_t *object, void *data);
static void xqc_interop_stream_closed(xqc_moqt_stream_t *stream,
    const xqc_moqt_object_t *last, const xqc_moqt_error_t *error, void *data);
static void xqc_interop_namespace(xqc_moqt_request_t *r,
    const xqc_moqt_namespace_t *ns, xqc_bool_t available, void *data);
static xqc_int_t xqc_interop_created(xqc_connection_t *conn,
    const xqc_cid_t *cid, void *data, void *proto_data);
static void xqc_interop_handshake(xqc_connection_t *conn,
    void *data, void *proto_data);
static xqc_int_t xqc_interop_closed(xqc_connection_t *conn,
    const xqc_cid_t *cid, void *data, void *proto_data);
static xqc_int_t xqc_interop_closing(xqc_connection_t *conn,
    const xqc_cid_t *cid, xqc_int_t error, void *data);
static int xqc_interop_init(xqc_interop_app_t *app, unsigned port);
static xqc_interop_peer_t *xqc_interop_connect(xqc_interop_app_t *app,
    const char *role);
static int xqc_interop_wait(xqc_interop_app_t *app, unsigned *value,
    unsigned target, unsigned ms);
static void xqc_interop_release(xqc_interop_app_t *app);
static int xqc_interop_url(xqc_interop_app_t *app, const char *url);
static void xqc_interop_name(xqc_moqt_namespace_t *ns, const char *a,
    const char *b, const char *c);
static void xqc_interop_tuple(xqc_moqt_namespace_t *ns,
    const xqc_interop_fixture_t *f, char fields[15][24]);
static int xqc_interop_run(xqc_interop_app_t *app, const char *name);

static void
xqc_interop_signal(int signo)
{
    xqc_interop_stop = 1;
}

static void
xqc_interop_log(xqc_log_level_t level, const void *buf, size_t size,
    void *data)
{
    fwrite(buf, 1, size, stderr);
    fputc('\n', stderr);
}

static xqc_interop_peer_t *
xqc_interop_peer(xqc_interop_app_t *app)
{
    if (app->peer_count == XQC_INTEROP_MAX_PEERS) {
        return NULL;
    }
    xqc_interop_peer_t *p = calloc(1, sizeof(*p));
    if (p != NULL) {
        p->fd = app->base.socket.fd;
        p->app = app;
        p->forward = 1;
        p->next = app->peers;
        app->peers = p;
        app->peer_count++;
    }
    return p;
}

static xqc_int_t
xqc_interop_accept(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *data)
{
    xqc_interop_peer_t *p = xqc_interop_peer(data);
    if (p == NULL) {
        return XQC_ERROR;
    }
    xqc_conn_set_transport_user_data(conn, p);
    return XQC_OK;
}

static int
xqc_interop_verify(const unsigned char **certs, const size_t *lengths,
    size_t count, void *data)
{
    xqc_interop_peer_t *p = data;
    return p->app->verify ? -1 : 0;
}

static uint64_t
xqc_interop_setup(xqc_moqt_session_t *session,
    const xqc_moqt_setup_t *setup, void *data)
{
    return XQC_MOQT_NO_ERROR;
}

static void
xqc_interop_ready(xqc_moqt_session_t *session, void *data)
{
    xqc_interop_peer_t *p = data;
    p->ready++;
    fprintf(stderr, "SETUP ready alpn=moqt-22 transport=quic role=%s\n",
            p->app->server ? "server" : p->role);
}

static xqc_int_t
xqc_interop_authorize(xqc_moqt_request_t *r, const xqc_moqt_message_t *m,
    const xqc_moqt_message_t *candidate, uint64_t *error, void *data)
{
    /* Anonymous, bounded interop endpoint; deployment policy is external. */
    return XQC_OK;
}

static void
xqc_interop_message(xqc_moqt_request_t *r, const xqc_moqt_message_t *m,
    void *data)
{
    xqc_interop_peer_t *p = data;
    xqc_moqt_message_t reply = {0};
    if (m->type == XQC_MOQT_MSG_REQUEST_OK
        || m->type == XQC_MOQT_MSG_SUBSCRIBE_OK
        || m->type == XQC_MOQT_MSG_REQUEST_ERROR)
    {
        p->response++;
        p->response_type = m->type;
        p->response_error = m->error.code;
        if (m->type != XQC_MOQT_MSG_REQUEST_ERROR) {
            p->subscription = xqc_moqt_request_subscription(r);
            for (size_t i = 0; i < m->parameter_count; i++) {
                if (m->parameters[i].type == XQC_MOQT_PARAM_FORWARD) {
                    p->forward = m->parameters[i].value[0] != 0;
                }
            }
        }
        return;
    }
    if (m->type == XQC_MOQT_MSG_PUBLISH_DONE) {
        p->done++;
        p->done_code = m->error.code;
        p->stream_count = m->stream_count;
        return;
    }
    if (m->type == XQC_MOQT_MSG_NAMESPACE
        || m->type == XQC_MOQT_MSG_NAMESPACE_DONE
        || m->type == XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY)
    {
        return;
    }
    if (m->type == XQC_MOQT_MSG_PUBLISH_NAMESPACE) {
        reply.type = XQC_MOQT_MSG_REQUEST_OK;
    } else if (m->type == XQC_MOQT_MSG_PUBLISH) {
        reply.type = XQC_MOQT_MSG_REQUEST_OK;
    } else if (m->type == XQC_MOQT_MSG_SUBSCRIBE) {
        if (xqc_interop_fixture_parse(&m->track_namespace, &p->fixture)
            != 0 && (p->app->server || p->basic))
        {
            reply.type = XQC_MOQT_MSG_REQUEST_ERROR;
            reply.error.code = XQC_MOQT_REQUEST_DOES_NOT_EXIST;
        } else {
            reply.type = XQC_MOQT_MSG_SUBSCRIBE_OK;
            reply.track_alias = p->next_alias++;
            p->sending = r;
            if (p->basic) {
                p->fixture.priority = 128;
            }
            p->group = p->fixture.first_group;
            p->object = p->fixture.first_object;
            p->sent_streams = 0;
            p->forward = 1;
            for (size_t i = 0; i < m->parameter_count; i++) {
                if (m->parameters[i].type == XQC_MOQT_PARAM_FORWARD) {
                    p->forward = m->parameters[i].value[0] != 0;
                }
            }
        }
    } else if (m->type == XQC_MOQT_MSG_REQUEST_UPDATE) {
        for (size_t i = 0; i < m->parameter_count; i++) {
            if (m->parameters[i].type == XQC_MOQT_PARAM_FORWARD) {
                p->forward = m->parameters[i].value[0] != 0;
            }
        }
        reply.type = XQC_MOQT_MSG_REQUEST_OK;
    } else {
        reply.type = XQC_MOQT_MSG_REQUEST_ERROR;
        reply.error.code = XQC_MOQT_REQUEST_NOT_SUPPORTED;
    }
    if (xqc_moqt_request_send(r, &reply) != XQC_OK) {
        p->error = 1;
        return;
    }
    if (reply.type == XQC_MOQT_MSG_SUBSCRIBE_OK) {
        p->incoming++;
        p->subscription = xqc_moqt_request_subscription(r);
        if (p->basic || p->app->server) {
            p->generating = 1;
        }
    }
}

static void
xqc_interop_request_closed(xqc_moqt_request_t *r,
    const xqc_moqt_error_t *error, void *data)
{
    xqc_interop_peer_t *p = data;
    if (p->request == r) {
        p->request = NULL;
    }
    if (p->sending == r) {
        p->sending = NULL;
        p->generating = 0;
    }
}

static void
xqc_interop_subscription_closed(xqc_moqt_subscription_t *sub,
    const xqc_moqt_error_t *error, void *data)
{
    xqc_interop_peer_t *p = data;
    if (p->subscription == sub) {
        p->subscription = NULL;
        p->generating = 0;
    }
}

static void
xqc_interop_object(xqc_moqt_subscription_t *sub,
    xqc_moqt_stream_t *stream, const xqc_moqt_object_t *object, void *data)
{
    xqc_interop_peer_t *p = data;
    xqc_interop_oracle_object(&p->oracle, object);
}

static void
xqc_interop_stream_closed(xqc_moqt_stream_t *stream,
    const xqc_moqt_object_t *last, const xqc_moqt_error_t *error, void *data)
{
    xqc_interop_peer_t *p = data;
    p->streams_closed++;
    p->streams_reset += error != NULL;
    for (unsigned i = 0; i < 2; i++) {
        if (p->streams[i] == stream) {
            p->streams[i] = NULL;
        }
    }
}

static void
xqc_interop_namespace(xqc_moqt_request_t *r,
    const xqc_moqt_namespace_t *ns, xqc_bool_t available, void *data)
{
    xqc_interop_peer_t *p = data;
    if (available) {
        p->namespaces++;
    } else {
        p->removals++;
    }
}

static xqc_int_t
xqc_interop_created(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *data, void *proto_data)
{
    xqc_interop_peer_t *p = data;
    xqc_moqt_config_t config;
    xqc_moqt_config_init(&config, XQC_MOQT_VERSION_DRAFT_22);
    xqc_moqt_kv_t opts[2] = {0};
    if (!p->app->server) {
        opts[0].type = XQC_MOQT_OPT_PATH;
        opts[0].value.bytes = (struct iovec){p->app->path,
                                             strlen(p->app->path)};
        opts[1].type = XQC_MOQT_OPT_AUTHORITY;
        opts[1].value.bytes = (struct iovec){p->app->authority,
                                             strlen(p->app->authority)};
        config.setup_options = opts;
        config.setup_option_count = 2;
    }
    xqc_moqt_callbacks_t cbs = {
        .on_setup = xqc_interop_setup,
        .on_ready = xqc_interop_ready,
        .on_authorize = xqc_interop_authorize,
        .on_message = xqc_interop_message,
        .on_request_closed = xqc_interop_request_closed,
        .on_subscription_closed = xqc_interop_subscription_closed,
        .on_object = xqc_interop_object,
        .on_stream_closed = xqc_interop_stream_closed,
        .on_namespace = xqc_interop_namespace,
    };
    p->session = xqc_moqt_session_create(conn, &config, &cbs, p);
    return p->session == NULL ? XQC_ERROR : XQC_OK;
}

static void
xqc_interop_handshake(xqc_connection_t *conn, void *data, void *proto_data)
{
    xqc_interop_peer_t *p = data;
    if (!p->session || xqc_moqt_session_start(p->session) != XQC_OK) {
        p->error = 1;
    }
}

static xqc_int_t
xqc_interop_closed(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *data, void *proto_data)
{
    xqc_interop_peer_t *p = data;
    if (p->session != NULL) {
        xqc_moqt_session_destroy(p->session);
        p->session = NULL;
    }
    p->closed++;
    return XQC_OK;
}

static xqc_int_t
xqc_interop_closing(xqc_connection_t *conn, const xqc_cid_t *cid,
    xqc_int_t error, void *data)
{
    xqc_interop_peer_t *p = data;
    p->error = error;
    return XQC_OK;
}

static int
xqc_interop_init(xqc_interop_app_t *app, unsigned port)
{
    xqc_config_t config;
    xqc_engine_ssl_config_t ssl = {0};
    xqc_engine_callback_t engine_cbs;
    xqc_transport_callbacks_t transport_cbs;
    xqc_conn_callbacks_t conn_cbs = {
        .conn_create_notify = xqc_interop_created,
        .conn_close_notify = xqc_interop_closed,
        .conn_handshake_finished = xqc_interop_handshake,
    };
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    app->base.socket.fd = -1;
    app->base.user_data = app;
    if (xqc_complex_case_make_socket(&app->base,
            (struct sockaddr *)&addr, sizeof(addr)))
    {
        return -1;
    }
    xqc_engine_type_t type = app->server
        ? XQC_ENGINE_SERVER : XQC_ENGINE_CLIENT;
    xqc_engine_get_default_config(&config, type);
    config.cfg_log_level = app->verbose ? XQC_LOG_DEBUG : XQC_LOG_ERROR;
    ssl.ciphers = XQC_TLS_CIPHERS;
    ssl.groups = XQC_TLS_GROUPS;
    if (app->server) {
        ssl.cert_file = (char *)app->cert;
        ssl.private_key_file = (char *)app->key;
    }
    xqc_complex_case_init_engine_callbacks(&engine_cbs);
    engine_cbs.log_callbacks.xqc_log_write_err = xqc_interop_log;
    xqc_complex_case_init_transport_callbacks(&transport_cbs);
    transport_cbs.server_accept = xqc_interop_accept;
    transport_cbs.conn_closing = xqc_interop_closing;
    transport_cbs.cert_verify_cb = xqc_interop_verify;
    app->base.engine = xqc_engine_create(type, &config, &ssl, &engine_cbs,
                                          &transport_cbs, app);
    if (app->base.engine == NULL) {
        return -1;
    }
    xqc_conn_settings_t settings = {
        .max_datagram_frame_size = XQC_INTEROP_DATAGRAM_SIZE,
    };
    if (app->server) {
        xqc_server_set_conn_settings(app->base.engine, &settings);
    }
    xqc_moqt_config_t moqt;
    xqc_moqt_config_init(&moqt, XQC_MOQT_VERSION_DRAFT_22);
    return xqc_moqt_init_alpn(app->base.engine, &moqt, &conn_cbs);
}

static xqc_interop_peer_t *
xqc_interop_connect(xqc_interop_app_t *app, const char *role)
{
    xqc_interop_peer_t *p = xqc_interop_peer(app);
    if (p == NULL) {
        return NULL;
    }
    p->role = role;
    xqc_moqt_config_t config;
    xqc_moqt_config_init(&config, XQC_MOQT_VERSION_DRAFT_22);
    xqc_conn_settings_t settings = {
        .proto_version = XQC_VERSION_V1,
        .max_datagram_frame_size = XQC_INTEROP_DATAGRAM_SIZE,
    };
    xqc_conn_ssl_config_t ssl = {0};
    const xqc_cid_t *cid = xqc_moqt_connect(app->base.engine, &config,
        &settings, NULL, 0, app->host, &ssl,
        (struct sockaddr *)&app->remote, app->remote_len, p);
    if (cid == NULL || xqc_interop_wait(app, &p->ready, 1,
                                       XQC_INTEROP_PHASE_MS))
    {
        return NULL;
    }
    return p;
}

static void
xqc_interop_generate(xqc_interop_peer_t *p)
{
    xqc_interop_fixture_t *f = &p->fixture;
    if (!p->generating || !p->subscription || !p->sending
        || xqc_complex_case_now_us() < p->next_send)
    {
        return;
    }
    if (!p->forward || p->group > f->last_group) {
        xqc_moqt_message_t done = {
            .type = XQC_MOQT_MSG_PUBLISH_DONE,
            .error.code = XQC_MOQT_PUBLISH_TRACK_ENDED,
            .stream_count = p->sent_streams,
        };
        if (xqc_moqt_request_send(p->sending, &done) != XQC_OK) {
            p->error = 1;
        }
        p->generating = 0;
        return;
    }
    unsigned sg = f->mode == 1 ? p->object
        : f->mode == 2 ? p->object % 2 : 0;
    unsigned slot = f->mode == 2 ? sg : 0;
    unsigned size = p->object == f->first_object ? f->size0 : f->size;
    unsigned char payload[1024], properties[] = {2, 1, 3, 1, 'x'};
    memset(payload, 't', size);
    xqc_moqt_object_t object = {
        .group_id = p->group, .object_id = p->object, .subgroup_id = sg,
        .priority = f->priority == 128 ? 128 : 200 + p->group % 2,
        .datagram = f->mode == 3,
        .payload = {payload, size}, .payload_length = size,
    };
    if (f->extensions) {
        object.properties = (struct iovec){properties, sizeof(properties)};
    }
    int last = p->object + f->object_step > f->last_object;
    if (last && f->markers) {
        object.status = XQC_MOQT_OBJECT_END_GROUP;
        object.payload = (struct iovec){0};
        object.payload_length = 0;
        object.properties = (struct iovec){0};
    }
    xqc_int_t rc;
    if (f->mode == 3) {
        rc = xqc_moqt_datagram_send(p->subscription, &object);
    } else {
        if (p->streams[slot] == NULL) {
            p->streams[slot] = xqc_moqt_subgroup_open(p->subscription,
                p->group, sg, object.priority, 0, 0);
            if (p->streams[slot] == NULL) {
                p->error = 1;
                return;
            }
            p->sent_streams++;
        }
        rc = xqc_moqt_stream_send_object(p->streams[slot], &object);
    }
    if (rc == -XQC_EAGAIN) {
        return;
    }
    if (rc != XQC_OK) {
        fprintf(stderr, "object send failed: %d at %u.%u\n",
                rc, p->group, p->object);
        p->error = 1;
        p->generating = 0;
        return;
    }
    if (last || f->mode == 1) {
        for (unsigned i = 0; i < 2; i++) {
            if (p->streams[i] != NULL) {
                xqc_moqt_stream_t *st = p->streams[i];
                p->streams[i] = NULL;
                if (xqc_moqt_stream_finish(st) != XQC_OK) {
                    p->error = 1;
                }
            }
        }
    }
    if (last) {
        p->group += f->group_step;
        p->object = f->first_object;
    } else {
        p->object += f->object_step;
    }
    p->next_send = xqc_complex_case_now_us() + f->pace_ms * 1000;
}

static void
xqc_interop_pump(xqc_interop_app_t *app, unsigned ms)
{
    xqc_complex_case_engine_t *engines[] = {&app->base};
    xqc_usec_t deadline = xqc_complex_case_now_us() + ms * 1000;
    do {
        xqc_complex_case_pump(engines, 1, 2);
        for (xqc_interop_peer_t *p = app->peers; p; p = p->next) {
            xqc_interop_generate(p);
        }
    } while (!xqc_interop_stop && xqc_complex_case_now_us() < deadline);
}

static int
xqc_interop_wait(xqc_interop_app_t *app, unsigned *value,
    unsigned target, unsigned ms)
{
    xqc_usec_t deadline = xqc_complex_case_now_us() + ms * 1000;
    while (*value < target && xqc_complex_case_now_us() < deadline
           && !xqc_interop_stop)
    {
        for (xqc_interop_peer_t *p = app->peers; p; p = p->next) {
            if (p->error || p->closed) {
                return -1;
            }
        }
        xqc_interop_pump(app, 2);
    }
    return *value >= target ? 0 : -1;
}

static void
xqc_interop_release(xqc_interop_app_t *app)
{
    for (xqc_interop_peer_t *p = app->peers; p; p = p->next) {
        if (p->session) {
            xqc_moqt_session_close(p->session, XQC_MOQT_NO_ERROR);
        }
    }
    if (app->base.engine) {
        xqc_interop_pump(app, 100);
    }
    xqc_complex_case_engine_release(&app->base);
    while (app->peers) {
        xqc_interop_peer_t *p = app->peers;
        app->peers = p->next;
        free(p);
    }
    app->peer_count = 0;
}

static int
xqc_interop_url(xqc_interop_app_t *app, const char *url)
{
    if (strncmp(url, "moqt://", 7)) {
        return -1;
    }
    const char *path = strchr(url + 7, '/');
    size_t length = path ? (size_t)(path - url - 7) : strlen(url + 7);
    if (!length || length >= sizeof(app->authority)
        || (path && strlen(path) >= sizeof(app->path)))
    {
        return -1;
    }
    memcpy(app->authority, url + 7, length);
    app->authority[length] = 0;
    strcpy(app->path, path ? path : "/");
    char host[300];
    strcpy(host, app->authority);
    char *port = strrchr(host, ':');
    if (port) {
        *port++ = 0;
    } else {
        port = "443";
    }
    if (!*host || strlen(host) >= sizeof(app->host)
        || strspn(port, "0123456789") != strlen(port)
        || !*port || strtoul(port, NULL, 10) > 65535
        || strtoul(port, NULL, 10) == 0 || strchr(host, '@'))
    {
        return -1;
    }
    strcpy(app->host, host);
    struct addrinfo hints = {.ai_family = AF_INET,
                             .ai_socktype = SOCK_DGRAM}, *info;
    if (getaddrinfo(host, port, &hints, &info)) {
        return -1;
    }
    memcpy(&app->remote, info->ai_addr, info->ai_addrlen);
    app->remote_len = info->ai_addrlen;
    freeaddrinfo(info);
    return 0;
}

static void
xqc_interop_name(xqc_moqt_namespace_t *ns, const char *a,
    const char *b, const char *c)
{
    const char *fields[] = {a, b, c};
    memset(ns, 0, sizeof(*ns));
    for (unsigned i = 0; i < 3 && fields[i]; i++) {
        ns->fields[ns->count++] = (struct iovec){(void *)fields[i],
                                                 strlen(fields[i])};
    }
}

static void
xqc_interop_tuple(xqc_moqt_namespace_t *ns,
    const xqc_interop_fixture_t *f, char fields[15][24])
{
    const int values[] = {f->mode, f->first_group, f->first_object,
        f->last_group, f->last_object, f->objects_per_group, f->size0,
        f->size, f->pace_ms, f->group_step, f->object_step, f->markers,
        f->extensions ? 1 : -1, f->extensions ? 2 : -1, 0};
    ns->fields[ns->count++] = (struct iovec){"moq-test-00", 11};
    for (unsigned i = 0; i < 15; i++) {
        int n = snprintf(fields[i], 24, "%d", values[i]);
        ns->fields[ns->count++] = (struct iovec){fields[i], n};
    }
}

static int
xqc_interop_request(xqc_interop_peer_t *p, uint64_t type,
    const xqc_moqt_namespace_t *ns, const char *track,
    int rendezvous, int forward_zero)
{
    xqc_moqt_message_t m = {.type = type, .track_namespace = *ns};
    unsigned char timeout[9], zero = 0, order = 1;
    int timeout_len = xqc_vi64_write(timeout, timeout + sizeof(timeout),
                                     rendezvous == 1 ? 5000 : 500);
    if (track) {
        m.track_name = (struct iovec){(void *)track, strlen(track)};
    }
    if (type == XQC_MOQT_MSG_SUBSCRIBE && rendezvous) {
        m.parameters[m.parameter_count++] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_RENDEZVOUS_TIMEOUT, timeout_len, timeout};
    }
    if (type == XQC_MOQT_MSG_SUBSCRIBE && forward_zero) {
        m.parameters[m.parameter_count++] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_FORWARD, 1, &zero};
    }
    if (type == XQC_MOQT_MSG_SUBSCRIBE) {
        m.parameters[m.parameter_count++] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_GROUP_ORDER, 1, &order};
    }
    p->response = 0;
    p->request = xqc_moqt_request_open(p->session, &m);
    if (p->request == NULL) {
        fprintf(stderr, "request open failed: type=%llu\n",
                (unsigned long long)type);
    }
    return p->request ? 0 : -1;
}

static int
xqc_interop_run(xqc_interop_app_t *app, const char *name)
{
    int data = !xqc_interop_fixture_case(name,
                                         &(xqc_interop_fixture_t){0});
    int basic = !strcmp(name, "data-subgroup-basic");
    int vectors = data && !basic;
    int publish = !strncmp(name, "publish-track-", 14);
    int pair = vectors || basic || !strcmp(name, "announce-subscribe")
        || !strcmp(name, "subscribe-before-announce")
        || !strcmp(name, "publish-track-subscribe")
        || !strcmp(name, "subscribe-namespace-lifecycle");
    int zero = !strcmp(name, "moq-test-forward-zero");
    int before = !strcmp(name, "subscribe-before-announce") || vectors;
    int discovery = !strcmp(name, "subscribe-namespace-lifecycle");
    const char *role = !strcmp(name, "setup-only") ? "client"
        : strstr(name, "error") || strstr(name, "timeout")
        ? "subscriber" : "publisher";
    xqc_interop_peer_t *p = xqc_interop_connect(app,
        before ? "subscriber" : role), *s = NULL;
    if (!p) {
        return -1;
    }
    if (!strcmp(name, "setup-only")) {
        return 0;
    }
    unsigned char entropy[16];
    FILE *random = fopen("/dev/urandom", "rb");
    if (!random) {
        return -1;
    }
    size_t got = fread(entropy, 1, sizeof(entropy), random);
    fclose(random);
    if (got != sizeof(entropy)) {
        return -1;
    }
    char run[33];
    for (unsigned i = 0; i < sizeof(entropy); i++) {
        snprintf(run + 2 * i, 3, "%02x", entropy[i]);
    }
    xqc_moqt_namespace_t ns;
    xqc_interop_name(&ns, "moq-test", basic ? name : "interop", run);
    char fields[15][24];
    if (data) {
        xqc_interop_fixture_case(name, &p->fixture);
        p->basic = basic;
        if (vectors) {
            xqc_interop_tuple(&ns, &p->fixture, fields);
        }
    }
    if (pair) {
        s = before ? p : xqc_interop_connect(app, "subscriber");
        if (!s) {
            return -1;
        }
        s->oracle.fixture = p->fixture;
    }
    if (discovery) {
        if (xqc_interop_request(s, XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE,
                                 &ns, NULL, 0, 0)
            || xqc_interop_wait(app, &s->response, 1, XQC_INTEROP_PHASE_MS)
            || s->response_type != XQC_MOQT_MSG_REQUEST_OK)
        {
            return -1;
        }
    }
    if (before) {
        if (xqc_interop_request(s, XQC_MOQT_MSG_SUBSCRIBE,
                                 &ns, "test-track", vectors, zero))
        {
            return -1;
        }
        xqc_interop_pump(app, vectors ? 200 : 500);
        p = xqc_interop_connect(app, "publisher");
        if (p == NULL) {
            return -1;
        }
        p->fixture = s->oracle.fixture;
    }
    if (!strcmp(name, "subscribe-error")
        || !strcmp(name, "rendezvous-timeout"))
    {
        int timeout = !strcmp(name, "rendezvous-timeout");
        xqc_interop_name(&ns, "nonexistent", timeout ? "rendezvous"
                                                       : "namespace", NULL);
        if (xqc_interop_request(p, XQC_MOQT_MSG_SUBSCRIBE,
                                 &ns, "test-track", timeout ? 2 : 0, 0)
            || xqc_interop_wait(app, &p->response, 1, 6000)
            || p->response_type != XQC_MOQT_MSG_REQUEST_ERROR
            || (timeout && p->response_error != XQC_MOQT_REQUEST_TIMEOUT))
        {
            return -1;
        }
        return 0;
    }
    if (xqc_interop_request(p, publish || vectors ? XQC_MOQT_MSG_PUBLISH
                               : XQC_MOQT_MSG_PUBLISH_NAMESPACE,
                             &ns, publish || vectors ? "test-track" : NULL,
                             0, 0)
        || xqc_interop_wait(app, &p->response, 1, XQC_INTEROP_PHASE_MS)
        || p->response_type != XQC_MOQT_MSG_REQUEST_OK)
    {
        return -1;
    }
    if (discovery) {
        if (xqc_interop_wait(app, &s->namespaces, 1, XQC_INTEROP_PHASE_MS)) {
            return -1;
        }
        xqc_moqt_request_cancel(p->request, XQC_MOQT_RESET_CANCELLED);
        return xqc_interop_wait(app, &s->removals, 1, XQC_INTEROP_PHASE_MS);
    }
    if (!strcmp(name, "publish-namespace-done")) {
        if (!p->request) {
            return -1;
        }
        xqc_moqt_request_cancel(p->request, XQC_MOQT_RESET_CANCELLED);
        xqc_interop_pump(app, 100);
        return p->error ? -1 : 0;
    }
    if (pair && !before) {
        xqc_moqt_namespace_t track_ns = ns;
        if (basic) {
            xqc_interop_tuple(&track_ns, &p->fixture, fields);
        }
        if (xqc_interop_request(s, XQC_MOQT_MSG_SUBSCRIBE, &track_ns,
                                 basic ? "track" : "test-track", 0, zero))
        {
            return -1;
        }
    }
    if (pair) {
        if (xqc_interop_wait(app, &s->response, 1, XQC_INTEROP_PHASE_MS)) {
            return -1;
        }
        if (before && !vectors
            && s->response_type == XQC_MOQT_MSG_REQUEST_ERROR)
        {
            return 0;
        }
        if (s->response_type != XQC_MOQT_MSG_SUBSCRIBE_OK) {
            return -1;
        }
    }
    if (vectors || publish) {
        p->sending = p->request;
        if (vectors) {
            p->group = p->fixture.first_group;
            p->object = p->fixture.first_object;
            p->generating = 1;
        } else {
            xqc_moqt_message_t done = {
                .type = XQC_MOQT_MSG_PUBLISH_DONE,
                .error.code = XQC_MOQT_PUBLISH_TRACK_ENDED,
            };
            if (!p->request
                || xqc_moqt_request_send(p->request, &done) != XQC_OK)
            {
                return -1;
            }
        }
    }
    if (data) {
        if (xqc_interop_wait(app, &s->done, 1, XQC_INTEROP_DELIVERY_MS)) {
            return -1;
        }
        xqc_usec_t end = xqc_complex_case_now_us()
            + XQC_INTEROP_DELIVERY_MS * 1000;
        while ((s->stream_count == UINT64_MAX
                || s->streams_closed < s->stream_count)
               && xqc_complex_case_now_us() < end)
        {
            xqc_interop_pump(app, 2);
        }
        xqc_interop_pump(app, 250);
        fprintf(stderr, "objects=%u markers=%u streams=%u/%llu bad=%u\n",
            s->oracle.objects, s->oracle.markers, s->streams_closed,
            (unsigned long long)s->stream_count, s->oracle.failed);
        if (!xqc_interop_oracle_complete(&s->oracle, zero)
            || s->done_code != XQC_MOQT_PUBLISH_TRACK_ENDED
            || s->streams_reset || p->error || s->error
            || (s->stream_count != UINT64_MAX
                && s->streams_closed != s->stream_count))
        {
            return -1;
        }
    }
    return 0;
}

int
main(int argc, char **argv)
{
    const char *url = getenv("RELAY_URL"), *test = getenv("TESTCASE");
    if (test != NULL && !*test) {
        test = NULL;
    }
    const char *flag = getenv("TLS_DISABLE_VERIFY");
    const char *verbose = getenv("VERBOSE");
    const char *port_env = getenv("MOQT_PORT");
    xqc_interop_app_t app = {.base.socket.fd = -1,
        .verify = !flag || strcmp(flag, "1"),
        .verbose = verbose && !strcmp(verbose, "1"),
        .cert = "/certs/cert.pem", .key = "/certs/priv.key"};
    unsigned port = port_env ? strtoul(port_env, NULL, 10) : 4443;
    static const struct option opts[] = {
        {"relay", required_argument, NULL, 'r'},
        {"test", required_argument, NULL, 't'},
        {"list", no_argument, NULL, 'l'},
        {"verbose", no_argument, NULL, 'v'},
        {"tls-disable-verify", no_argument, NULL, 'k'},
        {"server", no_argument, NULL, 's'},
        {"port", required_argument, NULL, 'p'},
        {"cert", required_argument, NULL, 'c'},
        {"key", required_argument, NULL, 'K'},
        {"help", no_argument, NULL, 'h'}, {0}
    };
    unsigned ncases = sizeof(xqc_interop_cases) / sizeof(xqc_interop_cases[0]);
    int c;
    while ((c = getopt_long(argc, argv, "r:t:lvksp:c:K:h", opts, NULL)) != -1) {
        switch (c) {
        case 'r': url = optarg; break;
        case 't': test = optarg; break;
        case 'v': app.verbose = 1; break;
        case 'k': app.verify = 0; break;
        case 's': app.server = 1; break;
        case 'p': port = strtoul(optarg, NULL, 10); break;
        case 'c': app.cert = optarg; break;
        case 'K': app.key = optarg; break;
        case 'l':
            for (unsigned i = 0; i < ncases; i++) {
                puts(xqc_interop_cases[i]);
            }
            return 0;
        case 'h':
            puts("moqt_interop --relay moqt://host:port [--test NAME]\n"
                 "  --list --tls-disable-verify --verbose\n"
                 "  --server [--port 4443 --cert FILE --key FILE]");
            return 0;
        default: return 1;
        }
    }
    signal(SIGINT, xqc_interop_signal);
    signal(SIGTERM, xqc_interop_signal);
    if (app.server) {
        if (!port || port > 65535 || xqc_interop_init(&app, port)) {
            xqc_interop_release(&app);
            return 1;
        }
        fprintf(stderr, "endpoint server moqt-22 UDP/%u (no relay)\n", port);
        while (!xqc_interop_stop) {
            xqc_interop_pump(&app, 10);
        }
        xqc_interop_release(&app);
        return 0;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    puts("TAP version 14");
    unsigned count = test ? 1 : ncases;
    printf("1..%u\n", count);
    if (!url) {
        url = "moqt://localhost:4443/";
    }
    int found = !test;
    for (unsigned i = 0; i < ncases; i++) {
        found |= test && !strcmp(test, xqc_interop_cases[i]);
    }
    if (!found) {
        puts("ok 1 - unsupported # SKIP test not implemented");
        return 127;
    }
    if (!strncmp(url, "https://", 8)) {
        unsigned index = 0;
        for (unsigned i = 0; i < ncases; i++) {
            if (!test || !strcmp(test, xqc_interop_cases[i])) {
                printf("ok %u - %s # SKIP WebTransport not implemented\n",
                       ++index, xqc_interop_cases[i]);
            }
        }
        return 127;
    }
    if (xqc_interop_url(&app, url)) {
        puts("Bail out! invalid/unsupported URL (IPv4 native QUIC)");
        return 1;
    }
    unsigned failed = 0, index = 0;
    for (unsigned i = 0; i < ncases; i++) {
        const char *name = xqc_interop_cases[i];
        if (test && strcmp(test, name)) {
            continue;
        }
        xqc_usec_t started = xqc_complex_case_now_us();
        int rc = xqc_interop_init(&app, 0) ? -1 : xqc_interop_run(&app, name);
        unsigned ready[3] = {0};
        const char *roles[3] = {0};
        unsigned peers = 0;
        for (xqc_interop_peer_t *p = app.peers; p; p = p->next) {
            rc = p->error ? -1 : rc;
            if (p->ready && peers < 3) {
                ready[peers] = p->ready;
                roles[peers++] = p->role;
            }
        }
        xqc_interop_release(&app);
        failed += rc != 0;
        printf("%s %u - %s\n  ---\n  duration_ms: %llu\n",
               rc ? "not ok" : "ok", ++index, name,
               (unsigned long long)(xqc_complex_case_now_us() - started)
                   / 1000);
        if (peers) {
            puts("  sessions:");
            for (unsigned j = 0; j < peers; j++) {
                if (ready[j]) {
                    printf("    %s:\n      transport: quic\n"
                           "      moqt_version: moqt-22\n", roles[j]);
                }
            }
        }
        puts("  ...");
        if (xqc_interop_stop) {
            puts("Bail out! interrupted");
            return 1;
        }
    }
    return failed ? 1 : 0;
}
