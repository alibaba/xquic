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
#ifdef XQC_ENABLE_WEBTRANSPORT
#include "include/moq/xqc_moqt_webtransport.h"
#endif

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
#ifdef XQC_ENABLE_WEBTRANSPORT
    xqc_h3_conn_t *h3;
    xqc_wt_session_t *wt;
#endif
    xqc_moqt_request_t *request, *sending;
    xqc_moqt_request_t *publications[2];
    xqc_moqt_subscription_t *subscription;
    xqc_moqt_stream_t *streams[2];
    xqc_interop_fixture_t fixture;
    xqc_interop_oracle_t oracle;
    xqc_interop_oracle_t fetch_oracle;
    xqc_interop_retention_t retention;
    xqc_moqt_fetch_t *fetch_sending;
    xqc_moqt_stream_t *fetch_stream;
    xqc_moqt_fetch_info_t fetched;
    xqc_moqt_location_t largest;
    unsigned history, available, paused, pause_at, has_largest;
    unsigned fetch_ready, fetch_closed, fetch_first, fetch_index, fetch_last;
    unsigned fetch_finished;
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
    unsigned peer_count, server, verify, verbose, webtransport;
    struct sockaddr_storage remote;
    socklen_t remote_len;
    char host[256], authority[300], path[1024];
    const char *cert, *key;
    xqc_usec_t deadline;
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
    "moq-test-increments", "moq-test-forward-zero",
    "publish-namespace-multi-publisher-retention", "fetch", "join"
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
static xqc_int_t xqc_interop_session_create(xqc_interop_peer_t *p,
    xqc_connection_t *conn);
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
static int xqc_interop_retention(xqc_interop_app_t *app, const char *run);
static int xqc_interop_history(xqc_interop_app_t *app, const char *name,
    const char *run);
static void xqc_interop_fetch_ready(xqc_moqt_fetch_t *fetch,
    xqc_moqt_subscription_t *sub, void *data);
static void xqc_interop_fetch_closed(xqc_moqt_fetch_t *fetch,
    const xqc_moqt_error_t *error, void *data);
static void xqc_interop_fetch_generate(xqc_interop_peer_t *p);
static int xqc_interop_fetch_end(xqc_interop_peer_t *p,
    const xqc_moqt_message_t *m, xqc_moqt_location_t *end);
static int xqc_interop_run_id(char run[33]);
#ifdef XQC_ENABLE_WEBTRANSPORT
static xqc_int_t xqc_interop_h3_created(xqc_h3_conn_t *h3,
    const xqc_cid_t *cid, void *data);
static xqc_int_t xqc_interop_h3_closed(xqc_h3_conn_t *h3,
    const xqc_cid_t *cid, void *data);
static int xqc_interop_wt_accept(xqc_http_headers_t *headers,
    xqc_http_headers_t *response, void *data);
static int xqc_interop_wt_ready(xqc_wt_session_t *wt,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *data);
static int xqc_interop_wt_closed(xqc_wt_session_t *wt,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *data);
#endif

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
    fprintf(stderr, "SETUP ready alpn=%s protocol=moqt-22 "
            "transport=%s role=%s\n",
            p->app->webtransport ? "h3" : "moqt-22",
            p->app->webtransport ? "webtransport" : "quic",
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
        || m->type == XQC_MOQT_MSG_FETCH_OK
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
                if (m->parameters[i].type == XQC_MOQT_PARAM_LARGEST_OBJECT) {
                    const uint8_t *v = m->parameters[i].value;
                    const uint8_t *end = v + m->parameters[i].length;
                    int n = xqc_vi64_read(v, end, &p->largest.group_id);
                    if (n < 0 || xqc_vi64_read(v + n, end,
                                                &p->largest.object_id) < 0)
                    {
                        p->error = 1;
                    } else {
                        p->has_largest = 1;
                    }
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
    unsigned char largest[18];
    if (m->type == XQC_MOQT_MSG_FETCH) {
        if (p->app->server && !p->history) {
            if (xqc_interop_fixture_parse(&m->track_namespace, &p->fixture)) {
                reply.type = XQC_MOQT_MSG_REQUEST_ERROR;
                reply.error.code = XQC_MOQT_REQUEST_DOES_NOT_EXIST;
            } else {
                p->available = xqc_interop_fixture_count(&p->fixture);
                p->history = 1;
            }
        }
        xqc_moqt_location_t end;
        if (!reply.type && (!p->history
                            || xqc_interop_fetch_end(p, m, &end)))
        {
            reply.type = XQC_MOQT_MSG_REQUEST_ERROR;
            reply.error.code = XQC_MOQT_REQUEST_INVALID_RANGE;
        } else if (!reply.type) {
            reply.type = XQC_MOQT_MSG_FETCH_OK;
            reply.end_group = end.group_id;
            reply.end_object = end.object_id;
        }
    } else if (m->type == XQC_MOQT_MSG_PUBLISH_NAMESPACE) {
        reply.type = XQC_MOQT_MSG_REQUEST_OK;
    } else if (m->type == XQC_MOQT_MSG_PUBLISH) {
        reply.type = XQC_MOQT_MSG_REQUEST_OK;
    } else if (m->type == XQC_MOQT_MSG_SUBSCRIBE) {
        if (!p->history
            && xqc_interop_fixture_parse(&m->track_namespace, &p->fixture)
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
                if (p->app->server && m->parameters[i].type
                                         == XQC_MOQT_PARAM_FILL_PARAMETERS)
                {
                    p->history = 1;
                    p->available = xqc_interop_fixture_count(&p->fixture);
                    p->group = p->fixture.last_group + p->fixture.group_step;
                }
            }
            if (p->history && p->available) {
                unsigned width = p->fixture.last_object
                    - p->fixture.first_object + 1;
                unsigned g = p->fixture.first_group
                    + (p->available - 1) / width;
                unsigned o = p->fixture.first_object
                    + (p->available - 1) % width;
                int n = xqc_vi64_write(largest, largest + sizeof(largest), g);
                n += xqc_vi64_write(largest + n,
                                      largest + sizeof(largest), o);
                reply.parameters[reply.parameter_count++] =
                    (xqc_moq_message_parameter_t){XQC_MOQT_PARAM_LARGEST_OBJECT,
                                                  n, largest};
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
        if (p->basic || p->app->server || p->history) {
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
    for (unsigned i = 0; i < 2; i++) {
        if (p->publications[i] == r) {
            p->publications[i] = NULL;
        }
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
    xqc_interop_oracle_t *oracle = stream && xqc_moqt_stream_fetch(stream)
        ? &p->fetch_oracle : &p->oracle;
    xqc_interop_oracle_object(oracle, object);
}

static void
xqc_interop_stream_closed(xqc_moqt_stream_t *stream,
    const xqc_moqt_object_t *last, const xqc_moqt_error_t *error, void *data)
{
    xqc_interop_peer_t *p = data;
    p->streams_closed++;
    p->streams_reset += error != NULL;
    if (p->fetch_stream == stream) {
        p->fetch_stream = NULL;
    }
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
    if (p->retention.run[0]) {
        xqc_interop_retention_event(&p->retention, ns, available);
    }
    if (available) {
        p->namespaces++;
    } else {
        p->removals++;
    }
}

static xqc_int_t
xqc_interop_session_create(xqc_interop_peer_t *p, xqc_connection_t *conn)
{
    xqc_moqt_config_t config;
    xqc_moqt_config_init(&config, XQC_MOQT_VERSION_DRAFT_22);
    xqc_moqt_kv_t opts[2] = {0};
    if (!p->app->server && !p->app->webtransport) {
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
        .on_fetch_ready = xqc_interop_fetch_ready,
        .on_fetch_closed = xqc_interop_fetch_closed,
    };
#ifdef XQC_ENABLE_WEBTRANSPORT
    if (p->app->webtransport) {
        /* Draft-22 6.2.1/9.1: CONNECT supplies authority/path for WT. */
        p->session = xqc_moqt_session_create_webtransport(p->wt,
            &config, &cbs, p);
    } else
#endif
    {
        p->session = xqc_moqt_session_create(conn, &config, &cbs, p);
    }
    return p->session == NULL ? XQC_ERROR : XQC_OK;
}

static xqc_int_t
xqc_interop_created(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *data, void *proto_data)
{
    return xqc_interop_session_create(data, conn);
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

#ifdef XQC_ENABLE_WEBTRANSPORT
static xqc_int_t
xqc_interop_h3_created(xqc_h3_conn_t *h3, const xqc_cid_t *cid, void *data)
{
    ((xqc_interop_peer_t *)data)->h3 = h3;
    return XQC_OK;
}

static xqc_int_t
xqc_interop_h3_closed(xqc_h3_conn_t *h3, const xqc_cid_t *cid, void *data)
{
    xqc_interop_peer_t *p = data;
    p->h3 = NULL;
    p->closed++;
    return XQC_OK;
}

static int
xqc_interop_wt_accept(xqc_http_headers_t *headers,
    xqc_http_headers_t *response, void *data)
{
    xqc_interop_peer_t *p = data;
    const char *protocols[] = {XQC_MOQT_ALPN_DRAFT_22}, *selected = NULL;
    /* Anonymous bounded test endpoint, one session per scenario peer. */
    if (p->wt || p->closed
        || xqc_wt_select_application_protocol(headers, protocols, 1,
                                                 &selected) != 1)
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
xqc_interop_wt_ready(xqc_wt_session_t *wt, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *data)
{
    xqc_interop_peer_t *p = data;
    if (p->wt) {
        return -XQC_ESTATE;
    }
    p->wt = wt;
    /* Draft-22 6.3: WT establishment is followed by both MoQT SETUPs. */
    if (xqc_interop_session_create(p, NULL) != XQC_OK
        || xqc_moqt_session_start(p->session) != XQC_OK)
    {
        p->error = 1;
        return -XQC_ESTATE;
    }
    return XQC_OK;
}

static int
xqc_interop_wt_closed(xqc_wt_session_t *wt, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *data)
{
    xqc_interop_peer_t *p = data;
    if (p->wt && p->wt != wt) {
        return XQC_OK;
    }
    p->wt = NULL;
    return xqc_interop_closed(NULL, cid, p, NULL);
}
#endif

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
#ifdef XQC_ENABLE_WEBTRANSPORT
    if (app->webtransport) {
        xqc_h3_callbacks_t h3 = {.h3c_cbs = {
            .h3_conn_create_notify = xqc_interop_h3_created,
            .h3_conn_close_notify = xqc_interop_h3_closed}};
        xqc_webtransport_session_callbacks_t sessions = {
            .webtransport_will_create_session_notify = xqc_interop_wt_accept,
            .webtransport_session_create_notify = xqc_interop_wt_ready,
            .webtransport_session_close_notify = xqc_interop_wt_closed,
        };
        xqc_webtransport_conn_settings_t wt = {
            .draft_version = XQC_WEBTRANSPORT_DRAFT_VERSION_16,
            .max_sessions_count = 1, .max_bidi_streams = 64,
            .max_uni_streams = 128, .init_recv_window = 65536,
            .enable_datagram = XQC_TRUE,
        };
        return xqc_h3_ctx_init(app->base.engine, &h3)
            || xqc_wt_ctx_init(app->base.engine, NULL, &sessions, NULL)
            || xqc_wt_engine_set_default_settings(app->base.engine, &wt);
    }
#endif
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
    xqc_conn_ssl_config_t ssl = {.cert_verify_flag = app->verify
        ? XQC_TLS_CERT_FLAG_NEED_VERIFY : 0};
    const xqc_cid_t *cid;
#ifdef XQC_ENABLE_WEBTRANSPORT
    if (app->webtransport) {
        cid = xqc_webtransport_connect(app->base.engine, &settings,
            NULL, 0, app->host, 0, &ssl,
            (struct sockaddr *)&app->remote, app->remote_len, p);
        const char *protocols[] = {XQC_MOQT_ALPN_DRAFT_22};
        int error;
        if (!cid || !p->h3
            || !xqc_wt_client_open_session_with_protocols(p->h3,
                app->authority, app->path, NULL, protocols, 1, &error))
        {
            return NULL;
        }
    } else
#endif
    {
        cid = xqc_moqt_connect(app->base.engine, &config, &settings,
            NULL, 0, app->host, &ssl,
            (struct sockaddr *)&app->remote, app->remote_len, p);
    }
    if (cid == NULL || xqc_interop_wait(app, &p->ready, 1,
                                       XQC_INTEROP_PHASE_MS))
    {
        return NULL;
    }
    return p;
}

static void
xqc_interop_fetch_ready(xqc_moqt_fetch_t *fetch,
    xqc_moqt_subscription_t *sub, void *data)
{
    xqc_interop_peer_t *p = data;
    const xqc_moqt_fetch_info_t *info = xqc_moqt_fetch_info(fetch);
    if (!p->history) {
        p->fetched = *info;
        p->fetch_ready++;
        return;
    }
    if (p->fetch_sending
        || xqc_interop_history_window(&p->fixture, p->available,
            &info->start, &info->end, &p->fetch_first, &p->fetch_last))
    {
        xqc_moqt_fetch_cancel(fetch, XQC_MOQT_RESET_INTERNAL_ERROR);
        p->error = 1;
        return;
    }
    p->fetched = *info;
    p->fetch_ready++;
    p->fetch_sending = fetch;
    p->fetch_stream = xqc_moqt_fetch_open(fetch);
    if (!p->fetch_stream) {
        fprintf(stderr, "FETCH source stream open failed\n");
        xqc_moqt_fetch_cancel(fetch, XQC_MOQT_RESET_INTERNAL_ERROR);
        p->error = 1;
        return;
    }
    unsigned width = p->fixture.last_object - p->fixture.first_object + 1;
    p->fetch_index = info->group_order == XQC_MOQT_GROUP_DESCENDING
        ? p->fetch_last / width * width : p->fetch_first;
    if (p->fetch_index < p->fetch_first) {
        p->fetch_index = p->fetch_first;
    }
    p->fetch_finished = 0;
    p->sent_streams += sub != NULL;
}

static void
xqc_interop_fetch_closed(xqc_moqt_fetch_t *fetch,
    const xqc_moqt_error_t *error, void *data)
{
    xqc_interop_peer_t *p = data;
    p->fetch_closed++;
    p->error |= error != NULL;
    if (p->fetch_sending == fetch) {
        p->fetch_sending = NULL;
        p->fetch_stream = NULL;
    }
}

static void
xqc_interop_fetch_generate(xqc_interop_peer_t *p)
{
    if (!p->fetch_stream || p->fetch_finished) {
        return;
    }
    const xqc_interop_fixture_t *f = &p->fixture;
    unsigned width = f->last_object - f->first_object + 1;
    unsigned g = f->first_group + p->fetch_index / width;
    unsigned id = f->first_object + p->fetch_index % width;
    unsigned size = id == f->first_object ? f->size0 : f->size;
    unsigned char payload[1024];
    memset(payload, 't', size);
    xqc_moqt_object_t object = {
        .group_id = g, .object_id = id,
        .priority = f->priority == 128 ? 128 : 200 + g % 2,
        .payload = {payload, size}, .payload_length = size,
    };
    int rc = xqc_moqt_stream_send_object(p->fetch_stream, &object);
    if (rc == -XQC_EAGAIN) {
        return;
    }
    if (rc != XQC_OK) {
        fprintf(stderr, "FETCH source send failed: %d at %u.%u\n", rc, g, id);
        p->error = 1;
        xqc_moqt_fetch_cancel(p->fetch_sending, XQC_MOQT_RESET_INTERNAL_ERROR);
        return;
    }
    if (p->fetched.group_order == XQC_MOQT_GROUP_DESCENDING) {
        unsigned group_first = p->fetch_index / width * width;
        unsigned group_last = group_first + width - 1;
        if (group_last > p->fetch_last) {
            group_last = p->fetch_last;
        }
        if (p->fetch_index < group_last) {
            p->fetch_index++;
            return;
        }
        if (group_first > p->fetch_first) {
            p->fetch_index = group_first - width;
            if (p->fetch_index < p->fetch_first) {
                p->fetch_index = p->fetch_first;
            }
            return;
        }
    } else if (p->fetch_index < p->fetch_last) {
        p->fetch_index++;
        return;
    }
    p->fetch_finished = 1;
    if (xqc_moqt_stream_finish(p->fetch_stream) != XQC_OK) {
        p->error = 1;
    }
}

static int
xqc_interop_fetch_end(xqc_interop_peer_t *p, const xqc_moqt_message_t *m,
    xqc_moqt_location_t *end)
{
    const xqc_interop_fixture_t *f = &p->fixture;
    if (!p->available || f->mode || f->markers || f->extensions) {
        return -1;
    }
    unsigned width = f->last_object - f->first_object + 1;
    *end = (xqc_moqt_location_t){
        f->first_group + (p->available - 1) / width,
        f->first_object + (p->available - 1) % width};
    xqc_moqt_location_t start = {f->first_group, f->first_object};
    for (size_t i = 0; i < m->parameter_count; i++) {
        if (m->parameters[i].type != XQC_MOQT_PARAM_LOCATION_FILTER) {
            continue;
        }
        const uint8_t *v = m->parameters[i].value;
        const uint8_t *limit = v + m->parameters[i].length;
        uint64_t fields[5] = {0};
        unsigned count = 0;
        while (v < limit) {
            if (count == 5) {
                return -1;
            }
            int n = xqc_vi64_read(v, limit, &fields[count++]);
            if (n < 0) {
                return -1;
            }
            v += n;
        }
        if (fields[0] == XQC_MOQT_FILTER_NEXT_OBJECT) {
            return -1;
        }
        if (fields[0] == XQC_MOQT_FILTER_RELATIVE_START) {
            start.group_id = !fields[1] ? end->group_id + 1
                : end->group_id >= fields[1] - 1
                  ? end->group_id - (fields[1] - 1) : 0;
        } else if (fields[0] >= XQC_MOQT_FILTER_ABSOLUTE_START) {
            start = (xqc_moqt_location_t){fields[1], fields[2]};
            if (fields[0] >= XQC_MOQT_FILTER_GROUP_END) {
                xqc_moqt_location_t requested = {
                    fields[1] + fields[3],
                    fields[0] == XQC_MOQT_FILTER_ABSOLUTE_RANGE
                        ? fields[4] : UINT64_MAX};
                if (requested.group_id < end->group_id
                    || (requested.group_id == end->group_id
                        && requested.object_id < end->object_id))
                {
                    *end = requested;
                }
            }
        }
    }
    unsigned first, last;
    if (xqc_interop_history_window(f, p->available, &start, end,
                                    &first, &last))
    {
        return -1;
    }
    /* draft-22 9.12: a definite inclusive end, also for whole-group filters. */
    *end = (xqc_moqt_location_t){f->first_group + last / width,
                                f->first_object + last % width};
    return 0;
}

static void
xqc_interop_generate(xqc_interop_peer_t *p)
{
    xqc_interop_fixture_t *f = &p->fixture;
    if (!p->generating || !p->subscription || !p->sending || p->paused
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
    if (p->history) {
        p->available++;
        if (p->available == p->pause_at) {
            p->paused = 1;
        }
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
            xqc_interop_fetch_generate(p);
            xqc_interop_generate(p);
        }
    } while (!xqc_interop_stop && xqc_complex_case_now_us() < deadline);
}

static int
xqc_interop_wait(xqc_interop_app_t *app, unsigned *value,
    unsigned target, unsigned ms)
{
    xqc_usec_t deadline = xqc_complex_case_now_us() + ms * 1000;
    if (app->deadline && app->deadline < deadline) {
        deadline = app->deadline;
    }
    while (*value < target && xqc_complex_case_now_us() < deadline
           && !xqc_interop_stop)
    {
        for (xqc_interop_peer_t *p = app->peers; p; p = p->next) {
            if (p->error || p->closed || p->retention.failed) {
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
    app->deadline = 0;
}

static int
xqc_interop_url(xqc_interop_app_t *app, const char *url)
{
    const char *start;
    if (!strncmp(url, "moqt://", 7)) {
        start = url + 7;
    } else if (!strncmp(url, "https://", 8)) {
        start = url + 8;
        app->webtransport = 1;
    } else {
        return -1;
    }
    const char *path = strpbrk(start, "/?#");
    const char *fragment = strchr(start, '#');
    size_t length = path ? (size_t)(path - start) : strlen(start);
    size_t path_len = path ? (fragment ? (size_t)(fragment - path)
                                         : strlen(path)) : 0;
    size_t leading = path_len && *path == '?' ? 1 : 0;
    if (!length || length >= sizeof(app->authority)
        || path_len + leading >= sizeof(app->path))
    {
        return -1;
    }
    memcpy(app->authority, start, length);
    app->authority[length] = 0;
    strcpy(app->path, "/");
    if (path_len) {
        memcpy(app->path + leading, path, path_len);
        app->path[path_len + leading] = 0;
    }
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
xqc_interop_run_id(char run[33])
{
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
    for (unsigned i = 0; i < sizeof(entropy); i++) {
        snprintf(run + 2 * i, 3, "%02x", entropy[i]);
    }
    return 0;
}

static int
xqc_interop_retention(xqc_interop_app_t *app, const char *run)
{
    app->deadline = xqc_complex_case_now_us() + 8000000;
    xqc_moqt_namespace_t prefix, shared, sync;
    xqc_interop_name(&prefix, "moq-test",
        "publish-namespace-multi-publisher-retention", run);
    shared = sync = prefix;
    shared.fields[shared.count++] = (struct iovec){"shared", 6};
    sync.fields[sync.count++] = (struct iovec){"sync", 4};
    xqc_interop_peer_t *observers[3] = {xqc_interop_connect(app, "observer")};
    if (!observers[0]) {
        return -1;
    }
    memcpy(observers[0]->retention.run, run, 33);
    if (xqc_interop_request(observers[0], XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE,
                              &prefix, NULL, 0, 0)
        || xqc_interop_wait(app, &observers[0]->response, 1, 5000)
        || observers[0]->response_type != XQC_MOQT_MSG_REQUEST_OK)
    {
        return -1;
    }
    xqc_interop_peer_t *first = xqc_interop_connect(app, "publisher_1");
    xqc_interop_peer_t *second = xqc_interop_connect(app, "publisher_2");
    if (!first || !second
        || xqc_interop_request(first, XQC_MOQT_MSG_PUBLISH_NAMESPACE,
                                 &shared, NULL, 0, 0)
        || xqc_interop_wait(app, &first->response, 1, 5000)
        || first->response_type != XQC_MOQT_MSG_REQUEST_OK
        || xqc_interop_wait(app, &observers[0]->retention.adds[0], 1, 5000))
    {
        return -1;
    }
    first->publications[0] = first->request;
    if (xqc_interop_request(second, XQC_MOQT_MSG_PUBLISH_NAMESPACE,
                              &shared, NULL, 0, 0)
        || xqc_interop_wait(app, &second->response, 1, 5000)
        || second->response_type != XQC_MOQT_MSG_REQUEST_OK)
    {
        return -1;
    }
    second->publications[0] = second->request;
    if (xqc_interop_request(second, XQC_MOQT_MSG_PUBLISH_NAMESPACE,
                              &sync, NULL, 0, 0)
        || xqc_interop_wait(app, &second->response, 1, 5000)
        || second->response_type != XQC_MOQT_MSG_REQUEST_OK
        || xqc_interop_wait(app, &observers[0]->retention.adds[1], 1, 5000)
        || !second->publications[0] || !second->request)
    {
        return -1;
    }
    second->publications[1] = second->request;
    xqc_moqt_request_cancel(second->publications[0], XQC_MOQT_RESET_CANCELLED);
    xqc_moqt_request_cancel(second->publications[1], XQC_MOQT_RESET_CANCELLED);
    /* The sync withdrawal is the barrier for the second publisher's exit. */
    if (xqc_interop_wait(app, &observers[0]->retention.removes[1], 1, 5000)) {
        return -1;
    }
    const char *roles[] = {"subscriber_1", "subscriber_2"};
    for (unsigned i = 1; i < 3; i++) {
        observers[i] = xqc_interop_connect(app, roles[i - 1]);
        if (!observers[i]) {
            return -1;
        }
        memcpy(observers[i]->retention.run, run, 33);
        if (xqc_interop_request(observers[i], XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE,
                                  &prefix, NULL, 0, 0)
            || xqc_interop_wait(app, &observers[i]->response, 1, 5000)
            || observers[i]->response_type != XQC_MOQT_MSG_REQUEST_OK
            || xqc_interop_wait(app, &observers[i]->retention.adds[0], 1, 5000)
            || observers[i]->retention.adds[1])
        {
            return -1;
        }
    }
    for (unsigned i = 0; i < 3; i++) {
        if (!observers[i]->retention.present[0]
            || observers[i]->retention.failed)
        {
            return -1;
        }
        observers[i]->retention.allow_remove = 1;
    }
    if (!first->publications[0]) {
        return -1;
    }
    xqc_moqt_request_cancel(first->publications[0], XQC_MOQT_RESET_CANCELLED);
    for (unsigned i = 0; i < 3; i++) {
        if (xqc_interop_wait(app, &observers[i]->retention.removes[0], 1, 5000)
            || observers[i]->retention.failed
            || (i && observers[i]->retention.adds[1]))
        {
            return -1;
        }
    }
    return 0;
}

static int
xqc_interop_history(xqc_interop_app_t *app, const char *name, const char *run)
{
    app->deadline = xqc_complex_case_now_us() + 15000000;
    int join = !strcmp(name, "join");
    xqc_moqt_namespace_t ns;
    xqc_interop_name(&ns, "moq-test", name, run);
    xqc_interop_peer_t *pub = xqc_interop_connect(app, "publisher");
    if (!pub) {
        return -1;
    }
    xqc_interop_fixture_case("data-subgroup-basic", &pub->fixture);
    pub->fixture.last_group = 5;
    pub->fixture.size = pub->fixture.size0;
    pub->fixture.pace_ms = 20;
    pub->history = 1;
    pub->pause_at = 11;
    if (xqc_interop_request(pub, XQC_MOQT_MSG_PUBLISH_NAMESPACE,
                              &ns, NULL, 0, 0)
        || xqc_interop_wait(app, &pub->response, 1, 5000)
        || pub->response_type != XQC_MOQT_MSG_REQUEST_OK)
    {
        return -1;
    }
    xqc_interop_peer_t *live = xqc_interop_connect(app, "subscriber");
    if (!live) {
        return -1;
    }
    live->oracle.fixture = pub->fixture;
    if (xqc_interop_request(live, XQC_MOQT_MSG_SUBSCRIBE, &ns, "track", 0, 0)
        || xqc_interop_wait(app, &live->response, 1, 5000)
        || live->response_type != XQC_MOQT_MSG_SUBSCRIBE_OK
        || xqc_interop_wait(app, &live->oracle.objects, 11, 5000)
        || live->oracle.failed || pub->available != 11)
    {
        return -1;
    }
    const char *role = join ? "joiner" : "fetcher";
    xqc_interop_peer_t *reader = xqc_interop_connect(app, role);
    if (!reader) {
        return -1;
    }
    reader->oracle.fixture = reader->fetch_oracle.fixture = pub->fixture;
    unsigned char order = 1, next = XQC_MOQT_FILTER_NEXT_OBJECT;
    unsigned char range[] = {XQC_MOQT_FILTER_ABSOLUTE_RANGE, 1, 0, 0, 4};
    /* draft-22 3.4/9.20.15: length + uncounted inner parameters. */
    unsigned char fill[] = {3, XQC_MOQT_PARAM_LOCATION_FILTER,
                            XQC_MOQT_FILTER_RELATIVE_START, 2};
    xqc_moqt_message_t m = {
        .type = join ? XQC_MOQT_MSG_SUBSCRIBE : XQC_MOQT_MSG_FETCH,
        .track_namespace = ns, .track_name = {"track", 5},
    };
    m.parameters[m.parameter_count++] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_LOCATION_FILTER, join ? 1 : sizeof(range),
        join ? &next : range};
    m.parameters[m.parameter_count++] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_GROUP_ORDER, 1, &order};
    if (join) {
        m.parameters[m.parameter_count++] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_FILL_PARAMETERS, sizeof(fill), fill};
    }
    reader->request = xqc_moqt_request_open(reader->session, &m);
    if (!reader->request
        || xqc_interop_wait(app, &reader->response, 1, 5000)
        || reader->response_type != (join ? XQC_MOQT_MSG_SUBSCRIBE_OK
                                          : XQC_MOQT_MSG_FETCH_OK))
    {
        return -1;
    }
    pub->paused = 0;
    if (xqc_interop_wait(app, &reader->fetch_closed, 1, 5000)
        || reader->fetch_ready != 1)
    {
        return -1;
    }
    xqc_moqt_location_t start = {1, 0}, end = {1, 4};
    if (join) {
        if (!reader->has_largest || reader->largest.group_id != 2
            || reader->largest.object_id != 0)
        {
            return -1;
        }
        end = reader->largest;
    }
    if (reader->fetched.start.group_id != start.group_id
        || reader->fetched.start.object_id != start.object_id
        || reader->fetched.end.group_id != end.group_id
        || reader->fetched.end.object_id != end.object_id
        || !xqc_interop_history_complete(&reader->fetch_oracle, &start, &end)
        || xqc_interop_wait(app, &live->done, 1, 5000)
        || !xqc_interop_oracle_complete(&live->oracle, 0))
    {
        return -1;
    }
    if (join) {
        start = (xqc_moqt_location_t){2, 1};
        end = (xqc_moqt_location_t){5, 4};
        if (xqc_interop_wait(app, &reader->done, 1, 5000)
            || !xqc_interop_history_complete(&reader->oracle, &start, &end))
        {
            return -1;
        }
    }
    fprintf(stderr, "%s history=%u live=%u fetch_fin=%u bad=%u\n", name,
        reader->fetch_oracle.objects, join ? reader->oracle.objects
                                          : live->oracle.objects,
        reader->fetch_closed, reader->fetch_oracle.failed);
    return reader->error || live->error || pub->error ? -1 : 0;
}

static int
xqc_interop_run(xqc_interop_app_t *app, const char *name)
{
    if (!strcmp(name, "publish-namespace-multi-publisher-retention")
        || !strcmp(name, "fetch") || !strcmp(name, "join"))
    {
        char run[33];
        if (xqc_interop_run_id(run)) {
            return -1;
        }
        return !strcmp(name, "publish-namespace-multi-publisher-retention")
            ? xqc_interop_retention(app, run)
            : xqc_interop_history(app, name, run);
    }
    int fixture = !xqc_interop_fixture_case(name,
                                            &(xqc_interop_fixture_t){0});
    int pub_data = !strcmp(name, "publish-track-subscribe");
    int data = fixture || pub_data;
    int basic = !strcmp(name, "data-subgroup-basic");
    int vectors = fixture && !basic;
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
    char run[33];
    if (xqc_interop_run_id(run)) {
        return -1;
    }
    xqc_moqt_namespace_t ns;
    xqc_interop_name(&ns, "moq-test", basic ? name : "interop", run);
    char fields[15][24];
    if (data) {
        xqc_interop_fixture_case(pub_data ? "data-subgroup-basic" : name,
                                  &p->fixture);
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
            || p->response_error == XQC_MOQT_REQUEST_INTERNAL_ERROR
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
            return s->response_error == XQC_MOQT_REQUEST_INTERNAL_ERROR
                ? -1 : 0;
        }
        if (s->response_type != XQC_MOQT_MSG_SUBSCRIBE_OK) {
            return -1;
        }
    }
    if (vectors || publish) {
        p->sending = p->request;
        if (vectors || pub_data) {
            if (pub_data && xqc_interop_wait(app, &p->forward, 1,
                                              XQC_INTEROP_PHASE_MS))
            {
                return -1;
            }
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
    const char *transport = getenv("MOQT_TRANSPORT");
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
        {"transport", required_argument, NULL, 'T'},
        {"help", no_argument, NULL, 'h'}, {0}
    };
    unsigned ncases = sizeof(xqc_interop_cases) / sizeof(xqc_interop_cases[0]);
    int c;
    while ((c = getopt_long(argc, argv, "r:t:lvksp:c:K:T:h",
                           opts, NULL)) != -1)
    {
        switch (c) {
        case 'r': url = optarg; break;
        case 't': test = optarg; break;
        case 'v': app.verbose = 1; break;
        case 'k': app.verify = 0; break;
        case 's': app.server = 1; break;
        case 'p': port = strtoul(optarg, NULL, 10); break;
        case 'c': app.cert = optarg; break;
        case 'K': app.key = optarg; break;
        case 'T': transport = optarg; break;
        case 'l':
            for (unsigned i = 0; i < ncases; i++) {
                puts(xqc_interop_cases[i]);
            }
            return 0;
        case 'h':
            puts("moqt_interop --relay URL [--test NAME]\n"
                 "  --list --tls-disable-verify --verbose\n"
                 "  --transport quic|webtransport (HTTPS selects WT)\n"
                 "  --server [--port 4443 --cert FILE --key FILE]");
            return 0;
        default: return 1;
        }
    }
    signal(SIGINT, xqc_interop_signal);
    signal(SIGTERM, xqc_interop_signal);
    if (transport && strcmp(transport, "quic")
        && strcmp(transport, "webtransport"))
    {
        fprintf(stderr, "invalid transport: %s\n", transport);
        return 1;
    }
    app.webtransport = transport && !strcmp(transport, "webtransport");
    if (app.server) {
#ifndef XQC_ENABLE_WEBTRANSPORT
        if (app.webtransport) {
            fprintf(stderr, "WebTransport is disabled in this build\n");
            return 127;
        }
#endif
        if (!port || port > 65535 || xqc_interop_init(&app, port)) {
            xqc_interop_release(&app);
            return 1;
        }
        fprintf(stderr, "endpoint server moqt-22 transport=%s UDP/%u "
                "(no relay)\n", app.webtransport ? "webtransport" : "quic",
                port);
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
    if (transport && !strcmp(transport, "quic")
        && !strncmp(url, "https://", 8))
    {
        puts("Bail out! HTTPS requires WebTransport");
        return 1;
    }
    if (xqc_interop_url(&app, url)) {
        puts("Bail out! invalid/unsupported URL (IPv4)");
        return 1;
    }
#ifndef XQC_ENABLE_WEBTRANSPORT
    if (app.webtransport) {
        unsigned index = 0;
        for (unsigned i = 0; i < ncases; i++) {
            if (!test || !strcmp(test, xqc_interop_cases[i])) {
                printf("ok %u - %s # SKIP WebTransport disabled in build\n",
                       ++index, xqc_interop_cases[i]);
            }
        }
        return 127;
    }
#endif
    unsigned failed = 0, index = 0;
    for (unsigned i = 0; i < ncases; i++) {
        const char *name = xqc_interop_cases[i];
        if (test && strcmp(test, name)) {
            continue;
        }
        xqc_usec_t started = xqc_complex_case_now_us();
        int rc = xqc_interop_init(&app, 0) ? -1 : xqc_interop_run(&app, name);
        unsigned ready[XQC_INTEROP_MAX_PEERS] = {0};
        const char *roles[XQC_INTEROP_MAX_PEERS] = {0};
        unsigned peers = 0;
        for (xqc_interop_peer_t *p = app.peers; p; p = p->next) {
            rc = p->error || p->retention.failed ? -1 : rc;
            if (p->ready && peers < XQC_INTEROP_MAX_PEERS) {
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
                    printf("    %s:\n      transport: %s\n"
                           "      moqt_version: moqt-22\n", roles[j],
                           app.webtransport ? "webtransport" : "quic");
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
