/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <xquic/xqc_webtransport.h>
#include "complex_case_common.h"
#include "src/common/xqc_priority_q.h"
#include "src/transport/xqc_engine.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_request.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_session.h"

typedef struct {
    xqc_complex_case_engine_t base;
    xqc_h3_conn_t            *h3;
    xqc_wt_session_t         *session;
    int                       server;
    int                       draft07;
    int                       settings_full;
    int                       missing_datagram;
    int                       pending_reject;
    int                       session_limit;
    int                       reset_credit;
    int                       http_message_errors;
    int                       http_received;
    int                       ready;
    int                       closed;
    int                       drained;
    int                       bidi_fin;
    int                       uni_fin;
    int                       reset;
    int                       failed;
    unsigned                  status;
    uint32_t                  close_error;
    size_t                    bidi_bytes;
    size_t                    uni_bytes;
    size_t                    dgram_bytes;
    int                       conn_closed;
    int                       abrupt_close;
    int                       bidi_created;
    int                       bidi_closed;
    int                       unread;
    char                      close_reason[32];
    xqc_int_t                 conn_error;
    xqc_conn_err_type_t        conn_error_type;
} wt_endpoint_t;

static void wt_init_settings(xqc_h3_conn_t *h3,
    xqc_h3_conn_settings_t *settings, void *data);
static int wt_http_create(xqc_h3_request_t *request, void *data);
static int wt_http_read(xqc_h3_request_t *request,
    xqc_request_notify_flag_t flags, void *data);
static void wt_http_closing(xqc_h3_request_t *request,
    xqc_int_t error, void *data);
static int wt_bidi_created(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *data);
static int wt_bidi_closed(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *data);
static int wt_close_endpoint(int server, int fd, const char *mode, int legacy);
static int wt_abrupt_close(const char *mode, int legacy);
static int wt_fd_transfer(int fd, void *data, size_t len, int send);

static const char wt_payload[] = "webtransport-16-loopback";

#define WT_CHECK(expr)                                                        \
    do {                                                                     \
        if (!(expr)) {                                                       \
            fprintf(stderr, "line %d: %s\n", __LINE__, #expr);                 \
            goto fail;                                                       \
        }                                                                    \
    } while (0)

static int
wt_accept(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *data)
{
    xqc_conn_set_transport_user_data(conn, data);
    return XQC_OK;
}

static int
wt_conn_create(xqc_h3_conn_t *h3, const xqc_cid_t *cid, void *data)
{
    wt_endpoint_t *ep = data;
    ep->h3 = h3;
    if (ep->missing_datagram) {
        return xqc_h3_conn_settings_add_extern(&h3->local_h3_conn_settings,
                                               XQC_WT_SETTING_DATAGRAM, 0);
    }
    return XQC_OK;
}

static int
wt_conn_close(xqc_h3_conn_t *h3, const xqc_cid_t *cid, void *data)
{
    wt_endpoint_t *ep = data;
    ep->conn_error = xqc_conn_get_errno(h3->conn);
    ep->conn_error_type = xqc_conn_get_err_type(h3->conn);
    snprintf(ep->close_reason, sizeof(ep->close_reason), "%s",
             h3->conn->conn_close_msg ? h3->conn->conn_close_msg : "");
    ep->conn_closed++;
    ep->h3 = NULL;
    return XQC_OK;
}

static int
wt_session_accept(xqc_http_headers_t *headers, xqc_http_headers_t *response,
    void *data)
{
    wt_endpoint_t *ep = data;
    if (!ep || !ep->server || !ep->h3) {
        return 0;
    }
    /* draft-ietf-webtrans-http3-16 Section 3.2: check browser origins. */
    for (size_t i = 0; i < headers->count; i++) {
        xqc_http_header_t *h = &headers->headers[i];
        if (h->name.iov_len == 6 && !memcmp(h->name.iov_base, "origin", 6)) {
            return h->value.iov_len == 20
                && !memcmp(h->value.iov_base, "https://allowed.test", 20);
        }
    }
    return 0;
}

static int
wt_session_ready(xqc_wt_session_t *session, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *data)
{
    wt_endpoint_t *ep = data;
    ep->session = session;
    ep->ready++;
    ep->status = xqc_wt_session_get_response_status(session);
    return XQC_OK;
}

static int
wt_session_closed(xqc_wt_session_t *session, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *data)
{
    wt_endpoint_t *ep = data;
    ep->status = xqc_wt_session_get_response_status(session);
    ep->close_error = xqc_wt_session_get_close_error_code(session);
    ep->closed++;
    ep->session = NULL;
    return XQC_OK;
}

static void
wt_session_drained(xqc_wt_session_t *session, void *data)
{
    wt_endpoint_t *ep = data;
    ep->drained++;
}

static wt_endpoint_t *
wt_endpoint(xqc_wt_session_t *session)
{
    return xqc_h3_conn_get_user_data(xqc_wt_session_get_h3_conn(session));
}

static void
wt_check_payload(wt_endpoint_t *ep, const void *data, size_t len,
    size_t *received)
{
    if (*received + len > sizeof(wt_payload)
        || memcmp(data, wt_payload + *received, len))
    {
        ep->failed = 1;
        return;
    }
    *received += len;
}

static int
wt_bidi_read(xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *data, size_t len, void *stream_data)
{
    wt_endpoint_t *ep = wt_endpoint(session);
    if (ep->abrupt_close) {
        ep->bidi_fin |= xqc_wt_bidistream_get_recv_fin(stream);
        ep->unread = len > 0;
        return -XQC_EAGAIN;
    }
    wt_check_payload(ep, data, len, &ep->bidi_bytes);
    ep->bidi_fin |= xqc_wt_bidistream_get_recv_fin(stream);
    return XQC_OK;
}

static int
wt_bidi_created(xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *data)
{
    wt_endpoint(session)->bidi_created++;
    return XQC_OK;
}

static int
wt_bidi_closed(xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *data)
{
    wt_endpoint(session)->bidi_closed++;
    return XQC_OK;
}

static int
wt_uni_read(xqc_wt_unistream_t *stream, xqc_wt_session_t *session,
    void *data, size_t len, void *stream_data)
{
    wt_endpoint_t *ep = wt_endpoint(session);
    wt_check_payload(ep, data, len, &ep->uni_bytes);
    ep->uni_fin |= xqc_wt_unistream_get_recv_fin(stream);
    return XQC_OK;
}

static void
wt_datagram_read(xqc_wt_session_t *session, const void *data, size_t len,
    void *user_data, uint64_t recv_time)
{
    wt_endpoint_t *ep = wt_endpoint(session);
    wt_check_payload(ep, data, len, &ep->dgram_bytes);
}

static int
wt_bidi_closing(xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *stream_data)
{
    wt_endpoint_t *ep = wt_endpoint(session);
    uint32_t error = 0;
    if (!xqc_wt_bidistream_closing_is_stop_sending(stream)
        && xqc_wt_bidistream_get_recv_error_code(stream, &error)
        && error == 42)
    {
        ep->reset++;
    }
    return XQC_OK;
}

static void
wt_init_settings(xqc_h3_conn_t *h3,
    xqc_h3_conn_settings_t *settings, void *data)
{
    wt_endpoint_t *ep = data;
    if (ep->settings_full) {
        for (size_t i = 0; i < XQC_H3_MAX_EXTERN_SETTINGS; i++) {
            if (xqc_h3_conn_settings_add_extern(settings, 0x100 + i, 7)
                != XQC_OK)
            {
                ep->failed = 1;
            }
        }
    }
}

static int
wt_http_create(xqc_h3_request_t *request, void *data)
{
    xqc_h3_request_set_user_data(request,
                                 xqc_h3_get_conn_user_data_by_request(request));
    return XQC_OK;
}

static int
wt_http_read(xqc_h3_request_t *request,
    xqc_request_notify_flag_t flags, void *data)
{
    wt_endpoint_t *ep = data;
    uint8_t fin = 0;
    if (!(flags & XQC_REQ_NOTIFY_READ_HEADER)) {
        return XQC_OK;
    }
    xqc_http_headers_t *headers = xqc_h3_request_recv_headers(request, &fin);
    if (headers == NULL) {
        return -XQC_ESTATE;
    }
    const char *name = ep->server ? ":method" : ":status";
    const char *value = ep->server ? "GET" : "200";
    for (size_t i = 0; i < headers->count; i++) {
        xqc_http_header_t *field = &headers->headers[i];
        if (field->name.iov_len == strlen(name)
            && !memcmp(field->name.iov_base, name, strlen(name))
            && field->value.iov_len == strlen(value)
            && !memcmp(field->value.iov_base, value, strlen(value)))
        {
            ep->http_received++;
        }
    }
    if (ep->server) {
        xqc_http_header_t field = {
            .name = {(void *)":status", 7}, .value = {(void *)"200", 3},
        };
        xqc_http_headers_t response = {.headers = &field, .count = 1};
        return xqc_h3_request_send_headers(request, &response, 1) < 0
            ? -XQC_ESTATE : XQC_OK;
    }
    return XQC_OK;
}

static int
wt_engine_init(wt_endpoint_t *ep, xqc_engine_type_t type, int no_reset)
{
    xqc_config_t config;
    xqc_engine_ssl_config_t ssl = {0};
    xqc_engine_callback_t engine_cbs;
    xqc_transport_callbacks_t transport_cbs;
    struct sockaddr_in addr = {0};
    xqc_h3_callbacks_t h3;
    xqc_webtransport_session_callbacks_t sessions = {0};
    xqc_webtransport_stream_callbacks_t streams = {0};
    xqc_webtransport_dgram_callbacks_t dgrams = {0};

    xqc_memzero(&h3, sizeof(h3));
    ep->server = type == XQC_ENGINE_SERVER;
    ep->base.socket.fd = -1;
    ep->base.user_data = ep;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (xqc_complex_case_make_socket(
        &ep->base, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        perror("WebTransport loopback socket");
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
    xqc_complex_case_init_transport_callbacks(&transport_cbs);
    transport_cbs.server_accept = wt_accept;
    ep->base.engine = xqc_engine_create(type, &config, &ssl, &engine_cbs,
                                        &transport_cbs, ep);
    if (!ep->base.engine) {
        return -1;
    }
    h3.h3c_cbs.h3_conn_create_notify = wt_conn_create;
    h3.h3c_cbs.h3_conn_close_notify = wt_conn_close;
    h3.h3c_cbs.h3_conn_init_settings = wt_init_settings;
    h3.h3r_cbs.h3_request_create_notify = wt_http_create;
    h3.h3r_cbs.h3_request_read_notify = wt_http_read;
    h3.h3r_cbs.h3_request_closing_notify = wt_http_closing;
    sessions.webtransport_will_create_session_notify = wt_session_accept;
    sessions.webtransport_session_create_notify = wt_session_ready;
    sessions.webtransport_session_close_notify = wt_session_closed;
    sessions.webtransport_session_drain_notify = wt_session_drained;
    streams.wt_bidistream_read_notify = wt_bidi_read;
    streams.wt_unistream_read_notify = wt_uni_read;
    streams.wt_bidistream_closing_notify = wt_bidi_closing;
    streams.wt_bidistream_create_notify = wt_bidi_created;
    streams.wt_bidistream_close_notify = wt_bidi_closed;
    dgrams.dgram_read_notify = wt_datagram_read;
    if (xqc_h3_ctx_init(ep->base.engine, &h3) != XQC_OK
        || xqc_wt_ctx_init(ep->base.engine, &dgrams, &sessions, &streams)
            != XQC_OK)
    {
        return -1;
    }
    if (ep->draft07) {
        xqc_webtransport_conn_settings_t settings =
            xqc_wt_ctx_get(ep->base.engine)->settings;
        settings.draft_version = XQC_WEBTRANSPORT_DRAFT_VERSION_7;
        if (xqc_wt_engine_set_default_settings(ep->base.engine, &settings)
            != XQC_OK)
        {
            return -1;
        }
    }
    if (no_reset) {
        xqc_conn_settings_t settings = ep->base.engine->default_conn_settings;
        settings.enable_reset_stream_at = 0;
        xqc_server_set_conn_settings(ep->base.engine, &settings);
    }
    if (ep->session_limit || ep->reset_credit) {
        xqc_webtransport_conn_settings_t settings =
            xqc_wt_ctx_get(ep->base.engine)->settings;
        settings.max_sessions_count = ep->reset_credit ? 2
            : ep->server ? 65 : 66;
        if (ep->reset_credit) {
            settings.init_recv_window = 32;
        }
        if (xqc_wt_engine_set_default_settings(ep->base.engine, &settings)
            != XQC_OK)
        {
            return -1;
        }
    }
    if (ep->pending_reject) {
        xqc_webtransport_conn_settings_t settings =
            xqc_wt_ctx_get(ep->base.engine)->settings;
        settings.max_sessions_count = 2;
        if (xqc_wt_engine_set_default_settings(ep->base.engine, &settings)
            != XQC_OK
            || xqc_wt_ctx_set_pending_datagram_policy(
                ep->base.engine, 8, 1, sizeof(wt_payload)) != XQC_OK)
        {
            return -1;
        }
    }
    if (ep->abrupt_close) {
        xqc_conn_settings_t settings = ep->base.engine->default_conn_settings;
        settings.idle_time_out = 5000;
        settings.init_idle_time_out = 8000;
        settings.ping_on = 0;
        xqc_server_set_conn_settings(ep->base.engine, &settings);
    }
    return 0;
}

static void
wt_http_closing(xqc_h3_request_t *request, xqc_int_t error, void *data)
{
    wt_endpoint_t *ep = data;
    if (error == H3_MESSAGE_ERROR) {
        ep->http_message_errors++;
    }
}

static int
wt_fd_transfer(int fd, void *data, size_t len, int send)
{
    size_t offset = 0;
    while (offset < len) {
        ssize_t n = send ? write(fd, (char *)data + offset, len - offset)
                         : read(fd, (char *)data + offset, len - offset);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return -1;
        }
        offset += n;
    }
    return 0;
}

static int
wt_close_endpoint(int server, int fd, const char *mode, int legacy)
{
    wt_endpoint_t ep;
    xqc_memzero(&ep, sizeof(ep));
    xqc_complex_case_engine_t *engines[] = {&ep.base};
    struct sockaddr_storage peer;
    xqc_conn_ssl_config_t ssl = {0};
    int err = 0, rc = 1;
    char ready = 1;
    int peer_ready = 0;
    int initiator = !strcmp(mode, server ? "close-server" : "close-client");
    int exits = !strcmp(mode, server ? "exit-server" : "exit-client");
    int idle = !strcmp(mode, "idle") || !strncmp(mode, "exit-", 5);

    ep.base.socket.fd = -1;
    ep.abrupt_close = 1;
    ep.draft07 = legacy;
    WT_CHECK(wt_engine_init(&ep,
        server ? XQC_ENGINE_SERVER : XQC_ENGINE_CLIENT, 0) == 0);
    if (server) {
        WT_CHECK(wt_fd_transfer(fd, &ep.base.local, sizeof(peer), 1) == 0);
    } else {
        WT_CHECK(wt_fd_transfer(fd, &peer, sizeof(peer), 0) == 0);
        WT_CHECK(xqc_webtransport_connect(ep.base.engine,
            &ep.base.engine->default_conn_settings, NULL, 0, "localhost", 0,
            &ssl, (struct sockaddr *)&peer, sizeof(struct sockaddr_in), &ep)
            != NULL);
        WT_CHECK(xqc_wt_client_open_session(ep.h3, "localhost", "/wt",
            "https://allowed.test", &err) != NULL);
    }
    for (int i = 0; i < 300 && !ep.ready && !ep.conn_closed; i++) {
        xqc_complex_case_pump(engines, 1, 10);
    }
    WT_CHECK(ep.ready == 1 && ep.session && !ep.closed);
    WT_CHECK(ep.session->wt_conn->negotiated_version
        == (legacy ? XQC_WEBTRANSPORT_DRAFT_VERSION_7
                   : XQC_WEBTRANSPORT_DRAFT_VERSION_16));
    xqc_wt_bidistream_t *bidi = xqc_wt_session_create_bidi_stream(
        ep.session, NULL, &err);
    WT_CHECK(bidi != NULL);
    WT_CHECK(xqc_wt_bidistream_send(bidi, wt_payload, sizeof(wt_payload), 0)
        == sizeof(wt_payload));
    for (int i = 0; i < 300 && !ep.unread && !ep.conn_closed; i++) {
        xqc_complex_case_pump(engines, 1, 10);
    }
    fprintf(stderr, "%s: unread=%d created=%d closed=%d conn_closed=%d\n",
            server ? "server" : "client", ep.unread, ep.bidi_created,
            ep.bidi_closed, ep.conn_closed);
    WT_CHECK(ep.unread && ep.bidi_created == 2 && !ep.bidi_closed);
    WT_CHECK(ep.bidi_bytes == 0 && !ep.bidi_fin && !ep.closed);
    /* Both peers must retain unread data before either one terminates. */
    WT_CHECK(wt_fd_transfer(fd, &ready, sizeof(ready), 1) == 0);
    for (int i = 0; i < 300 && !peer_ready; i++) {
        ssize_t n = recv(fd, &ready, sizeof(ready), MSG_DONTWAIT);
        if (n == sizeof(ready)) {
            peer_ready = 1;
            break;
        }
        WT_CHECK(n < 0 && (errno == EAGAIN || errno == EINTR));
        xqc_complex_case_pump(engines, 1, 10);
    }
    WT_CHECK(peer_ready);
    close(fd);
    fd = -1;
    printf("%s: ready with two open bidi streams and unread data\n",
           server ? "server" : "client");
    if (exits) {
        /* A real peer process disappears without session/connection cleanup. */
        _exit(42);
    }
    if (initiator) {
        WT_CHECK(xqc_h3_conn_close(ep.base.engine,
            &ep.h3->conn->scid_set.user_scid) == XQC_OK);
    }
    /* RFC 9000 Sections 10.1/10.2: open streams do not defer termination. */
    for (int i = 0; i < 500 && !ep.conn_closed; i++) {
        xqc_complex_case_pump(engines, 1, 10);
    }
    WT_CHECK(ep.conn_closed == 1 && ep.closed == 1 && ep.bidi_closed == 2);
    WT_CHECK(!ep.failed && ep.conn_error == 0);
    WT_CHECK(!strcmp(ep.close_reason,
        idle ? "idle timeout" : initiator ? "local close" : "remote close"));
    WT_CHECK(xqc_pq_empty(ep.base.engine->conns_active_pq));
    WT_CHECK(xqc_pq_empty(ep.base.engine->conns_wait_wakeup_pq));
    xqc_complex_case_pump(engines, 1, 30);
    WT_CHECK(ep.conn_closed == 1 && ep.closed == 1 && ep.bidi_closed == 2);
    printf("%s: %s; callbacks once; engine queues empty\n",
           server ? "server" : "client", ep.close_reason);
    xqc_complex_case_engine_release(&ep.base);
    rc = 0;
fail:
    if (fd >= 0) {
        close(fd);
    }
    /* The owning child exits on failure; do not mask it in teardown. */
    return rc;
}

static int
wt_abrupt_close(const char *mode, int legacy)
{
    int fds[2], rc = 1, status[2] = {0}, done[2] = {0};
    pid_t children[2] = {-1, -1};
    WT_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    for (int i = 0; i < 2; i++) {
        children[i] = fork();
        if (children[i] == 0) {
            close(fds[i]);
            _exit(wt_close_endpoint(!i, fds[1 - i], mode, legacy));
        }
        if (children[i] < 0) {
            close(fds[0]);
            close(fds[1]);
            goto fail;
        }
    }
    close(fds[0]);
    close(fds[1]);
    for (int i = 0; i < 2000 && (!done[0] || !done[1]); i++) {
        for (int j = 0; j < 2; j++) {
            if (!done[j]) {
                done[j] = waitpid(children[j], &status[j], WNOHANG)
                    == children[j];
            }
        }
        usleep(10000);
    }
    for (int i = 0; i < 2; i++) {
        int expected = !strcmp(mode, i ? "exit-client" : "exit-server")
            ? 42 : 0;
        fprintf(stderr, "%s process: status=%d expected_exit=%d\n",
                i ? "client" : "server", status[i], expected);
        WT_CHECK(done[i] && WIFEXITED(status[i])
            && WEXITSTATUS(status[i]) == expected);
    }
    rc = 0;
fail:
    for (int i = 0; i < 2; i++) {
        if (children[i] > 0 && !done[i]) {
            kill(children[i], SIGKILL);
            waitpid(children[i], NULL, 0);
        }
    }
    printf("webtransport %s%s: %s\n", legacy ? "draft07-" : "", mode,
           rc == 0 ? "pass" : "fail");
    return rc;
}

int
main(int argc, char **argv)
{
    wt_endpoint_t client, server;
    xqc_complex_case_engine_t *engines[] = {&client.base, &server.base};
    xqc_conn_ssl_config_t ssl = {0};
    xqc_wt_bidistream_t *bidi;
    xqc_wt_unistream_t *uni;
    int err = 0, rc = 1;
    const char *mode = argc == 2 ? argv[1] : "";
    int legacy = !strncmp(mode, "draft07-", 8);
    if (legacy) {
        mode += 8;
    }
    if (!strcmp(mode, "close-client") || !strcmp(mode, "close-server")
        || !strcmp(mode, "idle") || !strcmp(mode, "exit-client")
        || !strcmp(mode, "exit-server"))
    {
        setbuf(stdout, NULL);
        return wt_abrupt_close(mode, legacy);
    }
    int legacy_client = legacy && !strcmp(mode, "client");
    if (legacy_client || (legacy && !strcmp(mode, "server"))) {
        mode = "transfer";
    }
    int reject = !strcmp(mode, "reject-origin");
    int no_reset = !strcmp(mode, "missing-reset");
    int misplaced = !strcmp(mode, "misplaced-stream-type");
    int capacity = !strcmp(mode, "settings-capacity");
    int no_datagram = !strcmp(mode, "missing-datagram");
    int pending = !strcmp(mode, "pending-datagram-reject");
    int limit = !strcmp(mode, "session-limit");
    int credit = !strcmp(mode, "reset-credit");
    int pseudo = !strcmp(mode, "connect-pseudo-headers");

    xqc_memzero(&client, sizeof(client));
    xqc_memzero(&server, sizeof(server));
    client.base.socket.fd = server.base.socket.fd = -1;
    server.draft07 = legacy && !legacy_client;
    client.draft07 = legacy_client;
    server.settings_full = capacity;
    server.missing_datagram = no_datagram;
    client.pending_reject = server.pending_reject = pending;
    client.session_limit = server.session_limit = limit;
    client.reset_credit = server.reset_credit = credit;
    WT_CHECK(argc == 2
        && (reject || no_reset || misplaced || capacity
            || no_datagram || pending || limit || credit || pseudo
            || !strcmp(mode, "transfer")));
    WT_CHECK(wt_engine_init(&server, XQC_ENGINE_SERVER, no_reset) == 0);
    WT_CHECK(wt_engine_init(&client, XQC_ENGINE_CLIENT, 0) == 0);
    const xqc_cid_t *cid = xqc_webtransport_connect(
        client.base.engine,
        &client.base.engine->default_conn_settings, NULL, 0, "localhost", 0,
        &ssl, (struct sockaddr *)&server.base.local, server.base.locallen,
        &client);
    WT_CHECK(cid != NULL && client.h3 != NULL);
    /* Open before SETTINGS to exercise delayed CONNECT transmission. */
    client.session = xqc_wt_client_open_session(
        client.h3, "localhost", "/wt",
        reject ? "https://denied.test" : "https://allowed.test", &err);
    WT_CHECK(client.session != NULL && err == XQC_OK);
    for (int i = 0; i < 100 && !client.ready && !client.closed; i++) {
        xqc_complex_case_pump(engines, 2, 10);
    }
    if (reject || no_reset || no_datagram || capacity) {
        /* draft-ietf-webtrans-http3-16 Sections 3.1 and 3.2. */
        WT_CHECK(client.ready == 0 && server.ready == 0);
        WT_CHECK(client.closed == 1);
        WT_CHECK(no_reset || no_datagram || capacity || client.status == 403);
        if (no_datagram || capacity) {
            /* Draft-16 Section 3.1: ordinary H3 survives WT unavailability. */
            WT_CHECK(client.close_error == XQC_WT_REQUIREMENTS_NOT_MET);
            WT_CHECK(client.h3 && server.h3 && !server.failed);
            if (capacity) {
                WT_CHECK(xqc_wt_get_conn_from_h3(server.h3) == NULL);
                WT_CHECK(server.h3->local_h3_conn_settings.extern_settings_count
                    == XQC_H3_MAX_EXTERN_SETTINGS);
            }
            xqc_h3_request_t *request = xqc_h3_request_create(
                client.base.engine, cid, NULL, &client);
            WT_CHECK(request != NULL);
            xqc_http_header_t fields[] = {
                {.name = {(void *)":method", 7}, .value = {(void *)"GET", 3}},
                {.name = {(void *)":scheme", 7}, .value = {(void *)"https", 5}},
                {.name = {(void *)":authority", 10},
                 .value = {(void *)"localhost", 9}},
                {.name = {(void *)":path", 5}, .value = {(void *)"/", 1}},
            };
            xqc_http_headers_t headers = {
                .headers = fields, .count = sizeof(fields) / sizeof(fields[0]),
            };
            WT_CHECK(xqc_h3_request_send_headers(request, &headers, 1) >= 0);
            for (int i = 0; i < 100 && !client.http_received; i++) {
                xqc_complex_case_pump(engines, 2, 10);
            }
            WT_CHECK(client.http_received == 1 && server.http_received == 1);
            WT_CHECK(client.h3 && server.h3);
            WT_CHECK(xqc_h3_conn_get_errno(client.h3) == H3_NO_ERROR
                && xqc_h3_conn_get_errno(server.h3) == H3_NO_ERROR);
        }
        rc = 0;
        goto fail;
    }
    WT_CHECK(client.ready == 1 && server.ready == 1 && client.status == 200);
    WT_CHECK(client.session->wt_conn->negotiated_version
        == (legacy ? XQC_WEBTRANSPORT_DRAFT_VERSION_7
                   : XQC_WEBTRANSPORT_DRAFT_VERSION_16));
    if (legacy) {
        WT_CHECK(server.session->wt_conn->negotiated_version
            == XQC_WEBTRANSPORT_DRAFT_VERSION_7);
        WT_CHECK(!client.session->flow_control
            && !server.session->flow_control);
        WT_CHECK(!client.h3->conn->local_settings.reset_stream_at
            || !client.h3->conn->remote_settings.reset_stream_at);
    }
    if (limit) {
        /* Section 5.1: enforce the configured active-session cap above 64. */
        for (int count = 2; count <= 66; count++) {
            WT_CHECK(xqc_wt_client_open_session(
                client.h3, "localhost", "/wt", "https://allowed.test", &err)
                != NULL);
            for (int i = 0; i < 100 && !client.closed
                 && client.ready < count; i++)
            {
                xqc_complex_case_pump(engines, 2, 10);
            }
            WT_CHECK(client.ready == (count > 65 ? 65 : count));
            WT_CHECK(server.ready == client.ready);
            WT_CHECK(client.closed == (count > 65));
        }
        WT_CHECK(xqc_wt_conn_active_session_count(
            xqc_wt_get_conn_from_h3(server.h3)) == 65);
        WT_CHECK(client.close_error == H3_REQUEST_REJECTED);
        WT_CHECK(!server.failed && !client.failed);
        rc = 0;
        goto fail;
    }
    if (pending) {
        /* Sections 4.5 and 6: rejection releases the bounded early queue. */
        xqc_wt_conn_t *server_conn = xqc_wt_get_conn_from_h3(server.h3);
        unsigned char packet[1 + sizeof(wt_payload)];
        memcpy(packet + 1, wt_payload, sizeof(wt_payload));
        for (unsigned attempt = 1; attempt <= 2; attempt++) {
            packet[0] = attempt;
            WT_CHECK(xqc_datagram_send(
                client.h3->conn, packet,
                sizeof(packet), NULL, XQC_DATA_QOS_HIGHEST) == XQC_OK);
            for (int i = 0; i < 100 && !server_conn->pending_count; i++) {
                xqc_complex_case_pump(engines, 2, 10);
            }
            WT_CHECK(server_conn->pending_count == 1);
            WT_CHECK(server_conn->pending_bytes == sizeof(wt_payload));
            WT_CHECK(xqc_wt_client_open_session(
                client.h3, "localhost", "/wt",
                attempt == 1 ? "https://denied.test" : "https://allowed.test",
                &err) != NULL);
            for (int i = 0; i < 100
                 && (attempt == 1 ? !client.closed : client.ready < 2); i++)
            {
                xqc_complex_case_pump(engines, 2, 10);
            }
            WT_CHECK(server_conn->pending_count == 0);
            WT_CHECK(server_conn->pending_bytes == 0);
            if (attempt == 1) {
                WT_CHECK(client.closed == 1 && client.status == 403);
                WT_CHECK(server.dgram_bytes == 0);
            } else {
                WT_CHECK(client.ready == 2 && server.ready == 2);
                WT_CHECK(server.dgram_bytes == sizeof(wt_payload));
            }
        }
        WT_CHECK(!server.failed && !client.failed);
        rc = 0;
        goto fail;
    }
    if (pseudo) {
        /* RFC 9114 Section 4.3: an ambiguous request never opens WT. */
        xqc_h3_request_t *request = xqc_h3_request_create(
            client.base.engine, cid, NULL, &client);
        WT_CHECK(request != NULL);
        const char *names[] = {":method", ":protocol", ":scheme",
            ":authority", ":path", ":method", "origin"};
        const char *values[] = {"CONNECT", "webtransport-h3", "https",
            "localhost", "/wt", "GET", "https://allowed.test"};
        xqc_http_header_t fields[7];
        xqc_memzero(fields, sizeof(fields));
        for (size_t i = 0; i < 7; i++) {
            fields[i].name.iov_base = (void *)names[i];
            fields[i].name.iov_len = strlen(names[i]);
            fields[i].value.iov_base = (void *)values[i];
            fields[i].value.iov_len = strlen(values[i]);
        }
        xqc_http_headers_t headers = {.headers = fields, .count = 7};
        /* Release the valid session's slot before testing malformed input. */
        WT_CHECK(xqc_wt_session_close(client.session) == XQC_OK);
        for (int i = 0; i < 100 && !server.closed; i++) {
            xqc_complex_case_pump(engines, 2, 10);
        }
        WT_CHECK(server.closed == 1);
        WT_CHECK(xqc_h3_request_send_headers(request, &headers, 0) >= 0);
        for (int i = 0; i < 100 && !client.http_message_errors; i++) {
            xqc_complex_case_pump(engines, 2, 10);
        }
        WT_CHECK(client.http_message_errors == 1);
        WT_CHECK(server.ready == 1 && client.ready == 1);
        WT_CHECK(client.h3 && server.h3 && !client.conn_closed);
        rc = 0;
        goto fail;
    }
    if (credit) {
        /* Draft-16 Sections 5.4, 5.6: discarded bytes replenish credit. */
        unsigned char discarded[32] = {0};
        WT_CHECK(client.session->flow_control && server.session->flow_control);
        client.base.engine->config->manually_triggered_send = 1;
        bidi = xqc_wt_session_create_bidi_stream(client.session, NULL, &err);
        WT_CHECK(bidi != NULL);
        WT_CHECK(xqc_wt_bidistream_send(bidi, discarded, sizeof(discarded), 0)
            == sizeof(discarded));
        WT_CHECK(xqc_wt_bidistream_reset(bidi, 42) == XQC_OK);
        client.base.engine->config->manually_triggered_send = 0;
        for (int i = 0; i < 100 && (!server.reset
            || client.session->send_data_limit == sizeof(discarded)); i++)
        {
            xqc_complex_case_pump(engines, 2, 10);
        }
        WT_CHECK(server.reset == 1 && server.bidi_bytes == 0);
        WT_CHECK(client.session->send_data_limit == 2 * sizeof(discarded));
        bidi = xqc_wt_session_create_bidi_stream(client.session, NULL, &err);
        WT_CHECK(bidi != NULL);
        WT_CHECK(xqc_wt_bidistream_send(bidi, wt_payload,
            sizeof(wt_payload), 1) == sizeof(wt_payload));
        for (int i = 0; i < 100 && !server.bidi_fin; i++) {
            xqc_complex_case_pump(engines, 2, 10);
        }
        WT_CHECK(server.bidi_fin && server.bidi_bytes == sizeof(wt_payload));
        WT_CHECK(!server.failed && !client.failed && !server.closed);
        rc = 0;
        goto fail;
    }
    if (misplaced) {
        /*
         * Section 4.3: an established CONNECT cannot become a WT data stream.
         */
        xqc_h3_stream_t *h3s = xqc_wt_session_get_h3_stream(client.session);
        unsigned char marker[] = {0x40, 0x41};
        WT_CHECK(xqc_stream_send(h3s->stream, marker, 1, 0) == 1);
        xqc_complex_case_pump(engines, 2, 20);
        WT_CHECK(server.h3 != NULL
            && xqc_conn_get_errno(server.h3->conn) == 0);
        WT_CHECK(xqc_stream_send(h3s->stream, marker + 1, 1, 0) == 1);
        for (int i = 0; i < 400
             && (!client.conn_closed || !server.conn_closed); i++)
        {
            xqc_complex_case_pump(engines, 2, 10);
        }
        WT_CHECK(client.conn_closed && server.conn_closed);
        WT_CHECK(client.conn_error == H3_FRAME_ERROR
            && server.conn_error == H3_FRAME_ERROR);
        WT_CHECK(client.conn_error_type == XQC_CONN_ERR_TYPE_APPLICATION);
        rc = 0;
        goto fail;
    }
    for (int i = 0; i < 2; i++) {
        wt_endpoint_t *ep = i ? &server : &client;
        bidi = xqc_wt_session_create_bidi_stream(ep->session, NULL, &err);
        WT_CHECK(bidi != NULL);
        WT_CHECK(xqc_wt_bidistream_send(
            bidi, wt_payload,
            sizeof(wt_payload), 1) == sizeof(wt_payload));
        uni = xqc_wt_session_create_uni_stream(ep->session, NULL, &err);
        WT_CHECK(uni != NULL);
        WT_CHECK(xqc_wt_unistream_send(
            uni, wt_payload,
            sizeof(wt_payload), 1) == sizeof(wt_payload));
        WT_CHECK(xqc_wt_session_datagram_send(
            ep->session, wt_payload, sizeof(wt_payload), NULL) == XQC_OK);
    }
    for (int i = 0; i < 100 && (!client.uni_fin || !server.uni_fin
        || !client.bidi_fin || !server.bidi_fin
        || !client.dgram_bytes || !server.dgram_bytes); i++)
    {
        xqc_complex_case_pump(engines, 2, 10);
    }
    WT_CHECK(!client.failed && !server.failed);
    WT_CHECK(client.bidi_fin && server.bidi_fin);
    WT_CHECK(client.uni_fin && server.uni_fin);
    WT_CHECK(client.bidi_bytes == sizeof(wt_payload)
        && server.bidi_bytes == sizeof(wt_payload));
    WT_CHECK(client.uni_bytes == sizeof(wt_payload)
        && server.uni_bytes == sizeof(wt_payload));
    WT_CHECK(client.dgram_bytes == sizeof(wt_payload)
        && server.dgram_bytes == sizeof(wt_payload));
    /* Draft-16 preserves the prefix; draft-07 uses its sole-session rule. */
    bidi = xqc_wt_session_create_bidi_stream(client.session, NULL, &err);
    WT_CHECK(bidi != NULL && xqc_wt_bidistream_reset(bidi, 42) == XQC_OK);
    for (int i = 0; i < 100 && !server.reset; i++) {
        xqc_complex_case_pump(engines, 2, 10);
    }
    WT_CHECK(server.reset == 1);
    WT_CHECK(xqc_wt_session_drain(server.session) == XQC_OK);
    for (int i = 0; i < 100 && !client.drained; i++) {
        xqc_complex_case_pump(engines, 2, 10);
    }
    WT_CHECK(client.drained == 1);
    WT_CHECK(xqc_wt_session_close_with_error(client.session, 17, "done", 4)
        == XQC_OK);
    for (int i = 0; i < 100 && !server.closed; i++) {
        xqc_complex_case_pump(engines, 2, 10);
    }
    WT_CHECK(server.closed == 1 && server.close_error == 17);
    rc = 0;

fail:
    xqc_complex_case_engine_release(&client.base);
    xqc_complex_case_engine_release(&server.base);
    printf("webtransport %s: %s\n", argc == 2 ? argv[1] : "usage",
           rc == 0 ? "pass" : "fail");
    return rc;
}
