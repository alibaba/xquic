/**
 * wt_test_client.c - WebTransport echo client for interop testing
 *
 * Uses only xquic public API (xqc_webtransport.h + xqc_http3.h + xquic.h).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <event2/event.h>

#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include <xquic/xqc_webtransport.h>

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 4433
#define ECHO_MSG     "Hello WebTransport from xquic client!"

static xqc_usec_t wt_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (xqc_usec_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

typedef struct {
    xqc_engine_t       *engine;
    struct event_base  *eb;
    struct event       *ev_engine;
    struct event       *ev_socket;
    struct event       *ev_poll;
    int                 fd;
    struct sockaddr_in  local_addr;
    struct sockaddr_in  peer_addr;
    socklen_t           peer_addrlen;
    xqc_cid_t           cid;
    int                  session_ready;
    int                  echo_done;
    int                  echo_ok;
    char                 recv_buf[65536];
    size_t               recv_len;
    char                 host[256];
} wt_ctx_t;

static wt_ctx_t *g_ctx = NULL;

/* forward declarations */
static void engine_cb(int fd, short what, void *arg);
static void socket_cb(evutil_socket_t fd, short what, void *arg);
static void read_socket(wt_ctx_t *ctx);

/* ==================== transport callbacks ==================== */

static ssize_t
write_socket_cb(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user)
{
    ssize_t res = sendto(g_ctx->fd, buf, size, 0, peer_addr, peer_addrlen);
    return (res < 0 && errno == EAGAIN) ? XQC_SOCKET_EAGAIN : res;
}

static ssize_t
write_socket_ex_cb(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user)
{
    return write_socket_cb(buf, size, peer_addr, peer_addrlen, user);
}

static void
save_token_cb(const unsigned char *token, unsigned token_len, void *user)
{
}

static void
set_timer_cb(xqc_msec_t wake_after, void *user)
{
    struct timeval tv = { wake_after / 1000, (wake_after % 1000) * 1000 };
    event_add(g_ctx->ev_engine, &tv);
}

static void
log_cb(xqc_log_level_t lvl, const void *buf, size_t sz, void *user)
{
}

/* ==================== WT callbacks ==================== */

static int
on_session_create(xqc_webtransport_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user)
{
    if (!headers) return 0;
    for (size_t i = 0; i < headers->count; i++) {
        size_t nlen = headers->headers[i].name.iov_len;
        size_t vlen = headers->headers[i].value.iov_len;
        char *n = (char *)headers->headers[i].name.iov_base;
        char *v = (char *)headers->headers[i].value.iov_base;
        if (n && v && nlen == 7 && memcmp(n, ":status", 7) == 0 &&
            vlen == 3 && memcmp(v, "200", 3) == 0) {
            g_ctx->session_ready = 1;
            printf("[OK] session-setup\n");
            ssize_t sent = xqc_wt_session_send_bidi(session, ECHO_MSG, strlen(ECHO_MSG), 1);
            if (sent > 0) {
                printf("[INFO] Sent bidi echo: %zd bytes\n", sent);
            } else {
                printf("[FAIL] send_bidi failed: %zd\n", sent);
            }
            return 0;
        }
    }
    return 0;
}

static int
on_session_close(xqc_webtransport_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user)
{
    if (!g_ctx->echo_done && !g_ctx->session_ready) {
        printf("[FAIL] Session closed before echo\n");
    }
    event_base_loopbreak(g_ctx->eb);
    return 0;
}

static void
on_handshake_done(xqc_webtransport_session_t *session)
{
    xqc_int_t ret = xqc_wt_client_open_session(g_ctx->engine, &g_ctx->cid,
                                                 "/echo", g_ctx->host, g_ctx);
    if (ret != XQC_OK) {
        printf("[FAIL] open_session: %d\n", ret);
    } else {
        printf("[INFO] Extended CONNECT sent\n");
    }
}

static xqc_int_t
on_bidi_read(xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *data, size_t data_len, void *user)
{
    if (data_len > 0 && g_ctx->recv_len + data_len <= sizeof(g_ctx->recv_buf)) {
        memcpy(g_ctx->recv_buf + g_ctx->recv_len, data, data_len);
        g_ctx->recv_len += data_len;
    }
    size_t expected = strlen(ECHO_MSG);
    if (g_ctx->recv_len >= expected) {
        if (g_ctx->recv_len == expected &&
            memcmp(g_ctx->recv_buf, ECHO_MSG, expected) == 0) {
            printf("[OK] bidi-echo: %zu bytes match\n", g_ctx->recv_len);
            g_ctx->echo_ok = 1;
        } else {
            printf("[FAIL] bidi-echo: mismatch (%zu vs %zu)\n", g_ctx->recv_len, expected);
        }
        g_ctx->echo_done = 1;
        xqc_h3_conn_close(g_ctx->engine, &g_ctx->cid);
    }
    return 0;
}

/* ==================== engine / socket ==================== */

static void
engine_cb(int fd, short what, void *arg)
{
    read_socket(g_ctx);
    xqc_engine_main_logic(g_ctx->engine);
}

static void
read_socket(wt_ctx_t *ctx)
{
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    unsigned char buf[1500];
    ssize_t n;
    do {
        n = recvfrom(ctx->fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &alen);
        if (n < 0) break;
        xqc_engine_packet_process(ctx->engine, buf, n,
            (struct sockaddr *)&ctx->local_addr, sizeof(ctx->local_addr),
            (struct sockaddr *)&addr, alen, (xqc_usec_t)wt_now(), ctx);
    } while (n > 0);
    xqc_engine_finish_recv(ctx->engine);
}

static void
socket_cb(evutil_socket_t fd, short what, void *arg)
{
    if (what & EV_READ) read_socket(g_ctx);
    xqc_engine_main_logic(g_ctx->engine);
    read_socket(g_ctx);
    xqc_engine_main_logic(g_ctx->engine);
}

int
main(int argc, char *argv[])
{
    const char *host = DEFAULT_HOST;
    int port = DEFAULT_PORT;
    if (argc > 1) host = argv[1];
    if (argc > 2) port = atoi(argv[2]);

    wt_ctx_t ctx_s = {0};
    g_ctx = &ctx_s;
    strncpy(ctx_s.host, host, sizeof(ctx_s.host) - 1);

    struct event_base *eb = event_base_new();
    ctx_s.eb = eb;
    ctx_s.ev_engine = event_new(eb, -1, 0, engine_cb, &ctx_s);

    xqc_engine_callback_t ecbs = {
        .set_event_timer = set_timer_cb,
        .log_callbacks = { .xqc_log_write_err = log_cb, .xqc_log_write_stat = log_cb },
    };
    xqc_transport_callbacks_t tcbs = {
        .write_socket = write_socket_cb,
        .write_socket_ex = write_socket_ex_cb,
        .save_token = save_token_cb,
    };

    xqc_config_t cfg;
    xqc_engine_get_default_config(&cfg, XQC_ENGINE_CLIENT);
    cfg.cfg_log_level = XQC_LOG_WARN;
    cfg.enable_h3_ext = 1;

    xqc_engine_ssl_config_t ssl = {0};
    ssl.ciphers = XQC_TLS_CIPHERS;
    ssl.groups = XQC_TLS_GROUPS;

    ctx_s.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &cfg, &ssl, &ecbs, &tcbs, &ctx_s);
    if (!ctx_s.engine) { printf("[FAIL] engine_create\n"); return 1; }

    xqc_webtransport_session_callbacks_t scbs = {
        .webtransport_session_create_notify = on_session_create,
        .webtransport_session_close_notify = on_session_close,
        .webtransport_session_handshake_finished_notify = on_handshake_done,
    };
    xqc_webtransport_stream_callbacks_t stcbs = {
        .wt_bidistream_read_notify = on_bidi_read,
    };
    if (xqc_wt_ctx_init(ctx_s.engine, NULL, &scbs, &stcbs, 0) != XQC_OK) {
        printf("[FAIL] wt_ctx_init\n"); return 1;
    }

    /* socket */
    ctx_s.fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx_s.fd < 0) { printf("[FAIL] socket\n"); return 1; }
    fcntl(ctx_s.fd, F_SETFL, O_NONBLOCK);

    memset(&ctx_s.peer_addr, 0, sizeof(ctx_s.peer_addr));
    ctx_s.peer_addr.sin_family = AF_INET;
    ctx_s.peer_addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &ctx_s.peer_addr.sin_addr);
    ctx_s.peer_addrlen = sizeof(ctx_s.peer_addr);

    ctx_s.ev_socket = event_new(eb, ctx_s.fd, EV_READ | EV_PERSIST, socket_cb, &ctx_s);
    event_add(ctx_s.ev_socket, NULL);

    /* connect */
    xqc_conn_settings_t cs = {
        .proto_version = XQC_VERSION_V1,
        .cong_ctrl_callback = xqc_bbr_cb,
        .init_idle_time_out = 30000,
        .max_datagram_frame_size = 16383,
    };
    xqc_conn_ssl_config_t cssl = {0};
    const xqc_cid_t *cid = xqc_webtransport_connect(ctx_s.engine, &cs,
        NULL, 0, host, 0, &cssl,
        (struct sockaddr *)&ctx_s.peer_addr, ctx_s.peer_addrlen, &ctx_s);
    if (!cid) { printf("[FAIL] wt_connect\n"); return 1; }
    memcpy(&ctx_s.cid, cid, sizeof(xqc_cid_t));
    printf("[INFO] Connecting to %s:%d...\n", host, port);

    /* poll timer for reliable socket reading */
    ctx_s.ev_poll = event_new(eb, -1, EV_PERSIST, engine_cb, &ctx_s);
    struct timeval ptv = {0, 20000};
    event_add(ctx_s.ev_poll, &ptv);

    xqc_engine_main_logic(ctx_s.engine);

    struct timeval tv = {15, 0};
    event_base_loopexit(eb, &tv);
    event_base_dispatch(eb);

    printf("\nWebTransport client interop: %s\n", ctx_s.echo_ok ? "PASS" : "FAIL");

    event_free(ctx_s.ev_poll);
    event_free(ctx_s.ev_socket);
    event_free(ctx_s.ev_engine);
    xqc_engine_destroy(ctx_s.engine);
    close(ctx_s.fd);
    event_base_free(eb);
    return ctx_s.echo_ok ? 0 : 1;
}
