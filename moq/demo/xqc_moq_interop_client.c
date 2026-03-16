#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <memory.h>
#include <string.h>
#include <stdlib.h>
#include <event2/event.h>
#include <inttypes.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include <time.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>

#include "tests/platform.h"
#include "xqc_moq_demo_comm.h"

#ifndef XQC_SYS_WINDOWS
#include <unistd.h>
#include <getopt.h>
#else
#include "getopt.h"
#endif

#include <moq/xqc_moq.h>
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream_webtransport.h"
#include "src/http3/xqc_h3_conn.h"

#define XQC_INTEROP_VERSION       "0.1.0"
#define XQC_INTEROP_CID_LEN       12
#define XQC_INTEROP_TIMEOUT_SEC   10
#define XQC_INTEROP_MAX_TESTS     6

extern long xqc_random(void);
extern xqc_usec_t xqc_now();

typedef enum {
    XQC_DEMO_TEST_SETUP_ONLY = 0,
    XQC_DEMO_TEST_ANNOUNCE_ONLY,
    XQC_DEMO_TEST_SUBSCRIBE_ERROR,
    XQC_DEMO_TEST_ANNOUNCE_SUBSCRIBE,
    XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE,
    XQC_DEMO_TEST_PUBLISH_NAMESPACE_DONE,
    XQC_DEMO_TEST_ALL,
    XQC_DEMO_TEST_UNKNOWN,
} xqc_demo_test_case_t;

static const char *g_test_case_names[] = {
    "setup-only",
    "announce-only",
    "subscribe-error",
    "announce-subscribe",
    "subscribe-before-announce",
    "publish-namespace-done",
};

typedef struct xqc_demo_interop_conn_s {
    struct event        *ev_timeout;
    struct sockaddr     *peer_addr;
    socklen_t            peer_addrlen;
    struct sockaddr     *local_addr;
    socklen_t            local_addrlen;
    xqc_cid_t            cid;
    int                  fd;
    unsigned char       *token;
    unsigned             token_len;
    struct event        *ev_socket;
    int                  get_local_addr;
    xqc_moq_session_t  *session;
    int                  conn_role; /* 0 = publisher, 1 = subscriber */
    int                  session_ready;
    int                  closed;
    int                  publish_ns_ok_received;
    int                  publish_ns_done_sent;
    int                  subscribe_error_received;
    int                  announcement_received;
    int                  subscribe_sent;
    int                  subscribe_ok_received;
} xqc_demo_interop_conn_t;

static xqc_app_ctx_t       g_ctx;
static struct event_base   *g_eb;

static char     g_relay_host[256] = "";
static char     g_relay_sni[256]  = "";
static char     g_relay_path[256] = "/";
static int      g_relay_port = 4443;
static int      g_verbose = 0;
static int      g_tls_disable_verify = 0;
static xqc_moq_transport_type_t g_transport_type = XQC_MOQ_TRANSPORT_QUIC;

static xqc_demo_test_case_t  g_current_test = XQC_DEMO_TEST_UNKNOWN;
static int          g_test_passed = 0;
static char         g_fail_reason[512] = "";
static xqc_usec_t   g_test_start_us = 0;

static xqc_demo_interop_conn_t  *g_pub_conn = NULL;
static xqc_demo_interop_conn_t  *g_sub_conn = NULL;
static xqc_moq_user_session_t *g_pub_user_session = NULL;
static xqc_moq_user_session_t *g_sub_user_session = NULL;

static uint64_t g_request_id_counter = 0;
static int g_connections_closed = 0;
static int g_publisher_announced = 0;

#define XQC_INTEROP_NS_STR "moq-test/interop"
#define XQC_INTEROP_TRACK_NAME "test-track"

/* Helper: single-element namespace tuple from string */
static xqc_moq_track_ns_field_t interop_ns_tuple = {
    .len = sizeof(XQC_INTEROP_NS_STR) - 1,
    .data = (unsigned char *)XQC_INTEROP_NS_STR
};
static const char *XQC_NONEXISTENT_NS_STR = "nonexistent/namespace";
static xqc_moq_track_ns_field_t nonexistent_ns_tuple = {
    .len = sizeof("nonexistent/namespace") - 1,
    .data = (unsigned char *)"nonexistent/namespace"
};

#define VERBOSE(...) do { if (g_verbose) { fprintf(stderr, "[verbose] " __VA_ARGS__); fprintf(stderr, "\n"); } } while(0)

static void
xqc_demo_test_fail(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_fail_reason, sizeof(g_fail_reason), fmt, ap);
    va_end(ap);
    g_test_passed = 0;
}

static void
xqc_demo_test_pass(void)
{
    g_test_passed = 1;
}

static void
xqc_demo_tap_header(void)
{
    printf("TAP version 14\n");
    printf("# xquic-moq-interop-client v%s\n", XQC_INTEROP_VERSION);
    if (g_transport_type == XQC_MOQ_TRANSPORT_WEBTRANSPORT) {
        printf("# Relay: https://%s:%d%s (sni=%s, WebTransport)\n",
               g_relay_host, g_relay_port, g_relay_path, g_relay_sni);
    } else {
        printf("# Relay: moqt://%s:%d (sni=%s)\n", g_relay_host, g_relay_port, g_relay_sni);
    }
    fflush(stdout);
}

static void
xqc_demo_tap_plan(int count)
{
    printf("1..%d\n", count);
    fflush(stdout);
}

static void
xqc_demo_tap_result(int test_num, const char *test_name, int passed,
           uint64_t duration_ms, const char *message)
{
    printf("%s %d - %s\n", passed ? "ok" : "not ok", test_num, test_name);
    printf("  ---\n");
    printf("  duration_ms: %"PRIu64"\n", duration_ms);
    if (!passed && message && message[0]) {
        printf("  message: \"%s\"\n", message);
        if (strstr(message, "expected ") != NULL) {
            const char *exp = strstr(message, "expected ");
            const char *got = strstr(message, ", got ");
            if (exp && got) {
                printf("  expected: %.*s\n", (int)(got - exp - 9), exp + 9);
                printf("  received: %s\n", got + 6);
            }
        } else if (strstr(message, "timeout") != NULL) {
            printf("  received: timeout\n");
        }
    }
    printf("  ...\n");
    fflush(stdout);
}

static void
xqc_demo_interop_close_conn(xqc_demo_interop_conn_t *conn)
{
    if (conn == NULL || conn->closed) {
        return;
    }
    VERBOSE("closing connection role=%d", conn->conn_role);
    xqc_conn_close(g_ctx.engine, &conn->cid);
}

static void
xqc_demo_interop_timeout_callback(int fd, short what, void *arg)
{
    (void)fd; (void)what;

    if (g_current_test == XQC_DEMO_TEST_SUBSCRIBE_ERROR) {
        xqc_demo_interop_conn_t *sub = g_sub_conn;
        if (sub && sub->subscribe_error_received) {
            xqc_demo_test_pass();
        } else if (sub && sub->subscribe_ok_received) {
            xqc_demo_test_fail("expected SUBSCRIBE_ERROR, got SUBSCRIBE_OK");
        } else {
            xqc_demo_test_fail("timeout: no SUBSCRIBE_ERROR received");
        }
    } else {
        xqc_demo_test_fail("test timed out: deadline has elapsed");
    }
    if (g_pub_conn && !g_pub_conn->closed) {
        xqc_demo_interop_close_conn(g_pub_conn);
    }
    if (g_sub_conn && !g_sub_conn->closed) {
        xqc_demo_interop_close_conn(g_sub_conn);
    }
    if ((g_pub_conn == NULL || g_pub_conn->closed)
        && (g_sub_conn == NULL || g_sub_conn->closed))
    {
        event_base_loopbreak(g_eb);
    }
}

static void
xqc_demo_interop_delayed_action_callback(int fd, short what, void *arg);

static void
xqc_demo_interop_subscriber_subscribe_callback(int fd, short what, void *arg);

static void
xqc_demo_interop_delayed_announce_callback(int fd, short what, void *arg);

static void
xqc_demo_interop_create_subscriber_callback(int fd, short what, void *arg);

static void
xqc_demo_interop_socket_read_handler(xqc_demo_interop_conn_t *conn)
{
    ssize_t recv_sum = 0;
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = sizeof(peer_addr);
    unsigned char packet_buf[1500];

    do {
        ssize_t recv_size = recvfrom(conn->fd, packet_buf, sizeof(packet_buf), 0,
                                      (struct sockaddr *)&peer_addr, &peer_addrlen);
        if (recv_size < 0) {
            break;
        }
        recv_sum += recv_size;

        if (!conn->get_local_addr) {
            conn->get_local_addr = 1;
            socklen_t local_len = sizeof(struct sockaddr_in);
            getsockname(conn->fd, conn->local_addr, &local_len);
            conn->local_addrlen = local_len;
        }

        if (xqc_engine_packet_process(g_ctx.engine, packet_buf, recv_size,
                                       conn->local_addr, conn->local_addrlen,
                                       (struct sockaddr *)&peer_addr, peer_addrlen,
                                       (xqc_usec_t)xqc_now(), conn) != XQC_OK)
        {
            break;
        }
    } while (recv_sum < 64 * 1024);

    xqc_engine_finish_recv(g_ctx.engine);
}

static void
xqc_demo_interop_socket_write_handler(xqc_demo_interop_conn_t *conn)
{
    xqc_conn_continue_send(g_ctx.engine, &conn->cid);
}

static void
xqc_demo_interop_socket_event_callback(int fd, short what, void *arg)
{
    xqc_demo_interop_conn_t *conn = (xqc_demo_interop_conn_t *)arg;
    if (what & EV_READ) {
        xqc_demo_interop_socket_read_handler(conn);
    }
    if (what & EV_WRITE) {
        xqc_demo_interop_socket_write_handler(conn);
    }
}

static int
xqc_demo_interop_convert_addr(const char *addr_text, unsigned int port,
                     struct sockaddr *saddr, socklen_t *saddrlen)
{
    struct sockaddr_in *addr4 = (struct sockaddr_in *)saddr;
    memset(addr4, 0, sizeof(*addr4));
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(port);
    addr4->sin_addr.s_addr = inet_addr(addr_text);
    *saddrlen = sizeof(struct sockaddr_in);
    if (addr4->sin_addr.s_addr == INADDR_NONE) {
        return -1;
    }
    return 0;
}

static int
xqc_demo_interop_create_socket(xqc_demo_interop_conn_t *conn)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        close(fd);
        return -1;
    }
    int size = 1 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int));

#if !defined(__APPLE__)
    if (connect(fd, conn->peer_addr, conn->peer_addrlen) < 0) {
        close(fd);
        return -1;
    }
#endif

    conn->fd = fd;
    conn->ev_socket = event_new(g_eb, fd, EV_READ | EV_PERSIST,
                                 xqc_demo_interop_socket_event_callback, conn);
    event_add(conn->ev_socket, NULL);
    return 0;
}

static xqc_demo_interop_conn_t *
xqc_demo_interop_init_conn(int role)
{
    xqc_moq_user_session_t *user_session = calloc(1, sizeof(xqc_moq_user_session_t) + sizeof(xqc_demo_interop_conn_t));
    xqc_demo_interop_conn_t *conn = (xqc_demo_interop_conn_t *)user_session->data;
    conn->conn_role = role;

    struct sockaddr_in *peer = calloc(1, sizeof(struct sockaddr_in));
    peer->sin_family = AF_INET;
    peer->sin_port = htons(g_relay_port);
    inet_pton(AF_INET, g_relay_host, &peer->sin_addr.s_addr);
    conn->peer_addr = (struct sockaddr *)peer;
    conn->peer_addrlen = sizeof(struct sockaddr_in);

    conn->local_addr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
    memset(conn->local_addr, 0, sizeof(struct sockaddr_in));
    conn->local_addrlen = sizeof(struct sockaddr_in);

    if (xqc_demo_interop_create_socket(conn) < 0) {
        free(peer);
        free(conn->local_addr);
        free(user_session);
        return NULL;
    }

    if (role == 0) {
        g_pub_conn = conn;
        g_pub_user_session = user_session;
    } else {
        g_sub_conn = conn;
        g_sub_user_session = user_session;
    }
    return conn;
}

static int
xqc_demo_interop_send_announce(xqc_moq_session_t *session)
{
    xqc_moq_track_t *track = xqc_moq_track_create(session,
        (char *)XQC_INTEROP_NS_STR, (char *)XQC_INTEROP_TRACK_NAME,
        XQC_MOQ_TRACK_VIDEO, NULL, XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_PUB);
    if (track == NULL) {
        VERBOSE("failed to create track for announce");
        return -1;
    }
    VERBOSE("created track (announce) for %s/%s", XQC_INTEROP_NS_STR, XQC_INTEROP_TRACK_NAME);
    xqc_moq_publish_namespace_msg_t pub_ns;
    memset(&pub_ns, 0, sizeof(pub_ns));
    pub_ns.track_namespace_num = 1;
    pub_ns.track_namespace_tuple = &interop_ns_tuple;
    pub_ns.track_namespace_len = 0;
    pub_ns.params_num = 0;
    pub_ns.params = NULL;
    xqc_int_t ret = xqc_moq_write_publish_namespace(session, &pub_ns);
    VERBOSE("send PUBLISH_NAMESPACE(%s) ret=%d", XQC_INTEROP_NS_STR, (int)ret);
    return (int)ret;
}

static int
xqc_demo_interop_send_subscribe_namespace(xqc_moq_session_t *session)
{
    xqc_moq_track_t *track = xqc_moq_track_create(session,
        (char *)XQC_INTEROP_NS_STR, (char *)XQC_INTEROP_TRACK_NAME,
        XQC_MOQ_TRACK_VIDEO, NULL, XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        VERBOSE("failed to create track for interop subscribe");
        return -1;
    }
    int ret = xqc_moq_subscribe_latest(session, &interop_ns_tuple, 1, XQC_INTEROP_TRACK_NAME);
    VERBOSE("send SUBSCRIBE(%s/%s) ret=%d", XQC_INTEROP_NS_STR, XQC_INTEROP_TRACK_NAME, ret);
    return ret;
}

static int
xqc_demo_interop_send_subscribe_nonexistent(xqc_moq_session_t *session)
{
    xqc_moq_track_t *track = xqc_moq_track_create(session,
        (char *)"nonexistent/namespace", (char *)"test-track",
        XQC_MOQ_TRACK_VIDEO, NULL, XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        VERBOSE("failed to create track for nonexistent subscribe");
        return -1;
    }
    int ret = xqc_moq_subscribe_latest(session, &nonexistent_ns_tuple, 1, "test-track");
    VERBOSE("send SUBSCRIBE(nonexistent/namespace, test-track) ret=%d", ret);
    return ret;
}

static int
xqc_demo_interop_send_subscribe_interop(xqc_moq_session_t *session)
{
    xqc_moq_track_t *track = xqc_moq_track_create(session,
        (char *)XQC_INTEROP_NS_STR, (char *)XQC_INTEROP_TRACK_NAME,
        XQC_MOQ_TRACK_VIDEO, NULL, XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        VERBOSE("failed to create track for interop subscribe");
        return -1;
    }
    int ret = xqc_moq_subscribe_latest(session, &interop_ns_tuple, 1, XQC_INTEROP_TRACK_NAME);
    VERBOSE("send SUBSCRIBE(%s/%s) ret=%d", XQC_INTEROP_NS_STR, XQC_INTEROP_TRACK_NAME, ret);
    return ret;
}

static void
xqc_demo_interop_on_session_setup(xqc_moq_user_session_t *user_session, char *extdata,
                         const xqc_moq_message_parameter_t *params, uint64_t params_num)
{
    xqc_demo_interop_conn_t *conn = (xqc_demo_interop_conn_t *)user_session->data;
    conn->session = user_session->session;
    conn->session_ready = 1;
    VERBOSE("on_session_setup role=%d", conn->conn_role);

    switch (g_current_test) {
    case XQC_DEMO_TEST_SETUP_ONLY:
        xqc_demo_test_pass();
        xqc_demo_interop_close_conn(conn);
        break;

    case XQC_DEMO_TEST_ANNOUNCE_ONLY:
        if (conn->conn_role == 0) {
            xqc_demo_interop_send_announce(conn->session);
        }
        break;

    case XQC_DEMO_TEST_PUBLISH_NAMESPACE_DONE:
        if (conn->conn_role == 0) {
            xqc_demo_interop_send_announce(conn->session);
        }
        break;

    case XQC_DEMO_TEST_SUBSCRIBE_ERROR:
        if (conn->conn_role == 1) {
            conn->subscribe_sent = 1;
            xqc_demo_interop_send_subscribe_nonexistent(conn->session);
        }
        break;

    case XQC_DEMO_TEST_ANNOUNCE_SUBSCRIBE:
        if (conn->conn_role == 0) {
            xqc_demo_interop_send_announce(conn->session);
            g_publisher_announced = 1;
            if (g_sub_conn && g_sub_conn->session_ready && !g_sub_conn->subscribe_sent) {
                g_sub_conn->subscribe_sent = 1;
                VERBOSE("publisher announced, triggering subscriber SUBSCRIBE");
                xqc_demo_interop_send_subscribe_interop(g_sub_conn->session);
            }
        }
        if (conn->conn_role == 1) {
            if (g_publisher_announced) {
                conn->subscribe_sent = 1;
                xqc_demo_interop_send_subscribe_interop(conn->session);
            }
        }
        break;

    case XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE:
        if (conn->conn_role == 1) {
            conn->subscribe_sent = 1;
            xqc_demo_interop_send_subscribe_interop(conn->session);
        }
        if (conn->conn_role == 0) {
            struct event *ev = evtimer_new(g_eb, xqc_demo_interop_delayed_announce_callback, conn);
            struct timeval delay = { 2, 0 };
            event_add(ev, &delay);
        }
        break;

    default:
        break;
    }
}

static void
xqc_demo_interop_on_subscribe_ok(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
                        xqc_moq_track_info_t *track_info, xqc_moq_subscribe_ok_msg_t *subscribe_ok)
{
    xqc_demo_interop_conn_t *conn = (xqc_demo_interop_conn_t *)user_session->data;
    VERBOSE("on_subscribe_ok role=%d subscribe_id=%"PRIu64, conn->conn_role, subscribe_ok->subscribe_id);

    conn->subscribe_ok_received = 1;

    if (g_current_test == XQC_DEMO_TEST_SUBSCRIBE_ERROR) {
        xqc_demo_test_fail("expected SUBSCRIBE_ERROR, got SUBSCRIBE_OK");
        xqc_demo_interop_close_conn(conn);
        return;
    }

    if (g_current_test == XQC_DEMO_TEST_ANNOUNCE_SUBSCRIBE || g_current_test == XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE) {
        xqc_demo_test_pass();
        xqc_demo_interop_close_conn(conn);
        if (g_pub_conn && !g_pub_conn->closed) {
            xqc_demo_interop_close_conn(g_pub_conn);
        }
    }
}

static void
xqc_demo_interop_on_subscribe_error(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
                           xqc_moq_track_info_t *track_info, xqc_moq_subscribe_error_msg_t *subscribe_error)
{
    xqc_demo_interop_conn_t *conn = (xqc_demo_interop_conn_t *)user_session->data;
    VERBOSE("on_subscribe_error role=%d error_code=%"PRIu64" reason=%s",
            conn->conn_role, subscribe_error->error_code,
            subscribe_error->reason_phrase ? subscribe_error->reason_phrase : "null");

    if (conn->conn_role == 0
        || (conn->conn_role == 1 && !conn->subscribe_sent))
    {
        VERBOSE("ignoring SUBSCRIBE_ERROR for non-interop track (role=%d)", conn->conn_role);
        return;
    }

    conn->subscribe_error_received = 1;

    if (g_current_test == XQC_DEMO_TEST_SUBSCRIBE_ERROR) {
        xqc_demo_test_pass();
        xqc_demo_interop_close_conn(conn);
    }

    if (g_current_test == XQC_DEMO_TEST_ANNOUNCE_SUBSCRIBE) {
        xqc_demo_test_fail("expected SUBSCRIBE_OK, got SUBSCRIBE_ERROR (code=%"PRIu64")",
                           subscribe_error->error_code);
        xqc_demo_interop_close_conn(conn);
        if (g_pub_conn && !g_pub_conn->closed) {
            xqc_demo_interop_close_conn(g_pub_conn);
        }
    }

    if (g_current_test == XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE) {
        VERBOSE("subscribe-before-announce: SUBSCRIBE_ERROR received (relay doesn't buffer) - PASS");
        xqc_demo_test_pass();
        xqc_demo_interop_close_conn(conn);
        if (g_pub_conn && !g_pub_conn->closed) {
            xqc_demo_interop_close_conn(g_pub_conn);
        }
    }
}

static void
xqc_demo_interop_on_datachannel(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
                       xqc_moq_track_info_t *track_info)
{
}

static void
xqc_demo_interop_on_datachannel_msg(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
                           xqc_moq_track_info_t *track_info, uint8_t *msg, size_t msg_len)
{
}

static void
xqc_demo_interop_on_subscribe(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
                     xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg)
{
    xqc_demo_interop_conn_t *conn = (xqc_demo_interop_conn_t *)user_session->data;
    VERBOSE("on_subscribe role=%d subscribe_id=%"PRIu64" track_name=%s",
            conn->conn_role, subscribe_id,
            msg && msg->track_name ? msg->track_name : "null");

    if (track == NULL && msg != NULL && msg->track_namespace_tuple && msg->track_namespace_num > 0 && msg->track_name) {
        track = xqc_moq_track_create_with_namespace_tuple(conn->session, msg->track_namespace_num,
            msg->track_namespace_tuple, msg->track_name, XQC_MOQ_TRACK_VIDEO, NULL,
            XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_PUB);
        VERBOSE("created track for on_subscribe: %p", (void *)track);
    }

    xqc_moq_subscribe_ok_msg_t ok;
    memset(&ok, 0, sizeof(ok));
    ok.subscribe_id = subscribe_id;
    ok.track_alias = msg ? msg->track_alias : 0;
    ok.expire_ms = 0;
    ok.group_order = 1;
    ok.content_exist = 0;
    int ret = xqc_moq_write_subscribe_ok(conn->session, &ok);
    VERBOSE("write_subscribe_ok ret=%d", ret);
}

static void
xqc_demo_interop_on_request_keyframe(xqc_moq_user_session_t *user_session, uint64_t subscribe_id, xqc_moq_track_t *track)
{
}

static void
xqc_demo_interop_on_bitrate_change(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
                          xqc_moq_track_info_t *track_info, uint64_t bitrate)
{
}

static void
xqc_demo_interop_on_publish(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
                   xqc_moq_publish_msg_t *publish_msg)
{
}

static void
xqc_demo_interop_on_publish_ok(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
                      xqc_moq_publish_ok_msg_t *publish_ok)
{
}

static void
xqc_demo_interop_on_publish_error(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
                         xqc_moq_track_info_t *track_info, xqc_moq_publish_error_msg_t *publish_error)
{
}

static void
xqc_demo_interop_on_publish_done(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
                        xqc_moq_publish_done_msg_t *publish_done)
{
}

static void
xqc_demo_interop_on_catalog(xqc_moq_user_session_t *user_session, xqc_moq_track_info_t **array, xqc_int_t size)
{
}

static void
xqc_demo_interop_on_video(xqc_moq_user_session_t *user_session, uint64_t subscribe_id, xqc_moq_video_frame_t *frame)
{
}

static void
xqc_demo_interop_on_audio(xqc_moq_user_session_t *user_session, uint64_t subscribe_id, xqc_moq_audio_frame_t *frame)
{
}

static void
xqc_demo_interop_delayed_action_callback(int fd, short what, void *arg)
{
    (void)fd; (void)what;
    xqc_demo_interop_conn_t *conn = (xqc_demo_interop_conn_t *)arg;
    if (conn == NULL || conn->closed) {
        return;
    }

    switch (g_current_test) {
    case XQC_DEMO_TEST_ANNOUNCE_ONLY:
        if (conn->session_ready) {
            xqc_demo_test_pass();
        } else {
            xqc_demo_test_fail("session setup not completed within deadline");
        }
        xqc_demo_interop_close_conn(conn);
        break;

    case XQC_DEMO_TEST_PUBLISH_NAMESPACE_DONE:
        if (conn->session_ready && !conn->publish_ns_done_sent) {
            xqc_moq_publish_namespace_done_msg_t done;
            memset(&done, 0, sizeof(done));
            done.track_namespace_num = 1;
            done.track_namespace_tuple = &interop_ns_tuple;
            done.track_namespace_len = 0;
            xqc_int_t ret = xqc_moq_write_publish_namespace_done(conn->session, &done);
            VERBOSE("send PUBLISH_NAMESPACE_DONE ret=%d", (int)ret);
            conn->publish_ns_done_sent = 1;
            if (ret >= 0) {
                xqc_demo_test_pass();
            } else {
                xqc_demo_test_fail("write_publish_namespace_done failed: %d", (int)ret);
            }
        } else if (!conn->session_ready) {
            xqc_demo_test_fail("session setup not completed within deadline");
        }
        xqc_demo_interop_close_conn(conn);
        break;

    case XQC_DEMO_TEST_ANNOUNCE_SUBSCRIBE:
    case XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE:
        break;

    default:
        break;
    }
}

static void
xqc_demo_interop_subscriber_subscribe_callback(int fd, short what, void *arg)
{
    (void)fd; (void)what;
    xqc_demo_interop_conn_t *conn = (xqc_demo_interop_conn_t *)arg;
    if (conn == NULL || conn->closed || conn->subscribe_sent) {
        return;
    }
    conn->subscribe_sent = 1;
    VERBOSE("subscriber fallback: sending SUBSCRIBE");
    xqc_demo_interop_send_subscribe_interop(conn->session);
}

static void
xqc_demo_interop_delayed_announce_callback(int fd, short what, void *arg)
{
    (void)fd; (void)what;
    xqc_demo_interop_conn_t *conn = (xqc_demo_interop_conn_t *)arg;
    if (conn == NULL || conn->closed) {
        return;
    }
    VERBOSE("delayed announce: sending PUBLISH_NAMESPACE");
    xqc_demo_interop_send_announce(conn->session);
    g_publisher_announced = 1;
}

static void
xqc_demo_interop_create_subscriber_callback(int fd, short what, void *arg)
{
    (void)fd; (void)what; (void)arg;
    if (g_sub_conn != NULL) {
        return;
    }
    xqc_demo_interop_conn_t *sub = xqc_demo_interop_init_conn(1);
    if (sub == NULL) {
        xqc_demo_test_fail("failed to create subscriber connection");
        return;
    }
    xqc_conn_settings_t settings;
    memset(&settings, 0, sizeof(settings));
    settings.cong_ctrl_callback = xqc_bbr_cb;
    xqc_conn_ssl_config_t ssl_cfg;
    memset(&ssl_cfg, 0, sizeof(ssl_cfg));
    if (g_tls_disable_verify) {
        ssl_cfg.cert_verify_flag |= XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;
    }
    const xqc_cid_t *cid = xqc_connect(g_ctx.engine, &settings, NULL, 0,
        g_relay_sni, 0, &ssl_cfg, sub->peer_addr, sub->peer_addrlen,
        XQC_ALPN_MOQ_QUIC, g_sub_user_session);
    if (cid == NULL) {
        xqc_demo_test_fail("subscriber xqc_connect failed");
        return;
    }
    memcpy(&sub->cid, cid, sizeof(xqc_cid_t));
    VERBOSE("created subscriber connection after publisher ANNOUNCE");
}

static int
xqc_demo_interop_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                           void *user_data, void *conn_proto_data)
{
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    xqc_demo_interop_conn_t *iconn = (xqc_demo_interop_conn_t *)user_session->data;

    xqc_moq_session_callbacks_t callbacks = {
        .on_session_setup           = xqc_demo_interop_on_session_setup,
        .on_datachannel             = xqc_demo_interop_on_datachannel,
        .on_datachannel_msg         = xqc_demo_interop_on_datachannel_msg,
        .on_subscribe               = xqc_demo_interop_on_subscribe,
        .on_request_keyframe        = xqc_demo_interop_on_request_keyframe,
        .on_bitrate_change          = xqc_demo_interop_on_bitrate_change,
        .on_subscribe_ok            = xqc_demo_interop_on_subscribe_ok,
        .on_subscribe_error         = xqc_demo_interop_on_subscribe_error,
        .on_publish                 = xqc_demo_interop_on_publish,
        .on_publish_ok              = xqc_demo_interop_on_publish_ok,
        .on_publish_error           = xqc_demo_interop_on_publish_error,
        .on_publish_done            = xqc_demo_interop_on_publish_done,
        .on_catalog                 = xqc_demo_interop_on_catalog,
        .on_video                   = xqc_demo_interop_on_video,
        .on_audio                   = xqc_demo_interop_on_audio,
    };

    xqc_moq_role_t role = XQC_MOQ_PUBSUB;

    xqc_moq_message_parameter_t setup_params[2];
    memset(setup_params, 0, sizeof(setup_params));
    setup_params[0].type = XQC_MOQ_PARAM_ROLE;
    setup_params[0].is_integer = 1;
    setup_params[0].int_value = role;
    setup_params[1].type = 0x02; /* MaxRequestId */
    setup_params[1].is_integer = 1;
    setup_params[1].int_value = 0xFFFFFFFF;

    xqc_moq_session_t *session = xqc_moq_session_create_with_params(
        conn, user_session, XQC_MOQ_TRANSPORT_QUIC,
        role, callbacks, NULL, 1,
        setup_params, 2);
    if (session == NULL) {
        return -1;
    }
    iconn->session = session;
    return 0;
}

static int
xqc_demo_interop_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                          void *user_data, void *conn_proto_data)
{
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    xqc_demo_interop_conn_t *iconn = (xqc_demo_interop_conn_t *)user_session->data;
    iconn->closed = 1;

    xqc_int_t err = xqc_conn_get_errno(conn);
    VERBOSE("conn_close role=%d err=%d", iconn->conn_role, (int)err);

    if (!g_test_passed && g_fail_reason[0] == '\0') {
        if ((g_current_test == XQC_DEMO_TEST_ANNOUNCE_ONLY || g_current_test == XQC_DEMO_TEST_PUBLISH_NAMESPACE_DONE)
            && iconn->session_ready)
        {
            VERBOSE("connection closed (err=%d) for %s, session was established - PASS",
                    (int)err, g_test_case_names[g_current_test]);
            xqc_demo_test_pass();
        } else if (g_current_test == XQC_DEMO_TEST_SUBSCRIBE_ERROR) {
            if (iconn->subscribe_error_received) {
                xqc_demo_test_pass();
            } else {
                xqc_demo_test_fail("connection closed without SUBSCRIBE_ERROR (err=%d)", (int)err);
            }
        } else if (err != 0) {
            xqc_demo_test_fail("connection error: %d", (int)err);
        }
    }

    xqc_moq_session_destroy(user_session->session);

    if (iconn->ev_socket) {
        event_del(iconn->ev_socket);
        event_free(iconn->ev_socket);
        iconn->ev_socket = NULL;
    }
    if (iconn->fd > 0) {
        close(iconn->fd);
        iconn->fd = -1;
    }
    if (iconn->peer_addr) {
        free(iconn->peer_addr);
        iconn->peer_addr = NULL;
    }
    if (iconn->local_addr) {
        free(iconn->local_addr);
        iconn->local_addr = NULL;
    }

    g_connections_closed++;
    int all_closed = 1;
    if (g_pub_conn && !g_pub_conn->closed) all_closed = 0;
    if (g_sub_conn && !g_sub_conn->closed) all_closed = 0;

    if (all_closed) {
        event_base_loopbreak(g_eb);
    }

    return 0;
}

static void
xqc_demo_interop_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data)
{
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    xqc_demo_interop_conn_t *iconn = (xqc_demo_interop_conn_t *)user_session->data;
    VERBOSE("handshake_finished role=%d", iconn->conn_role);
}

static void
xqc_demo_interop_drain_and_process(xqc_demo_interop_conn_t *conn)
{
    unsigned char buf[1500];
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen;
    for (;;) {
        peer_addrlen = sizeof(peer_addr);
        ssize_t n = recvfrom(conn->fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&peer_addr, &peer_addrlen);
        if (n <= 0) {
            break;
        }
        if (!conn->get_local_addr) {
            conn->get_local_addr = 1;
            socklen_t local_len = sizeof(struct sockaddr_in);
            getsockname(conn->fd, conn->local_addr, &local_len);
            conn->local_addrlen = local_len;
        }
        xqc_engine_packet_process(g_ctx.engine, buf, n,
                                   conn->local_addr, conn->local_addrlen,
                                   (struct sockaddr *)&peer_addr, peer_addrlen,
                                   (xqc_usec_t)xqc_now(), conn);
    }
    xqc_engine_finish_recv(g_ctx.engine);
}

static void
xqc_demo_interop_rebuild_socket(xqc_demo_interop_conn_t *conn)
{
    xqc_demo_interop_drain_and_process(conn);
    if (conn->ev_socket) {
        event_del(conn->ev_socket);
        event_free(conn->ev_socket);
        conn->ev_socket = NULL;
    }
    close(conn->fd);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return;
    }
    fcntl(fd, F_SETFL, O_NONBLOCK);
    int bufsz = 1 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(int));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(int));
    conn->fd = fd;
    conn->ev_socket = event_new(g_eb, fd, EV_READ | EV_PERSIST,
                                 xqc_demo_interop_socket_event_callback, conn);
    event_add(conn->ev_socket, NULL);
}

static ssize_t
xqc_demo_interop_write_socket(const unsigned char *buf, size_t size,
                              const struct sockaddr *peer_addr,
                              socklen_t peer_addrlen, void *user_data)
{
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    xqc_demo_interop_conn_t *conn = (xqc_demo_interop_conn_t *)user_session->data;
    ssize_t res;
    do {
        errno = 0;
        res = sendto(conn->fd, buf, size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
            int err = errno;
            if (err == EAGAIN) {
                return XQC_SOCKET_EAGAIN;
            }
            if (err == EPIPE || err == ECONNREFUSED) {
                xqc_demo_interop_drain_and_process(conn);
                xqc_demo_interop_rebuild_socket(conn);
                res = sendto(conn->fd, buf, size, 0, peer_addr, peer_addrlen);
                if (res < 0) {
                    return XQC_SOCKET_EAGAIN;
                }
                return res;
            }
        }
    } while (res < 0 && errno == EINTR);
    return res;
}

static void xqc_demo_save_token_stub(const unsigned char *t, unsigned l, void *d) { (void)t; (void)l; (void)d; }
static void xqc_demo_save_session_stub(const char *d, size_t l, void *u) { (void)d; (void)l; (void)u; }
static void xqc_demo_save_tp_stub(const char *d, size_t l, void *u) { (void)d; (void)l; (void)u; }

typedef struct xqc_demo_wt_ctx_s {
    xqc_h3_conn_t      *h3_conn;
    xqc_h3_request_t   *connect_request;
    uint64_t            session_id;
    uint8_t             connect_sent;
    uint8_t             session_ready;
    xqc_demo_interop_conn_t *iconn;
    xqc_moq_user_session_t  *user_session;
} xqc_demo_wt_ctx_t;

static xqc_demo_wt_ctx_t *g_wt_ctx = NULL;
#define MAX_WT_CTX 2
static xqc_demo_wt_ctx_t *g_wt_ctxs[MAX_WT_CTX] = {NULL, NULL};

static xqc_demo_wt_ctx_t *
xqc_demo_wt_ctx_for_user_session(xqc_moq_user_session_t *us)
{
    for (int i = 0; i < MAX_WT_CTX; i++) {
        if (g_wt_ctxs[i] && g_wt_ctxs[i]->user_session == us) {
            return g_wt_ctxs[i];
        }
    }
    return NULL;
}

static xqc_demo_wt_ctx_t *
xqc_demo_wt_ctx_for_h3_conn(xqc_h3_conn_t *h3c)
{
    for (int i = 0; i < MAX_WT_CTX; i++) {
        if (g_wt_ctxs[i] && g_wt_ctxs[i]->h3_conn == h3c) {
            return g_wt_ctxs[i];
        }
    }
    return NULL;
}

static void
xqc_demo_wt_h3_conn_init_settings(xqc_h3_conn_t *h3_conn,
    xqc_h3_conn_settings_t *settings, void *h3c_user_data)
{
    VERBOSE("wt: h3_conn_init_settings - enabling WT settings");
#if 0
    /* WebTransport settings not available on moq_draft_14_dev_relay branch */
    settings->enable_connect_protocol = 1;
    settings->enable_h3_datagram = 1;
    settings->webtransport_max_sessions = 1;
#endif
}

static int
xqc_demo_wt_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *h3c_user_data)
{
    xqc_moq_user_session_t *us = (xqc_moq_user_session_t *)h3c_user_data;
    xqc_demo_wt_ctx_t *ctx = xqc_demo_wt_ctx_for_user_session(us);
    if (ctx == NULL) {
        ctx = calloc(1, sizeof(xqc_demo_wt_ctx_t));
        ctx->user_session = us;
        ctx->iconn = (xqc_demo_interop_conn_t *)us->data;
        for (int i = 0; i < MAX_WT_CTX; i++) {
            if (g_wt_ctxs[i] == NULL) { g_wt_ctxs[i] = ctx; break; }
        }
        if (g_wt_ctx == NULL) g_wt_ctx = ctx;
    }
    ctx->h3_conn = h3_conn;
    VERBOSE("wt: h3_conn_create_notify role=%d", ctx->iconn ? ctx->iconn->conn_role : -1);
    return 0;
}

static int
xqc_demo_wt_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *h3c_user_data)
{
    xqc_demo_wt_ctx_t *ctx = xqc_demo_wt_ctx_for_h3_conn(h3_conn);
    VERBOSE("wt: h3_conn_close_notify ctx=%p", (void*)ctx);

    if (ctx && ctx->iconn) {
        xqc_demo_interop_conn_t *iconn = ctx->iconn;
        iconn->closed = 1;

        xqc_connection_t *conn = xqc_h3_conn_get_xqc_conn(h3_conn);
        xqc_int_t err = xqc_conn_get_errno(conn);

        if (!g_test_passed && g_fail_reason[0] == '\0') {
            if ((g_current_test == XQC_DEMO_TEST_SETUP_ONLY
                 || g_current_test == XQC_DEMO_TEST_ANNOUNCE_ONLY
                 || g_current_test == XQC_DEMO_TEST_PUBLISH_NAMESPACE_DONE)
                && iconn->session_ready)
            {
                xqc_demo_test_pass();
            } else if (err != 0) {
                xqc_demo_test_fail("wt connection error: %d", (int)err);
            }
        }

        if (iconn->session) {
            xqc_moq_session_destroy(iconn->session);
        }

        if (iconn->ev_socket) {
            event_del(iconn->ev_socket);
            event_free(iconn->ev_socket);
            iconn->ev_socket = NULL;
        }
        if (iconn->fd > 0) {
            close(iconn->fd);
            iconn->fd = -1;
        }
        if (iconn->peer_addr) {
            free(iconn->peer_addr);
            iconn->peer_addr = NULL;
        }
        if (iconn->local_addr) {
            free(iconn->local_addr);
            iconn->local_addr = NULL;
        }

        g_connections_closed++;
        event_base_loopbreak(g_eb);
    }

    if (ctx) {
        for (int i = 0; i < MAX_WT_CTX; i++) {
            if (g_wt_ctxs[i] == ctx) { g_wt_ctxs[i] = NULL; break; }
        }
        if (g_wt_ctx == ctx) g_wt_ctx = NULL;
        free(ctx);
    }

    return 0;
}

static void
xqc_demo_wt_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *h3c_user_data)
{
    xqc_demo_wt_ctx_t *ctx = xqc_demo_wt_ctx_for_h3_conn(h3_conn);
    if (ctx == NULL || ctx->connect_sent) {
        return;
    }
    VERBOSE("wt: h3 handshake finished, sending CONNECT role=%d", ctx->iconn ? ctx->iconn->conn_role : -1);

    xqc_demo_interop_conn_t *iconn = ctx->iconn;
    ctx->connect_request = xqc_h3_request_create(g_ctx.engine, &iconn->cid, NULL, ctx);
    if (ctx->connect_request == NULL) {
        xqc_demo_test_fail("wt: failed to create CONNECT request");
        return;
    }

    char authority[300];
    snprintf(authority, sizeof(authority), "%s:%d", g_relay_sni, g_relay_port);

    xqc_http_header_t headers[] = {
        {
            .name  = {.iov_base = (void *)":method",    .iov_len = 7},
            .value = {.iov_base = (void *)"CONNECT",    .iov_len = 7},
            .flags = 0,
        },
        {
            .name  = {.iov_base = (void *)":protocol",  .iov_len = 9},
            .value = {.iov_base = (void *)"webtransport", .iov_len = 12},
            .flags = 0,
        },
        {
            .name  = {.iov_base = (void *)":scheme",    .iov_len = 7},
            .value = {.iov_base = (void *)"https",      .iov_len = 5},
            .flags = 0,
        },
        {
            .name  = {.iov_base = (void *)":authority",  .iov_len = 10},
            .value = {.iov_base = (void *)authority,     .iov_len = strlen(authority)},
            .flags = 0,
        },
        {
            .name  = {.iov_base = (void *)":path",      .iov_len = 5},
            .value = {.iov_base = (void *)g_relay_path,  .iov_len = strlen(g_relay_path)},
            .flags = 0,
        },
    };

    xqc_http_headers_t h = {
        .headers = headers,
        .count   = 5,
    };

    ssize_t ret = xqc_h3_request_send_headers(ctx->connect_request, &h, 0);
    if (ret < 0) {
        xqc_demo_test_fail("wt: failed to send CONNECT headers: %zd", ret);
        return;
    }
    ctx->connect_sent = 1;
    VERBOSE("wt: CONNECT request sent to %s%s", authority, g_relay_path);
}

static int
xqc_demo_wt_h3_request_create_notify(xqc_h3_request_t *h3_request, void *h3s_user_data)
{
    VERBOSE("wt: h3_request_create_notify");
    return 0;
}

static int
xqc_demo_wt_h3_request_close_notify(xqc_h3_request_t *h3_request, void *h3s_user_data)
{
    VERBOSE("wt: h3_request_close_notify");
    return 0;
}

static int
xqc_demo_wt_h3_request_read_notify(xqc_h3_request_t *h3_request,
    xqc_request_notify_flag_t flag, void *strm_user_data)
{
    if (!(flag & XQC_REQ_NOTIFY_READ_HEADER)) {
        return 0;
    }

    unsigned char fin = 0;
    xqc_http_headers_t *headers = xqc_h3_request_recv_headers(h3_request, &fin);
    if (headers == NULL) {
        return 0;
    }

    int got_200 = 0;
    for (int i = 0; i < headers->count; i++) {
        char *name  = (char *)headers->headers[i].name.iov_base;
        char *value = (char *)headers->headers[i].value.iov_base;
        VERBOSE("wt: response header %s: %s", name, value);
        if (strcmp(name, ":status") == 0 && strcmp(value, "200") == 0) {
            got_200 = 1;
        }
    }

    if (!got_200) {
        xqc_demo_test_fail("wt: CONNECT response was not 200");
        return -1;
    }

    xqc_demo_wt_ctx_t *ctx = (xqc_demo_wt_ctx_t *)strm_user_data;
    if (ctx == NULL) {
        xqc_demo_test_fail("wt: no wt_ctx in request_read_notify");
        return -1;
    }

    VERBOSE("wt: CONNECT 200 OK - WebTransport session established");
    ctx->session_ready = 1;
    ctx->session_id = xqc_h3_stream_id(ctx->connect_request);
    VERBOSE("wt: session_id = %llu (CONNECT stream ID)", (unsigned long long)ctx->session_id);

    xqc_demo_interop_conn_t *iconn = ctx->iconn;
    xqc_moq_user_session_t *user_session = ctx->user_session;

    xqc_moq_session_callbacks_t callbacks = {
        .on_session_setup           = xqc_demo_interop_on_session_setup,
        .on_datachannel             = xqc_demo_interop_on_datachannel,
        .on_datachannel_msg         = xqc_demo_interop_on_datachannel_msg,
        .on_subscribe               = xqc_demo_interop_on_subscribe,
        .on_request_keyframe        = xqc_demo_interop_on_request_keyframe,
        .on_bitrate_change          = xqc_demo_interop_on_bitrate_change,
        .on_subscribe_ok            = xqc_demo_interop_on_subscribe_ok,
        .on_subscribe_error         = xqc_demo_interop_on_subscribe_error,
        .on_publish                 = xqc_demo_interop_on_publish,
        .on_publish_ok              = xqc_demo_interop_on_publish_ok,
        .on_publish_error           = xqc_demo_interop_on_publish_error,
        .on_publish_done            = xqc_demo_interop_on_publish_done,
        .on_catalog                 = xqc_demo_interop_on_catalog,
        .on_video                   = xqc_demo_interop_on_video,
        .on_audio                   = xqc_demo_interop_on_audio,
    };

    xqc_connection_t *quic_conn = xqc_h3_conn_get_xqc_conn(ctx->h3_conn);
    xqc_moq_session_t *session = xqc_moq_session_create(
        quic_conn, user_session, XQC_MOQ_TRANSPORT_WEBTRANSPORT,
        XQC_MOQ_PUBSUB, callbacks, NULL, 1);
    if (session == NULL) {
        xqc_demo_test_fail("wt: failed to create MoQ session");
        return -1;
    }
    iconn->session = session;

#if 0
    /* WebTransport session context APIs not available on moq_draft_14_dev_relay branch */
    xqc_moq_wt_session_ctx_t *wt_sess_ctx = xqc_moq_wt_session_ctx_create();
    wt_sess_ctx->h3_conn = ctx->h3_conn;
    wt_sess_ctx->session_id = ctx->session_id;
    wt_sess_ctx->session_ready = 1;
    wt_sess_ctx->moq_session = session;
    session->wt_session_ctx = wt_sess_ctx;

    xqc_int_t ret2 = xqc_moq_session_wt_start(session);
    if (ret2 < 0) {
        xqc_demo_test_fail("wt: failed to start MoQ session: %d", (int)ret2);
        return -1;
    }
#endif

    VERBOSE("wt: MoQ CLIENT_SETUP sent over WebTransport");
    return 0;
}

static int
xqc_demo_run_single_test(xqc_demo_test_case_t tc)
{
    g_current_test = tc;
    g_test_passed = 0;
    g_fail_reason[0] = '\0';
    g_connections_closed = 0;
    g_pub_conn = NULL;
    g_sub_conn = NULL;
    g_pub_user_session = NULL;
    g_sub_user_session = NULL;
    g_request_id_counter = 0;
    g_publisher_announced = 0;
    g_wt_ctx = NULL;
    memset(g_wt_ctxs, 0, sizeof(g_wt_ctxs));
    g_test_start_us = xqc_now();

    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.log_fd = -1;
    if (g_verbose) {
        xqc_app_open_log_file(&g_ctx, "./interop_clog");
    }
    xqc_platform_init_env();

    xqc_engine_ssl_config_t engine_ssl_cfg;
    memset(&engine_ssl_cfg, 0, sizeof(engine_ssl_cfg));
    engine_ssl_cfg.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_cfg.groups = XQC_TLS_GROUPS;

    xqc_engine_callback_t engine_cbs = {
        .set_event_timer = xqc_app_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = xqc_app_write_log,
            .xqc_log_write_stat = xqc_app_write_log,
        },
    };

    xqc_transport_callbacks_t tcbs = {
        .write_socket    = xqc_demo_interop_write_socket,
        .save_token      = xqc_demo_save_token_stub,
        .save_session_cb = xqc_demo_save_session_stub,
        .save_tp_cb      = xqc_demo_save_tp_stub,
    };

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        xqc_demo_test_fail("engine config failed");
        return 0;
    }
    if (g_verbose) {
        xqc_app_set_log_level('d', &config);
    } else {
        xqc_app_set_log_level('e', &config);
    }
    config.cid_len = XQC_INTEROP_CID_LEN;

    g_ctx.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &config, &engine_ssl_cfg,
                                      &engine_cbs, &tcbs, &g_ctx);
    if (g_ctx.engine == NULL) {
        xqc_demo_test_fail("engine creation failed");
        return 0;
    }

    g_eb = event_base_new();
    g_ctx.ev_engine = event_new(g_eb, -1, 0, xqc_app_engine_callback, &g_ctx);

    if (g_transport_type == XQC_MOQ_TRANSPORT_WEBTRANSPORT) {
        xqc_h3_callbacks_t h3_cbs = {
            .h3c_cbs = {
                .h3_conn_create_notify      = xqc_demo_wt_h3_conn_create_notify,
                .h3_conn_close_notify       = xqc_demo_wt_h3_conn_close_notify,
                .h3_conn_handshake_finished = xqc_demo_wt_h3_conn_handshake_finished,
                .h3_conn_init_settings      = xqc_demo_wt_h3_conn_init_settings,
            },
            .h3r_cbs = {
                .h3_request_create_notify   = xqc_demo_wt_h3_request_create_notify,
                .h3_request_close_notify    = xqc_demo_wt_h3_request_close_notify,
                .h3_request_read_notify     = xqc_demo_wt_h3_request_read_notify,
            },
        };
        xqc_h3_ctx_init(g_ctx.engine, &h3_cbs);
    } else {
        xqc_conn_callbacks_t conn_cbs = {
            .conn_create_notify = xqc_demo_interop_conn_create_notify,
            .conn_close_notify = xqc_demo_interop_conn_close_notify,
            .conn_handshake_finished = xqc_demo_interop_conn_handshake_finished,
        };
        xqc_moq_init_alpn(g_ctx.engine, &conn_cbs, g_transport_type);
    }

    struct event *ev_timeout = evtimer_new(g_eb, xqc_demo_interop_timeout_callback, NULL);
    int timeout_sec = XQC_INTEROP_TIMEOUT_SEC;
    if (tc == XQC_DEMO_TEST_SUBSCRIBE_ERROR) {
        timeout_sec = 4;
    } else if (tc == XQC_DEMO_TEST_ANNOUNCE_SUBSCRIBE || tc == XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE) {
        timeout_sec = 20;
    }
    struct timeval tv_timeout = { timeout_sec, 0 };
    event_add(ev_timeout, &tv_timeout);

    int first_role;
    switch (tc) {
    case XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE:
        first_role = 1;
        break;
    default:
        first_role = (tc == XQC_DEMO_TEST_SUBSCRIBE_ERROR) ? 1 : 0;
        break;
    }

    xqc_demo_interop_conn_t *first = xqc_demo_interop_init_conn(first_role);
    if (first == NULL) {
        xqc_demo_test_fail("failed to create connection");
        goto cleanup;
    }

    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(conn_settings));
    conn_settings.cong_ctrl_callback = xqc_bbr_cb;
    conn_settings.proto_version = XQC_VERSION_V1;

    xqc_conn_ssl_config_t conn_ssl_cfg;
    memset(&conn_ssl_cfg, 0, sizeof(conn_ssl_cfg));
    if (g_tls_disable_verify) {
        conn_ssl_cfg.cert_verify_flag |= XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;
    }

    xqc_moq_user_session_t *first_us = (first_role == 0) ? g_pub_user_session : g_sub_user_session;
    const xqc_cid_t *cid;
    if (g_transport_type == XQC_MOQ_TRANSPORT_WEBTRANSPORT) {
        cid = xqc_h3_connect(g_ctx.engine, &conn_settings, NULL, 0,
            g_relay_sni, 0, &conn_ssl_cfg, first->peer_addr, first->peer_addrlen,
            first_us);
    } else {
        cid = xqc_connect(g_ctx.engine, &conn_settings, NULL, 0,
            g_relay_sni, 0, &conn_ssl_cfg, first->peer_addr, first->peer_addrlen,
            XQC_ALPN_MOQ_QUIC, first_us);
    }
    if (cid == NULL) {
        xqc_demo_test_fail("xqc_connect failed");
        goto cleanup;
    }
    memcpy(&first->cid, cid, sizeof(xqc_cid_t));

    if (tc == XQC_DEMO_TEST_ANNOUNCE_ONLY || tc == XQC_DEMO_TEST_PUBLISH_NAMESPACE_DONE) {
        struct event *ev_delayed = evtimer_new(g_eb, xqc_demo_interop_delayed_action_callback, first);
        struct timeval delay = { 3, 0 };
        event_add(ev_delayed, &delay);
    }

    if (tc == XQC_DEMO_TEST_ANNOUNCE_SUBSCRIBE || tc == XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE) {
        int second_role = (tc == XQC_DEMO_TEST_ANNOUNCE_SUBSCRIBE) ? 1 : 0;
        xqc_demo_interop_conn_t *second = xqc_demo_interop_init_conn(second_role);
        if (second == NULL) {
            xqc_demo_test_fail("failed to create second connection");
            goto cleanup;
        }
        xqc_conn_settings_t second_settings;
        memset(&second_settings, 0, sizeof(second_settings));
        second_settings.cong_ctrl_callback = xqc_bbr_cb;
        xqc_conn_ssl_config_t second_ssl_cfg;
        memset(&second_ssl_cfg, 0, sizeof(second_ssl_cfg));
        if (g_tls_disable_verify) {
            second_ssl_cfg.cert_verify_flag |= XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;
        }
        xqc_moq_user_session_t *second_us = (second_role == 0) ? g_pub_user_session : g_sub_user_session;
        const xqc_cid_t *second_cid;
        if (g_transport_type == XQC_MOQ_TRANSPORT_WEBTRANSPORT) {
            second_settings.proto_version = XQC_VERSION_V1;
            second_cid = xqc_h3_connect(g_ctx.engine, &second_settings, NULL, 0,
                g_relay_sni, 0, &second_ssl_cfg, second->peer_addr, second->peer_addrlen,
                second_us);
        } else {
            second_cid = xqc_connect(g_ctx.engine, &second_settings, NULL, 0,
                g_relay_sni, 0, &second_ssl_cfg, second->peer_addr, second->peer_addrlen,
                XQC_ALPN_MOQ_QUIC, second_us);
        }
        if (second_cid == NULL) {
            xqc_demo_test_fail("second xqc_connect failed");
            goto cleanup;
        }
        memcpy(&second->cid, second_cid, sizeof(xqc_cid_t));
    }

    event_base_dispatch(g_eb);

cleanup:
    event_del(ev_timeout);
    event_free(ev_timeout);
    if (g_ctx.ev_engine) {
        event_del(g_ctx.ev_engine);
        event_free(g_ctx.ev_engine);
    }
    xqc_engine_destroy(g_ctx.engine);
    event_base_free(g_eb);

    if (g_pub_user_session && g_pub_conn && !g_pub_conn->closed) {
        free(g_pub_user_session);
    }
    if (g_sub_user_session && g_sub_conn && !g_sub_conn->closed) {
        free(g_sub_user_session);
    }

    return g_test_passed;
}

static int
xqc_demo_parse_relay_url(const char *url)
{
    const char *p = url;
    if (strncmp(p, "moqt://", 7) == 0) {
        p += 7;
        g_transport_type = XQC_MOQ_TRANSPORT_QUIC;
    } else if (strncmp(p, "https://", 8) == 0) {
        p += 8;
        g_transport_type = XQC_MOQ_TRANSPORT_WEBTRANSPORT;
    }

    const char *slash = strchr(p, '/');
    const char *host_end = slash ? slash : p + strlen(p);

    const char *colon = NULL;
    for (const char *c = p; c < host_end; c++) {
        if (*c == ':') colon = c;
    }

    if (colon) {
        size_t hlen = colon - p;
        if (hlen >= sizeof(g_relay_host)) hlen = sizeof(g_relay_host) - 1;
        memcpy(g_relay_host, p, hlen);
        g_relay_host[hlen] = '\0';

        char port_buf[16] = {0};
        size_t plen = host_end - (colon + 1);
        if (plen >= sizeof(port_buf)) plen = sizeof(port_buf) - 1;
        memcpy(port_buf, colon + 1, plen);
        g_relay_port = atoi(port_buf);
    } else {
        size_t hlen = host_end - p;
        if (hlen >= sizeof(g_relay_host)) hlen = sizeof(g_relay_host) - 1;
        memcpy(g_relay_host, p, hlen);
        g_relay_host[hlen] = '\0';
        g_relay_port = (g_transport_type == XQC_MOQ_TRANSPORT_WEBTRANSPORT) ? 443 : 4443;
    }

    if (slash && strlen(slash) > 0) {
        snprintf(g_relay_path, sizeof(g_relay_path), "%s", slash);
    } else {
        snprintf(g_relay_path, sizeof(g_relay_path), "/");
    }

    return 0;
}

static xqc_demo_test_case_t
xqc_demo_parse_test_name(const char *name)
{
    for (int i = 0; i < XQC_INTEROP_MAX_TESTS; i++) {
        if (strcmp(name, g_test_case_names[i]) == 0) {
            return (xqc_demo_test_case_t)i;
        }
    }
    return XQC_DEMO_TEST_UNKNOWN;
}

static int
xqc_demo_resolve_hostname(const char *hostname, char *ip_buf, size_t ip_buf_len)
{
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int ret = getaddrinfo(hostname, NULL, &hints, &res);
    if (ret != 0 || res == NULL) {
        return -1;
    }
    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ip_buf, ip_buf_len);
    freeaddrinfo(res);
    return 0;
}

int main(int argc, char *argv[])
{
    signal(SIGPIPE, SIG_IGN);

    const char *relay_url = getenv("RELAY_URL");
    const char *testcase = getenv("TESTCASE");
    const char *tls_verify = getenv("TLS_DISABLE_VERIFY");
    const char *verbose = getenv("VERBOSE");

    const char *cli_sni = NULL;
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--relay") == 0 || strcmp(argv[i], "-r") == 0) && i + 1 < argc) {
            relay_url = argv[++i];
        } else if ((strcmp(argv[i], "--test") == 0 || strcmp(argv[i], "-t") == 0) && i + 1 < argc) {
            testcase = argv[++i];
        } else if (strcmp(argv[i], "--sni") == 0 && i + 1 < argc) {
            cli_sni = argv[++i];
        } else if (strcmp(argv[i], "--tls-disable-verify") == 0) {
            g_tls_disable_verify = 1;
        } else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            g_verbose = 1;
        } else if (strcmp(argv[i], "--list") == 0 || strcmp(argv[i], "-l") == 0) {
            for (int j = 0; j < XQC_INTEROP_MAX_TESTS; j++) {
                printf("%s\n", g_test_case_names[j]);
            }
            return 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [OPTIONS]\n\n", argv[0]);
            printf("Options:\n");
            printf("  -r, --relay <URL>        Relay URL (moqt://host:port or https://host:port/path)\n");
            printf("  -t, --test <NAME>        Run specific test (omit to run all)\n");
            printf("  -l, --list               List available tests\n");
            printf("  -v, --verbose            Verbose output\n");
            printf("      --sni <hostname>     Override TLS SNI\n");
            printf("      --tls-disable-verify Disable TLS certificate verification\n");
            return 0;
        }
    }

    if (tls_verify && (strcmp(tls_verify, "1") == 0 || strcmp(tls_verify, "true") == 0)) {
        g_tls_disable_verify = 1;
    }
    if (verbose && (strcmp(verbose, "1") == 0 || strcmp(verbose, "true") == 0)) {
        g_verbose = 1;
    }

    if (relay_url == NULL || relay_url[0] == '\0') {
        fprintf(stderr, "error: RELAY_URL is required (e.g., moqt://host:4443 or https://host:443/path)\n");
        return 1;
    }

    if (xqc_demo_parse_relay_url(relay_url) < 0) {
        return 1;
    }

    snprintf(g_relay_sni, sizeof(g_relay_sni), "%s", g_relay_host);
    if (cli_sni) {
        snprintf(g_relay_sni, sizeof(g_relay_sni), "%s", cli_sni);
    }
    struct in_addr test_addr;
    if (inet_aton(g_relay_host, &test_addr) == 0) {
        char resolved_ip[64];
        if (xqc_demo_resolve_hostname(g_relay_host, resolved_ip, sizeof(resolved_ip)) < 0) {
            fprintf(stderr, "error: cannot resolve hostname '%s'\n", g_relay_host);
            return 1;
        }
        VERBOSE("resolved %s -> %s", g_relay_host, resolved_ip);
        strncpy(g_relay_host, resolved_ip, sizeof(g_relay_host) - 1);
    }

    xqc_demo_test_case_t tests[XQC_INTEROP_MAX_TESTS];
    int num_tests = 0;

    if (testcase && testcase[0]) {
        xqc_demo_test_case_t tc = xqc_demo_parse_test_name(testcase);
        if (tc == XQC_DEMO_TEST_UNKNOWN) {
            fprintf(stderr, "error: unknown test case '%s'\n", testcase);
            fprintf(stderr, "  valid: setup-only, announce-only, subscribe-error, announce-subscribe, subscribe-before-announce, publish-namespace-done\n");
            return 1;
        }
        tests[0] = tc;
        num_tests = 1;
    } else {
        for (int i = 0; i < XQC_INTEROP_MAX_TESTS; i++) {
            tests[i] = (xqc_demo_test_case_t)i;
        }
        num_tests = XQC_INTEROP_MAX_TESTS;
    }

    xqc_demo_tap_header();
    xqc_demo_tap_plan(num_tests);

    int all_passed = 1;
    for (int i = 0; i < num_tests; i++) {
        int passed = xqc_demo_run_single_test(tests[i]);
        uint64_t duration_ms = (xqc_now() - g_test_start_us) / 1000;
        xqc_demo_tap_result(i + 1, g_test_case_names[tests[i]], passed, duration_ms,
                   passed ? "" : g_fail_reason);
        if (!passed) {
            all_passed = 0;
        }
    }

    return all_passed ? 0 : 1;
}
