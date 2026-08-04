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
#include "moq/moq_transport/draft18/xqc_moq_d18_params.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_stream_webtransport.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/transport/xqc_stream.h"

#define XQC_INTEROP_VERSION       "0.7.0-draft18"
#define XQC_INTEROP_CID_LEN       12
#define XQC_INTEROP_TIMEOUT_SEC   2
#define XQC_INTEROP_MAX_TESTS     21

extern long xqc_random(void);
extern xqc_usec_t xqc_now();

typedef enum {
    XQC_DEMO_TEST_SETUP_ONLY = 0,
    XQC_DEMO_TEST_ANNOUNCE_ONLY,
    XQC_DEMO_TEST_PUBLISH_NAMESPACE_DONE,
    XQC_DEMO_TEST_SUBSCRIBE_ERROR,
    XQC_DEMO_TEST_ANNOUNCE_SUBSCRIBE,
    XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE,
    XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OK,
    XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OVERLAP,
    XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_NOTIFICATIONS,
    XQC_DEMO_TEST_SUBSCRIBE_TRACKS_PUBLISH,
    XQC_DEMO_TEST_SUBSCRIBE_TRACKS_OVERLAP,
    XQC_DEMO_TEST_REQUEST_UPDATE_SUCCESS,
    XQC_DEMO_TEST_REQUEST_UPDATE_OVERLAP,
    XQC_DEMO_TEST_PUBLISH_BLOCKED,
    XQC_DEMO_TEST_PUBLISH_DONE,
    XQC_DEMO_TEST_CONTROL_GOAWAY,
    XQC_DEMO_TEST_REQUEST_GOAWAY,
    XQC_DEMO_TEST_TRACK_STATUS_SUCCESS,
    XQC_DEMO_TEST_TRACK_STATUS_REJECTION,
    XQC_DEMO_TEST_FETCH_SUCCESS,
    XQC_DEMO_TEST_FETCH_REJECTION,
    XQC_DEMO_TEST_ALL,
    XQC_DEMO_TEST_UNKNOWN,
} xqc_demo_test_case_t;

static const char *g_test_case_names[] = {
    "setup-only",
    "announce-only",
    "publish-namespace-done",
    "subscribe-error",
    "announce-subscribe",
    "subscribe-before-announce",
    "subscribe-namespace-ok",
    "subscribe-namespace-overlap",
    "subscribe-namespace-notifications",
    "subscribe-tracks-publish",
    "subscribe-tracks-overlap",
    "request-update-success",
    "request-update-overlap",
    "publish-blocked",
    "publish-done",
    "control-goaway",
    "request-goaway",
    "track-status-success",
    "track-status-rejection",
    "fetch-success",
    "fetch-rejection",
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
    int                  publish_ns_sent;
    int                  publish_ns_ok_received;
    int                  publish_ns_cancelled;
    uint64_t             publish_ns_request_id;
    int                  subscribe_error_received;
    uint64_t             subscribe_request_id;
    int                  announcement_received;
    int                  subscribe_sent;
    int                  subscribe_ok_received;
    uint64_t             namespace_first_request_id;
    uint64_t             namespace_second_request_id;
    int                  namespace_second_sent;
    int                  namespace_first_generic_ok;
    int                  namespace_first_compat_ok;
    int                  namespace_second_generic_error;
    int                  namespace_second_compat_error;
    int                  namespace_notification_received;
    int                  namespace_done_received;
    uint64_t             tracks_first_request_id;
    uint64_t             tracks_second_request_id;
    int                  tracks_first_generic_ok;
    int                  tracks_second_sent;
    int                  tracks_overlap_error;
    int                  publish_received;
    int                  publish_response_sent;
    uint64_t             request_update_target_id;
    uint64_t             request_update_id;
    int                  request_update_initial_ok;
    int                  request_update_ok;
    int                  request_update_blocked;
    uint64_t             request_update_other_id;
    int                  request_update_other_ok;
    int                  request_update_sent;
    int                  request_update_overlap_error;
    int                  request_update_terminal_observed;
    uint64_t             publish_blocked_request_id;
    int                  publish_blocked_initial_ok;
    uint64_t             publish_done_discovery_request_id;
    uint64_t             publish_done_stream_request_id;
    int                  publish_done_discovery_ok;
    int                  publish_done_response_sent;
    int                  publish_done_callback_count;
    int                  publish_done_fin_observed;
    int                  publish_done_completion_scheduled;
    uint64_t             control_goaway_first_request_id;
    uint64_t             control_goaway_cutoff_request_id;
    int                  control_goaway_established_retained;
    int                  control_goaway_received;
    int                  control_goaway_cutoff_error;
    uint64_t             request_goaway_target_request_id;
    uint64_t             request_goaway_other_request_id;
    int                  request_goaway_target_ok;
    int                  request_goaway_other_ok;
    int                  request_goaway_received;
    int                  request_goaway_cancel_count;
    int                  request_goaway_other_retained;
    int                  request_goaway_completion_scheduled;
    int                  request_goaway_semantic_complete;
    uint64_t             finite_request_id;
    int                  finite_generic_ok;
    int                  finite_specific_ok;
    int                  finite_error_seen;
    int                  fetch_ok_seen;
    int                  fetch_header_seen;
    int                  fetch_header_fin;
    unsigned             fetch_object_count;
    int                  fetch_range_seen;
    int                  finite_completion_scheduled;
    unsigned             finite_completion_attempts;
} xqc_demo_interop_conn_t;

static xqc_app_ctx_t       g_ctx;
static struct event_base   *g_eb;
static struct event        *g_test_timeout_event;
static struct event        *g_close_timeout_event;

static char     g_relay_host[256] = "";
static char     g_relay_sni[256]  = "";
static char     g_relay_path[256] = "";
static int      g_relay_port = 4443;
static int      g_verbose = 0;
static int      g_tls_disable_verify = 0;
static int      g_disconnect_after_request = 0;
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

static xqc_moq_track_ns_field_t interop_ns_tuple[] = {
    {
        .len = sizeof("moq-test") - 1,
        .data = (unsigned char *)"moq-test",
    },
    {
        .len = sizeof("interop") - 1,
        .data = (unsigned char *)"interop",
    },
};
static const char *XQC_NONEXISTENT_NS_STR = "nonexistent/namespace";
static xqc_moq_track_ns_field_t nonexistent_ns_tuple[] = {
    {
        .len = sizeof("nonexistent") - 1,
        .data = (unsigned char *)"nonexistent",
    },
    {
        .len = sizeof("namespace") - 1,
        .data = (unsigned char *)"namespace",
    },
};

#define VERBOSE(...) do { if (g_verbose) { fprintf(stderr, "[verbose] " __VA_ARGS__); fprintf(stderr, "\n"); } } while(0)

static void
xqc_demo_interop_write_log(xqc_log_level_t lvl, const void *buf, size_t count,
    void *engine_user_data)
{
    if (g_verbose) {
        xqc_app_write_log(lvl, buf, count, engine_user_data);
    }
}

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
    printf("# Draft: draft-18\n");
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
xqc_demo_interop_close_timeout_callback(int fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    (void)arg;
    VERBOSE("connection close deadline elapsed; leaving event loop");
    event_base_loopbreak(g_eb);
}

static void
xqc_demo_interop_arm_close_timeout(void)
{
    if (g_close_timeout_event == NULL
        || event_pending(g_close_timeout_event, EV_TIMEOUT, NULL))
    {
        return;
    }

    struct timeval close_timeout = { 1, 0 };
    if (event_add(g_close_timeout_event, &close_timeout) < 0) {
        event_base_loopbreak(g_eb);
    }
}

static void
xqc_demo_interop_close_conn(xqc_demo_interop_conn_t *conn)
{
    if (conn == NULL || conn->closed) {
        return;
    }
    if (g_test_passed || g_fail_reason[0] != '\0') {
        xqc_demo_interop_arm_close_timeout();
    }
    VERBOSE("closing connection role=%d", conn->conn_role);
    xqc_conn_close(g_ctx.engine, &conn->cid);
}

static void
xqc_demo_interop_maybe_complete_preannounce(void)
{
    if (g_current_test != XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE
        || g_sub_conn == NULL || g_pub_conn == NULL
        || !g_pub_conn->publish_ns_ok_received
        || (!g_sub_conn->subscribe_ok_received
            && !g_sub_conn->subscribe_error_received))
    {
        return;
    }

    VERBOSE("subscribe-before-announce completed via %s after publisher REQUEST_OK",
            g_sub_conn->subscribe_ok_received ? "SUBSCRIBE_OK" : "REQUEST_ERROR");
    xqc_demo_test_pass();
    if (g_test_timeout_event) {
        event_del(g_test_timeout_event);
    }
    xqc_demo_interop_close_conn(g_sub_conn);
    xqc_demo_interop_close_conn(g_pub_conn);
}

static void
xqc_demo_interop_timeout_callback(int fd, short what, void *arg)
{
    (void)fd; (void)what;

    if (g_current_test == XQC_DEMO_TEST_ANNOUNCE_ONLY) {
        xqc_demo_test_fail("timeout: no REQUEST_OK received for PUBLISH_NAMESPACE");
    } else if (g_current_test == XQC_DEMO_TEST_PUBLISH_NAMESPACE_DONE) {
        xqc_demo_interop_conn_t *pub = g_pub_conn;
        if (pub && pub->publish_ns_ok_received && !pub->publish_ns_cancelled) {
            xqc_demo_test_fail("timeout: PUBLISH_NAMESPACE request stream was not cancelled");
        } else {
            xqc_demo_test_fail("timeout: no REQUEST_OK received for PUBLISH_NAMESPACE");
        }
    } else if (g_current_test == XQC_DEMO_TEST_SUBSCRIBE_ERROR) {
        xqc_demo_interop_conn_t *sub = g_sub_conn;
        if (sub && sub->subscribe_error_received) {
            xqc_demo_test_pass();
        } else if (sub && sub->subscribe_ok_received) {
            xqc_demo_test_fail("expected REQUEST_ERROR, got SUBSCRIBE_OK");
        } else {
            xqc_demo_test_fail("timeout: no REQUEST_ERROR received");
        }
    } else if (g_current_test == XQC_DEMO_TEST_ANNOUNCE_SUBSCRIBE) {
        if (g_pub_conn == NULL || !g_pub_conn->publish_ns_ok_received) {
            xqc_demo_test_fail("timeout: publisher did not receive REQUEST_OK");
        } else if (g_sub_conn == NULL || !g_sub_conn->subscribe_sent) {
            xqc_demo_test_fail("timeout: subscriber did not send SUBSCRIBE");
        } else {
            xqc_demo_test_fail("timeout: subscriber did not receive SUBSCRIBE_OK");
        }
    } else if (g_current_test == XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE) {
        if (g_sub_conn == NULL || !g_sub_conn->subscribe_sent) {
            xqc_demo_test_fail("timeout: subscriber did not send SUBSCRIBE before publisher start");
        } else if (g_pub_conn == NULL || !g_pub_conn->publish_ns_sent) {
            xqc_demo_test_fail("timeout: publisher did not send PUBLISH_NAMESPACE");
        } else if (!g_pub_conn->publish_ns_ok_received) {
            xqc_demo_test_fail("timeout: publisher did not receive REQUEST_OK");
        } else {
            xqc_demo_test_fail("timeout: subscriber received neither SUBSCRIBE_OK nor REQUEST_ERROR");
        }
    } else if (g_current_test == XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OK) {
        xqc_demo_test_fail(
            "timeout: namespace REQUEST_OK callbacks were incomplete");
    } else if (g_current_test
               == XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OVERLAP)
    {
        xqc_demo_test_fail(
            "timeout: namespace overlap REQUEST_ERROR callbacks were incomplete");
    } else if (g_current_test
               == XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_NOTIFICATIONS)
    {
        xqc_demo_test_fail(
            "timeout: NAMESPACE/NAMESPACE_DONE sequence was incomplete");
    } else if (g_current_test
               == XQC_DEMO_TEST_SUBSCRIBE_TRACKS_PUBLISH)
    {
        xqc_demo_interop_conn_t *sub = g_sub_conn;
        if (sub == NULL || !sub->tracks_first_generic_ok) {
            xqc_demo_test_fail(
                "timeout: SUBSCRIBE_TRACKS did not receive REQUEST_OK");
        } else if (!sub->publish_received) {
            xqc_demo_test_fail(
                "timeout: accepted SUBSCRIBE_TRACKS produced no PUBLISH");
        } else {
            xqc_demo_test_fail(
                "timeout: PUBLISH response was not sent");
        }
    } else if (g_current_test
               == XQC_DEMO_TEST_SUBSCRIBE_TRACKS_OVERLAP)
    {
        xqc_demo_test_fail(
            "timeout: overlapping SUBSCRIBE_TRACKS was not rejected");
    } else if (g_current_test
               == XQC_DEMO_TEST_REQUEST_UPDATE_SUCCESS)
    {
        xqc_demo_test_fail(
            "timeout: REQUEST_UPDATE success lifecycle was incomplete");
    } else if (g_current_test
               == XQC_DEMO_TEST_REQUEST_UPDATE_OVERLAP)
    {
        xqc_demo_test_fail(
            "timeout: REQUEST_UPDATE overlap lifecycle was incomplete");
    } else if (g_current_test == XQC_DEMO_TEST_PUBLISH_BLOCKED) {
        xqc_demo_test_fail(
            "timeout: PUBLISH_BLOCKED callback was not received");
    } else if (g_current_test == XQC_DEMO_TEST_PUBLISH_DONE) {
        xqc_demo_test_fail(
            "timeout: PUBLISH_DONE callback/FIN lifecycle was incomplete");
    } else if (g_current_test == XQC_DEMO_TEST_CONTROL_GOAWAY) {
        xqc_demo_test_fail(
            "timeout: control GOAWAY lifecycle callbacks were incomplete");
    } else if (g_current_test == XQC_DEMO_TEST_REQUEST_GOAWAY) {
        xqc_demo_test_fail(
            "timeout: request GOAWAY target reset was incomplete");
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
xqc_demo_interop_delayed_close_callback(int fd, short what, void *arg);

static xqc_moq_stream_t *
xqc_demo_interop_find_local_request(xqc_demo_interop_conn_t *conn,
    uint64_t request_id)
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &conn->session->local_request_stream_list) {
        xqc_moq_stream_t *stream = xqc_list_entry(
            pos, xqc_moq_stream_t, request_list_member);
        if (stream->local_request && stream->request_id == request_id) {
            return stream;
        }
    }
    return NULL;
}

static void xqc_demo_interop_schedule_finite_completion(
    xqc_demo_interop_conn_t *conn);

static void
xqc_demo_interop_complete_finite_request(int fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    xqc_demo_interop_conn_t *conn = arg;
    conn->finite_completion_scheduled = 0;
    int callbacks_complete = 0;
    const char *case_name = g_test_case_names[g_current_test];
    if (g_current_test == XQC_DEMO_TEST_TRACK_STATUS_SUCCESS) {
        callbacks_complete =
            conn->finite_generic_ok && conn->finite_specific_ok;
    } else if (g_current_test == XQC_DEMO_TEST_FETCH_SUCCESS) {
        callbacks_complete = conn->fetch_ok_seen
            && conn->fetch_header_seen && conn->fetch_object_count == 3
            && conn->fetch_range_seen && conn->fetch_header_fin;
    } else {
        callbacks_complete = conn->finite_error_seen;
    }
    if (!callbacks_complete) {
        return;
    }

    xqc_moq_stream_t *stream = xqc_demo_interop_find_local_request(
        conn, conn->finite_request_id);
    uint8_t terminal_fin =
        g_current_test == XQC_DEMO_TEST_FETCH_SUCCESS
        ? (uint8_t)conn->fetch_header_fin
        : (stream != NULL ? stream->peer_fin_received : 0);
    if (stream == NULL || !stream->response_received || !terminal_fin
        || !stream->request_closed_notified)
    {
        if (++conn->finite_completion_attempts < 200) {
            xqc_demo_interop_schedule_finite_completion(conn);
            return;
        }
        xqc_demo_test_fail(
            "%s did not reach response+terminal-FIN+closed state",
            case_name);
        xqc_demo_interop_close_conn(conn);
        return;
    }

    printf("control_e2e|finite_request_complete|case:%s"
           "|request_id:%"PRIu64
           "|response_received:1|%s:1|closed_notified:1\n",
           case_name, conn->finite_request_id,
           g_current_test == XQC_DEMO_TEST_FETCH_SUCCESS
               ? "data_fin" : "peer_fin");
    xqc_demo_test_pass();
    if (g_test_timeout_event != NULL) {
        event_del(g_test_timeout_event);
    }
    xqc_demo_interop_close_conn(conn);
}

static void
xqc_demo_interop_schedule_finite_completion(xqc_demo_interop_conn_t *conn)
{
    if (conn->finite_completion_scheduled) {
        return;
    }
    conn->finite_completion_scheduled = 1;
    struct timeval delay = {0, 10000};
    if (event_base_once(g_eb, -1, EV_TIMEOUT,
                        xqc_demo_interop_complete_finite_request,
                        conn, &delay) < 0)
    {
        conn->finite_completion_scheduled = 0;
        xqc_demo_test_fail("failed to schedule finite request completion");
        xqc_demo_interop_close_conn(conn);
    }
}

static void
xqc_demo_interop_publish_done_complete_callback(
    int fd, short what, void *arg);

static void
xqc_demo_interop_request_goaway_complete_callback(
    int fd, short what, void *arg);

static void
xqc_demo_interop_create_publisher_callback(int fd, short what, void *arg);

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
xqc_demo_interop_send_announce(xqc_demo_interop_conn_t *conn)
{
    if (g_current_test == XQC_DEMO_TEST_ANNOUNCE_SUBSCRIBE
        || g_current_test == XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE)
    {
        xqc_moq_track_t *track = xqc_moq_track_create(conn->session,
            (char *)XQC_INTEROP_NS_STR, (char *)XQC_INTEROP_TRACK_NAME,
            XQC_MOQ_TRACK_VIDEO, NULL, XQC_MOQ_CONTAINER_NONE,
            XQC_MOQ_TRACK_FOR_PUB);
        if (track == NULL) {
            VERBOSE("failed to register publisher track before namespace advertisement");
            return -1;
        }
    }

    xqc_moq_publish_namespace_msg_t pub_ns;
    memset(&pub_ns, 0, sizeof(pub_ns));
    pub_ns.track_namespace_num = 2;
    pub_ns.track_namespace_tuple = interop_ns_tuple;
    pub_ns.params_num = 0;
    pub_ns.params = NULL;
    xqc_int_t ret = xqc_moq_publish_namespace(conn->session, &pub_ns);
    if (ret >= 0) {
        conn->publish_ns_sent = 1;
        conn->publish_ns_request_id = pub_ns.request_id;
    }
    VERBOSE("send PUBLISH_NAMESPACE(%s) request_id=%"PRIu64" ret=%d",
            XQC_INTEROP_NS_STR, pub_ns.request_id, (int)ret);
    return (int)ret;
}

static xqc_int_t
xqc_demo_interop_send_namespace_request(xqc_demo_interop_conn_t *conn,
    const xqc_moq_track_ns_field_t *prefix, uint64_t prefix_num,
    int second_request)
{
    xqc_moq_subscribe_namespace_msg_t request;
    memset(&request, 0, sizeof(request));
    request.request_id =
        xqc_moq_session_alloc_subscribe_id(conn->session);
    request.track_namespace_tuple =
        (xqc_moq_track_ns_field_t *)prefix;
    request.track_namespace_num = prefix_num;

    if (second_request) {
        conn->namespace_second_request_id = request.request_id;
        conn->namespace_second_sent = 1;

    } else {
        conn->namespace_first_request_id = request.request_id;
    }

    xqc_int_t ret =
        xqc_moq_write_subscribe_namespace(conn->session, &request);
    VERBOSE("send SUBSCRIBE_NAMESPACE request_id=%"PRIu64
            " prefix_num=%"PRIu64" ret=%d",
            request.request_id, prefix_num, (int)ret);
    return ret;
}

static void
xqc_demo_interop_maybe_advance_namespace_case(
    xqc_demo_interop_conn_t *conn)
{
    if (g_current_test == XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OK) {
        if (!conn->namespace_first_generic_ok
            || !conn->namespace_first_compat_ok)
        {
            return;
        }
        xqc_demo_test_pass();
        if (g_test_timeout_event) {
            event_del(g_test_timeout_event);
        }
        xqc_demo_interop_close_conn(conn);
        return;
    }

    if (g_current_test != XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OVERLAP) {
        return;
    }

    if (conn->namespace_first_generic_ok
        && conn->namespace_first_compat_ok
        && !conn->namespace_second_sent)
    {
        xqc_moq_track_ns_field_t child_prefix[2] = {
            {
                .len = sizeof("overlap") - 1,
                .data = (unsigned char *)"overlap",
            },
            {
                .len = sizeof("child") - 1,
                .data = (unsigned char *)"child",
            },
        };
        xqc_int_t ret = xqc_demo_interop_send_namespace_request(
            conn, child_prefix, 2, 1);
        if (ret != XQC_OK) {
            xqc_demo_test_fail(
                "second SUBSCRIBE_NAMESPACE send failed: %d", (int)ret);
            xqc_demo_interop_close_conn(conn);
        }
        return;
    }

    if (conn->namespace_second_generic_error
        && conn->namespace_second_compat_error)
    {
        xqc_demo_test_pass();
        if (g_test_timeout_event) {
            event_del(g_test_timeout_event);
        }
        xqc_demo_interop_close_conn(conn);
    }
}

static xqc_int_t
xqc_demo_interop_send_tracks_request(xqc_demo_interop_conn_t *conn,
    const xqc_moq_track_ns_field_t *prefix, uint64_t prefix_num,
    int second_request)
{
    xqc_moq_subscribe_tracks_msg_t request;
    memset(&request, 0, sizeof(request));
    request.track_namespace_tuple =
        (xqc_moq_track_ns_field_t *)prefix;
    request.track_namespace_num = prefix_num;

    xqc_int_t ret =
        xqc_moq_write_subscribe_tracks(conn->session, &request);
    if (ret == XQC_OK) {
        if (second_request) {
            conn->tracks_second_request_id = request.request_id;
            conn->tracks_second_sent = 1;
        } else {
            conn->tracks_first_request_id = request.request_id;
        }
    }
    VERBOSE("send SUBSCRIBE_TRACKS request_id=%"PRIu64
            " prefix_num=%"PRIu64" ret=%d",
            request.request_id, prefix_num, (int)ret);
    return ret;
}

static xqc_int_t
xqc_demo_interop_send_request_update_initial(
    xqc_demo_interop_conn_t *conn)
{
    xqc_moq_track_ns_field_t prefix[2] = {
        {
            .len = sizeof("update") - 1,
            .data = (unsigned char *)"update",
        },
        {
            .len = sizeof("old") - 1,
            .data = (unsigned char *)"old",
        },
    };
    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 0,
    };
    xqc_moq_subscribe_tracks_msg_t request;
    memset(&request, 0, sizeof(request));
    request.track_namespace_tuple = prefix;
    request.track_namespace_num = 2;
    request.params_num = 1;
    request.params = &forward;

    xqc_int_t ret = xqc_moq_write_subscribe_tracks(
        conn->session, &request);
    if (ret == XQC_OK) {
        conn->request_update_target_id = request.request_id;
    }
    return ret;
}

static xqc_int_t
xqc_demo_interop_send_request_update(xqc_demo_interop_conn_t *conn)
{
    uint8_t serialized_prefix[] = {
        0x02, 0x06, 'u', 'p', 'd', 'a', 't', 'e',
        0x03, 'n', 'e', 'w',
    };
    xqc_moq_message_parameter_t prefix = {
        .type = XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
        .length = sizeof(serialized_prefix),
        .value = serialized_prefix,
    };
    xqc_moq_request_update_msg_t update;
    memset(&update, 0, sizeof(update));
    update.params_num = 1;
    update.params = &prefix;

    xqc_int_t ret = xqc_moq_write_request_update(
        conn->session, conn->request_update_target_id, &update);
    if (ret == XQC_OK) {
        conn->request_update_id = update.request_id;
    }
    return ret;
}

static xqc_int_t
xqc_demo_interop_send_request_update_overlap_initial(
    xqc_demo_interop_conn_t *conn)
{
    xqc_moq_track_ns_field_t old_prefix[2] = {
        {
            .len = sizeof("overlap") - 1,
            .data = (unsigned char *)"overlap",
        },
        {
            .len = sizeof("old") - 1,
            .data = (unsigned char *)"old",
        },
    };
    xqc_moq_track_ns_field_t other_prefix[3] = {
        {
            .len = sizeof("overlap") - 1,
            .data = (unsigned char *)"overlap",
        },
        {
            .len = sizeof("conflict") - 1,
            .data = (unsigned char *)"conflict",
        },
        {
            .len = sizeof("child") - 1,
            .data = (unsigned char *)"child",
        },
    };
    xqc_moq_subscribe_tracks_msg_t first;
    xqc_moq_subscribe_tracks_msg_t second;
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    first.track_namespace_tuple = old_prefix;
    first.track_namespace_num = 2;
    second.track_namespace_tuple = other_prefix;
    second.track_namespace_num = 3;

    xqc_int_t ret = xqc_moq_write_subscribe_tracks(
        conn->session, &first);
    if (ret != XQC_OK) {
        return ret;
    }
    conn->request_update_target_id = first.request_id;
    ret = xqc_moq_write_subscribe_tracks(conn->session, &second);
    if (ret == XQC_OK) {
        conn->request_update_other_id = second.request_id;
    }
    return ret;
}

static xqc_int_t
xqc_demo_interop_send_request_update_overlap(
    xqc_demo_interop_conn_t *conn)
{
    uint8_t serialized_prefix[] = {
        0x02, 0x07, 'o', 'v', 'e', 'r', 'l', 'a', 'p',
        0x08, 'c', 'o', 'n', 'f', 'l', 'i', 'c', 't',
    };
    xqc_moq_message_parameter_t prefix = {
        .type = XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
        .length = sizeof(serialized_prefix),
        .value = serialized_prefix,
    };
    xqc_moq_request_update_msg_t update;
    memset(&update, 0, sizeof(update));
    update.params_num = 1;
    update.params = &prefix;
    xqc_int_t ret = xqc_moq_write_request_update(
        conn->session, conn->request_update_target_id, &update);
    if (ret == XQC_OK) {
        conn->request_update_id = update.request_id;
        conn->request_update_sent = 1;
    }
    return ret;
}

static void
xqc_demo_interop_maybe_complete_request_update(
    xqc_demo_interop_conn_t *conn)
{
    if (g_current_test != XQC_DEMO_TEST_REQUEST_UPDATE_SUCCESS
        || !conn->request_update_initial_ok
        || !conn->request_update_ok
        || !conn->request_update_blocked)
    {
        return;
    }

    printf("control_e2e|request_update_ok|target_id:%"PRIu64
           "|update_id:%"PRIu64
           "|forward:0|prefix:update/new\n",
           conn->request_update_target_id, conn->request_update_id);
    xqc_demo_test_pass();
    if (g_test_timeout_event) {
        event_del(g_test_timeout_event);
    }
    struct timeval flush_delay = { 0, 100000 };
    if (event_base_once(g_eb, -1, EV_TIMEOUT,
                        xqc_demo_interop_delayed_close_callback,
                        conn, &flush_delay) < 0)
    {
        xqc_demo_interop_close_conn(conn);
    }
}

static void
xqc_demo_interop_maybe_complete_request_update_overlap(
    xqc_demo_interop_conn_t *conn)
{
    if (g_current_test != XQC_DEMO_TEST_REQUEST_UPDATE_OVERLAP
        || !conn->request_update_overlap_error
        || !conn->request_update_terminal_observed)
    {
        return;
    }

    xqc_demo_test_pass();
    if (g_test_timeout_event) {
        event_del(g_test_timeout_event);
    }
    struct timeval flush_delay = { 0, 100000 };
    if (event_base_once(g_eb, -1, EV_TIMEOUT,
                        xqc_demo_interop_delayed_close_callback,
                        conn, &flush_delay) < 0)
    {
        xqc_demo_interop_close_conn(conn);
    }
}

static xqc_int_t
xqc_demo_interop_send_control_goaway_requests(
    xqc_demo_interop_conn_t *conn)
{
    xqc_moq_track_ns_field_t first_prefix[2] = {
        {
            .len = sizeof("goaway") - 1,
            .data = (unsigned char *)"goaway",
        },
        {
            .len = sizeof("keep") - 1,
            .data = (unsigned char *)"keep",
        },
    };
    xqc_moq_track_ns_field_t cutoff_prefix[2] = {
        {
            .len = sizeof("goaway") - 1,
            .data = (unsigned char *)"goaway",
        },
        {
            .len = sizeof("cutoff") - 1,
            .data = (unsigned char *)"cutoff",
        },
    };
    xqc_moq_subscribe_tracks_msg_t first;
    xqc_moq_subscribe_tracks_msg_t cutoff;
    memset(&first, 0, sizeof(first));
    memset(&cutoff, 0, sizeof(cutoff));
    first.track_namespace_tuple = first_prefix;
    first.track_namespace_num = 2;
    cutoff.track_namespace_tuple = cutoff_prefix;
    cutoff.track_namespace_num = 2;

    xqc_int_t ret = xqc_moq_write_subscribe_tracks(
        conn->session, &first);
    if (ret != XQC_OK) {
        return ret;
    }
    conn->control_goaway_first_request_id = first.request_id;

    ret = xqc_moq_write_subscribe_tracks(conn->session, &cutoff);
    if (ret != XQC_OK) {
        return ret;
    }
    conn->control_goaway_cutoff_request_id = cutoff.request_id;
    VERBOSE("control GOAWAY requests first=%"PRIu64" cutoff=%"PRIu64,
            first.request_id, cutoff.request_id);
    return XQC_OK;
}

static xqc_int_t
xqc_demo_interop_send_request_goaway_requests(
    xqc_demo_interop_conn_t *conn)
{
    xqc_moq_track_ns_field_t target_prefix[2] = {
        {
            .len = sizeof("request-goaway") - 1,
            .data = (unsigned char *)"request-goaway",
        },
        {
            .len = sizeof("target") - 1,
            .data = (unsigned char *)"target",
        },
    };
    xqc_moq_track_ns_field_t other_prefix[2] = {
        {
            .len = sizeof("request-goaway") - 1,
            .data = (unsigned char *)"request-goaway",
        },
        {
            .len = sizeof("other") - 1,
            .data = (unsigned char *)"other",
        },
    };
    xqc_moq_subscribe_tracks_msg_t target;
    xqc_moq_subscribe_tracks_msg_t other;
    memset(&target, 0, sizeof(target));
    memset(&other, 0, sizeof(other));
    target.track_namespace_tuple = target_prefix;
    target.track_namespace_num = 2;
    other.track_namespace_tuple = other_prefix;
    other.track_namespace_num = 2;

    xqc_int_t ret = xqc_moq_write_subscribe_tracks(
        conn->session, &target);
    if (ret != XQC_OK) {
        return ret;
    }
    conn->request_goaway_target_request_id = target.request_id;
    ret = xqc_moq_write_subscribe_tracks(conn->session, &other);
    if (ret == XQC_OK) {
        conn->request_goaway_other_request_id = other.request_id;
    }
    return ret;
}

static void
xqc_demo_interop_maybe_complete_control_goaway(
    xqc_demo_interop_conn_t *conn)
{
    if (g_current_test != XQC_DEMO_TEST_CONTROL_GOAWAY
        || !conn->control_goaway_established_retained
        || !conn->control_goaway_received
        || !conn->control_goaway_cutoff_error)
    {
        return;
    }

    printf("control_e2e|established_retained|request_id:%"PRIu64
           "|local:1|response_received:1|closed_notified:0"
           "|active:1|prefix:goaway/keep\n",
           conn->control_goaway_first_request_id);
    xqc_demo_test_pass();
    if (g_test_timeout_event) {
        event_del(g_test_timeout_event);
    }
    struct timeval flush_delay = { 0, 100000 };
    if (event_base_once(g_eb, -1, EV_TIMEOUT,
                        xqc_demo_interop_delayed_close_callback,
                        conn, &flush_delay) < 0)
    {
        xqc_demo_interop_close_conn(conn);
    }
}

static void
xqc_demo_interop_maybe_complete_tracks_publish(
    xqc_demo_interop_conn_t *conn)
{
    if (g_current_test != XQC_DEMO_TEST_SUBSCRIBE_TRACKS_PUBLISH
        || g_test_passed
        || !conn->tracks_first_generic_ok
        || !conn->publish_received
        || !conn->publish_response_sent)
    {
        return;
    }

    xqc_demo_test_pass();
    if (g_test_timeout_event) {
        event_del(g_test_timeout_event);
    }
    struct timeval flush_delay = { 0, 100000 };
    if (event_base_once(g_eb, -1, EV_TIMEOUT,
                        xqc_demo_interop_delayed_close_callback,
                        conn, &flush_delay) < 0)
    {
        xqc_demo_interop_close_conn(conn);
    }
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
    int ret = xqc_moq_subscribe_latest(session, XQC_NONEXISTENT_NS_STR, "test-track");
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
    int ret = xqc_moq_subscribe_latest(session, XQC_INTEROP_NS_STR, XQC_INTEROP_TRACK_NAME);
    VERBOSE("send SUBSCRIBE(%s/%s) ret=%d", XQC_INTEROP_NS_STR, XQC_INTEROP_TRACK_NAME, ret);
    return ret;
}

static int
xqc_demo_interop_start_subscribe(xqc_demo_interop_conn_t *conn)
{
    if (conn == NULL || conn->session == NULL || conn->subscribe_sent) {
        return -1;
    }
    xqc_int_t ret = xqc_demo_interop_send_subscribe_interop(conn->session);
    if (ret < 0) {
        xqc_demo_test_fail("SUBSCRIBE send failed: %d", (int)ret);
        xqc_demo_interop_close_conn(conn);
        if (g_pub_conn != NULL && !g_pub_conn->closed) {
            xqc_demo_interop_close_conn(g_pub_conn);
        }
        return ret;
    }
    conn->subscribe_sent = 1;
    conn->subscribe_request_id = (uint64_t)ret;
    return XQC_OK;
}

static xqc_int_t
xqc_demo_interop_send_track_status(xqc_demo_interop_conn_t *conn)
{
    xqc_moq_track_ns_field_t *track_namespace = interop_ns_tuple;
    const char *track_namespace_str = XQC_INTEROP_NS_STR;
    if (g_current_test == XQC_DEMO_TEST_TRACK_STATUS_REJECTION) {
        track_namespace = nonexistent_ns_tuple;
        track_namespace_str = XQC_NONEXISTENT_NS_STR;
    }
    xqc_moq_stream_t *stream = xqc_moq_stream_create_with_transport(
        conn->session, XQC_STREAM_BIDI);
    if (stream == NULL) {
        return -XQC_ECREATE_STREAM;
    }
    xqc_moq_track_status_msg_t request;
    memset(&request, 0, sizeof(request));
    request.request_id = xqc_moq_session_alloc_request_id(conn->session);
    request.track_namespace_num = 2;
    request.track_namespace_tuple = track_namespace;
    request.track_name = (char *)XQC_INTEROP_TRACK_NAME;
    request.track_name_len = sizeof(XQC_INTEROP_TRACK_NAME) - 1;
    xqc_int_t ret = xqc_moq_write_track_status(
        conn->session, stream, &request);
    if (ret != XQC_OK) {
        xqc_moq_stream_close(stream);
        return ret;
    }
    conn->finite_request_id = request.request_id;
    printf("control_e2e|track_status_sent|request_id:%"PRIu64
           "|track:%s/%s\n", request.request_id,
           track_namespace_str, XQC_INTEROP_TRACK_NAME);
    return XQC_OK;
}

static xqc_int_t
xqc_demo_interop_send_fetch(xqc_demo_interop_conn_t *conn)
{
    xqc_moq_track_ns_field_t *track_namespace = interop_ns_tuple;
    const char *track_namespace_str = XQC_INTEROP_NS_STR;
    if (g_current_test == XQC_DEMO_TEST_FETCH_REJECTION) {
        track_namespace = nonexistent_ns_tuple;
        track_namespace_str = XQC_NONEXISTENT_NS_STR;
    }
    xqc_moq_stream_t *stream = xqc_moq_stream_create_with_transport(
        conn->session, XQC_STREAM_BIDI);
    if (stream == NULL) {
        return -XQC_ECREATE_STREAM;
    }
    xqc_moq_fetch_msg_t request;
    memset(&request, 0, sizeof(request));
    request.request_id = xqc_moq_session_alloc_request_id(conn->session);
    request.fetch_type = XQC_MOQ_FETCH_STANDALONE;
    request.track_namespace_num = 2;
    request.track_namespace_tuple = track_namespace;
    request.track_name = (char *)XQC_INTEROP_TRACK_NAME;
    request.track_name_len = sizeof(XQC_INTEROP_TRACK_NAME) - 1;
    request.start_group_id = 1;
    request.start_object_id = 2;
    request.end_group_id = 3;
    request.end_object_id = 4;
    xqc_int_t ret = xqc_moq_write_fetch(conn->session, stream, &request);
    if (ret != XQC_OK) {
        xqc_moq_stream_close(stream);
        return ret;
    }
    conn->finite_request_id = request.request_id;
    printf("control_e2e|fetch_sent|request_id:%"PRIu64
           "|track:%s/%s|range:1/2-3/4\n", request.request_id,
           track_namespace_str, XQC_INTEROP_TRACK_NAME);
    return XQC_OK;
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
        if (g_test_timeout_event) {
            event_del(g_test_timeout_event);
        }
        xqc_demo_interop_close_conn(conn);
        break;

    case XQC_DEMO_TEST_ANNOUNCE_ONLY:
        if (conn->conn_role == 0) {
            int ret = xqc_demo_interop_send_announce(conn);
            if (ret < 0) {
                xqc_demo_test_fail("PUBLISH_NAMESPACE send failed: %d", ret);
                xqc_demo_interop_close_conn(conn);
            }
        }
        break;

    case XQC_DEMO_TEST_PUBLISH_NAMESPACE_DONE:
        if (conn->conn_role == 0) {
            int ret = xqc_demo_interop_send_announce(conn);
            if (ret < 0) {
                xqc_demo_test_fail("PUBLISH_NAMESPACE send failed: %d", ret);
                xqc_demo_interop_close_conn(conn);
            }
        }
        break;

    case XQC_DEMO_TEST_SUBSCRIBE_ERROR:
        if (conn->conn_role == 1) {
            int ret = xqc_demo_interop_send_subscribe_nonexistent(conn->session);
            if (ret < 0) {
                xqc_demo_test_fail("SUBSCRIBE send failed: %d", ret);
                xqc_demo_interop_close_conn(conn);
            } else {
                conn->subscribe_sent = 1;
                conn->subscribe_request_id = (uint64_t)ret;
            }
        }
        break;

    case XQC_DEMO_TEST_ANNOUNCE_SUBSCRIBE:
        if (conn->conn_role == 0) {
            int ret = xqc_demo_interop_send_announce(conn);
            if (ret < 0) {
                xqc_demo_test_fail("PUBLISH_NAMESPACE send failed: %d", ret);
                xqc_demo_interop_close_conn(conn);
            }
        }
        if (conn->conn_role == 1) {
            if (g_publisher_announced) {
                xqc_demo_interop_start_subscribe(conn);
            }
        }
        break;

    case XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE:
        if (conn->conn_role == 1) {
            int ret = xqc_demo_interop_start_subscribe(conn);
            if (ret == XQC_OK) {
                struct timeval publisher_delay = { 0, 500000 };
                if (event_base_once(g_eb, -1, EV_TIMEOUT,
                                    xqc_demo_interop_create_publisher_callback,
                                    NULL, &publisher_delay) < 0)
                {
                    xqc_demo_test_fail("failed to schedule publisher connection");
                    xqc_demo_interop_close_conn(conn);
                }
            }
        }
        if (conn->conn_role == 0) {
            int ret = xqc_demo_interop_send_announce(conn);
            if (ret < 0) {
                xqc_demo_test_fail("PUBLISH_NAMESPACE send failed: %d", ret);
                xqc_demo_interop_close_conn(conn);
                if (g_sub_conn && !g_sub_conn->closed) {
                    xqc_demo_interop_close_conn(g_sub_conn);
                }
            }
        }
        break;

    case XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OK:
        if (conn->conn_role == 1
            && xqc_demo_interop_send_namespace_request(
                conn, NULL, 0, 0) != XQC_OK)
        {
            xqc_demo_test_fail("root SUBSCRIBE_NAMESPACE send failed");
            xqc_demo_interop_close_conn(conn);
        }
        break;

    case XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OVERLAP:
        if (conn->conn_role == 1) {
            xqc_moq_track_ns_field_t prefix = {
                .len = sizeof("overlap") - 1,
                .data = (unsigned char *)"overlap",
            };
            if (xqc_demo_interop_send_namespace_request(
                    conn, &prefix, 1, 0) != XQC_OK)
            {
                xqc_demo_test_fail(
                    "first SUBSCRIBE_NAMESPACE send failed");
                xqc_demo_interop_close_conn(conn);
            }
        }
        break;

    case XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_NOTIFICATIONS:
        if (conn->conn_role == 1) {
            xqc_moq_track_ns_field_t prefix = {
                .len = sizeof("explicit") - 1,
                .data = (unsigned char *)"explicit",
            };
            if (xqc_demo_interop_send_namespace_request(
                    conn, &prefix, 1, 0) != XQC_OK)
            {
                xqc_demo_test_fail(
                    "notification SUBSCRIBE_NAMESPACE send failed");
                xqc_demo_interop_close_conn(conn);
            }
        }
        break;

    case XQC_DEMO_TEST_SUBSCRIBE_TRACKS_PUBLISH:
        if (conn->conn_role == 1
            && xqc_demo_interop_send_tracks_request(
                conn, NULL, 0, 0) != XQC_OK)
        {
            xqc_demo_test_fail("root SUBSCRIBE_TRACKS send failed");
            xqc_demo_interop_close_conn(conn);
        }
        break;

    case XQC_DEMO_TEST_SUBSCRIBE_TRACKS_OVERLAP:
        if (conn->conn_role == 1) {
            xqc_moq_track_ns_field_t prefix = {
                .len = sizeof("overlap") - 1,
                .data = (unsigned char *)"overlap",
            };
            if (xqc_demo_interop_send_tracks_request(
                    conn, &prefix, 1, 0) != XQC_OK)
            {
                xqc_demo_test_fail(
                    "first SUBSCRIBE_TRACKS send failed");
                xqc_demo_interop_close_conn(conn);
            }
        }
        break;

    case XQC_DEMO_TEST_REQUEST_UPDATE_SUCCESS:
        if (conn->conn_role == 1
            && xqc_demo_interop_send_request_update_initial(conn)
                != XQC_OK)
        {
            xqc_demo_test_fail(
                "REQUEST_UPDATE initial request send failed");
            xqc_demo_interop_close_conn(conn);
        }
        break;

    case XQC_DEMO_TEST_REQUEST_UPDATE_OVERLAP:
        if (conn->conn_role == 1
            && xqc_demo_interop_send_request_update_overlap_initial(
                conn) != XQC_OK)
        {
            xqc_demo_test_fail(
                "REQUEST_UPDATE overlap initial requests failed");
            xqc_demo_interop_close_conn(conn);
        }
        break;

    case XQC_DEMO_TEST_PUBLISH_BLOCKED:
        if (conn->conn_role == 1) {
            xqc_moq_track_ns_field_t prefix[2] = {
                {
                    .len = sizeof("blocked") - 1,
                    .data = (unsigned char *)"blocked",
                },
                {
                    .len = sizeof("base") - 1,
                    .data = (unsigned char *)"base",
                },
            };
            xqc_int_t ret = xqc_demo_interop_send_tracks_request(
                conn, prefix, 2, 0);
            if (ret == XQC_OK) {
                conn->publish_blocked_request_id =
                    conn->tracks_first_request_id;
            } else {
                xqc_demo_test_fail(
                    "PUBLISH_BLOCKED request send failed");
                xqc_demo_interop_close_conn(conn);
            }
        }
        break;

    case XQC_DEMO_TEST_PUBLISH_DONE:
        if (conn->conn_role == 1) {
            xqc_moq_track_ns_field_t prefix = {
                .len = sizeof("done") - 1,
                .data = (unsigned char *)"done",
            };
            xqc_int_t ret = xqc_demo_interop_send_tracks_request(
                conn, &prefix, 1, 0);
            if (ret == XQC_OK) {
                conn->publish_done_discovery_request_id =
                    conn->tracks_first_request_id;
            } else {
                xqc_demo_test_fail(
                    "PUBLISH_DONE discovery request send failed");
                xqc_demo_interop_close_conn(conn);
            }
        }
        break;

    case XQC_DEMO_TEST_CONTROL_GOAWAY:
        if (conn->conn_role == 1
            && xqc_demo_interop_send_control_goaway_requests(conn)
                != XQC_OK)
        {
            xqc_demo_test_fail(
                "control GOAWAY request setup failed");
            xqc_demo_interop_close_conn(conn);
        }
        break;

    case XQC_DEMO_TEST_REQUEST_GOAWAY:
        if (conn->conn_role == 1
            && xqc_demo_interop_send_request_goaway_requests(conn)
                != XQC_OK)
        {
            xqc_demo_test_fail(
                "request GOAWAY sibling request setup failed");
            xqc_demo_interop_close_conn(conn);
        }
        break;

    case XQC_DEMO_TEST_TRACK_STATUS_SUCCESS:
    case XQC_DEMO_TEST_TRACK_STATUS_REJECTION:
        if (conn->conn_role == 1
            && xqc_demo_interop_send_track_status(conn) != XQC_OK)
        {
            xqc_demo_test_fail("TRACK_STATUS send failed");
            xqc_demo_interop_close_conn(conn);
        }
        break;

    case XQC_DEMO_TEST_FETCH_SUCCESS:
    case XQC_DEMO_TEST_FETCH_REJECTION:
        if (conn->conn_role == 1
            && xqc_demo_interop_send_fetch(conn) != XQC_OK)
        {
            xqc_demo_test_fail("FETCH send failed");
            xqc_demo_interop_close_conn(conn);
        }
        break;

    default:
        break;
    }
}

static void
xqc_demo_interop_on_request_ok(xqc_moq_user_session_t *user_session,
    uint64_t request_id, xqc_moq_msg_type_t request_type,
    xqc_moq_request_ok_msg_t *msg)
{
    xqc_demo_interop_conn_t *conn = (xqc_demo_interop_conn_t *)user_session->data;
    VERBOSE("on_request_ok role=%d request_id=%"PRIu64" request_type=0x%x params=%"PRIu64,
            conn->conn_role, request_id, request_type, msg->params_num);

    if (request_type
            == (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_TRACK_STATUS)
    {
        if (g_current_test != XQC_DEMO_TEST_TRACK_STATUS_SUCCESS
            || request_id != conn->finite_request_id
            || msg->params_num != 0
            || msg->track_properties_len != 2
            || msg->track_properties == NULL
            || msg->track_properties[0] != 0x02
            || msg->track_properties[1] != 0x01)
        {
            xqc_demo_test_fail("TRACK_STATUS generic REQUEST_OK mismatch");
            xqc_demo_interop_close_conn(conn);
            return;
        }
        conn->finite_generic_ok = 1;
        return;
    }

    if (request_type == XQC_MOQ_MSG_SUBSCRIBE_UPDATE) {
        if (g_current_test != XQC_DEMO_TEST_REQUEST_UPDATE_SUCCESS
            || request_id != conn->request_update_id
            || request_id != 2
            || msg->params_num != 0)
        {
            xqc_demo_test_fail(
                "REQUEST_UPDATE REQUEST_OK mismatch request_id=%"PRIu64,
                request_id);
            xqc_demo_interop_close_conn(conn);
            return;
        }
        conn->request_update_ok = 1;
        xqc_demo_interop_maybe_complete_request_update(conn);
        return;
    }

    if (request_type == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE) {
        if ((g_current_test != XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OK
             && g_current_test
                != XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OVERLAP
             && g_current_test
                != XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_NOTIFICATIONS)
            || request_id != conn->namespace_first_request_id
            || msg->params_num != 0)
        {
            xqc_demo_test_fail(
                "unexpected namespace REQUEST_OK request_id=%"PRIu64,
                request_id);
            xqc_demo_interop_close_conn(conn);
            return;
        }
        conn->namespace_first_generic_ok = 1;
        xqc_demo_interop_maybe_advance_namespace_case(conn);
        return;
    }

    if (request_type == XQC_MOQ_MSG_SUBSCRIBE_TRACKS) {
        if (g_current_test == XQC_DEMO_TEST_REQUEST_GOAWAY) {
            if (msg->params_num != 0
                || (request_id
                        != conn->request_goaway_target_request_id
                    && request_id
                        != conn->request_goaway_other_request_id))
            {
                xqc_demo_test_fail(
                    "request GOAWAY initial OK mismatch id=%"PRIu64,
                    request_id);
                xqc_demo_interop_close_conn(conn);
                return;
            }
            if (request_id
                    == conn->request_goaway_target_request_id)
            {
                conn->request_goaway_target_ok = 1;
            } else {
                conn->request_goaway_other_ok = 1;
            }
            return;
        }
        if (g_current_test == XQC_DEMO_TEST_PUBLISH_DONE) {
            if (request_id
                    != conn->publish_done_discovery_request_id
                || request_id != 0 || msg->params_num != 0)
            {
                xqc_demo_test_fail(
                    "PUBLISH_DONE discovery OK mismatch id=%"PRIu64,
                    request_id);
                xqc_demo_interop_close_conn(conn);
                return;
            }
            conn->publish_done_discovery_ok = 1;
            return;
        }
        if (g_current_test == XQC_DEMO_TEST_PUBLISH_BLOCKED) {
            if (request_id != conn->publish_blocked_request_id
                || request_id != 0 || msg->params_num != 0)
            {
                xqc_demo_test_fail(
                    "PUBLISH_BLOCKED initial OK mismatch id=%"PRIu64,
                    request_id);
                xqc_demo_interop_close_conn(conn);
                return;
            }
            conn->publish_blocked_initial_ok = 1;
            if (g_disconnect_after_request) {
                printf("control_e2e|disconnect_after_request"
                       "|case:publish-blocked|request_id:%"PRIu64"\n",
                       conn->publish_blocked_request_id);
                xqc_demo_interop_close_conn(conn);
            }
            return;
        }
        if (g_current_test == XQC_DEMO_TEST_REQUEST_UPDATE_OVERLAP) {
            if (msg->params_num != 0
                || (request_id != conn->request_update_target_id
                    && request_id != conn->request_update_other_id))
            {
                xqc_demo_test_fail(
                    "REQUEST_UPDATE overlap initial OK mismatch id=%"PRIu64,
                    request_id);
                xqc_demo_interop_close_conn(conn);
                return;
            }
            if (request_id == conn->request_update_target_id) {
                conn->request_update_initial_ok = 1;
            } else {
                conn->request_update_other_ok = 1;
            }
            if (conn->request_update_initial_ok
                && conn->request_update_other_ok
                && !conn->request_update_sent)
            {
                xqc_int_t ret =
                    xqc_demo_interop_send_request_update_overlap(conn);
                VERBOSE("send overlap REQUEST_UPDATE target=%"PRIu64
                        " update=%"PRIu64" ret=%d",
                        conn->request_update_target_id,
                        conn->request_update_id, (int)ret);
                if (ret != XQC_OK || conn->request_update_id != 4)
                {
                    xqc_demo_test_fail(
                        "overlap REQUEST_UPDATE send failed ret=%d id=%"PRIu64,
                        (int)ret, conn->request_update_id);
                    xqc_demo_interop_close_conn(conn);
                }
            }
            return;
        }
        if (g_current_test == XQC_DEMO_TEST_REQUEST_UPDATE_SUCCESS) {
            if (request_id != conn->request_update_target_id
                || request_id != 0 || msg->params_num != 0)
            {
                xqc_demo_test_fail(
                    "REQUEST_UPDATE initial REQUEST_OK mismatch request_id=%"PRIu64,
                    request_id);
                xqc_demo_interop_close_conn(conn);
                return;
            }
            conn->request_update_initial_ok = 1;
            xqc_int_t ret = xqc_demo_interop_send_request_update(conn);
            VERBOSE("send REQUEST_UPDATE target=%"PRIu64
                    " update=%"PRIu64" ret=%d",
                    conn->request_update_target_id,
                    conn->request_update_id, (int)ret);
            if (ret != XQC_OK || conn->request_update_id != 2) {
                xqc_demo_test_fail(
                    "REQUEST_UPDATE send failed ret=%d request_id=%"PRIu64,
                    (int)ret, conn->request_update_id);
                xqc_demo_interop_close_conn(conn);
            }
            return;
        }
        if (g_current_test == XQC_DEMO_TEST_CONTROL_GOAWAY) {
            if (request_id != conn->control_goaway_first_request_id
                || msg->params_num != 0)
            {
                xqc_demo_test_fail(
                    "control GOAWAY REQUEST_OK mismatch request_id=%"PRIu64,
                    request_id);
                xqc_demo_interop_close_conn(conn);
                return;
            }
            xqc_demo_interop_maybe_complete_control_goaway(conn);
            return;
        }
        if ((g_current_test
                != XQC_DEMO_TEST_SUBSCRIBE_TRACKS_PUBLISH
             && g_current_test
                != XQC_DEMO_TEST_SUBSCRIBE_TRACKS_OVERLAP)
            || request_id != conn->tracks_first_request_id
            || msg->params_num != 0)
        {
            xqc_demo_test_fail(
                "unexpected tracks REQUEST_OK request_id=%"PRIu64,
                request_id);
            xqc_demo_interop_close_conn(conn);
            return;
        }

        conn->tracks_first_generic_ok = 1;
        if (g_current_test
                == XQC_DEMO_TEST_SUBSCRIBE_TRACKS_PUBLISH)
        {
            xqc_demo_interop_maybe_complete_tracks_publish(conn);
            return;
        }

        if (!conn->tracks_second_sent) {
            xqc_moq_track_ns_field_t child_prefix[2] = {
                {
                    .len = sizeof("overlap") - 1,
                    .data = (unsigned char *)"overlap",
                },
                {
                    .len = sizeof("child") - 1,
                    .data = (unsigned char *)"child",
                },
            };
            if (xqc_demo_interop_send_tracks_request(
                    conn, child_prefix, 2, 1) != XQC_OK)
            {
                xqc_demo_test_fail(
                    "second SUBSCRIBE_TRACKS send failed");
                xqc_demo_interop_close_conn(conn);
            }
        }
        return;
    }

    if (request_type != XQC_MOQ_MSG_PUBLISH_NAMESPACE) {
        return;
    }

    conn->publish_ns_ok_received = 1;
    if (g_current_test == XQC_DEMO_TEST_ANNOUNCE_ONLY) {
        xqc_demo_test_pass();
        if (g_test_timeout_event) {
            event_del(g_test_timeout_event);
        }
        xqc_demo_interop_close_conn(conn);
        return;
    }

    if (g_current_test == XQC_DEMO_TEST_PUBLISH_NAMESPACE_DONE) {
        if (!conn->publish_ns_sent || request_id != conn->publish_ns_request_id) {
            xqc_demo_test_fail("REQUEST_OK did not match PUBLISH_NAMESPACE request");
            xqc_demo_interop_close_conn(conn);
            return;
        }

        xqc_int_t ret = xqc_moq_cancel_request(conn->session, request_id);
        VERBOSE("cancel PUBLISH_NAMESPACE request stream request_id=%"PRIu64" ret=%d",
                request_id, (int)ret);
        if (ret < 0) {
            xqc_demo_test_fail("PUBLISH_NAMESPACE request cancellation failed: %d", (int)ret);
            xqc_demo_interop_close_conn(conn);
            return;
        }

        conn->publish_ns_cancelled = 1;
        xqc_demo_test_pass();
        if (g_test_timeout_event) {
            event_del(g_test_timeout_event);
        }
        struct timeval flush_delay = { 0, 500000 };
        if (event_base_once(g_eb, -1, EV_TIMEOUT,
                            xqc_demo_interop_delayed_close_callback,
                            conn, &flush_delay) < 0)
        {
            xqc_demo_interop_close_conn(conn);
        }
    }

    if (g_current_test == XQC_DEMO_TEST_ANNOUNCE_SUBSCRIBE) {
        if (!conn->publish_ns_sent || request_id != conn->publish_ns_request_id) {
            xqc_demo_test_fail("REQUEST_OK did not match PUBLISH_NAMESPACE request");
            xqc_demo_interop_close_conn(conn);
            return;
        }
        g_publisher_announced = 1;
        if (g_sub_conn != NULL && g_sub_conn->session_ready
            && !g_sub_conn->subscribe_sent)
        {
            VERBOSE("namespace accepted, triggering subscriber SUBSCRIBE");
            xqc_demo_interop_start_subscribe(g_sub_conn);
        }
    }

    if (g_current_test == XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE) {
        if (!conn->publish_ns_sent || request_id != conn->publish_ns_request_id) {
            xqc_demo_test_fail("REQUEST_OK did not match PUBLISH_NAMESPACE request");
            xqc_demo_interop_close_conn(conn);
            if (g_sub_conn && !g_sub_conn->closed) {
                xqc_demo_interop_close_conn(g_sub_conn);
            }
            return;
        }
        g_publisher_announced = 1;
        xqc_demo_interop_maybe_complete_preannounce();
    }
}

static void
xqc_demo_interop_on_subscribe_namespace_ok(
    xqc_moq_user_session_t *user_session,
    xqc_moq_subscribe_namespace_ok_msg_t *msg)
{
    xqc_demo_interop_conn_t *conn =
        (xqc_demo_interop_conn_t *)user_session->data;
    if (msg == NULL
        || msg->request_id != conn->namespace_first_request_id)
    {
        xqc_demo_test_fail("namespace OK compatibility callback mismatch");
        xqc_demo_interop_close_conn(conn);
        return;
    }

    if (g_current_test == XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OK) {
        if (msg->track_namespace_tuple != NULL
            || msg->track_namespace_num != 0)
        {
            xqc_demo_test_fail(
                "root namespace OK callback did not retain root prefix");
            xqc_demo_interop_close_conn(conn);
            return;
        }

    } else if (g_current_test
               == XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OVERLAP)
    {
        if (msg->track_namespace_tuple == NULL
            || msg->track_namespace_num != 1
            || msg->track_namespace_tuple[0].len != sizeof("overlap") - 1
            || memcmp(msg->track_namespace_tuple[0].data, "overlap",
                      sizeof("overlap") - 1) != 0)
        {
            xqc_demo_test_fail(
                "overlap namespace OK callback prefix mismatch");
            xqc_demo_interop_close_conn(conn);
            return;
        }

    } else if (g_current_test
               == XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_NOTIFICATIONS)
    {
        if (msg->track_namespace_tuple == NULL
            || msg->track_namespace_num != 1
            || msg->track_namespace_tuple[0].len
                != sizeof("explicit") - 1
            || memcmp(msg->track_namespace_tuple[0].data,
                      "explicit", sizeof("explicit") - 1) != 0)
        {
            xqc_demo_test_fail(
                "notification namespace OK prefix mismatch");
            xqc_demo_interop_close_conn(conn);
            return;
        }

    } else {
        return;
    }

    conn->namespace_first_compat_ok = 1;
    xqc_demo_interop_maybe_advance_namespace_case(conn);
}

static int
xqc_demo_interop_is_explicit_child(
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num)
{
    return track_namespace_tuple != NULL
        && track_namespace_num == 2
        && track_namespace_tuple[0].len
            == sizeof("explicit") - 1
        && memcmp(track_namespace_tuple[0].data,
                  "explicit", sizeof("explicit") - 1) == 0
        && track_namespace_tuple[1].len
            == sizeof("child") - 1
        && memcmp(track_namespace_tuple[1].data,
                  "child", sizeof("child") - 1) == 0;
}

static void
xqc_demo_interop_on_namespace(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num)
{
    xqc_demo_interop_conn_t *conn =
        (xqc_demo_interop_conn_t *)user_session->data;
    if (g_current_test
            != XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_NOTIFICATIONS
        || request_id != conn->namespace_first_request_id
        || !conn->namespace_first_generic_ok
        || !conn->namespace_first_compat_ok
        || !xqc_demo_interop_is_explicit_child(
            track_namespace_tuple, track_namespace_num))
    {
        xqc_demo_test_fail(
            "NAMESPACE did not follow REQUEST_OK on namespace request");
        xqc_demo_interop_close_conn(conn);
        return;
    }
    conn->namespace_notification_received = 1;
    VERBOSE("NAMESPACE received request_id=%"PRIu64, request_id);
}

static void
xqc_demo_interop_on_namespace_done(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num)
{
    xqc_demo_interop_conn_t *conn =
        (xqc_demo_interop_conn_t *)user_session->data;
    if (g_current_test
            != XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_NOTIFICATIONS
        || request_id != conn->namespace_first_request_id
        || !conn->namespace_notification_received
        || !xqc_demo_interop_is_explicit_child(
            track_namespace_tuple, track_namespace_num))
    {
        xqc_demo_test_fail(
            "NAMESPACE_DONE arrived without matching NAMESPACE");
        xqc_demo_interop_close_conn(conn);
        return;
    }

    conn->namespace_done_received = 1;
    VERBOSE("NAMESPACE_DONE received request_id=%"PRIu64,
            request_id);
    xqc_demo_test_pass();
    if (g_test_timeout_event) {
        event_del(g_test_timeout_event);
    }
    xqc_demo_interop_close_conn(conn);
}

static void
xqc_demo_interop_on_subscribe_ok(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
                        xqc_moq_track_info_t *track_info, xqc_moq_subscribe_ok_msg_t *subscribe_ok)
{
    xqc_demo_interop_conn_t *conn = (xqc_demo_interop_conn_t *)user_session->data;
    VERBOSE("on_subscribe_ok role=%d subscribe_id=%"PRIu64, conn->conn_role, subscribe_ok->subscribe_id);

    if (conn->conn_role != 1 || !conn->subscribe_sent
        || subscribe_ok->subscribe_id != conn->subscribe_request_id)
    {
        xqc_demo_test_fail("SUBSCRIBE_OK did not match subscriber request");
        xqc_demo_interop_close_conn(conn);
        return;
    }
    conn->subscribe_ok_received = 1;

    if (g_current_test == XQC_DEMO_TEST_SUBSCRIBE_ERROR) {
        xqc_demo_test_fail("expected REQUEST_ERROR, got SUBSCRIBE_OK");
        xqc_demo_interop_close_conn(conn);
        return;
    }

    if (g_current_test == XQC_DEMO_TEST_ANNOUNCE_SUBSCRIBE) {
        if (g_pub_conn == NULL || !g_pub_conn->publish_ns_ok_received) {
            xqc_demo_test_fail("SUBSCRIBE_OK arrived before PUBLISH_NAMESPACE was accepted");
            xqc_demo_interop_close_conn(conn);
            return;
        }
        xqc_demo_test_pass();
        if (g_test_timeout_event) {
            event_del(g_test_timeout_event);
        }
        xqc_demo_interop_close_conn(conn);
        if (g_pub_conn && !g_pub_conn->closed) {
            xqc_demo_interop_close_conn(g_pub_conn);
        }
    }

    if (g_current_test == XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE) {
        xqc_demo_interop_maybe_complete_preannounce();
    }
}

static void
xqc_demo_interop_on_request_error(xqc_moq_user_session_t *user_session,
    uint64_t request_id, xqc_moq_msg_type_t request_type,
    xqc_moq_request_error_msg_t *request_error)
{
    xqc_demo_interop_conn_t *conn =
        (xqc_demo_interop_conn_t *)user_session->data;
    VERBOSE("on_request_error role=%d request_id=%"PRIu64" request_type=0x%x error_code=%"PRIu64" retry=%"PRIu64" reason=%s",
            conn->conn_role, request_id, request_type, request_error->error_code,
            request_error->retry_interval,
            request_error->reason_phrase ? request_error->reason_phrase : "");

    if (g_current_test == XQC_DEMO_TEST_TRACK_STATUS_REJECTION
        || g_current_test == XQC_DEMO_TEST_FETCH_REJECTION)
    {
        xqc_moq_msg_type_t expected_type =
            g_current_test == XQC_DEMO_TEST_TRACK_STATUS_REJECTION
            ? (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_TRACK_STATUS
            : XQC_MOQ_MSG_FETCH;
        if (request_id != conn->finite_request_id
            || request_type != expected_type
            || request_error->error_code
                != XQC_MOQ_REQUEST_ERROR_DOES_NOT_EXIST
            || request_error->retry_interval != 0)
        {
            xqc_demo_test_fail("finite REQUEST_ERROR mismatch id=%"PRIu64
                               " type=0x%x code=%"PRIu64,
                               request_id, request_type,
                               request_error->error_code);
            xqc_demo_interop_close_conn(conn);
            return;
        }
        conn->finite_error_seen = 1;
        printf("control_e2e|finite_request_error|case:%s"
               "|request_id:%"PRIu64"|code:0x10|retry:0\n",
               g_test_case_names[g_current_test], request_id);
        xqc_demo_interop_schedule_finite_completion(conn);
        return;
    }

    if (request_type == XQC_MOQ_MSG_SUBSCRIBE_UPDATE) {
        if (g_current_test != XQC_DEMO_TEST_REQUEST_UPDATE_OVERLAP
            || request_id != conn->request_update_id
            || request_id != 4
            || conn->request_update_target_id != 0
            || request_error->error_code
                != XQC_MOQ_REQUEST_ERROR_PREFIX_OVERLAP
            || request_error->retry_interval != 0)
        {
            xqc_demo_test_fail(
                "REQUEST_UPDATE overlap error mismatch id=%"PRIu64
                " code=%"PRIu64,
                request_id, request_error->error_code);
            xqc_demo_interop_close_conn(conn);
            return;
        }

        int terminal_observed = 0;
        xqc_list_head_t *pos;
        xqc_list_for_each(
            pos, &conn->session->local_request_stream_list)
        {
            xqc_moq_stream_t *stream = xqc_list_entry(
                pos, xqc_moq_stream_t, request_list_member);
            if (stream->local_request
                && stream->request_id
                    == conn->request_update_target_id
                && stream->request_type
                    == XQC_MOQ_MSG_SUBSCRIBE_TRACKS
                && stream->request_closed_notified
                && !stream->subscribe_tracks_active)
            {
                terminal_observed = 1;
                break;
            }
        }
        if (!terminal_observed) {
            xqc_demo_test_fail(
                "REQUEST_UPDATE overlap did not terminate request state");
            xqc_demo_interop_close_conn(conn);
            return;
        }
        conn->request_update_overlap_error = 1;
        conn->request_update_terminal_observed = 1;
        printf("control_e2e|request_update_error|target_id:%"PRIu64
               "|update_id:%"PRIu64"|code:0x30\n",
               conn->request_update_target_id, request_id);
        printf("control_e2e|request_update_terminal|target_id:%"PRIu64
               "|update_id:%"PRIu64
               "|closed_notified:1|active:0\n",
               conn->request_update_target_id, request_id);
        xqc_demo_interop_maybe_complete_request_update_overlap(conn);
        return;
    }

    if (request_type == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE) {
        if (g_current_test
                != XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OVERLAP
            || request_id != conn->namespace_second_request_id
            || request_error->error_code
                != XQC_MOQ_REQUEST_ERROR_PREFIX_OVERLAP
            || request_error->retry_interval != 0)
        {
            xqc_demo_test_fail(
                "unexpected namespace REQUEST_ERROR request_id=%"PRIu64
                " code=%"PRIu64,
                request_id, request_error->error_code);
            xqc_demo_interop_close_conn(conn);
            return;
        }
        conn->namespace_second_generic_error = 1;
        xqc_demo_interop_maybe_advance_namespace_case(conn);
        return;
    }

    if (request_type == XQC_MOQ_MSG_SUBSCRIBE_TRACKS) {
        if (g_current_test == XQC_DEMO_TEST_CONTROL_GOAWAY) {
            if (request_id
                    != conn->control_goaway_cutoff_request_id
                || request_error->error_code
                    != XQC_MOQ_REQUEST_ERROR_GOING_AWAY
                || request_error->retry_interval != 0)
            {
                xqc_demo_test_fail(
                    "control GOAWAY REQUEST_ERROR mismatch request_id=%"PRIu64
                    " code=%"PRIu64,
                    request_id, request_error->error_code);
                xqc_demo_interop_close_conn(conn);
                return;
            }
            conn->control_goaway_cutoff_error = 1;
            xqc_moq_namespace_prefix_t *accepted = NULL;
            xqc_list_head_t *pos;
            xqc_list_for_each(
                pos, &conn->session->local_request_stream_list)
            {
                xqc_moq_stream_t *stream = xqc_list_entry(
                    pos, xqc_moq_stream_t, request_list_member);
                if (stream->local_request
                    && stream->request_id
                        == conn->control_goaway_first_request_id
                    && stream->request_id == 0
                    && stream->request_type
                        == XQC_MOQ_MSG_SUBSCRIBE_TRACKS
                    && stream->response_received
                    && !stream->request_closed_notified
                    && stream->subscribe_tracks_active)
                {
                    accepted = stream->tracks_subscription;
                    break;
                }
            }
            if (accepted == NULL || accepted->prefix_num != 2
                || accepted->prefix_tuple[0].len
                    != sizeof("goaway") - 1
                || memcmp(accepted->prefix_tuple[0].data,
                          "goaway", sizeof("goaway") - 1) != 0
                || accepted->prefix_tuple[1].len
                    != sizeof("keep") - 1
                || memcmp(accepted->prefix_tuple[1].data,
                          "keep", sizeof("keep") - 1) != 0)
            {
                xqc_demo_test_fail(
                    "control GOAWAY did not retain established request");
                xqc_demo_interop_close_conn(conn);
                return;
            }
            conn->control_goaway_established_retained = 1;
            printf("control_e2e|going_away_error|request_id:%"PRIu64
                   "|code:0x06|retry:0\n", request_id);
            xqc_demo_interop_maybe_complete_control_goaway(conn);
            return;
        }
        if (g_current_test
                != XQC_DEMO_TEST_SUBSCRIBE_TRACKS_OVERLAP
            || !conn->tracks_second_sent
            || request_id != conn->tracks_second_request_id
            || request_error->error_code
                != XQC_MOQ_REQUEST_ERROR_PREFIX_OVERLAP
            || request_error->retry_interval != 0)
        {
            xqc_demo_test_fail(
                "unexpected tracks REQUEST_ERROR request_id=%"PRIu64
                " code=%"PRIu64,
                request_id, request_error->error_code);
            xqc_demo_interop_close_conn(conn);
            return;
        }

        conn->tracks_overlap_error = 1;
        xqc_demo_test_pass();
        if (g_test_timeout_event) {
            event_del(g_test_timeout_event);
        }
        xqc_demo_interop_close_conn(conn);
        return;
    }

    if (request_type != XQC_MOQ_MSG_SUBSCRIBE || conn->conn_role != 1
        || !conn->subscribe_sent)
    {
        return;
    }

    if (g_current_test == XQC_DEMO_TEST_SUBSCRIBE_ERROR) {
        if (request_id != conn->subscribe_request_id) {
            xqc_demo_test_fail("REQUEST_ERROR did not match SUBSCRIBE request");
            xqc_demo_interop_close_conn(conn);
            return;
        }
        conn->subscribe_error_received = 1;
        xqc_demo_test_pass();
        if (g_test_timeout_event) {
            event_del(g_test_timeout_event);
        }
        xqc_demo_interop_close_conn(conn);
    }

    if (g_current_test == XQC_DEMO_TEST_ANNOUNCE_SUBSCRIBE) {
        conn->subscribe_error_received = 1;
        xqc_demo_test_fail("expected SUBSCRIBE_OK, got REQUEST_ERROR (code=%"PRIu64")",
                           request_error->error_code);
        xqc_demo_interop_close_conn(conn);
        if (g_pub_conn && !g_pub_conn->closed) {
            xqc_demo_interop_close_conn(g_pub_conn);
        }
    }

    if (g_current_test == XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE) {
        if (request_id != conn->subscribe_request_id) {
            xqc_demo_test_fail("REQUEST_ERROR did not match SUBSCRIBE request");
            xqc_demo_interop_close_conn(conn);
            if (g_pub_conn && !g_pub_conn->closed) {
                xqc_demo_interop_close_conn(g_pub_conn);
            }
            return;
        }
        conn->subscribe_error_received = 1;
        xqc_demo_interop_maybe_complete_preannounce();
    }
}

static void
xqc_demo_interop_on_track_status_ok(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    xqc_moq_request_ok_msg_t *msg)
{
    xqc_demo_interop_conn_t *conn =
        (xqc_demo_interop_conn_t *)user_session->data;
    if (g_current_test != XQC_DEMO_TEST_TRACK_STATUS_SUCCESS
        || request_id != conn->finite_request_id
        || !conn->finite_generic_ok || msg == NULL
        || msg->track_properties_len != 2
        || msg->track_properties == NULL
        || msg->track_properties[0] != 0x02
        || msg->track_properties[1] != 0x01)
    {
        xqc_demo_test_fail("TRACK_STATUS dedicated callback mismatch");
        xqc_demo_interop_close_conn(conn);
        return;
    }
    conn->finite_specific_ok = 1;
    printf("control_e2e|track_status_ok|request_id:%"PRIu64
           "|properties:0201|generic_ok:1\n", request_id);
    xqc_demo_interop_schedule_finite_completion(conn);
}

static void
xqc_demo_interop_on_fetch_ok(xqc_moq_user_session_t *user_session,
    uint64_t request_id, xqc_moq_fetch_ok_msg_t *msg)
{
    xqc_demo_interop_conn_t *conn =
        (xqc_demo_interop_conn_t *)user_session->data;
    if (g_current_test != XQC_DEMO_TEST_FETCH_SUCCESS
        || request_id != conn->finite_request_id || msg == NULL
        || msg->end_of_track != 1 || msg->end_group_id != 6
        || msg->end_object_id != 9 || msg->track_properties_len != 2
        || msg->track_properties == NULL
        || msg->track_properties[0] != 0x02
        || msg->track_properties[1] != 0x01)
    {
        xqc_demo_test_fail("FETCH_OK callback mismatch");
        xqc_demo_interop_close_conn(conn);
        return;
    }
    conn->fetch_ok_seen = 1;
    printf("control_e2e|fetch_ok|request_id:%"PRIu64
           "|end_of_track:1|end:6/9|properties:0201\n", request_id);
    xqc_demo_interop_schedule_finite_completion(conn);
}

static void
xqc_demo_interop_on_fetch_header(xqc_moq_user_session_t *user_session,
    uint64_t request_id, uint8_t fin)
{
    xqc_demo_interop_conn_t *conn =
        (xqc_demo_interop_conn_t *)user_session->data;
    if (g_current_test != XQC_DEMO_TEST_FETCH_SUCCESS
        || request_id != conn->finite_request_id || fin != 0)
    {
        xqc_demo_test_fail("FETCH_HEADER callback mismatch id=%"PRIu64
                           " fin=%u", request_id, fin);
        xqc_demo_interop_close_conn(conn);
        return;
    }
    conn->fetch_header_seen = 1;
    printf("control_e2e|fetch_header|request_id:%"PRIu64"|fin:0\n",
           request_id);
    xqc_demo_interop_schedule_finite_completion(conn);
}

static void
xqc_demo_interop_on_fetch_object(xqc_moq_user_session_t *user_session,
    uint64_t request_id, xqc_moq_object_t *object)
{
    xqc_demo_interop_conn_t *conn =
        (xqc_demo_interop_conn_t *)user_session->data;
    unsigned index = conn->fetch_object_count;
    int valid = g_current_test == XQC_DEMO_TEST_FETCH_SUCCESS
        && request_id == conn->finite_request_id && object != NULL;
    if (valid && index == 0) {
        valid = object->group_id == 2 && object->subgroup_id == 3
            && object->object_id == 4 && object->publisher_priority == 7
            && object->object_properties_len == 2
            && object->object_properties != NULL
            && object->object_properties[0] == 0x38
            && object->object_properties[1] == 0x0e
            && object->payload_len == sizeof("imquic-fetch-A") - 1
            && memcmp(object->payload, "imquic-fetch-A",
                      sizeof("imquic-fetch-A") - 1) == 0;
    } else if (valid && index == 1) {
        valid = object->group_id == 2 && object->subgroup_id == 3
            && object->object_id == 5 && object->payload_len == 0
            && object->status == XQC_MOQ_OBJ_STATUS_NORMAL;
    } else if (valid && index == 2) {
        valid = object->group_id == 4 && object->subgroup_id == 4
            && object->object_id == 0
            && object->payload_len == sizeof("imquic-fetch-C") - 1
            && memcmp(object->payload, "imquic-fetch-C",
                      sizeof("imquic-fetch-C") - 1) == 0;
    } else {
        valid = 0;
    }
    if (!valid) {
        if (object == NULL) {
            xqc_demo_test_fail(
                "FETCH Object callback mismatch index=%u object=NULL", index);

        } else {
            uint8_t property0 = object->object_properties_len > 0
                && object->object_properties != NULL
                ? object->object_properties[0] : 0;
            uint8_t property1 = object->object_properties_len > 1
                && object->object_properties != NULL
                ? object->object_properties[1] : 0;
            xqc_demo_test_fail(
                "FETCH Object callback mismatch index=%u location=%"PRIu64
                "/%"PRIu64"/%"PRIu64" priority=%u priority_set=%u "
                "properties=%"PRIu64" property0=0x%02x property1=0x%02x "
                "payload=%"PRIu64,
                index, object->group_id, object->subgroup_id,
                object->object_id, object->publisher_priority,
                object->publisher_priority_set,
                object->object_properties_len, property0, property1,
                object->payload_len);
        }
        xqc_demo_interop_close_conn(conn);
        return;
    }
    conn->fetch_object_count++;
    printf("control_e2e|fetch_object|index:%u|location:%"PRIu64
           "/%"PRIu64"/%"PRIu64"|payload:%"PRIu64"|properties:%"PRIu64"\n",
           index, object->group_id, object->subgroup_id, object->object_id,
           object->payload_len, object->object_properties_len);
}

static void
xqc_demo_interop_on_fetch_range(xqc_moq_user_session_t *user_session,
    uint64_t request_id, uint64_t group_id, uint64_t object_id,
    uint8_t unknown, uint8_t end_of_stream)
{
    xqc_demo_interop_conn_t *conn =
        (xqc_demo_interop_conn_t *)user_session->data;
    if (g_current_test != XQC_DEMO_TEST_FETCH_SUCCESS
        || request_id != conn->finite_request_id || group_id != 6
        || object_id != 9 || unknown != 1 || end_of_stream != 1
        || conn->fetch_object_count != 3)
    {
        xqc_demo_test_fail("FETCH range callback mismatch");
        xqc_demo_interop_close_conn(conn);
        return;
    }
    conn->fetch_range_seen = 1;
    conn->fetch_header_fin = 1;
    printf("control_e2e|fetch_range|location:6/9|unknown:1|eos:1\n");
    xqc_demo_interop_schedule_finite_completion(conn);
}

static void
xqc_demo_interop_on_subscribe_namespace_error(
    xqc_moq_user_session_t *user_session,
    xqc_moq_subscribe_namespace_error_msg_t *msg)
{
    xqc_demo_interop_conn_t *conn =
        (xqc_demo_interop_conn_t *)user_session->data;
    if (g_current_test
            != XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OVERLAP
        || msg == NULL
        || msg->request_id != conn->namespace_second_request_id
        || msg->error_code != XQC_MOQ_REQUEST_ERROR_PREFIX_OVERLAP
        || msg->track_namespace_tuple == NULL
        || msg->track_namespace_num != 2
        || msg->track_namespace_tuple[0].len != sizeof("overlap") - 1
        || memcmp(msg->track_namespace_tuple[0].data, "overlap",
                  sizeof("overlap") - 1) != 0
        || msg->track_namespace_tuple[1].len != sizeof("child") - 1
        || memcmp(msg->track_namespace_tuple[1].data, "child",
                  sizeof("child") - 1) != 0)
    {
        xqc_demo_test_fail(
            "namespace error compatibility callback mismatch");
        xqc_demo_interop_close_conn(conn);
        return;
    }

    conn->namespace_second_compat_error = 1;
    xqc_demo_interop_maybe_advance_namespace_case(conn);
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
        VERBOSE("subscribe-before-announce: legacy SUBSCRIBE_ERROR received");
        xqc_demo_interop_maybe_complete_preannounce();
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
        track = xqc_moq_track_create_with_ns_tuple(conn->session, msg->track_namespace_tuple,
            msg->track_namespace_num, msg->track_name, XQC_MOQ_TRACK_VIDEO, NULL,
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
    if (ret < 0) {
        xqc_demo_test_fail("SUBSCRIBE_OK send failed: %d", ret);
        xqc_demo_interop_close_conn(conn);
        if (g_sub_conn && !g_sub_conn->closed) {
            xqc_demo_interop_close_conn(g_sub_conn);
        }
    }
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
    xqc_demo_interop_conn_t *conn =
        (xqc_demo_interop_conn_t *)user_session->data;
    if (g_current_test == XQC_DEMO_TEST_PUBLISH_DONE) {
        if (conn->conn_role != 1 || !conn->publish_done_discovery_ok
            || track == NULL || publish_msg == NULL
            || publish_msg->subscribe_id != 1
            || publish_msg->track_namespace_tuple == NULL
            || publish_msg->track_namespace_num != 2
            || publish_msg->track_namespace_tuple[0].len
                != sizeof("done") - 1
            || memcmp(publish_msg->track_namespace_tuple[0].data,
                      "done", sizeof("done") - 1) != 0
            || publish_msg->track_namespace_tuple[1].len
                != sizeof("lifecycle") - 1
            || memcmp(publish_msg->track_namespace_tuple[1].data,
                      "lifecycle", sizeof("lifecycle") - 1) != 0
            || publish_msg->track_name == NULL
            || publish_msg->track_name_len != sizeof("audio") - 1
            || memcmp(publish_msg->track_name, "audio",
                      sizeof("audio") - 1) != 0)
        {
            xqc_demo_test_fail(
                "PUBLISH_DONE PUBLISH request fields mismatch");
            xqc_demo_interop_close_conn(conn);
            return;
        }

        xqc_moq_publish_ok_msg_t publish_ok;
        memset(&publish_ok, 0, sizeof(publish_ok));
        publish_ok.subscribe_id = publish_msg->subscribe_id;
        publish_ok.forward = 1;
        publish_ok.group_order = XQC_MOQ_GROUP_ORDER_ASCENDING;
        xqc_int_t ret = xqc_moq_write_publish_ok(
            conn->session, &publish_ok);
        if (ret != XQC_OK) {
            xqc_demo_test_fail(
                "PUBLISH_DONE PUBLISH_OK send failed: %d", (int)ret);
            xqc_demo_interop_close_conn(conn);
            return;
        }
        conn->publish_done_stream_request_id =
            publish_msg->subscribe_id;
        conn->publish_done_response_sent = 1;
        return;
    }
    if (g_current_test != XQC_DEMO_TEST_SUBSCRIBE_TRACKS_PUBLISH) {
        return;
    }
    if (conn->conn_role != 1 || track == NULL || publish_msg == NULL
        || publish_msg->track_namespace_tuple == NULL
        || publish_msg->track_namespace_num != 1
        || publish_msg->track_namespace_tuple[0].len
            != sizeof("namespace") - 1
        || memcmp(publish_msg->track_namespace_tuple[0].data,
                  "namespace", sizeof("namespace") - 1) != 0
        || publish_msg->track_name == NULL
        || ((publish_msg->track_name_len != sizeof("video") - 1
             || memcmp(publish_msg->track_name, "video",
                       sizeof("video") - 1) != 0)
            && (publish_msg->track_name_len != sizeof("audio") - 1
                || memcmp(publish_msg->track_name, "audio",
                          sizeof("audio") - 1) != 0)))
    {
        xqc_demo_test_fail(
            "PUBLISH did not describe a discovered server track");
        xqc_demo_interop_close_conn(conn);
        return;
    }

    xqc_moq_publish_ok_msg_t publish_ok;
    memset(&publish_ok, 0, sizeof(publish_ok));
    publish_ok.subscribe_id = publish_msg->subscribe_id;
    publish_ok.forward = 1;
    publish_ok.group_order = XQC_MOQ_GROUP_ORDER_ASCENDING;
    xqc_int_t ret =
        xqc_moq_write_publish_ok(conn->session, &publish_ok);
    VERBOSE("PUBLISH received request_id=%"PRIu64
            " track=%.*s REQUEST_OK ret=%d",
            publish_msg->subscribe_id,
            (int)publish_msg->track_name_len,
            publish_msg->track_name, (int)ret);
    if (ret != XQC_OK) {
        xqc_demo_test_fail(
            "PUBLISH REQUEST_OK send failed: %d", (int)ret);
        xqc_demo_interop_close_conn(conn);
        return;
    }

    conn->publish_received = 1;
    conn->publish_response_sent = 1;
    xqc_demo_interop_maybe_complete_tracks_publish(conn);
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
    xqc_demo_interop_conn_t *conn =
        (xqc_demo_interop_conn_t *)user_session->data;
    if (g_current_test != XQC_DEMO_TEST_PUBLISH_DONE) {
        return;
    }

    conn->publish_done_callback_count++;
    if (conn->publish_done_callback_count != 1
        || !conn->publish_done_response_sent
        || track == NULL || publish_done == NULL
        || publish_done->subscribe_id
            != conn->publish_done_stream_request_id
        || publish_done->subscribe_id != 1
        || publish_done->status_code
            != XQC_MOQ_PUBLISH_DONE_TRACK_ENDED
        || publish_done->stream_count != 0
        || publish_done->reason_phrase == NULL
        || publish_done->reason_phrase_len != sizeof("e2e done") - 1
        || memcmp(publish_done->reason_phrase, "e2e done",
                  sizeof("e2e done") - 1) != 0)
    {
        xqc_demo_test_fail(
            "PUBLISH_DONE callback mismatch id=%"PRIu64
            " status=%"PRIu64" streams=%"PRIu64" callbacks=%d",
            publish_done ? publish_done->subscribe_id : XQC_MOQ_INVALID_ID,
            publish_done ? publish_done->status_code : XQC_MOQ_INVALID_ID,
            publish_done ? publish_done->stream_count : XQC_MOQ_INVALID_ID,
            conn->publish_done_callback_count);
        xqc_demo_interop_close_conn(conn);
        return;
    }

    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &conn->session->peer_request_stream_list) {
        xqc_moq_stream_t *stream = xqc_list_entry(
            pos, xqc_moq_stream_t, request_list_member);
        if (!stream->peer_request
            || stream->request_type != XQC_MOQ_MSG_PUBLISH
            || stream->request_id != publish_done->subscribe_id)
        {
            continue;
        }
        xqc_stream_t *quic_stream = stream->trans_ops.quic_stream(
            stream->trans_stream);
        if (stream->request_closed_notified
            && quic_stream != NULL
            && quic_stream->stream_state_recv
                == XQC_RECV_STREAM_ST_DATA_READ
            && quic_stream->stream_stats.peer_fin_read_time != 0)
        {
            conn->publish_done_fin_observed = 1;
        }
        break;
    }
    if (!conn->publish_done_fin_observed) {
        xqc_demo_test_fail(
            "PUBLISH_DONE callback arrived without consumed request FIN");
        xqc_demo_interop_close_conn(conn);
        return;
    }

    if (!conn->publish_done_completion_scheduled) {
        conn->publish_done_completion_scheduled = 1;
        struct timeval duplicate_window = { 0, 100000 };
        if (event_base_once(
                g_eb, -1, EV_TIMEOUT,
                xqc_demo_interop_publish_done_complete_callback,
                conn, &duplicate_window) < 0)
        {
            xqc_demo_test_fail(
                "failed to schedule PUBLISH_DONE duplicate check");
            xqc_demo_interop_close_conn(conn);
        }
    }
}

static void
xqc_demo_interop_on_publish_blocked(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    const xqc_moq_track_ns_field_t *full_namespace,
    uint64_t full_namespace_num, const char *track_name,
    size_t track_name_len)
{
    xqc_demo_interop_conn_t *conn =
        (xqc_demo_interop_conn_t *)user_session->data;
    if (g_current_test == XQC_DEMO_TEST_PUBLISH_BLOCKED) {
        if (!conn->publish_blocked_initial_ok
            || request_id != conn->publish_blocked_request_id
            || request_id != 0
            || full_namespace == NULL || full_namespace_num != 3
            || full_namespace[0].len != sizeof("blocked") - 1
            || memcmp(full_namespace[0].data, "blocked",
                      sizeof("blocked") - 1) != 0
            || full_namespace[1].len != sizeof("base") - 1
            || memcmp(full_namespace[1].data, "base",
                      sizeof("base") - 1) != 0
            || full_namespace[2].len != sizeof("child") - 1
            || memcmp(full_namespace[2].data, "child",
                      sizeof("child") - 1) != 0
            || track_name == NULL
            || track_name_len != sizeof("audio") - 1
            || memcmp(track_name, "audio", sizeof("audio") - 1) != 0)
        {
            xqc_demo_test_fail(
                "PUBLISH_BLOCKED reconstructed name mismatch");
            xqc_demo_interop_close_conn(conn);
            return;
        }
        printf("control_e2e|publish_blocked|request_id:%"PRIu64
               "|full_name:blocked/base/child/audio\n", request_id);
        xqc_demo_test_pass();
        if (g_test_timeout_event) {
            event_del(g_test_timeout_event);
        }
        struct timeval flush_delay = { 0, 100000 };
        if (event_base_once(g_eb, -1, EV_TIMEOUT,
                            xqc_demo_interop_delayed_close_callback,
                            conn, &flush_delay) < 0)
        {
            xqc_demo_interop_close_conn(conn);
        }
        return;
    }
    if (g_current_test != XQC_DEMO_TEST_REQUEST_UPDATE_SUCCESS) {
        return;
    }
    if (request_id != conn->request_update_target_id
        || full_namespace == NULL || full_namespace_num != 3
        || full_namespace[0].len != sizeof("update") - 1
        || memcmp(full_namespace[0].data, "update",
                  sizeof("update") - 1) != 0
        || full_namespace[1].len != sizeof("new") - 1
        || memcmp(full_namespace[1].data, "new",
                  sizeof("new") - 1) != 0
        || full_namespace[2].len != sizeof("probe") - 1
        || memcmp(full_namespace[2].data, "probe",
                  sizeof("probe") - 1) != 0
        || track_name == NULL
        || track_name_len != sizeof("audio") - 1
        || memcmp(track_name, "audio", sizeof("audio") - 1) != 0)
    {
        xqc_demo_test_fail(
            "REQUEST_UPDATE committed-prefix PUBLISH_BLOCKED mismatch");
        xqc_demo_interop_close_conn(conn);
        return;
    }

    conn->request_update_blocked = 1;
    xqc_demo_interop_maybe_complete_request_update(conn);
}

static void
xqc_demo_interop_on_goaway_draft18(
    xqc_moq_user_session_t *user_session, xqc_moq_goaway_scope_t scope,
    uint64_t target_request_id, const char *uri, size_t uri_len,
    uint64_t timeout_ms, uint64_t first_unprocessed_request_id)
{
    xqc_demo_interop_conn_t *conn =
        (xqc_demo_interop_conn_t *)user_session->data;
    if (g_current_test == XQC_DEMO_TEST_REQUEST_GOAWAY) {
        if (scope != XQC_MOQ_GOAWAY_SCOPE_REQUEST
            || target_request_id
                != conn->request_goaway_target_request_id
            || target_request_id != 0
            || uri != NULL || uri_len != 0 || timeout_ms != 100
            || first_unprocessed_request_id != XQC_MOQ_INVALID_ID)
        {
            xqc_demo_test_fail(
                "request GOAWAY callback mismatch target=%"PRIu64
                " timeout=%"PRIu64,
                target_request_id, timeout_ms);
            xqc_demo_interop_close_conn(conn);
            return;
        }
        conn->request_goaway_received = 1;
        printf("control_e2e|goaway|scope:request|target_id:%"PRIu64
               "|timeout_ms:%"PRIu64"\n",
               target_request_id, timeout_ms);
        return;
    }
    if (g_current_test != XQC_DEMO_TEST_CONTROL_GOAWAY) {
        return;
    }
    if (scope != XQC_MOQ_GOAWAY_SCOPE_CONTROL
        || timeout_ms != 1000
        || first_unprocessed_request_id
            != conn->control_goaway_cutoff_request_id)
    {
        xqc_demo_test_fail(
            "control GOAWAY callback mismatch cutoff=%"PRIu64
            " timeout=%"PRIu64,
            first_unprocessed_request_id, timeout_ms);
        xqc_demo_interop_close_conn(conn);
        return;
    }
    conn->control_goaway_received = 1;
    printf("control_e2e|goaway|scope:control|cutoff:%"PRIu64
           "|timeout_ms:%"PRIu64"\n",
           first_unprocessed_request_id, timeout_ms);
    xqc_demo_interop_maybe_complete_control_goaway(conn);
}

static void
xqc_demo_interop_on_request_cancelled(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    xqc_moq_msg_type_t request_type, uint8_t locally_initiated,
    uint64_t error_code)
{
    xqc_demo_interop_conn_t *conn =
        (xqc_demo_interop_conn_t *)user_session->data;
    if (g_current_test != XQC_DEMO_TEST_REQUEST_GOAWAY) {
        return;
    }
    if (conn->request_goaway_semantic_complete) {
        return;
    }
    if (!conn->request_goaway_target_ok
        || !conn->request_goaway_other_ok
        || !conn->request_goaway_received
        || request_id != conn->request_goaway_target_request_id
        || request_id != 0
        || request_type != XQC_MOQ_MSG_SUBSCRIBE_TRACKS
        || locally_initiated != 1
        || error_code != XQC_MOQ_REQUEST_STREAM_GOING_AWAY)
    {
        xqc_demo_test_fail(
            "request GOAWAY cancellation mismatch id=%"PRIu64
            " type=0x%x local=%u code=0x%"PRIx64,
            request_id, request_type, locally_initiated, error_code);
        xqc_demo_interop_close_conn(conn);
        return;
    }
    conn->request_goaway_cancel_count++;
    if (conn->request_goaway_cancel_count != 1) {
        xqc_demo_test_fail(
            "request GOAWAY target cancelled more than once");
        xqc_demo_interop_close_conn(conn);
        return;
    }

    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &conn->session->local_request_stream_list) {
        xqc_moq_stream_t *stream = xqc_list_entry(
            pos, xqc_moq_stream_t, request_list_member);
        if (stream->local_request
            && stream->request_id
                == conn->request_goaway_other_request_id
            && stream->request_id == 2
            && stream->request_type
                == XQC_MOQ_MSG_SUBSCRIBE_TRACKS
            && stream->response_received
            && !stream->request_closed_notified
            && !stream->d18_goaway_received)
        {
            conn->request_goaway_other_retained = 1;
            break;
        }
    }
    if (!conn->request_goaway_other_retained) {
        xqc_demo_test_fail(
            "request GOAWAY affected sibling request");
        xqc_demo_interop_close_conn(conn);
        return;
    }

    printf("control_e2e|request_reset|request_id:%"PRIu64
           "|code:0x04\n", request_id);
    printf("control_e2e|other_request_retained|request_id:%"PRIu64
           "\n", conn->request_goaway_other_request_id);
    if (!conn->request_goaway_completion_scheduled) {
        conn->request_goaway_completion_scheduled = 1;
        struct timeval duplicate_window = { 0, 100000 };
        if (event_base_once(
                g_eb, -1, EV_TIMEOUT,
                xqc_demo_interop_request_goaway_complete_callback,
                conn, &duplicate_window) < 0)
        {
            xqc_demo_test_fail(
                "failed to schedule request GOAWAY duplicate check");
            xqc_demo_interop_close_conn(conn);
        }
    }
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
xqc_demo_interop_delayed_close_callback(int fd, short what, void *arg)
{
    (void)fd; (void)what;
    xqc_demo_interop_conn_t *conn = (xqc_demo_interop_conn_t *)arg;
    if (conn == NULL || conn->closed) {
        return;
    }
    xqc_demo_interop_close_conn(conn);
}

static void
xqc_demo_interop_publish_done_complete_callback(
    int fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    xqc_demo_interop_conn_t *conn =
        (xqc_demo_interop_conn_t *)arg;
    if (conn == NULL || conn->closed) {
        return;
    }
    if (conn->publish_done_callback_count != 1
        || !conn->publish_done_fin_observed)
    {
        xqc_demo_test_fail(
            "PUBLISH_DONE duplicate/FIN check failed callbacks=%d fin=%d",
            conn->publish_done_callback_count,
            conn->publish_done_fin_observed);
        xqc_demo_interop_close_conn(conn);
        return;
    }

    printf("control_e2e|publish_done|wire_request_id:none"
           "|stream_request_id:%"PRIu64
           "|status:0x2|stream_count:0|callbacks:1|fin:1\n",
           conn->publish_done_stream_request_id);
    xqc_demo_test_pass();
    if (g_test_timeout_event) {
        event_del(g_test_timeout_event);
    }
    xqc_demo_interop_close_conn(conn);
}

static void
xqc_demo_interop_request_goaway_complete_callback(
    int fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    xqc_demo_interop_conn_t *conn =
        (xqc_demo_interop_conn_t *)arg;
    if (conn == NULL || conn->closed) {
        return;
    }
    if (!conn->request_goaway_received
        || conn->request_goaway_cancel_count != 1
        || !conn->request_goaway_other_retained)
    {
        xqc_demo_test_fail(
            "request GOAWAY completion mismatch received=%d"
            " cancellations=%d retained=%d",
            conn->request_goaway_received,
            conn->request_goaway_cancel_count,
            conn->request_goaway_other_retained);
        xqc_demo_interop_close_conn(conn);
        return;
    }
    uint64_t conn_err = xqc_moq_session_get_error(conn->session);
    if (conn_err != 0) {
        xqc_demo_test_fail(
            "request GOAWAY set connection error: %"PRIu64,
            conn_err);
        xqc_demo_interop_close_conn(conn);
        return;
    }
    conn->request_goaway_semantic_complete = 1;
    xqc_demo_interop_close_conn(conn);
}

static void
xqc_demo_interop_create_publisher_callback(int fd, short what, void *arg)
{
    (void)fd; (void)what; (void)arg;
    if (g_pub_conn != NULL) {
        return;
    }
    xqc_demo_interop_conn_t *pub = xqc_demo_interop_init_conn(0);
    if (pub == NULL) {
        xqc_demo_test_fail("failed to create delayed publisher connection");
        event_base_loopbreak(g_eb);
        return;
    }
    xqc_conn_settings_t settings;
    memset(&settings, 0, sizeof(settings));
    settings.cong_ctrl_callback = xqc_bbr_cb;
    settings.proto_version = XQC_VERSION_V1;
    xqc_conn_ssl_config_t ssl_cfg;
    memset(&ssl_cfg, 0, sizeof(ssl_cfg));
    if (g_tls_disable_verify) {
        ssl_cfg.cert_verify_flag |= XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;
    }
    const xqc_cid_t *cid = xqc_connect(g_ctx.engine, &settings, NULL, 0,
        g_relay_sni, 0, &ssl_cfg, pub->peer_addr, pub->peer_addrlen,
        XQC_ALPN_MOQ_DRAFT_18, g_pub_user_session);
    if (cid == NULL) {
        xqc_demo_test_fail("delayed publisher xqc_connect failed");
        event_base_loopbreak(g_eb);
        return;
    }
    memcpy(&pub->cid, cid, sizeof(xqc_cid_t));
    VERBOSE("created publisher connection 500 ms after subscriber");
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
        .on_request_ok              = xqc_demo_interop_on_request_ok,
        .on_request_error           = xqc_demo_interop_on_request_error,
        .on_fetch_ok                = xqc_demo_interop_on_fetch_ok,
        .on_fetch_header            = xqc_demo_interop_on_fetch_header,
        .on_fetch_object            = xqc_demo_interop_on_fetch_object,
        .on_fetch_range             = xqc_demo_interop_on_fetch_range,
        .on_track_status_ok         = xqc_demo_interop_on_track_status_ok,
        .on_subscribe_namespace_ok  =
            xqc_demo_interop_on_subscribe_namespace_ok,
        .on_subscribe_namespace_error =
            xqc_demo_interop_on_subscribe_namespace_error,
        .on_namespace               = xqc_demo_interop_on_namespace,
        .on_namespace_done          =
            xqc_demo_interop_on_namespace_done,
        .on_catalog                 = xqc_demo_interop_on_catalog,
        .on_video                   = xqc_demo_interop_on_video,
        .on_audio                   = xqc_demo_interop_on_audio,
    };

    xqc_moq_role_t role = XQC_MOQ_PUBSUB;

    char authority[sizeof(g_relay_sni) + 16];
    snprintf(authority, sizeof(authority), "%s:%d", g_relay_sni, g_relay_port);
    xqc_moq_session_t *session = xqc_moq_session_create_draft18(
        conn, user_session, XQC_MOQ_TRANSPORT_QUIC,
        role, callbacks, authority, g_relay_path);
    if (session == NULL) {
        return -1;
    }
    iconn->session = session;
    xqc_moq_session_set_publish_blocked_callback(
        session, xqc_demo_interop_on_publish_blocked);
    xqc_moq_session_set_goaway_draft18_callback(
        session, xqc_demo_interop_on_goaway_draft18);
    xqc_moq_session_set_request_cancelled_callback(
        session, xqc_demo_interop_on_request_cancelled);
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

    if (g_current_test == XQC_DEMO_TEST_REQUEST_GOAWAY) {
        printf("control_e2e|connection_close|case:request-goaway"
               "|conn_err:%d\n", (int)err);
        if (err != 0) {
            xqc_demo_test_fail(
                "request GOAWAY connection error: %d", (int)err);
        } else if (g_fail_reason[0] == '\0'
                   && !iconn->request_goaway_semantic_complete)
        {
            xqc_demo_test_fail(
                "request GOAWAY connection closed before semantic checks");
        } else if (g_fail_reason[0] == '\0') {
            xqc_demo_test_pass();
            if (g_test_timeout_event) {
                event_del(g_test_timeout_event);
            }
        }

    } else if (!g_test_passed && g_fail_reason[0] == '\0') {
        if (g_current_test == XQC_DEMO_TEST_ANNOUNCE_ONLY
            && iconn->publish_ns_ok_received)
        {
            xqc_demo_test_pass();
        } else if (g_current_test == XQC_DEMO_TEST_PUBLISH_NAMESPACE_DONE
                   && iconn->publish_ns_ok_received
                   && iconn->publish_ns_cancelled)
        {
            VERBOSE("connection closed (err=%d) for %s after request cancellation - PASS",
                    (int)err, g_test_case_names[g_current_test]);
            xqc_demo_test_pass();
        } else if (g_current_test == XQC_DEMO_TEST_PUBLISH_NAMESPACE_DONE) {
            xqc_demo_test_fail("connection closed before PUBLISH_NAMESPACE cancellation (err=%d)",
                               (int)err);
        } else if (g_current_test == XQC_DEMO_TEST_SUBSCRIBE_ERROR) {
            if (iconn->subscribe_error_received) {
                xqc_demo_test_pass();
            } else {
                xqc_demo_test_fail("connection closed without REQUEST_ERROR (err=%d)", (int)err);
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
        if (g_close_timeout_event) {
            event_del(g_close_timeout_event);
        }
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
            if (g_current_test == XQC_DEMO_TEST_SETUP_ONLY && iconn->session_ready)
            {
                xqc_demo_test_pass();
            } else if (g_current_test == XQC_DEMO_TEST_PUBLISH_NAMESPACE_DONE
                       && iconn->publish_ns_ok_received
                       && iconn->publish_ns_cancelled)
            {
                xqc_demo_test_pass();
            } else if (g_current_test == XQC_DEMO_TEST_PUBLISH_NAMESPACE_DONE) {
                xqc_demo_test_fail("wt connection closed before PUBLISH_NAMESPACE cancellation");
            } else if (g_current_test == XQC_DEMO_TEST_ANNOUNCE_ONLY
                       && iconn->publish_ns_ok_received)
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
        .on_request_ok              = xqc_demo_interop_on_request_ok,
        .on_request_error           = xqc_demo_interop_on_request_error,
        .on_fetch_ok                = xqc_demo_interop_on_fetch_ok,
        .on_fetch_header            = xqc_demo_interop_on_fetch_header,
        .on_fetch_object            = xqc_demo_interop_on_fetch_object,
        .on_fetch_range             = xqc_demo_interop_on_fetch_range,
        .on_track_status_ok         = xqc_demo_interop_on_track_status_ok,
        .on_subscribe_namespace_ok  =
            xqc_demo_interop_on_subscribe_namespace_ok,
        .on_subscribe_namespace_error =
            xqc_demo_interop_on_subscribe_namespace_error,
        .on_namespace               = xqc_demo_interop_on_namespace,
        .on_namespace_done          =
            xqc_demo_interop_on_namespace_done,
        .on_catalog                 = xqc_demo_interop_on_catalog,
        .on_video                   = xqc_demo_interop_on_video,
        .on_audio                   = xqc_demo_interop_on_audio,
    };

    xqc_connection_t *quic_conn = xqc_h3_conn_get_xqc_conn(ctx->h3_conn);
    xqc_moq_session_t *session = xqc_moq_session_create(
        quic_conn, user_session, XQC_MOQ_TRANSPORT_WEBTRANSPORT,
        XQC_MOQ_PUBSUB, callbacks, NULL);
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
            .xqc_log_write_err = xqc_demo_interop_write_log,
            .xqc_log_write_stat = xqc_demo_interop_write_log,
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
        xqc_moq_init_alpn_draft18(g_ctx.engine, &conn_cbs, g_transport_type);
    }

    struct event *ev_timeout = evtimer_new(g_eb, xqc_demo_interop_timeout_callback, NULL);
    struct event *ev_close_timeout = evtimer_new(
        g_eb, xqc_demo_interop_close_timeout_callback, NULL);
    g_test_timeout_event = ev_timeout;
    g_close_timeout_event = ev_close_timeout;
    if (ev_timeout == NULL || ev_close_timeout == NULL) {
        xqc_demo_test_fail("failed to create test deadline events");
        goto cleanup;
    }
    int timeout_sec = XQC_INTEROP_TIMEOUT_SEC;
    if (tc == XQC_DEMO_TEST_SUBSCRIBE_ERROR
        || tc == XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OK
        || tc == XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OVERLAP
        || tc
            == XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_NOTIFICATIONS
        || tc == XQC_DEMO_TEST_SUBSCRIBE_TRACKS_PUBLISH
        || tc == XQC_DEMO_TEST_SUBSCRIBE_TRACKS_OVERLAP
        || tc == XQC_DEMO_TEST_REQUEST_UPDATE_SUCCESS
        || tc == XQC_DEMO_TEST_REQUEST_UPDATE_OVERLAP
        || tc == XQC_DEMO_TEST_PUBLISH_BLOCKED
        || tc == XQC_DEMO_TEST_CONTROL_GOAWAY
        || tc == XQC_DEMO_TEST_TRACK_STATUS_SUCCESS
        || tc == XQC_DEMO_TEST_TRACK_STATUS_REJECTION
        || tc == XQC_DEMO_TEST_FETCH_SUCCESS
        || tc == XQC_DEMO_TEST_FETCH_REJECTION)
    {
        timeout_sec = 4;
    } else if (tc == XQC_DEMO_TEST_ANNOUNCE_SUBSCRIBE || tc == XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE) {
        timeout_sec = 20;
    }
    struct timeval tv_timeout = { timeout_sec, 0 };
    event_add(ev_timeout, &tv_timeout);

    int first_role;
    switch (tc) {
    case XQC_DEMO_TEST_SUBSCRIBE_BEFORE_ANNOUNCE:
    case XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OK:
    case XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_OVERLAP:
    case XQC_DEMO_TEST_SUBSCRIBE_NAMESPACE_NOTIFICATIONS:
    case XQC_DEMO_TEST_SUBSCRIBE_TRACKS_PUBLISH:
    case XQC_DEMO_TEST_SUBSCRIBE_TRACKS_OVERLAP:
    case XQC_DEMO_TEST_REQUEST_UPDATE_SUCCESS:
    case XQC_DEMO_TEST_REQUEST_UPDATE_OVERLAP:
    case XQC_DEMO_TEST_PUBLISH_BLOCKED:
    case XQC_DEMO_TEST_PUBLISH_DONE:
    case XQC_DEMO_TEST_CONTROL_GOAWAY:
    case XQC_DEMO_TEST_REQUEST_GOAWAY:
    case XQC_DEMO_TEST_TRACK_STATUS_SUCCESS:
    case XQC_DEMO_TEST_TRACK_STATUS_REJECTION:
    case XQC_DEMO_TEST_FETCH_SUCCESS:
    case XQC_DEMO_TEST_FETCH_REJECTION:
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
            XQC_ALPN_MOQ_DRAFT_18, first_us);
    }
    if (cid == NULL) {
        xqc_demo_test_fail("xqc_connect failed");
        goto cleanup;
    }
    memcpy(&first->cid, cid, sizeof(xqc_cid_t));

    if (tc == XQC_DEMO_TEST_ANNOUNCE_SUBSCRIBE) {
        int second_role = 1;
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
                XQC_ALPN_MOQ_DRAFT_18, second_us);
        }
        if (second_cid == NULL) {
            xqc_demo_test_fail("second xqc_connect failed");
            goto cleanup;
        }
        memcpy(&second->cid, second_cid, sizeof(xqc_cid_t));
    }

    event_base_dispatch(g_eb);

cleanup:
    if (ev_timeout) {
        event_del(ev_timeout);
        event_free(ev_timeout);
    }
    g_test_timeout_event = NULL;
    if (ev_close_timeout) {
        event_del(ev_close_timeout);
        event_free(ev_close_timeout);
    }
    g_close_timeout_event = NULL;
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
        g_relay_path[0] = '\0';
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
        } else if (strcmp(argv[i], "--disconnect-after-request") == 0) {
            g_disconnect_after_request = 1;
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
            printf("  -t, --test <SPEC>        Run comma-separated NAME[@PORT] cases (omit to run all)\n");
            printf("  -l, --list               List available tests\n");
            printf("  -v, --verbose            Verbose output\n");
            printf("      --sni <hostname>     Override TLS SNI\n");
            printf("      --tls-disable-verify Disable TLS certificate verification\n");
            printf("      --disconnect-after-request Close after the lifecycle request is queued\n");
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
    if (g_transport_type != XQC_MOQ_TRANSPORT_QUIC) {
        fprintf(stderr, "error: draft-18 interop cases currently support raw QUIC (moqt://) only\n");
        return 127;
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

    struct {
        xqc_demo_test_case_t test_case;
        int relay_port;
    } tests[XQC_INTEROP_MAX_TESTS];
    int num_tests = 0;

    if (testcase && testcase[0]) {
        char *test_list = strdup(testcase);
        if (test_list == NULL) {
            fprintf(stderr, "error: cannot allocate test case list\n");
            return 1;
        }
        char *entry = test_list;
        while (entry != NULL) {
            char *next_entry = strchr(entry, ',');
            if (next_entry != NULL) {
                *next_entry++ = '\0';
            }
            if (entry[0] == '\0' || num_tests >= XQC_INTEROP_MAX_TESTS) {
                fprintf(stderr, "error: invalid test case list '%s'\n", testcase);
                free(test_list);
                return 127;
            }

            int relay_port = g_relay_port;
            char *port_separator = strrchr(entry, '@');
            if (port_separator != NULL) {
                char *port_end = NULL;
                long parsed_port;
                *port_separator++ = '\0';
                parsed_port = strtol(port_separator, &port_end, 10);
                if (entry[0] == '\0' || port_separator[0] == '\0'
                    || port_end == NULL || *port_end != '\0'
                    || parsed_port < 1 || parsed_port > 65535)
                {
                    fprintf(stderr, "error: invalid test endpoint '%s@%s'\n",
                            entry, port_separator);
                    free(test_list);
                    return 127;
                }
                relay_port = (int)parsed_port;
            }

            xqc_demo_test_case_t tc = xqc_demo_parse_test_name(entry);
            if (tc == XQC_DEMO_TEST_UNKNOWN) {
                fprintf(stderr, "error: unknown test case '%s'\n", entry);
                fprintf(stderr,
                        "  use --list to show supported draft-18 cases\n");
                free(test_list);
                return 127;
            }
            tests[num_tests].test_case = tc;
            tests[num_tests].relay_port = relay_port;
            num_tests++;
            entry = next_entry;
        }
        free(test_list);
    } else {
        for (int i = 0; i < XQC_INTEROP_MAX_TESTS; i++) {
            tests[i].test_case = (xqc_demo_test_case_t)i;
            tests[i].relay_port = g_relay_port;
        }
        num_tests = XQC_INTEROP_MAX_TESTS;
    }

    xqc_demo_tap_header();
    xqc_demo_tap_plan(num_tests);

    int all_passed = 1;
    for (int i = 0; i < num_tests; i++) {
        g_relay_port = tests[i].relay_port;
        VERBOSE("running %s against %s:%d",
                g_test_case_names[tests[i].test_case],
                g_relay_host, g_relay_port);
        int passed = xqc_demo_run_single_test(tests[i].test_case);
        uint64_t duration_ms = (xqc_now() - g_test_start_us) / 1000;
        xqc_demo_tap_result(i + 1,
                   g_test_case_names[tests[i].test_case], passed, duration_ms,
                   passed ? "" : g_fail_reason);
        if (!passed) {
            all_passed = 0;
        }
    }

    return all_passed ? 0 : 1;
}
