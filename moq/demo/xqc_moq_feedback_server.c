
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
#include <signal.h>
#include <stdint.h>

#include "tests/platform.h"
#include "xqc_moq_demo_comm.h"

#ifndef XQC_SYS_WINDOWS
#include <unistd.h>
#include <sys/wait.h>
#include <getopt.h>
#endif

#include <moq/xqc_moq.h>
#include <moq/xqc_moq_fb_report.h>

#define TEST_ADDR "127.0.0.1"
#define TEST_PORT 9443

#define XQC_PACKET_TMP_BUF_LEN 1500
#define XQC_MAX_LOG_LEN 2048
#define XQC_CID_LEN 12

extern long xqc_random(void);
extern xqc_usec_t xqc_now();

xqc_app_ctx_t ctx;
struct event_base *eb;

int g_frame_num = 100;
int g_jitter_ms = 0;

static uint64_t g_feedback_report_count = 0;
static uint64_t g_total_objects_sent = 0;
static uint64_t g_last_objects_lost = 0;
static uint64_t g_last_objects_late = 0;
static uint64_t g_cc_adj_count = 0;  /* reports with loss/late > 0 (heuristic) */

typedef struct {
    user_conn_t          base;
    uint64_t             video_subscribe_id;
    xqc_moq_track_t     *video_track;
    xqc_moq_session_t   *moq_session;
    struct event         *ev_send_timer;
    uint64_t             video_seq;
    int                  countdown;
    int                  closing_notified;
} fb_server_conn_t;


static int
xqc_server_create_socket(const char *addr, unsigned int port)
{
    int fd;
    int type = AF_INET;
    ctx.local_addrlen = sizeof(struct sockaddr_in);
    struct sockaddr *saddr = (struct sockaddr *)&ctx.local_addr;
    int optval;

    fd = socket(type, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("create socket failed, errno: %d\n", get_sys_errno());
        return -1;
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("set socket nonblock failed, errno: %d\n", errno);
        goto err;
    }

    optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    int size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    memset(saddr, 0, sizeof(struct sockaddr_in));
    struct sockaddr_in *addr_v4 = (struct sockaddr_in *)saddr;
    addr_v4->sin_family = type;
    addr_v4->sin_port = htons(port);
    addr_v4->sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, saddr, ctx.local_addrlen) < 0) {
        printf("bind socket failed, errno: %d\n", get_sys_errno());
        goto err;
    }
    return fd;

err:
    close(fd);
    return -1;
}

static void
xqc_server_socket_read_handler(xqc_app_ctx_t *ctx)
{
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = sizeof(struct sockaddr_in);
    ssize_t recv_size = 0;
    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];

    do {
        recv_size = recvfrom(ctx->listen_fd, packet_buf, sizeof(packet_buf), 0,
                             (struct sockaddr *)&peer_addr, &peer_addrlen);
        if (recv_size < 0 && get_sys_errno() == EAGAIN) {
            break;
        }
        if (recv_size < 0) {
            printf("recvfrom err=%s\n", strerror(get_sys_errno()));
            break;
        }

        uint64_t recv_time = xqc_now();
        xqc_int_t ret = xqc_engine_packet_process(ctx->engine, packet_buf, recv_size,
                                        (struct sockaddr *)(&ctx->local_addr), ctx->local_addrlen,
                                        (struct sockaddr *)(&peer_addr), peer_addrlen,
                                        (xqc_usec_t)recv_time, NULL);
        if (ret != XQC_OK) {
            printf("packet process err: %d\n", ret);
            return;
        }
    } while (recv_size > 0);

    xqc_engine_finish_recv(ctx->engine);
}

static void
xqc_server_socket_event_callback(int fd, short what, void *arg)
{
    xqc_app_ctx_t *ctx = (xqc_app_ctx_t *)arg;
    if (what & EV_READ) {
        xqc_server_socket_read_handler(ctx);
    }
}


/* Feedback decision examples: Level 0 (auto), Level 1 (custom thresholds),
 * Level 2 (decision callback).  Uncomment below to try each level. */

/*
static xqc_int_t
fb_custom_decision_example(xqc_moq_session_t *session,
    const xqc_moq_fb_report_t *report, const xqc_moq_fb_input_t *input,
    xqc_moq_fb_decision_t *out_decision, void *user_data)
{
    if (input->loss_rate > 0.15) {
        out_decision->action = XQC_MOQ_FB_ACTION_PACING_GAIN;
        out_decision->u.pacing_gain.gain = 0.6f;
        return XQC_OK;
    }
    if (input->loss_rate > 0.05) {
        out_decision->action = XQC_MOQ_FB_ACTION_PACING_GAIN;
        out_decision->u.pacing_gain.gain = 0.85f;
        return XQC_OK;
    }
    return -1;
}

static xqc_int_t
fb_suppress_decision_example(xqc_moq_session_t *session,
    const xqc_moq_fb_report_t *report, const xqc_moq_fb_input_t *input,
    xqc_moq_fb_decision_t *out_decision, void *user_data)
{
    if (input->loss_rate < 0.01 && input->late_rate < 0.01) {
        out_decision->action = XQC_MOQ_FB_ACTION_NONE;
        return XQC_OK;
    }
    return -1;
}
*/

static void
fb_on_feedback_media(xqc_moq_session_t *session,
    const xqc_moq_fb_report_t *report, void *user_data)
{
    g_feedback_report_count++;

    double loss_rate = 0, late_rate = 0;
    uint64_t playout_ahead_ms = 0;

    if (report->summary_stats.total_objects_evaluated > 0) {
        loss_rate = (double)report->summary_stats.objects_lost
                  / report->summary_stats.total_objects_evaluated;
        late_rate = (double)report->summary_stats.objects_received_late
                  / report->summary_stats.total_objects_evaluated;
    }

    for (uint64_t i = 0; i < report->optional_metric_count; i++) {
        if (report->optional_metrics[i].metric_type == XQC_MOQ_FB_METRIC_PLAYOUT_AHEAD_MS) {
            playout_ahead_ms = report->optional_metrics[i].metric_value;
        }
    }

    printf("[FB_MEDIA] seq=%"PRIu64" ts=%"PRIu64" lost=%.1f%%(%"PRIu64"/%"PRIu64")"
           " late=%.1f%% avg_delta=%"PRId64"us playout=%"PRIu64"ms entries=%"PRIu64"\n",
           report->report_sequence,
           report->report_timestamp,
           loss_rate * 100,
           report->summary_stats.objects_lost,
           report->summary_stats.total_objects_evaluated,
           late_rate * 100,
           report->summary_stats.avg_inter_arrival_delta,
           playout_ahead_ms,
           report->object_entry_count);

    g_last_objects_lost = report->summary_stats.objects_lost;
    g_last_objects_late = report->summary_stats.objects_received_late;

    if (report->summary_stats.objects_lost > 0
        || report->summary_stats.objects_received_late > 0)
    {
        g_cc_adj_count++;
    }
}

static void
fb_on_feedback_network(xqc_moq_session_t *session,
    const xqc_moq_fb_network_stats_t *stats, void *user_data)
{
    printf("[FB_NET] srtt=%"PRIu64"us min_rtt=%"PRIu64"us bw=%"PRIu64"KB/s"
           " pacing=%"PRIu64"KB/s inflight=%"PRIu64
           " loss=%.2f%% (pkts %u/%u)\n",
           stats->srtt, stats->min_rtt,
           stats->bandwidth_estimate / 1024,
           stats->pacing_rate / 1024,
           stats->inflight_bytes,
           stats->recent_loss_rate * 100,
           stats->lost_count, stats->send_count);
}


static void fb_send_callback(int fd, short what, void *arg);

void
fb_on_session_setup(xqc_moq_user_session_t *user_session, char *extdata,
    const xqc_moq_message_parameter_t *params, uint64_t params_num)
{
    fb_server_conn_t *conn = (fb_server_conn_t *)user_session->data;

    printf("[SETUP] session established");
    if (params && params_num > 0) {
        printf(", params_num=%"PRIu64, params_num);
        for (uint64_t i = 0; i < params_num; i++) {
            printf(" param[%"PRIu64"]=0x%"PRIx64, i, params[i].type);
            if (params[i].type == XQC_MOQ_PARAM_DELIVERY_FEEDBACK) {
                printf("[DELIVERY_FEEDBACK]");
            }
        }
    }
    printf("\n");

    xqc_moq_session_t *session = user_session->session;
    conn->moq_session = session;
    conn->video_subscribe_id = XQC_MOQ_INVALID_ID;
    conn->countdown = g_frame_num;

    xqc_moq_selection_params_t video_params;
    memset(&video_params, 0, sizeof(xqc_moq_selection_params_t));
    video_params.codec = "av01";
    video_params.mime_type = "video/mp4";
    video_params.bitrate = 1000000;
    video_params.framerate = 30;
    video_params.width = 720;
    video_params.height = 720;
    xqc_moq_track_t *video_track = xqc_moq_track_create(session, "namespace", "video",
        XQC_MOQ_TRACK_VIDEO, &video_params, XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_PUB);
    if (video_track == NULL) {
        printf("create video track error\n");
    }
    conn->video_track = video_track;
}


void
fb_on_subscribe(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg)
{
    fb_server_conn_t *conn = (fb_server_conn_t *)user_session->data;
    xqc_moq_session_t *session = user_session->session;

    printf("[SUBSCRIBE] track=%s subscribe_id=%"PRIu64"\n",
           msg->track_name, subscribe_id);

    if (strcmp(msg->track_name, "video") == 0) {
        conn->video_subscribe_id = subscribe_id;

        xqc_moq_subscribe_ok_msg_t subscribe_ok;
        memset(&subscribe_ok, 0, sizeof(subscribe_ok));
        subscribe_ok.subscribe_id = subscribe_id;
        subscribe_ok.track_alias = msg ? msg->track_alias : 0;
        subscribe_ok.expire_ms = 0;
        subscribe_ok.group_order = 0x1;
        subscribe_ok.content_exist = 1;
        subscribe_ok.largest_group_id = 0;
        subscribe_ok.largest_object_id = 0;
        xqc_int_t ret = xqc_moq_write_subscribe_ok(session, &subscribe_ok);
        if (ret < 0) {
            printf("write_subscribe_ok error\n");
        }

        conn->ev_send_timer = evtimer_new(eb, fb_send_callback, conn);
        struct timeval time = { 0, 33333 };
        event_add(conn->ev_send_timer, &time);
    }
}

void
fb_on_subscribe_ok(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info, xqc_moq_subscribe_ok_msg_t *subscribe_ok)
{
    printf("[SUBSCRIBE_OK] track=%s/%s\n",
           track_info ? track_info->track_namespace : "null",
           track_info ? track_info->track_name : "null");
}

void
fb_on_subscribe_error(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info, xqc_moq_subscribe_error_msg_t *subscribe_error)
{
    printf("[SUBSCRIBE_ERROR] code=%"PRIu64"\n", subscribe_error->error_code);
}

void fb_on_request_keyframe(xqc_moq_user_session_t *user_session, uint64_t subscribe_id, xqc_moq_track_t *track) {}
void fb_on_bitrate_change(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_track_info_t *track_info, uint64_t bitrate) {}
void fb_on_video_frame(xqc_moq_user_session_t *user_session, uint64_t subscribe_id, xqc_moq_video_frame_t *video_frame) {}
void fb_on_audio_frame(xqc_moq_user_session_t *user_session, uint64_t subscribe_id, xqc_moq_audio_frame_t *audio_frame) {}

void fb_on_datachannel(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_track_info_t *track_info) {}
void fb_on_datachannel_msg(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_track_info_t *track_info, uint8_t *msg, size_t msg_len) {}
void fb_on_publish_msg(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_publish_msg_t *publish_msg) {}
void fb_on_publish_ok_msg(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_publish_ok_msg_t *publish_ok) {}
void fb_on_publish_error_msg(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_track_info_t *track_info, xqc_moq_publish_error_msg_t *publish_error) {}
void fb_on_publish_done_msg(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_publish_done_msg_t *publish_done) {}
void fb_on_catalog(xqc_moq_user_session_t *user_session, xqc_moq_track_info_t **track_info_array, xqc_int_t array_size) {}


int
xqc_server_accept(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *user_data)
{
    xqc_moq_user_session_t *user_session = calloc(1, sizeof(xqc_moq_user_session_t) + sizeof(fb_server_conn_t));
    fb_server_conn_t *fb_conn = (fb_server_conn_t *)user_session->data;

    xqc_moq_session_callbacks_t callbacks = {
        .on_session_setup       = fb_on_session_setup,
        .on_datachannel         = fb_on_datachannel,
        .on_datachannel_msg     = fb_on_datachannel_msg,
        .on_subscribe           = fb_on_subscribe,
        .on_request_keyframe    = fb_on_request_keyframe,
        .on_bitrate_change      = fb_on_bitrate_change,
        .on_feedback_media      = fb_on_feedback_media,
        .on_feedback_network    = fb_on_feedback_network,
        .on_subscribe_ok        = fb_on_subscribe_ok,
        .on_subscribe_error     = fb_on_subscribe_error,
        .on_publish             = fb_on_publish_msg,
        .on_publish_ok          = fb_on_publish_ok_msg,
        .on_publish_error       = fb_on_publish_error_msg,
        .on_publish_done        = fb_on_publish_done_msg,
        .on_catalog             = fb_on_catalog,
        .on_video               = fb_on_video_frame,
        .on_audio               = fb_on_audio_frame,
    };

    xqc_moq_message_parameter_t setup_params[2];
    memset(setup_params, 0, sizeof(setup_params));

    setup_params[0].type = XQC_MOQ_PARAM_ROLE;
    setup_params[0].is_integer = 1;
    setup_params[0].int_value = XQC_MOQ_PUBLISHER;

    setup_params[1].type = XQC_MOQ_PARAM_DELIVERY_FEEDBACK;
    setup_params[1].is_integer = 1;
    setup_params[1].int_value = 0x07; /* bit0=output, bit1=metrics, bit2=input */

    xqc_moq_session_t *session = xqc_moq_session_create_with_params(conn, user_session,
        XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_PUBLISHER, callbacks, NULL, 1,
        setup_params, 2);
    if (session == NULL) {
        printf("create session error\n");
        free(user_session);
        return -1;
    }
    xqc_moq_configure_bitrate(session, 1000000, 8000000, 1000000);

    /* -- Level 0: nothing to do here.  Auto decision with default thresholds. -- */

    /* -- Level 1: custom thresholds --
    {
        xqc_moq_fb_decision_config_t cfg;
        xqc_moq_fb_decision_config_default(&cfg);
        cfg.loss_heavy_threshold  = 0.10;
        cfg.late_heavy_threshold  = 0.15;
        cfg.heavy_gain            = 0.7f;
        cfg.override_duration_us  = 500000;
        xqc_moq_session_set_feedback_decision_config(session, &cfg);
    }
    */

    /* -- Level 2: user decision callback --
    xqc_moq_session_set_auto_cc_feedback(session, 0);
    */

    /* -- Crosslayer safety bounds --
    xqc_moq_session_set_crosslayer_bounds(session, 30000, 0.3f, 3.0f, 10000);
    */

    xqc_conn_set_transport_user_data(conn, user_session);

    fb_conn->base.peer_addr = calloc(1, sizeof(struct sockaddr_in6));
    fb_conn->base.peer_addrlen = sizeof(struct sockaddr_in6);
    xqc_conn_get_peer_addr(conn, (struct sockaddr *)fb_conn->base.peer_addr,
                           sizeof(struct sockaddr_in6), &fb_conn->base.peer_addrlen);

    memcpy(&fb_conn->base.cid, cid, sizeof(*cid));
    fb_conn->base.fd = ctx.listen_fd;

    return 0;
}

void
xqc_server_refuse(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *user_data)
{
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    free(user_session);
}

ssize_t
xqc_server_stateless_reset(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    const struct sockaddr *local_addr, socklen_t local_addrlen, void *user_data)
{
    int fd = ctx.listen_fd;
    ssize_t res;
    do {
        set_sys_errno(0);
        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
        if (res < 0 && get_sys_errno() == EAGAIN) {
            res = XQC_SOCKET_EAGAIN;
        }
    } while ((res < 0) && (EINTR == get_sys_errno()));
    return res;
}

int
xqc_server_conn_closing_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
    xqc_int_t err_code, void *conn_user_data)
{
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)conn_user_data;
    fb_server_conn_t *fb_conn = (fb_server_conn_t *)user_session->data;
    fb_conn->closing_notified = 1;
    return XQC_OK;
}

int
xqc_server_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data, void *conn_proto_data)
{
    return 0;
}

int
xqc_server_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data, void *conn_proto_data)
{
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    fb_server_conn_t *fb_conn = (fb_server_conn_t *)user_session->data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, cid);
    printf("[CONN_CLOSE] send=%u lost=%u recv=%u srtt=%"PRIu64"\n",
           stats.send_count, stats.lost_count, stats.recv_count, stats.srtt);

    uint64_t real_cc_dispatch = xqc_moq_session_get_cc_dispatch_count(user_session->session);
    float last_gain = xqc_moq_session_get_last_dispatched_gain(user_session->session);
    uint64_t pacing_rate = xqc_moq_session_get_pacing_rate(user_session->session);
    uint8_t override_active = xqc_moq_session_get_cc_override_active(user_session->session);
    printf("[SUMMARY] objects_sent=%"PRIu64" feedback_reports=%"PRIu64
           " last_lost=%"PRIu64" last_late=%"PRIu64
           " cc_adj=%"PRIu64" cc_dispatch=%"PRIu64
           " last_gain=%.3f pacing_rate=%"PRIu64" override_active=%u\n",
           g_total_objects_sent, g_feedback_report_count,
           g_last_objects_lost, g_last_objects_late,
           g_cc_adj_count, real_cc_dispatch,
           last_gain, pacing_rate, (unsigned)override_active);

    if (fb_conn->ev_send_timer) {
        event_del(fb_conn->ev_send_timer);
        event_free(fb_conn->ev_send_timer);
        fb_conn->ev_send_timer = NULL;
    }

    free(fb_conn->base.peer_addr);
    fb_conn->base.peer_addr = NULL;

    xqc_moq_session_destroy(user_session->session);
    free(user_session);
    return 0;
}

void
xqc_server_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data)
{
}


static void
fb_send_callback(int fd, short what, void *arg)
{
    fb_server_conn_t *conn = (fb_server_conn_t *)arg;
    if (conn->closing_notified) {
        return;
    }
    if (conn->countdown-- <= 0) {
        if (conn->video_subscribe_id != XQC_MOQ_INVALID_ID) {
            xqc_moq_publish_done_msg_t publish_done;
            memset(&publish_done, 0, sizeof(publish_done));
            publish_done.subscribe_id = conn->video_subscribe_id;
            publish_done.status_code = 0x2;
            const char *reason = "stream ended";
            publish_done.reason_phrase = (char *)reason;
            publish_done.reason_phrase_len = strlen(reason);
            xqc_moq_write_publish_done(conn->moq_session, &publish_done);
        }
        xqc_conn_close(ctx.engine, &conn->base.cid);
        return;
    }

    if (conn->video_subscribe_id != XQC_MOQ_INVALID_ID) {
        uint8_t payload[4096] = {1, 2, 3, 4, 5, 6, 7, 8};
        xqc_moq_video_frame_t video_frame;
        memset(&video_frame, 0, sizeof(video_frame));
        video_frame.type = (conn->video_seq % 30 == 0) ? XQC_MOQ_VIDEO_KEY : XQC_MOQ_VIDEO_DELTA;
        video_frame.seq_num = conn->video_seq++;
        video_frame.timestamp_us = xqc_now();
        video_frame.video_len = 2048;
        video_frame.video_data = payload;

        if (g_jitter_ms > 0) {
            usleep((xqc_random() % (g_jitter_ms * 1000)));
        }

        xqc_int_t ret = xqc_moq_write_video_frame(conn->moq_session,
            conn->video_subscribe_id, conn->video_track, &video_frame);
        if (ret < 0) {
            printf("write_video_frame error\n");
            return;
        }
        g_total_objects_sent++;
    }

    struct timeval time = { 0, 33333 };
    event_add(conn->ev_send_timer, &time);
}


void
stop(int signo)
{
    event_base_loopbreak(eb);
    xqc_engine_destroy(ctx.engine);
    fflush(stdout);
    exit(0);
}

int
main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    signal(SIGINT, stop);
    signal(SIGTERM, stop);

    char c_log_level = 'd';
    int ch = 0;
    char server_addr[64] = TEST_ADDR;
    int server_port = TEST_PORT;
    xqc_cong_ctrl_callback_t cong_ctrl = xqc_bbr_cb;

    while ((ch = getopt(argc, argv, "p:l:n:j:c:")) != -1) {
        switch (ch) {
        case 'p':
            server_port = atoi(optarg);
            break;
        case 'l':
            c_log_level = optarg[0];
            break;
        case 'n':
            g_frame_num = atoi(optarg);
            break;
        case 'j':
            g_jitter_ms = atoi(optarg);
            break;
        case 'c':
            switch (*optarg) {
            case 'b': cong_ctrl = xqc_bbr_cb; break;
            case 'c': cong_ctrl = xqc_cubic_cb; break;
            default: printf("unsupported cc\n"); return -1;
            }
            break;
        default:
            break;
        }
    }
    memset(&ctx, 0, sizeof(ctx));

    xqc_app_open_log_file(&ctx, "./slog_feedback");
    xqc_platform_init_env();

    xqc_engine_ssl_config_t engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    engine_ssl_config.private_key_file = "./server.key";
    engine_ssl_config.cert_file = "./server.crt";
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    char g_session_ticket_key[2048];
    char g_session_ticket_file[] = "session_ticket.key";
    int ticket_key_len = xqc_app_read_file_data(g_session_ticket_key,
        sizeof(g_session_ticket_key), g_session_ticket_file);
    if (ticket_key_len < 0) {
        engine_ssl_config.session_ticket_key_data = NULL;
        engine_ssl_config.session_ticket_key_len = 0;
    } else {
        engine_ssl_config.session_ticket_key_data = g_session_ticket_key;
        engine_ssl_config.session_ticket_key_len = ticket_key_len;
    }

    xqc_conn_settings_t conn_settings = {
        .cong_ctrl_callback = cong_ctrl,
        .cc_params = {
            .customize_on = 1,
            .bbr_ignore_app_limit = 1,
        },
    };

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) < 0) {
        return -1;
    }
    config.cid_len = XQC_CID_LEN;
    xqc_app_set_log_level(c_log_level, &config);

    xqc_engine_callback_t callback = {
        .set_event_timer = xqc_app_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = xqc_app_write_log,
            .xqc_log_write_stat = xqc_app_write_log,
        },
    };

    xqc_transport_callbacks_t tcbs = {
        .server_accept = xqc_server_accept,
        .server_refuse = xqc_server_refuse,
        .write_socket = xqc_app_write_socket,
        .write_socket_ex = xqc_app_write_socket_ex,
        .stateless_reset = xqc_server_stateless_reset,
        .conn_closing = xqc_server_conn_closing_notify,
    };

    ctx.engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &engine_ssl_config,
                                   &callback, &tcbs, &ctx);
    if (ctx.engine == NULL) {
        printf("error create engine\n");
        return -1;
    }

    xqc_server_set_conn_settings(ctx.engine, &conn_settings);

    xqc_conn_callbacks_t conn_cbs = {
        .conn_create_notify = xqc_server_conn_create_notify,
        .conn_close_notify = xqc_server_conn_close_notify,
        .conn_handshake_finished = xqc_server_conn_handshake_finished,
    };
    xqc_moq_init_alpn(ctx.engine, &conn_cbs, XQC_MOQ_TRANSPORT_QUIC);

    ctx.listen_fd = xqc_server_create_socket(server_addr, server_port);
    if (ctx.listen_fd < 0) {
        printf("create socket error\n");
        return 0;
    }

    eb = event_base_new();
    ctx.ev_engine = event_new(eb, -1, 0, xqc_app_engine_callback, &ctx);
    ctx.ev_socket = event_new(eb, ctx.listen_fd, EV_READ | EV_PERSIST,
        xqc_server_socket_event_callback, &ctx);
    event_add(ctx.ev_socket, NULL);

    printf("[SERVER] listening on %s:%d frames=%d jitter=%dms\n",
           server_addr, server_port, g_frame_num, g_jitter_ms);

    event_base_dispatch(eb);

    xqc_engine_destroy(ctx.engine);
    return 0;
}
