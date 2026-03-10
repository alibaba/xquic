
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

#define FILE_SESSION_TICKET "fb_test_session"
#define FILE_TRANS_PARAMS   "fb_tp_localhost"
#define FILE_TOKEN          "fb_xqc_token"

extern long xqc_random(void);
extern xqc_usec_t xqc_now();

xqc_app_ctx_t ctx;
struct event_base *eb;

int g_frame_num = 100;
uint64_t g_playout_ahead_ms = 200;

static uint64_t g_video_frames_received = 0;

static uint64_t g_feedback_reports_received = 0;

typedef struct {
    user_conn_t          base;
    xqc_moq_session_t   *moq_session;
    xqc_moq_track_t     *video_track;
    uint64_t             video_subscribe_id;
    struct event         *ev_playout_timer;
    /* upload (Client→Server media for bidirectional feedback) */
    xqc_moq_track_t     *upload_track;
    uint64_t             upload_subscribe_id;
    struct event         *ev_upload_timer;
    uint64_t             upload_seq;
    int                  upload_countdown;
    uint64_t             upload_subscribe_requests;
    uint64_t             upload_timer_starts;
} fb_client_conn_t;


static void
save_session_cb(const char *data, size_t data_len, void *user_data)
{
    FILE *fp = fopen(FILE_SESSION_TICKET, "wb");
    if (fp) { fwrite(data, 1, data_len, fp); fclose(fp); }
}

static void
save_tp_cb(const char *data, size_t data_len, void *user_data)
{
    FILE *fp = fopen(FILE_TRANS_PARAMS, "wb");
    if (fp) { fwrite(data, 1, data_len, fp); fclose(fp); }
}

static void
save_token(const unsigned char *data, unsigned data_len, void *user_data)
{
    FILE *fp = fopen(FILE_TOKEN, "wb");
    if (fp) { fwrite(data, 1, data_len, fp); fclose(fp); }
}


static void
xqc_client_socket_read_handler(xqc_moq_user_session_t *user_session, int fd)
{
    fb_client_conn_t *conn = (fb_client_conn_t *)user_session->data;
    ssize_t recv_size = 0;
    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];

    do {
        recv_size = recvfrom(fd, packet_buf, sizeof(packet_buf), 0,
                             conn->base.peer_addr, &conn->base.peer_addrlen);
        if (recv_size < 0 && get_sys_errno() == EAGAIN) {
            break;
        }
        if (recv_size < 0) {
            printf("recvfrom err=%s\n", strerror(get_sys_errno()));
            break;
        }
        if (recv_size == 0) {
            break;
        }

        if (conn->base.get_local_addr == 0) {
            conn->base.get_local_addr = 1;
            socklen_t tmp = sizeof(struct sockaddr_in6);
            getsockname(conn->base.fd, (struct sockaddr *)conn->base.local_addr, &tmp);
            conn->base.local_addrlen = tmp;
        }

        uint64_t recv_time = xqc_now();
        xqc_int_t ret = xqc_engine_packet_process(ctx.engine, packet_buf, recv_size,
                                        conn->base.local_addr, conn->base.local_addrlen,
                                        conn->base.peer_addr, conn->base.peer_addrlen,
                                        (xqc_usec_t)recv_time, user_session);
        if (ret != XQC_OK) {
            printf("packet process err: %d\n", ret);
            return;
        }
    } while (recv_size > 0);

    xqc_engine_finish_recv(ctx.engine);
}

static void
xqc_client_socket_event_callback(int fd, short what, void *arg)
{
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)arg;
    fb_client_conn_t *conn = (fb_client_conn_t *)user_session->data;
    if (what & EV_WRITE) {
        xqc_conn_continue_send(ctx.engine, &conn->base.cid);
    } else if (what & EV_READ) {
        xqc_client_socket_read_handler(user_session, fd);
    }
}


static void
fb_playout_timer_callback(int fd, short what, void *arg)
{
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)arg;
    fb_client_conn_t *conn = (fb_client_conn_t *)user_session->data;
    if (conn->moq_session) {
        xqc_moq_session_report_playout_status(conn->moq_session, g_playout_ahead_ms);
    }
    struct timeval time = { 0, 200000 };
    event_add(conn->ev_playout_timer, &time);
}


static void fb_upload_send_callback(int fd, short what, void *arg);

static void
fb_on_feedback_media(xqc_moq_user_session_t *user_session,
    const xqc_moq_fb_report_t *report)
{
    g_feedback_reports_received++;

    double loss_rate = 0, late_rate = 0;
    if (report->summary_stats.total_objects_evaluated > 0) {
        loss_rate = (double)report->summary_stats.objects_lost
                  / report->summary_stats.total_objects_evaluated;
        late_rate = (double)report->summary_stats.objects_received_late
                  / report->summary_stats.total_objects_evaluated;
    }

    printf("[FB_MEDIA_RECV] seq=%"PRIu64" ts=%"PRIu64" lost=%.1f%%(%"PRIu64"/%"PRIu64")"
           " late=%.1f%% avg_delta=%"PRId64"us entries=%"PRIu64"\n",
           report->report_sequence,
           report->report_timestamp,
           loss_rate * 100,
           report->summary_stats.objects_lost,
           report->summary_stats.total_objects_evaluated,
           late_rate * 100,
           report->summary_stats.avg_inter_arrival_delta,
           report->object_entry_count);
}

static void
fb_on_feedback_network(xqc_moq_user_session_t *user_session,
    const xqc_moq_fb_network_stats_t *stats)
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

void
fb_on_session_setup(xqc_moq_user_session_t *user_session, char *extdata,
    const xqc_moq_message_parameter_t *params, uint64_t params_num)
{
    fb_client_conn_t *conn = (fb_client_conn_t *)user_session->data;
    xqc_moq_session_t *session = user_session->session;

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

    conn->moq_session = session;
    conn->video_subscribe_id = XQC_MOQ_INVALID_ID;

    xqc_moq_track_t *sub_video = xqc_moq_track_create(session,
        "namespace", "video", XQC_MOQ_TRACK_VIDEO, NULL,
        XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_SUB);
    if (sub_video == NULL) {
        printf("create subscriber video track error\n");
    } else {
        conn->video_track = sub_video;
        xqc_moq_track_set_target_latency(sub_video, 50000); /* 50ms playout deadline for 30fps */
        xqc_int_t ret = xqc_moq_subscribe_latest(session, "namespace", "video");
        if (ret < 0) {
            printf("subscribe video error\n");
        } else {
            conn->video_subscribe_id = ret;
        }
    }

    xqc_moq_session_report_playout_status(session, g_playout_ahead_ms);

    conn->ev_playout_timer = evtimer_new(eb, fb_playout_timer_callback, user_session);
    struct timeval time = { 0, 200000 };
    event_add(conn->ev_playout_timer, &time);

    /* publish an upload track so Server can subscribe and generate MRR back */
    xqc_moq_selection_params_t upload_params;
    memset(&upload_params, 0, sizeof(xqc_moq_selection_params_t));
    upload_params.codec = "av01";
    upload_params.mime_type = "video/mp4";
    upload_params.bitrate = 500000;
    upload_params.framerate = 30;
    upload_params.width = 360;
    upload_params.height = 360;
    xqc_moq_track_t *upload_track = xqc_moq_track_create(session,
        "namespace", "upload", XQC_MOQ_TRACK_VIDEO, &upload_params,
        XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_PUB);
    if (upload_track == NULL) {
        printf("create upload track error\n");
    } else {
        conn->upload_track = upload_track;
        conn->upload_subscribe_id = XQC_MOQ_INVALID_ID;
        conn->upload_countdown = g_frame_num;
    }
}


void
fb_on_video_frame(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_video_frame_t *video_frame)
{
    g_video_frames_received++;
    printf("[VIDEO] seq=%"PRIu64" ts=%"PRIu64" len=%"PRIu64"\n",
           video_frame->seq_num, video_frame->timestamp_us, video_frame->video_len);
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

void
fb_on_subscribe(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg)
{
    fb_client_conn_t *conn = (fb_client_conn_t *)user_session->data;
    xqc_moq_session_t *session = user_session->session;
    const char *track_name = (msg && msg->track_name) ? msg->track_name : "null";

    printf("[CLIENT_SUBSCRIBE] track=%s subscribe_id=%"PRIu64"\n",
           track_name, subscribe_id);

    if (msg == NULL || msg->track_name == NULL) {
        return;
    }

    if (strcmp(msg->track_name, "upload") == 0) {
        conn->upload_subscribe_requests++;

        xqc_moq_subscribe_ok_msg_t subscribe_ok;
        memset(&subscribe_ok, 0, sizeof(subscribe_ok));
        subscribe_ok.subscribe_id = subscribe_id;
        subscribe_ok.track_alias = msg->track_alias;
        subscribe_ok.expire_ms = 0;
        subscribe_ok.group_order = 0x1;
        subscribe_ok.content_exist = 1;
        subscribe_ok.largest_group_id = 0;
        subscribe_ok.largest_object_id = 0;
        xqc_int_t ret = xqc_moq_write_subscribe_ok(session, &subscribe_ok);
        if (ret < 0) {
            printf("write_subscribe_ok error\n");
            return;
        }

        conn->upload_subscribe_id = subscribe_id;
        if (conn->ev_upload_timer == NULL) {
            conn->ev_upload_timer = evtimer_new(eb, fb_upload_send_callback, user_session);
            if (conn->ev_upload_timer == NULL) {
                printf("create upload timer error\n");
                return;
            }
        }

        if (!event_pending(conn->ev_upload_timer, EV_TIMEOUT, NULL)
            && conn->upload_countdown > 0)
        {
            struct timeval time = { 0, 33333 };
            event_add(conn->ev_upload_timer, &time);
            conn->upload_timer_starts++;
        }
    }
}
void fb_on_request_keyframe(xqc_moq_user_session_t *user_session, uint64_t subscribe_id, xqc_moq_track_t *track) {}
void fb_on_bitrate_change(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_track_info_t *track_info, uint64_t bitrate) {}
void fb_on_audio_frame(xqc_moq_user_session_t *user_session, uint64_t subscribe_id, xqc_moq_audio_frame_t *audio_frame) {}
void fb_on_datachannel(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_track_info_t *track_info) {}
void fb_on_datachannel_msg(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_track_info_t *track_info, uint8_t *msg, size_t msg_len) {}
void fb_on_publish_msg(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_publish_msg_t *publish_msg) {}
void fb_on_publish_ok_msg(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_publish_ok_msg_t *publish_ok) {}
void fb_on_publish_error_msg(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_track_info_t *track_info, xqc_moq_publish_error_msg_t *publish_error) {}

void
fb_on_publish_done_msg(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_publish_done_msg_t *publish_done)
{
    printf("[PUBLISH_DONE] status=%"PRIu64"\n", publish_done->status_code);
    fb_client_conn_t *conn = (fb_client_conn_t *)user_session->data;
    xqc_conn_close(ctx.engine, &conn->base.cid);
}

void fb_on_catalog(xqc_moq_user_session_t *user_session, xqc_moq_track_info_t **track_info_array, xqc_int_t array_size) {}


static void
fb_upload_send_callback(int fd, short what, void *arg)
{
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)arg;
    fb_client_conn_t *conn = (fb_client_conn_t *)user_session->data;

    if (conn->upload_countdown-- <= 0) {
        return;
    }

    if (conn->upload_subscribe_id != XQC_MOQ_INVALID_ID && conn->upload_track) {
        uint8_t payload[1024] = {0};
        xqc_moq_video_frame_t video_frame;
        memset(&video_frame, 0, sizeof(video_frame));
        video_frame.type = (conn->upload_seq % 30 == 0) ? XQC_MOQ_VIDEO_KEY : XQC_MOQ_VIDEO_DELTA;
        video_frame.seq_num = conn->upload_seq++;
        video_frame.timestamp_us = xqc_now();
        video_frame.video_len = 512;
        video_frame.video_data = payload;

        xqc_int_t ret = xqc_moq_write_video_frame(conn->moq_session,
            conn->upload_subscribe_id, conn->upload_track, &video_frame);
        if (ret < 0) {
            printf("upload write_video_frame error\n");
            return;
        }
    }

    struct timeval time = { 0, 33333 };
    event_add(conn->ev_upload_timer, &time);
}


int
xqc_client_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data, void *conn_proto_data)
{
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    fb_client_conn_t *fb_conn = (fb_client_conn_t *)user_session->data;

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
    setup_params[0].int_value = XQC_MOQ_PUBSUB;

    setup_params[1].type = XQC_MOQ_PARAM_DELIVERY_FEEDBACK;
    setup_params[1].is_integer = 1;
    setup_params[1].int_value = 0x07; /* bit0=output, bit1=metrics, bit2=input */

    xqc_moq_session_t *session = xqc_moq_session_create_with_params(conn, user_session,
        XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_PUBSUB, callbacks, NULL, 1,
        setup_params, 2);
    if (session == NULL) {
        printf("create session error\n");
        return -1;
    }
    xqc_moq_configure_bitrate(session, 1000000, 8000000, 1000000);

    return 0;
}

int
xqc_client_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data, void *conn_proto_data)
{
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    fb_client_conn_t *fb_conn = (fb_client_conn_t *)user_session->data;

    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, cid);
    printf("[CONN_CLOSE] send=%u lost=%u recv=%u srtt=%"PRIu64"\n",
           stats.send_count, stats.lost_count, stats.recv_count, stats.srtt);

    uint64_t reports_sent = xqc_moq_session_get_feedback_reports_sent(user_session->session);
    printf("[SUMMARY] video_frames_received=%"PRIu64" feedback_reports_sent=%"PRIu64
           " feedback_reports_received=%"PRIu64
           " upload_subscribe_requests=%"PRIu64
           " upload_timer_starts=%"PRIu64
           " playout_ahead=%"PRIu64"ms\n",
           g_video_frames_received, reports_sent, g_feedback_reports_received,
           fb_conn->upload_subscribe_requests, fb_conn->upload_timer_starts,
           g_playout_ahead_ms);

    if (fb_conn->ev_playout_timer) {
        event_del(fb_conn->ev_playout_timer);
        event_free(fb_conn->ev_playout_timer);
        fb_conn->ev_playout_timer = NULL;
    }

    if (fb_conn->ev_upload_timer) {
        event_del(fb_conn->ev_upload_timer);
        event_free(fb_conn->ev_upload_timer);
        fb_conn->ev_upload_timer = NULL;
    }

    free(fb_conn->base.peer_addr);
    fb_conn->base.peer_addr = NULL;
    free(fb_conn->base.local_addr);
    fb_conn->base.local_addr = NULL;

    xqc_moq_session_destroy(user_session->session);
    free(user_session);

    event_base_loopbreak(eb);
    return 0;
}

void
xqc_client_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data)
{
}


static int
xqc_client_create_socket(const struct sockaddr *saddr, socklen_t saddr_len)
{
    int fd;
    int size;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("create socket failed, errno: %d\n", get_sys_errno());
        return -1;
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("set socket nonblock failed, errno: %d\n", errno);
        goto err;
    }

    size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    return fd;

err:
    close(fd);
    return -1;
}


int
main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    int ch = 0;
    char c_log_level = 'd';
    char server_addr[64] = TEST_ADDR;
    int server_port = TEST_PORT;
    xqc_cong_ctrl_callback_t cong_ctrl = xqc_bbr_cb;

    while ((ch = getopt(argc, argv, "a:p:l:n:P:c:")) != -1) {
        switch (ch) {
        case 'a':
            snprintf(server_addr, sizeof(server_addr), "%s", optarg);
            break;
        case 'p':
            server_port = atoi(optarg);
            break;
        case 'l':
            c_log_level = optarg[0];
            break;
        case 'n':
            g_frame_num = atoi(optarg);
            break;
        case 'P':
            g_playout_ahead_ms = (uint64_t)atoi(optarg);
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

    xqc_app_open_log_file(&ctx, "./clog_feedback");
    xqc_platform_init_env();

    xqc_engine_ssl_config_t engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    xqc_engine_callback_t callback = {
        .set_event_timer = xqc_app_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = xqc_app_write_log,
            .xqc_log_write_stat = xqc_app_write_log,
        },
    };

    xqc_transport_callbacks_t tcbs = {
        .write_socket    = xqc_app_write_socket,
        .save_token      = save_token,
        .save_session_cb = save_session_cb,
        .save_tp_cb      = save_tp_cb,
    };

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        return -1;
    }
    xqc_app_set_log_level(c_log_level, &config);
    config.cid_len = XQC_CID_LEN;

    ctx.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &config, &engine_ssl_config,
                                   &callback, &tcbs, &ctx);
    if (ctx.engine == NULL) {
        printf("error create engine\n");
        return -1;
    }

    eb = event_base_new();
    ctx.ev_engine = event_new(eb, -1, 0, xqc_app_engine_callback, &ctx);

    xqc_conn_callbacks_t conn_cbs = {
        .conn_create_notify = xqc_client_conn_create_notify,
        .conn_close_notify = xqc_client_conn_close_notify,
        .conn_handshake_finished = xqc_client_conn_handshake_finished,
    };
    xqc_moq_init_alpn(ctx.engine, &conn_cbs, XQC_MOQ_TRANSPORT_QUIC);

    xqc_moq_user_session_t *user_session = calloc(1, sizeof(xqc_moq_user_session_t) + sizeof(fb_client_conn_t));
    fb_client_conn_t *fb_conn = (fb_client_conn_t *)user_session->data;

    struct sockaddr_in *peer_v4 = calloc(1, sizeof(struct sockaddr_in));
    peer_v4->sin_family = AF_INET;
    peer_v4->sin_port = htons(server_port);
    inet_pton(AF_INET, server_addr, &peer_v4->sin_addr);
    fb_conn->base.peer_addr = (struct sockaddr *)peer_v4;
    fb_conn->base.peer_addrlen = sizeof(struct sockaddr_in);

    fb_conn->base.local_addr = calloc(1, sizeof(struct sockaddr_in));
    memset(fb_conn->base.local_addr, 0, sizeof(struct sockaddr_in));
    fb_conn->base.local_addrlen = sizeof(struct sockaddr_in);

    fb_conn->base.fd = xqc_client_create_socket(fb_conn->base.peer_addr, fb_conn->base.peer_addrlen);
    if (fb_conn->base.fd < 0) {
        printf("create socket error\n");
        return -1;
    }

    fb_conn->base.ev_socket = event_new(eb, fb_conn->base.fd, EV_READ | EV_PERSIST,
                                        xqc_client_socket_event_callback, user_session);
    event_add(fb_conn->base.ev_socket, NULL);

    xqc_conn_settings_t conn_settings = {
        .cong_ctrl_callback = cong_ctrl,
        .cc_params = {
            .customize_on = 1,
            .bbr_ignore_app_limit = 1,
        },
    };

    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));
    conn_ssl_config.cert_verify_flag |= XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;

    const xqc_cid_t *cid;
    cid = xqc_connect(ctx.engine, &conn_settings, NULL, 0,
                      server_addr, 0, &conn_ssl_config, fb_conn->base.peer_addr,
                      fb_conn->base.peer_addrlen, XQC_ALPN_MOQ_QUIC, user_session);
    if (cid == NULL) {
        printf("xqc_connect error\n");
        goto end;
    }
    memcpy(&fb_conn->base.cid, cid, sizeof(xqc_cid_t));

    printf("[CLIENT] connecting to %s:%d playout_ahead=%"PRIu64"ms\n",
           server_addr, server_port, g_playout_ahead_ms);

    event_base_dispatch(eb);

end:
    xqc_engine_destroy(ctx.engine);
    return 0;
}
