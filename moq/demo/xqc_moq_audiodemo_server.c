
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <memory.h>
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
#else
#include "getopt.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "crypt32")
#endif

#include <moq/xqc_moq.h>

#define DEBUG printf("%s:%d (%s)\n", __FILE__, __LINE__, __FUNCTION__);

#define TEST_ADDR "127.0.0.1"
#define TEST_PORT 8080

#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100*1024*1024)

#define XQC_MAX_LOG_LEN 2048
#define XQC_CID_LEN 12

extern long xqc_random(void);
extern xqc_usec_t xqc_now();


xqc_app_ctx_t ctx;
struct event_base *eb;

int g_ipv6 = 0;
int g_spec_local_addr = 0;

static int
xqc_server_create_socket(const char *addr, unsigned int port)
{
    int fd;
    int type = g_ipv6 ? AF_INET6 : AF_INET;
    ctx.local_addrlen = g_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    struct sockaddr *saddr = (struct sockaddr *)&ctx.local_addr;
    int size;
    int optval = 1;

    fd = socket(type, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("create socket failed, errno: %d\n", get_sys_errno());
        return -1;
    }

#ifdef XQC_SYS_WINDOWS
    if (ioctlsocket(fd, FIONBIO, &optval) == SOCKET_ERROR) {
		goto err;
	}
#else
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("set socket nonblock failed, errno: %d\n", errno);
        goto err;
    }
#endif

    optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
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

    if (type == AF_INET6) {
        memset(saddr, 0, sizeof(struct sockaddr_in6));
        struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)saddr;
        addr_v6->sin6_family = type;
        addr_v6->sin6_port = htons(port);
        addr_v6->sin6_addr = in6addr_any;

    } else {
        memset(saddr, 0, sizeof(struct sockaddr_in));
        struct sockaddr_in *addr_v4 = (struct sockaddr_in *)saddr;
        addr_v4->sin_family = type;
        addr_v4->sin_port = htons(port);
        if (g_spec_local_addr) {
            addr_v4->sin_addr.s_addr = inet_addr(addr);
        } else {
            addr_v4->sin_addr.s_addr = htonl(INADDR_ANY);
        }
    }

    if (bind(fd, saddr, ctx.local_addrlen) < 0) {
        printf("bind socket failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    return fd;

err:
    close(fd);
    return -1;
}

void
xqc_server_socket_write_handler(xqc_app_ctx_t *ctx)
{
    DEBUG
}

int g_recv_total = 0;
void
xqc_server_socket_read_handler(xqc_app_ctx_t *ctx)
{
    //DEBUG;
    ssize_t recv_sum = 0;
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = g_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    ssize_t recv_size = 0;
    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];
    uint64_t recv_time;
    xqc_int_t ret;

    do {
        recv_size = recvfrom(ctx->listen_fd, packet_buf, sizeof(packet_buf), 0, (struct sockaddr *) &peer_addr,
                             &peer_addrlen);
        if (recv_size < 0 && get_sys_errno() == EAGAIN) {
            break;
        }

        if (recv_size < 0) {
            printf("!!!!!!!!!recvfrom: recvmsg = %zd err=%s\n", recv_size, strerror(get_sys_errno()));
            break;
        }

        recv_sum += recv_size;

        recv_time = xqc_now();
        //printf("xqc_server_read_handler recv_size=%zd, recv_time=%llu, now=%llu, recv_total=%d\n", recv_size, recv_time, xqc_now(), ++g_recv_total);
        /*printf("peer_ip: %s, peer_port: %d\n", inet_ntoa(ctx->peer_addr.sin_addr), ntohs(ctx->peer_addr.sin_port));
        printf("local_ip: %s, local_port: %d\n", inet_ntoa(ctx->local_addr.sin_addr), ntohs(ctx->local_addr.sin_port));*/

        ret = xqc_engine_packet_process(ctx->engine, packet_buf, recv_size,
                                        (struct sockaddr *) (&ctx->local_addr), ctx->local_addrlen,
                                        (struct sockaddr *) (&peer_addr), peer_addrlen,
                                        (xqc_usec_t) recv_time, NULL);
        if (ret != XQC_OK)
        {
            printf("xqc_server_read_handler: packet process err: %d\n", ret);
            return;
        }
    } while (recv_size > 0);

finish_recv:
    // mpshell
    // printf("recvfrom size:%zu\n", recv_sum);
    xqc_engine_finish_recv(ctx->engine);
}

static void
xqc_server_socket_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    xqc_app_ctx_t *ctx = (xqc_app_ctx_t *) arg;

    if (what & EV_WRITE) {
        xqc_server_socket_write_handler(ctx);

    } else if (what & EV_READ) {
        xqc_server_socket_read_handler(ctx);

    } else {
        printf("event callback: what=%d\n", what);
        exit(1);
    }
}

void on_session_setup(xqc_moq_user_session_t *user_session, char *extdata)
{
    DEBUG;

    int ret;
    xqc_moq_session_t *session = user_session->session;

    xqc_moq_selection_params_t audio_params;
    memset(&audio_params, 0, sizeof(xqc_moq_selection_params_t));
    audio_params.codec = "opus";
    audio_params.mime_type = "audio/mp4";
    audio_params.bitrate = 32000;
    audio_params.samplerate = 48000;
    audio_params.channel_config = "2";
    //xqc_moq_track_t *video_track = xqc_moq_track_create(session, "namespace", "video", XQC_MOQ_TRACK_VIDEO, &video_params,
    //                                                    XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_PUB);
    xqc_moq_track_t *audio_track = xqc_moq_track_create(session, "namespace", "audio", XQC_MOQ_TRACK_AUDIO, &audio_params,
                                                        XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_PUB);
    if (audio_track == NULL) {
        printf("create audio track error\n");
    }

}

void on_datachannel(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_track_info_t *track_info)
{
    DEBUG;
    printf("on_datachannel: track_namespace:%s track_name:%s\n",
           track_info ? track_info->track_namespace : "null",
           track_info ? track_info->track_name : "null");
}

void on_datachannel_msg(struct xqc_moq_user_session_s *user_session, xqc_moq_track_t *track, xqc_moq_track_info_t *track_info, uint8_t *msg, size_t msg_len)
{
    DEBUG;
    printf("on_datachannel_msg: track_namespace:%s track_name:%s\n",
           track_info ? track_info->track_namespace : "null",
           track_info ? track_info->track_name : "null");
    xqc_int_t ret;
    xqc_moq_session_t *session = user_session->session;
    if (strncmp((char*)msg, "datachannel req", strlen("datachannel req")) == 0) {
        ret = xqc_moq_write_datachannel(session, (uint8_t*)"datachannel rsp", strlen("datachannel rsp"));
        if (ret < 0) {
            printf("xqc_moq_write_datachannel error\n");
        }
    }
}

void on_subscribe(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
                  xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg)
{
    DEBUG;
    int ret;
    xqc_moq_session_t *session = user_session->session;

     if (strcmp(msg->track_name, "audio") == 0) {
        user_conn_t *user_conn = (user_conn_t *)(user_session->data);
        user_conn->audio_track = track;

        xqc_moq_subscribe_ok_msg_t subscribe_ok;
        subscribe_ok.subscribe_id = subscribe_id;
        subscribe_ok.expire_ms = 0;
        subscribe_ok.content_exist = 1;
        subscribe_ok.largest_group_id = 0;
        subscribe_ok.largest_object_id = 0;
        ret = xqc_moq_write_subscribe_ok(session, &subscribe_ok);
        if (ret < 0) {
            printf("xqc_moq_write_subscribe_ok error\n");
        }
    }
}

void on_subscribe_ok(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_track_info_t *track_info, xqc_moq_subscribe_ok_msg_t *subscribe_ok)
{
    DEBUG;
    printf("on_subscribe_ok: track_namespace:%s track_name:%s\n",
           track_info ? track_info->track_namespace : "null",
           track_info ? track_info->track_name : "null");
    printf("subscribe_id:%d expire_ms:%d content_exist:%d largest_group_id:%d largest_object_id:%d\n",
           (int)subscribe_ok->subscribe_id, (int)subscribe_ok->expire_ms, (int)subscribe_ok->content_exist,
           (int)subscribe_ok->largest_group_id, (int)subscribe_ok->largest_object_id);
}

void on_subscribe_error(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_track_info_t *track_info, xqc_moq_subscribe_error_msg_t *subscribe_error)
{
    DEBUG;
    printf("on_subscribe_error: track_namespace:%s track_name:%s\n",
           track_info ? track_info->track_namespace : "null",
           track_info ? track_info->track_name : "null");
    printf("subscribe_id:%d error_code:%d reason_phrase:%s track_alias:%d\n",
           (int)subscribe_error->subscribe_id, (int)subscribe_error->error_code, subscribe_error->reason_phrase, (int)subscribe_error->track_alias);
}

void on_catalog(xqc_moq_user_session_t *user_session, xqc_moq_track_info_t **track_info_array, xqc_int_t array_size)
{
    DEBUG;

    int ret;
    xqc_moq_session_t *session = user_session->session;

    for (int i = 0; i < array_size; i++) {
        xqc_moq_track_info_t *track_info = track_info_array[i];
        printf("track_namespace:%s track_name:%s track_type:%d codec:%s mime_type:%s bitrate:%d lang:%s framerate:%d width:%d height:%d "
               "display_width:%d display_height:%d samplerate:%d channel_config:%s\n",
               track_info->track_namespace, track_info->track_name, track_info->track_type, track_info->selection_params.codec,
               track_info->selection_params.mime_type, track_info->selection_params.bitrate,
               track_info->selection_params.lang ? track_info->selection_params.lang : "null",
               track_info->selection_params.framerate, track_info->selection_params.width, track_info->selection_params.height,
               track_info->selection_params.display_width, track_info->selection_params.display_height, track_info->selection_params.samplerate,
               track_info->selection_params.channel_config ? track_info->selection_params.channel_config : "null");
        
        //subscribe media
        if (track_info->track_type == XQC_MOQ_TRACK_AUDIO) {
            ret = xqc_moq_subscribe_latest(session, track_info->track_namespace, track_info->track_name);
            if (ret < 0) {
                printf("xqc_moq_subscribe error\n");
            }
        }
    }
}

void on_video_frame(xqc_moq_user_session_t *user_session, uint64_t subscribe_id, xqc_moq_video_frame_t *video_frame)
{
    DEBUG;
    xqc_moq_session_t *session = user_session->session;
    printf("subscribe_id:%"PRIu64", seq_num:%"PRIu64", timestamp_us:%"PRIu64", type:%d, video_len:%"PRIu64"\n",
           subscribe_id, video_frame->seq_num, video_frame->timestamp_us, video_frame->type, video_frame->video_len);

    //printf("video_data:%s\n",video_frame->video_data);
}

void on_audio_frame(xqc_moq_user_session_t *user_session, uint64_t subscribe_id, xqc_moq_audio_frame_t *audio_frame)
{
    DEBUG;
    static int audio_seq = 0;
    xqc_moq_session_t *session = user_session->session;
    user_conn_t *user_conn = (user_conn_t *)(user_session->data);
    if (!user_conn->audio_track)
    {
        return;
    }

    printf("subscribe_id:%"PRIu64", seq_num:%"PRIu64", timestamp_us:%"PRIu64", audio_len:%"PRIu64", ext_headers_len:%"PRIu64"\n",
           subscribe_id, audio_frame->seq_num, audio_frame->timestamp_us, audio_frame->audio_len, audio_frame->ext_headers_len);

    //printf("audio_data:%s\n",audio_frame->audio_data);

    xqc_int_t ret = xqc_moq_write_audio_frame(session, subscribe_id, user_conn->audio_track, audio_frame);
    if (ret < 0) {
        printf("xqc_moq_write_audio_frame error\n");
        return;
    }
}

int
xqc_server_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;
    xqc_moq_user_session_t *user_session = calloc(1, sizeof(xqc_moq_user_session_t) + sizeof(user_conn_t));
    user_conn_t *user_conn = (user_conn_t *)(user_session->data);
    user_conn->audio_track = NULL;
    xqc_moq_session_callbacks_t callbacks = {
        .on_session_setup = on_session_setup,
        .on_datachannel = on_datachannel,
        .on_datachannel_msg = on_datachannel_msg,
        .on_subscribe = on_subscribe,
        .on_subscribe_ok = on_subscribe_ok,
        .on_subscribe_error = on_subscribe_error,
        .on_catalog = on_catalog,
        .on_video = on_video_frame,
        .on_audio = on_audio_frame,
    };
    xqc_moq_session_t *session = xqc_moq_session_create(conn, user_session, XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_PUBSUB, callbacks, NULL);
    if (session == NULL) {
        printf("create session error\n");
        return -1;
    }

    xqc_conn_set_transport_user_data(conn, user_session);

    user_conn->peer_addr = calloc(1, sizeof(struct sockaddr_in6));
    user_conn->peer_addrlen = sizeof(struct sockaddr_in6);
    xqc_int_t ret = xqc_conn_get_peer_addr(conn, (struct sockaddr *)user_conn->peer_addr,
                                           sizeof(struct sockaddr_in6), &user_conn->peer_addrlen);
    if (ret != XQC_OK) {
        printf("get peer addr error, ret:%d\n",ret);
        return -1;
    }

    printf("-- server_accept user_session :%p, user_conn: %p\n", user_session, user_conn);

    memcpy(&user_conn->cid, cid, sizeof(*cid));
    user_conn->fd = ctx.listen_fd;

    return 0;
}

void
xqc_server_refuse(xqc_engine_t *engine, xqc_connection_t *conn,
                  const xqc_cid_t *cid, void *user_data)
{
    DEBUG;
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;
    printf("-- server_refuse user_session :%p, user_conn: %p\n", user_session, user_conn);

    free(user_session);
    user_conn = NULL;
}

int
xqc_server_conn_closing_notify(xqc_connection_t *conn,
                               const xqc_cid_t *cid, xqc_int_t err_code, void *conn_user_data)
{
    DEBUG;
    return XQC_OK;
}

int
xqc_server_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    DEBUG;
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;

    printf("-- user_data: %p user_conn: %p\n", user_data, user_conn);

    return 0;
}

int
xqc_server_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    DEBUG;
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, cid);
    printf("send_count:%u, lost_count:%u, lost_dgram_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, ack_info:%s, alpn:%s\n",
            stats.send_count, stats.lost_count, stats.lost_dgram_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info, stats.alpn);

    xqc_moq_session_destroy(user_session->session);
    free(user_session);

    return 0;
}

void
xqc_server_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;
}

void
stop(int signo)
{
    event_base_loopbreak(eb);
    xqc_engine_destroy(ctx.engine);
    fflush(stdout);
    exit(0);
}

int main(int argc, char *argv[])
{
    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    
    char c_log_level = 'd';
    int ch = 0;
    char server_addr[64] = TEST_ADDR;
    int server_port = TEST_PORT;
    xqc_cong_ctrl_callback_t cong_ctrl;
    cong_ctrl = xqc_bbr_cb;
    while ((ch = getopt(argc, argv, "p:c:CD:l:L:6k:rdMiPs:R:u:a:F:")) != -1) {
        switch (ch) {
        /* listen port */
        case 'p':
            printf("option port :%s\n", optarg);
            server_port = atoi(optarg);
            break;

        /* congestion control */
        case 'c':
            printf("option cong_ctl :%s\n", optarg);
            /* r:reno b:bbr c:cubic P:copa */
            switch (*optarg) {
            case 'b':
                cong_ctrl = xqc_bbr_cb;
                break;
            case 'c':
                cong_ctrl = xqc_cubic_cb;
                break;
#ifdef XQC_ENABLE_RENO
            case 'r':
                cong_ctrl = xqc_reno_cb;
                break;
#endif
#ifdef XQC_ENABLE_COPA
            case 'P':
                cong_ctrl = xqc_copa_cb;
                break;
#endif
            default:
                break;
            }
            break;

        /* log level */
        case 'l':
            printf("option log level :%s\n", optarg);
            c_log_level = optarg[0];
            break;

        default:
            break;
        }
    }
    memset(&ctx, 0, sizeof(ctx));

    xqc_app_open_log_file(&ctx, "./slog");
    xqc_platform_init_env();

    xqc_engine_ssl_config_t  engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    engine_ssl_config.private_key_file = "./server.key";
    engine_ssl_config.cert_file = "./server.crt";
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    char g_session_ticket_key[2048];
    char g_session_ticket_file[] = "session_ticket.key";
    int ticket_key_len  = xqc_app_read_file_data(g_session_ticket_key, sizeof(g_session_ticket_key), g_session_ticket_file);
    if (ticket_key_len < 0) {
        engine_ssl_config.session_ticket_key_data = NULL;
        engine_ssl_config.session_ticket_key_len = 0;
    } else {
        engine_ssl_config.session_ticket_key_data = g_session_ticket_key;
        engine_ssl_config.session_ticket_key_len = ticket_key_len;
    }


    xqc_conn_settings_t conn_settings = {
        .cong_ctrl_callback = cong_ctrl,
        .cc_params  =   {
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
        printf("xqc_create_socket error\n");
        return 0;
    }

    eb = event_base_new();
    ctx.ev_engine = event_new(eb, -1, 0, xqc_app_engine_callback, &ctx);
    ctx.ev_socket = event_new(eb, ctx.listen_fd, EV_READ | EV_PERSIST, xqc_server_socket_event_callback, &ctx);
    event_add(ctx.ev_socket, NULL);

    event_base_dispatch(eb);

    xqc_engine_destroy(ctx.engine);

    return 0;
}
