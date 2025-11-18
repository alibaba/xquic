
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
#define TEST_PORT 8443

#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100*1024*1024)

#define XQC_MAX_LOG_LEN 2048
#define XQC_CID_LEN 12

#define FILE_SESSION_TICKET "test_session"
#define FILE_TRANS_PARAMS "tp_localhost" 
#define FILE_TOKEN "xqc_token"

extern long xqc_random(void);
extern xqc_usec_t xqc_now();

void xqc_app_send_callback(int fd, short what, void* arg);

xqc_app_ctx_t ctx;
struct event_base *eb;

int g_ipv6 = 0;
int g_spec_local_addr = 0;
int g_frame_num = 5;
int g_fec_on = 0;
xqc_moq_role_t g_role = XQC_MOQ_PUBSUB;

static void
save_session_cb(const char * data, size_t data_len, void *user_data)
{
    DEBUG;
    FILE * fp  = fopen(FILE_SESSION_TICKET, "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        printf("save _session_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
}


static void
save_tp_cb(const char * data, size_t data_len, void * user_data)
{
    FILE * fp = fopen(FILE_TRANS_PARAMS, "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        printf("save _tp_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
}

static void
save_token(const unsigned char *data, unsigned data_len, void *user_data)
{
    FILE * fp  = fopen(FILE_TOKEN, "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        printf("save _session_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
}

void
xqc_client_socket_write_handler(user_conn_t *user_conn)
{
    DEBUG
    xqc_conn_continue_send(ctx.engine, &user_conn->cid);
}


void
xqc_client_socket_read_handler(user_conn_t *user_conn, int fd)
{
    //DEBUG;
    xqc_int_t ret;
    ssize_t recv_size = 0;
    ssize_t recv_sum = 0;

    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];

    static ssize_t last_rcv_sum = 0;
    static ssize_t rcv_sum = 0;

    do {
        recv_size = recvfrom(fd,
                             packet_buf, sizeof(packet_buf), 0,
                             user_conn->peer_addr, &user_conn->peer_addrlen);
        if (recv_size < 0 && get_sys_errno() == EAGAIN) {
            break;
        }

        if (recv_size < 0) {
            printf("recvfrom: recvmsg = %zd(%s)\n", recv_size, strerror(get_sys_errno()));
            break;
        }

        /* if recv_size is 0, break while loop, */
        if (recv_size == 0) {
            break;
        }

        recv_sum += recv_size;
        rcv_sum += recv_size;

        if (user_conn->get_local_addr == 0) {
            user_conn->get_local_addr = 1;
            socklen_t tmp = sizeof(struct sockaddr_in6);
            int ret = getsockname(user_conn->fd, (struct sockaddr *) user_conn->local_addr, &tmp);
            if (ret < 0) {
                printf("getsockname error, errno: %d\n", get_sys_errno());
                break;
            }
            user_conn->local_addrlen = tmp;
        }

        uint64_t recv_time = xqc_now();

        ret = xqc_engine_packet_process(ctx.engine, packet_buf, recv_size,
                                        user_conn->local_addr, user_conn->local_addrlen,
                                        user_conn->peer_addr, user_conn->peer_addrlen,
                                        (xqc_usec_t)recv_time, user_conn);
        if (ret != XQC_OK) {
            printf("xqc_client_read_handler: packet process err, ret: %d\n", ret);
            return;
        }

    } while (recv_size > 0);

finish_recv:
    // mpshell: 批量测试，无需打印
    // printf("recvfrom size:%zu\n", recv_sum);
    xqc_engine_finish_recv(ctx.engine);
}


static void
xqc_client_socket_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    user_conn_t *user_conn = (user_conn_t *) arg;

    if (what & EV_WRITE) {
        xqc_client_socket_write_handler(user_conn);

    } else if (what & EV_READ) {
        xqc_client_socket_read_handler(user_conn, fd);

    } else {
        printf("event callback: what=%d\n", what);
        exit(1);
    }
}

void
xqc_convert_addr_text_to_sockaddr(int type,
                                  const char *addr_text, unsigned int port,
                                  struct sockaddr **saddr, socklen_t *saddr_len)
{
    if (type == AF_INET6) {
        *saddr = calloc(1, sizeof(struct sockaddr_in6));
        memset(*saddr, 0, sizeof(struct sockaddr_in6));
        struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)(*saddr);
        inet_pton(type, addr_text, &(addr_v6->sin6_addr.s6_addr));
        addr_v6->sin6_family = type;
        addr_v6->sin6_port = htons(port);
        *saddr_len = sizeof(struct sockaddr_in6);

    } else {
        *saddr = calloc(1, sizeof(struct sockaddr_in));
        memset(*saddr, 0, sizeof(struct sockaddr_in));
        struct sockaddr_in *addr_v4 = (struct sockaddr_in *)(*saddr);
        inet_pton(type, addr_text, &(addr_v4->sin_addr.s_addr));
        addr_v4->sin_family = type;
        addr_v4->sin_port = htons(port);
        *saddr_len = sizeof(struct sockaddr_in);
    }
}

void
xqc_client_init_addr(user_conn_t *user_conn,
                     const char *server_addr, int server_port)
{
    int ip_type = (g_ipv6 ? AF_INET6 : AF_INET);
    xqc_convert_addr_text_to_sockaddr(ip_type,
                                      server_addr, server_port,
                                      &user_conn->peer_addr,
                                      &user_conn->peer_addrlen);

    if (ip_type == AF_INET6) {
        user_conn->local_addr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in6));
        memset(user_conn->local_addr, 0, sizeof(struct sockaddr_in6));
        user_conn->local_addrlen = sizeof(struct sockaddr_in6);

    } else {
        user_conn->local_addr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
        memset(user_conn->local_addr, 0, sizeof(struct sockaddr_in));
        user_conn->local_addrlen = sizeof(struct sockaddr_in);
    }
}

static int
xqc_client_create_socket(int type,
                         const struct sockaddr *saddr, socklen_t saddr_len, char *interface_type)
{
    int size;
    int fd = -1;
    int flags = 1;

    /* create fd & set socket option */
    fd = socket(type, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("create socket failed, errno: %d\n", get_sys_errno());
        return -1;
    }

#ifdef XQC_SYS_WINDOWS
    if (ioctlsocket(fd, FIONBIO, &flags) == SOCKET_ERROR) {
		goto err;
	}
#else
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("set socket nonblock failed, errno: %d\n", get_sys_errno());
        goto err;
    }
#endif

    size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

#if !defined(__APPLE__)
    int val = IP_PMTUDISC_DO;
    setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
#endif

    /* connect to peer addr */
#if !defined(__APPLE__)
    if (connect(fd, (struct sockaddr *)saddr, saddr_len) < 0) {
        printf("connect socket failed, errno: %d\n", get_sys_errno());
        goto err;
    }
#endif

    return fd;

err:
    close(fd);
    return -1;
}

int
xqc_client_create_conn_socket(user_conn_t *user_conn)
{
    int ip_type = (g_ipv6 ? AF_INET6 : AF_INET);
    user_conn->fd = xqc_client_create_socket(ip_type,
                                             user_conn->peer_addr, user_conn->peer_addrlen, NULL);
    if (user_conn->fd < 0) {
        printf("xqc_create_socket error\n");
        return -1;
    }

    user_conn->ev_socket = event_new(eb, user_conn->fd, EV_READ | EV_PERSIST,
                                     xqc_client_socket_event_callback, user_conn);
    event_add(user_conn->ev_socket, NULL);

    return 0;
}

void on_session_setup(xqc_moq_user_session_t *user_session, char *extdata)
{
    DEBUG;

    int ret;
    xqc_moq_session_t *session = user_session->session;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;

    user_conn->moq_session = session;
    user_conn->video_subscribe_id = -1;
    user_conn->audio_subscribe_id = -1;
    user_conn->countdown = g_frame_num;

    if (g_role == XQC_MOQ_SUBSCRIBER) {
        return;
    }

    xqc_moq_selection_params_t video_params;
    memset(&video_params, 0, sizeof(xqc_moq_selection_params_t));
    video_params.codec = "av01";
    video_params.mime_type = "video/mp4";
    video_params.width = 720;
    video_params.height = 720;
    video_params.bitrate = 1000000;
    video_params.framerate = 30;
    xqc_moq_track_t *video_track = xqc_moq_track_create(session, "namespace", "video", XQC_MOQ_TRACK_VIDEO, &video_params,
                                                        XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_PUB);
    if (video_track == NULL) {
        printf("create video track error\n");
    }
    user_conn->video_track = video_track;

    xqc_moq_selection_params_t audio_params;
    memset(&audio_params, 0, sizeof(xqc_moq_selection_params_t));
    audio_params.codec = "opus";
    audio_params.mime_type = "audio/mp4";
    audio_params.samplerate = 48000;
    audio_params.channel_config = "2";
    audio_params.bitrate = 32000;
    xqc_moq_track_t *audio_track = xqc_moq_track_create(session, "namespace", "audio", XQC_MOQ_TRACK_AUDIO, &audio_params,
                                                        XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_PUB);
    if (audio_track == NULL) {
        printf("create audio track error\n");
    }
    user_conn->audio_track = audio_track;
}

void on_datachannel(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_track_info_t *track_info)
{
    DEBUG;
    printf("on_datachannel: track_namespace:%s track_name:%s\n",
           track_info ? track_info->track_namespace : "null",
           track_info ? track_info->track_name : "null");

    xqc_int_t ret;
    xqc_moq_session_t *session = user_session->session;
    ret = xqc_moq_write_datachannel(session, (uint8_t*)"datachannel req", strlen("datachannel req"));
    if (ret < 0) {
        printf("xqc_moq_write_datachannel error\n");
    }
}

void on_datachannel_msg(struct xqc_moq_user_session_s *user_session, xqc_moq_track_t *track, xqc_moq_track_info_t *track_info, uint8_t *msg, size_t msg_len)
{
    DEBUG;
    printf("on_datachannel_msg: track_namespace:%s track_name:%s\n",
           track_info ? track_info->track_namespace : "null",
           track_info ? track_info->track_name : "null");
}

void on_subscribe(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
                  xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg)
{
    DEBUG;
    int ret;
    xqc_moq_session_t *session = user_session->session;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;

    if (strcmp(msg->track_name, "video") == 0) {
        user_conn->video_subscribe_id = subscribe_id;

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

    } else if (strcmp(msg->track_name, "audio") == 0) {
        user_conn->audio_subscribe_id = subscribe_id;

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

    user_conn->ev_send_timer = evtimer_new(eb, xqc_app_send_callback, user_conn);
    struct timeval time = { 0, 10000 };
    event_add(user_conn->ev_send_timer, &time);
}

void on_request_keyframe(xqc_moq_user_session_t *user_session, uint64_t subscribe_id, xqc_moq_track_t *track)
{
    DEBUG;
    int ret;
    xqc_moq_session_t *session = user_session->session;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;
    user_conn->request_keyframe = 1;
}

void on_bitrate_change(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track, xqc_moq_track_info_t *track_info, uint64_t bitrate)
{
    DEBUG;
    printf("on_bitrate_change: track_namespace:%s track_name:%s bitrate:%ld\n",track_info->track_namespace, track_info->track_name, bitrate);
    /* Configure encoder target bitrate */
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
    
        if (g_role == XQC_MOQ_PUBLISHER) {
            continue;
        }
        //subscribe media
        ret = xqc_moq_subscribe_latest(session, track_info->track_namespace, track_info->track_name);
        if (ret < 0) {
            printf("xqc_moq_subscribe error\n");
        }
    }
}

void on_video_frame(xqc_moq_user_session_t *user_session, uint64_t subscribe_id, xqc_moq_video_frame_t *video_frame)
{
    DEBUG;
    xqc_moq_session_t *session = user_session->session;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;
    printf("subscribe_id:%"PRIu64", seq_num:%"PRIu64", timestamp_us:%"PRIu64", type:%d, video_len:%"PRIu64", delay:%d, dcid:%s\n",
            subscribe_id, video_frame->seq_num, video_frame->timestamp_us, video_frame->type, video_frame->video_len,
            (int)(xqc_now() - video_frame->timestamp_us),xqc_dcid_str_by_scid(ctx.engine, &user_conn->cid));

    /* Test: Request a keyframe when the decoding fails */
    if (video_frame->seq_num == 3) {
        xqc_moq_request_keyframe(session, subscribe_id);
    }
}

void on_audio_frame(xqc_moq_user_session_t *user_session, uint64_t subscribe_id, xqc_moq_audio_frame_t *audio_frame)
{
    DEBUG;
    xqc_moq_session_t *session = user_session->session;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;
    printf("subscribe_id:%"PRIu64", seq_num:%"PRIu64", timestamp_us:%"PRIu64", audio_len:%"PRIu64", dcid:%s\n",
            subscribe_id, audio_frame->seq_num, audio_frame->timestamp_us, audio_frame->audio_len,
            xqc_dcid_str_by_scid(ctx.engine, &user_conn->cid));
    if (audio_frame->ext_headers && audio_frame->ext_headers_len > 0) {
        printf("audio ext headers: raw_len=%"PRIu64", data=", audio_frame->ext_headers_len);
        for (uint64_t i = 0; i < audio_frame->ext_headers_len; i++) {
            if (audio_frame->ext_headers[i] >= 32 && audio_frame->ext_headers[i] <= 126) {
                printf("%c", audio_frame->ext_headers[i]);
            } else {
                printf("\\x%02x", audio_frame->ext_headers[i]);
            }
        }
        printf("\n");
    }
    //printf("audio_data:%s\n",audio_frame->audio_data);
}

int
xqc_client_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    DEBUG;
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;

    xqc_moq_session_callbacks_t callbacks = {
        .on_session_setup = on_session_setup,
        .on_datachannel = on_datachannel,
        .on_datachannel_msg = on_datachannel_msg,
        /* For Publisher */
        .on_subscribe = on_subscribe,
        .on_request_keyframe = on_request_keyframe,
        .on_bitrate_change = on_bitrate_change,
        /* For Subscriber */
        .on_subscribe_ok = on_subscribe_ok,
        .on_subscribe_error = on_subscribe_error,
        .on_catalog = on_catalog,
        .on_video = on_video_frame,
        .on_audio = on_audio_frame,
    };
    xqc_moq_session_t *session = xqc_moq_session_create(conn, user_session, XQC_MOQ_TRANSPORT_QUIC, g_role, callbacks, "extdata");
    if (session == NULL) {
        printf("create session error\n");
        return -1;
    }
    xqc_moq_configure_bitrate(session, 1000000, 8000000, 1000000);
    return 0;
}

#define XQC_CACHE_SESSION_INVALID_ERR  (0x150)
int
xqc_client_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    DEBUG;
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, cid);
    printf("send_count:%u, lost_count:%u, lost_dgram_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, ack_info:%s, alpn:%s, fec_recovered:%d\n",
            stats.send_count, stats.lost_count, stats.lost_dgram_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info, stats.alpn,
            stats.fec_recover_pkt_cnt);

    xqc_int_t err = xqc_conn_get_errno(conn);
    if (xqc_conn_should_clear_0rtt_ticket(err) || err == XQC_CACHE_SESSION_INVALID_ERR) {
        printf("should_clear_0rtt_ticket, conn_err:%d, clear_0rtt_ticket:%d\n", err,
               xqc_conn_should_clear_0rtt_ticket(err));
        xqc_app_delete_file(FILE_SESSION_TICKET);
        xqc_app_delete_file(FILE_TRANS_PARAMS);
        xqc_app_delete_file(FILE_TOKEN);
    }
    
    xqc_moq_session_destroy(user_session->session);
    free(user_session);
    
    event_base_loopbreak(eb);

    return 0;
}

void
xqc_client_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data)
{
    DEBUG;
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;
}

void
xqc_app_send_callback(int fd, short what, void* arg)
{
    user_conn_t *user_conn = (user_conn_t *)arg;
    if (user_conn->countdown-- <= 0) {
        xqc_conn_close(ctx.engine, &user_conn->cid);
        return;
    }

    xqc_int_t ret;
    if (user_conn->video_subscribe_id != -1) {
        uint8_t payload_video[102400] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        xqc_moq_video_frame_t video_frame;
        if (user_conn->request_keyframe || user_conn->video_seq % 10 == 0) {
            video_frame.type = XQC_MOQ_VIDEO_KEY;
            user_conn->request_keyframe = 0;
        } else {
            video_frame.type = XQC_MOQ_VIDEO_DELTA;
        }
        video_frame.seq_num = user_conn->video_seq++;
        video_frame.timestamp_us = xqc_now();
        uint64_t bitrate = xqc_moq_target_bitrate(user_conn->moq_session);
        video_frame.video_len = bitrate / 8 / 30;
        video_frame.video_data = payload_video;
        ret = xqc_moq_write_video_frame(user_conn->moq_session, user_conn->video_subscribe_id, user_conn->video_track, &video_frame);
        if (ret < 0) {
            printf("xqc_moq_write_video_frame error\n");
            return;
        }
    }

    if (user_conn->audio_subscribe_id != -1) {
        uint8_t payload_audio[1024] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        xqc_moq_audio_frame_t audio_frame;
        audio_frame.seq_num = user_conn->audio_seq++;
        audio_frame.timestamp_us = xqc_now();
        audio_frame.audio_len = 1024;
        audio_frame.audio_data = payload_audio;

        static uint8_t test_ext_data[] = "X test_ext_data";
        test_ext_data[0] = '0' + (user_conn->countdown % 10);
        audio_frame.ext_headers = test_ext_data;
        audio_frame.ext_headers_len = sizeof(test_ext_data) - 1;
        ret = xqc_moq_write_audio_frame(user_conn->moq_session, user_conn->audio_subscribe_id, user_conn->audio_track, &audio_frame);
        if (ret < 0) {
            printf("xqc_moq_write_audio_frame error\n");
            return;
        }
    }

    struct timeval time = { 0, 33333 };
    event_add(user_conn->ev_send_timer, &time);
}

int main(int argc, char *argv[])
{
    int ret;
    char c_log_level = 'd';
    int ch = 0;
    char server_addr[64] = TEST_ADDR;
    int server_port = TEST_PORT;
    xqc_cong_ctrl_callback_t cong_ctrl;
    cong_ctrl = xqc_bbr_cb;
    char proxy_pass_addr[64];
    uint16_t proxy_pass_port = 0;
    uint8_t secret_key[16] = {0};
    int use_proxy = 0;
    int use_1rtt = 0;
    while ((ch = getopt(argc, argv, "a:p:r:c:l:A:P:k:n:f1")) != -1) {
        switch (ch) {
            case 'a':
                printf("option addr :%s\n", optarg);
                snprintf(server_addr, sizeof(server_addr), optarg);
                g_spec_local_addr = 1;
                break;
            case 'p': /* Server port. */
                printf("option port :%s\n", optarg);
                server_port = atoi(optarg);
                break;
            case 'r':
                printf("option role :%s\n", optarg);
                if (strcmp(optarg, "pub") == 0) {
                    g_role = XQC_MOQ_PUBLISHER;
                } else if (strcmp(optarg, "sub") == 0) {
                    g_role = XQC_MOQ_SUBSCRIBER;
                } else {
                    printf("illegal role");
                    exit(0);
                }
                break;
            case 'c': /* congestion control */
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
                        printf("unsupported cong_ctl\n");
                        return -1;
                }
                break;
            case 'l': /* Log level. e:error d:debug. */
                printf("option log level :%s\n", optarg);
                c_log_level = optarg[0];
                break;
            case 'A':
                printf("option proxy_pass_addr :%s\n", optarg);
                snprintf(proxy_pass_addr, sizeof(proxy_pass_addr), optarg);
                use_proxy = 1;
                break;
            case 'P':
                printf("option proxy_pass_port :%s\n", optarg);
                proxy_pass_port = (uint16_t)atoi(optarg);
                break;
            case 'k':
                //printf("option secret key :%s\n", optarg);
                if (strlen(optarg) != 16) {
                    printf("secret key must be 16 bytes\n");
                    return -1;
                }
                memcpy(secret_key, optarg, sizeof(secret_key));
                break;
            case 'n': /* send frame number */
                printf("option frame num :%s\n", optarg);
                g_frame_num = atoi(optarg);
                break;
            case 'f':
                printf("option open fec: on\n");
                g_fec_on = 1;
                break;
            case '1': /* Force 1RTT. */
                printf("option 1RTT :%s\n", "on");
                use_1rtt = 1;
                break;
            default:
                printf("other option :%c\n", ch);
                //usage(argc, argv);
                exit(0);
        }
    }
    memset(&ctx, 0, sizeof(ctx));

    xqc_app_open_log_file(&ctx, "./clog");
    xqc_platform_init_env();

    xqc_engine_ssl_config_t  engine_ssl_config;
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

    xqc_moq_user_session_t *user_session = calloc(1, sizeof(xqc_moq_user_session_t) + sizeof(user_conn_t));
    user_conn_t *user_conn = (user_conn_t *)user_session->data;

    xqc_client_init_addr(user_conn, server_addr, server_port);
    ret = xqc_client_create_conn_socket(user_conn);
    if (ret < 0) {
        return -1;
    }

    xqc_conn_settings_t conn_settings = {
        .cong_ctrl_callback = cong_ctrl,
        .cc_params  =   {
            .customize_on = 1, 
            .bbr_ignore_app_limit = 1,
        },
        .fec_level = XQC_FEC_STREAM_LEVEL,
        .enable_encode_fec = g_fec_on,
        .enable_decode_fec = g_fec_on,
        .fec_params = {
            .fec_encoder_schemes[0] = XQC_PACKET_MASK_CODE,
            .fec_decoder_schemes[0] = XQC_PACKET_MASK_CODE,
            .fec_encoder_schemes_num = 1,
            .fec_decoder_schemes_num = 1,
            .fec_code_rate = 0.1
        }
    };
    
#ifdef XQC_ENABLE_PROXY
    if (use_proxy) {
        uint8_t dcid[XQC_MOQ_PROXY_CID_LEN];
        config.cid_len = XQC_MOQ_PROXY_CID_LEN;
        uint32_t ip = 0;
        ip = inet_addr(proxy_pass_addr);
        if (ip == INADDR_NONE) {
            printf("invalid proxy_pass_addr\n");
            return -1;
        }
        if (xqc_moq_encode_cid_ipv4(ip, htons(proxy_pass_port), secret_key, config.cid_len, dcid) != 0) {
            printf("xqc_moq_encode_cid_ipv4 error\n");
            return -1;
        }

        conn_settings.specify_client_dcid = 1;
        memcpy(conn_settings.client_dcid, dcid, config.cid_len);
    }
#endif
    
    unsigned char token[XQC_TOKEN_MAX_KEY_LEN] = {0};
    int token_len = xqc_app_read_file_data(token, sizeof(token), FILE_TOKEN);
    if (token_len > 0) {
        user_conn->token = token;
        user_conn->token_len = token_len;
    } else {
        user_conn->token = NULL;
        user_conn->token_len = 0;
    }

    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));
    conn_ssl_config.cert_verify_flag |= XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;
    
    char session_ticket_data[8192]={0};
    char tp_data[8192] = {0};
    
    int session_len = xqc_app_read_file_data((unsigned char *)session_ticket_data, sizeof(session_ticket_data), FILE_SESSION_TICKET);
    int tp_len = xqc_app_read_file_data((unsigned char *)tp_data, sizeof(tp_data), FILE_TRANS_PARAMS);

    if (session_len < 0 || tp_len < 0 || use_1rtt) {
        printf("sessoin data read error or use_1rtt\n");
        conn_ssl_config.session_ticket_data = NULL;
        conn_ssl_config.session_ticket_len = 0;
        conn_ssl_config.transport_parameter_data = NULL;
        conn_ssl_config.transport_parameter_data_len = 0;
    } else {
        conn_ssl_config.session_ticket_data = session_ticket_data;
        conn_ssl_config.session_ticket_len = session_len;
        conn_ssl_config.transport_parameter_data = tp_data;
        conn_ssl_config.transport_parameter_data_len = tp_len;
    }

    const xqc_cid_t *cid;
    cid = xqc_connect(ctx.engine, &conn_settings, user_conn->token, user_conn->token_len,
                      server_addr, 0, &conn_ssl_config, user_conn->peer_addr,
                      user_conn->peer_addrlen, XQC_ALPN_MOQ_QUIC, user_session);
    if (cid == NULL) {
        printf("xqc_connect error, delete cache files then retry once\n");
        xqc_app_delete_file(FILE_SESSION_TICKET);
        xqc_app_delete_file(FILE_TRANS_PARAMS);
        xqc_app_delete_file(FILE_TOKEN);
        user_conn->token = NULL;
        user_conn->token_len = 0;
        conn_ssl_config.session_ticket_data = NULL;
        conn_ssl_config.session_ticket_len = 0;
        conn_ssl_config.transport_parameter_data = NULL;
        conn_ssl_config.transport_parameter_data_len = 0;
        
        cid = xqc_connect(ctx.engine, &conn_settings, user_conn->token, user_conn->token_len,
                          server_addr, 0, &conn_ssl_config, user_conn->peer_addr,
                          user_conn->peer_addrlen, XQC_ALPN_MOQ_QUIC, user_session);
    }
    if (cid == NULL) {
        printf("xqc_connect error\n");
        goto end;
    }
    memcpy(&user_conn->cid, cid, sizeof(xqc_cid_t));

    event_base_dispatch(eb);

end:
    xqc_engine_destroy(ctx.engine);
    //TODO: free other struct

    return 0;
}