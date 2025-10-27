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
#include "src/common/xqc_log.h"

#define DEBUG printf("%s:%d (%s)\n", __FILE__, __LINE__, __FUNCTION__);

#define TEST_ADDR "127.0.0.1"
#define TEST_PORT 4433

#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100*1024*1024)

#define XQC_MAX_LOG_LEN 2048

extern long xqc_random(void);
extern xqc_usec_t xqc_now();

void xqc_app_send_callback(int fd, short what, void* arg);

xqc_app_ctx_t ctx;
struct event_base *eb;

int g_ipv6 = 0;
int g_spec_local_addr = 0;
int g_frame_num = 10; // 发送帧数
xqc_moq_role_t g_role = XQC_MOQ_PUBSUB;

char* xqc_now_spec()
{
    // 生成一个时间戳
    static char now_spec[128];
    time_t now = time(NULL);
    struct tm *tm_now = localtime(&now);
    snprintf(now_spec, sizeof(now_spec), "%04d-%02d-%02d %02d:%02d:%02d",
             tm_now->tm_year + 1900, tm_now->tm_mon + 1, tm_now->tm_mday,
             tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec);
    return now_spec;
}

static int
xqc_server_create_socket(const char *addr, unsigned int port)
{
    printf("xqc_now_spec: %s\n", xqc_now_spec());
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

    if (extdata) {
        printf("extdata:%s\n",extdata);
    }

    int ret;
    xqc_moq_session_t *session = user_session->session;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;

    static int conn_record = 0;
    printf("conn_record: %d\n", ++conn_record);

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
    video_params.bitrate = 1000000;
    video_params.framerate = 30;
    video_params.width = 720;
    video_params.height = 720;
    xqc_moq_track_t *clock_track = xqc_moq_track_create(session, "moq", "date", XQC_MOQ_TRACK_VIDEO,
                                                        &video_params, XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_PUB);
    if (clock_track == NULL) {
        printf("create clock track error\n");
    }
    user_conn->video_track = clock_track;
    user_conn->clock_track = clock_track;

    user_conn->object_id = 0;
}

void on_subscribe(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
                  xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg)
{
    DEBUG;
    int ret;
    xqc_moq_session_t *session = user_session->session;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;

    if(strcmp(msg->track_name, "date") == 0) {
        xqc_moq_subscribe_ok_msg_t subscribe_ok;
        subscribe_ok.subscribe_id = subscribe_id;
        subscribe_ok.expire_ms = 0;
        subscribe_ok.content_exist = 0;
        subscribe_ok.largest_group_id = 0;
        subscribe_ok.largest_object_id = 0;
        subscribe_ok.params_num = 0;
        subscribe_ok.params = NULL;
        ret = xqc_moq_write_subscribe_ok(session, &subscribe_ok);
        if (ret < 0) {
            printf("xqc_moq_write_subscribe_ok error\n");
        }

        xqc_moq_message_parameter_t params[1];
        // test for announce
        xqc_moq_announce_msg_t announce_msg;
        announce_msg.track_namespace = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
        announce_msg.track_namespace->track_namespace_num = 1;
        announce_msg.track_namespace->track_namespace_len = xqc_calloc(1, sizeof(xqc_int_t));
        announce_msg.track_namespace->track_namespace_len[0] = strlen("moq");
        announce_msg.track_namespace->track_namespace = xqc_calloc(1, strlen("moq")+1);
        announce_msg.track_namespace->track_namespace[0] = "moq";
        announce_msg.params_num = 0;
        announce_msg.params = NULL;
        ret = xqc_moq_write_announce(session, &announce_msg);

        // test for interop
        char *buf = "hello world from xquic";
        xqc_moq_subgroup_msg_t *subgroup_msg = xqc_calloc(1, sizeof(xqc_moq_subgroup_msg_t));
        subgroup_msg->track_alias = 0; // only for test
        subgroup_msg->group_id = 0;
        subgroup_msg->subgroup_id = 0;
        subgroup_msg->publish_priority = 0;
        
        xqc_moq_subgroup_object_msg_t *subgroup_object1 = xqc_calloc(1, sizeof(xqc_moq_subgroup_object_msg_t));
        subgroup_object1->subgroup_header = subgroup_msg;
        subgroup_object1->object_id = 0;
        subgroup_object1->payload_len = strlen(buf);
        subgroup_object1->payload = xqc_calloc(1, strlen(buf)+1);
        strcpy(subgroup_object1->payload, buf);
        subgroup_object1->object_status = 0;

        xqc_moq_subgroup_object_msg_t *subgroup_object2 = xqc_calloc(1, sizeof(xqc_moq_subgroup_object_msg_t));
        subgroup_object2->subgroup_header = subgroup_msg;
        subgroup_object2->object_id = 1;
        subgroup_object2->payload_len = strlen(buf);
        subgroup_object2->payload = xqc_calloc(1, strlen(buf)+1);
        strcpy(subgroup_object2->payload, buf);
        subgroup_object2->object_status = 0;

        xqc_moq_subgroup_object_msg_t *subgroup_msg_object_array[2];
        subgroup_msg_object_array[0] = subgroup_object1;
        subgroup_msg_object_array[1] = subgroup_object2;

        ret = xqc_moq_write_subgroup(session,subgroup_msg,2,subgroup_msg_object_array);

        if(ret < 0) {
            printf("xqc_moq_write_subgroup_msg error\n");
        }

    }

    user_conn->ev_send_timer = evtimer_new(eb, xqc_app_send_callback, user_conn);
    struct timeval time = { 0,333333 };
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

void on_bitrate_change(xqc_moq_user_session_t *user_session, uint64_t bitrate)
{
    DEBUG;
    /* Configure encoder target bitrate */
}

void on_subscribe_ok(xqc_moq_user_session_t *user_session, xqc_moq_subscribe_ok_msg_t *subscribe_ok)
{
    DEBUG;
    printf("subscribe_id:%d expire_ms:%d content_exist:%d largest_group_id:%d largest_object_id:%d\n",
           (int)subscribe_ok->subscribe_id, (int)subscribe_ok->expire_ms, (int)subscribe_ok->content_exist,
           (int)subscribe_ok->largest_group_id, (int)subscribe_ok->largest_object_id);
}

void on_subscribe_error(xqc_moq_user_session_t *user_session, xqc_moq_subscribe_error_msg_t *subscribe_error)
{
    DEBUG;
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
    printf("subscribe_id:%"PRIu64", seq_num:%"PRIu64", timestamp_us:%"PRIu64", type:%d, video_len:%"PRIu64" scid:%s\n",
           subscribe_id, video_frame->seq_num, video_frame->timestamp_us, video_frame->type, video_frame->video_len,
           xqc_scid_str(ctx.engine, &user_conn->cid));

    /* Test: Request a keyframe when the decoding fails */
    if (video_frame->seq_num == 3) {
        xqc_moq_request_keyframe(session, subscribe_id);
    }
    //printf("video_data:%s\n",video_frame->video_data);
}

void on_audio_frame(xqc_moq_user_session_t *user_session, uint64_t subscribe_id, xqc_moq_audio_frame_t *audio_frame)
{
    DEBUG;
    xqc_moq_session_t *session = user_session->session;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;
    printf("subscribe_id:%"PRIu64", seq_num:%"PRIu64", timestamp_us:%"PRIu64", audio_len:%"PRIu64" scid:%s\n",
           subscribe_id, audio_frame->seq_num, audio_frame->timestamp_us, audio_frame->audio_len,
           xqc_scid_str(ctx.engine, &user_conn->cid));

    //printf("audio_data:%s\n",audio_frame->audio_data);
}

int
xqc_server_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;
    xqc_moq_user_session_t *user_session = calloc(1, sizeof(xqc_moq_user_session_t) + sizeof(user_conn_t));
    user_conn_t *user_conn = (user_conn_t *)(user_session->data);

    xqc_moq_session_callbacks_t callbacks = {
        .on_session_setup = on_session_setup,
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
        // .on_fetch = on_fetch,
        
    };
    
    xqc_moq_session_t *session = xqc_moq_session_create(conn, user_session, XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_SUPPORTED_VERSION_11, g_role, callbacks, NULL);
    if (session == NULL) {
        printf("create session error\n");
        return -1;
    }
    xqc_moq_configure_bitrate(session, 1000000, 8000000, 1000000);

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
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)conn_user_data;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;
    user_conn->closing_notified = 1;
    return XQC_OK;
}

void on_object_datagram(xqc_moq_user_session_t *user_session, xqc_moq_object_datagram_t *object_datagram)
{
    DEBUG;
    printf("recv datagram , payload:%s\n", object_datagram->payload);
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
xqc_app_send_callback(int fd, short what, void* arg)
{
    user_conn_t *user_conn = (user_conn_t *)arg;
    if (user_conn->closing_notified) {
        printf("Connection closing, stop sending\n");
        return;
    }
    
    xqc_int_t ret = 0;
    if (user_conn->countdown-- <= 0) {
        xqc_moq_write_goaway(user_conn->moq_session, 0, NULL);
        xqc_conn_close(ctx.engine, &user_conn->cid);
        return;
    }


    if(user_conn->clock_subscribe_id != -1 && user_conn->moq_session != NULL) {

        static uint64_t clock_count = 0;
        user_conn->object_id++;
        char *clock_info = xqc_now_spec();
        printf("timestamp for now: %s, count: %"PRIu64"\n", clock_info, ++clock_count);
        char buf[1024];
        // 将clock_info写入buf
        snprintf(buf, sizeof(buf), "%s", clock_info);

        xqc_moq_subgroup_msg_t *subgroup_msg = xqc_calloc(1, sizeof(xqc_moq_subgroup_msg_t));
        subgroup_msg->track_alias = 0; // only for test
        subgroup_msg->group_id = 0;
        subgroup_msg->subgroup_id = 0;
        subgroup_msg->publish_priority = 0;

        xqc_moq_subgroup_object_msg_t *subgroup_object = xqc_calloc(1, sizeof(xqc_moq_subgroup_object_msg_t));
        subgroup_object->subgroup_header = subgroup_msg;
        subgroup_object->object_id = user_conn->object_id;
        subgroup_object->payload_len = strlen(buf);
        subgroup_object->payload = xqc_calloc(1, strlen(buf)+1);
        strcpy(subgroup_object->payload, buf);
        subgroup_object->object_status = 0;

        xqc_moq_subgroup_object_msg_t *subgroup_msg_object_array[1];
        subgroup_msg_object_array[0] = subgroup_object;

        ret = xqc_moq_write_subgroup(user_conn->moq_session, subgroup_msg, 1, subgroup_msg_object_array);

        if(ret < 0) {
            printf("xqc_moq_write_subgroup_msg error\n");
            return;
        }

        // send datagram 
        ret = xqc_moq_write_object_datagram(user_conn->moq_session, 0, 0, user_conn->object_id, 0, (uint8_t*)buf, strlen(buf));
        if(ret < 0) {
            printf("xqc_moq_write_object_datagram error\n");
            return;
        }
    }



    struct timeval time = { 0,333333 };
    event_add(user_conn->ev_send_timer, &time);
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
    while ((ch = getopt(argc, argv, "p:r:c:l:n:")) != -1) {
        switch (ch) {
        /* listen port */
        case 'p':
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

        /* log level */
        case 'l':
            printf("option log level :%s\n", optarg);
            c_log_level = optarg[0];
            break;
        case 'n': /* send frame number */
            printf("option frame num :%s\n", optarg);
            g_frame_num = atoi(optarg);
            break;
        default:
            break;
        }
    }
    memset(&ctx, 0, sizeof(ctx));

    xqc_app_open_log_file(&ctx, "./rslog");
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
        .max_datagram_frame_size = 1024,
    };

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) < 0) {
        return -1;
    }
    config.cid_len = 12;

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
#ifdef XQC_MOQ_VERSION_11
    xqc_moq_init_alpn_by_custom(ctx.engine, &conn_cbs, XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_SUPPORTED_VERSION_11);
#endif
    xqc_moq_init_alpn_by_custom(ctx.engine, &conn_cbs, XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_SUPPORTED_VERSION_05);


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