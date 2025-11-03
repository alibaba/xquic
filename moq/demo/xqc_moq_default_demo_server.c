#include "moq/moq_transport/xqc_moq_session.h"
#include "src/common/xqc_malloc.h"
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
#include "src/transport/xqc_conn.h"
#include "moq/moq_transport/xqc_moq_default_track.h"
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
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_track.h"

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
int g_fec_on = 0;
int g_frame_num = 150;  /* Increased for dynamic track testing */
int g_subscribe_block = 1;
int g_start_sending_data = 0;
xqc_moq_role_t g_role = XQC_MOQ_PUBSUB;
int g_fast_rtt_mode = 1;  /* Fast RTT mode: 0RTT for client send first subgroup data */
/* g_namespace_subscribed moved to per-connection state in user_conn_t */

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
    char ts[32];
    xqc_get_timestamp(ts, sizeof(ts));

    if (extdata) {
        printf("%s extdata:%s\n", ts, extdata);
    }
    

    int ret;
    xqc_moq_session_t *session = user_session->session;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;


    user_conn->moq_session = session;
    user_conn->video_subscribe_id = -2;
    user_conn->audio_subscribe_id = -1;
    user_conn->countdown = g_frame_num;
    user_conn->stream3_message_count = 0;

    if (g_role == XQC_MOQ_SUBSCRIBER) {
        return;
    }

    /* Create multiple tracks for namespace subscription testing */
    xqc_moq_track_t *track1 = xqc_moq_track_create(session, "example/video", "stream1", XQC_MOQ_TRACK_DEFAULT,
                                                    NULL, XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_PUB);
    if (track1 == NULL) {
        printf("%s create track1 error\n", ts);
    }
    
    xqc_moq_track_t *track2 = xqc_moq_track_create(session, "example/video", "stream2", XQC_MOQ_TRACK_DEFAULT,
                                                    NULL, XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_PUB);
    if (track2 == NULL) {
        printf("%s create track2 error\n", ts);
    }
    
    xqc_moq_track_t *track3 = xqc_moq_track_create(session, "example/audio", "mic", XQC_MOQ_TRACK_AUDIO,
                                                    NULL, XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_PUB);
    if (track3 == NULL) {
        printf("%s create track3 error\n", ts);
    } else {
        user_conn->audio_track = track3;
        user_conn->audio_track_alias = track3->track_alias;
    }
    
    /* Keep one as default track for sending data */
    user_conn->default_track = track1;
    
    printf("\n%s [SERVER] Created initial tracks for namespace subscription test:\n", ts);
    printf("  - example/video/stream1 (alias=%llu)\n", (unsigned long long)track1->track_alias);
    printf("  - example/video/stream2 (alias=%llu)\n", (unsigned long long)track2->track_alias);
    printf("  - example/audio/mic (alias=%llu)\n", (unsigned long long)track3->track_alias);
    printf("  Tracks will be auto-published when client subscribes to 'example' namespace\n\n");
    
    /* Register send timer for dynamic track creation and data sending */
    user_conn->ev_send_timer = evtimer_new(eb, xqc_app_send_callback, user_conn);
    struct timeval time = { 0, 200000 };  /* 200ms */
    event_add(user_conn->ev_send_timer, &time);
}

void on_subscribe_v05(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
                  xqc_moq_track_t *track, xqc_moq_subscribe_msg_t_v05 *msg)
{
    DEBUG;
    int ret;
    xqc_moq_session_t *session = user_session->session;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;

    if (strcmp(msg->track_name, "video") == 0) {
        
        xqc_moq_subscribe_ok_msg_t subscribe_ok;
        subscribe_ok.subscribe_id = subscribe_id;
        subscribe_ok.expire_ms = 0;
        subscribe_ok.content_exist = 1;
        subscribe_ok.largest_group_id = 0;
        subscribe_ok.largest_object_id = 0;
        subscribe_ok.params_num = 0;
        subscribe_ok.params = NULL;
        ret = xqc_moq_write_subscribe_ok(session, &subscribe_ok);
        if (ret < 0) {
            printf("xqc_moq_write_subscribe_ok error\n");
        }
        user_conn->video_subscribe_id = subscribe_id;

    } else if (strcmp(msg->track_name, "audio") == 0) { 
        
        xqc_moq_subscribe_ok_msg_t subscribe_ok;
        subscribe_ok.subscribe_id = subscribe_id;
        subscribe_ok.expire_ms = 0;
        subscribe_ok.content_exist = 1;
        subscribe_ok.largest_group_id = 0;
        subscribe_ok.largest_object_id = 0;
        subscribe_ok.params_num = 0;
        subscribe_ok.params = NULL;
        ret = xqc_moq_write_subscribe_ok(session, &subscribe_ok);
        if (ret < 0) {
            printf("xqc_moq_write_subscribe_ok error\n");
        }
        user_conn->audio_subscribe_id = subscribe_id;
    }

    user_conn->ev_send_timer = evtimer_new(eb, xqc_app_send_callback, user_conn);
    struct timeval time = { 0, 10000 };
    event_add(user_conn->ev_send_timer, &time);
}

void on_subscribe_namespace(xqc_moq_user_session_t *user_session,
                            xqc_moq_subscribe_namespace_msg_t *subscribe_namespace)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;
    char ts[32];
    xqc_get_timestamp(ts, sizeof(ts));
    
    printf("\n%s [SERVER] SUBSCRIBE_NAMESPACE received:\n", ts);
    printf("  Request ID: %llu\n", (unsigned long long)subscribe_namespace->request_id);
    if (subscribe_namespace->track_namespace_prefix && 
        subscribe_namespace->track_namespace_prefix->track_namespace_num > 0) {
        printf("  Namespace: ");
        for (uint64_t i = 0; i < subscribe_namespace->track_namespace_prefix->track_namespace_num; i++) {
            printf("%s", subscribe_namespace->track_namespace_prefix->track_namespace[i]);
            if (i < subscribe_namespace->track_namespace_prefix->track_namespace_num - 1) {
                printf("/");
            }
        }
        printf("\n");
    }
    printf("  -> Tracks matching this namespace will be auto-published\n\n");
    
    user_conn->namespace_subscribed = 1;
    
    printf("%s [SERVER] Namespace subscribed, waiting for PUBLISH_OK from client...\n", ts);
    printf("%s [SERVER] Will create a new track 'example/video/stream3' after ~200ms to test dynamic PUBLISH...\n\n", ts);

    /* Fast RTT: send first frame on track-stream (subgroup/object). Datagram path removed. */
    if (g_fast_rtt_mode && user_conn->default_track) {
        const char *fast_msg = "test fast rtt";
        xqc_moq_stream_t *used_stream = xqc_moq_default_track_send_on_stream(
            user_conn->default_track, NULL, 0,
            (uint8_t *)fast_msg, strlen(fast_msg) + 1, 1);
        if (used_stream) {
            char ts2[32];
            xqc_get_timestamp(ts2, sizeof(ts2));
            printf("%s [SERVER] Sent fast-RTT subgroup on alias=%llu: '%s'\n", ts2,
                   (unsigned long long)user_conn->default_track->track_alias, fast_msg);
        }
    }
}


static void
xqc_demo_send_audio_frame_with_ext(user_conn_t *user_conn, xqc_moq_track_t *track)
{
    char ts[32];
    xqc_get_timestamp(ts, sizeof(ts));

    xqc_moq_audio_frame_t frame1;
    memset(&frame1, 0, sizeof(frame1));
    frame1.seq_num = ++user_conn->audio_seq;
    frame1.timestamp_us = xqc_now();
    static uint8_t audio_payload1[] = { 0x11, 0x22, 0x33, 0x44 };
    frame1.audio_data = audio_payload1;
    frame1.audio_len = sizeof(audio_payload1);
    static uint8_t ext_data1[] = "test_data1";
    frame1.ext_headers = ext_data1;
    frame1.ext_headers_len = sizeof(ext_data1) - 1;

    xqc_int_t ret = xqc_moq_write_audio_frame(user_conn->moq_session, 0, track, &frame1);
    if (ret >= 0) {
        printf("%s [SERVER] Sent audio frame #1 with ext_headers='%s' on track %s/%s (alias=%llu)\n",
               ts, ext_data1, track->track_info.track_namespace, track->track_info.track_name,
               (unsigned long long)track->track_alias);
    } else {
        printf("%s [SERVER] Failed to send audio frame #1: %d\n", ts, ret);
    }

    xqc_moq_audio_frame_t frame2;
    memset(&frame2, 0, sizeof(frame2));
    frame2.seq_num = ++user_conn->audio_seq;
    frame2.timestamp_us = xqc_now();
    static uint8_t audio_payload2[] = { 0x55, 0x66, 0x77, 0x88 };
    frame2.audio_data = audio_payload2;
    frame2.audio_len = sizeof(audio_payload2);
    static uint8_t ext_data2[] = "test_data2";
    frame2.ext_headers = ext_data2;
    frame2.ext_headers_len = sizeof(ext_data2) - 1;

    ret = xqc_moq_write_audio_frame(user_conn->moq_session, 0, track, &frame2);
    if (ret >= 0) {
        printf("%s [SERVER] Sent audio frame #2 with ext_headers='%s' on track %s/%s (alias=%llu)\n",
               ts, ext_data2, track->track_info.track_namespace, track->track_info.track_name,
               (unsigned long long)track->track_alias);
    } else {
        printf("%s [SERVER] Failed to send audio frame #2: %d\n", ts, ret);
    }
}


void on_publish_ok(xqc_moq_user_session_t *user_session, xqc_moq_publish_ok_msg_t *publish_ok)
{
    DEBUG;
    char ts[32];
    xqc_get_timestamp(ts, sizeof(ts));
    
    printf("\n%s [SERVER] PUBLISH_OK received for request_id=%llu\n", ts, 
           (unsigned long long)publish_ok->request_id);
    
    user_conn_t *user_conn = (user_conn_t *)user_session->data;
    xqc_moq_session_t *session = user_session->session;
    
    /* 查找对应的 track 并标记为已订阅 */
    xqc_list_head_t *pos;
    xqc_moq_track_t *track;
    xqc_list_for_each(pos, &session->track_list_for_pub) {
        track = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        if (track && track->track_info.track_name) {
            /* 根据 track name 匹配 */
            if (strcmp(track->track_info.track_name, "stream1") == 0 && !user_conn->stream1_subscribed) {
                user_conn->stream1_subscribed = 1;
                printf("  -> stream1 marked as subscribed\n\n");
                break;
            } else if (strcmp(track->track_info.track_name, "stream2") == 0 && !user_conn->stream2_subscribed) {
                user_conn->stream2_subscribed = 1;
                printf("  -> stream2 marked as subscribed\n\n");
                break;
            } else if (strcmp(track->track_info.track_name, "stream3") == 0 && !user_conn->stream3_subscribed) {
                user_conn->stream3_subscribed = 1;
                printf("  -> stream3 marked as subscribed, will send 10 messages\n\n");
                break;
            } else if (strcmp(track->track_info.track_name, "mic") == 0 && !user_conn->audio_ext_sent) {
                user_conn->audio_track = track;
                xqc_demo_send_audio_frame_with_ext(user_conn, track);
                user_conn->audio_ext_sent = 1;
                break;
            }
        }
    }
}

void on_track_status(xqc_moq_user_session_t *user_session, xqc_moq_track_status_msg_t *track_status)
{
    DEBUG;
    printf("msg report on_track_status track_name: %s\n", track_status->track_name);
    if(strcmp(track_status->track_name, "test")) {
        xqc_moq_session_t *session = user_session->session;
        const char *req_ns = "namespace";
        const char *req_name = track_status->track_name ? track_status->track_name : "track";
        if (track_status->track_namespace
            && track_status->track_namespace->track_namespace_num > 0
            && track_status->track_namespace->track_namespace
            && track_status->track_namespace->track_namespace[0]) {
            req_ns = track_status->track_namespace->track_namespace[0];
        }

        xqc_moq_track_t *track = xqc_moq_find_track_by_name(session, req_ns, req_name, XQC_MOQ_TRACK_FOR_PUB);
        if (track == NULL) {
            xqc_moq_track_status_error_msg_t track_status_error;
            track_status_error.request_id = track_status->request_id;
            track_status_error.error_code = XQC_MOQ_TRACK_STATUS_CODE_NOT_EXIST;
            track_status_error.error_reason = xqc_calloc(1, strlen("track not exist") + 1);
            track_status_error.error_reason_len = strlen("track not exist");
            strcpy(track_status_error.error_reason, "track not exist");
            xqc_int_t ret = xqc_moq_track_status_error(session, &track_status_error);
            if (ret < 0) {
                printf("xqc_moq_track_status_error error\n");
            } else {
                xqc_log(session->log, XQC_LOG_INFO, "|send track status error|");
                printf("send track status error\n");
            }
            return;
        }

        if (track->track_alias == XQC_MOQ_INVALID_ALIAS) {
            uint64_t alias;
            for (;;) {
                alias = xqc_moq_session_alloc_track_alias(session);
                if (alias == XQC_MOQ_ALIAS_DATACHANNEL
                    || alias == XQC_MOQ_ALIAS_CATALOG
                    || alias == XQC_MOQ_ALIAS_VIDEO
                    || alias == XQC_MOQ_ALIAS_AUDIO) {
                    continue;
                }
                if (xqc_moq_find_track_by_alias(session, alias, XQC_MOQ_TRACK_FOR_PUB) == NULL
                    && xqc_moq_find_track_by_alias(session, alias, XQC_MOQ_TRACK_FOR_SUB) == NULL) {
                    break;
                }
            }
            xqc_moq_track_set_alias(track, alias);
        }

        xqc_moq_track_status_ok_msg_t track_status_ok;
        track_status_ok.request_id = track_status->request_id;
        track_status_ok.track_alias = track->track_alias;
        track_status_ok.expires = 0;
        track_status_ok.group_order = track_status->group_order;
        track_status_ok.content_exists = 0;
        track_status_ok.params_num = 0;
        track_status_ok.params = NULL;

        xqc_int_t ret = 0;
        ret = xqc_moq_track_status_ok(session, &track_status_ok);
        if (ret < 0) {
            printf("xqc_moq_track_status_ok error\n");
        } else {
            printf("send track status ok\n");
        }
        g_start_sending_data = 1;
    } else {
        xqc_moq_track_status_error_msg_t track_status_error;
        track_status_error.request_id = track_status->request_id;
        track_status_error.error_code = XQC_MOQ_TRACK_STATUS_CODE_NOT_EXIST;
        track_status_error.error_reason = xqc_calloc(1, strlen("track not exist") + 1);
        track_status_error.error_reason_len = strlen("track not exist");
        strcpy(track_status_error.error_reason, "track not exist");
        
        xqc_int_t ret = 0;
        ret = xqc_moq_track_status_error(user_session->session, &track_status_error);
        if (ret < 0) {
            printf("xqc_moq_track_status_error error\n");
        }
        else {
            xqc_log(user_session->session->log, XQC_LOG_INFO, "|send track status error|");
            printf("send track status error\n");
        }
    }
}

void on_subscribe_v13(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t_v13 *msg)
{
    printf("on_subscribe_v13\n");
    DEBUG;
    int ret;
    xqc_moq_session_t *session = user_session->session;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;

    if (1) {
        
        xqc_moq_subscribe_ok_msg_t subscribe_ok;
        subscribe_ok.subscribe_id = subscribe_id;
        subscribe_ok.track_alias = track->track_alias;  // 设置正确的track_alias
        if(track->track_alias == XQC_MOQ_ALIAS_CATALOG) {
            printf("catch track alias = 1 \n");
        }
        else {
            printf("send subscribe ok & alias = %llu\n", track->track_alias);
        }
        subscribe_ok.expire_ms = 0;
        subscribe_ok.content_exist = 1;
        subscribe_ok.largest_group_id = 0;
        subscribe_ok.largest_object_id = 0;
        subscribe_ok.params_num = 0;
        subscribe_ok.params = NULL;
        ret = xqc_moq_write_subscribe_ok(session, &subscribe_ok);
        
        if (ret < 0) {
            printf("xqc_moq_write_subscribe_ok error\n");
        }
        user_conn->video_subscribe_id = subscribe_id;

        /* 标记具体流订阅状态，不立即发送 */
        if (track && track->track_info.track_name) {
            if (strcmp(track->track_info.track_name, "stream1") == 0) {
                user_conn->stream1_subscribed = 1;
                printf("stream1 subscribed (id=%llu)\n", (unsigned long long)subscribe_id);
            } else if (strcmp(track->track_info.track_name, "stream2") == 0) {
                user_conn->stream2_subscribed = 1;
                printf("stream2 subscribed (id=%llu)\n", (unsigned long long)subscribe_id);
            } else if (strcmp(track->track_info.track_name, "stream3") == 0) {
                user_conn->stream3_subscribed = 1;
                printf("stream3 subscribed (id=%llu)\n", (unsigned long long)subscribe_id);
            }
        }

        /* 不再在此处立即发送，改为由定时器在已订阅后发送 */
        {
            xqc_connection_t *qconn = xqc_moq_session_quic_conn(session);
            if (qconn) {
                qconn->remote_settings.max_datagram_frame_size = 0;
            }
        }

        /* 立即触发一次发送回调，尽快开始发送 */
        if (user_conn->ev_send_timer) {
            struct timeval t0 = {0, 10000}; /* 10ms */
            event_add(user_conn->ev_send_timer, &t0);
        }

    } 
    if (strcmp(msg->track_name, "track") == 0) {
        xqc_moq_subscribe_ok_msg_t subscribe_ok;
        subscribe_ok.subscribe_id = subscribe_id;
        subscribe_ok.track_alias = track->track_alias;
        subscribe_ok.expire_ms = 0;
        subscribe_ok.content_exist = 1;
        subscribe_ok.largest_group_id = 0;
        subscribe_ok.largest_object_id = 0;
        subscribe_ok.params_num = 0;
        subscribe_ok.params = NULL;
        ret = xqc_moq_write_subscribe_ok(session, &subscribe_ok);
        if (ret < 0) {
            printf("xqc_moq_write_subscribe_ok error\n");
        }
        user_conn->default_subscribe_id = subscribe_id;
        user_conn->default_track = track;

        user_conn->moq_session = session;
        
    }

    if (!user_conn->ev_send_timer) {
        user_conn->ev_send_timer = evtimer_new(eb, xqc_app_send_callback, user_conn);
        struct timeval time = { 0, 10000 };
        event_add(user_conn->ev_send_timer, &time);
    }
    
    /* Enable sending for priority test */
    g_start_sending_data = 1;
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
    g_subscribe_block = 0;
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

void on_goaway(xqc_moq_user_session_t *user_session, xqc_moq_goaway_msg_t *goaway)
{
    DEBUG;
    printf("moq server on goaway_msg: %s\n", goaway->new_URI);
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
        .on_subscribe_v05 = on_subscribe_v05,
        .on_subscribe_v13 = on_subscribe_v13,
        .on_publish_ok = on_publish_ok,
        .on_request_keyframe = on_request_keyframe,
        .on_bitrate_change = on_bitrate_change,
        /* For Subscriber */
        .on_subscribe_ok = on_subscribe_ok,
        .on_subscribe_error = on_subscribe_error,
        .on_video = on_video_frame,
        .on_audio = on_audio_frame,
        // .on_fetch = on_fetch,
        .on_goaway = on_goaway,
        .on_track_status = on_track_status,
        /* Namespace subscription */
        .on_subscribe_namespace = on_subscribe_namespace,
        
    };
#ifdef XQC_MOQ_VERSION_11
    printf("create session with version 13\n");
    xqc_moq_session_t *session = xqc_moq_session_create(conn, user_session, XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_SUPPORTED_VERSION_13, g_role, callbacks, NULL);
#elif XQC_MOQ_VERSION_05
    printf("create session with version 05\n");
    xqc_moq_session_t *session = xqc_moq_session_create(conn, user_session, XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_SUPPORTED_VERSION_05, g_role, callbacks, NULL);
#endif
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
    
    printf("[SERVER] Connection stats: send_count:%u, lost_count:%u, recv_count:%u, srtt:%"PRIu64", conn_err:%d\n",
            stats.send_count, stats.lost_count, stats.recv_count, stats.srtt, stats.conn_err);

    /* Cancel send timer to prevent use-after-free */
    if (user_conn->ev_send_timer) {
        event_del(user_conn->ev_send_timer);
        event_free(user_conn->ev_send_timer);
        user_conn->ev_send_timer = NULL;
    }

    xqc_moq_session_destroy(user_session->session);
    free(user_session);

    return 0;
}

void
xqc_server_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data)
{
    DEBUG;
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    user_conn_t *user_conn = (user_conn_t *) user_session->data;
    
    if (user_session && user_session->session && conn && conn->alpn) {
        printf("[Server Handshake Complete] ALPN negotiated: '%s'\n", conn->alpn);
    }
}

static double frame_size_factors[] = {1.368152866,0.00366879,0.00366879,0.003363057,0.001078988,0.001078988,0.027531634,0.000603985,0.000603985,0.000603985,0.000833977,0.000833977,0.000833977,0.000833977,0.000833977,0.000833977,0.000833977,0.841621703,0.127389974,0.086247113,0.074849428,0.06539769,0.06213128,0.055945951,0.055528963,0.052262553,0.044200776,0.044339773,0.0433668,0.043575294,0.036502503,0.036757765,0.038544601,0.03784263,0.032992647,0.032482122,0.034396589,0.032992647,0.027774035,0.030057677,0.03246476,0.033575722,0.03240304,0.029317036,0.031971,0.029563917,0.029193596,0.027650594,0.030674878,0.028082635,0.028823276,0.031168639,0.031724119,0.029502197,0.030304558,0.029378757,0.030304558,0.357544405,0.339707303,0.339892463,0.41555167,0.422095318,0.429059201,0.433741811,0.447669576,0.439384957,0.449230446,0.456674596,0.460516738,0.456194328,0.462557876,0.465199349,0.467060386,0.474684637,0.476365574,0.479427281,0.484890326,0.497797522,0.494255547,0.501999865,0.504641338,0.494015414,0.502480133,0.510404551,0.515867596,0.521570776,0.513946525,0.512085488,0.515807563,0.510944852,0.5051607,0.507759446,0.517091305,0.521225673,0.519512863,0.521993484,0.519867238,0.520989423,0.512838812,0.52140286,0.528372223,0.526777538,0.509607049,0.519152179,0.512293403,0.51412241,0.508978328,0.517894737,0.522124315,0.522524411,0.51023577,0.521266968,0.524696356,0.523610383,0.516923077,0.524124792,0.51800905,0.524924982,0.516408669,0.52835437,0.52641105,0.527497023,0.52658252,0.522638724,0.52755418,0.523038819,0.527897118,0.528868778,0.538585377,0.533098357,0.540185759,0.527268397,0.541728983,0.537156466,0.531326506,0.537156466,0.543500834,0.534070017,0.532469636,0.530069064,0.531497976,0.530469159,0.536083849,0.52950929,0.532367794,0.525507384,0.538427823,0.54328728,0.542029538,0.540314435,0.548604097,0.542029538,0.537970462,0.541515007,0.54334445,0.540485946,0.53659838,0.546317294,0.547632206,0.539342544,0.541629347,0.541572177,0.551977132,0.542715579,0.537970462,4.410800628,0.207127159,0.304018838,2.176954474,1.415290424,3.52188383,0.315384615,0.25588697,0.088508634,0.240910518,0.32188383,2.148634223,1.385588697,3.488979592,0.316985871,0.116368551,0.094046064,0.302308277,0.354937968,2.932890201,0.406699755,2.907061382,0.42218316,0.369206308,2.386041328,0.409477047,2.374515565,0.426106086,0.369136875,2.375001591,0.412080759,2.369551155,0.426210234,0.375212202,2.376667967,0.418711545,2.364690893,2.352644387,0.323207402,0.09164281,0.081922545,0.070878508,0.307909251,1.726765367,0.357607415,1.688981147,1.695826936,0.373291928,0.09506618,0.081920756,0.076814997,0.314194676,1.715230116,1.672326502,1.679566011,0.377788044,0.119909125,0.099371782,0.290075681,0.393829271,2.559128211,1.668287618,1.69564534,0.392686191,0.321777109,0.105277697,0.305920522,0.332515465,1.738427987,1.727766405,1.744368573,0.39125252,0.325237263,0.111022082,0.299232445,0.393534334,2.660831866,1.74114256,1.795057682,0.410242039,0.13211735,0.108195703,0.093290364,0.342985251,1.809597495,1.785026023,1.787137952,0.398057838,0.130452176,0.104174916,0.314189923,2.808092746,1.793067596,1.807485567,0.410770021,0.133904366,0.108073861,0.315530185,0.352245244,3.432005052,0.404068711,1.817639067,1.823771782,0.390584862,0.109007983,0.09162519,0.302858617,0.331450874,3.376491954,0.402741495,1.772287976,1.831213975,0.387526995,0.307147746,0.098934499,0.294670246,0.402218245,3.402855704,0.394812245,1.808472726,1.809237475,0.383622745,0.302921496,0.099538249,0.294992246,0.395214745,3.350032212,0.391384222,1.782264307,1.806486783,0.381862558,0.301665445,0.098204612,0.293697525,0.399033425,3.379274478,0.397718718,1.786566984,1.792383565,0.391476572,0.100178289,0.085529961,0.293454842,0.335121198,3.42457569,0.402666267,1.825669975,1.822821688,0.394731756,0.101846571,0.084273606,0.080681346,1.905178085,1.871815482,0.398410597,0.349935725,0.103225877,3.50674822,0.417197706,1.870824513,1.851789661,0.412655768,0.110327818,0.09298587,0.084851671,0.333089261,3.527888879,0.405925441,1.831433518,1.851072116,0.404338607,0.104062275,0.092605122,0.298710246,0.34231337,3.491423277,0.404132543,1.832732428,1.867516016,0.395972412,0.107524149,0.088978397,0.29743265,0.340046667,3.47072937,0.406831285,1.855185139,1.857073368,0.397390139,0.097243801,0.08156329,0.300433677,0.336351079,3.508576049,0.405148298,1.830925499,1.842460116,0.396240782,0.099337273,0.083369422,0.079259554,0.336035677,3.523499022,0.399681836,1.8157339,1.838594007,0.396885996,0.098553375,0.087205552,0.293110977,0.339118998,3.488715477,0.40778155,1.826382763,1.838881815,0.403834481,0.10192483,0.085889863,0.30306088,0.34068138,3.473585047,0.404040058,1.836579358,1.8458303,0.397256033,0.095346382,0.087616705,0.298826004,0.336487619,3.472351588,0.40804054,1.828990928,1.868678135,0.392874505,0.102205892,0.088853187,0.295449211,0.337897625,3.48645729,0.406392058,1.84106606,1.858045426,0.400910855,0.103442254,0.090666517,0.301012838,0.337815201,3.476937306,0.408905993,1.852481798,1.85713876,0.4014054,0.104060435,0.089224096,0.294995878,0.334724297,3.477637911,0.40902963,1.835378796,1.865916928,0.413324605,0.103027882,0.088596449,0.076005547,0.347023674,3.608527513,0.41073113,1.866758135,1.906412835,0.407993538,0.100888568,0.087403255,0.085811821,0.344754958,3.585083024,0.409291813,1.84761352,1.906831634,0.403386754,0.107589345,0.087989573,0.085309263,0.333070479,3.562886702,0.411134527,1.847236601,1.885640428,0.399659447,0.100846688,0.086398139,0.084385792,0.345653953,3.591439129,0.410162016,1.864388082,1.899268663,0.405833462,0.104935917,0.091277859,0.080981783,0.341619573,3.620730412,0.416129537,1.860395726,1.885778704,0.408859247,0.105272116,0.093967445,0.08278885,0.3514954,3.573190116,0.416207653,1.901363001,1.91248997,0.411402825,0.105621912,0.090996691,0.08290435,0.349867314,3.598310092,0.414437453,1.876094086,0.484491172,0.370294508,1.876769805,0.481154805,0.438753381,1.885427467,0.481957223,1.899617585,0.493275531,0.363621774,1.898772935,1.853056768,1.852643019,0.417969042,0.130910122,0.110470931,0.102609703,0.346845622,1.83849281,1.813667881,1.817019247,0.406384075,0.130496373,0.106954066,0.313952592,3.520878196,0.407501197,1.841347676,1.838616934,0.406675595,0.111926388,0.094431381,0.086933521,0.33906989,3.538406746,0.406675595,1.84380708,1.87938026,0.402093569,0.107552636,0.093806559,0.083809413,0.347442501,3.551444692,0.407342071,1.851013357,1.874798235,0.405433903,0.106500676,0.090710486,0.084020432,0.332882136,3.534634016,0.406597391,1.855804401,1.900806442,0.405683222,0.104755444,0.089754764,0.085225472,0.338416153,3.549367641,0.404740383,1.85315985,1.878714063,0.401530474,0.099507189,0.0910447,0.078663622,0.333497071,3.557163135,0.406991488,1.849199572,1.869042648,0.40303121,0.102216852,0.084416446,0.080706291,0.336373483,3.59868352,0.407741857,1.859579669,1.866791543,0.40478207,0.102550349,0.082332089,0.080039297,0.342626553,3.552369115,0.411076827,1.820954581,1.887058411,0.406357588,0.104127052,0.087694697,0.081912171,0.337965709,3.548972752,0.411141692,1.847745561,1.878114217,0.405026359,0.102920626,0.088443513,0.088393408,0.329694844,3.564474647,0.410254334,1.845537058,1.873269966,0.416244977,0.106993727,0.093462414,0.083366295,0.341089634,3.589191288,0.414443595,1.852239876,1.890487829,0.412223286,0.104228815,0.088725054,0.083767637,0.350545008,3.612045589,0.419010168,1.897959303,0.492389906,0.378549631,1.91266067,0.489042909,0.446379285,1.889019854,0.487390594,1.883427403,0.491076527,0.37266061,1.911728595,0.482094712,0.444769337,1.890290866,0.485611177,1.894569938,0.492559374,0.365754781,1.883893441,1.821478878,1.822746406,0.409616041,0.125321737,0.104918623,0.310012859,0.345670945,1.833962585,1.851163237,1.848220475,0.411047221,0.132432031,0.107077099,0.317927723,3.443617575,0.403709865,1.8025832,1.816288898,0.392234384,0.112362398,0.091479455,0.299132952,0.337817084,3.442725488,0.395843281,1.7957709,1.822655155,0.389233728,0.104171419,0.088194953,0.295889,0.334329835,3.434980551,0.399452178,1.820384388,1.815680657,0.393653613,0.10137351,0.088884293,0.292280103,0.331045333,3.44394197,0.402561368,1.813915603,1.869574418,0.40366279,0.103302774,0.084494261,0.299207635,0.33847092,3.488711634,0.401810748,1.845621345,1.852782573,0.393867547,0.096470797,0.087334058,0.297479062,0.33987024,3.528880362,0.407943064,1.836114197,1.851506722,0.40131687,0.100792228,0.087210588,0.298713757,0.337894729,3.50081164,0.405309049,1.834756033,1.846197535,0.395801901,0.103385086,0.089434091,0.302744001,0.339391958,3.461495641,0.406436885,1.844613884,1.837382347,0.400308464,0.0978096,0.087385321,0.081678187,0.329566315,3.499010815,0.403593633,1.831038848,1.840343958,0.406364488,0.099337218,0.089246343,0.08436633,0.334032767,3.52080545,0.414842477,1.824008321,1.86656369,0.413214447,0.104905218,0.091755187,0.081134008,0.341184307,3.544536996,0.410174398,1.862063547,1.882050593,0.409839185,0.101904601,0.088077085,0.084808763,0.34401183,3.590544912,0.409210662,1.883241706,1.879329853,0.408389032,0.103222441,0.088668666,0.079961639,0.342308161,3.583593773,0.411712003,1.868898246,1.89131779,0.40822078,0.102170868,0.083663177,0.085471883,0.341761343,3.58355171,0.409188227,1.870160134,1.883788524,0.411158521,0.105319318,0.092291428,0.085798563,0.347115269,3.586675083,0.417061125,1.879093943,1.889170531,0.419759458,0.104560411,0.09553786,0.086135855,0.34829579,3.61698917,0.414278469,1.874540506,1.887526235,0.412339042,0.105740932,0.088715091,0.085711385,0.352237408,3.574917786,0.424918632,1.867247477,0.491888584,0.371740344,1.935444295,0.483215911,0.438383266,1.884858083,0.482158272,1.883507263,0.493049258,0.368013992,1.895453576,0.480132043,0.441295971,1.856575292,0.485830814,1.879201525,0.492078356,0.363961533,1.881607673,1.843195906,1.816176046,0.408690707,0.12512525,0.108202071,0.307928295,0.343532377,1.817034468,1.821653597,1.805629717,0.40701474,0.127986658,0.107098385,0.307601277,3.495127177,0.407995794,1.820679222,1.811243708,0.391620261,0.107826768,0.094543166,0.306998798,0.339797815,3.4762448,0.41334961,1.8215344,1.836498951,0.396745108,0.103439899,0.08708139,0.300848982,0.338772845,3.460665267,0.402074948,1.826987236,1.854743404,0.621931034,0.190300723,0.152776877,0.130974455,0.102778284,0.423501826,0.420863031,0.517985269,0.519466436,0.529094022,2.31477447,0.481131784,0.431418092,0.419941743,2.309267881,0.490858376,0.434197119,0.418238573,2.282451794,0.564603337,0.511883595,0.507666015,2.226128783,0.569875312,0.515900337,0.509724596,2.223792955,0.56656003,0.508608237,0.500895309,2.178678865,0.548764573,0.498916987,0.497263007,2.1850596,0.55167205,0.486073447,0.483722485,3.244759763,0.558059308,0.491934658,0.480679993,0.483061874,0.480532504,3.23965746,0.557136134,0.494491791,0.48578376,0.482836004,0.473314761,3.226185253,0.550343779,0.474636351,0.477964666,0.472514456,0.4681529,3.171511008,0.54049279,0.468062152,0.468012745,0.472404178,0.464933306,3.141860452,0.527454957,0.463361825,0.456660991,0.466757745,3.103681993,0.537628865,0.469991176,0.46032049,0.458027878,3.044896029,0.535017392,0.464941389,0.459781234,0.453226046,3.05837417,0.525928366,0.460054688,0.449354309,1.943433161,0.499365504,0.444078144,1.929916115,1.936169754,0.509090462,0.324641627,0.101621673,0.446134728,3.553359213,0.417290297,1.886792845,1.874190381,0.408260718,0.094959704,0.087014392,0.079356453,0.339166013,3.598902661,0.415294565,1.889256672,1.876009874,0.405223185,0.105179501,0.090905742,0.080980157,0.348481148,3.582464859,0.413876277,1.853364078,1.879764799,0.413039488,0.097820738,0.090749863,0.081294137,0.340196928,3.581377032,0.410570957,1.853405918,0.493716136,0.374023482,1.937093909,0.490375876,0.448023091,1.923304631,0.48630761,1.919878723,0.500567951,0.369227212,1.913797737,0.489605046,0.445466784,1.879305045,0.483882252,1.862810986,0.492998505,0.368847854,1.877678203,1.869588537,1.882878749,0.42376894,0.138031924,0.108339499,0.097003458,0.347334747,1.857868589,1.805209343,1.828839774,0.402980653,0.130898277,0.111315364,0.098074859,3.577166299,0.276135051,1.849742447,1.854690929,0.408497162,0.11393879,0.096206731,0.085278834,0.09874119,2.370144653,0.54446718,0.506070765,0.500782027,2.266964789,0.565272812,0.516703667,0.499219994,2.204711665,0.544243738,0.499676608,0.493889599,3.324660925,0.56442635,0.506037146,0.500505348,0.47654752,0.470274638,3.242806068,0.548121866,0.487285382,0.480559269,0.472540182,0.470880316,3.213362635,0.532673966,0.463461926,0.458009977,0.461040766,2.093235806,0.517380537,0.457731783,0.462284727,3.137130461,0.53644821,0.46495624,0.462139975,0.451720145,3.057687803,0.525791693,0.457667573,0.455450077,0.45414738,3.728593214,0.380559458,0.44553181,0.442086339,0.438315319,1.977151404,0.48415046,0.437867795,1.982767941,1.903138044,0.500766384,0.36648986,0.108453175,0.441729724,3.598747022,0.420321969,1.921861328,0.49814769,0.374013265,1.917227405,0.485701463,0.440384473,1.892182317,1.890895643,0.492127784,0.362920357,0.107294179,0.345685527,1.878340589,1.851892667,1.845978476,0.408371816,0.126489786,0.110158654,0.094536695,3.54148046,0.412824414,1.816076221,1.840574363,0.406225531,0.106043903,0.092230747,0.305969905,0.411612566,3.405691444,0.394761433,1.752500905,1.804549451,0.388765056,0.309612891,0.102058323,0.295621346,0.402037036,3.393429238,0.394001892,1.795155128,1.818221188,0.385487037,0.306974485,0.094342985,0.296700694,0.399078823,3.38215605,0.394801408,1.794355611,1.869058158,0.391670836,0.099642046,0.084451458,0.295600631,0.334562437,3.445684171,0.404263026,1.829162649,1.849896179,0.398344991,0.099545434,0.083587146,0.297738392,0.336715797,3.459724199,0.399773482,1.810592263,1.812755407,0.395410809,0.095521054,0.086291767,0.079794017,0.405591996,3.557248741,0.405385061,1.857197473,1.837207582,0.395741905,0.103343185,0.086498701,0.080414821,0.333785658,3.512716395,0.399508116,1.840435763,1.884554239,0.400254595,0.106260442,0.090401681,0.08439991,0.344309953,3.590601393,0.404494382,1.862007884,1.872469305,0.399076116,0.109740722,0.092193877,0.082732751,0.337057812,3.540461595,0.41103798,1.840543216,1.882305542,0.399076116,0.1066148,0.087859264,0.080306976,0.335299319,3.570558896,0.41131826,1.854678997,1.885736023,0.398703945,0.102246725,0.086343529,0.084303591,0.338896681,3.522385429,0.41158308,1.829406748,1.904642814,0.410370943,0.106877012,0.093794296,0.086939454,0.344163205,3.564308637,0.407988468,1.87087018,1.879396934,0.40832285,0.108047351,0.088653165,0.086563274,0.345751522,3.5477985,0.407904872,1.86760995,1.858581623,0.405146217,0.107587575,0.087859006,0.084222596,0.33814432,3.575259665,0.414926905,1.872742827,1.896257464,0.410874045,0.100253267,0.088032398,0.085124674,0.341552219,3.562341181,0.414034615,1.86106979,1.912818849,0.412053991,0.112516277,0.091993645,0.085335379,0.341720783,3.609244034,0.408514153,1.864483205,1.890863425,0.409904804,0.103203132,0.091361531,0.086726029,0.339866582,3.60224864,0.410326213,1.859763421,0.478525256,0.367203878,1.875749825,1.894979006,1.892706849,0.427417993,0.136371502,0.107338384,0.099764527,0.354414428,1.869438278,0.393756407,1.856310259,1.889593152,0.410755508,0.110494157,0.097029523,1.951151779,0.407178964,1.862790114,1.862748037,0.409703583,0.109105617,0.102331223,3.602210514,0.285029483,1.917027345,1.911052414,0.414163744,0.11213516,0.101489683,0.090086821,0.343850227,3.568466992,0.411978575,1.852049328,1.859924715,0.402144758,0.101629993,0.091087809,0.084920839,0.33889165,3.585926184,0.40564493,1.846299046,1.861841476,0.403144807,0.10271338,0.088087661,0.083879121,0.338599969,3.535048684,0.403269813,1.840548763,1.86334155,0.406103286,0.103338411,0.090754459,0.085462532,0.340183381,3.568175311,0.405519924,1.829002534,1.867466661,0.406121236,0.10381984,0.087959632,0.083297314,0.336477854,3.53370433,0.40216659,1.82754556,1.865968059,0.402083335,0.104236119,0.094287064,0.085707707,0.333206344,3.531813006,0.405514443,1.827034435,1.856447196,0.40232011,0.103131346,0.090312526,0.084836525,0.336068798,3.531398157,0.411654202,1.841554133,1.86511753,0.398213109,0.104672611,0.090961502,0.080301951,0.332787002,3.614716451,0.405857179,1.855012689,1.87031228,0.399754064,0.105216039,0.089164009,0.086781286,0.335504143,3.556904062,0.41070623,1.844185929,1.877627658,0.412545525,0.108685618,0.090041854,0.085151002,0.346038287,3.598037389,0.410998845,1.861366617,1.889750284,0.398499999,0.104212787,0.088745987,0.08260107,0.342490958,3.605848195,0.421936696,1.864588519,0.487360113,0.366776603,1.916834334,0.478912932,0.445081972,1.894829428,0.485881857,1.857323944,0.482798636,0.365593998,1.87582327,0.48904955,1.899306434,0.487317877,0.367832501,1.874767373,0.483896769,0.44220993,1.883467969,0.481658266,1.89542073,0.500960075,0.377420051,1.881482882,0.48626198,0.446095634,1.812619264,1.795684173,1.797777572,0.405257897,0.12844724,0.105507353,0.312087284,0.340752064,1.788746756,1.799067689,1.795681133,0.400903754,0.127157124,0.10994213,0.417191476,1.82708741,1.773466937,1.810194945,0.405378846,0.324504657,0.113772163,0.402179697,1.816830316,2.672285334,0.408011262,0.351956823,0.314071479,0.406107078,3.388100134,0.394047241,1.788431853,1.779457186,0.391016291,0.312797078,0.100556163,0.291896075,0.400868482,3.366577275,0.396879741,1.763542108,1.808774433,0.379807929,0.30182804,0.097604495,0.291616863,0.394446609,3.38775749,0.393170212,1.798882355,1.80773736,0.382280948,0.310643158,0.096487648,0.291337651,0.396640416,3.361232361,0.39520447,1.778579662,1.775508332,0.383238246,0.302649232,0.093944947,0.29080104,0.401797776,3.394826957,0.398475479,1.801565482,1.806168665,0.388948893,0.301448401,0.093424588,0.293723061,0.401437527,3.399350084,0.390590028,1.803526838,1.794600667,0.388788783,0.304610587,0.090382484,0.292802424,0.401997915,3.415040932,0.396994456,1.775707606,1.804567558,0.384465794,0.300968069,0.096066414,0.292642313,0.395593487,3.451894622,0.402142589,1.822549222,1.85725625,0.391816531,0.099080984,0.085517789,0.297570764,0.331990957,3.47607071,0.405051915,1.842340833,1.833162114,0.398454711,0.102072263,0.085640718,0.302283052,0.335883717,3.480127375,0.402060636,1.841357399,1.852175174,0.395463432,0.104530848,0.089451525,0.296300495,0.337440821,3.496640873,0.408903698,1.821278953,1.881870989,0.405309434,0.104943224,0.08694702,0.084578004,0.336233934,3.544213221,0.405392558,1.838106547,1.8995347,0.40593286,0.103696374,0.087071705,0.085118306,0.341221335,3.566240908,0.405350996,1.858471767,1.86948561,0.41017215,0.107520048,0.092142229,0.08844324,0.333324617,3.554437393,0.4089253,1.845920142,1.863292921,0.403771653,0.10087018,0.085070852,0.080432903,0.345589892,3.607488826,0.409309464,1.849873205,1.85948337,0.407136731,0.101199216,0.084184592,0.083471874,0.336444895,3.569292538,0.404991612,1.856211557,1.884552585,0.40834558,0.101499451,0.091521396,0.082507608,0.339169994,3.585098111,0.417568992,1.859817072,1.901448198,0.412202643,0.106320779,0.089299393,0.081878739,0.336696443,3.55784571,0.411511186,1.848154354,1.89076808,0.403755572,0.10604959,0.08961106,0.082866796,0.3443875,3.570090095,0.406085175,1.843817765,1.917636129,0.405033032,0.102015801,0.091157684,0.083161396,0.34005267,3.577160497,0.407894861,1.868522086,1.878664746,0.408526147,0.104793459,0.092209827,0.08488691,0.340768128,3.604768734,0.412271777,1.862167141,0.491158178,0.362064399,1.915215986,0.490025885,0.446059102,1.938868772,0.484877819,1.932430813,0.493504938,0.367796813,1.869362424,1.856659516,0.482258915,0.363041394,0.113041092,0.346128755,1.871167906,1.875603329,0.39993416,0.355745746,0.104667678,0.352802615,3.531383809,0.419997192,1.856162085,1.84729124,0.407644333,0.10276086,0.090988337,0.083775595,0.33869387,3.537158183,0.402232428,1.827052684,1.836029616,0.404250179,0.104675966,0.087339781,0.299985999,0.339723335,3.489802809,0.404044286,1.831911757,1.851759836,0.397085105,0.107970253,0.086886817,0.297309391,0.338199727,3.500797492,0.405444358,1.840229831,1.869754878,0.396261533,0.103440608,0.089481067,0.30315675,0.337046727,3.472096017,0.404785501,1.841842676,1.87059022,0.405590356,0.104282759,0.091200543,0.079659862,0.334721409,3.561320804,0.412006474,1.848717089,1.885672265,0.408215132,0.103907791,0.091575511,0.086950906,0.343970619,3.548821871,0.407840164,1.871673461,1.876339729,0.407215217,0.103949454,0.089075725,0.08203466,0.337596164,3.552279909,0.404578331,1.831100655,1.846407918,0.392831849,0.104022159,0.085949289,0.085124044,0.332986444,3.517690249,0.400326453,1.814054029,1.859566303,0.397479357,0.101340112,0.089869204,0.081658014,0.337690342,3.545501012,0.410683281,1.834850209,1.848425492,0.403297336,0.103692061,0.085701715,0.082607046,0.330717019,3.501391656,0.401151698,1.811289458,1.869634294,0.39607644,0.10092749,0.086320649,0.085908027,0.332450034,3.568255001,0.411621602,1.869155935,1.900354023,0.40662487,0.103503749,0.089410391,0.083541917,0.339700802,3.568786635,0.414314256,1.853892815};
double frame_size_factor()
{
    static int i = 0;
    double ret = frame_size_factors[i];
    i = (i + 1) % (int)(sizeof(frame_size_factors) / sizeof(double));
    printf("%d %f\n",i, ret);
    return ret;
}

void
xqc_app_send_callback(int fd, short what, void* arg)
{
    user_conn_t *user_conn = (user_conn_t *)arg;
    if (user_conn->closing_notified) {
        printf("Connection closing, stop sending\n");
        return;
    }
    
    if (user_conn->namespace_subscribed && !user_conn->new_track_created) {
        char ts[32];
        xqc_get_timestamp(ts, sizeof(ts));
        printf("\n%s [SERVER] Creating dynamic track 'example/video/stream3'...\n", ts);
        
        /* Debug: Check namespace_watch_list */
        if (xqc_list_empty(&user_conn->moq_session->namespace_watch_list)) {
            printf("%s [SERVER] WARNING: namespace_watch_list is EMPTY!\n", ts);
        } else {
            printf("%s [SERVER] namespace_watch_list is NOT empty\n", ts);
        }
        
        xqc_moq_track_t *track4 = xqc_moq_track_create(user_conn->moq_session, "example/video", "stream3", 
                                                        XQC_MOQ_TRACK_DEFAULT, NULL, XQC_MOQ_CONTAINER_LOC, 
                                                        XQC_MOQ_TRACK_FOR_PUB);
        if (track4 != NULL) {
            printf("%s [SERVER] Dynamic track created:\n", ts);
            printf("  - alias=%llu\n", (unsigned long long)track4->track_alias);
            printf("  - namespace='%s'\n", track4->track_info.track_namespace);
            printf("  - name='%s'\n", track4->track_info.track_name);
            printf("%s [SERVER] xqc_moq_namespace_notify_on_track_added should be called automatically\n", ts);
            
            /* Store for later use, wait for PUBLISH_OK to mark as subscribed */
            user_conn->dynamic_track = track4;
            printf("%s [SERVER] stream3 created, waiting for PUBLISH_OK before sending data\n\n", ts);
        } else {
            printf("%s [SERVER] Failed to create dynamic track\n\n", ts);
        }
        user_conn->new_track_created = 1;
    }
    
    if (user_conn->dynamic_track && user_conn->stream3_subscribed) {
        if (user_conn->stream3_message_count < 10) {
            char ts[32];
            xqc_get_timestamp(ts, sizeof(ts));
            char buffer[128];
            snprintf(buffer, sizeof(buffer), "Message #%d from stream3", user_conn->stream3_message_count + 1);
            
            int idx = user_conn->stream_pool.next_idx;
            uint64_t subgroup_id = idx;
            xqc_moq_stream_t *stream = user_conn->stream_pool.streams[idx];
            xqc_bool_t is_first = (stream == NULL);  

            xqc_moq_stream_t *used_stream = xqc_moq_default_track_send_on_stream(
                user_conn->dynamic_track,
                stream,
                subgroup_id,
                (uint8_t*)buffer,
                strlen(buffer) + 1,
                is_first
            );
            
            if (used_stream) {
                if (is_first) {
                    user_conn->stream_pool.streams[idx] = used_stream;
                    printf("%s [SERVER] Created new stream for subgroup %d\n", ts, idx);
                }
                
                printf("%s [SERVER] Sent on stream3: '%s' (%d/10) [subgroup=%d, stream_idx=%d]\n", 
                       ts, buffer, user_conn->stream3_message_count + 1, (int)subgroup_id, idx);
                
                user_conn->stream3_message_count++;
                
                user_conn->stream_pool.next_idx = (user_conn->stream_pool.next_idx + 1) % MAX_SUBGROUP_STREAMS;
            }
        } else if (user_conn->stream3_message_count == 10) {
            char ts[32];
            xqc_get_timestamp(ts, sizeof(ts));
            printf("%s [SERVER] All 10 messages sent on stream3 (distributed across %d streams). Sending GOAWAY...\n", 
                   ts, MAX_SUBGROUP_STREAMS);
            xqc_int_t ret = xqc_moq_write_goaway(user_conn->moq_session, 0, "");
            if (ret >= 0) {
                printf("%s [SERVER] GOAWAY sent successfully\n", ts);
            } else {
                printf("%s [SERVER] GOAWAY send failed: %d\n", ts, ret);
            }
            user_conn->stream3_message_count++;
            user_conn->countdown = 3; /* Close after 3 more cycles */
        }
    }
    
    xqc_int_t ret;
    if (user_conn->countdown-- <= 0) {
        xqc_conn_close(ctx.engine, &user_conn->cid);
        return;
    }

    struct timeval time = { 0, 200000 };  /* 200ms */
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
    while ((ch = getopt(argc, argv, "p:r:c:l:n:fd:F")) != -1) {
        switch (ch) {
        /* listen port */
        case 'p':
            printf("option port :%s\n", optarg);
            server_port = atoi(optarg);
            break;
        case 'F': /* Fast RTT mode */
            printf("Fast RTT mode enabled\n");
            g_fast_rtt_mode = 1;
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
        case 'f':
            printf("option open fec: on\n");
            g_fec_on = 1;
            break;
        case 'd': /* Drop rate ‰. */
            printf("option drop rate :%s\n", optarg);
            g_drop_rate = atoi(optarg);
            break;
        default:
            break;
        }
    }
    memset(&ctx, 0, sizeof(ctx));

    xqc_app_open_log_file(&ctx, "./default_slog");
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
        .fec_level = XQC_FEC_STREAM_LEVEL,
        .enable_encode_fec = g_fec_on,
        .enable_decode_fec = g_fec_on,
        .fec_params = {
            .fec_encoder_schemes[0] = XQC_PACKET_MASK_CODE,
            .fec_decoder_schemes[0] = XQC_PACKET_MASK_CODE,
            .fec_encoder_schemes_num = 1,
            .fec_decoder_schemes_num = 1,
            .fec_code_rate = 0.2
        }
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
    if (g_fast_rtt_mode) {
        printf("[Fast RTT] Server mode enabled\n");
    }
    xqc_moq_init_alpn_by_custom(ctx.engine, &conn_cbs, XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_SUPPORTED_VERSION_14);
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