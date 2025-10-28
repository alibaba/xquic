
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_message.h"
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
#include "moq/moq_transport/xqc_moq_track.h"

#define DEBUG printf("%s:%d (%s)\n", __FILE__, __LINE__, __FUNCTION__);

#define TEST_ADDR "127.0.0.1"
#define TEST_PORT 4433

#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100*1024*1024)

#define XQC_MAX_LOG_LEN 2048
#define XQC_TLS_SPECIAL_GROUPS "X25519:P-256:P-384:P-521"
#define XQC_DEMO_MULTI_ALPN 1


extern long xqc_random(void);
extern xqc_usec_t xqc_now();

void xqc_app_send_callback(int fd, short what, void* arg);

xqc_app_ctx_t ctx;
struct event_base *eb;

int g_ipv6 = 0;
int g_spec_local_addr = 0;
int g_frame_num = 150;  /* Increased for dynamic track testing */
int g_fec_on = 0;
uint64_t g_request_id = 0;
xqc_moq_role_t g_role = XQC_MOQ_PUBSUB;
int g_fast_rtt_mode = 1;  /* Fast RTT mode: 0RTT for client send first subgroup data */

uint64_t alloc_g_request_id()
{
    g_request_id+=2;
    return g_request_id-2;
}

void
save_session_cb(const char * data, size_t data_len, void *user_data)
{
    FILE * fp  = fopen("test_session", "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        printf("save _session_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
    return;
}


void
save_tp_cb(const char * data, size_t data_len, void * user_data)
{
    FILE * fp = fopen("tp_localhost", "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        printf("save _tp_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
    return;
}

void
xqc_client_save_token(const unsigned char *token, unsigned token_len, void *user_data)
{
    int fd = open("./xqc_token", O_TRUNC | O_CREAT | O_WRONLY, 0666);
    if (fd < 0) {
        printf("save token error %s\n", strerror(get_sys_errno()));
        return;
    }

    ssize_t n = write(fd, token, token_len);
    if (n < token_len) {
        printf("save token error %s\n", strerror(get_sys_errno()));
        close(fd);
        return;
    }
    close(fd);
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
    char ts[32];
    xqc_get_timestamp(ts, sizeof(ts));

    int ret;
    xqc_moq_session_t *session = user_session->session;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;
    user_conn->moq_session = session;
    user_conn->countdown = g_frame_num;
   
    /* Subscribe to "example" namespace */
    const char *segments[] = {"example"};
    uint64_t request_id;
    ret = xqc_moq_subscribe_namespace_by_path(session, segments, 1, &request_id);
    
    if (ret == XQC_OK) {
        printf("\n%s [CLIENT] Subscribed to namespace 'example', request_id=%llu\n", ts, (unsigned long long)request_id);
        printf("  Waiting for server to publish matching tracks...\n\n");
    } else {
        printf("\n%s [CLIENT] Failed to subscribe namespace, ret=%d\n", ts, ret);
    }


    // ret = xqc_moq_subscribe_datachannel(session);
    // if (ret < 0) {
    //     printf("xqc_moq_subscribe_datachannel error\n");
    //     return;
    // }
    // ret = xqc_moq_subscribe_catalog(session);
    // if (ret < 0) {
    //     printf("xqc_moq_subscribe_catalog error\n");
    //     return;
    // }

    // user_conn->moq_session = session;
    // user_conn->video_subscribe_id = -1;
    // user_conn->audio_subscribe_id = -1;
    // user_conn->clock_subscribe_id = -1;
    // if (g_role == XQC_MOQ_SUBSCRIBER) {
    //     return;
    // }

    // xqc_moq_selection_params_t video_params;
    // memset(&video_params, 0, sizeof(xqc_moq_selection_params_t));
    // video_params.codec = "av01";
    // video_params.mime_type = "video/mp4";
    // video_params.width = 720;
    // video_params.height = 720;
    // video_params.bitrate = 1000000;
    // video_params.framerate = 30;
    // // xqc_moq_track_t *video_track = xqc_moq_track_create(session, "namespace", "video", XQC_MOQ_TRACK_VIDEO, &video_params,
    // //                                                     XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_PUB);
    // xqc_moq_track_t *default_track = xqc_moq_track_create(session, "namespace", "track", XQC_MOQ_TRACK_DEFAULT,
    //                                                     NULL, XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_PUB);
    // if (default_track == NULL) {
    //     printf("create video track error\n");
    // }
    // user_conn->default_track = default_track;
    // interop experiment
    // xqc_moq_subscribe_latest(session, "moq-date", "date");

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
    struct timeval time = { 0, 33333 };
    event_add(user_conn->ev_send_timer, &time);
}

void on_subscribe_v13(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t_v13 *msg)
{
    DEBUG;
    printf("on_subscribe_v13\n");
    int ret;
    xqc_moq_session_t *session = user_session->session;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;

    if (strcmp(msg->track_name, "video") == 0) {
        
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
        printf("subscribe_id: %lld\n", subscribe_id);

    } else if (strcmp(msg->track_name, "audio") == 0) {
        user_conn->audio_subscribe_id = subscribe_id;

        xqc_moq_subscribe_ok_msg_t subscribe_ok;
        subscribe_ok.subscribe_id = subscribe_id;
        subscribe_ok.track_alias = track->track_alias;  // 设置正确的track_alias
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
    }

    // user_conn->ev_send_timer = evtimer_new(eb, xqc_app_send_callback, user_conn);
    struct timeval time = { 0, 33333 };
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
    printf("msg report on_subscribe_ok\n");
    DEBUG;
    printf("subscribe_id:%d expire_ms:%d content_exist:%d largest_group_id:%d largest_object_id:%d\n",
           (int)subscribe_ok->subscribe_id, (int)subscribe_ok->expire_ms, (int)subscribe_ok->content_exist,
           (int)subscribe_ok->largest_group_id, (int)subscribe_ok->largest_object_id);
    xqc_moq_track_status_msg_t track_status;
    track_status.subscriber_priority = 0;
    track_status.group_order = 0;
    track_status.forward = 0;
    track_status.filter_type = XQC_MOQ_FILTER_LARGEST_OBJECT;
    track_status.start_location = 0;
    track_status.end_group = 0;
    track_status.params_num = 0;
    track_status.params = NULL;
    track_status.request_id = alloc_g_request_id();

    track_status.track_namespace = (xqc_moq_msg_track_namespace_t *)malloc(sizeof(xqc_moq_msg_track_namespace_t));
    track_status.track_namespace->track_namespace_num = 1;
    track_status.track_namespace->track_namespace = (char **)calloc(track_status.track_namespace->track_namespace_num, sizeof(char *));
    track_status.track_namespace->track_namespace[0] = (char *)calloc(strlen("namespace") + 1, sizeof(char));
    strcpy(track_status.track_namespace->track_namespace[0], "namespace");
    track_status.track_namespace->track_namespace_len = (uint64_t *)calloc(track_status.track_namespace->track_namespace_num, sizeof(uint64_t));
    track_status.track_namespace->track_namespace_len[0] = strlen(track_status.track_namespace->track_namespace[0]);
    track_status.track_name = (char *)calloc(strlen("track") + 1, sizeof(char));
    strcpy(track_status.track_name, "track");
    track_status.track_name_len = strlen(track_status.track_name);
    xqc_int_t ret = xqc_moq_track_status(user_session->session, &track_status);
    if(ret < 0) {
        printf("xqc_moq_track_status error\n");
    }
    else {
        printf("send track status ok\n");
    }

    track_status.request_id = alloc_g_request_id();
    xqc_free((void*)(track_status.track_name));
    track_status.track_name = (char *)calloc(strlen("test") + 1, sizeof(char));
    strcpy(track_status.track_name, "test");
    track_status.track_name_len = strlen(track_status.track_name);
    ret = xqc_moq_track_status(user_session->session, &track_status);
    if(ret < 0) {
        printf("xqc_moq_track_status error\n");
    }
    else {
        printf("send track status ok\n");
    }
}

void on_track_status_ok(xqc_moq_user_session_t *user_session, xqc_moq_track_status_ok_msg_t *track_status_ok)
{
    DEBUG;
    printf("msg report on_track_status_ok, subscribe_id: %lld\n", track_status_ok->request_id);
}

void on_track_status_error(xqc_moq_user_session_t *user_session, xqc_moq_track_status_error_msg_t *track_status_error)
{
    // no specific track so we recevice
    // we need to publish the specific track
    xqc_int_t ret = 0;


    xqc_moq_subscribe_namespace_msg_t *subscribe_namespace = xqc_calloc(1, sizeof(xqc_moq_subscribe_namespace_msg_t));
    subscribe_namespace->request_id = alloc_g_request_id();
    subscribe_namespace->track_namespace_prefix_num = 1;
    subscribe_namespace->track_namespace_prefix = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
    subscribe_namespace->track_namespace_prefix->track_namespace_num = 1;
    subscribe_namespace->track_namespace_prefix->track_namespace = xqc_calloc(1, sizeof(char *));
    subscribe_namespace->track_namespace_prefix->track_namespace[0] = xqc_calloc(1, strlen("moq-date") + 1);
    subscribe_namespace->track_namespace_prefix->track_namespace_len = xqc_calloc(1, sizeof(uint64_t));
    subscribe_namespace->track_namespace_prefix->track_namespace_len[0] = strlen("moq-date");
    strcpy(subscribe_namespace->track_namespace_prefix->track_namespace[0], "moq-date");
    ret = xqc_moq_write_subscribe_namespace(user_session->session, subscribe_namespace);
    if(ret < 0) {
        printf("xqc_moq_write_subscribe_namespace error: %d\n", ret);
    }
    else {
        printf("xqc_moq_write_subscribe_namespace success\n");
    }


    printf("show moq_track_status_error contetnt : subscribe_id: %lld, error_code: %lld, error_reason: %s\n",
         track_status_error->request_id, track_status_error->error_code, track_status_error->error_reason);


    // xqc_moq_publish_msg_t publish_msg;
    // memset(&publish_msg, 0, sizeof(xqc_moq_publish_msg_t));
    // publish_msg.request_id = alloc_g_request_id();
    // publish_msg.track_alias = 0;
    // publish_msg.track_name = "date";
    // publish_msg.track_name_len = strlen(publish_msg.track_name);
    // printf("publish_msg.track_name: %s\n", publish_msg.track_name);
    // publish_msg.track_namespace = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
    // publish_msg.track_namespace->track_namespace_len = xqc_calloc(1, sizeof(uint64_t));

    // publish_msg.track_namespace->track_namespace = xqc_calloc(1, sizeof(char *));
    // publish_msg.track_namespace->track_namespace[0] = xqc_calloc(1, strlen("moq-date") + 1);
    // publish_msg.track_namespace->track_namespace[0] = "moq-date";
    // publish_msg.track_namespace->track_namespace_len[0] = strlen("moq-date");
    // publish_msg.track_namespace->track_namespace_num = 1;
    // publish_msg.group_order = 0;
    // publish_msg.content_exists = 0;
    // publish_msg.forward = 1;
    // publish_msg.params_num = 0;
    
    // ret = xqc_moq_publish(user_session->session, &publish_msg);
    // if (ret < 0) {
    //     printf("xqc_moq_publish error\n");
    // }
    // else {
    //     printf("xqc_moq_publish success\n");
    // }


    // test announce 
    xqc_moq_announce_msg_t announce_msg;
    memset(&announce_msg, 0, sizeof(xqc_moq_announce_msg_t));
    announce_msg.request_id = alloc_g_request_id();
    announce_msg.track_namespace = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
    announce_msg.track_namespace->track_namespace_num = 1;
    announce_msg.track_namespace->track_namespace = xqc_calloc(1, sizeof(char *));
    announce_msg.track_namespace->track_namespace_len = xqc_calloc(1, sizeof(uint64_t));
    announce_msg.track_namespace->track_namespace_len[0] = strlen("moq-date");
    announce_msg.track_namespace->track_namespace[0] = xqc_calloc(1, strlen("moq-date") + 1);
    strcpy(announce_msg.track_namespace->track_namespace[0], "moq-date");
    announce_msg.params_num = 0;
    announce_msg.params = NULL;
    ret = xqc_moq_write_announce(user_session->session, &announce_msg);
    if(ret < 0) {
        printf("xqc_moq_write_announce error: %d\n", ret);
    }
    else {
        printf("xqc_moq_write_announce success\n");
    }
}

void on_subscribe_error(xqc_moq_user_session_t *user_session, xqc_moq_subscribe_error_msg_t *subscribe_error)
{
    printf("==>on_subscribe_error\n");
    DEBUG;
    printf("subscribe_id:%d error_code:%d reason_phrase:%s track_alias:%d\n",
           (int)subscribe_error->subscribe_id, (int)subscribe_error->error_code, subscribe_error->reason_phrase, (int)subscribe_error->track_alias);
}

void on_video_frame(xqc_moq_user_session_t *user_session, uint64_t subscribe_id, xqc_moq_video_frame_t *video_frame)
{
    DEBUG;
    xqc_moq_session_t *session = user_session->session;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;
    int diff = (int)(xqc_now() - video_frame->timestamp_us) ;
    printf("subscribe_id:%"PRIu64", seq_num:%"PRIu64", timestamp_us:%"PRIu64", type:%d, video_len:%"PRIu64", delay:%d, dcid:%s\n",
            subscribe_id, video_frame->seq_num, video_frame->timestamp_us, video_frame->type, video_frame->video_len,
            (int)(xqc_now() - video_frame->timestamp_us),xqc_dcid_str_by_scid(ctx.engine, &user_conn->cid));

    static int tot_delay = 0 ; 
    static int cnt = 0 ;
    tot_delay += diff;
    cnt++;

    if(cnt==100)
    {
        printf("!!! recv complete\n");
        printf("tot_delay: %d\n", tot_delay);
        printf("avg_delay: %d\n", tot_delay/cnt);
    }

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

    //printf("audio_data:%s\n",audio_frame->audio_data);
}

void on_object_datagram(xqc_moq_user_session_t *user_session, xqc_moq_object_datagram_t *object_datagram)
{
    DEBUG;
    printf("on object datagram : track_alias:%"PRIu64", group_id:%"PRIu64", object_id:%"PRIu64", publisher_priority:%d, payload_len:%zu\n",
            object_datagram->track_alias, object_datagram->group_id, object_datagram->object_id,
            object_datagram->publisher_priority, object_datagram->payload_len);
}

void on_subgroup_object(xqc_moq_user_session_t *user_session, xqc_moq_subgroup_object_msg_t *subgroup_object)
{
    DEBUG;
    char ts[32];
    xqc_get_timestamp(ts, sizeof(ts));
    
    printf("\n%s [CLIENT] Received data on subgroup object:\n", ts);



    // If the object group_id is 1, send subscribe update v13
    if(subgroup_object->subgroup_header->group_id == 1) {
        // xqc_moq_subscribe_update_msg_t_v13 update;
        // memset(&update, 0, sizeof(xqc_moq_subscribe_update_msg_t_v13));
        // update.subscribe_id = 2;
        // update.start_group_id = 3;
        // update.start_object_id = 0;
        // update.end_group = 0;
        // update.subscriber_priority = 0;
        // update.forward = 1;
        // xqc_int_t ret = xqc_moq_write_subscribe_update_v13(user_session->session, &update);
        // if(ret < 0) {
        //     printf("xqc_moq_write_subscribe_update_v13 error: %d\n", ret);
        // }
        // else {
        //         printf("xqc_moq_write_subscribe_update_v13 success\n");
        // }

        // test unsubscribe = OK
        // xqc_moq_unsubscribe_msg_t unsubscribe_msg;
        // memset(&unsubscribe_msg, 0, sizeof(xqc_moq_unsubscribe_msg_t));
        // unsubscribe_msg.subscribe_id = 2;
        // xqc_int_t ret = xqc_moq_write_unsubscribe(user_session->session, &unsubscribe_msg);
        // if(ret < 0) {
        //     printf("xqc_moq_unsubscribe error: %d\n", ret);
        // }
        // else {
        //     printf("xqc_moq_unsubscribe success\n");
        // }


       
    }
}

void
on_publish(xqc_moq_user_session_t *user_session, xqc_moq_publish_msg_t *publish)
{
    DEBUG;
    char ts[32];
    xqc_get_timestamp(ts, sizeof(ts));
    
    printf("\n%s [CLIENT] PUBLISH received (from namespace subscription):\n", ts);
    printf("  Track: %s/%s\n", 
           publish->track_namespace->track_namespace[0],
           publish->track_name);
    printf("  Track Alias: %llu\n", (unsigned long long)publish->track_alias);

    xqc_moq_track_t *track =  xqc_moq_track_create(user_session->session,
                         publish->track_namespace->track_namespace[0],
                         publish->track_name,
                         XQC_MOQ_TRACK_DEFAULT,
                         NULL,
                         XQC_MOQ_CONTAINER_LOC,
                         XQC_MOQ_TRACK_FOR_SUB);
    
    if (track == NULL) {
        printf("%s [CLIENT] ✗ Failed to create track for PUBLISH\n\n", ts);
        return;
    }
    
    track->track_alias = publish->track_alias;
    track->subscribe_id = publish->request_id;
    
    printf("  -> Sending PUBLISH_OK\n");
    xqc_moq_publish_ok_msg_t *publish_ok = xqc_moq_msg_create_publish_ok(user_session->session);
    if (publish_ok) {
        publish_ok->request_id = publish->request_id;
        publish_ok->params_num = 0;
        publish_ok->params = NULL;
        
        printf("[DEBUG] About to send PUBLISH_OK, msg_type=0x%x, request_id=%llu\n", 
               XQC_MOQ_MSG_PUBLISH_OK, (unsigned long long)publish_ok->request_id);
        
        xqc_int_t ret = xqc_moq_write_publish_ok_msg(user_session->session, publish_ok);
        if (ret >= 0) {
            printf("  -> PUBLISH_OK sent successfully, ret=%d\n\n", ret);
        } else {
            printf("  -> PUBLISH_OK send failed: %d\n\n", ret);
        }
        xqc_moq_msg_free_publish_ok(publish_ok);
    }
}

void on_subscribe_namespace_ok(xqc_moq_user_session_t *user_session,
                                xqc_moq_subscribe_namespace_ok_msg_t *ok)
{
    DEBUG;
    char ts[32];
    xqc_get_timestamp(ts, sizeof(ts));
    
    printf("\n%s [CLIENT] SUBSCRIBE_NAMESPACE_OK received, request_id=%llu\n", ts, 
           (unsigned long long)ok->request_id);
    printf("  Namespace subscription confirmed. Waiting for PUBLISH messages...\n\n");
}

void on_publish_namespace(xqc_moq_user_session_t *user_session,
                          xqc_moq_publish_namespace_msg_t *publish_namespace)
{
    DEBUG;
    char ts[32];
    xqc_get_timestamp(ts, sizeof(ts));
    
    printf("\n%s [CLIENT] PUBLISH_NAMESPACE received:\n", ts);
    printf("  Request ID: %llu\n", (unsigned long long)publish_namespace->request_id);
    
    if (publish_namespace->track_namespace && 
        publish_namespace->track_namespace->track_namespace_num > 0) {
        printf("  Namespace: ");
        for (uint64_t i = 0; i < publish_namespace->track_namespace->track_namespace_num; i++) {
            printf("%s", publish_namespace->track_namespace->track_namespace[i]);
            if (i < publish_namespace->track_namespace->track_namespace_num - 1) {
                printf("/");
            }
        }
        printf("\n");
        printf("  -> Namespace is available for publishing\n\n");
    }
}

void on_publish_namespace_done(xqc_moq_user_session_t *user_session,
                                xqc_moq_publish_namespace_done_msg_t *publish_namespace_done)
{
    DEBUG;
    char ts[32];
    xqc_get_timestamp(ts, sizeof(ts));
    
    printf("\n%s [CLIENT] PUBLISH_NAMESPACE_DONE received:\n", ts);
    
    if (publish_namespace_done->track_namespace && 
        publish_namespace_done->track_namespace->track_namespace_num > 0) {
        printf("  Namespace: ");
        for (uint64_t i = 0; i < publish_namespace_done->track_namespace->track_namespace_num; i++) {
            printf("%s", publish_namespace_done->track_namespace->track_namespace[i]);
            if (i < publish_namespace_done->track_namespace->track_namespace_num - 1) {
                printf("/");
            }
        }
        printf("\n");
        printf("  -> Namespace publishing withdrawn\n\n");
    }
}

void on_goaway(xqc_moq_user_session_t *user_session, xqc_moq_goaway_msg_t *goaway)
{
    DEBUG;
    char ts[32];
    xqc_get_timestamp(ts, sizeof(ts));
    
    printf("\n%s [CLIENT] GOAWAY received from server\n", ts);
    if (goaway->new_URI && goaway->new_URI_len > 0) {
        printf("  New session URI: %s\n", goaway->new_URI);
    } else {
        printf("  No new session URI provided\n");
    }
    printf("  -> Closing connection as requested by server\n\n");
    
    user_conn_t *user_conn = (user_conn_t *)user_session->data;
    xqc_conn_close(ctx.engine, &user_conn->cid);
}

void on_publish_ok(xqc_moq_user_session_t *user_session, xqc_moq_publish_ok_msg_t *publish_ok)
{
    DEBUG;
    printf("on publish ok : request_id:%"PRIu64"\n", publish_ok->request_id);

    xqc_int_t ret = 0;
    xqc_moq_subscribe_msg_t_v13 subscribe_msg;
    memset(&subscribe_msg, 0, sizeof(xqc_moq_subscribe_msg_t_v13));
    subscribe_msg.request_id = alloc_g_request_id(); // for test
    subscribe_msg.track_namespace = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
    subscribe_msg.track_namespace->track_namespace_num = 1;
    subscribe_msg.track_namespace->track_namespace = xqc_calloc(1, sizeof(char *));
    subscribe_msg.track_namespace->track_namespace[0] = xqc_calloc(1, strlen("moq-date") + 1);
    subscribe_msg.track_namespace->track_namespace[0] = "moq-date";
    subscribe_msg.track_namespace->track_namespace_len = xqc_calloc(1, sizeof(uint64_t));
    subscribe_msg.track_namespace->track_namespace_len[0] = strlen("moq-date");
    subscribe_msg.track_name = "date";
    subscribe_msg.track_name_len = strlen(subscribe_msg.track_name);
    subscribe_msg.track_alias = 0;

    subscribe_msg.group_order = 0;
    subscribe_msg.forward = 1;
    subscribe_msg.filter_type = XQC_MOQ_FILTER_LARGEST_OBJECT;
    subscribe_msg.params_num = 0;
    subscribe_msg.params = NULL;
    ret = xqc_moq_write_subscribe_v13(user_session->session, &subscribe_msg);
    if (ret < 0) {
        printf("xqc_moq_subscribe error\n");
    }
    else {
        printf("xqc_moq_subscribe success\n");
    }

    
    user_conn_t *user_conn = (user_conn_t *)user_session->data;
    // user_conn->ev_send_timer = evtimer_new(eb, xqc_app_send_callback, user_conn);
    struct timeval time = { 0, 33333 };
    event_add(user_conn->ev_send_timer, &time);
}

void on_publish_error(xqc_moq_user_session_t *user_session, xqc_moq_publish_error_msg_t *publish_error)
{
    DEBUG;
    printf("on publish error : request_id:%"PRIu64"\n", publish_error->request_id);
}

void on_announce_ok(xqc_moq_user_session_t *user_session, xqc_moq_announce_ok_msg_t *announce_ok)
{
    DEBUG;
    printf("on announce ok : request_id:%"PRIu64"\n", announce_ok->request_id);
}


static int
is_fast_rtt_alpn(const char *alpn)
{
    if (!alpn) {
        return 0;
    }
    return (strcmp(alpn, "moq-15-t0") == 0 || strcmp(alpn, "moq-15-t1") == 0);
}

int
xqc_client_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    DEBUG;
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;

    xqc_moq_session_callbacks_t callbacks = {
        .on_session_setup = on_session_setup,
        /* For Publisher */
        .on_subscribe_v05 = on_subscribe_v05,
        .on_subscribe_v13 = on_subscribe_v13,
        .on_publish = on_publish,
        .on_publish_ok = on_publish_ok,
        .on_publish_error = on_publish_error,
        .on_request_keyframe = on_request_keyframe,
        .on_bitrate_change = on_bitrate_change,
        /* For Subscriber */
        .on_subscribe_ok = on_subscribe_ok,
        .on_subscribe_error = on_subscribe_error,
        .on_video = on_video_frame,
        .on_audio = on_audio_frame,
        .on_subgroup_object = on_subgroup_object,
        .on_datagram = on_object_datagram,
        .on_track_status_ok = on_track_status_ok,
        .on_track_status_error = on_track_status_error,
        .on_subscribe_namespace_ok = on_subscribe_namespace_ok,
        .on_publish_namespace = on_publish_namespace,
        .on_publish_namespace_done = on_publish_namespace_done,
        .on_announce_ok = on_announce_ok,
        .on_goaway = on_goaway,
    };
#ifdef XQC_MOQ_VERSION_11
    xqc_moq_session_t *session = xqc_moq_session_create(conn, user_session, XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_SUPPORTED_VERSION_13, g_role, callbacks, "");
#elif XQC_MOQ_VERSION_05
    xqc_moq_session_t *session = xqc_moq_session_create(conn, user_session, XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_SUPPORTED_VERSION_05, g_role, callbacks, "extdata");
#endif
    if (session == NULL) {
        printf("create session error\n");
        return -1;
    }
    else {
        printf("create session ok\n");
    }
    
    const char *negotiated_alpn = xqc_moq_get_negotiated_alpn(session);
    if (g_fast_rtt_mode && negotiated_alpn && is_fast_rtt_alpn(negotiated_alpn)) {
        printf("[Demo] Fast RTT mode enabled (ALPN=%s), triggering session setup immediately\n", 
               negotiated_alpn);
        xqc_moq_trigger_session_setup(session, "");
    } else {
        printf("[Demo] Standard mode (ALPN=%s), waiting for SERVER_SETUP\n", 
               negotiated_alpn ? negotiated_alpn : "NULL");
    }
    
    // xqc_moq_configure_bitrate(session, 1000000, 8000000, 1000000);
    return 0;
}

int
xqc_client_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    DEBUG;
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, cid);
    
    printf("[Client Close Debug] xqc_conn_stats ALPN: '%s'\n", stats.alpn);
    
    printf("send_count:%u, lost_count:%u, lost_dgram_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, ack_info:%s, alpn:%s, fec_recovered:%d\n",
            stats.send_count, stats.lost_count, stats.lost_dgram_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info, stats.alpn,
            stats.fec_recover_pkt_cnt);

    if (user_session) {
        if (user_session->session) {
            xqc_moq_session_destroy(user_session->session);
            user_session->session = NULL;
        }
        free(user_session);
        user_session = NULL;
    }
    
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
    // send_subgroup
    user_conn_t *user_conn = (user_conn_t *)arg;
    if (user_conn->countdown-- < 0) {
        printf("countdown <= 0, close conn\n");
        xqc_moq_subscribe_done(user_conn->moq_session, 2, XQC_MOQ_STATUS_TRACK_ENDED, 1,
             "test", strlen("test"));
        
        // xqc_conn_close(ctx.engine, &user_conn->cid);
        return;
    }

    /* Disabled client-side subgroup sending for isolation */

    struct timeval time = { 2, 0 };
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
    uint8_t secret_key[16] = {0};
    int use_proxy = 0;
    while ((ch = getopt(argc, argv, "a:p:r:c:l:A:k:n:fF")) != -1) {
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
            case 'l': /* Log level. e:error d:debug. */
                printf("option log level :%s\n", optarg);
                c_log_level = optarg[0];
                break;
            case 'A':
                printf("option proxy_pass_addr :%s\n", optarg);
                snprintf(proxy_pass_addr, sizeof(proxy_pass_addr), optarg);
                use_proxy = 1;
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
            default:
                printf("other option :%c\n", ch);
                //usage(argc, argv);
                exit(0);
        }
    }
    memset(&ctx, 0, sizeof(ctx));

    xqc_app_open_log_file(&ctx, "./default_clog");
    xqc_platform_init_env();

    xqc_engine_ssl_config_t  engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));

    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_SPECIAL_GROUPS;

    xqc_engine_callback_t callback = {
        .set_event_timer = xqc_app_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = xqc_app_write_log,
            .xqc_log_write_stat = xqc_app_write_log,
        },
    };

    xqc_transport_callbacks_t tcbs = {
        .write_socket = xqc_app_write_socket,
        .save_token = xqc_client_save_token,
        .save_session_cb = save_session_cb,
        .save_tp_cb = save_tp_cb,
    };

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        return -1;
    }
    xqc_app_set_log_level(c_log_level, &config);
    config.cid_len = 12;

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
#ifdef XQC_MOQ_VERSION_11
    xqc_moq_init_alpn_by_custom(ctx.engine, &conn_cbs, XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_SUPPORTED_VERSION_14);
#endif
    xqc_moq_init_alpn_by_custom(ctx.engine, &conn_cbs, XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_SUPPORTED_VERSION_05);

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
        },
        .max_datagram_frame_size = 1024,
    };

    if (use_proxy) {
        uint8_t dcid[12];
        uint32_t token = 0;
        token = inet_addr(proxy_pass_addr);
        if (token == INADDR_NONE) {
            printf("invalid proxy_pass_addr\n");
            return -1;
        }
        if (xqc_moq_encode_cid(token, secret_key, config.cid_len, dcid) != 0) {
            printf("xqc_moq_encode_cid error\n");
            return -1;
        }

        //conn_settings.specify_client_dcid = 1;
        //memcpy(conn_settings.client_dcid, dcid, config.cid_len);
    }

    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));
    conn_ssl_config.cert_verify_flag |= XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;

    const xqc_cid_t *cid = NULL;
#ifdef XQC_MOQ_VERSION_11
    #ifdef XQC_DEMO_MULTI_ALPN
    {
        const char *alpns[10];
        int alpn_count = 0;
        
        if (g_fast_rtt_mode) {
            printf("[Fast RTT] Using optimistic ALPN: moq-15-t0\n");
            alpns[alpn_count++] = XQC_ALPN_MOQ_QUIC_V15_T0;
            alpns[alpn_count++] = XQC_ALPN_MOQ_QUIC_V15_T1;
        }
        
        alpns[alpn_count++] = XQC_ALPN_MOQ_QUIC_V14;
        alpns[alpn_count++] = XQC_ALPN_MOQ_QUIC_V05;
        alpns[alpn_count++] = XQC_ALPN_MOQ_QUIC_INTEROP;
        
        cid = xqc_connect_with_alpns(ctx.engine, &conn_settings, NULL, 0,
                                     server_addr, 0, &conn_ssl_config, user_conn->peer_addr,
                                     user_conn->peer_addrlen, alpns, alpn_count, user_session);
    }
    #else
    cid = xqc_connect(ctx.engine, &conn_settings, NULL, 0,
                      server_addr, 0, &conn_ssl_config, user_conn->peer_addr,
                      user_conn->peer_addrlen, "moq-00", user_session);
    #endif
#else  /* XQC_MOQ_VERSION_05 */
    cid = xqc_connect(ctx.engine, &conn_settings, NULL, 0,
                      server_addr, 0, &conn_ssl_config, user_conn->peer_addr,
                      user_conn->peer_addrlen, "moq-00", user_session);
#endif
    if(cid == NULL)
    {
        printf("xqc_connect error\n");
        xqc_engine_destroy(ctx.engine);
        return -1;
    }

    event_base_dispatch(eb);

    xqc_engine_destroy(ctx.engine);
    //TODO: free other struct

    return 0;
}