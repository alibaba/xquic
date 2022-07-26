/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <event2/event.h>
#include <memory.h>

#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xqc_http3.h>

#include "platform.h"

#ifndef XQC_SYS_WINDOWS
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#else
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"event.lib")
#pragma comment(lib, "Iphlpapi.lib")
#include <third_party/wingetopt/src/getopt.h>
#endif

int
printf_null(const char *format, ...)
{
    return 0;
}

#define XQC_ALPN_TRANSPORT "transport"

//#define printf printf_null

#define DEBUG printf("%s:%d (%s)\n", __FILE__, __LINE__, __FUNCTION__);

#define TEST_DROP (g_drop_rate != 0 && rand() % 1000 < g_drop_rate)

#define TEST_SERVER_ADDR "127.0.0.1"
#define TEST_SERVER_PORT 8443


#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100*1024*1024)

#define XQC_MAX_TOKEN_LEN 256

#define XQC_TEST_SHORT_HEADER_PACKET_A "\x40\xAB\x3f\x12\x0a\xcd\xef\x00\x89"
#define XQC_TEST_SHORT_HEADER_PACKET_B "\x80\xAB\x3f\x12\x0a\xcd\xef\x00\x89"

#define MAX_HEADER 100

#define XQC_MAX_LOG_LEN 2048

typedef struct user_conn_s user_conn_t;

typedef struct user_stream_s {
    xqc_stream_t       *stream;
    xqc_h3_request_t   *h3_request;
    user_conn_t        *user_conn;
    uint64_t            send_offset;
    int                 header_sent;
    int                 header_recvd;
    char               *send_body;
    size_t              send_body_len;
    size_t              send_body_max;
    char               *recv_body;
    size_t              recv_body_len;
    FILE               *recv_body_fp;
    int                 recv_fin;
    xqc_msec_t          start_time;
    xqc_msec_t          first_frame_time;   /* first frame download time */
    xqc_msec_t          last_read_time;
    int                 abnormal_count;
    int                 body_read_notify_cnt;
} user_stream_t;

typedef struct user_conn_s {
    int                 fd;
    xqc_cid_t           cid;

    struct sockaddr    *local_addr;
    socklen_t           local_addrlen;
    xqc_flag_t          get_local_addr;
    struct sockaddr    *peer_addr;
    socklen_t           peer_addrlen;

    unsigned char      *token;
    unsigned            token_len;

    struct event       *ev_socket;
    struct event       *ev_timeout;

    int                 h3;

    int                 rebinding_fd;
    struct event       *rebinding_ev_socket;
} user_conn_t;

#define XQC_DEMO_INTERFACE_MAX_LEN 64
#define XQC_DEMO_MAX_PATH_COUNT    8
#define MAX_HEADER_KEY_LEN 128
#define MAX_HEADER_VALUE_LEN 4096

typedef struct xqc_user_path_s {
    int                 path_fd;
    uint64_t            path_id;

    struct sockaddr    *peer_addr;
    socklen_t           peer_addrlen;
    struct sockaddr    *local_addr;
    socklen_t           local_addrlen;

    struct event       *ev_socket;
} xqc_user_path_t;


typedef struct client_ctx_s {
    xqc_engine_t   *engine;
    struct event   *ev_engine;
    int             log_fd;
    int             keylog_fd;
    struct event   *ev_delay;
} client_ctx_t;

client_ctx_t ctx;
struct event_base *eb;
int g_req_cnt;
int g_req_max;
int g_send_body_size;
int g_send_body_size_defined;
int g_save_body;
int g_read_body;
int g_echo_check;
int g_drop_rate;
int g_spec_url;
int g_is_get;
uint64_t g_last_sock_op_time;
//currently, the maximum used test case id is 19
//please keep this comment updated if you are adding more test cases. :-D
int g_test_case;
int g_ipv6;
int g_no_crypt;
int g_conn_timeout = 1;
char g_write_file[256];
char g_read_file[256];
char g_log_path[256];
char g_host[64] = "test.xquic.com";
char g_url_path[256] = "/path/resource";
char g_scheme[8] = "https";
char g_url[2048];
char g_headers[MAX_HEADER][256];
int g_header_cnt = 0;
int g_ping_id = 1;
int g_verify_cert = 0;
int g_verify_cert_allow_self_sign = 0;
int g_header_num = 6;
char g_header_key[MAX_HEADER_KEY_LEN];
char g_header_value[MAX_HEADER_VALUE_LEN];

char g_multi_interface[XQC_DEMO_MAX_PATH_COUNT][64];
xqc_user_path_t g_client_path[XQC_DEMO_MAX_PATH_COUNT];
int g_multi_interface_cnt = 0;
int hsk_completed = 0;

#define XQC_TEST_LONG_HEADER_LEN 32769
char test_long_value[XQC_TEST_LONG_HEADER_LEN] = {'\0'};


static uint64_t last_recv_ts = 0;

static void xqc_client_socket_event_callback(int fd, short what, void *arg);
static void xqc_client_timeout_callback(int fd, short what, void *arg);

#ifdef XQC_SYS_WINDOWS
static void usleep(unsigned long usec)
{
    HANDLE timer;
    LARGE_INTEGER interval;
    interval.QuadPart = -(10 * usec);

    timer = CreateWaitableTimer(NULL, TRUE, NULL);
    SetWaitableTimer(timer, &interval, 0, NULL, NULL, 0);
    WaitForSingleObject(timer, INFINITE);
    CloseHandle(timer);
}
#endif

void
xqc_client_set_event_timer(xqc_msec_t wake_after, void *user_data)
{
    client_ctx_t *ctx = (client_ctx_t *) user_data;
    //printf("xqc_engine_wakeup_after %llu us, now %llu\n", wake_after, xqc_now());

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);

}

void
save_session_cb(const char * data, size_t data_len, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    printf("save_session_cb use server domain as the key. h3[%d]\n", user_conn->h3);

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
    user_conn_t *user_conn = (user_conn_t*)user_data;
    printf("save_tp_cb use server domain as the key. h3[%d]\n", user_conn->h3);

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
    user_conn_t *user_conn = (user_conn_t*)user_data;
    printf("xqc_client_save_token use client ip as the key. h3[%d]\n", user_conn->h3);

    if (g_test_case == 16) { /* test application delay */
        usleep(300*1000);
    }
    int fd = open("./xqc_token", O_TRUNC | O_CREAT | O_WRONLY, 0666);
    if (fd < 0) {
        printf("save token error %s\n", strerror(get_last_sys_errno()));
        return;
    }

    ssize_t n = write(fd, token, token_len);
    if (n < token_len) {
        printf("save token error %s\n", strerror(get_last_sys_errno()));
        close(fd);
        return;
    }
    close(fd);
}

int
xqc_client_read_token(unsigned char *token, unsigned token_len)
{
    int fd = open("./xqc_token", O_RDONLY);
    if (fd < 0) {
        printf("read token error %s\n", strerror(get_last_sys_errno()));
        return -1;
    }

    ssize_t n = read(fd, token, token_len);
    printf("read token size %zu\n", n);
    close(fd);
    return n;
}

int
read_file_data(char *data, size_t data_len, char *filename)
{
    int ret = 0;
    size_t total_len, read_len;
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        ret = -1;
        goto end;
    }

    fseek(fp, 0, SEEK_END);
    total_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (total_len > data_len) {
        ret = -1;
        goto end;
    }

    read_len = fread(data, 1, total_len, fp);
    if (read_len != total_len) {
        ret = -1;
        goto end;
    }

    ret = read_len;

end:
    if (fp) {
        fclose(fp);
    }
    return ret;
}

ssize_t 
xqc_client_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user)
{
    user_conn_t *user_conn = (user_conn_t *) user;
    ssize_t res = 0;
    int fd = user_conn->fd;

    if (g_test_case == 41) {
        /* delay short header packet to make server idle timeout */
        if ((buf[0] & 0xC0) == 0x40) {
            sleep(2);
            g_test_case = -1;
        }
    }

    if (g_test_case == 42 && hsk_completed == 1) {
        fd = user_conn->rebinding_fd;
    }

    /* COPY to run corruption test cases */
    unsigned char send_buf[XQC_PACKET_TMP_BUF_LEN];
    size_t send_buf_size = 0;

    if (size > XQC_PACKET_TMP_BUF_LEN) {
        printf("xqc_client_write_socket err: size=%zu is too long\n", size);
        return XQC_SOCKET_ERROR;
    }
    send_buf_size = size;
    memcpy(send_buf, buf, send_buf_size);

    /* trigger version negotiation */
    if (g_test_case == 33) {
        /* makes version 0xff000001 */
        send_buf[1] = 0xff;
    }

    /* make initial packet loss to test 0rtt buffer */
    if (g_test_case == 39) {
        g_test_case = -1;
        return size;
    }

    do {
        set_last_sys_errno(0);

        g_last_sock_op_time = xqc_now();

        if (TEST_DROP) {
            return send_buf_size;
        }
        if (g_test_case == 5) { /* socket send fail */
            g_test_case = -1;
            set_last_sys_errno(EAGAIN);
            return XQC_SOCKET_EAGAIN;
        }

        /* client Initial dcid corruption */
        if (g_test_case == 22) {
            /* client initial dcid corruption, bytes [6, 13] is the DCID of xquic's Initial packet */
            g_test_case = -1;
            send_buf[6] = ~send_buf[6];
            printf("test case 22, corrupt byte[6]\n");
        }

        /* client Initial scid corruption */
        if (g_test_case == 23) {
            /* bytes [15, 22] is the SCID of xquic's Initial packet */
            g_test_case = -1;
            send_buf[15] = ~send_buf[15];
            printf("test case 23, corrupt byte[15]\n");
        }

        res = sendto(fd, send_buf, send_buf_size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
            printf("xqc_client_write_socket err %zd %s\n", res, strerror(get_last_sys_errno()));
            if (get_last_sys_errno() == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        }
    } while ((res < 0) && (get_last_sys_errno() == EINTR));

    return res;
}

ssize_t
xqc_client_send_stateless_reset(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, int fd, void *user)
{
    return xqc_client_write_socket(buf, size, peer_addr, peer_addrlen, user);
}

xqc_int_t 
xqc_client_conn_closing_notify(xqc_connection_t *conn,
    const xqc_cid_t *cid, xqc_int_t err_code, void *conn_user_data)
{
    printf("conn closing: %d\n", err_code);
    return XQC_OK;
}


#if defined(XQC_SUPPORT_SENDMMSG) && !defined(XQC_SYS_WINDOWS)
ssize_t 
xqc_client_write_mmsg(const struct iovec *msg_iov, unsigned int vlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user)
{
    const int MAX_SEG = 128;
    user_conn_t *user_conn = (user_conn_t *) user;
    ssize_t res = 0;
    int fd = user_conn->fd;
    struct mmsghdr mmsg[MAX_SEG];
    memset(&mmsg, 0, sizeof(mmsg));
    for (int i = 0; i < vlen; i++) {
        mmsg[i].msg_hdr.msg_iov = (struct iovec *)&msg_iov[i];
        mmsg[i].msg_hdr.msg_iovlen = 1;
    }
    do {
        set_last_sys_errno(0);
        if (TEST_DROP) return vlen;

        if (g_test_case == 5) { /* socket send fail */
            g_test_case = -1;
            errno = EAGAIN;
            return XQC_SOCKET_EAGAIN;
        }

        res = sendmmsg(fd, mmsg, vlen, 0);
        if (res < 0) {
            printf("sendmmsg err %zd %s\n", res, strerror(errno));
            if (errno == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        }
    } while ((res < 0) && (errno == EINTR));
    return res;
}
#endif

static int 
xqc_client_create_socket(int type, 
    const struct sockaddr *saddr, socklen_t saddr_len)
{
    int size;
    int fd = -1;
    int flags;

    /* create fd & set socket option */
    fd = socket(type, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("create socket failed, errno: %d\n", get_last_sys_errno());
        return -1;
    }

#ifdef XQC_SYS_WINDOWS
    if (ioctlsocket(fd, FIONBIO, &flags) == SOCKET_ERROR) {
		goto err;
	}
#else
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("set socket nonblock failed, errno: %d\n", get_last_sys_errno());
        goto err;
    }
#endif

    size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_last_sys_errno());
        goto err;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_last_sys_errno());
        goto err;
    }

    g_last_sock_op_time = xqc_now();

    /* connect to peer addr */
#if !defined(__APPLE__)
    if (connect(fd, (struct sockaddr *)saddr, saddr_len) < 0) {
        printf("connect socket failed, errno: %d\n", get_last_sys_errno());
        goto err;
    }
#endif

    return fd;

err:
    close(fd);
    return -1;
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

#ifndef XQC_SYS_WINDOWS
static int
xqc_client_bind_to_interface(int fd, 
    const char *interface_name)
{
    struct ifreq ifr;
    memset(&ifr, 0x00, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, sizeof(ifr.ifr_name) - 1);

    printf("bind to nic: %s\n", interface_name);

#if (XQC_TEST_MP)
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifr, sizeof(ifr)) < 0) {
        printf("bind to nic error: %d, try use sudo\n", get_last_sys_errno());
        return XQC_ERROR;
    }
#endif

    return XQC_OK;
}
#endif

static int
xqc_client_create_path_socket(xqc_user_path_t *path,
    char *path_interface)
{
    path->path_fd = xqc_client_create_socket((g_ipv6 ? AF_INET6 : AF_INET), 
                                             path->peer_addr, path->peer_addrlen);
    if (path->path_fd < 0) {
        printf("|xqc_client_create_path_socket error|");
        return XQC_ERROR;
    }
#ifndef XQC_SYS_WINDOWS
    if (path_interface != NULL
        && xqc_client_bind_to_interface(path->path_fd, path_interface) < 0) 
    {
        printf("|xqc_client_bind_to_interface error|");
        return XQC_ERROR;
    }
#endif

    return XQC_OK;
}


static int
xqc_client_create_path(xqc_user_path_t *path, 
    char *path_interface, user_conn_t *user_conn)
{
    path->path_id = 0;

    path->peer_addr = calloc(1, user_conn->peer_addrlen);
    memcpy(path->peer_addr, user_conn->peer_addr, user_conn->peer_addrlen);
    path->peer_addrlen = user_conn->peer_addrlen;
    
    if (xqc_client_create_path_socket(path, path_interface) < 0) {
        printf("xqc_client_create_path_socket error\n");
        return XQC_ERROR;
    }
    
    path->ev_socket = event_new(eb, path->path_fd, 
                EV_READ | EV_PERSIST, xqc_client_socket_event_callback, user_conn);
    event_add(path->ev_socket, NULL);

    return XQC_OK;
}


user_conn_t * 
xqc_client_user_conn_create(const char *server_addr, int server_port,
    int transport)
{
    user_conn_t *user_conn = calloc(1, sizeof(user_conn_t));

    /* use HTTP3? */
    user_conn->h3 = transport ? 0 : 1;

    user_conn->ev_timeout = event_new(eb, -1, 0, xqc_client_timeout_callback, user_conn);
    /* set connection timeout */
    struct timeval tv;
    tv.tv_sec = g_conn_timeout;
    tv.tv_usec = 0;
    event_add(user_conn->ev_timeout, &tv);

    int ip_type = (g_ipv6 ? AF_INET6 : AF_INET);
    xqc_client_init_addr(user_conn, server_addr, server_port);
                                      
    user_conn->fd = xqc_client_create_socket(ip_type, 
                                             user_conn->peer_addr, user_conn->peer_addrlen);
    if (user_conn->fd < 0) {
        printf("xqc_create_socket error\n");
        return NULL;
    }

    user_conn->ev_socket = event_new(eb, user_conn->fd, EV_READ | EV_PERSIST, 
                                     xqc_client_socket_event_callback, user_conn);
    event_add(user_conn->ev_socket, NULL);


    user_conn->rebinding_fd = xqc_client_create_socket(ip_type, 
                                                       user_conn->peer_addr, user_conn->peer_addrlen);
    if (user_conn->rebinding_fd < 0) {
        printf("|rebinding|xqc_create_socket error\n");
        return NULL;
    }

    user_conn->rebinding_ev_socket = event_new(eb, user_conn->rebinding_fd, EV_READ | EV_PERSIST,
                                               xqc_client_socket_event_callback, user_conn);
    event_add(user_conn->rebinding_ev_socket, NULL);

    return user_conn;
}


int
xqc_client_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *)user_data;
    xqc_conn_set_alp_user_data(conn, user_conn);

    printf("xqc_conn_is_ready_to_send_early_data:%d\n", xqc_conn_is_ready_to_send_early_data(conn));
    return 0;
}

int
xqc_client_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *)conn_proto_data;

    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, ack_info:%s\n",
           stats.send_count, stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info);

    event_base_loopbreak(eb);
    return 0;
}

void
xqc_client_conn_ping_acked_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *user_data, void *conn_proto_data)
{
    DEBUG;
    if (ping_user_data) {
        printf("====>ping_id:%d\n", *(int *) ping_user_data);

    } else {
        printf("====>no ping_id\n");
    }
}

void
xqc_client_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid, const xqc_cid_t *new_cid, void *user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;

    memcpy(&user_conn->cid, new_cid, sizeof(*new_cid));

    printf("====>RETIRE SCID:%s\n", xqc_scid_str(retire_cid));
    printf("====>SCID:%s\n", xqc_scid_str(new_cid));
    printf("====>DCID:%s\n", xqc_dcid_str_by_scid(ctx.engine, new_cid));

}

void
xqc_client_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;
    xqc_conn_send_ping(ctx.engine, &user_conn->cid, NULL);
    xqc_conn_send_ping(ctx.engine, &user_conn->cid, &g_ping_id);

    printf("====>DCID:%s\n", xqc_dcid_str_by_scid(ctx.engine, &user_conn->cid));
    printf("====>SCID:%s\n", xqc_scid_str(&user_conn->cid));

    hsk_completed = 1;
}

int
xqc_client_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;
    if (g_test_case == 18) { /* test h3 settings */
        xqc_h3_conn_settings_t settings = {
            .max_field_section_size = 512,
            .qpack_max_table_capacity = 4096,
            .qpack_blocked_streams = 32,
        };
        xqc_h3_conn_set_settings(conn, &settings);
    }

    if (g_test_case == 32) {
        xqc_h3_conn_settings_t settings = {
            .max_field_section_size = 10000000,
            .qpack_max_table_capacity = 4096,
            .qpack_blocked_streams = 32,
        };
        xqc_h3_conn_set_settings(conn, &settings);
    }

    if (g_test_case == 19) { /* test header size constraints */
        xqc_h3_conn_settings_t settings = {
            .max_field_section_size = 100,
        };
        xqc_h3_conn_set_settings(conn, &settings);
    }

    printf("xqc_h3_conn_is_ready_to_send_early_data:%d\n", xqc_h3_conn_is_ready_to_send_early_data(conn));
    return 0;
}

int
xqc_client_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;
    printf("conn errno:%d\n", xqc_h3_conn_get_errno(conn));

    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, ack_info:%s\n",
           stats.send_count, stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info);

    event_base_loopbreak(eb);
    return 0;
}

void
xqc_client_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;

    xqc_h3_conn_send_ping(ctx.engine, &user_conn->cid, NULL);
    xqc_h3_conn_send_ping(ctx.engine, &user_conn->cid, &g_ping_id);

    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, &user_conn->cid);
    printf("0rtt_flag:%d\n", stats.early_data_flag);

    printf("====>DCID:%s\n", xqc_dcid_str_by_scid(ctx.engine, &user_conn->cid));
    printf("====>SCID:%s\n", xqc_scid_str(&user_conn->cid));

    hsk_completed = 1;
}

void
xqc_client_h3_conn_ping_acked_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *user_data)
{
    DEBUG;
    if (ping_user_data) {
        printf("====>ping_id:%d\n", *(int *) ping_user_data);

    } else {
        printf("====>no ping_id\n");
    }
}

void
xqc_client_h3_conn_update_cid_notify(xqc_h3_conn_t *conn, const xqc_cid_t *retire_cid, const xqc_cid_t *new_cid, void *user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;

    memcpy(&user_conn->cid, new_cid, sizeof(*new_cid));

    printf("====>RETIRE SCID:%s\n", xqc_scid_str(retire_cid));
    printf("====>SCID:%s\n", xqc_scid_str(new_cid));
    printf("====>DCID:%s\n", xqc_dcid_str_by_scid(ctx.engine, new_cid));

}

int
xqc_client_stream_send(xqc_stream_t *stream, void *user_data)
{
    ssize_t ret;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    if (user_stream->start_time == 0) {
        user_stream->start_time = xqc_now();
    }

    if (user_stream->send_body == NULL) {
        user_stream->send_body_max = MAX_BUF_SIZE;
        if (g_read_body) {
            user_stream->send_body = malloc(user_stream->send_body_max);
        } else {
            user_stream->send_body = malloc(g_send_body_size);
            memset(user_stream->send_body, 1, g_send_body_size);
        }
        if (user_stream->send_body == NULL) {
            printf("send_body malloc error\n");
            return -1;
        }

        /* specified size > specified file > default size */
        if (g_send_body_size_defined) {
            user_stream->send_body_len = g_send_body_size;
        } else if (g_read_body) {
            ret = read_file_data(user_stream->send_body, user_stream->send_body_max, g_read_file);
            if (ret < 0) {
                printf("read body error\n");
                return -1;
            } else {
                user_stream->send_body_len = ret;
            }
        } else {
            user_stream->send_body_len = g_send_body_size;
        }
    }

    int fin = 1;
    if (g_test_case == 4) { /* test fin_only */
        fin = 0;
    }

    if (user_stream->send_offset < user_stream->send_body_len) {
        ret = xqc_stream_send(stream, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, fin);
        if (ret < 0) {
            printf("xqc_stream_send error %zd\n", ret);
            return 0;

        } else {
            user_stream->send_offset += ret;
            printf("xqc_stream_send offset=%"PRIu64"\n", user_stream->send_offset);
        }
    }

    if (g_test_case == 4) { /* test fin_only */
        if (user_stream->send_offset == user_stream->send_body_len) {
            fin = 1;
            usleep(200*1000);
            ret = xqc_stream_send(stream, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, fin);
            printf("xqc_stream_send sent:%zd, offset=%"PRIu64", fin=1\n", ret, user_stream->send_offset);
        }
    }

    return 0;
}

int
xqc_client_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    //DEBUG;
    int ret = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    ret = xqc_client_stream_send(stream, user_stream);
    return ret;
}

int
xqc_client_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    //DEBUG;
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    char buff[4096] = {0};
    size_t buff_size = 4096;
    int save = g_save_body;

    if (save && user_stream->recv_body_fp == NULL) {
        user_stream->recv_body_fp = fopen(g_write_file, "wb");
        if (user_stream->recv_body_fp == NULL) {
            printf("open error\n");
            return -1;
        }
    }

    if (g_echo_check && user_stream->recv_body == NULL) {
        user_stream->recv_body = malloc(user_stream->send_body_len);
        if (user_stream->recv_body == NULL) {
            printf("recv_body malloc error\n");
            return -1;
        }
    }

    ssize_t read;
    ssize_t read_sum = 0;

    do {
        read = xqc_stream_recv(stream, buff, buff_size, &fin);
        if (read == -XQC_EAGAIN) {
            break;

        } else if (read < 0) {
            printf("xqc_stream_recv error %zd\n", read);
            return 0;
        }

        if (save && fwrite(buff, 1, read, user_stream->recv_body_fp) != read) {
            printf("fwrite error\n");
            return -1;
        }
        if (save) fflush(user_stream->recv_body_fp);

        /* write received body to memory */
        if (g_echo_check && user_stream->recv_body_len + read <= user_stream->send_body_len) {
            memcpy(user_stream->recv_body + user_stream->recv_body_len, buff, read);
        }

        read_sum += read;
        user_stream->recv_body_len += read;

    } while (read > 0 && !fin);

    printf("xqc_stream_recv read:%zd, offset:%zu, fin:%d\n", read_sum, user_stream->recv_body_len, fin);

    /* test first frame rendering time */
    if (g_test_case == 14 && user_stream->first_frame_time == 0 && user_stream->recv_body_len >= 98*1024) {
        user_stream->first_frame_time = xqc_now();
    }

    /* test abnormal rate */
    if (g_test_case == 14) {
        xqc_msec_t tmp = xqc_now();
        if (tmp - user_stream->last_read_time > 150*1000 && user_stream->last_read_time != 0 ) {
            user_stream->abnormal_count++;
            printf("\033[33m!!!!!!!!!!!!!!!!!!!!abnormal!!!!!!!!!!!!!!!!!!!!!!!!\033[0m\n");
        }
        user_stream->last_read_time = tmp;
    }

    if (fin) {
        user_stream->recv_fin = 1;
        xqc_msec_t now_us = xqc_now();
        printf("\033[33m>>>>>>>> request time cost:%"PRIu64" us, speed:%"PRIu64" K/s \n"
               ">>>>>>>> send_body_size:%zu, recv_body_size:%zu \033[0m\n",
               now_us - user_stream->start_time,
               (user_stream->send_body_len + user_stream->recv_body_len)*1000/(now_us - user_stream->start_time),
               user_stream->send_body_len, user_stream->recv_body_len);

        /* write to eval file */
        /*{
            FILE* fp = NULL;
            fp = fopen("eval_result.txt", "a+");
            if (fp == NULL) {
                exit(1);
            }

            fprintf(fp, "recv_size: %lu; cost_time: %lu\n", stats.recv_body_size, (uint64_t)((now_us - user_stream->start_time)/1000));
            fclose(fp);

            exit(0);
        }*/

    }
    return 0;
}

int
xqc_client_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t*)user_data;
    if (g_echo_check) {
        int pass = 0;
        printf("user_stream->recv_fin:%d, user_stream->send_body_len:%zu, user_stream->recv_body_len:%zd\n",
               user_stream->recv_fin, user_stream->send_body_len, user_stream->recv_body_len);
        if (user_stream->recv_fin && user_stream->send_body_len == user_stream->recv_body_len
            && memcmp(user_stream->send_body, user_stream->recv_body, user_stream->send_body_len) == 0) {
            pass = 1;
        }
        printf(">>>>>>>> pass:%d\n", pass);
    }

    /* test first frame rendering time */
    if (g_test_case == 14) {
        printf("first_frame_time: %"PRIu64", start_time: %"PRIu64"\n", user_stream->first_frame_time, user_stream->start_time);
        xqc_msec_t t = user_stream->first_frame_time - user_stream->start_time + 200000 /* server-side time consumption */;
        printf("\033[33m>>>>>>>> first_frame pass:%d time:%"PRIu64"\033[0m\n", t <= 1000000 ? 1 : 0, t);
    }

    /* test abnormal rate */
    if (g_test_case == 14) {
        printf("\033[33m>>>>>>>> abnormal pass:%d count:%d\033[0m\n", user_stream->abnormal_count == 0 ? 1 : 0, user_stream->abnormal_count);
    }
    free(user_stream->send_body);
    free(user_stream->recv_body);
    free(user_stream);
    return 0;
}

void
xqc_client_request_send_fin_only(int fd, short what, void *arg)
{
    user_stream_t *us = (user_stream_t *)arg;
    xqc_int_t ret = xqc_h3_request_finish(us->h3_request);
    if (ret < 0) {
        printf("xqc_h3_request_finish error %d\n", ret);

    } else {
        printf("xqc_h3_request_finish success\n");
    }
}

int
xqc_client_request_send(xqc_h3_request_t *h3_request, user_stream_t *user_stream)
{
    if (user_stream->start_time == 0) {
        user_stream->start_time = xqc_now();
    }
    ssize_t ret = 0;
    char content_len[10];

    if (user_stream->send_body == NULL && !g_is_get /* POST */) {
        user_stream->send_body_max = MAX_BUF_SIZE;
        if (g_read_body) {
            user_stream->send_body = malloc(user_stream->send_body_max);

        } else {
            user_stream->send_body = malloc(g_send_body_size);
            memset(user_stream->send_body, 1, g_send_body_size);
        }

        if (user_stream->send_body == NULL) {
            printf("send_body malloc error\n");
            return -1;
        }

        /* specified size > specified file > default size */
        if (g_send_body_size_defined) {
            user_stream->send_body_len = g_send_body_size;

        } else if (g_read_body) {
            ret = read_file_data(user_stream->send_body, user_stream->send_body_max, g_read_file);
            if (ret < 0) {
                printf("read body error\n");
                return -1;

            } else {
                user_stream->send_body_len = ret;
            }

        } else {
            user_stream->send_body_len = g_send_body_size;
        }
    }

    if (g_is_get) {
        snprintf(content_len, sizeof(content_len), "%d", 0);

    } else {
        snprintf(content_len, sizeof(content_len), "%zu", user_stream->send_body_len);
    }
    int header_size = 6;
    xqc_http_header_t header[MAX_HEADER] = {
        {
            .name   = {.iov_base = ":method", .iov_len = 7},
            .value  = {.iov_base = "POST", .iov_len = 4},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = ":scheme", .iov_len = 7},
            .value  = {.iov_base = g_scheme, .iov_len = strlen(g_scheme)},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "host", .iov_len = 4},
            .value  = {.iov_base = g_host, .iov_len = strlen(g_host)},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = ":path", .iov_len = 5},
            .value  = {.iov_base = g_url_path, .iov_len = strlen(g_url_path)},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "content-type", .iov_len = 12},
            .value  = {.iov_base = "text/plain", .iov_len = 10},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "content-length", .iov_len = 14},
            .value  = {.iov_base = content_len, .iov_len = strlen(content_len)},
            .flags  = 0,
        },
    };

    if (g_test_case == 29) {
        memset(test_long_value, 'a', XQC_TEST_LONG_HEADER_LEN - 1);

        xqc_http_header_t test_long_hdr = {
            .name   = {.iov_base = "long_filed_line", .iov_len = 15},
            .value  = {.iov_base = test_long_value, .iov_len = strlen(test_long_value)},
            .flags  = 0,
        };

        header[header_size] = test_long_hdr;
        header_size++;
    }

    if (g_test_case == 34) {

        xqc_http_header_t uppercase_name_hdr = {
            .name   = {.iov_base = "UpperCaseFiledLineName", .iov_len = 22},
            .value  = {.iov_base = "UpperCaseFiledLineValue", .iov_len = 23},
            .flags  = 0,
        };
        header[header_size] = uppercase_name_hdr;
        header_size++;

        xqc_http_header_t lowcase_start_hdr = {
            .name   = {.iov_base = "filelineNamewithLowerCaseStart", .iov_len = 30},
            .value  = {.iov_base = "UpperCaseFiledLineValue", .iov_len = 23},
            .flags  = 0,
        };
        header[header_size] = lowcase_start_hdr;
        header_size++;

        memset(test_long_value, 'A', 1024);
    
        xqc_http_header_t test_long_hdr = {
            .name   = {.iov_base = test_long_value, .iov_len = 1024},
            .value  = {.iov_base = "header_with_long_name", .iov_len = 21},
            .flags  = 0,
        };

        header[header_size] = test_long_hdr;
        header_size++;

        header[header_size] = lowcase_start_hdr;
        header_size++;
    }

    if (g_header_cnt > 0) {
        for (int i = 0; i < g_header_cnt; i++) {
            char *pos = strchr(g_headers[i], ':');
            if (pos == NULL) {
                continue;
            }
            header[header_size].name.iov_base = g_headers[i];
            header[header_size].name.iov_len = pos - g_headers[i];
            header[header_size].value.iov_base = pos + 1;
            header[header_size].value.iov_len = strlen(pos+1);
            header[header_size].flags = 0;
            header_size++;
        }
    }

    while (header_size < g_header_num) {
        int m = 0, n = 0;
        m = rand();
        n = rand();
        header[header_size].name.iov_base = g_header_key;
        header[header_size].name.iov_len = m%(MAX_HEADER_KEY_LEN - 1) + 1;
        header[header_size].value.iov_base = g_header_value;
        header[header_size].value.iov_len = n%(MAX_HEADER_VALUE_LEN - 1) + 1;
        header[header_size].flags = 0;
        header_size++;
    }

    xqc_http_headers_t headers = {
        .headers = header,
        .count  = header_size,
    };

    int header_only = g_is_get;
    if (g_is_get) {
         header[0].value.iov_base = "GET";
         header[0].value.iov_len = sizeof("GET") - 1;
    }

    /* send header */
    if (user_stream->header_sent == 0) {
        if (g_test_case == 30 || g_test_case == 37 || g_test_case == 38) {
            ret = xqc_h3_request_send_headers(h3_request, &headers, 0);

        } else  {
            ret = xqc_h3_request_send_headers(h3_request, &headers, header_only);
        }

        if (ret < 0) {
            printf("xqc_h3_request_send_headers error %zd\n", ret);
            return ret;

        } else {
            printf("xqc_h3_request_send_headers success size=%zd\n", ret);
            user_stream->header_sent = 1;
        }

        if (g_test_case == 30) {
            usleep(200*1000);
            ret = xqc_h3_request_send_headers(h3_request, &headers, header_only);
            if (ret < 0) {
                printf("xqc_h3_request_send_headers error %zd\n", ret);
                return ret;

            } else {
                printf("xqc_h3_request_send_headers success size=%zd\n", ret);
            }
        }

        if (g_test_case == 37) {
            header_only = 1;
            struct timeval finish = {1, 0};
            ctx.ev_delay = event_new(eb, -1, 0, xqc_client_request_send_fin_only, user_stream);
            event_add(ctx.ev_delay, &finish);

        } else if (g_test_case == 38) {
            header_only = 1;
            ret = xqc_h3_request_finish(h3_request);
            if (ret < XQC_OK) {
                printf("xqc_h3_request_finish fail, error %zd\n", ret);
                return ret;
            }
            
        }
    }

    if (header_only) {
        return 0;
    }

    int fin = 1;
    if (g_test_case == 4 || g_test_case == 31 || g_test_case == 35 || g_test_case == 36) { /* test fin_only */
        fin = 0;
    }

    if (user_stream->send_body) {
        memset(user_stream->send_body, 0, user_stream->send_body_len);
    }

    /* send body */
    if (user_stream->send_offset < user_stream->send_body_len) {
        ret = xqc_h3_request_send_body(h3_request, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, fin);
        if (ret == -XQC_EAGAIN) {
            return 0;

        } else if (ret < 0) {
            printf("xqc_h3_request_send_body error %zd\n", ret);
            return 0;

        } else {
            user_stream->send_offset += ret;
            printf("xqc_h3_request_send_body sent:%zd, offset=%"PRIu64"\n", ret, user_stream->send_offset);
        }
    }

    /* send trailer header */
    if (user_stream->send_offset == user_stream->send_body_len) {
        if (g_test_case == 31) {
            ret = xqc_h3_request_send_headers(h3_request, &headers, 1);
            if (ret < 0) {
                printf("xqc_h3_request_send_headers error %zd\n", ret);
                return ret;

            } else {
                printf("xqc_h3_request_send_headers success size=%zd\n", ret);
            }
        }

        /* no tailer header, fin only */
        if (g_test_case == 35) {
            struct timeval finish = {1, 0};
            ctx.ev_delay = event_new(eb, -1, 0, xqc_client_request_send_fin_only, user_stream);
            event_add(ctx.ev_delay, &finish);

        } else if (g_test_case == 36) {
            ret = xqc_h3_request_finish(h3_request);
            if (ret != XQC_OK) {
                printf("send request finish error, ret: %zd\n", ret);

            } else {
                printf("send request finish suc\n");
            }
        }
    }

    if (g_test_case == 4) { /* test fin_only */
        if (user_stream->send_offset == user_stream->send_body_len) {
            fin = 1;
            usleep(200*1000);
            ret = xqc_h3_request_send_body(h3_request, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, fin);
            printf("xqc_h3_request_send_body sent:%zd, offset=%"PRIu64", fin=1\n", ret, user_stream->send_offset);
        }
    }
    return 0;
}

int
xqc_client_request_write_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    //DEBUG;
    ssize_t ret = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    if (g_test_case == 1) { /* reset stream */
        xqc_h3_request_close(h3_request);
        return 0;
    }

    if (g_test_case == 2) { /* user close connection */
        xqc_h3_conn_close(ctx.engine, &user_stream->user_conn->cid);
        return 0;
    }

    if (g_test_case == 3) { /* close connection with error */
        return -1;
    }

    ret = xqc_client_request_send(h3_request, user_stream);
    return ret;
}

int
xqc_client_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag, void *user_data)
{
    //DEBUG;
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    if (g_test_case == 21) { /* reset stream */
        xqc_h3_request_close(h3_request);
        return 0;
    }

    if (g_test_case == 28) { /* Send header after reset stream */
        xqc_h3_request_close(h3_request);
        xqc_http_header_t header = {
            .name = {
                .iov_base = "name",
                .iov_len = sizeof("name")
            },
            .value = {
                .iov_base = "value",
                .iov_len = sizeof("value")
            },
        };

        xqc_http_headers_t headers = {
            .headers = &header,
            .count = 1,
        };

        ssize_t sent = xqc_h3_request_send_headers(h3_request, &headers, 1);
        if (sent < 0) {
            printf("send headers error\n");
        }

        return 0;
    }

    /* stream read notify fail */
    if (g_test_case == 12) {
        return -1;
    }

    if ((flag & XQC_REQ_NOTIFY_READ_HEADER) || (flag & XQC_REQ_NOTIFY_READ_TRAILER)) {
        xqc_http_headers_t *headers;
        headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            printf("xqc_h3_request_recv_headers error\n");
            return -1;
        }

        for (int i = 0; i < headers->count; i++) {
            printf("%s = %s\n", (char *)headers->headers[i].name.iov_base, (char *)headers->headers[i].value.iov_base);
        }

        user_stream->header_recvd = 1;

        if (fin) {
            /* only header, receive request completed */
            user_stream->recv_fin = 1;
            return 0;
        }

        /* continue to receive body */
    }

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {

        char buff[4096] = {0};
        size_t buff_size = 4096;

        int save = g_save_body;

        if (save && user_stream->recv_body_fp == NULL) {
            user_stream->recv_body_fp = fopen(g_write_file, "wb");
            if (user_stream->recv_body_fp == NULL) {
                printf("open error\n");
                return -1;
            }
        }

        if (g_echo_check && user_stream->recv_body == NULL) {
            user_stream->recv_body = malloc(user_stream->send_body_len);
            if (user_stream->recv_body == NULL) {
                printf("recv_body malloc error\n");
                return -1;
            }
        }

        ssize_t read;
        ssize_t read_sum = 0;
        do {
            read = xqc_h3_request_recv_body(h3_request, buff, buff_size, &fin);
            if (read == -XQC_EAGAIN) {
                break;

            } else if (read < 0) {
                printf("xqc_h3_request_recv_body error %zd\n", read);
                return 0;
            }

            if (save && fwrite(buff, 1, read, user_stream->recv_body_fp) != read) {
                printf("fwrite error\n");
                return -1;
            }

            if (save) {
                fflush(user_stream->recv_body_fp);
            }

            /* write received body to memory */
            if (g_echo_check && user_stream->recv_body_len + read <= user_stream->send_body_len) {
                memcpy(user_stream->recv_body + user_stream->recv_body_len, buff, read);
            }

            read_sum += read;
            user_stream->recv_body_len += read;

        } while (read > 0 && !fin);

        if (flag & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
            fin = 1;
        }

        printf("xqc_h3_request_recv_body read:%zd, offset:%zu, fin:%d\n", read_sum, user_stream->recv_body_len, fin);
    }


    if (flag & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
        fin = 1;

        printf("h3 fin only received\n");
    }


    if (fin) {
        user_stream->recv_fin = 1;
        xqc_request_stats_t stats;
        stats = xqc_h3_request_get_stats(h3_request);
        xqc_msec_t now_us = xqc_now();
        printf("\033[33m>>>>>>>> request time cost:%"PRIu64" us, speed:%"PRIu64" K/s \n"
               ">>>>>>>> send_body_size:%zu, recv_body_size:%zu \033[0m\n",
               now_us - user_stream->start_time,
               (stats.send_body_size + stats.recv_body_size)*1000/(now_us - user_stream->start_time),
               stats.send_body_size, stats.recv_body_size);

        /* write to eval file */
        /*{
            FILE* fp = NULL;
            fp = fopen("eval_result.txt", "a+");
            if (fp == NULL) {
                exit(1);
            }

            fprintf(fp, "recv_size: %lu; cost_time: %lu\n", stats.recv_body_size, (uint64_t)((now_us - user_stream->start_time)/1000));
            fclose(fp);

            exit(0);
        }*/

    }
    return 0;
}

int
xqc_client_request_close_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t *)user_data;
    user_conn_t *user_conn = user_stream->user_conn;

    xqc_request_stats_t stats;
    stats = xqc_h3_request_get_stats(h3_request);
    printf("send_body_size:%zu, recv_body_size:%zu, send_header_size:%zu, recv_header_size:%zu, recv_fin:%d, err:%d\n",
           stats.send_body_size, stats.recv_body_size,
           stats.send_header_size, stats.recv_header_size,
           user_stream->recv_fin, stats.stream_err);

    if (g_echo_check) {
        int pass = 0;
        if (user_stream->recv_fin && user_stream->send_body_len == user_stream->recv_body_len
            && memcmp(user_stream->send_body, user_stream->recv_body, user_stream->send_body_len) == 0)
        {
            pass = 1;

            /* large data read once for all */
            if (user_stream->send_body_len >= 1024 * 1024 && user_stream->body_read_notify_cnt == 1) {
                pass = 0;
                printf("large body received once for all");
            }
        }
        printf(">>>>>>>> pass:%d\n", pass);
    }

    free(user_stream->send_body);
    free(user_stream->recv_body);
    free(user_stream);

    if (g_req_cnt < g_req_max) {
        user_stream = calloc(1, sizeof(user_stream_t));
        user_stream->user_conn = user_conn;
        user_stream->h3_request = xqc_h3_request_create(ctx.engine, &user_conn->cid, user_stream);
        if (user_stream->h3_request == NULL) {
            printf("xqc_h3_request_create error\n");
            free(user_stream);
            return 0;
        }

        xqc_client_request_send(user_stream->h3_request, user_stream);
        g_req_cnt++;
    }
    return 0;
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

    ssize_t recv_size = 0;
    ssize_t recv_sum = 0;

#ifdef __linux__
    int batch = 0;
    if (batch) {
#define VLEN 100
#define BUFSIZE XQC_PACKET_TMP_BUF_LEN
#define TIMEOUT 10
        struct sockaddr_in6 pa[VLEN];
        struct mmsghdr msgs[VLEN];
        struct iovec iovecs[VLEN];
        char bufs[VLEN][BUFSIZE+1];
        struct timespec timeout;
        int retval;

        do {
            memset(msgs, 0, sizeof(msgs));
            for (int i = 0; i < VLEN; i++) {
                iovecs[i].iov_base = bufs[i];
                iovecs[i].iov_len = BUFSIZE;
                msgs[i].msg_hdr.msg_iov = &iovecs[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
                msgs[i].msg_hdr.msg_name = &pa[i];
                msgs[i].msg_hdr.msg_namelen = user_conn->peer_addrlen;
            }

            timeout.tv_sec = TIMEOUT;
            timeout.tv_nsec = 0;

            retval = recvmmsg(fd, msgs, VLEN, 0, &timeout);
            if (retval == -1) {
                break;
            }

            uint64_t recv_time = xqc_now();
            for (int i = 0; i < retval; i++) {
                recv_sum += msgs[i].msg_len;

                if (xqc_engine_packet_process(ctx.engine, iovecs[i].iov_base, msgs[i].msg_len,
                                              user_conn->local_addr, user_conn->local_addrlen,
                                              user_conn->peer_addr, user_conn->peer_addrlen,
                                              (xqc_msec_t)recv_time, user_conn) != XQC_OK) 
                {
                    printf("xqc_server_read_handler: packet process err\n");
                    return;
                }
            }
        } while (retval > 0);
        goto finish_recv;
    }
#endif

    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];

    static ssize_t last_rcv_sum = 0;
    static ssize_t rcv_sum = 0;

    do {
        recv_size = recvfrom(fd, 
                             packet_buf, sizeof(packet_buf), 0, 
                             user_conn->peer_addr, &user_conn->peer_addrlen);
        if (recv_size < 0 && get_last_sys_errno() == EAGAIN) {
            break;
        }

        if (recv_size < 0) {
            printf("recvfrom: recvmsg = %zd(%s)\n", recv_size, strerror(get_last_sys_errno()));
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
                printf("getsockname error, errno: %d\n", get_last_sys_errno());
                break;
            }
            user_conn->local_addrlen = tmp;
        }

        uint64_t recv_time = xqc_now();
        g_last_sock_op_time = recv_time;


        if (TEST_DROP) continue;

        if (g_test_case == 6) { /* socket recv fail */
            g_test_case = -1;
            break;
        }

        if (g_test_case == 8) { /* packet with wrong cid */
            g_test_case = -1;
            recv_size = sizeof(XQC_TEST_SHORT_HEADER_PACKET_A) - 1;
            memcpy(packet_buf, XQC_TEST_SHORT_HEADER_PACKET_A, recv_size);
        }

        static char copy[XQC_PACKET_TMP_BUF_LEN];

        if (g_test_case == 9) { /* duplicate packet */
            memcpy(copy, packet_buf, recv_size);
            again:;
        }

        if (g_test_case == 10) { /* illegal packet */
            g_test_case = -1;
            recv_size = sizeof(XQC_TEST_SHORT_HEADER_PACKET_B) - 1;
            memcpy(packet_buf, XQC_TEST_SHORT_HEADER_PACKET_B, recv_size);
        }

        /* amplification limit */
        if (g_test_case == 25) {
            static int loss_num = 0;
            loss_num++;
            /* continuous loss to make server at amplification limit */
            if (loss_num >= 1 && loss_num <= 10) {
                continue;
            }
        }

        if (xqc_engine_packet_process(ctx.engine, packet_buf, recv_size,
                                      user_conn->local_addr, user_conn->local_addrlen,
                                      user_conn->peer_addr, user_conn->peer_addrlen,
                                      (xqc_msec_t)recv_time, user_conn) != XQC_OK)
        {
            printf("xqc_client_read_handler: packet process err\n");
            return;
        }

        if (g_test_case == 9) { /* duplicate packet */
            g_test_case = -1;
            memcpy(packet_buf, copy, recv_size);
            goto again;
        }

    } while (recv_size > 0);

    if ((xqc_now() - last_recv_ts) > 200000) {
        printf("recving rate: %.3lf Kbps\n", (rcv_sum - last_rcv_sum) * 8.0 * 1000 / (xqc_now() - last_recv_ts));
        last_recv_ts = xqc_now();
        last_rcv_sum = rcv_sum;
    }

finish_recv:
    printf("recvfrom size:%zu\n", recv_sum);
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


static void
xqc_client_engine_callback(int fd, short what, void *arg)
{
    printf("timer wakeup now:%"PRIu64"\n", xqc_now());
    client_ctx_t *ctx = (client_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}

static void
xqc_client_timeout_callback(int fd, short what, void *arg)
{
    printf("xqc_client_timeout_callback now %"PRIu64"\n", xqc_now());
    user_conn_t *user_conn = (user_conn_t *) arg;
    int rc;
    static int restart_after_a_while = 1;

    /* write to eval file */
    /*{
        FILE* fp = NULL;
        fp = fopen("eval_result.txt", "a+");
        if (fp == NULL) {
            exit(1);
        }

        fprintf(fp, "recv_size: %u; cost_time: %u\n", 11, 60 * 1000);
        fclose(fp);

    }*/
    //Test case 15: testing restart from idle
    if (restart_after_a_while && g_test_case == 15) {
        restart_after_a_while--;
        //we don't care the memory leak caused by user_stream. It's just for one-shot testing. :D
        user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
        memset(user_stream, 0, sizeof(user_stream_t));
        user_stream->user_conn = user_conn;
        printf("gtest 15: restart from idle!\n");
        user_stream->stream = xqc_stream_create(ctx.engine, &(user_conn->cid), user_stream);
        if (user_stream->stream == NULL) {
            printf("xqc_stream_create error\n");
            goto conn_close;
        }
        xqc_client_stream_send(user_stream->stream, user_stream);
        struct timeval tv;
        tv.tv_sec = g_conn_timeout;
        tv.tv_usec = 0;
        event_add(user_conn->ev_timeout, &tv);
        printf("scheduled a new stream request\n");
        return;
    }

    if (xqc_now() - g_last_sock_op_time < (uint64_t)g_conn_timeout * 1000000) {
        struct timeval tv;
        tv.tv_sec = g_conn_timeout;
        tv.tv_usec = 0;
        event_add(user_conn->ev_timeout, &tv);
        return;
    }

conn_close:
    rc = xqc_conn_close(ctx.engine, &user_conn->cid);
    if (rc) {
        printf("xqc_conn_close error\n");
        return;
    }
    //event_base_loopbreak(eb);
}


int
xqc_client_open_log_file(void *engine_user_data)
{
    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    //ctx->log_fd = open("/home/jiuhai.zjh/ramdisk/clog", (O_WRONLY | O_APPEND | O_CREAT), 0644);
    ctx->log_fd = open(g_log_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return 0;
}

int
xqc_client_close_log_file(void *engine_user_data)
{
    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        return -1;
    }
    close(ctx->log_fd);
    return 0;
}


void 
xqc_client_write_log(xqc_log_level_t lvl, const void *buf, size_t count, void *engine_user_data)
{
    unsigned char log_buf[XQC_MAX_LOG_LEN + 1];

    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        printf("xqc_client_write_log fd err\n");
        return;
    }

    int log_len = snprintf(log_buf, XQC_MAX_LOG_LEN + 1, "%s\n", (char *)buf);
    if (log_len < 0) {
        printf("xqc_client_write_log err\n");
        return;
    }

    int write_len = write(ctx->log_fd, log_buf, log_len);
    if (write_len < 0) {
        printf("write log failed, errno: %d\n", get_last_sys_errno());
    }
}


/**
 * key log functions
 */

int
xqc_client_open_keylog_file(client_ctx_t *ctx)
{
    ctx->keylog_fd = open("./ckeys.log", (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->keylog_fd <= 0) {
        return -1;
    }

    return 0;
}

int
xqc_client_close_keylog_file(client_ctx_t *ctx)
{
    if (ctx->keylog_fd <= 0) {
        return -1;
    }

    close(ctx->keylog_fd);
    ctx->keylog_fd = 0;
    return 0;
}


void 
xqc_keylog_cb(const char *line, void *user_data)
{
    client_ctx_t *ctx = (client_ctx_t*)user_data;
    if (ctx->keylog_fd <= 0) {
        printf("write keys error!\n");
        return;
    }

    int write_len = write(ctx->keylog_fd, line, strlen(line));
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", get_last_sys_errno());
        return;
    }

    write_len = write(ctx->keylog_fd, "\n", 1);
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", get_last_sys_errno());
    }
}


int 
xqc_client_cert_verify(const unsigned char *certs[], 
    const size_t cert_len[], size_t certs_len, void *conn_user_data)
{
    /* self-signed cert used in test cases, return >= 0 means success */
    return 0;
}


void usage(int argc, char *argv[]) {
    char *prog = argv[0];
    char *const slash = strrchr(prog, '/');
    if (slash) {
        prog = slash + 1;
    }
    printf(
"Usage: %s [Options]\n"
"\n"
"Options:\n"
"   -a    Server addr.\n"
"   -p    Server port.\n"
"   -P    Number of Parallel requests per single connection. Default 1.\n"
"   -n    Total number of requests to send. Defaults 1.\n"
"   -c    Congestion Control Algorithm. r:reno b:bbr c:cubic B:bbr2 bbr+ bbr2+\n"
"   -C    Pacing on.\n"
"   -t    Connection timeout. Default 3 seconds.\n"
"   -T    Transport layer. No HTTP3.\n"
"   -1    Force 1RTT.\n"
"   -s    Body size to send.\n"
"   -w    Write received body to file.\n"
"   -r    Read sending body from file. priority s > r\n"
"   -l    Log level. e:error d:debug.\n"
"   -E    Echo check on. Compare sent data with received data.\n"
"   -d    Drop rate ‰.\n"
"   -u    Url. default https://test.xquic.com/path/resource\n"
"   -H    Header. eg. key:value\n"
"   -h    Host & sni. eg. test.xquic.com\n"
"   -G    GET on. Default is POST\n"
"   -x    Test case ID\n"
"   -N    No encryption\n"
"   -6    IPv6\n"
"   -V    Force cert verification. 0: don't allow self-signed cert. 1: allow self-signed cert.\n"
"   -q    name-value pair num of request header, default and larger than 6\n"
"   -o    Output log file path, default ./clog\n"
, prog);
}

int main(int argc, char *argv[]) {

    g_req_cnt = 0;
    g_req_max = 1;
    g_send_body_size = 1024*1024;
    g_send_body_size_defined = 0;
    g_save_body = 0;
    g_read_body = 0;
    g_echo_check = 0;
    g_drop_rate = 0;
    g_spec_url = 0;
    g_is_get = 0;
    g_test_case = 0;
    g_ipv6 = 0;
    g_no_crypt = 0;

    char server_addr[64] = TEST_SERVER_ADDR;
    int server_port = TEST_SERVER_PORT;
    int req_paral = 1;
    char c_cong_ctl = 'b';
    char c_log_level = 'd';
    int c_cong_plus = 0;
    int pacing_on = 0;
    int transport = 0;
    int use_1rtt = 0;
    strcpy(g_log_path, "./clog");

    int ch = 0;
    while ((ch = getopt(argc, argv, "a:p:P:n:c:Ct:T1s:w:r:l:Ed:u:H:h:Gx:6NMi:V:q:o:")) != -1) {
        switch (ch) {
        case 'a': /* Server addr. */
            printf("option addr :%s\n", optarg);
            snprintf(server_addr, sizeof(server_addr), optarg);
            break;
        case 'p': /* Server port. */
            printf("option port :%s\n", optarg);
            server_port = atoi(optarg);
            break;
        case 'P': /* Number of Parallel requests per single connection. Default 1. */
            printf("option req_paral :%s\n", optarg);
            req_paral = atoi(optarg);
            break;
        case 'n': /* Total number of requests to send. Defaults 1. */
            printf("option req_max :%s\n", optarg);
            g_req_max = atoi(optarg);
            break;
        case 'c': /* Congestion Control Algorithm. r:reno b:bbr c:cubic B:bbr2 bbr+ bbr2+ */
            c_cong_ctl = optarg[0];
            if (strncmp("bbr2", optarg, 4) == 0) {
                c_cong_ctl = 'B';
            }

            if (strncmp("bbr2+", optarg, 5) == 0
                || strncmp("bbr+", optarg, 4) == 0)
            {
                c_cong_plus = 1;
            }
            printf("option cong_ctl : %c: %s: plus? %d\n", c_cong_ctl, optarg, c_cong_plus);
            break;
        case 'C': /* Pacing on */
            printf("option pacing :%s\n", "on");
            pacing_on = 1;
            break;
        case 't': /* Connection timeout. Default 3 seconds. */
            printf("option g_conn_timeout :%s\n", optarg);
            g_conn_timeout = atoi(optarg);
            break;
        case 'T': /* Transport layer. No HTTP3. */
            printf("option transport :%s\n", "on");
            transport = 1;
            break;
        case '1': /* Force 1RTT. */
            printf("option 1RTT :%s\n", "on");
            use_1rtt = 1;
            break;
        case 's': /* Body size to send. */
            printf("option send_body_size :%s\n", optarg);
            g_send_body_size = atoi(optarg);
            g_send_body_size_defined = 1;
            if (g_send_body_size > MAX_BUF_SIZE) {
                printf("max send_body_size :%d\n", MAX_BUF_SIZE);
                exit(0);
            }
            break;
        case 'w': /* Write received body to file. */
            printf("option save body :%s\n", optarg);
            snprintf(g_write_file, sizeof(g_write_file), optarg);
            g_save_body = 1;
            break;
        case 'r': /* Read sending body from file. priority s > r */
            printf("option read body :%s\n", optarg);
            snprintf(g_read_file, sizeof(g_read_file), optarg);
            g_read_body = 1;
            break;
        case 'l': /* Log level. e:error d:debug. */
            printf("option log level :%s\n", optarg);
            c_log_level = optarg[0];
            break;
        case 'E': /* Echo check on. Compare sent data with received data. */
            printf("option echo check :%s\n", "on");
            g_echo_check = 1;
            break;
        case 'd': /* Drop rate ‰. */
            printf("option drop rate :%s\n", optarg);
            g_drop_rate = atoi(optarg);
            srand((unsigned)time(NULL));
            break;
        case 'u': /* Url. default https://test.xquic.com/path/resource */
            printf("option url :%s\n", optarg);
            snprintf(g_url, sizeof(g_url), optarg);
            g_spec_url = 1;
            sscanf(g_url, "%[^://]://%[^/]%s", g_scheme, g_host, g_url_path);
            break;
        case 'H': /* Header. eg. key:value */
            printf("option header :%s\n", optarg);
            snprintf(g_headers[g_header_cnt], sizeof(g_headers[g_header_cnt]), "%s", optarg);
            g_header_cnt++;
            break;
        case 'h': /* Host & sni. eg. test.xquic.com */
            printf("option host & sni :%s\n", optarg);
            snprintf(g_host, sizeof(g_host), optarg);
            break;
        case 'G': /* GET on. Default is POST */
            printf("option get :%s\n", "on");
            g_is_get = 1;
            break;
        case 'x': /* Test case ID */
            printf("option test case id: %s\n", optarg);
            g_test_case = atoi(optarg);
            break;
        case '6': /* IPv6 */
            printf("option IPv6 :%s\n", "on");
            g_ipv6 = 1;
            break;
        case 'N': /* No encryption */
            printf("option No crypt: %s\n", "yes");
            g_no_crypt = 1;
            break;
        case 'V': /* Force cert verification. 0: don't allow self-signed cert. 1: allow self-signed cert. */
            printf("option enable cert verify: %s\n", "yes");
            g_verify_cert = 1;
            g_verify_cert_allow_self_sign = atoi(optarg);
            break;
        case 'q': /* name-value pair num of request header, default and larger than 6. */
            printf("option name-value pair num: %s\n", optarg);
            g_header_num = atoi(optarg);
            break;
        case 'o':
            printf("option log path :%s\n", optarg);
            snprintf(g_log_path, sizeof(g_log_path), optarg);
            break;
        default:
            printf("other option :%c\n", ch);
            usage(argc, argv);
            exit(0);
        }

    }

    memset(g_header_key, 'k', sizeof(g_header_key));
    memset(g_header_value, 'v', sizeof(g_header_value));
    memset(&ctx, 0, sizeof(ctx));

    xqc_client_open_keylog_file(&ctx);
    xqc_client_open_log_file(&ctx);

    xqc_platform_init_env();

    xqc_engine_ssl_config_t  engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    /* client does not need to fill in private_key_file & cert_file */
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    if (g_test_case == 27) {
        engine_ssl_config.ciphers = "TLS_CHACHA20_POLY1305_SHA256";
    }

    xqc_engine_callback_t callback = {
        .set_event_timer = xqc_client_set_event_timer, /* call xqc_engine_main_logic when the timer expires */
        .log_callbacks = {
            .xqc_log_write_err = xqc_client_write_log,
            .xqc_log_write_stat = xqc_client_write_log,
        },
        .keylog_cb = xqc_keylog_cb,
    };

    xqc_transport_callbacks_t tcbs = {
        .write_socket = xqc_client_write_socket,
        .save_token = xqc_client_save_token,
        .save_session_cb = save_session_cb,
        .save_tp_cb = save_tp_cb,
        .cert_verify_cb = xqc_client_cert_verify,
        .conn_closing = xqc_client_conn_closing_notify,
    };

    xqc_cong_ctrl_callback_t cong_ctrl;
    uint32_t cong_flags = 0;
    if (c_cong_ctl == 'b') {
        cong_ctrl = xqc_bbr_cb;
        cong_flags = XQC_BBR_FLAG_NONE;
#if XQC_BBR_RTTVAR_COMPENSATION_ENABLED
        if (c_cong_plus) {
            cong_flags |= XQC_BBR_FLAG_RTTVAR_COMPENSATION;
        }
#endif
    }
#ifndef XQC_DISABLE_RENO
    else if (c_cong_ctl == 'r') {
        cong_ctrl = xqc_reno_cb;
    }
#endif
    else if (c_cong_ctl == 'c') {
        cong_ctrl = xqc_cubic_cb;
    }
#ifdef XQC_ENABLE_BBR2
    else if (c_cong_ctl == 'B') {
        cong_ctrl = xqc_bbr2_cb;
        cong_flags = XQC_BBR2_FLAG_NONE;
#if XQC_BBR2_PLUS_ENABLED
        if (c_cong_plus) {
            cong_flags |= XQC_BBR2_FLAG_RTTVAR_COMPENSATION;
            cong_flags |= XQC_BBR2_FLAG_FAST_CONVERGENCE;
        }
#endif
    }
#endif
    else {
        printf("unknown cong_ctrl, option is b, r, c, B, bbr+, bbr2+\n");
        return -1;
    }
    printf("congestion control flags: %x\n", cong_flags);

    xqc_conn_settings_t conn_settings = {
        .pacing_on  =   pacing_on,
        .ping_on    =   0,
        .cong_ctrl_callback = cong_ctrl,
        .cc_params  =   {.customize_on = 1, .init_cwnd = 32, .cc_optimization_flags = cong_flags},
        //.so_sndbuf  =   1024*1024,
        .proto_version = XQC_VERSION_V1,
        .spurious_loss_detect_on = 0,
        .keyupdate_pkt_threshold = 0,
    };

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        return -1;
    }
    config.cfg_log_level = c_log_level == 'e' ? XQC_LOG_ERROR : (c_log_level == 'i' ? XQC_LOG_INFO : c_log_level == 'w'? XQC_LOG_STATS: XQC_LOG_DEBUG);

    /* test different cid_len */
    if (g_test_case == 13) {
        config.cid_len = XQC_MAX_CID_LEN;
    }

    /* check draft-29 version */
    if (g_test_case == 17) {
        conn_settings.proto_version = XQC_IDRAFT_VER_29;
    }

#if defined(XQC_SUPPORT_SENDMMSG) && !defined(XQC_SYS_WINDOWS)
    if (g_test_case == 20) { /* test sendmmsg */
        printf("test sendmmsg!\n");
        tcbs.write_mmsg = xqc_client_write_mmsg;
        config.sendmmsg_on = 1;
    }
#endif

    if (g_test_case == 24) {
        conn_settings.idle_time_out = 10000;
    }

    /* test spurious loss detect */
    if (g_test_case == 26) {
        conn_settings.spurious_loss_detect_on = 1;
    }

    /* test key update */
    if (g_test_case == 40) {
        conn_settings.keyupdate_pkt_threshold = 30;
    }

    eb = event_base_new();

    ctx.ev_engine = event_new(eb, -1, 0, xqc_client_engine_callback, &ctx);

    ctx.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &config, &engine_ssl_config,
                                   &callback, &tcbs, &ctx);
    if (ctx.engine == NULL) {
        printf("xqc_engine_create error\n");
        return -1;
    }

    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify = xqc_client_h3_conn_create_notify,
            .h3_conn_close_notify = xqc_client_h3_conn_close_notify,
            .h3_conn_handshake_finished = xqc_client_h3_conn_handshake_finished,
            .h3_conn_ping_acked = xqc_client_h3_conn_ping_acked_notify,
        },
        .h3r_cbs = {
            .h3_request_close_notify = xqc_client_request_close_notify,
            .h3_request_read_notify = xqc_client_request_read_notify,
            .h3_request_write_notify = xqc_client_request_write_notify,
        }
    };

    /* init http3 context */
    int ret = xqc_h3_ctx_init(ctx.engine, &h3_cbs);
    if (ret != XQC_OK) {
        printf("init h3 context error, ret: %d\n", ret);
        return ret;
    }

    /* register transport callbacks */
    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs = {
            .conn_create_notify = xqc_client_conn_create_notify,
            .conn_close_notify = xqc_client_conn_close_notify,
            .conn_handshake_finished = xqc_client_conn_handshake_finished,
            .conn_ping_acked = xqc_client_conn_ping_acked_notify,
        },
        .stream_cbs = {
            .stream_write_notify = xqc_client_stream_write_notify,
            .stream_read_notify = xqc_client_stream_read_notify,
            .stream_close_notify = xqc_client_stream_close_notify,
        }
    };

    xqc_engine_register_alpn(ctx.engine, XQC_ALPN_TRANSPORT, 9, &ap_cbs);

    user_conn_t *user_conn = xqc_client_user_conn_create(server_addr, server_port, transport);
    if (user_conn == NULL) {
        printf("xqc_client_user_conn_create error\n");
        return -1;
    }

    unsigned char token[XQC_MAX_TOKEN_LEN];
    int token_len = XQC_MAX_TOKEN_LEN;
    token_len = xqc_client_read_token(token, token_len);
    if (token_len > 0) {
        user_conn->token = token;
        user_conn->token_len = token_len;
    }

    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

    if (g_verify_cert) {
        conn_ssl_config.cert_verify_flag |= XQC_TLS_CERT_FLAG_NEED_VERIFY;
        if (g_verify_cert_allow_self_sign) {
            conn_ssl_config.cert_verify_flag |= XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;
        }
    }

    char session_ticket_data[8192]={0};
    char tp_data[8192] = {0};

    int session_len = read_file_data(session_ticket_data, sizeof(session_ticket_data), "test_session");
    int tp_len = read_file_data(tp_data, sizeof(tp_data), "tp_localhost");

    if (session_len < 0 || tp_len < 0 || use_1rtt) {
        printf("sessoin data read error or use_1rtt\n");
        conn_ssl_config.session_ticket_data = NULL;
        conn_ssl_config.transport_parameter_data = NULL;

    } else {
        conn_ssl_config.session_ticket_data = session_ticket_data;
        conn_ssl_config.session_ticket_len = session_len;
        conn_ssl_config.transport_parameter_data = tp_data;
        conn_ssl_config.transport_parameter_data_len = tp_len;
    }


    const xqc_cid_t *cid;
    if (user_conn->h3) {
        if (g_test_case == 7) {user_conn->token_len = -1;} /* create connection fail */
        cid = xqc_h3_connect(ctx.engine, &conn_settings, user_conn->token, user_conn->token_len,
                             g_host, g_no_crypt, &conn_ssl_config, user_conn->peer_addr, 
                             user_conn->peer_addrlen, user_conn);
    } else {
        cid = xqc_connect(ctx.engine, &conn_settings, user_conn->token, user_conn->token_len,
                          "127.0.0.1", g_no_crypt, &conn_ssl_config, user_conn->peer_addr, 
                          user_conn->peer_addrlen, XQC_ALPN_TRANSPORT, user_conn);
    }

    if (cid == NULL) {
        printf("xqc_connect error\n");
        xqc_engine_destroy(ctx.engine);
        return 0;
    }

    /* copy cid to its own memory space to prevent crashes caused by internal cid being freed */
    memcpy(&user_conn->cid, cid, sizeof(*cid));

    for (int i = 0; i < req_paral; i++) {
        g_req_cnt++;
        user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
        user_stream->user_conn = user_conn;
        if (user_conn->h3) {
            if (g_test_case == 11) { /* create stream fail */
                xqc_cid_t tmp;
                xqc_h3_request_create(ctx.engine, &tmp, user_stream);
                continue;
            }

            user_stream->h3_request = xqc_h3_request_create(ctx.engine, cid, user_stream);
            if (user_stream->h3_request == NULL) {
                printf("xqc_h3_request_create error\n");
                continue;
            }

            xqc_client_request_send(user_stream->h3_request, user_stream);

        } else {
            user_stream->stream = xqc_stream_create(ctx.engine, cid, user_stream);
            if (user_stream->stream == NULL) {
                printf("xqc_stream_create error\n");
                continue;
            }

            xqc_client_stream_send(user_stream->stream, user_stream);
        }
    }

    last_recv_ts = xqc_now();
    event_base_dispatch(eb);

    event_free(user_conn->ev_socket);
    event_free(user_conn->ev_timeout);
    event_free(user_conn->rebinding_ev_socket);

    free(user_conn->peer_addr);
    free(user_conn->local_addr);
    free(user_conn);

    if (ctx.ev_delay) {
        event_free(ctx.ev_delay);
    }

    xqc_engine_destroy(ctx.engine);
    xqc_client_close_keylog_file(&ctx);
    xqc_client_close_log_file(&ctx);

    return 0;
}
