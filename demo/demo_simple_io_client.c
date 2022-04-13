/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "common.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <event2/event.h>
#include <xquic/xquic.h>


/* definition for quic */
#define MAX_SESSION_TICKET_LEN      2048    /* session ticket len */
#define MAX_TRANSPORT_PARAMS_LEN    2048    /* transport parameter len */
#define XQC_MAX_TOKEN_LEN           256     /* token len */

#define SESSION_TICKET_FILE         "session_ticket"
#define TRANSPORT_PARAMS_FILE       "transport_params"
#define TOKEN_FILE                  "token"

#define LOG_PATH "clog.log"
#define OUT_DIR  "."

#define DATA_SEND_BUF_SIZE          10 * 1024 * 1024
#define DATA_SEND_BUF_SEND_TIMES    99999
#define DATA_SEND_TIME_S            15

/* network arguments */
typedef struct {
    /* ipv4 or ipv6 */
    int     ipv6;

    struct sockaddr_storage addr;
    int                     addr_len;
    char                    server_addr[64];
    uint16_t                server_port;

    CC_TYPE             cc;     /* congestion control algorithm */
    int                 pacing; /* is pacing on */

} xqc_simple_io_cli_args_net_config_t;

typedef struct {
    char alpn[16];

    /* 0-rtt config */
    int  st_len;                        /* session ticket len */
    char st[MAX_SESSION_TICKET_LEN];    /* session ticket buf */
    int  tp_len;                        /* transport params len */
    char tp[MAX_TRANSPORT_PARAMS_LEN];  /* transport params buf */
    int  token_len;                     /* token len */
    char token[XQC_MAX_TOKEN_LEN];      /* token buf */

    uint8_t no_crypt;
    char *cipher_suites;                 /* cipher suites */

    uint8_t use_0rtt;                   /* 0-rtt switch, default turned off */
    uint64_t keyupdate_pkt_threshold;   /* packet limit of a single 1-rtt key, 0 for unlimited */

} xqc_simple_io_cli_args_quic_config_t;

/* environment config */
typedef struct {

    /* log path */
    char    log_path[256];
    int     log_level;

    /* out file */
    char    out_file_dir[256];

    /* key export */
    char    key_out_path[256];

} xqc_simple_io_cli_args_env_config_t;

typedef struct {
    /* network args */
    xqc_simple_io_cli_args_net_config_t   net_cfg;

    /* quic args */
    xqc_simple_io_cli_args_quic_config_t  quic_cfg;

    /* environment args */
    xqc_simple_io_cli_args_env_config_t   env_cfg;

} xqc_simple_io_cli_client_args_t;

typedef enum {
    emXQC_FILE_SEND_IDLE = 0,
    emXQC_FILE_SEND_STARTED,
    emXQC_FILE_SEND_FINISHED
} emXQC_FILE_SEND_STATE;

typedef struct {
    emXQC_FILE_SEND_STATE   state;

    uint8_t*    buf;
    size_t      buf_sz;
    size_t      buf_read_pos;

    size_t      send_repeat_num;
    size_t      send_repeat_cnt;
    uint8_t     fin_flag;

    size_t      total_sent_bytes;
    size_t      last_sent_bytes;

    xqc_usec_t  start_ts;
    xqc_usec_t  last_ts;
} xqc_data_send_t;

typedef struct xqc_simple_io_cli_ctx_s {
    xqc_engine_t        *engine;

    int                 log_fd;

    xqc_simple_io_cli_client_args_t args;

    int                 transport_fd;
    struct sockaddr_storage local_addr;
    struct sockaddr_storage peer_addr;

    struct event_base   *eb;
    struct event        *ev_engine;
    struct event        *ev_socket_r;
    struct event        *ev_socket_w;
    struct event        *ev_add_w_timer;

    xqc_cid_t           cid;
    xqc_data_send_t     data_send;

    xqc_demo_ring_queue_t   send_pkt_ring_queue;

} xqc_simple_io_cli_ctx_t;

/* the global unique client context */
static xqc_simple_io_cli_ctx_t gs_cli_ctx;


/**
 * engine callbacks
 **/
static void
xqc_simple_io_cli_set_event_timer(xqc_usec_t wake_after, void *eng_user_data)
{
    xqc_simple_io_cli_ctx_t *ctx = (xqc_simple_io_cli_ctx_t *)eng_user_data;
    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);
}

static void
xqc_simple_io_cli_write_log_file(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data)
{
    xqc_simple_io_cli_ctx_t *ctx = (xqc_simple_io_cli_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        return;
    }
    int write_len = write(ctx->log_fd, buf, size);
    if (write_len < 0) {
        printf("write log failed, errno: %d\n", errno);
        return;
    }
    write_len = write(ctx->log_fd, line_break, 1);
    if (write_len < 0) {
        printf("write log failed, errno: %d\n", errno);
    }
}

/**
 * transport callback
 **/
static ssize_t
xqc_simple_io_cli_write_socket(const unsigned char* buf, size_t size, const struct sockaddr* peer_addr,
                               socklen_t peer_addrlen, void* conn_user_data)
{
    xqc_simple_io_cli_ctx_t *ctx = (xqc_simple_io_cli_ctx_t *)conn_user_data;
    int ret;
    xqc_demo_addr_info_t addr_info;

    memcpy(&addr_info.addr, peer_addr, peer_addrlen);
    addr_info.addr_len = peer_addrlen;

    ret = xqc_demo_ring_queue_push2(&ctx->send_pkt_ring_queue,
                                    (uint8_t*)&addr_info, sizeof(xqc_demo_addr_info_t),
                                    (uint8_t*)buf, size);
    if (1 == ret) {
        printf("ring queue full, can't write.\n");
        return XQC_SOCKET_EAGAIN;
    }
    if (0 != ret) {
        printf("xqc_demo_ring_queue_push failed!\n");
        return -1;
    }
    return (ssize_t)size;
}

static void
xqc_simple_io_cli_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
    const xqc_cid_t *new_cid, void *user_data)
{
    xqc_simple_io_cli_ctx_t *ctx = user_data;
    memcpy(&ctx->cid, new_cid, sizeof(xqc_cid_t));
}

static void
xqc_simple_io_cli_save_session_cb(const char *data, size_t data_len, void *conn_user_data)
{
    FILE * fp  = fopen(SESSION_TICKET_FILE, "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        printf("save _session_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
}

static void
xqc_simple_io_cli_save_tp_cb(const char *data, size_t data_len, void *conn_user_data)
{
    FILE * fp = fopen(TRANSPORT_PARAMS_FILE, "wb");
    if (NULL == fp) {
        printf("open file for transport parameter error\n");
        return;
    }

    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        fclose(fp);
        return;
    }
    fclose(fp);
}

static void
xqc_simple_io_cli_save_token(const unsigned char *token, uint32_t token_len, void *conn_user_data)
{
    int fd = open(TOKEN_FILE, O_TRUNC | O_CREAT | O_WRONLY, S_IRWXU);
    if (fd < 0) {
        return;
    }

    ssize_t n = write(fd, token, token_len);
    if (n < token_len) {
        close(fd);
        return;
    }
    close(fd);
}

/**
 * connection callbacks
 **/
static int
xqc_simple_io_cli_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                     void *user_data, void *conn_proto_data)
{
    DEBUG;
    xqc_simple_io_cli_ctx_t *ctx = &gs_cli_ctx;
    xqc_conn_set_transport_user_data(conn, ctx);
    xqc_conn_set_alp_user_data(conn, ctx);
    memcpy(&ctx->cid, cid, sizeof(xqc_cid_t));
    printf("xqc_conn_is_ready_to_send_early_data: %d\n", xqc_conn_is_ready_to_send_early_data(conn));
    return 0;
}

static int
xqc_simple_io_cli_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                    void *user_data, void *conn_proto_data)
{
    DEBUG;
    xqc_simple_io_cli_ctx_t *ctx = user_data;
    event_base_loopbreak(ctx->eb);
    return 0;
}

/**
 * stream callbacks
 **/
static int
xqc_simple_io_cli_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    ssize_t sent_bytes;
    ssize_t want_send_bytes;
    xqc_usec_t cur_ts;
    uint64_t transport_speed_kB;
    xqc_simple_io_cli_ctx_t *ctx = (xqc_simple_io_cli_ctx_t *)user_data;
    xqc_data_send_t *data_send = &ctx->data_send;

    if (emXQC_FILE_SEND_FINISHED == data_send->state) {
        return 0;
    }

    if (emXQC_FILE_SEND_IDLE == data_send->state) {
        printf("Begin to send data!\n");
        data_send->start_ts = xqc_demo_now();
        data_send->last_ts = data_send->start_ts;
        data_send->state = emXQC_FILE_SEND_STARTED;
    }

    cur_ts = xqc_demo_now();
    if (cur_ts > (data_send->last_ts + 1000000)) {
        transport_speed_kB = ((data_send->total_sent_bytes - data_send->last_sent_bytes) * 1000000 /
                              ((cur_ts - data_send->last_ts))) / 1000;
        printf("Current speed: %" PRIu64 " kB/s\n", transport_speed_kB);
        data_send->last_sent_bytes = data_send->total_sent_bytes;
        data_send->last_ts = cur_ts;
    }

    /* End sending data after 10s */
    if (cur_ts > (data_send->start_ts + DATA_SEND_TIME_S * 1000000)) {
        data_send->fin_flag = 1;
    }

    while (1) {
        if (data_send->buf_read_pos >= data_send->buf_sz) {
            data_send->buf_read_pos = 0;
            data_send->send_repeat_cnt++;
            if (data_send->send_repeat_cnt >= data_send->send_repeat_num) {
                printf("in write_notify, error\n");
                data_send->state = emXQC_FILE_SEND_FINISHED;
                return 0;

            } else if (data_send->send_repeat_cnt + 1 >= data_send->send_repeat_num) {
                data_send->fin_flag = 1;
            }
        }

        want_send_bytes = data_send->buf_sz - data_send->buf_read_pos;
        sent_bytes = xqc_stream_send(stream,
                                     data_send->buf + data_send->buf_read_pos,
                                     want_send_bytes,
                                     data_send->fin_flag);
        if (-XQC_EAGAIN == sent_bytes) {
            return 0;

        } else if (sent_bytes <= 0) {
            printf("xqc_stream_send failed! sent_bytes: %zd, want send: %zu\n",
                     sent_bytes, want_send_bytes);
            return 0;

        } else {
            data_send->total_sent_bytes += sent_bytes;
            data_send->buf_read_pos += sent_bytes;
            if ((data_send->fin_flag == 1) && (sent_bytes == want_send_bytes)) {
                transport_speed_kB = (data_send->total_sent_bytes * 1000000 /
                                      (cur_ts - data_send->start_ts)) / 1000;
                xqc_conn_stats_t stats = xqc_conn_get_stats(ctx->engine, &ctx->cid);
                printf("Data sent! Average speed: %" PRIu64 " kB/s\n", transport_speed_kB);
                printf("Data size: %zu kB\n", data_send->total_sent_bytes / 1000);
                printf("Spent time: %" PRIu64 "ms\n", (cur_ts - data_send->start_ts) / 1000);
                printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%" PRIu64 " "
                       "early_data_flag:%d, conn_err:%d, ack_info:%s\n", stats.send_count, stats.lost_count,
                       stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err,
                       stats.ack_info);
                data_send->state = emXQC_FILE_SEND_FINISHED;
                return 0;
            }
        }
    }
}

static int
xqc_simple_io_cli_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    unsigned char fin = 0;
    char buff[4096] = {0};
    size_t buff_size = 4096;
    size_t min;

    ssize_t read_bytes;
    read_bytes = xqc_stream_recv(stream, (unsigned char*)buff, buff_size, &fin);
    if (read_bytes < 0) {
        printf("xqc_stream_recv failed! read_bytes: %zd\n", read_bytes);
    } else {
        min = MIN(read_bytes, buff_size);
        buff[min] = 0;
        printf("received: %s\n", buff);
    }

    return 0;
}

static int
xqc_simple_io_cli_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    return 0;
}

/**
 * transport callbacks
 **/
static int
xqc_simple_io_cli_transport_create_socket(int family)
{
    int size;
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("create socket failed, errno: %d\n", errno);
        return -1;
    }

    /* non-block */
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("set socket nonblock failed, errno: %d\n", errno);
        goto err;
    }

    /* send/recv buffer size */
    size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
        goto err;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
        goto err;
    }

    return fd;

err:
    close(fd);
    return -1;
}

static int
xqc_simple_io_cli_transport_setup(xqc_simple_io_cli_ctx_t *ctx)
{
    if (ctx->args.net_cfg.ipv6) {
        /* setup ipv6 udp socket */
        ctx->transport_fd = xqc_simple_io_cli_transport_create_socket(AF_INET6);
        if (ctx->transport_fd < 0) {
            goto err;
        }

    } else {
        /* setup ipv4 udp socket */
        ctx->transport_fd = xqc_simple_io_cli_transport_create_socket(AF_INET);
        if (ctx->transport_fd < 0) {
            goto err;
        }
    }

    return 0;

err:
    if (ctx->transport_fd > 0) {
        close(ctx->transport_fd);
        ctx->transport_fd = -1;
    }
    return -1;
}

/**
 * libevent functions
 **/
static void
xqc_simple_io_cli_event_engine_callback(int fd, short what, void *arg)
{
    xqc_simple_io_cli_ctx_t *ctx = (xqc_simple_io_cli_ctx_t *) arg;
    xqc_engine_main_logic(ctx->engine);
}

static void
xqc_simple_io_cli_event_socket_write_callback(int fd, short what, void *arg)
{
    xqc_simple_io_cli_ctx_t *ctx = (xqc_simple_io_cli_ctx_t *)arg;
    int ret;
    size_t data_size;
    size_t send_data_size;
    xqc_demo_addr_info_t *addr_info;
    uint8_t packet_buf[2048];

    ret = xqc_demo_ring_queue_pop(&ctx->send_pkt_ring_queue, packet_buf, sizeof(packet_buf), &data_size);
    if (1 == ret) {
        return;
    } else if (ret != 0) {
        printf("xqc_demo_ring_queue_pop failed!\n");
        return;
    }

    send_data_size = data_size - sizeof(xqc_demo_addr_info_t);
    addr_info = (xqc_demo_addr_info_t *)packet_buf;
    ret = sendto(fd, (uint8_t*)(addr_info + 1), send_data_size, 0,
                 (struct sockaddr*)(&addr_info->addr), addr_info->addr_len);
    if (ret != send_data_size) {
        printf("sendto failed! ret: %d, err: %s\n", ret, strerror(errno));
    }
}

static void
xqc_simple_io_cli_event_socket_read_callback(int fd, short what, void *arg)
{
    xqc_simple_io_cli_ctx_t *ctx = (xqc_simple_io_cli_ctx_t *)arg;
    ssize_t recv_size = 0;
    ssize_t recv_sum = 0;
    struct sockaddr addr;
    socklen_t addr_len = 0;
    unsigned char packet_buf[1500];

    do {
        recv_size = recvfrom(fd, packet_buf, sizeof(packet_buf), 0,
                             (struct sockaddr *)&addr, &addr_len);
        if (recv_size < 0 && errno == EAGAIN) {
            break;
        }

        if (recv_size < 0) {
            printf("!!!!!!!!!recvfrom: recvmsg = %zd err=%s\n", recv_size, strerror(errno));
            break;
        }
        recv_sum += recv_size;

        uint64_t recv_time = xqc_demo_now();
        xqc_int_t ret = xqc_engine_packet_process(ctx->engine, packet_buf, recv_size,
                                                  (struct sockaddr *)(&ctx->local_addr), sizeof(ctx->local_addr),
                                                  (struct sockaddr *)(&addr), addr_len,
                                                  (xqc_usec_t)recv_time, ctx);
        if (ret != XQC_OK) {
            printf("server_read_handler: packet process err, ret: %d\n", ret);
            return;
        }
    } while (recv_size > 0);

    xqc_engine_finish_recv(ctx->engine);
}

static void
xqc_simple_io_cli_event_add_write_callback(int fd, short what, void *arg)
{
    event_add(((xqc_simple_io_cli_ctx_t *)arg)->ev_socket_w, NULL);
}

static int
xqc_simple_io_cli_event_setup(xqc_simple_io_cli_ctx_t *ctx)
{
    ctx->eb = event_base_new();
    ctx->ev_engine = event_new(ctx->eb, -1, 0, xqc_simple_io_cli_event_engine_callback, ctx);

    ctx->ev_socket_r = event_new(ctx->eb, ctx->transport_fd, EV_READ | EV_PERSIST,
                                 xqc_simple_io_cli_event_socket_read_callback, ctx);
    event_add(ctx->ev_socket_r, NULL);
    ctx->ev_socket_w = event_new(ctx->eb, ctx->transport_fd, EV_WRITE | EV_PERSIST,
                                 xqc_simple_io_cli_event_socket_write_callback, ctx);
    event_add(ctx->ev_socket_w, NULL);

    ctx->ev_add_w_timer = event_new(ctx->eb, -1, 0,
                                    xqc_simple_io_cli_event_add_write_callback, ctx);
    return 0;
}

/**
 * setup engine
 **/
static void
xqc_simple_io_cli_usage(int argc, char *argv[])
{
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
            "   -c    Congestion Control Algorithm. r:reno b:bbr c:cubic B:bbr2\n"
            "   -C    Pacing on.\n"
            "   -S    cipher suites\n"
            "   -0    use 0-RTT\n"
            "   -D    save request body directory\n"
            "   -l    Log level. e:error d:debug.\n"
            "   -L    xuqic log directory.\n"
            "   -N    No encryption\n"
            "   -u    key update packet threshold\n"
            "   -6    IPv6\n"
            , prog);
}

static void xqc_simple_io_cli_parse_addr(xqc_simple_io_cli_client_args_t *args)
{
    if (args->net_cfg.ipv6) {
        args->net_cfg.addr.ss_family = AF_INET6;
        args->net_cfg.addr_len = sizeof(struct sockaddr_in6);
        struct sockaddr_in6 * addr = (struct sockaddr_in6 *)&args->net_cfg.addr;
        addr->sin6_port = htons(args->net_cfg.server_port);
        if (!inet_pton(AF_INET6, args->net_cfg.server_addr, &addr->sin6_addr)) {
            printf("Invalid ipv6 address: %s\n", args->net_cfg.server_addr);
            exit(-1);
        }

    } else {
        args->net_cfg.addr.ss_family = AF_INET;
        args->net_cfg.addr_len = sizeof(struct sockaddr_in);
        struct sockaddr_in * addr = (struct sockaddr_in *)&args->net_cfg.addr;
        addr->sin_port = htons(args->net_cfg.server_port);
        if (!inet_pton(AF_INET, args->net_cfg.server_addr, &addr->sin_addr)) {
            printf("Invalid ipv4 address: %s\n", args->net_cfg.server_addr);
            exit(-1);
        }
    }
}

static void
xqc_simple_io_cli_parse_args(int argc, char *argv[], xqc_simple_io_cli_client_args_t *args)
{
    int ch = 0;
    while ((ch = getopt(argc, argv, "a:p:c:CS:0D:l:L:Nu:6")) != -1) {
        switch (ch) {
            /* server ip */
            case 'a':
                printf("option addr: %s\n", optarg);
                snprintf(args->net_cfg.server_addr, sizeof(args->net_cfg.server_addr), "%s", optarg);
                break;

                /* server port */
            case 'p':
                printf("option port: %s\n", optarg);
                args->net_cfg.server_port = atoi(optarg);
                break;

                /* congestion control */
            case 'c':
                printf("option cong_ctl: %s\n", optarg);
                /* r:reno b:bbr c:cubic */
                switch (*optarg) {
                    case 'b':
                        args->net_cfg.cc = CC_TYPE_BBR;
                        break;
                    case 'c':
                        args->net_cfg.cc = CC_TYPE_CUBIC;
                        break;
                    case 'r':
                        args->net_cfg.cc = CC_TYPE_RENO;
                        break;
#ifdef XQC_ENABLE_BBR2
                    case 'B':
                        args->net_cfg.cc = CC_TYPE_BBR2;
                        break;
#endif
                    default:
                        printf("invalid cc flag: %c!\n", *optarg);
                        exit(-1);
                        break;
                }
                break;

                /* pacing */
            case 'C':
                printf("option pacing: %s\n", "on");
                args->net_cfg.pacing = 1;
                break;

                /* ssl cipher suites */
            case 'S':
                printf("option cipher suites: %s\n", optarg);
                args->quic_cfg.cipher_suites = optarg;
                break;

                /* 0rtt option */
            case '0':
                printf("option 0rtt\n");
                args->quic_cfg.use_0rtt = 1;
                break;

                /* out file directory */
            case 'D':
                printf("option save body dir: %s\n", optarg);
                strncpy(args->env_cfg.out_file_dir, optarg, sizeof(args->env_cfg.out_file_dir) - 1);
                break;

                /* log level */
            case 'l':
                printf("option log level: %s\n", optarg);
                /* e:error d:debug */
                args->env_cfg.log_level = optarg[0];
                break;

                /* log directory */
            case 'L':
                printf("option log directory: %s\n", optarg);
                strncpy(args->env_cfg.log_path, optarg, sizeof(args->env_cfg.log_path) - 1);
                break;

                /* no encryption */
            case 'N':
                printf("option No crypt: %s\n", "yes");
                args->quic_cfg.no_crypt = 1;
                break;

                /* key update packet threshold */
            case 'u':
                printf("key update packet threshold: %s\n", optarg);
                args->quic_cfg.keyupdate_pkt_threshold = atoi(optarg);
                break;

                /* ipv6 */
            case '6':
                printf("option IPv6: %s\n", "on");
                args->net_cfg.ipv6 = 1;
                break;

            default:
                printf("other option: %c\n", ch);
                xqc_simple_io_cli_usage(argc, argv);
                exit(0);
        }
    }
    xqc_simple_io_cli_parse_addr(args);
}

static int
xqc_simple_io_cli_close_log_file(xqc_simple_io_cli_ctx_t *ctx)
{
    if (ctx->log_fd <= 0) {
        return -1;
    }
    close(ctx->log_fd);
    return 0;
}

static int
xqc_simple_io_cli_open_log_file(xqc_simple_io_cli_ctx_t *ctx)
{
    ctx->log_fd = open(ctx->args.env_cfg.log_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return 0;
}

static int
xqc_simple_io_cli_read_token(char *token, unsigned token_len)
{
    int fd = open(TOKEN_FILE, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    ssize_t n = read(fd, token, token_len);
    close(fd);
    return n;
}

static void
xqc_simple_io_cli_init_0rtt(xqc_simple_io_cli_client_args_t *args)
{
    /* read session ticket */
    int ret = xqc_demo_read_file_data(args->quic_cfg.st,
                                      MAX_SESSION_TICKET_LEN, SESSION_TICKET_FILE);
    args->quic_cfg.st_len = ret > 0 ? ret : 0;

    /* read transport params */
    ret = xqc_demo_read_file_data(args->quic_cfg.tp,
                                  MAX_TRANSPORT_PARAMS_LEN, TRANSPORT_PARAMS_FILE);
    args->quic_cfg.tp_len = ret > 0 ? ret : 0;

    /* read token */
    ret = xqc_simple_io_cli_read_token(
            args->quic_cfg.token, XQC_MAX_TOKEN_LEN);
    args->quic_cfg.token_len = ret > 0 ? ret : 0;
}

static void
xqc_simple_io_cli_init_engine_ssl_config(xqc_engine_ssl_config_t* cfg, xqc_simple_io_cli_client_args_t *args)
{
    memset(cfg, 0, sizeof(xqc_engine_ssl_config_t));
    if (args->quic_cfg.cipher_suites) {
        cfg->ciphers = args->quic_cfg.cipher_suites;

    } else {
        cfg->ciphers = XQC_TLS_CIPHERS;
    }

    cfg->groups = XQC_TLS_GROUPS;
}

static void
xqc_simple_io_cli_init_conn_ssl_config(xqc_conn_ssl_config_t *conn_ssl_config,
                                       xqc_simple_io_cli_client_args_t *args)
{
    memset(conn_ssl_config, 0, sizeof(xqc_conn_ssl_config_t));

    /* set session ticket and transport parameter args */
    if (args->quic_cfg.st_len < 0 || args->quic_cfg.tp_len < 0) {
        conn_ssl_config->session_ticket_data = NULL;
        conn_ssl_config->transport_parameter_data = NULL;

    } else {
        conn_ssl_config->session_ticket_data = args->quic_cfg.st;
        conn_ssl_config->session_ticket_len = args->quic_cfg.st_len;
        conn_ssl_config->transport_parameter_data = args->quic_cfg.tp;
        conn_ssl_config->transport_parameter_data_len = args->quic_cfg.tp_len;
    }
}

static void
xqc_simple_io_cli_init_conneciton_settings(xqc_conn_settings_t* settings,
                                           xqc_simple_io_cli_client_args_t *args)
{
    xqc_cong_ctrl_callback_t cong_ctrl;
    switch (args->net_cfg.cc) {
        case CC_TYPE_BBR:
            cong_ctrl = xqc_bbr_cb;
            break;

        case CC_TYPE_CUBIC:
            cong_ctrl = xqc_reno_cb;
            break;

        case CC_TYPE_RENO:
            cong_ctrl = xqc_cubic_cb;
            break;

#ifdef XQC_ENABLE_BBR2
        case CC_TYPE_BBR2:
            cong_ctrl = xqc_bbr2_cb;
            break;
#endif

        default:
            printf("Invalid cc flag: %d!\n", args->net_cfg.cc);
            exit(-1);
            break;
    }

    memset(settings, 0, sizeof(xqc_conn_settings_t));

    settings->pacing_on = args->net_cfg.pacing;
    settings->cong_ctrl_callback = cong_ctrl;
    settings->so_sndbuf = 1024*1024;
    settings->proto_version = XQC_VERSION_V1;
    settings->spurious_loss_detect_on = 1;

    settings->cc_params.customize_on = 1;
    settings->cc_params.init_cwnd = 16;
    settings->cc_params.expect_bw = UINT32_MAX;
    settings->cc_params.max_expect_bw = UINT32_MAX;
}

/* set client args to default values */
static void
xqc_simple_io_cli_init_args(xqc_simple_io_cli_client_args_t *args)
{
    memset(args, 0, sizeof(xqc_simple_io_cli_client_args_t));

    /* net cfg */
    strncpy(args->net_cfg.server_addr, DEFAULT_SERVER_ADDR, sizeof(args->net_cfg.server_addr));
    args->net_cfg.server_port = DEFAULT_SERVER_PORT;

    /* env cfg */
    args->env_cfg.log_level = XQC_LOG_DEBUG;
    strncpy(args->env_cfg.log_path, LOG_PATH, sizeof(args->env_cfg.log_path));
    strncpy(args->env_cfg.out_file_dir, OUT_DIR, sizeof(args->env_cfg.out_file_dir));

    /* quic cfg */
    strncpy(args->quic_cfg.alpn, "alpn", sizeof(args->quic_cfg.alpn));
}

static void
xqc_simple_io_cli_init_data_sent(xqc_simple_io_cli_ctx_t *ctx)
{
    xqc_data_send_t *data_send = &ctx->data_send;
    bzero(data_send, sizeof(xqc_data_send_t));
    data_send->buf = (uint8_t*)malloc(DATA_SEND_BUF_SIZE);
    assert(data_send->buf);
    data_send->buf_sz = DATA_SEND_BUF_SIZE;
    data_send->send_repeat_num = DATA_SEND_BUF_SEND_TIMES;
}

static void xqc_simple_io_cli_free_data_sent(xqc_simple_io_cli_ctx_t *ctx)
{
    xqc_data_send_t *data_send = &ctx->data_send;
    if (data_send->buf) {
        free(data_send->buf);
    }
    bzero(data_send, sizeof(xqc_data_send_t));
}

static void
xqc_simple_io_cli_init_ctx(xqc_simple_io_cli_ctx_t *ctx)
{
    xqc_demo_ring_queue_init(&ctx->send_pkt_ring_queue,
                             RING_QUEUE_ELE_MAX_NUM, RING_QUEUE_ELE_BUF_SIZE);
    xqc_simple_io_cli_init_data_sent(ctx);
    xqc_simple_io_cli_open_log_file(ctx);
}

static void
xqc_simple_io_cli_free_ctx(xqc_simple_io_cli_ctx_t *ctx)
{
    xqc_demo_ring_queue_free(&ctx->send_pkt_ring_queue);
    xqc_simple_io_cli_free_data_sent(ctx);
    xqc_simple_io_cli_close_log_file(ctx);
}

static void
xqc_simple_io_cli_init_callback(xqc_engine_callback_t *cb, xqc_transport_callbacks_t *transport_cbs,
                                xqc_simple_io_cli_client_args_t* args)
{
    static xqc_engine_callback_t callback;
    bzero(&callback, sizeof(callback));
    callback.set_event_timer = xqc_simple_io_cli_set_event_timer;
    callback.log_callbacks.xqc_log_write_err = xqc_simple_io_cli_write_log_file;
    callback.log_callbacks.xqc_log_write_stat = xqc_simple_io_cli_write_log_file;

    static xqc_transport_callbacks_t tcb;
    bzero(&tcb, sizeof(tcb));
    tcb.write_socket = xqc_simple_io_cli_write_socket;
    tcb.conn_update_cid_notify = xqc_simple_io_cli_conn_update_cid_notify;
    tcb.save_token = xqc_simple_io_cli_save_token;
    tcb.save_session_cb = xqc_simple_io_cli_save_session_cb;
    tcb.save_tp_cb = xqc_simple_io_cli_save_tp_cb;

    *cb = callback;
    *transport_cbs = tcb;
}

static int
xqc_simple_io_cli_init_alpn_ctx(xqc_simple_io_cli_ctx_t *ctx)
{
    int ret = 0;

    xqc_app_proto_callbacks_t ap_cbs;
    bzero(&ap_cbs, sizeof(ap_cbs));
    ap_cbs.conn_cbs.conn_create_notify = xqc_simple_io_cli_conn_create_notify;
    ap_cbs.conn_cbs.conn_close_notify = xqc_simple_io_cli_conn_close_notify;
    ap_cbs.stream_cbs.stream_read_notify = xqc_simple_io_cli_stream_read_notify;
    ap_cbs.stream_cbs.stream_write_notify = xqc_simple_io_cli_stream_write_notify;
    ap_cbs.stream_cbs.stream_close_notify = xqc_simple_io_cli_stream_close_notify;

    ret = xqc_engine_register_alpn(ctx->engine, "transport", 9, &ap_cbs);
    if (XQC_OK != ret) {
        printf ("xqc_engine_register_alpn failed!\n");
    }

    return ret;
}

static
int xqc_simple_io_cli_setup_engine(xqc_simple_io_cli_ctx_t *ctx,
                          xqc_simple_io_cli_client_args_t *args)
{
    xqc_config_t config;
    xqc_engine_ssl_config_t engine_ssl_config;
    xqc_engine_callback_t callback;
    xqc_transport_callbacks_t transport_cbs;

    xqc_simple_io_cli_init_engine_ssl_config(&engine_ssl_config, args);

    xqc_simple_io_cli_init_callback(&callback, &transport_cbs, args);

    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        return XQC_ERROR;
    }

    if (xqc_simple_io_cli_transport_setup(ctx) != 0) {
        return XQC_ERROR;
    }

    xqc_simple_io_cli_event_setup(ctx);

    switch (args->env_cfg.log_level) {
        case 'd':
            config.cfg_log_level = XQC_LOG_DEBUG;
            break;
        case 'i':
            config.cfg_log_level = XQC_LOG_INFO;
            break;
        case 'w':
            config.cfg_log_level = XQC_LOG_WARN;
            break;
        case 'e':
            config.cfg_log_level = XQC_LOG_ERROR;
            break;
        default:
            config.cfg_log_level = XQC_LOG_DEBUG;
            break;
    }

    ctx->engine = xqc_engine_create(XQC_ENGINE_CLIENT, &config,
                                    &engine_ssl_config, &callback, &transport_cbs, ctx);
    if (ctx->engine == NULL) {
        printf("xqc_engine_create error\n");
        return XQC_ERROR;
    }

    if (xqc_simple_io_cli_init_alpn_ctx(ctx) < 0) {
        printf("init alpn ctx error!\n");
        return XQC_ERROR;
    }

    return XQC_OK;
}

static const xqc_cid_t *
xqc_simple_io_cli_connect(xqc_simple_io_cli_ctx_t *ctx,
                     xqc_simple_io_cli_client_args_t *args)
{
    /* load 0-rtt args before create connection */
    xqc_simple_io_cli_init_0rtt(args);

    /* init connection settings */
    xqc_conn_settings_t conn_settings;
    xqc_simple_io_cli_init_conneciton_settings(&conn_settings, args);

    xqc_conn_ssl_config_t conn_ssl_config;
    xqc_simple_io_cli_init_conn_ssl_config(&conn_ssl_config, args);

    const xqc_cid_t* cid = xqc_connect(ctx->engine, &conn_settings,
                      (const unsigned char*)args->quic_cfg.token, args->quic_cfg.token_len,
                      "", args->quic_cfg.no_crypt, &conn_ssl_config,
                      (struct sockaddr*)&args->net_cfg.addr, args->net_cfg.addr_len,
                      "transport", ctx);
    return cid;
}


int main(int argc, char *argv[])
{
    int ret;
    xqc_simple_io_cli_client_args_t *args;
    xqc_simple_io_cli_ctx_t *ctx;
    const xqc_cid_t* cid;
    xqc_stream_t* stream;

    ctx = &gs_cli_ctx;
    bzero(ctx, sizeof(xqc_simple_io_cli_ctx_t));

    args = &gs_cli_ctx.args;
    xqc_simple_io_cli_init_args(args);
    xqc_simple_io_cli_parse_args(argc, argv, args);

    xqc_simple_io_cli_init_ctx(ctx);


    if (0 != xqc_simple_io_cli_setup_engine(ctx, args)) {
        printf("xqc_simple_io_cli_setup_engine failed!\n");
        return -1;
    }

    cid = xqc_simple_io_cli_connect(ctx, args);
    if (!cid) {
        printf("xqc_simple_io_cli_connect failed!\n");
        return -1;
    }

    stream = xqc_stream_create(ctx->engine, cid, ctx);
    if (!stream) {
        printf("xqc_simple_io_cli_connect failed!\n");
        return -1;
    }

    event_base_dispatch(ctx->eb);

    xqc_engine_destroy(ctx->engine);
    xqc_simple_io_cli_free_ctx(ctx);

    return 0;
}
