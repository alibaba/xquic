/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <inttypes.h>
#include <errno.h>
#include <assert.h>

#include <event2/event.h>
#include <xquic/xquic.h>


#define SESSION_TICKET_KEY_FILE     "session_ticket.key"
#define SESSION_TICKET_KEY_BUF_LEN  2048

#define LOG_PATH        "slog.log"
#define SOURCE_DIR      "."
#define PRIV_KEY_PATH   "server.key"
#define CERT_PEM_PATH   "server.crt"

#define DATA_RECV_BUF_SIZE          10 * 1024 * 1024


typedef struct {
    short   port;

    /* ipv4 or ipv6 */
    int     ipv6;

    CC_TYPE cc;     /* congestion control algorithm */
    int     pacing; /* is pacing on */

} xqc_simple_io_svr_args_net_config_t;

typedef struct {
    /* cipher config */
    char cipher_suit[CIPHER_SUIT_LEN];
    char groups[TLS_GROUPS_LEN];

    /* 0-rtt config */
    int  stk_len;                           /* session ticket len */
    char stk[SESSION_TICKET_KEY_BUF_LEN];   /* session ticket buf */

} xqc_simple_io_svr_args_quic_config_t;

/* environment config */
typedef struct {
    /* log path */
    char    log_path[PATH_LEN];
    int     log_level;

    /* resource dir */
    char    resource_dir[RESOURCE_LEN];

    /* tls certs */
    char    priv_key_path[PATH_LEN];
    char    cert_pem_path[PATH_LEN];

    /* key export */
    char    key_out_path[PATH_LEN];
} xqc_simple_io_svr_args_env_config_t;


typedef struct {
    /* network args */
    xqc_simple_io_svr_args_net_config_t    net_cfg;

    /* quic args */
    xqc_simple_io_svr_args_quic_config_t   quic_cfg;

    /* environment args */
    xqc_simple_io_svr_args_env_config_t    env_cfg;
} xqc_simple_io_svr_args_t;

typedef enum {
    emXQC_FILE_RECV_IDLE = 0,
    emXQC_FILE_RECV_STARTED,
    emXQC_FILE_RECV_FINISHED
} emXQC_FILE_RECV_STATE;

typedef struct {
    emXQC_FILE_RECV_STATE   state;

    uint8_t*    buf;
    size_t      buf_sz;
    size_t      buf_write_pos;

    size_t      total_recv_bytes;
    size_t      last_recv_bytes;

    xqc_usec_t  start_ts;
    xqc_usec_t  last_ts;
} xqc_data_recv_t;

typedef struct {
    xqc_engine_t        *engine;

    int                 log_fd;

    xqc_simple_io_svr_args_t    args;

    int                 transport_fd;
    struct sockaddr_storage local_addr;
    struct sockaddr_storage peer_addr;

    struct event_base   *eb;
    struct event        *ev_engine;
    struct event        *ev_socket_r;
    struct event        *ev_add_w_timer;

    xqc_cid_t           cid;
    xqc_data_recv_t     data_recv;

} xqc_simple_io_svr_ctx_t;


/* the global unique server context */
static xqc_simple_io_svr_ctx_t gs_svr_ctx;


/**
 * engine callbacks
 **/
static void
xqc_simple_io_svr_set_event_timer(xqc_msec_t wake_after, void *eng_user_data)
{
    xqc_simple_io_svr_ctx_t *ctx = (xqc_simple_io_svr_ctx_t *)eng_user_data;
    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);
}

static void
xqc_simple_io_svr_write_log_file(xqc_log_level_t lvl, const void *buf, size_t size, void *eng_user_data)
{
    xqc_simple_io_svr_ctx_t *ctx = (xqc_simple_io_svr_ctx_t*)eng_user_data;
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
 * transport callbacks
 **/
static int
xqc_simple_io_svr_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid,
    void *eng_user_data)
{
    DEBUG;
    return 0;
}

static ssize_t
xqc_simple_io_svr_write_socket(const unsigned char* buf, size_t size, const struct sockaddr* peer_addr,
                               socklen_t peer_addrlen, void* conn_user_data)
{
    int ret;
    xqc_simple_io_svr_ctx_t *ctx = (xqc_simple_io_svr_ctx_t*)conn_user_data;

    ret = sendto(ctx->transport_fd, buf, size, 0,
                 peer_addr, peer_addrlen);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return XQC_SOCKET_EAGAIN;
        } else {
            printf("sendto failed! ret: %d, err: %s\n", ret, strerror(errno));
            return -1;
        }
    }

    return (ssize_t)size;
}

static void
xqc_simple_io_svr_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
                                    const xqc_cid_t *new_cid, void *user_data)
{
    xqc_simple_io_svr_ctx_t *ctx = user_data;
    memcpy(&ctx->cid, new_cid, sizeof(xqc_cid_t));
}

/**
 * connection callbacks
 **/
static int
xqc_simple_io_svr_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                     void *user_data, void *conn_proto_data)
{
    DEBUG;
    xqc_simple_io_svr_ctx_t *ctx = &gs_svr_ctx;
    xqc_conn_set_transport_user_data(conn, ctx);
    xqc_conn_set_alp_user_data(conn, ctx);
    memcpy(&ctx->cid, cid, sizeof(xqc_cid_t));
    return 0;
}

static int
xqc_simple_io_svr_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                    void *user_data, void *conn_proto_data)
{
    DEBUG;
    xqc_simple_io_svr_ctx_t *ctx = user_data;
    event_base_loopbreak(ctx->eb);
    return 0;
}

/**
 * stream callbacks
 **/
static int
xqc_simple_io_svr_stream_create_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    xqc_stream_set_user_data(stream, &gs_svr_ctx);
    return 0;
}

static int
xqc_simple_io_svr_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    return 0;
}

static int
xqc_simple_io_svr_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    return 0;
}

static int
xqc_simple_io_svr_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    unsigned char fin = 0;
    ssize_t read_bytes;
    xqc_usec_t cur_ts;
    uint64_t transport_speed_kB;
    xqc_simple_io_svr_ctx_t *ctx = (xqc_simple_io_svr_ctx_t *)user_data;
    xqc_data_recv_t *data_recv = &ctx->data_recv;

    if (emXQC_FILE_RECV_FINISHED == data_recv->state) {
        return 0;
    }

    if (emXQC_FILE_RECV_IDLE == data_recv->state) {
        printf("Begin to receive data!\n");
        data_recv->start_ts = xqc_demo_now();
        data_recv->last_ts = data_recv->start_ts;
        data_recv->state = emXQC_FILE_RECV_STARTED;
    }

    cur_ts = xqc_demo_now();
    if (cur_ts > (data_recv->last_ts + 1000000)) {
        transport_speed_kB = ((data_recv->total_recv_bytes - data_recv->last_recv_bytes) * 1000000 /
                              ((cur_ts - data_recv->last_ts))) / 1000;
        printf("Current speed: %" PRIu64 " kB/s\n", transport_speed_kB);
        data_recv->last_recv_bytes = data_recv->total_recv_bytes;
        data_recv->last_ts = cur_ts;
    }

    while (1) {
        if (data_recv->buf_write_pos >= data_recv->buf_sz) {
            /* reuse buffer to recv data */
            data_recv->buf_write_pos = 0;
        }
        read_bytes = xqc_stream_recv(stream,
                                     (unsigned char*)(data_recv->buf + data_recv->buf_write_pos),
                                     data_recv->buf_sz - data_recv->buf_write_pos,
                                     &fin);
        if (-XQC_EAGAIN == read_bytes) {
            return 0;

        } else if (read_bytes < 0) {
            printf("xqc_stream_recv failed! read_bytes: %zd\n",
                     read_bytes);
            return 0;

        } else {
            data_recv->total_recv_bytes += read_bytes;
            data_recv->buf_write_pos += read_bytes;
            if (0 != fin) {
                cur_ts = xqc_demo_now();
                transport_speed_kB = (data_recv->total_recv_bytes * 1000000 /
                                      ((cur_ts - data_recv->start_ts))) / 1000;
                xqc_conn_stats_t stats = xqc_conn_get_stats(ctx->engine, &ctx->cid);
                printf("Data received! Average speed: %" PRIu64 " kB/s\n", transport_speed_kB);
                printf("Data size: %zu kB\n", data_recv->total_recv_bytes / 1000);
                printf("Spent time: %" PRIu64 "ms\n", (cur_ts - data_recv->start_ts) / 1000);
                printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%" PRIu64 " "
                       "early_data_flag:%d, conn_err:%d, ack_info:%s\n", stats.send_count,
                       stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt,
                       stats.early_data_flag, stats.conn_err, stats.ack_info);
                data_recv->state = emXQC_FILE_RECV_FINISHED;
                xqc_conn_close(ctx->engine, &ctx->cid);
                return 0;
            }
        }
    }
}

/**
 * transport callbacks
 **/
static int
xqc_simple_io_svr_transport_create_socket(int family)
{
    int size;
    int opt_reuseaddr;
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

    /* reuse port */
    opt_reuseaddr = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt_reuseaddr, sizeof(opt_reuseaddr)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
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
xqc_simple_io_svr_transport_setup(xqc_simple_io_svr_ctx_t *ctx)
{

    if (ctx->args.net_cfg.ipv6) {
        /* setup ipv6 udp socket */
        struct sockaddr_in6 *local_addr6 = (struct sockaddr_in6 *)&ctx->local_addr;
        ctx->transport_fd = xqc_simple_io_svr_transport_create_socket(AF_INET6);
        if (ctx->transport_fd < 0) {
            goto err;
        }
        bzero(local_addr6, sizeof(*local_addr6));
        local_addr6->sin6_family = AF_INET6;
        local_addr6->sin6_port = htons(ctx->args.net_cfg.port);
        local_addr6->sin6_addr = in6addr_any;
        if (bind(ctx->transport_fd, (struct sockaddr*)local_addr6, sizeof(*local_addr6)) < 0) {
            printf("bind ipv6 socket failed, errno: %d, %s\n", errno, strerror(errno));
            goto err;
        }

    } else {
        /* setup ipv4 udp socket */
        struct sockaddr_in *local_addr = (struct sockaddr_in *)&ctx->local_addr;
        ctx->transport_fd = xqc_simple_io_svr_transport_create_socket(AF_INET);
        if (ctx->transport_fd < 0) {
            goto err;
        }
        bzero(local_addr, sizeof(*local_addr));
        local_addr->sin_family = AF_INET;
        local_addr->sin_port = htons(ctx->args.net_cfg.port);
        local_addr->sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(ctx->transport_fd, (struct sockaddr*)local_addr, sizeof(*local_addr)) < 0) {
            printf("bind ipv4 socket failed, errno: %d, %s\n", errno, strerror(errno));
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
xqc_simple_io_svr_event_engine_callback(int fd, short what, void *arg)
{
    xqc_simple_io_svr_ctx_t *ctx = (xqc_simple_io_svr_ctx_t *) arg;
    xqc_engine_main_logic(ctx->engine);
}

static void
xqc_simple_io_svr_event_socket_read_callback(int fd, short what, void *arg)
{
    xqc_simple_io_svr_ctx_t *ctx = (xqc_simple_io_svr_ctx_t *)arg;
    ssize_t recv_sum = 0;
    socklen_t peer_addrlen = sizeof(ctx->peer_addr);
    ssize_t recv_size = 0;
    unsigned char packet_buf[1500];

    do {
        recv_size = recvfrom(fd, packet_buf, sizeof(packet_buf), 0,
                             (struct sockaddr *)&ctx->peer_addr, &peer_addrlen);
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
                                        (struct sockaddr*) (&ctx->local_addr), sizeof(ctx->local_addr),
                                        (struct sockaddr*) (&ctx->peer_addr), peer_addrlen,
                                        (xqc_usec_t) recv_time, ctx);
        if (ret != XQC_OK) {
            printf("server_read_handler: packet process err, ret: %d\n", ret);
            return;
        }
    } while (recv_size > 0);

    xqc_engine_finish_recv(ctx->engine);
}

static int
xqc_simple_io_svr_event_setup(xqc_simple_io_svr_ctx_t *ctx)
{
    ctx->eb = event_base_new();
    ctx->ev_engine = event_new(ctx->eb, -1, 0, xqc_simple_io_svr_event_engine_callback, ctx);

    ctx->ev_socket_r = event_new(ctx->eb, ctx->transport_fd, EV_READ | EV_PERSIST,
                                 xqc_simple_io_svr_event_socket_read_callback, ctx);
    event_add(ctx->ev_socket_r, NULL);
    return 0;
}

/**
 * setup engine
 **/
static void
xqc_simple_io_svr_usage(int argc, char *argv[])
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
            "   -p    Server port. Default: 8443\n"
            "   -c    Congestion Control Algorithm. r:reno b:bbr c:cubic B:bbr2\n"
            "   -C    Pacing on.\n"
            "   -D    Server resource directory.\n"
            "   -l    Log level. e:error d:debug.\n"
            "   -L    xuqic log directory.\n"
            "   -6    IPv6\n"
            , prog);
}

static void
xqc_simple_io_svr_parse_args(int argc, char *argv[], xqc_simple_io_svr_args_t *args)
{
    int ch = 0;
    while ((ch = getopt(argc, argv, "p:c:CD:l:L:6")) != -1) {
        switch (ch) {
            /* listen port */
            case 'p':
                printf("option port: %s\n", optarg);
                args->net_cfg.port = atoi(optarg);
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

                /* server resource dir */
            case 'D':
                printf("option read dir: %s\n", optarg);
                strncpy(args->env_cfg.resource_dir, optarg, RESOURCE_LEN - 1);
                break;

                /* log level */
            case 'l':
                printf("option log level: %s\n", optarg);
                args->env_cfg.log_level = optarg[0];
                break;

                /* log file */
            case 'L':
                printf("option log file: %s\n", optarg);
                snprintf(args->env_cfg.log_path, sizeof(args->env_cfg.log_path), "%s", optarg);
                break;

                /* ipv6 */
            case '6':
                printf("option IPv6: %s\n", "on");
                args->net_cfg.ipv6 = 1;
                break;

            default:
                printf("other option: %c\n", ch);
                xqc_simple_io_svr_usage(argc, argv);
                exit(0);
        }
    }
}

static int
xqc_simple_io_svr_open_log_file(xqc_simple_io_svr_ctx_t *ctx)
{
    ctx->log_fd = open(ctx->args.env_cfg.log_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return 0;
}

static int
xqc_simple_io_svr_close_log_file(xqc_simple_io_svr_ctx_t *ctx)
{
    if (ctx->log_fd <= 0) {
        return -1;
    }
    close(ctx->log_fd);
    return 0;
}

static void
xqc_simple_io_svr_init_0rtt(xqc_simple_io_svr_args_t *args)
{
    /* read session ticket key */
    int ret = xqc_demo_read_file_data(args->quic_cfg.stk,
            SESSION_TICKET_KEY_BUF_LEN, SESSION_TICKET_KEY_FILE);
    args->quic_cfg.stk_len = ret > 0 ? ret : 0;
}

static void
xqc_simple_io_svr_init_args(xqc_simple_io_svr_args_t *args)
{
    memset(args, 0, sizeof(xqc_simple_io_svr_args_t));

    /* net cfg */
    args->net_cfg.port = DEFAULT_SERVER_PORT;

    /* env cfg */
    args->env_cfg.log_level = XQC_LOG_DEBUG;
    strncpy(args->env_cfg.log_path, LOG_PATH, TLS_GROUPS_LEN - 1);
    strncpy(args->env_cfg.resource_dir, SOURCE_DIR, RESOURCE_LEN - 1);
    strncpy(args->env_cfg.priv_key_path, PRIV_KEY_PATH, PATH_LEN - 1);
    strncpy(args->env_cfg.cert_pem_path, CERT_PEM_PATH, PATH_LEN - 1);

    /* quic cfg */
    xqc_simple_io_svr_init_0rtt(args);
    strncpy(args->quic_cfg.cipher_suit, XQC_TLS_CIPHERS, CIPHER_SUIT_LEN - 1);
    strncpy(args->quic_cfg.groups, XQC_TLS_GROUPS, TLS_GROUPS_LEN - 1);
}

static void
xqc_simple_io_svr_init_data_recv(xqc_simple_io_svr_ctx_t *ctx)
{
    xqc_data_recv_t *data_recv = &ctx->data_recv;
    bzero(data_recv, sizeof(xqc_data_recv_t));
    data_recv->buf = (uint8_t*)malloc(DATA_RECV_BUF_SIZE);
    assert(data_recv->buf);
    data_recv->buf_sz = DATA_RECV_BUF_SIZE;
}

static void
xqc_simple_io_svr_free_data_recv(xqc_simple_io_svr_ctx_t *ctx)
{
    xqc_data_recv_t *data_recv = &ctx->data_recv;
    if (data_recv->buf) {
        free(data_recv->buf);
    }
    bzero(data_recv, sizeof(xqc_data_recv_t));
}

static void
xqc_simple_io_svr_init_ctx(xqc_simple_io_svr_ctx_t *ctx)
{
    xqc_simple_io_svr_init_data_recv(ctx);
    xqc_simple_io_svr_open_log_file(ctx);
}

static void
xqc_simple_io_svr_free_ctx(xqc_simple_io_svr_ctx_t *ctx)
{
    xqc_simple_io_svr_free_data_recv(ctx);
    xqc_simple_io_svr_close_log_file(ctx);
}

static void
xqc_simple_io_svr_init_callback(xqc_engine_callback_t *cb, xqc_transport_callbacks_t *transport_cbs,
    xqc_simple_io_svr_args_t* args)
{
    static xqc_engine_callback_t callback;
    bzero(&callback, sizeof(callback));
    callback.set_event_timer = xqc_simple_io_svr_set_event_timer;
    callback.log_callbacks.xqc_log_write_err = xqc_simple_io_svr_write_log_file;
    callback.log_callbacks.xqc_log_write_stat = xqc_simple_io_svr_write_log_file;

    static xqc_transport_callbacks_t tcb;
    bzero(&tcb, sizeof(tcb));
    tcb.server_accept = xqc_simple_io_svr_accept;
    tcb.write_socket = xqc_simple_io_svr_write_socket;
    tcb.conn_update_cid_notify = xqc_simple_io_svr_conn_update_cid_notify;

    *cb = callback;
    *transport_cbs = tcb;
}

static int
xqc_simple_io_svr_init_alpn_ctx(xqc_simple_io_svr_ctx_t *ctx)
{
    int ret = 0;

    xqc_app_proto_callbacks_t ap_cbs;
    bzero(&ap_cbs, sizeof(ap_cbs));
    ap_cbs.conn_cbs.conn_create_notify = xqc_simple_io_svr_conn_create_notify;
    ap_cbs.conn_cbs.conn_close_notify = xqc_simple_io_svr_conn_close_notify;
    ap_cbs.stream_cbs.stream_read_notify = xqc_simple_io_svr_stream_read_notify;
    ap_cbs.stream_cbs.stream_write_notify = xqc_simple_io_svr_stream_write_notify;
    ap_cbs.stream_cbs.stream_create_notify = xqc_simple_io_svr_stream_create_notify;
    ap_cbs.stream_cbs.stream_close_notify = xqc_simple_io_svr_stream_close_notify;

    ret = xqc_engine_register_alpn(ctx->engine, "transport", 9, &ap_cbs);
    if (XQC_OK != ret) {
        printf("xqc_engine_register_alpn failed!\n");
    }

    return ret;
}

static void
xqc_simple_io_svr_init_ssl_config(xqc_engine_ssl_config_t *cfg, xqc_simple_io_svr_args_t *args)
{
    bzero(cfg, sizeof(xqc_engine_ssl_config_t));
    cfg->private_key_file = args->env_cfg.priv_key_path;
    cfg->cert_file = args->env_cfg.cert_pem_path;
    cfg->ciphers = args->quic_cfg.cipher_suit;
    cfg->groups = args->quic_cfg.groups;

    if (args->quic_cfg.stk_len <= 0) {
        cfg->session_ticket_key_data = NULL;
        cfg->session_ticket_key_len = 0;

    } else {
        cfg->session_ticket_key_data = args->quic_cfg.stk;
        cfg->session_ticket_key_len = args->quic_cfg.stk_len;
    }
}

static void
xqc_simple_io_svr_init_conn_settings(xqc_simple_io_svr_args_t *args)
{
    xqc_cong_ctrl_callback_t ccc = {0};
    switch (args->net_cfg.cc) {
        case CC_TYPE_BBR:
            ccc = xqc_bbr_cb;
            break;
        case CC_TYPE_CUBIC:
            ccc = xqc_cubic_cb;
            break;
        case CC_TYPE_RENO:
            ccc = xqc_reno_cb;
            break;
#ifdef XQC_ENABLE_BBR2
        case CC_TYPE_BBR2:
            ccc = xqc_bbr2_cb;
            break;
#endif
        default:
            printf("Invalid cc flag: %d!\n", args->net_cfg.cc);
            exit(-1);
            break;
    }

    xqc_conn_settings_t conn_settings;
    bzero(&conn_settings, sizeof(conn_settings));
    conn_settings.pacing_on = args->net_cfg.pacing;
    conn_settings.cong_ctrl_callback = ccc;
    conn_settings.cc_params.customize_on = 1;
    conn_settings.cc_params.init_cwnd = 16;
    conn_settings.cc_params.expect_bw = UINT32_MAX;
    conn_settings.cc_params.max_expect_bw = UINT32_MAX;
    conn_settings.spurious_loss_detect_on = 1;
    conn_settings.so_sndbuf = 1024*1024;

    xqc_server_set_conn_settings(&conn_settings);
}

static int
xqc_simple_io_svr_setup_engine(xqc_simple_io_svr_ctx_t *ctx,
                                 xqc_simple_io_svr_args_t *args)
{
    xqc_config_t config;
    xqc_engine_ssl_config_t cfg;
    xqc_engine_callback_t callback;
    xqc_transport_callbacks_t transport_cbs;

    xqc_simple_io_svr_init_ssl_config(&cfg, args);

    xqc_simple_io_svr_init_callback(&callback, &transport_cbs, args);

    xqc_simple_io_svr_init_conn_settings(args);

    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        return XQC_ERROR;
    }

    if (xqc_simple_io_svr_transport_setup(ctx) != 0) {
        return XQC_ERROR;
    }

    xqc_simple_io_svr_event_setup(ctx);

    config.cid_len = 12;

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

    ctx->engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &cfg,
                                    &callback, &transport_cbs, ctx);
    if (ctx->engine == NULL) {
        printf("xqc_engine_create error\n");
        return -1;
    }

    if (xqc_simple_io_svr_init_alpn_ctx(ctx) < 0) {
        printf("init alpn ctx error!\n");
        return -1;
    }

    return 0;
}


int main(int argc, char *argv[])
{
    xqc_simple_io_svr_args_t *args;
    xqc_simple_io_svr_ctx_t *ctx;

    ctx = &gs_svr_ctx;
    bzero(ctx, sizeof(xqc_simple_io_svr_ctx_t));

    args = &gs_svr_ctx.args;
    xqc_simple_io_svr_init_args(args);
    xqc_simple_io_svr_parse_args(argc, argv, args);

    xqc_simple_io_svr_init_ctx(ctx);

    if (xqc_simple_io_svr_setup_engine(ctx, args) < 0) {
        printf("xqc_simple_io_svr_setup_engine failed!\n");
        return -1;
    }

    event_base_dispatch(ctx->eb);

    xqc_engine_destroy(ctx->engine);
    xqc_simple_io_svr_free_ctx(ctx);

    return 0;
}
