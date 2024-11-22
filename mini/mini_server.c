#include "mini_server.h"

void
xqc_mini_svr_init_ssl_config(xqc_engine_ssl_config_t  *ssl_cfg, xqc_mini_svr_args_t *args)
{
    ssl_cfg->private_key_file = args->env_cfg.private_key_file;
    ssl_cfg->cert_file = args->env_cfg.cert_file;
    ssl_cfg->ciphers = args->quic_cfg.ciphers;
    ssl_cfg->groups = args->quic_cfg.groups;

    /* for server, load session ticket key if there exists */
    if (args->quic_cfg.session_ticket_key_len <= 0) {
        ssl_cfg->session_ticket_key_data = NULL;
        ssl_cfg->session_ticket_key_len = 0;

    } else {
        ssl_cfg->session_ticket_key_data = args->quic_cfg.session_ticket_key_data;
        ssl_cfg->session_ticket_key_len = args->quic_cfg.session_ticket_key_len;
    }
}

void
xqc_mini_svr_init_args(xqc_mini_svr_args_t *args)
{
    int ret;
    char *p = NULL;

    /* init network args */
    strncpy(args->net_cfg.ip, DEFAULT_IP, sizeof(args->net_cfg.ip) - 1);
    args->net_cfg.port = DEFAULT_PORT;

    /**
     * init quic config
     * it's recommended to replace the constant value with option arguments according to actual needs
     */
    p = args->quic_cfg.session_ticket_key_data;
    ret = xqc_mini_read_file_data(p,
        SESSION_TICKET_KEY_BUF_LEN, SESSION_TICKET_KEY_FILE);
    args->quic_cfg.session_ticket_key_len = ret > 0 ? ret : 0;
    args->quic_cfg.cc = CC_TYPE_BBR;
    args->quic_cfg.multipath = 1;
    strncpy(args->quic_cfg.mp_sched, "minrtt", 32);
    strncpy(args->quic_cfg.ciphers, XQC_TLS_CIPHERS, CIPHER_SUIT_LEN - 1);
    strncpy(args->quic_cfg.groups, XQC_TLS_GROUPS, TLS_GROUPS_LEN - 1);

    /* init env config */
    strncpy(args->env_cfg.log_path, LOG_PATH, TLS_GROUPS_LEN - 1);
    strncpy(args->env_cfg.key_out_path, KEY_PATH, PATH_LEN - 1);
    strncpy(args->env_cfg.private_key_file, PRIV_KEY_PATH, PATH_LEN - 1);
    strncpy(args->env_cfg.cert_file, CERT_PEM_PATH, PATH_LEN - 1);
}

int
xqc_mini_svr_init_ctx(xqc_mini_svr_ctx_t *ctx, xqc_mini_svr_args_t *args)
{
    memset(ctx, 0, sizeof(xqc_mini_svr_ctx_t));

    /* init event base */
    struct event_base *eb = event_base_new();
    ctx->eb = eb;

    ctx->args = args;
    /* init log writer fd */
    ctx->log_fd = xqc_mini_svr_open_log_file(ctx);
    if (ctx->log_fd < 0) {
        printf("[error] open log file failed\n");
        return XQC_ERROR;
    }
    /* init keylog writer fd */
    ctx->keylog_fd = xqc_mini_svr_open_keylog_file(ctx);
    if (ctx->keylog_fd < 0) {
        printf("[error] open keylog file failed\n");
        return XQC_ERROR;
    }
    return XQC_OK;
}

/**
 * @brief init engine & transport callbacks
 */
void
xqc_mini_svr_init_callback(xqc_engine_callback_t *cb, xqc_transport_callbacks_t *tcb,
    xqc_mini_svr_args_t *args)
{
    static xqc_engine_callback_t callback = {
        .set_event_timer = xqc_mini_svr_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = xqc_mini_svr_write_log_file,
            .xqc_log_write_stat = xqc_mini_svr_write_log_file,
            .xqc_qlog_event_write = xqc_mini_svr_write_qlog_file
        },
        .keylog_cb = xqc_mini_svr_keylog_cb,
    };

    static xqc_transport_callbacks_t transport_cbs = {
        .server_accept = xqc_mini_svr_accept,
        .write_socket = xqc_mini_svr_write_socket,
        .write_socket_ex = xqc_mini_svr_write_socket_ex,
        .conn_update_cid_notify = xqc_mini_svr_conn_update_cid_notify,
    };

    *cb = callback;
    *tcb = transport_cbs;
}

/**
 * @brief init xquic server engine
 */
int
xqc_mini_svr_init_xquic_engine(xqc_mini_svr_ctx_t *ctx, xqc_mini_svr_args_t *args)
{
    int ret;
    xqc_config_t egn_cfg;
    xqc_engine_callback_t callback;
    xqc_engine_ssl_config_t ssl_cfg = {0};
    xqc_transport_callbacks_t transport_cbs;

    /* get default parameters of xquic engine */
    ret = xqc_engine_get_default_config(&egn_cfg, XQC_ENGINE_SERVER);
    if (ret < 0) {
        return XQC_ERROR;
    }

    /* init ssl config */
    xqc_mini_svr_init_ssl_config(&ssl_cfg, args);

    /* init engine & transport callbacks */
    xqc_mini_svr_init_callback(&callback, &transport_cbs, args);
    
    /* create server engine */
    ctx->engine = xqc_engine_create(XQC_ENGINE_SERVER, &egn_cfg, &ssl_cfg,
                                    &callback, &transport_cbs, ctx);
    if (ctx->engine == NULL) {
        printf("[error] xqc_engine_create error\n");
        return XQC_ERROR;
    }

    ctx->ev_engine = event_new(ctx->eb, -1, 0, xqc_mini_svr_engine_cb, ctx);

    return XQC_OK;
}

int
xqc_mini_svr_init_env(xqc_mini_svr_ctx_t *ctx, xqc_mini_svr_args_t *args)
{
    int ret = XQC_OK;

    /* init server args */
    xqc_mini_svr_init_args(args);

    /* init server ctx */
    ret = xqc_mini_svr_init_ctx(ctx, args);

    return ret;
}

xqc_cong_ctrl_callback_t
xqc_mini_svr_get_cc_cb(xqc_mini_svr_args_t *args)
{
    xqc_cong_ctrl_callback_t ccc = xqc_bbr_cb;
    switch (args->quic_cfg.cc) {
    case CC_TYPE_BBR:
        ccc = xqc_bbr_cb;
        break;
    case CC_TYPE_CUBIC:
        ccc = xqc_cubic_cb;
        break;
    default:
        break;
    }
    return ccc;
}

xqc_scheduler_callback_t
xqc_mini_svr_get_sched_cb(xqc_mini_svr_args_t *args)
{
    xqc_scheduler_callback_t sched = xqc_minrtt_scheduler_cb;
    if (strncmp(args->quic_cfg.mp_sched, "minrtt", strlen("minrtt")) == 0) {
        sched = xqc_minrtt_scheduler_cb;

    } if (strncmp(args->quic_cfg.mp_sched, "backup", strlen("backup")) == 0) {
        sched = xqc_backup_scheduler_cb;
    }
    return sched;
}

void
xqc_mini_svr_init_conn_settings(xqc_engine_t *engine, xqc_mini_svr_args_t *args)
{
    /* parse congestion control callback */
    xqc_cong_ctrl_callback_t ccc = xqc_mini_svr_get_cc_cb(args);
    /* parse mp scheduler callback */
    xqc_scheduler_callback_t sched = xqc_mini_svr_get_sched_cb(args);

    /* init connection settings */
    xqc_conn_settings_t conn_settings = {
        .cong_ctrl_callback = ccc,
        .cc_params = {
            .customize_on = 1,
            .init_cwnd = 32,
            .bbr_enable_lt_bw = 1,
        },
        .spurious_loss_detect_on = 1,
        .init_idle_time_out = 60000,
        .enable_multipath = args->quic_cfg.multipath,
        .scheduler_callback = sched,
        .standby_path_probe_timeout = 1000,
        .adaptive_ack_frequency = 1,
        .anti_amplification_limit = 4,
    };

    /* set customized connection settings to engine ctx */
    xqc_server_set_conn_settings(engine, &conn_settings);
}

/* create socket and bind port */
static int
xqc_mini_svr_init_socket(int family, uint16_t port, 
        struct sockaddr *local_addr, socklen_t local_addrlen)
{
    int size;
    int opt_reuseaddr;
    int flags = 1;
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("create socket failed, errno: %d\n", get_sys_errno());
        return XQC_ERROR;
    }

    /* non-block */
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

    /* reuse port */
    opt_reuseaddr = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt_reuseaddr, sizeof(opt_reuseaddr)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    /* send/recv buffer size */
    size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    /* bind port */
    if (bind(fd, local_addr, local_addrlen) < 0) {
        printf("bind socket failed, family: %d, errno: %d, %s\n", family, 
            get_sys_errno(), strerror(get_sys_errno()));
        goto err;
    }

    return fd;

err:
    close(fd);
    return -1;
}

static int
xqc_mini_svr_create_socket(xqc_mini_svr_user_conn_t *user_conn, xqc_mini_svr_net_config_t* cfg)
{
    /* ipv4 socket */
    user_conn->local_addr->sin_family = AF_INET;
    user_conn->local_addr->sin_port = htons(cfg->port);
    user_conn->local_addr->sin_addr.s_addr = htonl(INADDR_ANY);
    user_conn->local_addrlen = sizeof(struct sockaddr_in);
    user_conn->fd = xqc_mini_svr_init_socket(AF_INET, cfg->port, (struct sockaddr*)user_conn->local_addr, 
        user_conn->local_addrlen);
    printf("[stats] create ipv4 socket fd: %d success, bind socket to ip: %s, port: %d\n", user_conn->fd, cfg->ip, cfg->port);

    if (!user_conn->fd) {
        return -1;
    }

    return 0;
}

int
xqc_mini_svr_init_alpn_ctx(xqc_engine_t *engine)
{
    int ret = 0;

    /* init http3 callbacks */
    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify = xqc_mini_svr_h3_conn_create_notify,
            .h3_conn_close_notify = xqc_mini_svr_h3_conn_close_notify,
            .h3_conn_handshake_finished = xqc_mini_svr_h3_conn_handshake_finished,
        },
        .h3r_cbs = {
            .h3_request_create_notify = xqc_mini_svr_h3_request_create_notify,
            .h3_request_close_notify = xqc_mini_svr_h3_request_close_notify,
            .h3_request_read_notify = xqc_mini_svr_h3_request_read_notify,
            .h3_request_write_notify = xqc_mini_svr_h3_request_write_notify,
        }
    };

    /* init http3 context */
    ret = xqc_h3_ctx_init(engine, &h3_cbs);
    if (ret != XQC_OK) {
        printf("init h3 context error, ret: %d\n", ret);
        return ret;
    }

    return ret;
}

int
xqc_mini_svr_init_engine_ctx(xqc_mini_svr_ctx_t *ctx, xqc_mini_svr_args_t *args)
{
    int ret;

    /* init connection settings */
    xqc_mini_svr_init_conn_settings(ctx->engine, args);

    /* init alpn ctx */
    ret = xqc_mini_svr_init_alpn_ctx(ctx->engine);

    return ret;
}

void
xqc_mini_svr_socket_write_handler(xqc_mini_svr_user_conn_t *user_conn, int fd)
{
    DEBUG
    printf("[stats] socket write handler\n");
}

void
xqc_mini_svr_socket_read_handler(xqc_mini_svr_user_conn_t *user_conn, int fd)
{
    DEBUG;
    ssize_t recv_size, recv_sum;
    struct sockaddr_in peer_addr = {0};
    socklen_t peer_addrlen = sizeof(peer_addr);
    uint64_t recv_time;
    xqc_int_t ret;
    unsigned char packet_buf[XQC_PACKET_BUF_LEN] = {0};
    xqc_mini_svr_ctx_t *ctx;

    ctx = user_conn->ctx;
    ctx->current_fd = fd;
    recv_size = recv_sum = 0;

    do {
        /* recv quic packet from client */
        recv_size = recvfrom(fd, packet_buf, sizeof(packet_buf), 0,
                            (struct sockaddr *) &peer_addr, &peer_addrlen);
        if (recv_size < 0 && get_sys_errno() == EAGAIN) {
            break;
        }
        memcpy(user_conn->peer_addr, &peer_addr, peer_addrlen);
        user_conn->peer_addrlen = peer_addrlen;
    
        if (recv_size < 0) {
            printf("recvfrom: recvmsg = %zd err=%s\n", recv_size, strerror(get_sys_errno()));
            break;
        }

        user_conn->local_addrlen = sizeof(struct sockaddr_in6);
        ret = getsockname(user_conn->fd, (struct sockaddr *)user_conn->local_addr,
                          &user_conn->local_addrlen);
        if (ret != 0) {
            printf("[error] getsockname error, errno: %d\n", get_sys_errno());
        }
        // printf("[stats] get sock name %d\n", user_conn->local_addr->sin_family);

        recv_sum += recv_size;
        recv_time = xqc_now();
        /* process quic packet with xquic engine */
        ret = xqc_engine_packet_process(ctx->engine, packet_buf, recv_size,
                                        (struct sockaddr *)(user_conn->local_addr), user_conn->local_addrlen,
                                        (struct sockaddr *)(user_conn->peer_addr), user_conn->peer_addrlen,
                                        (xqc_usec_t)recv_time, user_conn);
        if (ret != XQC_OK) {
            printf("[error] server_read_handler: packet process err, ret: %d\n", ret);
            return;
        }
    } while (recv_size > 0);

finish_recv:
    // printf("[stats] xqc_mini_svr_socket_read_handler, recv size:%zu\n", recv_sum);
    xqc_engine_finish_recv(ctx->engine);
}

static void
xqc_mini_svr_socket_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t *)arg;
    if (what & EV_WRITE) {
        xqc_mini_svr_socket_write_handler(user_conn, fd);

    } else if (what & EV_READ) {
        xqc_mini_svr_socket_read_handler(user_conn, fd);

    } else {
        printf("event callback: fd=%d, what=%d\n", fd, what);
        exit(1);
    }
}

void
xqc_mini_svr_free_ctx(xqc_mini_svr_ctx_t *ctx)
{
    xqc_mini_svr_close_keylog_file(ctx);
    xqc_mini_svr_close_log_file(ctx);

    if (ctx->args) {
        free(ctx->args);
        ctx->args = NULL;
    }

}

void
xqc_mini_svr_free_user_conn(xqc_mini_svr_user_conn_t *user_conn)
{
    if (user_conn->local_addr) {
        free(user_conn->local_addr);
        user_conn->local_addr = NULL;
    }
    if (user_conn->peer_addr) {
        free(user_conn->peer_addr);
        user_conn->peer_addr = NULL;
    }
    if (user_conn) {
        free(user_conn);
        user_conn = NULL;
    }
}

xqc_mini_svr_user_conn_t *
xqc_mini_svr_create_user_conn(xqc_mini_svr_ctx_t *ctx)
{
    int ret;
    xqc_mini_svr_user_conn_t *user_conn = calloc(1, sizeof(xqc_mini_svr_user_conn_t));

    user_conn->ctx = ctx;

    user_conn->local_addr = (struct sockaddr_in *)calloc(1, sizeof(struct sockaddr_in));
    user_conn->peer_addr = (struct sockaddr_in *)calloc(1, sizeof(struct sockaddr_in));
    
    /* init server socket and save to ctx->fd */
    ret = xqc_mini_svr_create_socket(user_conn, &ctx->args->net_cfg);
    if (ret < 0) {
        printf("[error] xqc_create_socket error\n");
        goto error;
    }

    /* bind socket event callback to fd event */
    user_conn->ev_socket = event_new(ctx->eb, user_conn->fd, EV_READ | EV_PERSIST,
        xqc_mini_svr_socket_event_callback, user_conn);
    event_add(user_conn->ev_socket, NULL);

    return user_conn;
error:
    xqc_mini_svr_free_user_conn(user_conn);
    return NULL;
}

void
xqc_mini_cli_on_connection_finish(xqc_mini_svr_user_conn_t *user_conn)
{
    if (user_conn->ev_timeout) {
        event_del(user_conn->ev_timeout);
        user_conn->ev_timeout = NULL;
    }

    if (user_conn->ev_socket) {
        event_del(user_conn->ev_socket);
        user_conn->ev_timeout = NULL;
    }
}

int
main(int argc, char *argv[])
{
    int ret;
    xqc_mini_svr_ctx_t svr_ctx = {0}, *ctx = &svr_ctx;
    xqc_mini_svr_args_t *args = NULL;
    xqc_mini_svr_user_conn_t *user_conn = NULL;

    args = calloc(1, sizeof(xqc_mini_svr_args_t));
    if (args == NULL) {
        printf("[error] calloc args failed\n");
        goto exit;
    }

    /* init env (for windows) */
    xqc_platform_init_env();

    /* init server environment */
    ret = xqc_mini_svr_init_env(ctx, args);
    if (ret < 0) {
        printf("[error] init server environment failed\n");
        goto exit;
    }

    /* create & init engine to ctx->engine */
    ret = xqc_mini_svr_init_xquic_engine(ctx, args);
    if (ret < 0) {
        printf("[error] init xquic engine failed\n");
        goto exit;
    }

    /* init engine ctx */
    ret = xqc_mini_svr_init_engine_ctx(ctx, args);
    if (ret < 0) {
        printf("[error] init engine ctx failed\n");
        goto exit;
    }

    /* initiate user_conn */
    user_conn = xqc_mini_svr_create_user_conn(ctx);

    /* start event loop */
    event_base_dispatch(ctx->eb);

exit:
    xqc_engine_destroy(ctx->engine);
    xqc_mini_svr_free_ctx(ctx);
    if (user_conn) {
        xqc_mini_svr_free_user_conn(user_conn);
    }

    return 0;
}