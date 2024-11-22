#include "mini_client.h"

#include <netdb.h>

void
xqc_mini_cli_init_engine_ssl_config(xqc_engine_ssl_config_t *ssl_cfg, xqc_mini_cli_args_t *args)
{
    ssl_cfg->ciphers = args->quic_cfg.ciphers;
    ssl_cfg->groups = args->quic_cfg.groups;
}


void
xqc_mini_cli_init_callback(xqc_engine_callback_t *cb, xqc_transport_callbacks_t *tcb, xqc_mini_cli_args_t *args)
{
    static xqc_engine_callback_t callback = {
        .set_event_timer = xqc_mini_cli_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = xqc_mini_cli_write_log_file,
            .xqc_log_write_stat = xqc_mini_cli_write_log_file,
            .xqc_qlog_event_write = xqc_mini_cli_write_qlog_file
        },
        .keylog_cb = xqc_mini_cli_keylog_cb,
    };

    static xqc_transport_callbacks_t transport_cbs = {
        .write_socket = xqc_mini_cli_write_socket,
        .write_socket_ex = xqc_mini_cli_write_socket_ex,
        .save_token = xqc_mini_cli_save_token,
        .save_session_cb = xqc_mini_cli_save_session_cb,
        .save_tp_cb = xqc_mini_cli_save_tp_cb,
    };

    *cb = callback;
    *tcb = transport_cbs;
}

int
xqc_mini_cli_init_xquic_engine(xqc_mini_cli_ctx_t *ctx, xqc_mini_cli_args_t *args)
{
    int ret;
    xqc_config_t egn_cfg;
    xqc_engine_callback_t callback;
    xqc_engine_ssl_config_t ssl_cfg = {0};
    xqc_transport_callbacks_t transport_cbs;
    
    /* get default parameters of xquic engine */
    ret = xqc_engine_get_default_config(&egn_cfg, XQC_ENGINE_CLIENT);
    if (ret < 0) {
        return XQC_ERROR;
    }

    /* init ssl config */
    xqc_mini_cli_init_engine_ssl_config(&ssl_cfg, args);

    /* init engine & transport callbacks */
    xqc_mini_cli_init_callback(&callback, &transport_cbs, args);

    /* create client engine */
    ctx->engine = xqc_engine_create(XQC_ENGINE_CLIENT, &egn_cfg, &ssl_cfg,
                                    &callback, &transport_cbs, ctx);
    if (ctx->engine == NULL) {
        printf("[error] xqc_engine_create error\n");
        return XQC_ERROR;
    }

    ctx->ev_engine = event_new(ctx->eb, -1, 0, xqc_mini_cli_engine_cb, ctx);
    return XQC_OK;
}

void
xqc_mini_cli_convert_text_to_sockaddr(int type,
    const char *addr_text, unsigned int port,
    struct sockaddr **saddr, socklen_t *saddr_len)
{
    *saddr = calloc(1, sizeof(struct sockaddr_in));
    struct sockaddr_in *addr_v4 = (struct sockaddr_in *)(*saddr);
    inet_pton(type, addr_text, &(addr_v4->sin_addr.s_addr));
    addr_v4->sin_family = type;
    addr_v4->sin_port = htons(port);
    *saddr_len = sizeof(struct sockaddr_in);
}

void
xqc_mini_cli_init_args(xqc_mini_cli_args_t *args)
{
    /* init network args */
    args->net_cfg.conn_timeout = 9;

    /**
     * init quic config
     * it's recommended to replace the constant value with option arguments according to actual needs
     */
    strncpy(args->quic_cfg.ciphers, XQC_TLS_CIPHERS, CIPHER_SUIT_LEN - 1);
    strncpy(args->quic_cfg.groups, XQC_TLS_GROUPS, TLS_GROUPS_LEN - 1);
    args->quic_cfg.multipath = 0;


    /* init environmen args */
    // args->env_cfg.log_level = XQC_LOG_DEBUG;
    strncpy(args->env_cfg.log_path, LOG_PATH, sizeof(args->env_cfg.log_path));
    strncpy(args->env_cfg.out_file_dir, OUT_DIR, sizeof(args->env_cfg.out_file_dir));
    strncpy(args->env_cfg.key_out_path, KEY_PATH, sizeof(args->env_cfg.key_out_path));

    /* init request args */
    args->req_cfg.method = REQUEST_METHOD_GET;   // GET
    strncpy(args->req_cfg.scheme, "https", sizeof(args->req_cfg.scheme));
    strncpy(args->req_cfg.url, "/", sizeof(args->req_cfg.url));
    strncpy(args->req_cfg.host, DEFAULT_HOST, sizeof(args->req_cfg.host));
}

int
xqc_mini_cli_init_ctx(xqc_mini_cli_ctx_t *ctx, xqc_mini_cli_args_t *args)
{
    memset(ctx, 0, sizeof(xqc_mini_cli_ctx_t));

    /* init event base */
    struct event_base *eb = event_base_new();
    ctx->eb = eb;

    ctx->args = args;

    /* init log writer fd */
    ctx->log_fd = xqc_mini_cli_open_log_file(ctx);
    if (ctx->log_fd < 0) {
        printf("[error] open log file failed\n");
        return XQC_ERROR;
    }
    /* init keylog writer fd */
    ctx->keylog_fd = xqc_mini_cli_open_keylog_file(ctx);
    if (ctx->keylog_fd < 0) {
        printf("[error] open keylog file failed\n");
        return XQC_ERROR;
    }

    return 0;
}


int
xqc_mini_cli_init_env(xqc_mini_cli_ctx_t *ctx, xqc_mini_cli_args_t *args)
{
    int ret = XQC_OK;

    /* init client args */
    xqc_mini_cli_init_args(args);
    
    /* init client ctx */
    ret = xqc_mini_cli_init_ctx(ctx, args);

    return ret;
}

xqc_scheduler_callback_t
xqc_mini_cli_get_sched_cb(xqc_mini_cli_args_t *args)
{
    xqc_scheduler_callback_t sched = xqc_minrtt_scheduler_cb;
    if (strncmp(args->quic_cfg.mp_sched, "minrtt", strlen("minrtt")) == 0) {
        sched = xqc_minrtt_scheduler_cb;

    } if (strncmp(args->quic_cfg.mp_sched, "backup", strlen("backup")) == 0) {
        sched = xqc_backup_scheduler_cb;
    }
    return sched;
}

xqc_cong_ctrl_callback_t
xqc_mini_cli_get_cc_cb(xqc_mini_cli_args_t *args)
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

void
xqc_mini_cli_init_conn_settings(xqc_conn_settings_t *settings, xqc_mini_cli_args_t *args)
{
    /* parse congestion control callback */
    xqc_cong_ctrl_callback_t ccc = xqc_mini_cli_get_cc_cb(args);
    /* parse mp scheduler callback */
    xqc_scheduler_callback_t sched = xqc_mini_cli_get_sched_cb(args);

    /* init connection settings */
    memset(settings, 0, sizeof(xqc_conn_settings_t));
    settings->cong_ctrl_callback = ccc;
    settings->cc_params.customize_on = 1;
    settings->cc_params.init_cwnd = 96;
    settings->so_sndbuf = 1024*1024;
    settings->proto_version = XQC_VERSION_V1;
    settings->spurious_loss_detect_on = 1;
    settings->scheduler_callback = sched;
    settings->reinj_ctl_callback = xqc_deadline_reinj_ctl_cb;
    settings->adaptive_ack_frequency = 1;
}

int
xqc_mini_cli_init_alpn_ctx(xqc_mini_cli_ctx_t *ctx)
{
    int ret = XQC_OK;

    /* init http3 callbacks */
    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify = xqc_mini_cli_h3_conn_create_notify,
            .h3_conn_close_notify = xqc_mini_cli_h3_conn_close_notify,
            .h3_conn_handshake_finished = xqc_mini_cli_h3_conn_handshake_finished,
        },
        .h3r_cbs = {
            .h3_request_create_notify = xqc_mini_cli_h3_request_create_notify,
            .h3_request_close_notify = xqc_mini_cli_h3_request_close_notify,
            .h3_request_read_notify = xqc_mini_cli_h3_request_read_notify,
            .h3_request_write_notify = xqc_mini_cli_h3_request_write_notify,
        }
    };

    /* init http3 context */
    ret = xqc_h3_ctx_init(ctx->engine, &h3_cbs);
    if (ret != XQC_OK) {
        printf("init h3 context error, ret: %d\n", ret);
        return ret;
    }

    return ret;
}

int
xqc_mini_cli_init_engine_ctx(xqc_mini_cli_ctx_t *ctx)
{
    int ret;

    /* init alpn ctx */
    ret = xqc_mini_cli_init_alpn_ctx(ctx);

    return ret;
}

void
xqc_mini_cli_free_ctx(xqc_mini_cli_ctx_t *ctx)
{
    xqc_mini_cli_close_keylog_file(ctx);
    xqc_mini_cli_close_log_file(ctx);
    
    if (ctx->args) {
        free(ctx->args);
        ctx->args = NULL;
    }
}

void
xqc_mini_cli_init_0rtt(xqc_mini_cli_args_t *args)
{
    /* read session ticket */
    int ret = xqc_mini_read_file_data(args->quic_cfg.session_ticket,
        SESSION_TICKET_BUF_MAX_SIZE, SESSION_TICKET_FILE);
    args->quic_cfg.session_ticket_len = ret > 0 ? ret : 0;

    /* read transport params */
    ret = xqc_mini_read_file_data(args->quic_cfg.transport_parameter,
        TRANSPORT_PARAMS_MAX_SIZE, TRANSPORT_PARAMS_FILE);
    args->quic_cfg.transport_parameter_len = ret > 0 ? ret : 0;

    /* read token */
    ret = xqc_mini_cli_read_token(
        args->quic_cfg.token, TOKEN_MAX_SIZE);
    args->quic_cfg.token_len = ret > 0 ? ret : 0;
}

void
xqc_mini_cli_init_conn_ssl_config(xqc_conn_ssl_config_t *conn_ssl_config, xqc_mini_cli_args_t *args)
{
    /* set session ticket and transport parameter args */
    if (args->quic_cfg.session_ticket_len < 0 || args->quic_cfg.transport_parameter_len < 0) {
        conn_ssl_config->session_ticket_data = NULL;
        conn_ssl_config->transport_parameter_data = NULL;

    } else {
        conn_ssl_config->session_ticket_data = args->quic_cfg.session_ticket;
        conn_ssl_config->session_ticket_len = args->quic_cfg.session_ticket_len;
        conn_ssl_config->transport_parameter_data = args->quic_cfg.transport_parameter;
        conn_ssl_config->transport_parameter_data_len = args->quic_cfg.transport_parameter_len;
    }
}

int
xqc_mini_cli_format_h3_req(xqc_http_header_t *headers, xqc_mini_cli_req_config_t* req_cfg)
{
    /* response header buf list */
    xqc_http_header_t req_hdr[] = {
        {
            .name = {.iov_base = ":method", .iov_len = 7},
            .value = {.iov_base = method_s[req_cfg->method], .iov_len = strlen(method_s[req_cfg->method])},
            .flags = 0,
        },
        {
            .name = {.iov_base = ":scheme", .iov_len = 7},
            .value = {.iov_base = req_cfg->scheme, .iov_len = strlen(req_cfg->scheme)},
            .flags = 0,
        },
        {
            .name   = {.iov_base = "host", .iov_len = 4},
            .value  = {.iov_base = req_cfg->host, .iov_len = strlen(req_cfg->host)},
            .flags  = 0,
        },
        {
            .name = {.iov_base = ":path", .iov_len = 5},
            .value = {.iov_base = req_cfg->url, .iov_len = strlen(req_cfg->path)},
            .flags = 0,
        },
        {
            .name   = {.iov_base = "content-type", .iov_len = 12},
            .value  = {.iov_base = "text/plain", .iov_len = 10},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "content-length", .iov_len = 14},
            .value  = {.iov_base = 0, .iov_len = 0},
            .flags  = 0,
        },
    };

    size_t req_sz = sizeof(req_hdr) / sizeof(req_hdr[0]);
    if (req_sz > H3_HDR_CNT) {
        printf("[error] header length is too large, request_size: %zd\n", req_sz);
        return XQC_ERROR;
    }

    for (size_t i = 0; i < req_sz; i++) {
        headers[i] = req_hdr[i];
    }
    return req_sz;
}

int
xqc_mini_cli_request_send(xqc_h3_request_t *h3_request, xqc_mini_cli_user_stream_t *user_stream)
{
    int ret, fin;
    /* send packet header/body */
    xqc_http_header_t header[H3_HDR_CNT];
    xqc_mini_cli_req_config_t* req_cfg;

    req_cfg = &user_stream->user_conn->ctx->args->req_cfg;

    fin = 1;
    ret = xqc_mini_cli_format_h3_req(header, req_cfg);
    if (ret > 0) {
        user_stream->h3_hdrs.headers = header;
        user_stream->h3_hdrs.count = ret;

        if (user_stream->start_time == 0) {
            user_stream->start_time = xqc_now();
        }
        /* send header */
        ret = xqc_h3_request_send_headers(user_stream->h3_request, &user_stream->h3_hdrs, fin);
        if (ret < 0) {
            printf("[error] xqc_mini_cli_h3_request_send error %d\n", ret);
        } else {
            printf("[stats] xqc_mini_cli_h3_request_send success \n");
            user_stream->hdr_sent = 1;
        }
    }

    if (req_cfg->method == REQUEST_METHOD_GET) {
        return XQC_OK;
    }

    return XQC_OK;
}

int
xqc_mini_cli_send_h3_req(xqc_mini_cli_user_conn_t *user_conn, xqc_mini_cli_user_stream_t *user_stream)
{
    user_stream->user_conn = user_conn;

    xqc_stream_settings_t settings = { .recv_rate_bytes_per_sec = 0 };
    user_stream->h3_request = xqc_h3_request_create(user_conn->ctx->engine, &user_conn->cid,
        &settings, user_stream);
    if (user_stream->h3_request == NULL) {
        printf("[error] xqc_h3_request_create error\n");
        return XQC_ERROR;
    }

    xqc_mini_cli_request_send(user_stream->h3_request, user_stream);

    /* generate engine main log to send packets */
    xqc_engine_main_logic(user_conn->ctx->engine);
    return XQC_OK;
}


int
xqc_mini_cli_init_socket(xqc_mini_cli_user_conn_t *user_conn)
{
    int fd, size;
    xqc_mini_cli_ctx_t *ctx = user_conn->ctx;
    xqc_mini_cli_net_config_t* cfg = &ctx->args->net_cfg;
    struct sockaddr *addr = user_conn->local_addr;

    fd = socket(addr->sa_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("[error] create socket failed, errno: %d\n", get_sys_errno());
        return XQC_ERROR;
    }

#ifdef XQC_SYS_WINDOWS
    if (ioctlsocket(fd, FIONBIO, &flags) == SOCKET_ERROR) {
		goto err;
	}
#else
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("[error] set socket nonblock failed, errno: %d\n", get_sys_errno());
        goto err;
    }
#endif

    size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
        printf("[error] setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int)) < 0) {
        printf("[error] setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

#if !defined(__APPLE__)
    int val = IP_PMTUDISC_DO;
    setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
#endif

#if !defined(__APPLE__)
    if (connect(fd, (struct sockaddr *)user_conn->peer_addr, user_conn->peer_addrlen) < 0) {
        printf("[error] connect socket failed, errno: %d\n", get_sys_errno());
        goto err;
    }
#endif

    ctx->args->net_cfg.last_socket_time = xqc_now();
    printf("[stats] init socket succesfully \n");

    user_conn->fd = fd;

    return XQC_OK;
err:
    close(fd);
    return XQC_ERROR;
}

void
xqc_mini_cli_socket_write_handler(xqc_mini_cli_user_conn_t *user_conn, int fd)
{
    DEBUG
    printf("[stats] socket write handler\n");
}

void
xqc_mini_cli_socket_read_handler(xqc_mini_cli_user_conn_t *user_conn, int fd)
{
    DEBUG
    ssize_t recv_size, recv_sum;
    uint64_t recv_time;
    xqc_int_t ret;
    unsigned char packet_buf[XQC_PACKET_BUF_LEN];
    xqc_mini_cli_ctx_t *ctx;

    recv_size = recv_sum = 0;
    ctx = user_conn->ctx;

    do {
        /* recv quic packet from server */
        recv_size = recvfrom(fd, packet_buf, sizeof(packet_buf), 0,
                             user_conn->peer_addr, &user_conn->peer_addrlen);
        if (recv_size < 0 && get_sys_errno() == EAGAIN) {
            break;
        }

        if (recv_size < 0) {
            printf("recvfrom: recvmsg = %zd err=%s\n", recv_size, strerror(get_sys_errno()));
            break;
        }

        if (user_conn->get_local_addr == 0) {
            user_conn->get_local_addr = 1;
            user_conn->local_addrlen = sizeof(struct sockaddr_in6);
            ret = getsockname(user_conn->fd, (struct sockaddr*)user_conn->local_addr,
                                        &user_conn->local_addrlen);
            if (ret != 0) {
                printf("getsockname error, errno: %d\n", get_sys_errno());
                user_conn->local_addrlen = 0;
                break;
            }
        }

        recv_sum += recv_size;
        recv_time = xqc_now();
        ctx->args->net_cfg.last_socket_time = recv_time;

        /* process quic packet with xquic engine */
        ret = xqc_engine_packet_process(ctx->engine, packet_buf, recv_size,
                                        user_conn->local_addr, user_conn->local_addrlen,
                                        user_conn->peer_addr, user_conn->peer_addrlen,
                                        (xqc_usec_t)recv_time, user_conn);
        if (ret != XQC_OK) {
            printf("[error] client_read_handler: packet process err, ret: %d\n", ret);
            return;
        }
    } while (recv_size > 0);

finish_recv:
    // printf("[stats] xqc_mini_cli_socket_read_handler, recv size:%zu\n", recv_sum);
    xqc_engine_finish_recv(ctx->engine);
}

static void
xqc_mini_cli_socket_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *)arg;

    if (what & EV_WRITE) {
        xqc_mini_cli_socket_write_handler(user_conn, fd);

    } else if (what & EV_READ) {
        xqc_mini_cli_socket_read_handler(user_conn, fd);

    } else {
        printf("event callback: fd=%d, what=%d\n", fd, what);
        exit(1);
    }
}
int
xqc_mini_cli_init_xquic_connection(xqc_mini_cli_user_conn_t *user_conn)
{
    xqc_conn_ssl_config_t conn_ssl_config = {0};
    xqc_conn_settings_t conn_settings = {0};
    xqc_mini_cli_ctx_t *ctx;
    xqc_mini_cli_args_t *args;

    ctx = user_conn->ctx;
    args = ctx->args;

    /* load 0-rtt args */
    xqc_mini_cli_init_0rtt(ctx->args);

    /* init connection settings */
    xqc_mini_cli_init_conn_settings(&conn_settings, ctx->args);

    /* init connection ssl config */
    xqc_mini_cli_init_conn_ssl_config(&conn_ssl_config, ctx->args);

    /* build connection */
    const xqc_cid_t *cid = xqc_h3_connect(ctx->engine, &conn_settings, args->quic_cfg.token,
        args->quic_cfg.token_len, args->req_cfg.host, args->quic_cfg.no_encryption, &conn_ssl_config, 
        user_conn->peer_addr, user_conn->peer_addrlen, user_conn);
    if (cid == NULL) {
        return XQC_ERROR;
    }
    memcpy(&user_conn->cid, cid, sizeof(xqc_cid_t));
    printf("[stats] init xquic connection success \n");

    return XQC_OK;
}
void
xqc_mini_cli_on_socket_created(xqc_mini_cli_user_conn_t *user_conn)
{
    xqc_mini_cli_ctx_t *ctx;
    
    ctx = user_conn->ctx;
    
    /* init callback function for READ/PERSIST EVENT */
    user_conn->ev_socket = event_new(ctx->eb, user_conn->fd, EV_READ | EV_PERSIST,
        xqc_mini_cli_socket_event_callback, user_conn);
    event_add(user_conn->ev_socket, NULL);
}
int
xqc_mini_cli_main_process(xqc_mini_cli_user_conn_t *user_conn, xqc_mini_cli_ctx_t *ctx)
{
    int ret;
    xqc_mini_cli_args_t *args;

    user_conn->ctx = ctx;
    args = ctx->args;

    ret = xqc_mini_cli_init_xquic_connection(user_conn);
    if (ret < 0) {
        printf("[error] mini socket init xquic connection failed\n");
        return XQC_ERROR;
    }

    xqc_mini_cli_user_stream_t *user_stream = calloc(1, sizeof(xqc_mini_cli_user_stream_t));
    ret = xqc_mini_cli_send_h3_req(user_conn, user_stream);
    if (ret < 0) {
        return XQC_ERROR;
    }

    return XQC_OK;
}

void
xqc_mini_cli_init_local_addr(struct sockaddr *local_addr)
{
    char s_port[16] = "8443";
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    /* resolve server's ip from hostname */
    struct addrinfo *result = NULL;
    int rv = getaddrinfo(DEFAULT_IP, s_port, &hints, &result);
    if (rv != 0) {
        printf("get addr info from hostname: %s\n", gai_strerror(rv));
    }
    memcpy(local_addr, result->ai_addr, result->ai_addrlen);
}

xqc_mini_cli_user_conn_t *
xqc_mini_cli_user_conn_create(xqc_mini_cli_ctx_t *ctx)
{
    int ret;
    xqc_mini_cli_user_conn_t *user_conn = calloc(1, sizeof(xqc_mini_cli_user_conn_t));

    user_conn->ctx = ctx;

    /* set connection timeout */
    struct timeval tv;
    tv.tv_sec = ctx->args->net_cfg.conn_timeout;
    tv.tv_usec = 0;
    user_conn->ev_timeout = event_new(ctx->eb, -1, 0, xqc_mini_cli_timeout_callback, user_conn);
    event_add(user_conn->ev_timeout, &tv);

    user_conn->local_addr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
    xqc_mini_cli_init_local_addr(user_conn->local_addr);
    user_conn->local_addrlen = sizeof(struct sockaddr_in);

    xqc_mini_cli_convert_text_to_sockaddr(AF_INET, DEFAULT_IP, DEFAULT_PORT,
        &(user_conn->peer_addr), &(user_conn->peer_addrlen));

    /* init socket fd */
    ret = xqc_mini_cli_init_socket(user_conn);
    if (ret < 0) {
        printf("[error] mini socket init socket failed\n");
        return NULL;
    }

    user_conn->ev_socket = event_new(ctx->eb, user_conn->fd, EV_READ | EV_PERSIST,
        xqc_mini_cli_socket_event_callback, user_conn);
    event_add(user_conn->ev_socket, NULL);

    return user_conn;
}

void
xqc_mini_cli_free_user_conn(xqc_mini_cli_user_conn_t *user_conn)
{
    free(user_conn->peer_addr);
    free(user_conn->local_addr);
    free(user_conn);
}

void
xqc_mini_cli_on_connection_finish(xqc_mini_cli_user_conn_t *user_conn)
{
    if (user_conn->ev_timeout) {
        event_del(user_conn->ev_timeout);
        user_conn->ev_timeout = NULL;
    }

    if (user_conn->ev_socket) {
        event_del(user_conn->ev_socket);
        user_conn->ev_timeout = NULL;
    }

    close(user_conn->fd);   
}

int main(int argc, char *argv[])
{
    int ret;
    xqc_mini_cli_ctx_t cli_ctx = {0}, *ctx = &cli_ctx;
    xqc_mini_cli_args_t *args = NULL;
    xqc_mini_cli_user_conn_t *user_conn = NULL;

    args = calloc(1, sizeof(xqc_mini_cli_args_t));
    if (args == NULL) {
        printf("[error] calloc args failed\n");
        goto exit;
    }

    /* init env (for windows) */
    xqc_platform_init_env();

    /* init client environment (ctx & args) */
    ret = xqc_mini_cli_init_env(ctx, args);
    if (ret < 0) {
        goto exit;
    }

    /* init client engine */
    ret = xqc_mini_cli_init_xquic_engine(ctx, args);
    if (ret < 0) {
        printf("[error] init xquic engine failed\n");
        goto exit;
    }

    /* init engine ctx */
    ret = xqc_mini_cli_init_engine_ctx(ctx);
    if (ret < 0) {
        printf("[error] init engine ctx failed\n");
        goto exit;
    }

    user_conn = xqc_mini_cli_user_conn_create(ctx);
    if (user_conn == NULL) {
        printf("[error] init user_conn failed.\n");
        goto exit;
    }

    /* cli main process: build connection, process request, etc. */
    xqc_mini_cli_main_process(user_conn, ctx);

    /* start event loop */
    event_base_dispatch(ctx->eb);

exit:
    xqc_engine_destroy(ctx->engine);
    xqc_mini_cli_on_connection_finish(user_conn);
    xqc_mini_cli_free_ctx(ctx);
    xqc_mini_cli_free_user_conn(user_conn);

    return 0;
}