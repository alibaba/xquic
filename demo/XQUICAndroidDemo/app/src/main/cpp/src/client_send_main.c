//
// Created by Neho on 2022/8/26.
//

#include "global_common.h"
#include "xqc_common.h"
#include <fcntl.h>
#include <linux/time.h>
#include <errno.h>
#include <unistd.h>

uint64_t g_last_sock_op_time;
int g_req_cnt = 0;
static uint64_t last_recv_ts = 0;

int
jni_client_open_keylog_file(client_ctx_t *jctx) {
    jctx->keylog_fd = fopen("./ckey.log", "w");  // or "a+" ?
    if (jctx->keylog_fd <= 0) {
        return XQC_ERROR;
    }
    return XQC_OK;
}

int
jni_client_open_log_file(client_ctx_t *jctx) {
    jctx->log_fd = fopen("./c.log", "w");  // or "a+" ?
    if (jctx->log_fd <= 0) {
        return XQC_ERROR;
    }
    return XQC_OK;
}


void
jni_client_engine_callback(struct ev_loop *main_loop, ev_timer *io_w, int what) {
    client_ctx_t *_ctx = (client_ctx_t *) io_w->client_ctx;
    LOGD("timer wakeup now:%lu\n", xqc_now());
    xqc_engine_main_logic(_ctx->engine);
}

//////////////////////////START//////////////////////////////
////////////xqc_engine_callback xquic engine 回调////////////
////////////////////////////////////////////////////////////
void
xqc_client_set_event_timer(xqc_msec_t wake_after, void *user_data) {
    client_ctx_t *ctx = (client_ctx_t *) user_data;
    ctx->ev_engine.repeat = wake_after / 1000000.0;
    ev_timer_again(ctx->eb, &ctx->ev_engine);
}

void
xqc_client_write_log(xqc_log_level_t lvl, const void *buf, size_t count, void *engine_user_data) {
    // TODO: 暂时不写log了
#if 0
    unsigned char log_buf[XQC_MAX_LOG_LEN + 1];

    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    if (!ctx->log_fd) {
        LOGE("xqc_client_write_log fd err\n");
        return;
    }

    int log_len = snprintf(log_buf, XQC_MAX_LOG_LEN + 1, "%s\n", (char *)buf);
    if (log_len < 0) {
        LOGE("xqc_client_write_log err\n");
        return;
    }

    size_t write_len = fwrite(log_buf, log_len, 1, ctx->log_fd);
    if (write_len != 1) {
        LOGE("write log failed, errno: %d\n", errno);
    }
#endif
}

void
xqc_keylog_cb(const char *line, void *user_data) {
    client_ctx_t *ctx = (client_ctx_t*)user_data;
    if (!ctx->keylog_fd) {
        LOGD("write keys error!\n");
        return;
    }

    size_t write_len = fwrite(line, strlen(line), 1, ctx->keylog_fd);
    if (write_len != 1) {
        LOGD("write keys failed, errno: %d\n", errno);
        return;
    }

    write_len = fwrite("\n", 1, 1, ctx->keylog_fd);
    if (write_len != 1) {
        LOGD("write keys failed, errno: %d\n", errno);
    }
}
///////////////////////////END///////////////////////////////
////////////xqc_engine_callback xquic engine 回调////////////
////////////////////////////////////////////////////////////


//////////////////////////START//////////////////////////////
//////////xqc_transport_callbacks_t xquic 传输层 回调/////////
////////////////////////////////////////////////////////////
ssize_t
xqc_client_write_socket(const unsigned char *buf, size_t size,
                        const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user)
{
    user_conn_t *user_conn = (user_conn_t *) user;
    ssize_t res = 0;
    int fd = user_conn->fd;

    /* COPY to run corruption test cases */
    // no more testcase, so no need to copy

    do {
        errno = 0;
        g_last_sock_op_time = xqc_now();

        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
            LOGD("xqc_client_write_socket err %zd %s\n", res, strerror(errno));
            if (errno == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        }
    } while ((res < 0) && (errno == EINTR));

    return res;
}

void
xqc_client_save_token(const unsigned char *token, unsigned token_len, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    // TODO: 保存 token 到安卓层客户端的回调
#if 0
    LOGD("xqc_client_save_token use client ip as the key. h3[%d]\n", user_conn->h3);

    if (g_test_case == 16) { /* test application delay */
        usleep(300*1000);
    }
    int fd = open("./xqc_token", O_TRUNC | O_CREAT | O_WRONLY, 0666);
    if (fd < 0) {
        LOGD("save token error %s\n", strerror(get_last_sys_errno()));
        return;
    }

    ssize_t n = write(fd, token, token_len);
    if (n < token_len) {
        LOGD("save token error %s\n", strerror(get_last_sys_errno()));
        close(fd);
        return;
    }
    close(fd);
#endif
}

void
save_session_cb(const char * data, size_t data_len, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    // TODO: 保存 test_session 到安卓层客户端的回调
#if 0
    LOGD("save_session_cb use server domain as the key. h3[%d]\n", user_conn->h3);

    FILE * fp  = fopen("test_session", "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        LOGD("save _session_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
#endif
}

void
save_tp_cb(const char * data, size_t data_len, void * user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    // TODO: 保存 tp_localhost 到安卓层客户端的回调
#if 0
    LOGD("save_tp_cb use server domain as the key. h3[%d]\n", user_conn->h3);

    FILE * fp = fopen("tp_localhost", "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        LOGD("save _tp_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
    return;
#endif
}

int
xqc_client_cert_verify(const unsigned char *certs[],
                       const size_t cert_len[], size_t certs_len, void *conn_user_data)
{
    /* self-signed cert used in test cases, return >= 0 means success */
    return 0;
}

xqc_int_t
xqc_client_conn_closing_notify(xqc_connection_t *conn,
                               const xqc_cid_t *cid, xqc_int_t err_code, void *conn_user_data)
{
    LOGD("conn closing: %d\n", err_code);
    return XQC_OK;
}
///////////////////////////END///////////////////////////////
//////////xqc_transport_callbacks_t xquic 传输层 回调/////////
////////////////////////////////////////////////////////////


int
xqc_client_request_send(xqc_h3_request_t *h3_request, user_stream_t *user_stream, client_user_data_params_t *params)
{
    if (user_stream->start_time == 0) {
        user_stream->start_time = xqc_now();
    }
    ssize_t ret = 0;
    char content_len[10];

    if (user_stream->send_body == NULL && !params->g_is_get /* POST */) {
        user_stream->send_body_max = MAX_BUF_SIZE;
        if (/* g_read_body */ 0) {
            user_stream->send_body = malloc(user_stream->send_body_max);

        } else {
            user_stream->send_body = malloc(params->g_send_body_size);
            memset(user_stream->send_body, 1, params->g_send_body_size);
        }

        if (user_stream->send_body == NULL) {
            LOGD("send_body malloc error\n");
            return -1;
        }

        /* 此处原来的逻辑幻化成了这样一句话（因为java暂时没有read form file功能开放） */
        user_stream->send_body_len = params->g_send_body_size;
    }

    if (params->g_is_get) {
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
                    .value  = {.iov_base = params->g_scheme, .iov_len = strlen(params->g_scheme)},
                    .flags  = 0,
            },
            {
                    .name   = {.iov_base = "host", .iov_len = 4},
                    .value  = {.iov_base = params->g_host, .iov_len = strlen(params->g_host)},
                    .flags  = 0,
            },
            {
                    .name   = {.iov_base = ":path", .iov_len = 5},
                    .value  = {.iov_base = params->g_url_path, .iov_len = strlen(params->g_url_path)},
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

    xqc_http_headers_t headers = {
            .headers = header,
            .count  = header_size,
    };

    int header_only = params->g_is_get;
    if (params->g_is_get) {
        header[0].value.iov_base = "GET";
        header[0].value.iov_len = sizeof("GET") - 1;
    }

    /* send header */
    if (user_stream->header_sent == 0) {
        if (0) {
            ret = xqc_h3_request_send_headers(h3_request, &headers, 0);

        } else  {
            ret = xqc_h3_request_send_headers(h3_request, &headers, header_only);
        }

        if (ret < 0) {
            LOGD("xqc_h3_request_send_headers error %zd\n", ret);
            return ret;

        } else {
            LOGD("xqc_h3_request_send_headers success size=%zd\n", ret);
            user_stream->header_sent = 1;
        }

    }

    if (header_only) {
        return 0;
    }

    int fin = 1;

    if (user_stream->send_body) {
        memset(user_stream->send_body, 0, user_stream->send_body_len);
    }

    /* send body */
    if (user_stream->send_offset < user_stream->send_body_len) {
        ret = xqc_h3_request_send_body(h3_request, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, fin);
        if (ret == -XQC_EAGAIN) {
            return 0;

        } else if (ret < 0) {
            LOGD("xqc_h3_request_send_body error %zd\n", ret);
            return 0;

        } else {
            user_stream->send_offset += ret;
            LOGD("xqc_h3_request_send_body success, sent:%zd, offset=%lu\n", ret, user_stream->send_offset);
        }
    }

    return 0;
}

//////////////////////////START//////////////////////////////
//////////////////xqc_h3_callbacks_t h3 回调/////////////////
////////////////////////////////////////////////////////////
int
xqc_client_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;

    LOGD("xqc_h3_conn_is_ready_to_send_early_data:%d\n", xqc_h3_conn_is_ready_to_send_early_data(conn));
    return 0;
}

int
xqc_client_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *) user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(user_conn->ctx->engine, cid);
    LOGD("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%lu early_data_flag:%d, conn_err:%d, ack_info:%s\n",
            stats.send_count, stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info);

    // 正确吗？
    ev_break(user_conn->ctx->eb, EVBREAK_ONE);
    return 0;
}

void
xqc_client_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;

    xqc_h3_conn_send_ping(user_conn->ctx->engine, &user_conn->cid, NULL);
    xqc_h3_conn_send_ping(user_conn->ctx->engine, &user_conn->cid, (void *) 1);

    xqc_conn_stats_t stats = xqc_conn_get_stats(user_conn->ctx->engine, &user_conn->cid);
    LOGD("0rtt_flag:%d\n", stats.early_data_flag);

    LOGD("====>DCID:%s\n", xqc_dcid_str_by_scid(user_conn->ctx->engine, &user_conn->cid));
    LOGD("====>SCID:%s\n", xqc_scid_str(&user_conn->cid));
}

void
xqc_client_h3_conn_ping_acked_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *user_data) {
    DEBUG;
    // TODO: signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x1.Cause: null pointer dereference
#if 0
    if (ping_user_data) {
        LOGD("====>ping_id:%d\n", *(int *) ping_user_data);

    } else {
        LOGD("====>no ping_id\n");
    }
#endif
}

int
xqc_client_request_close_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG
    user_stream_t *user_stream = (user_stream_t *)user_data;
    user_conn_t *user_conn = user_stream->user_conn;

    xqc_request_stats_t stats;
    stats = xqc_h3_request_get_stats(h3_request);
    LOGD("send_body_size:%zu, recv_body_size:%zu, send_header_size:%zu, recv_header_size:%zu, recv_fin:%d, err:%d\n",
           stats.send_body_size, stats.recv_body_size,
           stats.send_header_size, stats.recv_header_size,
           user_stream->recv_fin, stats.stream_err);

    if (user_conn->ctx->user_params->g_echo_check) {
        int pass = 0;
        if (user_stream->recv_fin && user_stream->send_body_len == user_stream->recv_body_len
            && memcmp(user_stream->send_body, user_stream->recv_body, user_stream->send_body_len) == 0)
        {
            pass = 1;

            /* large data read once for all */
            if (user_stream->send_body_len >= 1024 * 1024 && user_stream->body_read_notify_cnt == 1) {
                pass = 0;
                LOGD("large body received once for all");
            }
        }
        LOGD(">>>>>>>> pass:%d\n", pass);
    }

    free(user_stream->send_body);
    free(user_stream->recv_body);
    free(user_stream);

    if (g_req_cnt < user_conn->ctx->user_params->g_req_max) {
        user_stream = calloc(1, sizeof(user_stream_t));
        user_stream->user_conn = user_conn;
        user_stream->h3_request = xqc_h3_request_create(user_conn->ctx->engine, &user_conn->cid, user_stream);
        if (user_stream->h3_request == NULL) {
            LOGD("xqc_h3_request_create error\n");
            free(user_stream);
            return 0;
        }

        xqc_client_request_send(user_stream->h3_request, user_stream, user_conn->ctx->user_params);
        g_req_cnt++;
    }
    return 0;
}


int
xqc_client_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag, void *user_data)
{
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    user_conn_t* user_conn = user_stream->user_conn;

    // 头
    LOGD("开始解析头部");
    if ((flag & XQC_REQ_NOTIFY_READ_HEADER) || (flag & XQC_REQ_NOTIFY_READ_TRAILER)) {
        xqc_http_headers_t *headers;
        headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            LOGD("xqc_h3_request_recv_headers error\n");
            return -1;
        }

        for (int i = 0; i < headers->count; i++) {
            LOGD("%s = %s\n", (char *)headers->headers[i].name.iov_base, (char *)headers->headers[i].value.iov_base);
        }

        LOGD("头部解析完了");
        user_stream->header_recvd = 1;

        if (fin) {
            /* only header, receive request completed */
            user_stream->recv_fin = 1;
            return 0;
        }

        /* continue to receive body */
    }

    // 体
    LOGD("开始解析响应体");
    if (flag & XQC_REQ_NOTIFY_READ_BODY) {

        char buff[4096] = {0};
        size_t buff_size = 4096;

        if (user_stream->recv_body == NULL) {
            user_stream->recv_body = malloc(user_stream->send_body_len);
            if (user_stream->recv_body == NULL) {
                LOGD("recv_body malloc error\n");
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
                LOGD("xqc_h3_request_recv_body error %zd\n", read);
                return 0;
            }

            /* write received body to memory */
            if (user_stream->recv_body_len + read <= user_stream->send_body_len) {
                if(user_stream->recv_body == NULL) {LOGE("shift");}
                LOGD("user_stream->recv_body: %s", user_stream->recv_body);
                memcpy(user_stream->recv_body + user_stream->recv_body_len, buff, read);
            }

            read_sum += read;
            user_stream->recv_body_len += read;

        } while (read > 0 && !fin);

        if (flag & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
            fin = 1;
        }

        LOGI("xqc_h3_request_recv_body content: %s, size:%zd, offset:%zu, fin:%d",
            user_stream->recv_body, read_sum, user_stream->recv_body_len, fin);

        // 把body内容传回去
        user_conn->ctx->user_params->callback_body_content(user_conn->ctx->user_params->java_level_obj, user_stream->recv_body, user_stream->recv_body_len);
    }
    LOGD("响应体解析完了");


    if (flag & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
        fin = 1;

        LOGD("h3 fin only received\n");
    }

    if (fin) {
        user_stream->recv_fin = 1;
        xqc_request_stats_t stats;
        stats = xqc_h3_request_get_stats(h3_request);
        xqc_msec_t now_us = xqc_now();
        LOGD(">>>>>>>> request time cost:%lu us, speed:%lu K/s, send_body_size:%zu, recv_body_size:%zu \n",
                now_us - user_stream->start_time,
                (stats.send_body_size + stats.recv_body_size)*1000/(now_us - user_stream->start_time),
                stats.send_body_size, stats.recv_body_size);
    }
    return 0;
}

int
xqc_client_request_write_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    user_stream_t *user_stream = (user_stream_t *) user_data;
    return xqc_client_request_send(h3_request, user_stream, user_stream->user_conn->ctx->user_params);
}

///////////////////////////END///////////////////////////////
//////////////////xqc_h3_callbacks_t h3 回调/////////////////
////////////////////////////////////////////////////////////
int
init_ctx_engine(client_ctx_t *ctx, client_user_data_params_t *user_params) {
    DEBUG
    // 初始化 ssl config 相关设置
    xqc_engine_ssl_config_t  engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    /* client does not need to fill in private_key_file & cert_file */
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    // 初始化engine的回调
    xqc_engine_callback_t callback = {
            .set_event_timer = xqc_client_set_event_timer, /* call xqc_engine_main_logic when the timer expires */
            .log_callbacks = {
                    .xqc_log_write_err = xqc_client_write_log,
                    .xqc_log_write_stat = xqc_client_write_log,
            },
            .keylog_cb = xqc_keylog_cb,
    };

    // xquic 传输层的回调
    xqc_transport_callbacks_t tcbs = {
            .write_socket = xqc_client_write_socket,
            .save_token = xqc_client_save_token,
            .save_session_cb = save_session_cb,
            .save_tp_cb = save_tp_cb,
            .cert_verify_cb = xqc_client_cert_verify,
            .conn_closing = xqc_client_conn_closing_notify,
    };

    // xquic config (?
    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        return XQC_ERROR;
    }
    config.cfg_log_level = user_params->log_level;

    // 创建 'xqc' engine
    ctx->engine = xqc_engine_create(XQC_ENGINE_CLIENT, &config, &engine_ssl_config, &callback, &tcbs, ctx);

    // 验证是否创建成功
    if (ctx->engine == NULL) {
        LOGE("xqc_engine_create error");
        return XQC_ERROR;
    }

    // init h3 callbacks(hq可以不写吗 试一下)
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

    // 初始化h3 context
    int ret = xqc_h3_ctx_init(ctx->engine, &h3_cbs);
    if (ret != XQC_OK) {
        LOGE("init h3 context error, ret: %d\n", ret);
        return ret;
    } else {
        LOGD("init h3 ok");
    }

    // all finished
    return XQC_OK;
}

static void
jni_client_timeout_callback(struct ev_loop *main_loop, struct ev_timer *io_w, int what)
{
    LOGD("jni_client_timeout_callback now %lu\n", xqc_now());
    user_conn_t *user_conn = (user_conn_t *) io_w->data;

    if (xqc_now() - g_last_sock_op_time < (uint64_t)user_conn->ctx->user_params->g_conn_timeout * 1000000) {
        user_conn->ev_timeout.repeat = user_conn->ctx->user_params->g_conn_timeout;
        ev_timer_again(user_conn->ctx->eb, &user_conn->ev_timeout);
        return;
    }

    int rc = xqc_conn_close(user_conn->ctx->engine, &user_conn->cid);
    if (rc) {
        LOGE("xqc_conn_close error\n");
        return;
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
    int ip_type = (user_conn->ctx->user_params->g_ipv6 ? AF_INET6 : AF_INET);
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
                         const struct sockaddr *saddr, socklen_t saddr_len)
{
    int size;
    int fd = -1;
    int flags;

    /* create fd & set socket option */
    fd = socket(type, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOGE("create socket failed, errno: %d\n", errno);
        return -1;
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        LOGE("set socket nonblock failed, errno: %d\n", errno);
        goto err;
    }

    size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
        LOGE("setsockopt failed, errno: %d\n", errno);
        goto err;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int)) < 0) {
        LOGE("setsockopt failed, errno: %d\n", errno);
        goto err;
    }

    g_last_sock_op_time = xqc_now();

    /* connect to peer addr */
#if !defined(__APPLE__)
    if (connect(fd, (struct sockaddr *)saddr, saddr_len) < 0) {
        LOGE("connect socket failed, errno: %d\n", errno);
        goto err;
    }
#endif

    return fd;

    err:
    close(fd);
    return -1;
}


void
xqc_client_socket_read_handler(user_conn_t *user_conn)
{
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

            retval = recvmmsg(user_conn->fd, msgs, VLEN, 0, &timeout);
            if (retval == -1) {
                break;
            }

            uint64_t recv_time = xqc_now();
            for (int i = 0; i < retval; i++) {
                recv_sum += msgs[i].msg_len;

                if (xqc_engine_packet_process(user_conn->ctx->engine, iovecs[i].iov_base, msgs[i].msg_len,
                                              user_conn->local_addr, user_conn->local_addrlen,
                                              user_conn->peer_addr, user_conn->peer_addrlen,
                                              (xqc_msec_t)recv_time, user_conn) != XQC_OK)
                {
                    LOGE("xqc_server_read_handler: packet process err\n");
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
        recv_size = recvfrom(user_conn->fd,
                             packet_buf, sizeof(packet_buf), 0,
                             user_conn->peer_addr, &user_conn->peer_addrlen);
        if (recv_size < 0 && errno == EAGAIN) {
            break;
        }

        if (recv_size < 0) {
            LOGE("recvfrom: recvmsg = %zd(%s)\n", recv_size, strerror(errno));
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
                LOGE("getsockname error, errno: %d\n", errno);
                break;
            }
            user_conn->local_addrlen = tmp;
        }

        uint64_t recv_time = xqc_now();
        g_last_sock_op_time = recv_time;

        static char copy[XQC_PACKET_TMP_BUF_LEN];

        if (xqc_engine_packet_process(user_conn->ctx->engine, packet_buf, recv_size,
                                      user_conn->local_addr, user_conn->local_addrlen,
                                      user_conn->peer_addr, user_conn->peer_addrlen,
                                      (xqc_msec_t)recv_time, user_conn) != XQC_OK)
        {
            LOGE("xqc_client_read_handler: packet process err\n");
            return;
        }


    } while (recv_size > 0);

    if ((xqc_now() - last_recv_ts) > 200000) {
        LOGD("recving rate: %.3lf Kbps\n", (rcv_sum - last_rcv_sum) * 8.0 * 1000 / (xqc_now() - last_recv_ts));
        last_recv_ts = xqc_now();
        last_rcv_sum = rcv_sum;
    }

    finish_recv:
    LOGD("recvfrom size:%zu\n", recv_sum);
    xqc_engine_finish_recv(user_conn->ctx->engine);
}

static void
jni_client_socket_event_callback(struct ev_loop *main_loop, struct ev_timer *io_w, int what)
{
    user_conn_t *user_conn = (user_conn_t *) io_w->data;

    if (what & EV_WRITE) {
        xqc_conn_continue_send(user_conn->ctx->engine, &user_conn->cid);

    } else if (what & EV_READ) {
        xqc_client_socket_read_handler(user_conn);

    } else {
        LOGD("event callback: what=%d\n", what);
        exit(1);
    }
}

user_conn_t *
xqc_client_user_conn_create(const char *server_addr, int server_port,
                            int transport, client_ctx_t *ctx)
{
    user_conn_t *user_conn = calloc(1, sizeof(user_conn_t));
    // 把ctx交给user_conn
    user_conn->ctx = ctx;

    /* use HTTP3? */
    user_conn->h3 = transport ? 0 : 1;

    user_conn->ev_timeout.data = user_conn;
    ev_timer_init(&user_conn->ev_timeout, jni_client_timeout_callback, 0, 0);
    /* set connection timeout */
    user_conn->ev_timeout.repeat = ctx->user_params->g_conn_timeout;
    ev_timer_start(ctx->eb, &user_conn->ev_timeout);

    int ip_type = (ctx->user_params->g_ipv6 ? AF_INET6 : AF_INET);
    xqc_client_init_addr(user_conn, server_addr, server_port);

    user_conn->fd = xqc_client_create_socket(ip_type,
                                             user_conn->peer_addr, user_conn->peer_addrlen);
    if (user_conn->fd < 0) {
        LOGE("xqc_create_socket error\n");
        return NULL;
    }

    user_conn->ev_socket.data = user_conn;
    ev_io_init(&user_conn->ev_socket, jni_client_socket_event_callback, user_conn->fd, EV_READ);
    ev_io_start(ctx->eb, &user_conn->ev_socket);

    return user_conn;
}

void
init_connection_settings(xqc_conn_settings_t *settings, client_user_data_params_t *user_params) {
    // CC
    xqc_cong_ctrl_callback_t cong_ctrl;
    switch (user_params->cc) {
        case CC_TYPE_BBR:
            cong_ctrl = xqc_bbr_cb;
            LOGD("cong_ctrl type:xqc_bbr_cb");
            break;
        case CC_TYPE_CUBIC:
            cong_ctrl = xqc_cubic_cb;
            LOGD("cong_ctrl type xqc_cubic_cb");
            break;
        case CC_TYPE_RENO:
            cong_ctrl = xqc_reno_cb;
            LOGD("cong_ctrl type xqc_reno_cb");
            break;
        default:
            break;
    }

    memset(settings, 0, sizeof(xqc_conn_settings_t));
    settings->pacing_on = user_params->pacing_on;
    settings->cong_ctrl_callback = cong_ctrl;//拥塞控制算法
    settings->cc_params.customize_on = 1;//是否打开自定义
    settings->cc_params.init_cwnd = 32;//拥塞窗口数
    settings->so_sndbuf = 1024 * 1024;//socket send  buf的大小
    settings->proto_version = 1;
    settings->init_idle_time_out = 10 * 1000;//xquic default 10s
    settings->idle_time_out = 10 * 1000;//xquic default 120s
    settings->spurious_loss_detect_on = 1;//散列丢失检测
    settings->keyupdate_pkt_threshold = 0;//单个 1-rtt 密钥的数据包限制，0 表示无限制
}

void
init_connection_ssl_config(xqc_conn_ssl_config_t *conn_ssl_config, client_user_data_params_t *user_params) {
    memset(conn_ssl_config, 0, sizeof(xqc_conn_ssl_config_t));

    conn_ssl_config->session_ticket_data = "";
    conn_ssl_config->session_ticket_len = 0;
    conn_ssl_config->transport_parameter_data = "";
    conn_ssl_config->transport_parameter_data_len = 0;
}

/* start here */
int
client_send(client_user_data_params_t *user_params) {
    uint64_t start_time = xqc_now();

    // 分配client ctx空间，并初始化为全0
    client_ctx_t *ctx = calloc(1, sizeof(client_ctx_t)); // calloc有赋初值为0的功能

    // 把user_params交给ctx（request_close_notify回调找不到了）
    ctx->user_params = user_params;

    // 把client context交给ev_engine，以便于客户端引擎回调获取到ev_engine
    ctx->ev_engine.client_ctx = ctx;

    // 获取log和keylog的句柄
    jni_client_open_keylog_file(ctx);
    jni_client_open_log_file(ctx);

    // 注册event base（放在ctx中为了后面xqc engine回调找得到主eb）
    ctx->eb = ev_loop_new(EVFLAG_AUTO);

    // create ev_engine 事件并启动
    ev_timer_init(&ctx->ev_engine, jni_client_engine_callback, 0, 0);
    ev_timer_start(ctx->eb, &ctx->ev_engine);

    // 初始化context中的engine
    int engine_state = init_ctx_engine(ctx, user_params);
    if (engine_state != XQC_OK) {return XQC_ERROR;}

    // TODO: register transport callbacks(这里先没有做关于所有只用传输层的coding)
    user_conn_t *user_conn = xqc_client_user_conn_create(user_params->server_addr, user_params->server_port, user_params->transport, ctx);

    // 初始化连接
    // 连接设置
    xqc_conn_settings_t conn_settings;
    init_connection_settings(&conn_settings, user_params);
    // config
    xqc_conn_ssl_config_t conn_ssl_config;
    init_connection_ssl_config(&conn_ssl_config, user_params);
    // 得到cid
    const xqc_cid_t *cid = xqc_h3_connect(user_conn->ctx->engine, &conn_settings,
                              (const unsigned char *) "", 0,
                              user_params->g_host, 0, &conn_ssl_config,
                              (struct sockaddr *) user_conn->peer_addr,
                              16, user_conn);
    if (cid != NULL) {
        /* copy cid to its own memory space to prevent crashes caused by internal cid being freed */
        memcpy(&user_conn->cid, cid, sizeof(xqc_cid_t));

        // 终于，发送request了
        for (int i = 0; i < user_params->req_paral; i++) {
            g_req_cnt++;
            user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
            user_stream->user_conn = user_conn;
            // h3 only here
            user_stream->h3_request = xqc_h3_request_create(ctx->engine, cid, user_stream);
            if (user_stream->h3_request == NULL) {
                LOGE("xqc_h3_request_create error\n");
                continue;
            }

            xqc_client_request_send(user_stream->h3_request, user_stream, user_params);
        }
    } else {
        LOGE("xqc h3 connect error");
    }

    last_recv_ts = xqc_now();
    ev_run(ctx->eb, 0);


    // 收尾工作了！！！
    ev_timer_stop(ctx->eb, &ctx->ev_engine);
//    ev_loop_destroy(ctx->eb);
    xqc_engine_destroy(ctx->engine);

    ev_io_stop(ctx->eb, &user_conn->ev_socket);
    ev_timer_stop(ctx->eb, &user_conn->ev_timeout);

    free(user_conn->peer_addr);
    free(user_conn->local_addr);
    free(user_conn);

    LOGD("client send finish, total time:%lu us", (xqc_now() - start_time));
    return XQC_OK;
}
