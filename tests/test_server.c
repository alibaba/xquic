/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <memory.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <event2/event.h>
#include <inttypes.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include <time.h>

int
printf_null(const char *format, ...)
{
    return 0;
}


#define DEBUG printf("%s:%d (%s)\n", __FILE__, __LINE__, __FUNCTION__);

#define TEST_ADDR "127.0.0.1"
#define TEST_PORT 8443

#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100*1024*1024)

#define XQC_ALPN_TRANSPORT "transport"

#define XQC_MAX_LOG_LEN 2048

typedef struct xqc_quic_lb_ctx_s {
    uint8_t    sid_len;
    uint8_t    sid_buf[XQC_MAX_CID_LEN];
    uint8_t    conf_id;
    uint8_t    cid_len;
    uint8_t    cid_buf[XQC_MAX_CID_LEN];
} xqc_quic_lb_ctx_t;


typedef struct user_stream_s {
    xqc_stream_t       *stream;
    xqc_h3_request_t   *h3_request;
    uint64_t            send_offset;
    int                 header_sent;
    int                 header_recvd;
    char               *send_body;
    size_t              send_body_len;
    size_t              send_body_max;
    char               *recv_body;
    size_t              recv_body_len;
    FILE               *recv_body_fp;
} user_stream_t;

typedef struct user_conn_s {
    struct event        *ev_timeout;
    struct sockaddr_in6  peer_addr;
    socklen_t            peer_addrlen;
    xqc_cid_t            cid;
} user_conn_t;

typedef struct xqc_server_ctx_s {
    int fd;
    xqc_engine_t        *engine;
    struct sockaddr_in6  local_addr;
    socklen_t            local_addrlen;
    struct event        *ev_socket;
    struct event        *ev_engine;
    int                  log_fd;
    int                  keylog_fd;
    xqc_quic_lb_ctx_t    quic_lb_ctx;
} xqc_server_ctx_t;

xqc_server_ctx_t ctx;
struct event_base *eb;
int g_echo = 0;
int g_send_body_size;
int g_send_body_size_defined;
int g_save_body;
int g_read_body;
int g_spec_url;
int g_test_case;
int g_ipv6;
int g_batch=0;
char g_write_file[256];
char g_read_file[256];
char g_log_path[256];
char g_host[64] = "test.xquic.com";
char g_path[256] = "/path/resource";
char g_scheme[8] = "https";
char g_url[256];
char g_sid[XQC_MAX_CID_LEN];
size_t g_sid_len = 0;
static uint64_t last_snd_ts;


#define XQC_TEST_LONG_HEADER_LEN 32769
char test_long_value[XQC_TEST_LONG_HEADER_LEN] = {'\0'};


static inline uint64_t 
now()
{
    /* get microsecond unit time */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ul = tv.tv_sec * (uint64_t)1000000 + tv.tv_usec;
    return  ul;
}

void
xqc_server_set_event_timer(xqc_msec_t wake_after, void *user_data)
{
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) user_data;

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);

}

int
read_file_data( char * data, size_t data_len, char *filename)
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

int
xqc_server_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;
    return 0;
}

int
xqc_server_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t*)user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, ack_info:%s\n",
           stats.send_count, stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info);

    free(user_conn);
    return 0;
}

void
xqc_server_conn_handshake_finished(xqc_connection_t *conn, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;
}

void
xqc_server_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid, const xqc_cid_t *new_cid, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;

    memcpy(&user_conn->cid, new_cid, sizeof(*new_cid));

    printf("====>RETIRE SCID:%s\n", xqc_scid_str(retire_cid));
    printf("====>SCID:%s\n", xqc_scid_str(new_cid));
    printf("====>DCID:%s\n", xqc_dcid_str_by_scid(ctx.engine, new_cid));

}

int
xqc_server_stream_send(xqc_stream_t *stream, void *user_data)
{
    ssize_t ret;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    if (user_stream->send_body == NULL) {
        user_stream->send_body_max = MAX_BUF_SIZE;

        /* priority: echo > specified size > specified file > default size */
        if (g_echo) {
            user_stream->send_body = malloc(user_stream->recv_body_len);
            memcpy(user_stream->send_body, user_stream->recv_body, user_stream->recv_body_len);
            user_stream->send_body_len = user_stream->recv_body_len;

        } else {
            if (g_send_body_size_defined) {
                user_stream->send_body = malloc(g_send_body_size);
                user_stream->send_body_len = g_send_body_size;

            } else if (g_read_body) {
                user_stream->send_body = malloc(user_stream->send_body_max);
                ret = read_file_data(user_stream->send_body, user_stream->send_body_max, g_read_file);
                if (ret < 0) {
                    printf("read body error\n");
                    return -1;

                } else {
                    user_stream->send_body_len = ret;
                }

            } else {
                user_stream->send_body = malloc(g_send_body_size);
                user_stream->send_body_len = g_send_body_size;
            }
        }
    }

    if (user_stream->send_offset < user_stream->send_body_len) {
        ret = xqc_stream_send(stream, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, 1);
        if (ret < 0) {
            printf("xqc_stream_send error %zd\n", ret);
            return 0;

        } else {
            user_stream->send_offset += ret;
            printf("xqc_stream_send offset=%"PRIu64"\n", user_stream->send_offset);
        }
    }

    if (g_test_case == 12 /* test linger close */
        && user_stream->send_offset == user_stream->send_body_len)
    {
        user_conn_t *user_conn = xqc_get_conn_user_data_by_stream(stream);
        xqc_conn_close(ctx.engine, &user_conn->cid);
        printf("xqc_conn_close\n");
    }

    return 0;
}

int
xqc_server_stream_create_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    int ret = 0;

    user_stream_t *user_stream = calloc(1, sizeof(*user_stream));
    user_stream->stream = stream;
    xqc_stream_set_user_data(stream, user_stream);

    return 0;
}

int
xqc_server_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t*)user_data;
    free(user_stream->send_body);
    free(user_stream->recv_body);
    free(user_stream);

    return 0;
}

int
xqc_server_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    //DEBUG;
    int ret = xqc_server_stream_send(stream, user_data);
    return ret;
}

int
xqc_server_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    //DEBUG;
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    if (g_echo && user_stream->recv_body == NULL) {
        user_stream->recv_body = malloc(MAX_BUF_SIZE);
        if (user_stream->recv_body == NULL) {
            printf("recv_body malloc error\n");
            return -1;
        }
    }

    int save = g_save_body;

    if (save && user_stream->recv_body_fp == NULL) {
        user_stream->recv_body_fp = fopen(g_write_file, "wb");
        if (user_stream->recv_body_fp == NULL) {
            printf("open error\n");
            return -1;
        }
    }

    char buff[4096] = {0};
    size_t buff_size = 4096;
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
        read_sum += read;

        /* write received body to file */
        if (save && fwrite(buff, 1, read, user_stream->recv_body_fp) != read) {
            printf("fwrite error\n");
            return -1;
        }

        if (save) {
            fflush(user_stream->recv_body_fp);
        }

        /* write received body to memory */
        if (g_echo) {
            memcpy(user_stream->recv_body + user_stream->recv_body_len, buff, read);
        }
        user_stream->recv_body_len += read;
    } while (read > 0 && !fin);

    printf("xqc_stream_recv read:%zd, offset:%zu, fin:%d\n", read_sum, user_stream->recv_body_len, fin);

    if (fin) {
        xqc_server_stream_send(stream, user_data);
    }
    return 0;
}

int
xqc_server_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *conn_user_data)
{

    DEBUG;
    /* user_conn_t *user_conn = (xqc_server_ctx_t*)conn_user_data; */

    user_conn_t *user_conn = calloc(1, sizeof(user_conn_t));
    xqc_h3_conn_set_user_data(h3_conn, user_conn);

    xqc_h3_conn_get_peer_addr(h3_conn, (struct sockaddr *)&user_conn->peer_addr,
                              sizeof(user_conn->peer_addr), &user_conn->peer_addrlen);

    memcpy(&user_conn->cid, cid, sizeof(*cid));
    return 0;
}

int
xqc_server_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *conn_user_data)
{

    DEBUG;
    user_conn_t *user_conn = (user_conn_t*)conn_user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, ack_info:%s\n",
           stats.send_count, stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info);

    free(user_conn);
    //event_base_loopbreak(eb);
    return 0;
}

void
xqc_server_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *conn_user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *)conn_user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, &user_conn->cid);
    printf("0rtt_flag:%d\n", stats.early_data_flag);
}

void
xqc_server_h3_conn_update_cid_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *retire_cid,
    const xqc_cid_t *new_cid, void *conn_user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *)conn_user_data;

    memcpy(&user_conn->cid, new_cid, sizeof(*new_cid));

    printf("====>RETIRE SCID:%s\n", xqc_scid_str(retire_cid));
    printf("====>SCID:%s\n", xqc_scid_str(new_cid));
    printf("====>DCID:%s\n", xqc_dcid_str_by_scid(ctx.engine, new_cid));

}

#define MAX_HEADER 100

int
xqc_server_request_send(xqc_h3_request_t *h3_request, user_stream_t *user_stream)
{
    ssize_t ret = 0;
    int header_cnt = 6;
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
            .value  = {.iov_base = g_path, .iov_len = strlen(g_path)},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "content-type", .iov_len = 12},
            .value  = {.iov_base = "text/plain", .iov_len = 10},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = ":status", .iov_len = 7},
            .value  = {.iov_base = "200", .iov_len = 3},
            .flags  = 0,
        },
    };

    if (g_test_case == 9) {
        memset(test_long_value, 'a', XQC_TEST_LONG_HEADER_LEN - 1);

        xqc_http_header_t test_long_hdr = {
            .name   = {.iov_base = "long_filed_line", .iov_len = 15},
            .value  = {.iov_base = test_long_value, .iov_len = strlen(test_long_value)},
            .flags  = 0,
        };

        header[header_cnt] = test_long_hdr;
        header_cnt++;
    }

    xqc_http_headers_t headers = {
        .headers = header,
        .count  = header_cnt,
    };

    int header_only = 0;
    if (g_echo && user_stream->recv_body_len == 0) {
        header_only = 1;
    }

    if (user_stream->header_sent == 0) {
        ret = xqc_h3_request_send_headers(h3_request, &headers, header_only);
        if (ret < 0) {
            printf("xqc_h3_request_send_headers error %zd\n", ret);
            return ret;

        } else {
            printf("xqc_h3_request_send_headers success size=%zd\n", ret);
            user_stream->header_sent = 1;
        }

        if (header_only) {
            return 0;
        }
    }

    if (user_stream->send_body == NULL) {
        user_stream->send_body_max = MAX_BUF_SIZE;

        /* priority: echo > specified size > specified file > default size */
        if (g_echo) {
            user_stream->send_body = malloc(user_stream->recv_body_len);
            memcpy(user_stream->send_body, user_stream->recv_body, user_stream->recv_body_len);
            user_stream->send_body_len = user_stream->recv_body_len;

        } else {
            if (g_send_body_size_defined) {
                user_stream->send_body = malloc(g_send_body_size);
                user_stream->send_body_len = g_send_body_size;

            } else if (g_read_body) {
                user_stream->send_body = malloc(user_stream->send_body_max);
                ret = read_file_data(user_stream->send_body, user_stream->send_body_max, g_read_file);
                if (ret < 0) {
                    printf("read body error\n");
                    return -1;

                } else {
                    user_stream->send_body_len = ret;
                }

            } else {
                user_stream->send_body = malloc(g_send_body_size);
                user_stream->send_body_len = g_send_body_size;
            }
        }
    }

    if (user_stream->send_body) {
        memset(user_stream->send_body, 0, user_stream->send_body_len);
    }

    if (user_stream->send_offset < user_stream->send_body_len) {
        ret = xqc_h3_request_send_body(h3_request, user_stream->send_body + user_stream->send_offset,
                                       user_stream->send_body_len - user_stream->send_offset, 1);
        if (ret < 0) {
            printf("xqc_h3_request_send_body error %zd\n", ret);
            return 0;

        } else {
            user_stream->send_offset += ret;
            printf("xqc_h3_request_send_body sent:%zd, offset=%"PRIu64"\n", ret, user_stream->send_offset);
        }
    }

    if (g_test_case == 12 /* test linger close */
        && user_stream->send_offset == user_stream->send_body_len)
    {
        user_conn_t *user_conn = xqc_h3_get_conn_user_data_by_request(h3_request);
        xqc_h3_conn_close(ctx.engine, &user_conn->cid);
        printf("xqc_h3_conn_close\n");
    }

    return 0;
}

int
xqc_server_request_create_notify(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    DEBUG;
    int ret = 0;

    user_stream_t *user_stream = calloc(1, sizeof(*user_stream));
    user_stream->h3_request = h3_request;
    xqc_h3_request_set_user_data(h3_request, user_stream);

    return 0;
}

int
xqc_server_request_close_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t*)user_data;
    free(user_stream->send_body);
    free(user_stream->recv_body);
    free(user_stream);

    return 0;
}

int
xqc_server_request_write_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    //DEBUG;
    int ret = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    ret = xqc_server_request_send(h3_request, user_stream);
    return ret;
}

int
xqc_server_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag, void *user_data)
{
    //DEBUG;
    int ret;
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    if ((flag & XQC_REQ_NOTIFY_READ_HEADER) || (flag & XQC_REQ_NOTIFY_READ_TRAILER)) {
        xqc_http_headers_t *headers;
        headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            printf("xqc_h3_request_recv_headers error\n");
            return -1;
        }

        for (int i = 0; i < headers->count; i++) {
            printf("%s = %s\n", (char*)headers->headers[i].name.iov_base, (char*)headers->headers[i].value.iov_base);
        }

        user_stream->header_recvd++;

        if (fin) {
            /* only header. request received, start processing business logic. */
            xqc_server_request_send(h3_request, user_stream);
            return 0;
        }

        /* continue to receive body */
    }

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {

        if (g_echo && user_stream->recv_body == NULL) {
            user_stream->recv_body = malloc(MAX_BUF_SIZE);
            if (user_stream->recv_body == NULL) {
                printf("recv_body malloc error\n");
                return -1;
            }
        }

        int save = g_save_body;

        if (save && user_stream->recv_body_fp == NULL) {
            user_stream->recv_body_fp = fopen(g_write_file, "wb");
            if (user_stream->recv_body_fp == NULL) {
                printf("open error\n");
                return -1;
            }
        }

        char buff[4096] = {0};
        size_t buff_size = 4096;
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

            read_sum += read;

            /* write received body to file */
            if (save && fwrite(buff, 1, read, user_stream->recv_body_fp) != read) {
                printf("fwrite error\n");
                return -1;
            }

            if (save) {
                fflush(user_stream->recv_body_fp);
            }

            /* write received body to memory */
            if (g_echo) {
                memcpy(user_stream->recv_body + user_stream->recv_body_len, buff, read);
            }
            user_stream->recv_body_len += read;

        } while (read > 0 && !fin);

        printf("xqc_h3_request_recv_body read:%zd, offset:%zu, fin:%d\n", read_sum, user_stream->recv_body_len, fin);
    }

    if (flag & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
        fin = 1;

        printf("h3 fin only received\n");
    }

    if (fin) {
        xqc_server_request_send(h3_request, user_stream);
    }

    return 0;
}


ssize_t 
xqc_server_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data; //user_data may be empty when "reset" is sent
    ssize_t res;
    static ssize_t last_snd_sum = 0;
    static ssize_t snd_sum = 0;
    int fd = ctx.fd;

    /* COPY to run corruption test cases */
    unsigned char send_buf[XQC_PACKET_TMP_BUF_LEN];
    size_t send_buf_size = 0;
    
    if (size > XQC_PACKET_TMP_BUF_LEN) {
        printf("xqc_server_write_socket err: size=%zu is too long\n", size);
        return XQC_SOCKET_ERROR;
    }
    send_buf_size = size;
    memcpy(send_buf, buf, send_buf_size);

    /* server Initial dcid corruption ... */
    if (g_test_case == 3) {
        /* client initial dcid corruption, bytes [6, 13] is the DCID of xquic's Initial packet */
        g_test_case = -1;
        send_buf[6] = ~send_buf[6];
    }

    /* server Initial scid corruption ... */
    if (g_test_case == 4) {
        /* bytes [15, 22] is the SCID of xquic's Initial packet */
        g_test_case = -1;
        send_buf[15] = ~send_buf[15];
    }

    /* server odcid hash ... */
    if (g_test_case == 5) {
        /* the first dategram of server is Initial/server hello, drop it */
        g_test_case = -1;
        return size;
    }

    do {
        errno = 0;
        res = sendto(fd, send_buf, send_buf_size, 0, peer_addr, peer_addrlen);
        //printf("xqc_server_send write %zd, %s\n", res, strerror(errno));
        if (res < 0) {
            printf("xqc_server_write_socket err %zd %s\n", res, strerror(errno));
            if (errno == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }

        } else {
            snd_sum += res;
        }
    } while ((res < 0) && (errno == EINTR));

    if ((now() - last_snd_ts) > 200000) {
        printf("sending rate: %.3f Kbps\n", (snd_sum - last_snd_sum) * 8.0 * 1000 / (now() - last_snd_ts));
        last_snd_ts = now();
        last_snd_sum = snd_sum;
    }

    return res;
}


ssize_t
xqc_server_send_stateless_reset(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, int fd, void *user)
{
    return xqc_server_write_socket(buf, size, peer_addr, peer_addrlen, user);
}

void
xqc_server_socket_write_handler(xqc_server_ctx_t *ctx)
{
    DEBUG
}

int g_recv_total = 0;
void
xqc_server_socket_read_handler(xqc_server_ctx_t *ctx)
{
    //DEBUG;
    ssize_t recv_sum = 0;
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = g_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    ssize_t recv_size = 0;
    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];
    uint64_t recv_time;

#ifdef __linux__
    int batch = 0; /* packets are not necessarily on the same connection */
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
                msgs[i].msg_hdr.msg_namelen = peer_addrlen;
            }

            timeout.tv_sec = TIMEOUT;
            timeout.tv_nsec = 0;

            retval = recvmmsg(ctx->fd, msgs, VLEN, 0, &timeout);
            if (retval == -1) {
                break;
            }

            uint64_t recv_time = now();
            for (int i = 0; i < retval; i++) {
                recv_sum += msgs[i].msg_len;

                if (xqc_engine_packet_process(ctx->engine, iovecs[i].iov_base, msgs[i].msg_len,
                                              (struct sockaddr *) (&ctx->local_addr), ctx->local_addrlen,
                                              (struct sockaddr *) (&pa[i]), peer_addrlen,
                                              (xqc_msec_t) recv_time, NULL) != XQC_OK)
                {
                    printf("xqc_server_read_handler: packet process err\n");
                    return;
                }
            }
        } while (retval > 0);
        goto finish_recv;
    }
#endif

    do {
        recv_size = recvfrom(ctx->fd, packet_buf, sizeof(packet_buf), 0, (struct sockaddr *) &peer_addr,
                             &peer_addrlen);
        if (recv_size < 0 && errno == EAGAIN) {
            break;
        }

        if (recv_size < 0) {
            printf("!!!!!!!!!recvfrom: recvmsg = %zd err=%s\n", recv_size, strerror(errno));
            break;
        }

        /* amplification limit */
        if (g_test_case == 8) {
            static int loss_num = 0;
            loss_num++;
            /* continous loss to make server at amplification limit */
            if (loss_num >= 2 && loss_num <= 10) {
                continue;
            }
        }

        recv_sum += recv_size;

        recv_time = now();
        //printf("xqc_server_read_handler recv_size=%zd, recv_time=%llu, now=%llu, recv_total=%d\n", recv_size, recv_time, now(), ++g_recv_total);
        /*printf("peer_ip: %s, peer_port: %d\n", inet_ntoa(ctx->peer_addr.sin_addr), ntohs(ctx->peer_addr.sin_port));
        printf("local_ip: %s, local_port: %d\n", inet_ntoa(ctx->local_addr.sin_addr), ntohs(ctx->local_addr.sin_port));*/
        if (xqc_engine_packet_process(ctx->engine, packet_buf, recv_size,
                                      (struct sockaddr *) (&ctx->local_addr), ctx->local_addrlen,
                                      (struct sockaddr *) (&peer_addr), peer_addrlen,
                                      (xqc_msec_t) recv_time, NULL) != XQC_OK)
        {
            printf("xqc_server_read_handler: packet process err\n");
            return;
        }
    } while (recv_size > 0);

finish_recv:
    printf("recvfrom size:%zu\n", recv_sum);
    xqc_engine_finish_recv(ctx->engine);
}


static void
xqc_server_socket_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) arg;

    if (what & EV_WRITE) {
        xqc_server_socket_write_handler(ctx);

    } else if (what & EV_READ) {
        xqc_server_socket_read_handler(ctx);

    } else {
        printf("event callback: what=%d\n", what);
        exit(1);
    }
}

int
xqc_server_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = calloc(1, sizeof(*user_conn));
    xqc_conn_set_transport_user_data(conn, user_conn);

    xqc_int_t ret = xqc_conn_get_peer_addr(conn, (struct sockaddr *)&user_conn->peer_addr,
                                           sizeof(user_conn->peer_addr), &user_conn->peer_addrlen);
    if (ret != XQC_OK) {
        return -1;
    }

    memcpy(&user_conn->cid, cid, sizeof(*cid));

    if (g_test_case == 11) {
        g_test_case = -1;
        return -1;
    }

    if (g_batch) {
        int ret = connect(ctx.fd, &user_conn->peer_addr, user_conn->peer_addrlen);
        if (ret != 0) {
            printf("connect error, errno: %d\n", errno);
            return ret;
        }
    }

    return 0;
}

static int
xqc_server_create_socket(const char *addr, unsigned int port)
{
    int fd;
    int type = g_ipv6 ? AF_INET6 : AF_INET;
    ctx.local_addrlen = g_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    struct sockaddr *saddr = (struct sockaddr *)&ctx.local_addr;
    int size;
    int optval;

    fd = socket(type, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("create socket failed, errno: %d\n", errno);
        return -1;
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("set socket nonblock failed, errno: %d\n", errno);
        goto err;
    }

    optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
        goto err;
    }

    size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
        goto err;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
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
        addr_v4->sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(fd, saddr, ctx.local_addrlen) < 0) {
        printf("bind socket failed, errno: %d\n", errno);
        goto err;
    }

    return fd;

err:
    close(fd);
    return -1;
}


static void
xqc_server_engine_callback(int fd, short what, void *arg)
{
    //DEBUG;
    printf("timer wakeup now:%"PRIu64"\n", now());
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}

static ssize_t
xqc_server_cid_generate(const xqc_cid_t *ori_cid, uint8_t *cid_buf, size_t cid_buflen, void *engine_user_data)
{
    ssize_t              cid_buf_index = 0, i;
    ssize_t              cid_len, sid_len;
    xqc_quic_lb_ctx_t   *quic_lb_ctx;

    quic_lb_ctx = &(ctx.quic_lb_ctx);

    cid_len = quic_lb_ctx->cid_len;
    sid_len = quic_lb_ctx->sid_len;

    if (sid_len < 0 || sid_len > cid_len || cid_len > cid_buflen) {
        return XQC_ERROR;
    }

    cid_buf[cid_buf_index] = quic_lb_ctx->conf_id;
    cid_buf_index += 1;

    memcpy(cid_buf + cid_buf_index, quic_lb_ctx->sid_buf, sid_len);
    cid_buf_index += sid_len;

    for (i = cid_buf_index; i < cid_len; i++) {
        cid_buf[i] = (uint8_t)rand();
    }

    /* xqc_log(engine->log, XQC_LOG_DEBUG, "|cid:%s|cid_len:%ud|", xqc_scid_str(cid), cid->cid_len); */
    return cid_len;
}


int 
xqc_server_open_log_file(void *engine_user_data)
{
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t*)engine_user_data;
    //ctx->log_fd = open("/home/jiuhai.zjh/ramdisk/slog", (O_WRONLY | O_APPEND | O_CREAT), 0644);
    ctx->log_fd = open(g_log_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return 0;
}

int 
xqc_server_close_log_file(void *engine_user_data)
{
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        return -1;
    }
    close(ctx->log_fd);
    return 0;
}


void 
xqc_server_write_log(xqc_log_level_t lvl, const void *buf, size_t count, void *engine_user_data)
{
    unsigned char log_buf[XQC_MAX_LOG_LEN + 1];

    xqc_server_ctx_t *ctx = (xqc_server_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        printf("xqc_server_write_log fd err\n");
        return;
    }

    int log_len = snprintf(log_buf, XQC_MAX_LOG_LEN + 1, "%s\n", (char*)buf);
    if (log_len < 0) {
        printf("xqc_server_write_log err\n");
        return;
    }

    int write_len = write(ctx->log_fd, log_buf, log_len);
    if (write_len < 0) {
        printf("xqc_server_write_log write failed, errno: %d\n", errno);
    }
}


/**
 * key log functions
 */

int
xqc_server_open_keylog_file(xqc_server_ctx_t *ctx)
{
    ctx->keylog_fd = open("./skeys.log", (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->keylog_fd <= 0) {
        return -1;
    }

    return 0;
}

int
xqc_server_close_keylog_file(xqc_server_ctx_t *ctx)
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
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t*)user_data;
    if (ctx->keylog_fd <= 0) {
        printf("write keys error!\n");
        return;
    }

    int write_len = write(ctx->keylog_fd, line, strlen(line));
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", errno);
        return;
    }

    write_len = write(ctx->keylog_fd, "\n", 1);
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", errno);
    }
}

#if defined(XQC_SUPPORT_SENDMMSG)
ssize_t xqc_server_write_mmsg(const struct iovec *msg_iov, unsigned int vlen,
                                const struct sockaddr *peer_addr,
                                socklen_t peer_addrlen, void *user)
{
    printf("write_mmsg!\n");
    const int MAX_SEG = 128;
    user_conn_t *user_conn = (user_conn_t *) user;
    ssize_t res = 0;
    int fd = ctx.fd;
    struct mmsghdr mmsg[MAX_SEG];
    memset(&mmsg, 0, sizeof(mmsg));
    for (int i = 0; i < vlen; i++) {
        mmsg[i].msg_hdr.msg_iov = (struct iovec *)&msg_iov[i];
        mmsg[i].msg_hdr.msg_iovlen = 1;
    }
    do {
        errno = 0;
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

void
stop(int signo)
{
    event_base_loopbreak(eb);
    xqc_engine_destroy(ctx.engine);
    fflush(stdout);
    exit(0);
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
"   -p    Server port.\n"
"   -e    Echo. Send received body.\n"
"   -c    Congestion Control Algorithm. r:reno b:bbr c:cubic B:bbr2 bbr+ bbr2+\n"
"   -C    Pacing on.\n"
"   -s    Body size to send.\n"
"   -w    Write received body to file.\n"
"   -r    Read sending body from file. priority e > s > r\n"
"   -l    Log level. e:error d:debug.\n"
"   -u    Url. default https://test.xquic.com/path/resource\n"
"   -x    Test case ID\n"
"   -6    IPv6\n"
"   -b    batch\n"
"   -S    server sid\n"
"   -o    Output log file path, default ./slog\n"
, prog);
}


int main(int argc, char *argv[]) {

    signal (SIGINT, stop);
    g_send_body_size = 1024*1024;
    g_send_body_size_defined = 0;
    g_save_body = 0;
    g_read_body = 0;
    g_spec_url = 0;
    g_ipv6 = 0;

    int server_port = TEST_PORT;
    char c_cong_ctl = 'b';
    char c_log_level = 'd';
    int c_cong_plus = 0;
    int pacing_on = 0;
    strncpy(g_log_path, "./slog", sizeof(g_log_path));

    int ch = 0;
    while ((ch = getopt(argc, argv, "p:ec:Cs:w:r:l:u:x:6bS:o:")) != -1) {
        switch (ch) {
        case 'p': /* Server port. */
            printf("option port :%s\n", optarg);
            server_port = atoi(optarg);
            break;
        case 'e': /* Echo. Send received body. */
            printf("option echo :%s\n", "on");
            g_echo = 1;
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
        case 'C': /* Pacing on. */
            printf("option pacing :%s\n", "on");
            pacing_on = 1;
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
        case 'r': /* Read sending body from file. priority e > s > r */
            printf("option read body :%s\n", optarg);
            snprintf(g_read_file, sizeof(g_read_file), optarg);
            g_read_body = 1;
            break;
        case 'l': /* Log level. e:error d:debug. */
            printf("option log level :%s\n", optarg);
            c_log_level = optarg[0];
            break;
        case 'u': /* Url. default https://test.xquic.com/path/resource */
            printf("option url :%s\n", optarg);
            snprintf(g_url, sizeof(g_url), optarg);
            g_spec_url = 1;
            sscanf(g_url, "%[^://]://%[^/]%[^?]", g_scheme, g_host, g_path);
            break;
        case 'x': /* Test case ID */
            printf("option test case id: %s\n", optarg);
            g_test_case = atoi(optarg);
            break;
        case '6': /* IPv6 */
            printf("option IPv6 :%s\n", "on");
            g_ipv6 = 1;
            break;
        case 'b': /* batch */
            printf("option send batch: on\n");
            g_batch = 1;
            break;
        case 'S': /* set server sid */
            printf("set server sid \n");
            snprintf(g_sid, sizeof(g_sid), optarg);
            g_sid_len = strlen(g_sid);
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

    memset(&ctx, 0, sizeof(ctx));

    char g_session_ticket_file[] = "session_ticket.key";

    xqc_server_open_keylog_file(&ctx);
    xqc_server_open_log_file(&ctx);

    xqc_engine_ssl_config_t  engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    engine_ssl_config.private_key_file = "./server.key";
    engine_ssl_config.cert_file = "./server.crt";
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    char g_session_ticket_key[2048];
    int ticket_key_len  = read_file_data(g_session_ticket_key, sizeof(g_session_ticket_key), g_session_ticket_file);

    if (ticket_key_len < 0) {
        engine_ssl_config.session_ticket_key_data = NULL;
        engine_ssl_config.session_ticket_key_len = 0;

    } else {
        engine_ssl_config.session_ticket_key_data = g_session_ticket_key;
        engine_ssl_config.session_ticket_key_len = ticket_key_len;
    }

    xqc_engine_callback_t callback = {
        .set_event_timer = xqc_server_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = xqc_server_write_log,
            .xqc_log_write_stat = xqc_server_write_log,
        },
        .keylog_cb = xqc_keylog_cb,

    };

    xqc_transport_callbacks_t tcbs = {
        .server_accept = xqc_server_accept,
        .write_socket = xqc_server_write_socket,
        .conn_update_cid_notify = xqc_server_conn_update_cid_notify,
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
#if XQC_BBR2_PLUS_ENABLED
        if (c_cong_plus) {
            cong_flags |= XQC_BBR2_FLAG_RTTVAR_COMPENSATION;
            cong_flags |= XQC_BBR2_FLAG_FAST_CONVERGENCE;
        }
#endif
    }
#endif
    else {
        printf("unknown cong_ctrl, option is b, r, c\n");
        return -1;
    }
    printf("congestion control flags: %x\n", cong_flags);

    xqc_conn_settings_t conn_settings = {
        .pacing_on  =   pacing_on,
        .cong_ctrl_callback = cong_ctrl,
        .cc_params  =   {.customize_on = 1, .init_cwnd = 32, .cc_optimization_flags = cong_flags},
        .spurious_loss_detect_on = 0,
    };

    if (g_test_case == 6) {
        conn_settings.idle_time_out = 10000;
    }

    if (g_test_case == 12) {
        conn_settings.linger.linger_on = 1;
    }

    xqc_server_set_conn_settings(&conn_settings);

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) < 0) {
        return -1;
    }
    config.cfg_log_level = c_log_level == 'e' ? XQC_LOG_ERROR : (c_log_level == 'i' ? XQC_LOG_INFO : c_log_level == 'w'? XQC_LOG_WARN: XQC_LOG_DEBUG);

    eb = event_base_new();
    ctx.ev_engine = event_new(eb, -1, 0, xqc_server_engine_callback, &ctx);

#if defined(XQC_SUPPORT_SENDMMSG)
    if (g_batch) {
        tcbs.write_mmsg = xqc_server_write_mmsg,
        config.sendmmsg_on = 1;
    }
#endif

    /* test server cid negotiate */
    if (g_test_case == 1 || g_test_case == 5 || g_test_case == 6 || g_sid_len != 0) {

        callback.cid_generate_cb = xqc_server_cid_generate;
        config.cid_negotiate = 1;
        config.cid_len = XQC_MAX_CID_LEN;
    }

    ctx.engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &engine_ssl_config,
                                   &callback, &tcbs, &ctx);
    if (ctx.engine == NULL) {
        printf("error create engine\n");
        return -1;
    }

    /* register http3 callbacks */
    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify = xqc_server_h3_conn_create_notify,
            .h3_conn_close_notify = xqc_server_h3_conn_close_notify,
            .h3_conn_handshake_finished = xqc_server_h3_conn_handshake_finished,
        },
        .h3r_cbs = {
            .h3_request_write_notify = xqc_server_request_write_notify,
            .h3_request_read_notify = xqc_server_request_read_notify,
            .h3_request_create_notify = xqc_server_request_create_notify,
            .h3_request_close_notify = xqc_server_request_close_notify,
        }
    };

    /* register transport callbacks */
    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs = {
            .conn_create_notify = xqc_server_conn_create_notify,
            .conn_close_notify = xqc_server_conn_close_notify,
            .conn_handshake_finished = xqc_server_conn_handshake_finished,
        },
        .stream_cbs = {
            .stream_write_notify = xqc_server_stream_write_notify,
            .stream_read_notify = xqc_server_stream_read_notify,
            .stream_create_notify = xqc_server_stream_create_notify,
            .stream_close_notify = xqc_server_stream_close_notify,
        }
    };


    /* test NULL stream callback */
    if (g_test_case == 2) {
        memset(&ap_cbs.stream_cbs, 0, sizeof(ap_cbs.stream_cbs));
    }

    /* init http3 context */
    xqc_int_t ret = xqc_h3_ctx_init(ctx.engine, &h3_cbs);
    if (ret != XQC_OK) {
        printf("init h3 context error, ret: %d\n", ret);
        return ret;
    }

    xqc_engine_register_alpn(ctx.engine, XQC_ALPN_TRANSPORT, 9, &ap_cbs);

    if (g_test_case == 10) {
        xqc_h3_engine_set_max_field_section_size(ctx.engine, 10000000);
    }

    /* for lb cid generate */
    memcpy(ctx.quic_lb_ctx.sid_buf, g_sid, g_sid_len);
    ctx.quic_lb_ctx.sid_len = g_sid_len;
    ctx.quic_lb_ctx.conf_id = 0;
    ctx.quic_lb_ctx.cid_len = XQC_MAX_CID_LEN;

    ctx.fd = xqc_server_create_socket(TEST_ADDR, server_port);
    if (ctx.fd < 0) {
        printf("xqc_create_socket error\n");
        return 0;
    }

    ctx.ev_socket = event_new(eb, ctx.fd, EV_READ | EV_PERSIST, xqc_server_socket_event_callback, &ctx);

    event_add(ctx.ev_socket, NULL);
    last_snd_ts = 0;
    event_base_dispatch(eb);

    xqc_h3_ctx_destroy(ctx.engine);
    xqc_engine_destroy(ctx.engine);
    xqc_server_close_keylog_file(&ctx);
    xqc_server_close_log_file(&ctx);

    return 0;
}
