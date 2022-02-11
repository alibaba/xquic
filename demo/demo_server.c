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
#include <ctype.h>

#include "common.h"
#include "xqc_hq.h"



#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100*1024*1024)


/**
 * ============================================================================
 * the network config definition section
 * network config is those arguments about socket connection
 * all configuration on network should be put under this section
 * ============================================================================
 */

#define DEFAULT_IP   "127.0.0.1"
#define DEFAULT_PORT 8443

typedef struct xqc_demo_svr_net_config_s {

    /* server addr info */
    struct sockaddr addr;
    int     addr_len;
    char    ip[64];
    short   port;

    /* ipv4 or ipv6 */
    int     ipv6;

    /* congestion control algorithm */
    CC_TYPE cc;     /* congestion control algorithm */
    int     pacing; /* is pacing on */

    /* idle persist timeout */
    int     conn_timeout;
} xqc_demo_svr_net_config_t;



/**
 * ============================================================================
 * the quic config definition section
 * quic config is those arguments about quic connection
 * all configuration on network should be put under this section
 * ============================================================================
 */

#define SESSION_TICKET_KEY_FILE     "session_ticket.key"
#define SESSION_TICKET_KEY_BUF_LEN  2048
typedef struct xqc_demo_svr_quic_config_s {
    /* cipher config */
    char cipher_suit[CIPHER_SUIT_LEN];
    char groups[TLS_GROUPS_LEN];

    /* 0-rtt config */
    int  stk_len;                           /* session ticket len */
    char stk[SESSION_TICKET_KEY_BUF_LEN];   /* session ticket buf */

    /* retry */
    int  retry_on;
} xqc_demo_svr_quic_config_t;


/**
 * ============================================================================
 * the environment config definition section
 * environment config is those arguments about IO inputs and outputs
 * all configuration on environment should be put under this section
 * ============================================================================
 */

#define LOG_PATH "slog.log"
#define KEY_PATH "skeys.log"
#define SOURCE_DIR  "."
#define PRIV_KEY_PATH "server.key"
#define CERT_PEM_PATH "server.crt"



/* environment config */
typedef struct xqc_demo_svr_env_config_s {
    /* log path */
    char    log_path[PATH_LEN];
    int     log_level;

    /* source file dir */
    char    source_file_dir[RESOURCE_LEN];

    /* tls certs */
    char    priv_key_path[PATH_LEN];
    char    cert_pem_path[PATH_LEN];

    /* key export */
    int     key_output_flag;
    char    key_out_path[PATH_LEN];
} xqc_demo_svr_env_config_t;


typedef struct xqc_demo_svr_args_s {
    /* network args */
    xqc_demo_svr_net_config_t    net_cfg;

    /* quic args */
    xqc_demo_svr_quic_config_t   quic_cfg;

    /* environment args */
    xqc_demo_svr_env_config_t    env_cfg;
} xqc_demo_svr_args_t;



typedef struct xqc_demo_svr_ctx_s {
    xqc_engine_t        *engine;
    struct event        *ev_engine;

    /* ipv4 server */
    int                 fd;
    struct sockaddr_in  local_addr;
    socklen_t           local_addrlen;
    struct event        *ev_socket;

    /* ipv6 server */
    int                 fd6;
    struct sockaddr_in6 local_addr6;
    socklen_t           local_addrlen6;
    struct event        *ev_socket6;

    /* used to remember fd type to send stateless reset */
    int                 current_fd;

    int                 log_fd;
    int                 keylog_fd;

    xqc_demo_svr_args_t *args;
} xqc_demo_svr_ctx_t;


typedef struct xqc_demo_svr_user_conn_s {
    struct event          *ev_timeout;
    struct sockaddr_in6     peer_addr;
    socklen_t               peer_addrlen;
    xqc_cid_t               cid;
    xqc_demo_svr_ctx_t     *ctx;
} xqc_demo_svr_user_conn_t;

typedef struct xqc_demo_svr_resource_s {
    FILE       *fp;
    int         total_len;      /* total len of file */
    int         total_offset;   /* total sent offset of file */
    char       *buf;           /* send buf */
    int         buf_size;       /* send buf size */
    int         buf_len;        /* send buf len */
    int         buf_offset;     /* send buf offset */
} xqc_demo_svr_resource_t;


#define REQ_BUF_SIZE        2048
#define REQ_H3_BODY_SIZE    1024 * 1024
typedef struct xqc_demo_svr_user_stream_s {
    xqc_hq_request_t           *hq_request;
    xqc_h3_request_t           *h3_request;

    // uint64_t            send_offset;
    int                         header_sent;
    int                         header_recvd;
    size_t                      send_body_len;
    size_t                      recv_body_len;
    char                       *recv_buf;

    // xqc_demo_svr_user_conn_t         *conn;
    xqc_demo_svr_resource_t     res;  /* resource info */
} xqc_demo_svr_user_stream_t;


/* the global unique server context */
xqc_demo_svr_ctx_t svr_ctx;



/******************************************************************************
 *                   start of engine callback functions                       *
 ******************************************************************************/

void
xqc_demo_svr_set_event_timer(xqc_msec_t wake_after, void *eng_user_data)
{
    xqc_demo_svr_ctx_t *ctx = (xqc_demo_svr_ctx_t *)eng_user_data;

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);
}


int
xqc_demo_svr_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid,
    void *eng_user_data)
{
    DEBUG;

    return 0;
}

/**
 * start of server keylog functions
 */
int
xqc_demo_svr_open_log_file(xqc_demo_svr_ctx_t *ctx)
{
    ctx->log_fd = open(ctx->args->env_cfg.log_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return 0;
}

int
xqc_demo_svr_close_log_file(xqc_demo_svr_ctx_t *ctx)
{
    if (ctx->log_fd <= 0) {
        return -1;
    }
    close(ctx->log_fd);
    return 0;
}

void
xqc_demo_svr_write_log_file(xqc_log_level_t lvl, const void *buf, size_t size, void *eng_user_data)
{
    xqc_demo_svr_ctx_t *ctx = (xqc_demo_svr_ctx_t*)eng_user_data;
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
 * start of server keylog functions
 */
int
xqc_demo_svr_open_keylog_file(xqc_demo_svr_ctx_t *ctx)
{
    ctx->keylog_fd = open(ctx->args->env_cfg.key_out_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->keylog_fd <= 0) {
        return -1;
    }

    return 0;
}

int
xqc_demo_svr_close_keylog_file(xqc_demo_svr_ctx_t *ctx)
{
    if (ctx->keylog_fd <= 0) {
        return -1;
    }
    close(ctx->keylog_fd);
    ctx->keylog_fd = 0;
    return 0;
}

void
xqc_demo_svr_keylog_cb(const char *line, void *eng_user_data)
{
    xqc_demo_svr_ctx_t *ctx = (xqc_demo_svr_ctx_t*)eng_user_data;
    if (ctx->keylog_fd <= 0) {
        printf("write keys error!\n");
        return;
    }

    int write_len = write(ctx->keylog_fd, line, strlen(line));
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", errno);
        return;
    }
    write_len = write(ctx->keylog_fd, line_break, 1);
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", errno);
    }
}


/******************************************************************************
 *                   start of common callback functions                       *
 ******************************************************************************/
void
xqc_demo_svr_tls_key_cb(char *key, void *conn_user_data)
{
    xqc_demo_svr_user_conn_t *user_conn = (xqc_demo_svr_user_conn_t*)conn_user_data;
    if (user_conn->ctx->args->env_cfg.key_output_flag
        && strlen(user_conn->ctx->args->env_cfg.key_out_path))
    {
        FILE* pkey = fopen(user_conn->ctx->args->env_cfg.key_out_path, "a+");
        if (NULL == pkey) {
            return;
        }

        fprintf(pkey, key);
        fclose(pkey);
    }
}


void
xqc_demo_svr_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
    const xqc_cid_t *new_cid, void *user_data)
{
    xqc_demo_svr_user_conn_t *user_conn = (xqc_demo_svr_user_conn_t *)user_data;
    memcpy(&user_conn->cid, new_cid, sizeof(*new_cid));
}

/******************************************************************************
 *                              common functions                              *
 ******************************************************************************/

void
xqc_demo_svr_close_user_stream_resource(xqc_demo_svr_user_stream_t * user_stream)
{
    if (user_stream->res.buf) {
        free(user_stream->res.buf);
        user_stream->res.buf = NULL;
    }

    if (user_stream->res.fp)
    {
        fclose(user_stream->res.fp);
        user_stream->res.fp = NULL;
    }
}


/******************************************************************************
 *                       start of hq callback functions                       *
 ******************************************************************************/

int
xqc_demo_svr_hq_conn_create_notify(xqc_hq_conn_t *hqc, const xqc_cid_t *cid, void *conn_user_data)
{
    DEBUG;
    xqc_demo_svr_user_conn_t *user_conn = calloc(1, sizeof(xqc_demo_svr_user_conn_t));
    xqc_hq_conn_set_user_data(hqc, user_conn);

    /* set ctx */
    user_conn->ctx = &svr_ctx;
    memcpy(&user_conn->cid, cid, sizeof(*cid));

    /* set addr info */
    xqc_hq_conn_get_peer_addr(hqc, (struct sockaddr *)&user_conn->peer_addr, 
                              sizeof(user_conn->peer_addr), &user_conn->peer_addrlen);

    return 0;
}

int
xqc_demo_svr_hq_conn_close_notify(xqc_hq_conn_t *conn, const xqc_cid_t *cid, void *conn_user_data)
{
    DEBUG;

    if (conn_user_data == &svr_ctx) {
        return 0;
    }

    xqc_demo_svr_user_conn_t *user_conn = (xqc_demo_svr_user_conn_t*)conn_user_data;
    free(user_conn);
    user_conn = NULL;
    return 0;
}

void
xqc_demo_svr_hq_conn_handshake_finished(xqc_hq_conn_t *conn, void *conn_user_data)
{
    DEBUG;
    // printf("xqc_demo_svr_conn_handshake_finished, user_data: %p, conn: %p\n", conn_user_data, conn);
    xqc_demo_svr_user_conn_t *user_conn = (xqc_demo_svr_user_conn_t *)conn_user_data;
}


int
xqc_demo_svr_send_rsp_resource(xqc_demo_svr_user_stream_t *user_stream, char* data, ssize_t len,
    int fin)
{
    ssize_t ret = xqc_hq_request_send_rsp(user_stream->hq_request, data, len, fin);
    if (ret == -XQC_EAGAIN) {
        ret = 0;
    }

    return ret;
}

int
xqc_demo_svr_hq_req_create_notify(xqc_hq_request_t *hqr, void *req_user_data)
{
    DEBUG;
    xqc_demo_svr_user_stream_t *user_stream = calloc(1, sizeof(xqc_demo_svr_user_stream_t));
    user_stream->hq_request = hqr;

    xqc_hq_request_set_user_data(hqr, user_stream);

    user_stream->recv_buf = calloc(1, REQ_BUF_SIZE);

    return 0;
}

int
xqc_demo_svr_hq_req_close_notify(xqc_hq_request_t *hqr, void *req_user_data)
{
    DEBUG;
    xqc_demo_svr_user_stream_t *user_stream = (xqc_demo_svr_user_stream_t*)req_user_data;
    free(user_stream);
    return 0;
}

/**
 * send buf utill EAGAIN
 * [return] > 0: finish send; 0: not finished
 */
int
xqc_demo_svr_hq_send_file(xqc_hq_request_t *hqr, xqc_demo_svr_user_stream_t *user_stream)
{
    int ret = 0;
    xqc_demo_svr_resource_t *res = &user_stream->res;
    while (res->total_offset < res->total_len) {   /* still have bytes to be sent */
        char *send_buf = NULL;  /* the buf need to be send */
        int send_len = 0;       /* len of the the buf gonna be sent */
        if (res->buf_offset < res->buf_len) {
            /* prev buf not sent completely, continue send from last offset */
            send_buf = res->buf + res->buf_offset;
            send_len = res->buf_len - res->buf_offset;

        } else {
            /* prev buf sent, read new buf and send */
            res->buf_offset = 0;
            res->buf_len = fread(res->buf, 1, res->buf_size, res->fp);
            if (res->buf_len <= 0) {
                return -1;
            }
            send_buf = res->buf;
            send_len = res->buf_len;
        }

        /* send buf */
        int fin = send_len + res->total_offset == res->total_len ? 1 : 0;
        ret = xqc_demo_svr_send_rsp_resource(user_stream, send_buf, send_len, fin);
        if (ret > 0) {
            res->buf_offset += ret;
            res->total_offset += ret;

        } else if (ret == 0) {
            break;

        } else {
            printf("send file data failed!!: ret: %d\n", ret);
            return -1;
        }
    }

    return res->total_offset == res->total_len;
}


void
xqc_demo_svr_handle_hq_request(xqc_demo_svr_user_stream_t *user_stream, xqc_hq_request_t *hqr,
    char *resource, ssize_t len)
{
    int ret = 0;

    /* format file path */
    char file_path[PATH_LEN] = {0};
    snprintf(file_path, sizeof(file_path), "%s%s", svr_ctx.args->env_cfg.source_file_dir, resource);
    user_stream->res.fp = fopen(file_path, "rb");
    if (NULL == user_stream->res.fp) {
        printf("error open file [%s]\n", file_path);
        goto handle_error;
    }
    // printf("open file[%s] suc, user_conn: %p\n", file_path, user_stream->conn);

    /* create buf */
    user_stream->res.buf = (char*)malloc(READ_FILE_BUF_LEN);
    if (NULL == user_stream->res.buf) {
        printf("error create resource buf\n");
        goto handle_error;
    }
    user_stream->res.buf_size = READ_FILE_BUF_LEN;

    /* get total len */
    fseek(user_stream->res.fp, 0, SEEK_END);
    user_stream->res.total_len = ftell(user_stream->res.fp);
    fseek(user_stream->res.fp, 0, SEEK_SET);

    /* begin to send file */
    ret = xqc_demo_svr_hq_send_file(hqr, user_stream);
    if (ret == 0) {
        return;
    }

handle_error:
    xqc_demo_svr_close_user_stream_resource(user_stream);
}


int
xqc_demo_svr_hq_req_read_notify(xqc_hq_request_t *hqr, void *req_user_data)
{
    DEBUG;
    unsigned char fin = 0;
    xqc_demo_svr_user_stream_t *user_stream = (xqc_demo_svr_user_stream_t *)req_user_data;
    ssize_t read;
    do {
        char *buf = user_stream->recv_buf + user_stream->recv_body_len;
        size_t buf_size = REQ_BUF_SIZE - user_stream->recv_body_len;
        read = xqc_hq_request_recv_req(hqr, buf, buf_size, &fin);
        if (read == -XQC_EAGAIN) {
            break;

        } else if (read < 0) {
            printf("xqc_stream_recv error %zd\n", read);
            return 0;
        }

        user_stream->recv_body_len += read;
    } while (read > 0 && !fin);

    if (fin) {
        xqc_demo_svr_handle_hq_request(user_stream, hqr, user_stream->recv_buf,
            user_stream->recv_body_len);
    }

    return 0;
}


int
xqc_demo_svr_hq_req_write_notify(xqc_hq_request_t *hqr, void *req_user_data)
{
    DEBUG;
    //printf("xqc_demo_svr_hq_req_write_notify user_data: %p\n", user_data);
    xqc_demo_svr_user_stream_t *user_stream = (xqc_demo_svr_user_stream_t*)req_user_data;
    int ret = xqc_demo_svr_hq_send_file(hqr, user_stream);
    if (ret != 0) {
        /* error or finish, close user_stream */
        xqc_demo_svr_close_user_stream_resource(user_stream);
    }

    return 0;
}



/******************************************************************************
 *                     start of http/3 callback functions                     *
 ******************************************************************************/

int
xqc_demo_svr_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *conn_user_data)
{
    DEBUG;
    xqc_demo_svr_ctx_t *ctx = (xqc_demo_svr_ctx_t*)conn_user_data;

    xqc_demo_svr_user_conn_t *user_conn = calloc(1, sizeof(xqc_demo_svr_user_conn_t));
    user_conn->ctx = &svr_ctx;
    xqc_h3_conn_set_user_data(h3_conn, user_conn);

/*
    printf("xqc_demo_svr_h3_conn_create_notify, user_conn: %p, h3_conn: %p, ctx: %p\n", user_conn,
        h3_conn, ctx);
*/
    xqc_h3_conn_get_peer_addr(h3_conn, (struct sockaddr *)&user_conn->peer_addr,
                              sizeof(user_conn->peer_addr), &user_conn->peer_addrlen);

    memcpy(&user_conn->cid, cid, sizeof(*cid));
    return 0;
}


int
xqc_demo_svr_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *conn_user_data)
{
    DEBUG;
    xqc_demo_svr_user_conn_t *user_conn = (xqc_demo_svr_user_conn_t*)conn_user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(user_conn->ctx->engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" "
            "early_data_flag:%d, conn_err:%d, ack_info:%s\n", stats.send_count,
            stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt,
            stats.early_data_flag, stats.conn_err, stats.ack_info);

    free(user_conn);
    user_conn = NULL;
    return 0;
}


void 
xqc_demo_svr_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *conn_user_data)
{
    DEBUG;
    xqc_demo_svr_user_conn_t *user_conn = (xqc_demo_svr_user_conn_t *)conn_user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(user_conn->ctx->engine, &user_conn->cid);
}


int
xqc_demo_svr_h3_request_create_notify(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    DEBUG;
/*
    printf("xqc_demo_svr_h3_request_create_notify, h3_request: %p, strm_user_data: %p\n",
        h3_request, strm_user_data);
*/
    xqc_demo_svr_user_stream_t *user_stream = calloc(1, sizeof(*user_stream));
    user_stream->h3_request = h3_request;

    // user_stream->conn = (xqc_demo_svr_user_conn_t*)strm_user_data;

    xqc_h3_request_set_user_data(h3_request, user_stream);
    user_stream->recv_buf = calloc(1, REQ_BUF_SIZE);

    return 0;
}


int
xqc_demo_svr_h3_request_close_notify(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    DEBUG;
    xqc_demo_svr_user_stream_t *user_stream = (xqc_demo_svr_user_stream_t*)strm_user_data;
    xqc_demo_svr_close_user_stream_resource(user_stream);
    free(user_stream);

    return 0;
}


void
xqc_demo_svr_set_rsp_header_value_str(xqc_http_headers_t *rsp_hdrs, H3_HDR_TYPE hdr_type, char *v)
{
    rsp_hdrs->headers[hdr_type].value.iov_base = v;
    rsp_hdrs->headers[hdr_type].value.iov_len = strlen(v);
}


void
xqc_demo_svr_set_rsp_header_value_int(xqc_http_headers_t *rsp_hdrs, H3_HDR_TYPE hdr_type, int v)
{
    sprintf(rsp_hdrs->headers[hdr_type].value.iov_base, "%d", v);
    rsp_hdrs->headers[hdr_type].value.iov_len = strlen(
        (char*)rsp_hdrs->headers[hdr_type].value.iov_base);
}


int
xqc_demo_svr_request_send_body(xqc_demo_svr_user_stream_t *user_stream, char* data, ssize_t len,
    int fin)
{
    ssize_t ret = xqc_h3_request_send_body(user_stream->h3_request, data, len, fin);
    if (ret == -XQC_EAGAIN) {
        ret = 0;
    }

    return ret;
}


int
xqc_demo_svr_send_body(xqc_demo_svr_user_stream_t *user_stream)
{
    int ret = 0;
    xqc_demo_svr_resource_t *res = &user_stream->res;
    while (res->total_offset < res->total_len) {    /* still have bytes to be sent */
        char *send_buf = NULL;  /* the buf need to be sent */
        int send_len = 0;       /* len of the the buf gonna be sent */
        if (res->buf_offset < res->buf_len) {
            /* prev buf not sent completely, continue send from last offset */
            send_buf = res->buf + res->buf_offset;
            send_len = res->buf_len - res->buf_offset;

        } else {
            /* prev buf sent, read new buf and send */
            res->buf_offset = 0;
            res->buf_len = fread(res->buf, 1, res->buf_size, res->fp);
            if (res->buf_len <= 0) {
                return -1;
            }
            send_buf = res->buf;
            send_len = res->buf_len;
        }

        /* send buf */
        int fin = send_len + res->total_offset == res->total_len ? 1 : 0;
        ret = xqc_demo_svr_request_send_body(user_stream, send_buf, send_len, fin);

        if (ret > 0) {
            res->buf_offset += ret;
            res->total_offset += ret;

        } else if (ret == 0) {
            break;

        } else {
            printf("send file data failed!!: ret: %d\n", ret);
            return -1;
        }
    }

    return res->total_offset == res->total_len;
}


int
xqc_demo_svr_handle_h3_request(xqc_demo_svr_user_stream_t *user_stream,
    xqc_http_headers_t *req_hdrs)
{
    DEBUG;
    ssize_t ret = 0;

    /* response header buf list */
    char rsp_hdr_buf[H3_HDR_CNT][RSP_HDR_BUF_LEN];
    xqc_http_header_t rsp_hdr[] = {
        {
            .name = {.iov_base = ":status", .iov_len = 7},
            .value = {.iov_base = rsp_hdr_buf[H3_HDR_STATUS], .iov_len = 0},
            .flags = 0,
        },
        {
            .name = {.iov_base = "content-type", .iov_len = 12},
            .value = {.iov_base = "text/plain", .iov_len = 10},
            .flags = 0,
        },
        {
            .name = {.iov_base = "content-length", .iov_len = 14},
            .value = {.iov_base = rsp_hdr_buf[H3_HDR_CONTENT_LENGTH], .iov_len = 0},
            .flags = 0,
        }
    };
    /* response header */
    xqc_http_headers_t rsp_hdrs;
    rsp_hdrs.headers = rsp_hdr;
    rsp_hdrs.count = sizeof(rsp_hdr) / sizeof(rsp_hdr[0]);

    /* format file path */
    char file_path[PATH_LEN] = {0};
    snprintf(file_path, sizeof(file_path), "%s%s", 
             svr_ctx.args->env_cfg.source_file_dir, user_stream->recv_buf);
    user_stream->res.fp = fopen(file_path, "rb");
    if (NULL == user_stream->res.fp) {
        printf("error open file [%s]\n", file_path);
        xqc_demo_svr_set_rsp_header_value_int(&rsp_hdrs, H3_HDR_STATUS, 404);
        goto h3_handle_error;
    }

    /* create buf */
    user_stream->res.buf = (char*)malloc(READ_FILE_BUF_LEN);
    if (NULL == user_stream->res.buf) {
        printf("error create response buf\n");
        xqc_demo_svr_set_rsp_header_value_int(&rsp_hdrs, H3_HDR_STATUS, 500);
        goto h3_handle_error;
    }
    user_stream->res.buf_size = READ_FILE_BUF_LEN;

    /* get total len */
    fseek(user_stream->res.fp, 0, SEEK_END);
    user_stream->res.total_len = ftell(user_stream->res.fp);
    fseek(user_stream->res.fp, 0, SEEK_SET);

    xqc_demo_svr_set_rsp_header_value_int(&rsp_hdrs, H3_HDR_CONTENT_LENGTH,
        user_stream->res.total_len);
    xqc_demo_svr_set_rsp_header_value_int(&rsp_hdrs, H3_HDR_STATUS, 200);

    /* send header first */
    if (user_stream->header_sent == 0) {
        ret = xqc_h3_request_send_headers(user_stream->h3_request, &rsp_hdrs, 0);
        if (ret < 0) {
            printf("xqc_h3_request_send_headers error %zd\n", ret);
            return ret;
        } else {
            printf("xqc_h3_request_send_headers success size=%zd\n", ret);
            user_stream->header_sent = 1;
        }
    }

    /* begin to send file */
    ret = xqc_demo_svr_send_body(user_stream);
    if (ret == 0) {
        return 0;
    }

h3_handle_error:
    xqc_demo_svr_close_user_stream_resource(user_stream);
    return -1;
}


int
xqc_demo_svr_h3_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag,
    void *strm_user_data)
{
    DEBUG;
    int ret;
    unsigned char fin = 0;
    xqc_demo_svr_user_stream_t *user_stream = (xqc_demo_svr_user_stream_t *)strm_user_data;

    /* recv headers */
    xqc_http_headers_t *headers = NULL;
    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            printf("xqc_h3_request_recv_headers error\n");
            return -1;
        }

        /* print headers */
        for (int i = 0; i < headers->count; i++) {
            /* save path */
            if (strcmp((char*)headers->headers[i].name.iov_base, ":path") == 0) {
                strncpy(user_stream->recv_buf, (char*)headers->headers[i].value.iov_base,
                    headers->headers[i].value.iov_len);
            }
            printf("%s = %s\n", (char*)headers->headers[i].name.iov_base,
                (char*)headers->headers[i].value.iov_base);
        }

        /* TODO: if recv headers once for all? */
        user_stream->header_recvd = 1;

    } else if (flag & XQC_REQ_NOTIFY_READ_BODY) {   /* recv body */
        char buff[4096] = {0};
        size_t buff_size = 4096;
        ssize_t read = 0;
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
            user_stream->recv_body_len += read;
        } while (read > 0 && !fin);

        printf("xqc_h3_request_recv_body read:%zd, offset:%zu, fin:%d\n", read_sum,
            user_stream->recv_body_len, fin);
    }

    if (fin) {
        xqc_demo_svr_handle_h3_request(user_stream, headers);
    }

    return 0;
}


int
xqc_demo_svr_h3_request_write_notify(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    DEBUG;
    xqc_demo_svr_user_stream_t *user_stream = (xqc_demo_svr_user_stream_t *)strm_user_data;
    int ret = xqc_demo_svr_send_body(user_stream);

    return ret;
}


/******************************************************************************
 *                     start of socket operation function                     *
 ******************************************************************************/

ssize_t
xqc_demo_svr_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    ssize_t res;

    xqc_demo_svr_user_conn_t *user_conn = (xqc_demo_svr_user_conn_t *)conn_user_data;

    int fd = svr_ctx.current_fd;

    do {
        errno = 0;
        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
            printf("xqc_demo_svr_write_socket err %zd %s, fd: %d\n", res, strerror(errno), fd);
            if (errno == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        }
    } while ((res < 0) && (errno == EINTR));

    return res;
}


void
xqc_demo_svr_socket_write_handler(xqc_demo_svr_ctx_t *ctx, int fd)
{
    DEBUG
}

void
xqc_demo_svr_socket_read_handler(xqc_demo_svr_ctx_t *ctx, int fd)
{
    DEBUG;
    ssize_t recv_sum = 0;
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = sizeof(peer_addr);
    ssize_t recv_size = 0;
    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];

    ctx->current_fd = fd;

    do {
        recv_size = recvfrom(fd, packet_buf, sizeof(packet_buf), 0,
                             (struct sockaddr *) &peer_addr, &peer_addrlen);
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
                                      (struct sockaddr *)(&ctx->local_addr), ctx->local_addrlen,
                                      (struct sockaddr *)(&peer_addr), peer_addrlen,
                                      (xqc_usec_t)recv_time, ctx);
        if (ret != XQC_OK) {
            printf("server_read_handler: packet process err, ret: %d\n", ret);
            return;
        }
    } while (recv_size > 0);

finish_recv:
    // printf("recvfrom size:%zu\n", recv_sum);
    xqc_engine_finish_recv(ctx->engine);
}


static void
xqc_demo_svr_socket_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    xqc_demo_svr_ctx_t *ctx = (xqc_demo_svr_ctx_t *)arg;
    if (what & EV_WRITE) {
        xqc_demo_svr_socket_write_handler(ctx, fd);

    } else if (what & EV_READ) {
        xqc_demo_svr_socket_read_handler(ctx, fd);

    } else {
        printf("event callback: fd=%d, what=%d\n", fd, what);
        exit(1);
    }
}

/* create socket and bind port */
static int
xqc_demo_svr_init_socket(int family, uint16_t port, 
        struct sockaddr *local_addr, socklen_t local_addrlen)
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

    /* bind port */
    if (bind(fd, local_addr, local_addrlen) < 0) {
        printf("bind socket failed, family: %d, errno: %d, %s\n", family, errno, strerror(errno));
        goto err;
    }

    return fd;

err:
    close(fd);
    return -1;
}

static int
xqc_demo_svr_create_socket(xqc_demo_svr_ctx_t *ctx, xqc_demo_svr_net_config_t* cfg)
{
    /* ipv4 socket */
    memset(&ctx->local_addr, 0, sizeof(ctx->local_addr));
    ctx->local_addr.sin_family = AF_INET;
    ctx->local_addr.sin_port = htons(cfg->port);
    ctx->local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    ctx->local_addrlen = sizeof(ctx->local_addr);
    ctx->fd = xqc_demo_svr_init_socket(AF_INET, cfg->port, (struct sockaddr*)&ctx->local_addr, 
        ctx->local_addrlen);
    printf("create ipv4 socket fd: %d\n", ctx->fd);

    /* ipv6 socket */
    memset(&ctx->local_addr6, 0, sizeof(ctx->local_addr6));
    ctx->local_addr6.sin6_family = AF_INET6;
    ctx->local_addr6.sin6_port = htons(cfg->port);
    ctx->local_addr6.sin6_addr = in6addr_any;
    ctx->local_addrlen6 = sizeof(ctx->local_addr6);
    ctx->fd6 = xqc_demo_svr_init_socket(AF_INET6, cfg->port, (struct sockaddr*)&ctx->local_addr6, 
        ctx->local_addrlen6);
    printf("create ipv6 socket fd: %d\n", ctx->fd6);

    if (!ctx->fd && !ctx->fd6) {
        return -1;
    }

    return 0;
}


static void
xqc_demo_svr_engine_callback(int fd, short what, void *arg)
{
    xqc_demo_svr_ctx_t *ctx = (xqc_demo_svr_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}


void
xqc_demo_svr_usage(int argc, char *argv[])
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
            "   -p    Server port.\n"
            "   -c    Congestion Control Algorithm. r:reno b:bbr c:cubic\n"
            "   -C    Pacing on.\n"
            "   -l    Log level. e:error d:debug.\n"
            "   -L    xuqic log directory.\n"
            "   -6    IPv6\n"
            "   -k    Key output file path\n"
            "   -r    retry\n"
            , prog);
}


void
xqc_demo_svr_init_0rtt(xqc_demo_svr_args_t *args)
{
    /* read session ticket key */
    int ret = xqc_demo_read_file_data(args->quic_cfg.stk,
            SESSION_TICKET_KEY_BUF_LEN, SESSION_TICKET_KEY_FILE);
    args->quic_cfg.stk_len = ret > 0 ? ret : 0;
}


void
xqc_demo_svr_init_args(xqc_demo_svr_args_t *args)
{
    memset(args, 0, sizeof(xqc_demo_svr_args_t));

    /* net cfg */
    strncpy(args->net_cfg.ip, DEFAULT_IP, sizeof(args->net_cfg.ip) - 1);
    args->net_cfg.port = DEFAULT_PORT;

    /* quic cfg */
    xqc_demo_svr_init_0rtt(args);
    strncpy(args->quic_cfg.cipher_suit, XQC_TLS_CIPHERS, CIPHER_SUIT_LEN - 1);
    strncpy(args->quic_cfg.groups, XQC_TLS_GROUPS, TLS_GROUPS_LEN - 1);

    /* env cfg */
    args->env_cfg.log_level = XQC_LOG_DEBUG;
    strncpy(args->env_cfg.log_path, LOG_PATH, TLS_GROUPS_LEN - 1);
    strncpy(args->env_cfg.source_file_dir, SOURCE_DIR, RESOURCE_LEN - 1);
    strncpy(args->env_cfg.priv_key_path, PRIV_KEY_PATH, PATH_LEN - 1);
    strncpy(args->env_cfg.cert_pem_path, CERT_PEM_PATH, PATH_LEN - 1);
}

void
xqc_demo_svr_parse_args(int argc, char *argv[], xqc_demo_svr_args_t *args)
{
    int ch = 0;
    while ((ch = getopt(argc, argv, "p:c:CD:l:L:6k:r")) != -1) {
        switch (ch) {
        /* listen port */
        case 'p':
            printf("option port :%s\n", optarg);
            args->net_cfg.port = atoi(optarg);
            break;

        /* congestion control */
        case 'c':
            printf("option cong_ctl :%s\n", optarg);
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
            default:
                break;
            }
            break;

        /* pacing */
        case 'C':
            printf("option pacing :%s\n", "on");
            args->net_cfg.pacing = 1;
            break;

        /* server resource dir */
        case 'D':
            printf("option read dir :%s\n", optarg);
            strncpy(args->env_cfg.source_file_dir, optarg, RESOURCE_LEN - 1);
            break;

        /* log level */
        case 'l':
            printf("option log level :%s\n", optarg);
            args->env_cfg.log_level = optarg[0];
            break;

        /* log path */
        case 'L': /* log directory */
            printf("option log directory :%s\n", optarg);
            snprintf(args->env_cfg.log_path, sizeof(args->env_cfg.log_path), "%s", optarg);
            break;

        /* ipv6 */
        case '6': //IPv6
            printf("option IPv6 :%s\n", "on");
            args->net_cfg.ipv6 = 1;
            break;

        /* key out path */
        case 'k': /* key out path */
            printf("option key output file: %s\n", optarg);
            args->env_cfg.key_output_flag = 1;
            strncpy(args->env_cfg.key_out_path, optarg, sizeof(args->env_cfg.key_out_path) - 1);
            break;

        /* retry */
        case 'r':
            printf("option validate addr with retry packet\n");
            args->quic_cfg.retry_on = 1;
            break;

        default:
            printf("other option :%c\n", ch);
            xqc_demo_svr_usage(argc, argv);
            exit(0);
        }
    }
}

void
xqc_demo_svr_init_callback(xqc_engine_callback_t *cb, xqc_transport_callbacks_t *transport_cbs,
    xqc_demo_svr_args_t* args)
{
    static xqc_engine_callback_t callback = {
        .set_event_timer = xqc_demo_svr_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = xqc_demo_svr_write_log_file,
            .xqc_log_write_stat = xqc_demo_svr_write_log_file
        },
        .keylog_cb = xqc_demo_svr_keylog_cb,
    };


    static xqc_transport_callbacks_t tcb = {
        .server_accept = xqc_demo_svr_accept,
        .write_socket = xqc_demo_svr_write_socket,
        .conn_update_cid_notify = xqc_demo_svr_conn_update_cid_notify,
    };

    *cb = callback;
    *transport_cbs = tcb;
}

/* init server ctx */
void
xqc_demo_svr_init_ctx(xqc_demo_svr_ctx_t *ctx, xqc_demo_svr_args_t *args)
{
    memset(ctx, 0, sizeof(xqc_demo_svr_ctx_t));
    ctx->current_fd = -1;
    ctx->args = args;
    xqc_demo_svr_open_log_file(ctx);
    xqc_demo_svr_open_keylog_file(ctx);
}

/* init ssl config */
void
xqc_demo_svr_init_ssl_config(xqc_engine_ssl_config_t *cfg, xqc_demo_svr_args_t *args)
{
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

void
xqc_demo_svr_init_conn_settings(xqc_demo_svr_args_t *args)
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
    default:
        break;
    }

    /* init connection settings */
    xqc_conn_settings_t conn_settings = {
        .pacing_on  =   args->net_cfg.pacing,
        .cong_ctrl_callback = ccc,
        .cc_params = {
            .customize_on = 1,
            .init_cwnd = 32,
        },
        .spurious_loss_detect_on = 1,
    };

    xqc_server_set_conn_settings(&conn_settings);
}


int
xqc_demo_svr_init_alpn_ctx(xqc_demo_svr_ctx_t *ctx)
{
    int ret = 0;

    xqc_hq_callbacks_t hq_cbs = {
        .hqc_cbs = {
            .conn_create_notify = xqc_demo_svr_hq_conn_create_notify,
            .conn_close_notify = xqc_demo_svr_hq_conn_close_notify,
        },
        .hqr_cbs = {
            .req_create_notify = xqc_demo_svr_hq_req_create_notify,
            .req_close_notify = xqc_demo_svr_hq_req_close_notify,
            .req_read_notify = xqc_demo_svr_hq_req_read_notify,
            .req_write_notify = xqc_demo_svr_hq_req_write_notify,
        }
    };

    /* init hq context */
    ret = xqc_hq_ctx_init(ctx->engine, &hq_cbs);
    if (ret != XQC_OK) {
        printf("init hq context error, ret: %d\n", ret);
        return ret;
    }

    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify = xqc_demo_svr_h3_conn_create_notify,
            .h3_conn_close_notify = xqc_demo_svr_h3_conn_close_notify,
            .h3_conn_handshake_finished = xqc_demo_svr_h3_conn_handshake_finished,
        },
        .h3r_cbs = {
            .h3_request_create_notify = xqc_demo_svr_h3_request_create_notify,
            .h3_request_close_notify = xqc_demo_svr_h3_request_close_notify,
            .h3_request_read_notify = xqc_demo_svr_h3_request_read_notify,
            .h3_request_write_notify = xqc_demo_svr_h3_request_write_notify,
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


/* init xquic server engine */
int
xqc_demo_svr_init_xquic_engine(xqc_demo_svr_ctx_t *ctx, xqc_demo_svr_args_t *args)
{
    /* init engine ssl config */
    xqc_engine_ssl_config_t cfg = {0};
    xqc_demo_svr_init_ssl_config(&cfg, args);

    /* init engine callbacks */
    xqc_engine_callback_t callback;
    xqc_transport_callbacks_t transport_cbs;
    xqc_demo_svr_init_callback(&callback, &transport_cbs, args);

    /* init server connection settings */
    xqc_demo_svr_init_conn_settings(args);

    /* init engine config */
    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        return XQC_ERROR;
    }

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

    /* create server engine */
    ctx->engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &cfg,
                                    &callback, &transport_cbs, ctx);
    if (ctx->engine == NULL) {
        printf("xqc_engine_create error\n");
        return -1;
    }

    if (xqc_demo_svr_init_alpn_ctx(ctx) < 0) {
        printf("init alpn ctx error!");
        return -1;
    }

    return 0;
}


#if 0
void stop(int signo)
{
    event_base_loopbreak(eb);
    xqc_engine_destroy(ctx.engine);
    fflush(stdout);
    exit(0);
}
#endif


void
xqc_demo_svr_free_ctx(xqc_demo_svr_ctx_t *ctx)
{
    xqc_demo_svr_close_keylog_file(ctx);
    xqc_demo_svr_close_log_file(ctx);

    if (ctx->args) {
        free(ctx->args);
        ctx->args = NULL;
    }

    free(ctx);
}


int
main(int argc, char *argv[])
{
    /* get input server args */
    xqc_demo_svr_args_t *args = calloc(1, sizeof(xqc_demo_svr_args_t));
    xqc_demo_svr_init_args(args);
    xqc_demo_svr_parse_args(argc, argv, args);

    /* init server ctx */
    xqc_demo_svr_ctx_t *ctx = &svr_ctx;
    xqc_demo_svr_init_ctx(ctx, args);

    /* engine event */
    struct event_base *eb = event_base_new();
    ctx->ev_engine = event_new(eb, -1, 0, xqc_demo_svr_engine_callback, ctx);

    if (xqc_demo_svr_init_xquic_engine(ctx, args) < 0) {
        return -1;
    }

    /* init socket */
    int ret = xqc_demo_svr_create_socket(ctx, &args->net_cfg);
    if (ret < 0) {
        printf("xqc_create_socket error\n");
        return 0;
    }

    /* socket event */
    ctx->ev_socket = event_new(eb, ctx->fd, EV_READ | EV_PERSIST,
        xqc_demo_svr_socket_event_callback, ctx);
    event_add(ctx->ev_socket, NULL);

    /* socket event */
    ctx->ev_socket6 = event_new(eb, ctx->fd6, EV_READ | EV_PERSIST,
        xqc_demo_svr_socket_event_callback, ctx);
    event_add(ctx->ev_socket6, NULL);

    event_base_dispatch(eb);

    xqc_engine_destroy(ctx->engine);
    // xqc_demo_svr_free_ctx(ctx);

    return 0;
}
