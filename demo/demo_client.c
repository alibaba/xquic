/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#define _GNU_SOURCE

#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xqc_http3.h>
#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <string.h>
#include <event2/event.h>
#include "common.h"
#include "xqc_hq.h"
#include "../tests/platform.h"

#ifdef XQC_SYS_WINDOWS
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"event.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Bcrypt.lib")
#include "../tests/getopt.h"
#else
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netdb.h>
#endif


#define XQC_PACKET_TMP_BUF_LEN  1600
#define MAX_BUF_SIZE            (100*1024*1024)
#define XQC_INTEROP_TLS_GROUPS  "X25519:P-256:P-384:P-521"
#define MAX_PATH_CNT            2


typedef enum xqc_demo_cli_alpn_type_s {
    ALPN_HQ,
    ALPN_H3,
} xqc_demo_cli_alpn_type_t;


#define MAX_HEADER 100

typedef struct xqc_demo_cli_user_conn_s xqc_demo_cli_user_conn_t;

typedef struct xqc_demo_cli_user_stream_s {
    xqc_demo_cli_user_conn_t   *user_conn;

    /* save file */
    char                        file_name[RESOURCE_LEN];
    FILE                        *recv_body_fp;

    /* stat for IO */
    size_t                      send_body_len;
    size_t                      recv_body_len;
    int                         recv_fin;
    xqc_msec_t                  start_time;

    /* hq request content */
    xqc_hq_request_t           *hq_request;
    char                       *send_buf;
    size_t                      send_len;
    size_t                      send_offset;

    /* h3 request content */
    xqc_h3_request_t           *h3_request;
    xqc_http_headers_t          h3_hdrs;
    uint8_t                     hdr_sent;
} xqc_demo_cli_user_stream_t;


/**
 * ============================================================================
 * the network config definition section
 * network config is those arguments about socket connection
 * all configuration on network should be put under this section
 * ============================================================================
 */


typedef enum xqc_demo_cli_task_mode_s {
    /* send multi requests in single connection with multi streams */
    MODE_SCMR,

    /* serially send multi requests in multi connections, with one request each connection */
    MODE_SCSR_SERIAL,

    /* concurrently send multi requests in multi connections, with one request each connection */
    MODE_SCSR_CONCURRENT,
} xqc_demo_cli_task_mode_t;


/* network arguments */
typedef struct xqc_demo_cli_net_config_s {

    /* server addr info */
    struct sockaddr_in6 addr;
    int                 addr_len;
    char                server_addr[64];
    short               server_port;
    char                host[256];

    /* ipv4 or ipv6 */
    int                 ipv6;

    /* congestion control algorithm */
    CC_TYPE             cc;     /* congestion control algorithm */
    int                 pacing; /* is pacing on */

    /* idle persist timeout */
    int                 conn_timeout;

    xqc_demo_cli_task_mode_t mode;

    char iflist[MAX_PATH_CNT][128];     /* list of interfaces */
    int ifcnt;
    
    int multipath;

    uint8_t rebind_p0;
    uint8_t rebind_p1;

} xqc_demo_cli_net_config_t;

/**
 * ============================================================================
 * the quic config definition section
 * quic config is those arguments about quic connection
 * all configuration on network should be put under this section
 * ============================================================================
 */

/* definition for quic */
#define MAX_SESSION_TICKET_LEN      8192    /* session ticket len */
#define MAX_TRANSPORT_PARAMS_LEN    8192    /* transport parameter len */
#define XQC_MAX_TOKEN_LEN           8192     /* token len */

#define SESSION_TICKET_FILE         "session_ticket"
#define TRANSPORT_PARAMS_FILE       "transport_params"
#define TOKEN_FILE                  "token"

typedef struct xqc_demo_cli_quic_config_s {
    /* alpn protocol of client */
    xqc_demo_cli_alpn_type_t alpn_type;
    char alpn[16];

    /* 0-rtt config */
    int  st_len;                        /* session ticket len */
    char st[MAX_SESSION_TICKET_LEN];    /* session ticket buf */
    int  tp_len;                        /* transport params len */
    char tp[MAX_TRANSPORT_PARAMS_LEN];  /* transport params buf */
    int  token_len;                     /* token len */
    char token[XQC_MAX_TOKEN_LEN];      /* token buf */

    char *cipher_suites;                /* cipher suites */

    uint8_t use_0rtt;                   /* 0-rtt switch, default turned off */
    uint64_t keyupdate_pkt_threshold;   /* packet limit of a single 1-rtt key, 0 for unlimited */

    uint8_t mp_ack_on_any_path;

    char mp_sched[32];
    uint8_t mp_backup;

    uint64_t close_path;

    uint8_t no_encryption;

    uint64_t recv_rate;

    uint32_t reinjection;

    uint8_t mp_version;

    /* support interop test */
    int is_interop_mode;

    uint8_t send_path_standby;
    xqc_msec_t path_status_timer_threshold;

    uint64_t least_available_cid_count;

    size_t max_pkt_sz;

    char co_str[XQC_CO_STR_MAX_LEN];

} xqc_demo_cli_quic_config_t;



/**
 * ============================================================================
 * the environment config definition section
 * environment config is those arguments about IO inputs and outputs
 * all configuration on environment should be put under this section
 * ============================================================================
 */

#define LOG_PATH "clog.log"
#define KEY_PATH "ckeys.log"
#define OUT_DIR  "."

/* environment config */
typedef struct xqc_demo_cli_env_config_s {

    /* log path */
    char    log_path[256];
    int     log_level;

    /* out file */
    char    out_file_dir[256];

    /* key export */
    int     key_output_flag;
    char    key_out_path[256];

    /* life cycle */
    int     life;
} xqc_demo_cli_env_config_t;


/**
 * ============================================================================
 * the request config definition section
 * all configuration on request should be put under this section
 * ============================================================================
 */

#define MAX_REQUEST_CNT 2048    /* client might deal MAX_REQUEST_CNT requests once */
#define MAX_REQUEST_LEN 256     /* the max length of a request */
#define g_host ""

/* args of one single request */
typedef struct xqc_demo_cli_request_s {
    char            path[RESOURCE_LEN];         /* request path */
    char            scheme[8];                  /* request scheme, http/https */
    REQUEST_METHOD  method;
    char            auth[AUTHORITY_LEN];
    char            url[URL_LEN];               /* original url */
    // char            headers[MAX_HEADER][256];   /* field line of h3 */
} xqc_demo_cli_request_t;


/* request bundle args */
typedef struct xqc_demo_cli_requests_s {
    /* requests */
    char                    urls[MAX_REQUEST_CNT * MAX_REQUEST_LEN];
    int                     request_cnt;    /* requests cnt in urls */
    xqc_demo_cli_request_t  reqs[MAX_REQUEST_CNT];

    /* do not save responses to files */
    int dummy_mode;

    /* delay X us to start reqs */
    uint64_t req_start_delay; 

    uint64_t idle_gap;

    /* serial requests */
    uint8_t serial;

    int throttled_req;

} xqc_demo_cli_requests_t;


/**
 * ============================================================================
 * the client args definition section
 * client initial args
 * ============================================================================
 */
typedef struct xqc_demo_cli_client_args_s {
    /* network args */
    xqc_demo_cli_net_config_t   net_cfg;

    /* quic args */
    xqc_demo_cli_quic_config_t  quic_cfg;

    /* environment args */
    xqc_demo_cli_env_config_t   env_cfg;

    /* request args */
    xqc_demo_cli_requests_t     req_cfg;
} xqc_demo_cli_client_args_t;


typedef enum xqc_demo_cli_task_status_s {
    TASK_STATUS_WAITTING,
    TASK_STATUS_RUNNING,
    TASK_STATUS_FINISHED,
    TASK_STATUS_FAILED,
} xqc_demo_cli_task_status_t;

typedef struct xqc_demo_cli_task_schedule_info_s {

    xqc_demo_cli_task_status_t  status;         /* task status */
    int                         req_create_cnt; /* streams created */
    int                         req_sent_cnt;
    int                         req_fin_cnt;    /* the req cnt which have received FIN */
    uint8_t                     fin_flag;       /* all reqs finished, need close */
} xqc_demo_cli_task_schedule_info_t;


/* 
 * the task schedule info, used to mark the operation 
 * info of all requests, the client will exit when all
 * tasks are finished or closed
 */
typedef struct xqc_demo_cli_task_schedule_s {
    /* the cnt of tasks that been running or have been ran */
    int idx;

    /* the task status, 0: not executed; 1: suc; -1: failed */
    xqc_demo_cli_task_schedule_info_t   *schedule_info;
} xqc_demo_cli_task_schedule_t;

/* 
 * task info structure. 
 * a task is strongly correlate to a net connection
 */
typedef struct xqc_demo_cli_task_s {
    int         task_idx;
    int         req_cnt;
    xqc_demo_cli_request_t   *reqs;      /* a task could contain multipule requests, which wil be sent  */
    xqc_demo_cli_user_conn_t *user_conn; /* user_conn handle */
} xqc_demo_cli_task_t;


typedef struct xqc_demo_cli_task_ctx_s {
    /* task mode */
    xqc_demo_cli_task_mode_t        mode;

    /* total task cnt */
    int                             task_cnt;

    /* task list */
    xqc_demo_cli_task_t            *tasks;

    /* current task schedule info */
    xqc_demo_cli_task_schedule_t    schedule;        /* current task index */
} xqc_demo_cli_task_ctx_t;


typedef struct xqc_demo_cli_ctx_s {
    /* xquic engine context */
    xqc_engine_t    *engine;

    /* libevent context */
    struct event    *ev_engine;
    struct event    *ev_task;
    struct event    *ev_kill;
    struct event_base *eb;  /* handle of libevent */

    /* log context */
    int             log_fd;
    char            log_path[256];

    /* key log context */
    int             keylog_fd;

    /* client context */
    xqc_demo_cli_client_args_t  *args;

    /* task schedule context */
    xqc_demo_cli_task_ctx_t     task_ctx;
} xqc_demo_cli_ctx_t;

typedef struct xqc_demo_cli_user_path_s {

    uint64_t                path_id;
    uint8_t                 is_active;

    int                     fd;
    int                     rebind_fd;

    struct sockaddr_in6     local_addr;
    socklen_t               local_addrlen;
    struct sockaddr_in6     peer_addr;
    socklen_t               peer_addrlen;
    
    struct event           *ev_socket;
    struct event           *ev_rebind_socket;
    struct event           *ev_timeout;

    uint64_t                last_sock_op_time;

    xqc_demo_cli_user_conn_t *user_conn;

} xqc_demo_cli_user_path_t;


typedef struct xqc_demo_cli_user_conn_s {
    
    xqc_cid_t                cid;
    xqc_hq_conn_t           *hqc_handle;

    xqc_demo_cli_user_path_t paths[MAX_PATH_CNT];
    int                      active_path_cnt;
    int                      total_path_cnt;

    struct event            *ev_delay_req;
    struct event            *ev_idle_restart;
    struct event            *ev_close_path;
    struct event            *ev_rebinding_p0;
    struct event            *ev_rebinding_p1;

    xqc_demo_cli_ctx_t      *ctx;
    xqc_demo_cli_task_t     *task;

    int                     send_path_standby;
    int                     path_status; /* 0:available 1:standby */
    xqc_msec_t              path_status_time;
    xqc_msec_t              path_status_timer_threshold;
} xqc_demo_cli_user_conn_t;

static void
xqc_demo_cli_delayed_idle_restart(int fd, short what, void *arg);

void
xqc_demo_cli_continue_send_reqs(xqc_demo_cli_user_conn_t *user_conn);

void
xqc_demo_cli_send_requests(xqc_demo_cli_user_conn_t *user_conn, 
    xqc_demo_cli_client_args_t *args,
    xqc_demo_cli_request_t *reqs, int req_cnt);


int xqc_demo_cli_init_user_path(xqc_demo_cli_user_conn_t *user_conn, 
    int path_seq, uint64_t path_id);

int
xqc_demo_cli_close_task(xqc_demo_cli_task_t *task)
{
    xqc_demo_cli_user_conn_t *user_conn = task->user_conn;
    int i;

    for (i = 0; i < user_conn->total_path_cnt; i++) {
        if (user_conn->paths[i].is_active) {
            user_conn->paths[i].is_active = 0;
            user_conn->active_path_cnt--;
            /* remove event handle */
            if (user_conn->paths[i].ev_socket) {
                event_del(user_conn->paths[i].ev_socket);
            }
            
            event_del(user_conn->paths[i].ev_timeout);
            /* close socket */
            close(user_conn->paths[i].fd);

            if (user_conn->paths[i].ev_rebind_socket) {
                event_del(user_conn->paths[i].ev_rebind_socket);
            }

            if (user_conn->paths[i].rebind_fd != -1) {
                close(user_conn->paths[i].rebind_fd);
            }
        }
    }

    if (user_conn->ev_delay_req) {
        event_del(user_conn->ev_delay_req);
        user_conn->ev_delay_req = NULL;
    }

    if (user_conn->ev_idle_restart) {
        event_del(user_conn->ev_idle_restart);
        user_conn->ev_idle_restart = NULL;
    }

    if (user_conn->ev_close_path) {
        event_del(user_conn->ev_close_path);
        user_conn->ev_close_path = NULL;
    }

    if (user_conn->ev_rebinding_p0) {
        event_del(user_conn->ev_rebinding_p0);
        user_conn->ev_rebinding_p0 =  NULL;
    }

    if (user_conn->ev_rebinding_p1) {
        event_del(user_conn->ev_rebinding_p1);
        user_conn->ev_rebinding_p1 =  NULL;
    }

    return 0;
}


/**
 * [return] 1: all req suc, task finished, 0: still got req underway
 */
void
xqc_demo_cli_on_stream_fin(xqc_demo_cli_user_stream_t *user_stream)
{
    xqc_demo_cli_task_ctx_t *ctx = &user_stream->user_conn->ctx->task_ctx;
    xqc_demo_cli_user_conn_t *user_conn = user_stream->user_conn;
    xqc_demo_cli_ctx_t *conn_ctx = user_conn->ctx;
    int task_idx = user_stream->user_conn->task->task_idx;

    /* all reqs are finished, close the connection */
    if (++ctx->schedule.schedule_info[task_idx].req_fin_cnt
        == ctx->tasks[task_idx].req_cnt)
    {
        ctx->schedule.schedule_info[task_idx].fin_flag = 1;
        /* close xquic conn */
        if (conn_ctx->args->quic_cfg.alpn_type == ALPN_H3) {
            xqc_h3_conn_close(conn_ctx->engine, &user_conn->cid);

        } else {
            xqc_hq_conn_close(conn_ctx->engine, user_conn->hqc_handle, &user_conn->cid);
        }
    }
    printf("task[%d], fin_cnt: %d, fin_flag: %d\n", task_idx, 
        ctx->schedule.schedule_info[task_idx].req_fin_cnt,
        ctx->schedule.schedule_info[task_idx].fin_flag);
}

/* directly finish a task */
void
xqc_demo_cli_on_task_finish(xqc_demo_cli_ctx_t *ctx, xqc_demo_cli_task_t *task)
{
    xqc_demo_cli_close_task(task);
    ctx->task_ctx.schedule.schedule_info[task->task_idx].status = TASK_STATUS_FINISHED;

    printf("task finished, total task_req_cnt: %d, req_fin_cnt: %d, req_sent_cnt: %d, "
            "req_create_cnt: %d\n", task->req_cnt, 
            ctx->task_ctx.schedule.schedule_info[task->task_idx].req_fin_cnt,
            ctx->task_ctx.schedule.schedule_info[task->task_idx].req_sent_cnt,
            ctx->task_ctx.schedule.schedule_info[task->task_idx].req_create_cnt);
}

/* directly fail a task */
void
xqc_demo_cli_on_task_fail(xqc_demo_cli_ctx_t *ctx, xqc_demo_cli_task_t *task)
{
    ctx->task_ctx.schedule.schedule_info[task->task_idx].status = TASK_STATUS_FAILED;

    printf("task failed, total task_req_cnt: %d, req_fin_cnt: %d, req_sent_cnt: %d, "
           "req_create_cnt: %d\n", task->req_cnt, 
           ctx->task_ctx.schedule.schedule_info[task->task_idx].req_fin_cnt,
           ctx->task_ctx.schedule.schedule_info[task->task_idx].req_sent_cnt,
           ctx->task_ctx.schedule.schedule_info[task->task_idx].req_create_cnt);
}


/******************************************************************************
 *                   start of engine callback functions                       *
 ******************************************************************************/

void
xqc_demo_cli_set_event_timer(xqc_usec_t wake_after, void *eng_user_data)
{
    xqc_demo_cli_ctx_t *ctx = (xqc_demo_cli_ctx_t *) eng_user_data;
    //printf("xqc_engine_wakeup_after %llu us, now %llu\n", wake_after, xqc_now());

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);

}


int
xqc_demo_cli_open_log_file(xqc_demo_cli_ctx_t *ctx)
{
    ctx->log_fd = open(ctx->log_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return 0;
}

int
xqc_demo_cli_close_log_file(xqc_demo_cli_ctx_t *ctx)
{
    if (ctx->log_fd <= 0) {
        return -1;
    }
    close(ctx->log_fd);
    return 0;
}

void
xqc_demo_cli_write_log_file(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data)
{
    xqc_demo_cli_ctx_t *ctx = (xqc_demo_cli_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        return;
    }
    //printf("%s", (char *)buf);
    int write_len = write(ctx->log_fd, buf, size);
    if (write_len < 0) {
        printf("write log failed, errno: %d\n", get_sys_errno());
        return;
    }
    write_len = write(ctx->log_fd, line_break, 1);
    if (write_len < 0) {
        printf("write log failed, errno: %d\n", get_sys_errno());
    }
}

void
xqc_demo_cli_write_qlog_file(qlog_event_importance_t imp, const void *buf, size_t size, void *engine_user_data)
{
    xqc_demo_cli_ctx_t *ctx = (xqc_demo_cli_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        return;
    }
    int write_len = write(ctx->log_fd, buf, size);
    if (write_len < 0) {
        printf("write qlog failed, errno: %d\n", get_sys_errno());
        return;
    }
    write_len = write(ctx->log_fd, line_break, 1);
    if (write_len < 0) {
        printf("write qlog failed, errno: %d\n", get_sys_errno());
    }
}


int
xqc_demo_cli_open_keylog_file(xqc_demo_cli_ctx_t *ctx)
{
    if (ctx->args->env_cfg.key_output_flag) {
        ctx->keylog_fd = open(ctx->args->env_cfg.key_out_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
        if (ctx->keylog_fd <= 0) {
            return -1;
        }
    }

    return 0;
}

int
xqc_demo_cli_close_keylog_file(xqc_demo_cli_ctx_t *ctx)
{
    if (ctx->keylog_fd <= 0) {
        return -1;
    }
    close(ctx->keylog_fd);
    ctx->keylog_fd = 0;
    return 0;
}

void
xqc_demo_cli_keylog_cb(const xqc_cid_t *scid, const char *line, void *engine_user_data)
{
    xqc_demo_cli_ctx_t *ctx = (xqc_demo_cli_ctx_t*)engine_user_data;

    if (ctx->args->env_cfg.key_output_flag == 0) {
        return;
    }

    if (ctx->keylog_fd <= 0) {
        printf("write keys error!\n");
        return;
    }

    int write_len = write(ctx->keylog_fd, line, strlen(line));
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", get_sys_errno());
        return;
    }
    write_len = write(ctx->keylog_fd, line_break, 1);
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", get_sys_errno());
    }
}


/******************************************************************************
 *                   start of common callback functions                       *
 ******************************************************************************/

void
xqc_demo_cli_save_session_cb(const char *data, size_t data_len, void *conn_user_data)
{
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t*)conn_user_data;

    FILE * fp  = fopen(SESSION_TICKET_FILE, "wb");
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
xqc_demo_cli_save_tp_cb(const char *data, size_t data_len, void *conn_user_data)
{
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t*)conn_user_data;
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
    return;
}


void
xqc_demo_cli_save_token(const unsigned char *token, uint32_t token_len, void *conn_user_data)
{
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t*)conn_user_data;

    int fd = open(TOKEN_FILE, O_TRUNC | O_CREAT | O_WRONLY, 0666);
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

int
xqc_demo_cli_read_token(unsigned char *token, unsigned token_len)
{
    int fd = open(TOKEN_FILE, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    ssize_t n = read(fd, token, token_len);
    close(fd);
    return n;
}


ssize_t
xqc_demo_cli_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data)
{
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t *)conn_user_data;
    ssize_t res = 0;
    xqc_demo_cli_user_path_t *user_path = NULL;
    int i;

    for (i = 0; i < user_conn->total_path_cnt; i++) {
        if (user_conn->paths[i].is_active 
            && user_conn->paths[i].path_id == path_id) 
        {
            user_path = &user_conn->paths[i];
        }
    }

    if (user_path == NULL) {
        // printf("path %"PRIu64" is not avaliable!\n", path_id);
        return XQC_SOCKET_ERROR;
    }

    // printf("path %"PRIu64" with fd:%d\n", path_id, user_path->fd);

    do {
        set_sys_errno(0);
        res = sendto(user_path->fd, buf, size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
            printf("xqc_demo_cli_write_socket err %zd %s, fd: %d, buf: %p, size: %zu, "
                "server_addr: %s\n", res, strerror(get_sys_errno()), user_path->fd, buf, size,
                user_conn->ctx->args->net_cfg.server_addr);
            if (get_sys_errno() == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        }
        user_path->last_sock_op_time = xqc_now();
    } while ((res < 0) && (get_sys_errno() == EINTR));

    return res;
}


ssize_t
xqc_demo_cli_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    return xqc_demo_cli_write_socket_ex(0, buf, size, peer_addr, peer_addrlen, conn_user_data);
}

#if defined(XQC_SUPPORT_SENDMMSG) && !defined(XQC_SYS_WINDOWS)
ssize_t
xqc_demo_cli_write_mmsg(void *conn_user_data, struct iovec *msg_iov, unsigned int vlen, 
    const struct sockaddr *peer_addr, socklen_t peer_addrlen)
{
    const int MAX_SEG = 128;
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t *)conn_user_data;
    ssize_t res = 0;
    int fd = user_conn->paths[0].fd;
    struct mmsghdr mmsg[MAX_SEG];
    memset(&mmsg, 0, sizeof(mmsg));
    for (int i = 0; i < vlen; i++) {
        mmsg[i].msg_hdr.msg_iov = &msg_iov[i];
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

    } while ((res < 0) && (get_sys_errno() == EINTR));
    return res;
}
#endif

void
xqc_demo_cli_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
    const xqc_cid_t *new_cid, void *user_data)
{
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t *)user_data;
    memcpy(&user_conn->cid, new_cid, sizeof(*new_cid));
}

void
xqc_demo_cli_conn_create_path(const xqc_cid_t *cid, void *conn_user_data)
{
    xqc_demo_cli_user_conn_t *user_conn = conn_user_data;
    xqc_demo_cli_ctx_t *ctx = user_conn->ctx;
    uint64_t path_id;
    int ret;
    int backup = 0;
    if (user_conn->total_path_cnt < ctx->args->net_cfg.ifcnt
        && user_conn->total_path_cnt < MAX_PATH_CNT) 
    {

        if (user_conn->total_path_cnt == 1 && ctx->args->quic_cfg.mp_backup) {
            backup = 1;
        }

        ret = xqc_conn_create_path(ctx->engine, &(user_conn->cid), &path_id, backup);
        if (ret < 0) {
            printf("not support mp, xqc_conn_create_path err = %d\n", ret);
            return;
        }

        if (backup == 1) {
            printf("Init No.%d path (id = %"PRIu64") to STANDBY state\n", 1, path_id);
        }

        ret = xqc_demo_cli_init_user_path(user_conn, user_conn->total_path_cnt, path_id);
        if (ret < 0) {
            xqc_conn_close_path(ctx->engine, &(user_conn->cid), path_id);
            return;
        }

        if (user_conn->total_path_cnt == 2 && ctx->args->quic_cfg.mp_backup) {
            printf("set No.%d path (id = %"PRIu64") to STANDBY state\n", 1, path_id);
            xqc_conn_mark_path_standby(ctx->engine, &(user_conn->cid), path_id);
        }
        
    }
}

void
xqc_demo_cli_path_removed(const xqc_cid_t *scid, uint64_t path_id,
    void *conn_user_data)
{
    xqc_demo_cli_user_conn_t *user_conn = conn_user_data;
    int i;
    for (i = 0; i < user_conn->total_path_cnt; i++) {
        if (user_conn->paths[i].is_active
            && user_conn->paths[i].path_id == path_id)
        {
            user_conn->paths[i].is_active = 0;
            user_conn->active_path_cnt--;
            /* remove event handle */
            if (user_conn->paths[i].ev_socket) {
                event_del(user_conn->paths[i].ev_socket);
            }
            event_del(user_conn->paths[i].ev_timeout);
            /* close socket */
            close(user_conn->paths[i].fd);

            if (user_conn->paths[i].ev_rebind_socket) {
                event_del(user_conn->paths[i].ev_rebind_socket);
            }

            if (user_conn->paths[i].rebind_fd != -1) {
                close(user_conn->paths[i].rebind_fd);
            }

            printf("No.%d path removed id = %"PRIu64"\n", i, path_id);   
        }
    }

}



/******************************************************************************
 *                       start of hq callback functions                       *
 ******************************************************************************/

int
xqc_demo_cli_hq_conn_create_notify(xqc_hq_conn_t *hqc, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;

    // printf("xqc_demo_cli_hq_conn_create_notify, conn: %p, user_conn: %p\n", conn, user_data);
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t *)user_data;
    user_conn->hqc_handle = hqc;
    memcpy(&user_conn->cid, cid, sizeof(xqc_cid_t));
    return 0;
}

int
xqc_demo_cli_hq_conn_close_notify(xqc_hq_conn_t *hqc, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;
    // printf("xqc_demo_cli_hq_conn_close_notify, conn: %p, user_conn: %p\n", conn, user_data);

    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t *) user_data;
    xqc_demo_cli_on_task_finish(user_conn->ctx, user_conn->task);
    free(user_conn);
    return 0;
}

void
xqc_demo_cli_hq_conn_handshake_finished(xqc_hq_conn_t *hqc, void *conn_user_data)
{
    DEBUG;
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t *)conn_user_data;
    printf("hqc[%p] handshake finished\n", hqc);
}


int
xqc_demo_cli_hq_req_send(xqc_hq_request_t *hqr, xqc_demo_cli_user_stream_t *user_stream)
{
    ssize_t ret = 0;

    if (user_stream->start_time == 0) {
        user_stream->start_time = xqc_now();
    }

    ret = xqc_hq_request_send_req(hqr, user_stream->send_buf);
    if (ret < 0) {
        switch (-ret) {
        case XQC_EAGAIN:
            return 0;

        default:
            printf("send stream failed, ret: %zd\n", ret);
            return -1;
        }

    } else {
        user_stream->send_offset += ret;
        user_stream->send_body_len += ret;
    }

    return ret;
}

int
xqc_demo_cli_hq_req_write_notify(xqc_hq_request_t *hqr, void *req_user_data)
{
    DEBUG;
    ssize_t ret = 0;
    xqc_demo_cli_user_stream_t *user_stream = (xqc_demo_cli_user_stream_t *)req_user_data;
    if (user_stream->send_len > user_stream->send_offset)
    {
        ret = xqc_demo_cli_hq_req_send(hqr, user_stream);
        // printf("xqc_demo_cli_hq_req_write_notify, user_stream[%p] send_cnt: %d\n", user_stream, ret);
        if (ret == user_stream->send_len) {
            user_stream->user_conn->ctx->task_ctx.schedule.schedule_info->req_sent_cnt++;
        }
    }

    return 0;
}

void
xqc_demo_path_status_trigger(xqc_demo_cli_user_conn_t *user_conn)
{
    xqc_msec_t ts_now = xqc_now(), path_status_time = 0;

    if (user_conn->send_path_standby) {

        /* set initial path standby here */
        if (user_conn->path_status == 0
            && xqc_conn_available_paths(user_conn->ctx->engine, &user_conn->cid) >= 2)
        {
            if (ts_now > user_conn->path_status_time + user_conn->path_status_timer_threshold) {
                xqc_conn_mark_path_standby(user_conn->ctx->engine, &user_conn->cid, 0);
                user_conn->path_status = 1; /* 1:standby */

                user_conn->path_status_time = ts_now;
                printf("mark_path_standby: path_id=0 path_status=%d now=%"PRIu64" pre=%"PRIu64" threshold=%"PRIu64"\n",
                            user_conn->path_status, ts_now, user_conn->path_status_time, user_conn->path_status_timer_threshold);
            }

        } else if (user_conn->path_status == 1) {

            if (ts_now > user_conn->path_status_time + user_conn->path_status_timer_threshold) {
                xqc_conn_mark_path_available(user_conn->ctx->engine, &user_conn->cid, 0);
                user_conn->path_status = 0; /* 0:available */

                user_conn->path_status_time = ts_now;
                printf("mark_path_available: path_id=0 path_status=%d now=%"PRIu64" pre=%"PRIu64" threshold=%"PRIu64"\n",
                       user_conn->path_status, ts_now, user_conn->path_status_time, user_conn->path_status_timer_threshold);
            }
        }
    }
}

int
xqc_demo_cli_hq_req_read_notify(xqc_hq_request_t *hqr, void *req_user_data)
{
    DEBUG;
    unsigned char fin = 0;
    xqc_demo_cli_user_stream_t *user_stream = (xqc_demo_cli_user_stream_t *)req_user_data;
    char buff[4096] = {0};
    size_t buff_size = 4096;

    xqc_demo_path_status_trigger(user_stream->user_conn);

    ssize_t read = 0;
    ssize_t read_sum = 0;
    do {
        read = xqc_hq_request_recv_rsp(hqr, buff, buff_size, &fin);
        if (read == -XQC_EAGAIN) {
            break;

        } else if (read < 0) {
            printf("xqc_stream_recv error %zd\n", read);
            return 0;
        }

        if (user_stream->recv_body_fp) {
            int nwrite = fwrite(buff, 1, read, user_stream->recv_body_fp);
            if (nwrite != read) {
                printf("fwrite error\n");
                return -1;
            }
            fflush(user_stream->recv_body_fp);
        }

        read_sum += read;
        user_stream->recv_body_len += read;
    } while (read > 0 && !fin);

    if (fin) {
        user_stream->recv_fin = 1;
        xqc_msec_t now_us = xqc_now();
        printf("\033[33m>>>>>>>> request time cost:%"PRIu64" us, speed:%"PRIu64" K/s \n"
               ">>>>>>>> user_stream[%p], req: %s, send_body_size:%zu, recv_body_size:%zu \033[0m\n",
               now_us - user_stream->start_time,
               (user_stream->send_body_len + user_stream->recv_body_len)*1000/(now_us - user_stream->start_time),
               user_stream, user_stream->file_name, user_stream->send_body_len, user_stream->recv_body_len);

        /* close file */
        if (user_stream->recv_body_fp) {
            fclose(user_stream->recv_body_fp);
            user_stream->recv_body_fp = NULL;
        }

        // xqc_demo_cli_on_stream_fin(user_stream);
    }
    return 0;
}


int
xqc_demo_cli_hq_req_close_notify(xqc_hq_request_t *hqr, void *req_user_data)
{
    DEBUG;
    // printf("xqc_demo_cli_hq_req_close_notify, stream: %p, user_conn: %p\n", stream, user_data);

    xqc_demo_cli_user_stream_t *user_stream = (xqc_demo_cli_user_stream_t *)req_user_data;

    /* print stats */
    xqc_request_stats_t stats = xqc_hq_request_get_stats(hqr);

    printf("\033[33m[HQ-req] send_bytes:%zu, recv_bytes:%zu, path_info:%s\n\033[0m", 
           stats.send_body_size, stats.recv_body_size, stats.stream_info);

    /* task schedule */
    xqc_demo_cli_continue_send_reqs(user_stream->user_conn);
    xqc_demo_cli_on_stream_fin(user_stream);

    free(user_stream->send_buf);
    free(user_stream);
    return 0;
}


/******************************************************************************
 *                     start of http/3 callback functions                     *
 ******************************************************************************/

ssize_t
xqc_demo_cli_h3_request_send(xqc_demo_cli_user_stream_t *user_stream)
{
    ssize_t ret = 0;
    if (!user_stream->hdr_sent)
    {
        if (user_stream->start_time == 0) {
            user_stream->start_time = xqc_now();
        }

        ret = xqc_h3_request_send_headers(user_stream->h3_request, &user_stream->h3_hdrs, 1);
        if (ret < 0) {
            printf("xqc_demo_cli_h3_request_send error %zd\n", ret);
        } else {
            printf("xqc_demo_cli_h3_request_send success size=%zd\n", ret);
            user_stream->hdr_sent = 1;
        }
    }

    return ret;
}

int
xqc_demo_cli_h3_request_write_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    ssize_t ret = 0;
    xqc_demo_cli_user_stream_t *user_stream = (xqc_demo_cli_user_stream_t *) user_data;
    // printf("xqc_demo_cli_h3_request_write_notify, h3_request: %p, user_stream: %p\n", h3_request, user_stream);
    ret = xqc_demo_cli_h3_request_send(user_stream);

    return 0;
}


int
xqc_demo_cli_h3_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag,
    void *user_data)
{
    DEBUG;
    unsigned char fin = 0;
    xqc_demo_cli_user_stream_t *user_stream = (xqc_demo_cli_user_stream_t *) user_data;
    xqc_demo_cli_task_ctx_t *ctx = &user_stream->user_conn->ctx->task_ctx;
    xqc_demo_cli_user_conn_t *user_conn = user_stream->user_conn;
    uint32_t task_idx = user_conn->task->task_idx;

    xqc_demo_path_status_trigger(user_conn);

    // printf("xqc_demo_cli_h3_request_read_notify, h3_request: %p, user_stream: %p\n", h3_request, user_stream);
    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_http_headers_t *headers;
        headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            printf("xqc_h3_request_recv_headers error\n");
            return -1;
        }

        for (int i = 0; i < headers->count; i++) {
            printf("%s = %s\n", (char *)headers->headers[i].name.iov_base,
                (char *)headers->headers[i].value.iov_base);
        }

        if (fin) {
            /* only header in request */
            user_stream->recv_fin = 1;
            return 0;
        }
    }

    /* continue to recv body */
    if (!(flag & XQC_REQ_NOTIFY_READ_BODY)) {
        return 0;
    }

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

        if (user_stream->recv_body_fp) {
            if (fwrite(buff, 1, read, user_stream->recv_body_fp) != read) {
                printf("fwrite error\n");
                return -1;
            }
            fflush(user_stream->recv_body_fp);
        }

        read_sum += read;
        user_stream->recv_body_len += read;
    } while (read > 0 && !fin);

    if (read > 0) {
        printf("xqc_h3_request_recv_body size %zd, fin:%d\n", read, fin);
    }

    if (fin) {
        user_stream->recv_fin = 1;
        xqc_request_stats_t stats;
        stats = xqc_h3_request_get_stats(h3_request);
        xqc_msec_t now_us = xqc_now();
        printf("\033[33m>>>>>>>> request time cost:%"PRIu64" us, speed:%"PRIu64" K/s \n"
               ">>>>>>>> send_body_size:%zu, recv_body_size:%zu \033[0m\n"
               "stream_info:%s\n",
               now_us - user_stream->start_time,
               (stats.send_body_size + stats.recv_body_size) * 1000 / (now_us - user_stream->start_time),
               stats.send_body_size, stats.recv_body_size, stats.stream_info);
        
        if (user_stream->recv_body_fp) {
            fclose(user_stream->recv_body_fp);
            user_stream->recv_body_fp = NULL;
        }
        // xqc_demo_cli_on_stream_fin(user_stream);
        task_idx = user_stream->user_conn->task->task_idx;
        if (ctx->schedule.schedule_info[task_idx].req_create_cnt
            < ctx->tasks[task_idx].user_conn->task->req_cnt)
        {
            if (user_conn->ctx->args->req_cfg.idle_gap) {

                user_conn->ev_idle_restart = event_new(user_conn->ctx->eb, -1, 0, 
                                                       xqc_demo_cli_delayed_idle_restart, 
                                                       user_conn);
                struct timeval tv = {
                    .tv_sec = user_conn->ctx->args->req_cfg.idle_gap / 1000,
                    .tv_usec = (user_conn->ctx->args->req_cfg.idle_gap % 1000) * 1000,
                };
                event_add(user_conn->ev_idle_restart, &tv);  

            } else {
                xqc_demo_cli_continue_send_reqs(ctx->tasks[task_idx].user_conn);
            }
            
        }
    }

    return 0;
}

int
xqc_demo_cli_h3_request_create_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    //"xqc_demo_cli_h3_request_create_notify, h3_request: %p, user_data: %p\n", h3_request, user_data);

    return 0;
}

int
xqc_demo_cli_h3_request_close_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    xqc_demo_cli_user_stream_t *user_stream = (xqc_demo_cli_user_stream_t *)user_data;
    xqc_demo_cli_user_conn_t *user_conn = user_stream->user_conn;

    /* task schedule */
    xqc_demo_cli_on_stream_fin(user_stream);

    xqc_request_stats_t stats;
    stats = xqc_h3_request_get_stats(h3_request);
    printf("send_body_size:%zu, recv_body_size:%zu, send_header_size:%zu, recv_header_size:%zu, "
           "recv_fin:%d, err:%d, rate_limit:%"PRIu64", mp_state:%d, early_data:%d, avail_send_weight:%.3lf, avail_recv_weight:%.3lf, cwnd_blk:%"PRIu64"\n", 
           stats.send_body_size, stats.recv_body_size, stats.send_header_size, stats.recv_header_size, 
           user_stream->recv_fin, stats.stream_err, stats.rate_limit, stats.mp_state, stats.early_data_state,
           stats.mp_default_path_send_weight, stats.mp_default_path_recv_weight, stats.cwnd_blocked_ms);
    
    printf("\033[33m[H3-req] send_bytes:%zu, recv_bytes:%zu, path_info:%s\n\033[0m", 
           stats.send_body_size + stats.send_header_size, 
           stats.recv_body_size + stats.recv_header_size,
           stats.stream_info);

    free(user_stream);
    return 0;
}


/******************************************************************************
 *                     start of socket callback functions                     *
 ******************************************************************************/

void
xqc_demo_cli_socket_write_handler(xqc_demo_cli_user_conn_t *user_conn, int fd)
{
    DEBUG;
    // xqc_conn_continue_send(user_conn->ctx->engine, &user_conn->cid);
}

void
xqc_demo_cli_socket_read_handler(xqc_demo_cli_user_conn_t *user_conn, int fd)
{
    DEBUG;
    ssize_t recv_size = 0;
    ssize_t recv_sum = 0;
    struct sockaddr addr;
    socklen_t addr_len = 0;
    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];
    int i;
    xqc_demo_cli_user_path_t *user_path = NULL;
    for (i = 0; i < user_conn->total_path_cnt; i++) {
        if (user_conn->paths[i].is_active
            && user_conn->paths[i].fd == fd)
        {
            user_path = &user_conn->paths[i];
        }
    }

    if (user_path == NULL) {
        return;
    }

    // printf("socket read: path%"PRIu64" fd:%d\n", user_path->path_id, user_path->fd);

    do {
        recv_size = recvfrom(user_path->fd, packet_buf, sizeof(packet_buf), 0,
                            (struct sockaddr *)&addr, &addr_len);
        if (recv_size < 0 && get_sys_errno() == EAGAIN) {
            break;
        }

        if (recv_size <= 0) {
            break;
        }

        user_path->local_addrlen = sizeof(struct sockaddr_in6);
        xqc_int_t ret = getsockname(user_path->fd, (struct sockaddr*)&user_path->local_addr,
                                    &user_path->local_addrlen);
        if (ret != 0) {
            printf("getsockname error, errno: %d\n", get_sys_errno());
        }

        recv_sum += recv_size;
        uint64_t recv_time = xqc_now();
        user_path->last_sock_op_time = recv_time;
        if (xqc_engine_packet_process(user_conn->ctx->engine, packet_buf, recv_size,
                                      (struct sockaddr *)(&user_path->local_addr),
                                      user_path->local_addrlen, (struct sockaddr *)(&addr),
                                      addr_len, (xqc_msec_t)recv_time,
                                      user_conn) != XQC_OK)
        {
            return;
        }
    } while (recv_size > 0);

finish_recv:
    xqc_engine_finish_recv(user_conn->ctx->engine);
}


static void
xqc_demo_cli_socket_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t *) arg;

    if (what & EV_WRITE) {
        xqc_demo_cli_socket_write_handler(user_conn, fd);

    } else if (what & EV_READ) {
        xqc_demo_cli_socket_read_handler(user_conn, fd);

    } else {
        printf("event callback: what=%d\n", what);
        exit(1);
    }
}


/******************************************************************************
 *                     start of engine callback functions                     *
 ******************************************************************************/

static void
xqc_demo_cli_engine_callback(int fd, short what, void *arg)
{
    // printf("timer wakeup now:%"PRIu64"\n", xqc_now());
    xqc_demo_cli_ctx_t *ctx = (xqc_demo_cli_ctx_t *) arg;
    xqc_engine_main_logic(ctx->engine);
}


static void
xqc_demo_cli_idle_callback(int fd, short what, void *arg)
{
    int rc = 0;
    xqc_demo_cli_user_path_t *user_path = (xqc_demo_cli_user_path_t*) arg;
    xqc_demo_cli_user_conn_t *user_conn = user_path->user_conn;

    if (xqc_now() - user_path->last_sock_op_time < (uint64_t)user_conn->ctx->args->net_cfg.conn_timeout * 1000000) {
        struct timeval tv;
        tv.tv_sec = user_conn->ctx->args->net_cfg.conn_timeout;
        tv.tv_usec = 0;
        event_add(user_path->ev_timeout, &tv);

    } else {
        if (user_conn->active_path_cnt > 1) {
            /* close path first */
            rc = xqc_conn_close_path(user_conn->ctx->engine, &user_conn->cid, user_path->path_id);

        } 
        /* if there is only one path, we close the connection */
        if (user_conn->active_path_cnt <= 1 || rc == -XQC_EMP_NO_ACTIVE_PATH)
        {
            if (user_conn->ctx->args->quic_cfg.alpn_type == ALPN_H3) {
                rc = xqc_h3_conn_close(user_conn->ctx->engine, &user_conn->cid);

            } else {
                rc = xqc_hq_conn_close(user_conn->ctx->engine, user_conn->hqc_handle, &user_conn->cid);
            }

            if (user_conn->ev_delay_req) {
                event_del(user_conn->ev_delay_req);
                user_conn->ev_delay_req = NULL;
            }

            if (user_conn->ev_idle_restart) {
                event_del(user_conn->ev_idle_restart);
                user_conn->ev_idle_restart = NULL;
            }

            if (user_conn->ev_close_path) {
                event_del(user_conn->ev_close_path);
                user_conn->ev_close_path = NULL;
            }

            if (user_conn->ev_rebinding_p0) {
                event_del(user_conn->ev_rebinding_p0);
                user_conn->ev_rebinding_p0 =  NULL;
            }

            if (user_conn->ev_rebinding_p1) {
                event_del(user_conn->ev_rebinding_p1);
                user_conn->ev_rebinding_p1 =  NULL;
            }

            printf("socket idle timeout, task failed, total task_cnt: %d, req_fin_cnt: %d, req_sent_cnt: %d, req_create_cnt: %d\n",
                   user_conn->ctx->task_ctx.tasks[user_conn->task->task_idx].req_cnt, 
                   user_conn->ctx->task_ctx.schedule.schedule_info[user_conn->task->task_idx].req_fin_cnt, 
                   user_conn->ctx->task_ctx.schedule.schedule_info[user_conn->task->task_idx].req_sent_cnt,
                   user_conn->ctx->task_ctx.schedule.schedule_info[user_conn->task->task_idx].req_create_cnt);
            xqc_demo_cli_on_task_fail(user_conn->ctx, user_conn->task);
        }
        
        if (rc) {
            printf("close path or conn error, path_id %"PRIu64"\n", user_path->path_id);
            return;
        }
    }
}

static void
xqc_demo_cli_delayed_req_start(int fd, short what, void *arg)
{
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t *) arg;
    int req_cnt = user_conn->task->req_cnt;
    if (user_conn->ctx->args->req_cfg.serial) {
        req_cnt = req_cnt > 1 ? 1 : req_cnt;
    }
    xqc_demo_cli_send_requests(user_conn, user_conn->ctx->args,
                               user_conn->task->reqs, req_cnt);
}

static void
xqc_demo_cli_delayed_idle_restart(int fd, short what, void *arg) 
{
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t *)arg;
    xqc_demo_cli_task_ctx_t *ctx = &user_conn->ctx->task_ctx;
    int task_idx = user_conn->task->task_idx;
    xqc_demo_cli_continue_send_reqs(ctx->tasks[task_idx].user_conn);
}

static void
xqc_demo_cli_close_path_timeout(int fd, short what, void *arg)
{
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t *) arg;
    if (user_conn->active_path_cnt > 1) 
    {
        xqc_conn_close_path(user_conn->ctx->engine, &(user_conn->cid), user_conn->paths[1].path_id);
    }
}

static void
xqc_demo_cli_rebind_path0(int fd, short what, void *arg)
{
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t *) arg;
    if (user_conn->paths[0].is_active) {
        // change fd
        int temp = user_conn->paths[0].fd;
        user_conn->paths[0].fd = user_conn->paths[0].rebind_fd;
        user_conn->paths[0].rebind_fd = user_conn->paths[0].fd;

        //stop read from the old socket
        event_del(user_conn->paths[0].ev_socket);
        user_conn->paths[0].ev_socket = NULL;

        xqc_h3_conn_send_ping(user_conn->ctx->engine, &user_conn->cid, NULL);
    }
}

static void
xqc_demo_cli_rebind_path1(int fd, short what, void *arg)
{
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t *) arg;
    if (user_conn->paths[1].is_active) {
        // change fd
        int temp = user_conn->paths[1].fd;
        user_conn->paths[1].fd = user_conn->paths[1].rebind_fd;
        user_conn->paths[1].rebind_fd = user_conn->paths[1].fd;

        event_del(user_conn->paths[1].ev_socket);
        user_conn->paths[1].ev_socket = NULL;

        xqc_h3_conn_send_ping(user_conn->ctx->engine, &user_conn->cid, NULL);
    }
}


/******************************************************************************
 *                        start of client init functions                      *
 ******************************************************************************/

void
xqc_demo_cli_init_0rtt(xqc_demo_cli_client_args_t *args)
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
    ret = xqc_demo_cli_read_token(
        args->quic_cfg.token, XQC_MAX_TOKEN_LEN);
    args->quic_cfg.token_len = ret > 0 ? ret : 0;
}


void
xqc_demo_cli_init_engine_ssl_config(xqc_engine_ssl_config_t* cfg, xqc_demo_cli_client_args_t *args)
{
    memset(cfg, 0, sizeof(xqc_engine_ssl_config_t));
    if (args->quic_cfg.cipher_suites) {
        cfg->ciphers = args->quic_cfg.cipher_suites;

    } else {
        cfg->ciphers = XQC_TLS_CIPHERS;
    }

    cfg->groups = XQC_INTEROP_TLS_GROUPS;
}

void
xqc_demo_cli_init_conn_ssl_config(xqc_conn_ssl_config_t *conn_ssl_config,
    xqc_demo_cli_client_args_t *args)
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

void
xqc_demo_cli_init_conneciton_settings(xqc_conn_settings_t* settings,
    xqc_demo_cli_client_args_t *args)
{
    xqc_cong_ctrl_callback_t cong_ctrl = xqc_bbr_cb;
    switch (args->net_cfg.cc) {
    case CC_TYPE_BBR:
        cong_ctrl = xqc_bbr_cb;
        break;

    case CC_TYPE_CUBIC:
        cong_ctrl = xqc_cubic_cb;
        break;
#ifdef XQC_ENABLE_COPA
    case CC_TYPE_COPA:
        cong_ctrl = xqc_copa_cb;
        break;
#endif
#ifdef XQC_ENABLE_RENO
    case CC_TYPE_RENO:
        cong_ctrl = xqc_reno_cb;
        break;
#endif

    default:
        break;
    }

    xqc_scheduler_callback_t sched = xqc_minrtt_scheduler_cb;
    if (strncmp(args->quic_cfg.mp_sched, "minrtt", strlen("minrtt")) == 0) {
        sched = xqc_minrtt_scheduler_cb;

    } if (strncmp(args->quic_cfg.mp_sched, "backup", strlen("backup")) == 0) {
        sched = xqc_backup_scheduler_cb;

    } else {
#ifdef XQC_ENABLE_MP_INTEROP
        sched = xqc_interop_scheduler_cb;
#endif
    }

    memset(settings, 0, sizeof(xqc_conn_settings_t));
    settings->pacing_on = args->net_cfg.pacing;
    settings->cong_ctrl_callback = cong_ctrl;
    settings->cc_params.customize_on = 1,
    settings->cc_params.init_cwnd = 96,
    settings->so_sndbuf = 1024*1024;
    settings->proto_version = XQC_VERSION_V1;
    settings->spurious_loss_detect_on = 1;
    settings->keyupdate_pkt_threshold = args->quic_cfg.keyupdate_pkt_threshold;
    settings->enable_multipath = args->net_cfg.multipath;
    settings->mp_ack_on_any_path = args->quic_cfg.mp_ack_on_any_path;
    settings->scheduler_callback = sched;
    settings->recv_rate_bytes_per_sec = args->quic_cfg.recv_rate;
    settings->mp_enable_reinjection = args->quic_cfg.reinjection;
    settings->reinj_ctl_callback = xqc_deadline_reinj_ctl_cb;
    settings->standby_path_probe_timeout = 1000;
    settings->multipath_version = args->quic_cfg.mp_version;
    settings->mp_ping_on = 1;
    settings->is_interop_mode = args->quic_cfg.is_interop_mode;
    settings->max_pkt_out_size = args->quic_cfg.max_pkt_sz;
    settings->adaptive_ack_frequency = 1;
    if (args->req_cfg.throttled_req != -1) {
        settings->enable_stream_rate_limit = 1;
        settings->recv_rate_bytes_per_sec = 0;
    }
    strncpy(settings->conn_option_str, args->quic_cfg.co_str, XQC_CO_STR_MAX_LEN);
}

/* set client args to default values */
void
xqc_demo_cli_init_args(xqc_demo_cli_client_args_t *args)
{
    memset(args, 0, sizeof(xqc_demo_cli_client_args_t));

    /* net cfg */
    args->net_cfg.conn_timeout = 30;
    strncpy(args->net_cfg.server_addr, "127.0.0.1", sizeof(args->net_cfg.server_addr));
    args->net_cfg.server_port = 8443;

    /* env cfg */
    args->env_cfg.log_level = XQC_LOG_DEBUG;
    strncpy(args->env_cfg.log_path, LOG_PATH, sizeof(args->env_cfg.log_path));
    strncpy(args->env_cfg.out_file_dir, OUT_DIR, sizeof(args->env_cfg.out_file_dir));
    strncpy(args->env_cfg.key_out_path, KEY_PATH, sizeof(args->env_cfg.out_file_dir));

    /* quic cfg */
    args->quic_cfg.alpn_type = ALPN_HQ;
    strncpy(args->quic_cfg.alpn, "hq-interop", sizeof(args->quic_cfg.alpn));
    args->quic_cfg.keyupdate_pkt_threshold = UINT64_MAX;
    /* default 04 */
    args->quic_cfg.mp_version = XQC_MULTIPATH_04;
    args->quic_cfg.max_pkt_sz = 1200;

    args->req_cfg.throttled_req = -1;

}

void
xqc_demo_cli_parse_server_addr(char *url, xqc_demo_cli_net_config_t *cfg)
{
    /* get hostname and port */
    char s_port[16] = {0};
    sscanf(url, "%*[^://]://%[^:]:%[^/]", cfg->host, s_port);

    /* parse port */
    cfg->server_port = atoi(s_port);

    /* set hint for hostname resolve */
    struct addrinfo hints = {0};
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    /* resolve server's ip from hostname */
    struct addrinfo *result = NULL;
    int rv = getaddrinfo(cfg->host, s_port, &hints, &result);
    if (rv != 0) {
        printf("get addr info from hostname: %s\n", gai_strerror(rv));
    }
    memcpy(&cfg->addr, result->ai_addr, result->ai_addrlen);
    cfg->addr_len = result->ai_addrlen;

    /* convert to string. */
    if (result->ai_family == AF_INET6) {
        inet_ntop(result->ai_family, &(((struct sockaddr_in6*)result->ai_addr)->sin6_addr),
            cfg->server_addr, sizeof(cfg->server_addr));
    } else {
        inet_ntop(result->ai_family, &(((struct sockaddr_in*)result->ai_addr)->sin_addr),
            cfg->server_addr, sizeof(cfg->server_addr));
    }

    printf("server[%s] addr: %s:%d.\n", cfg->host, cfg->server_addr, cfg->server_port);
    freeaddrinfo(result);
}

void
xqc_demo_cli_parse_urls(char *urls, xqc_demo_cli_client_args_t *args)
{
    /* split urls */
    int cnt = 0;
    static char *separator = " ";
    char *token = strtok(urls, separator);
    while (token != NULL) {
        if (token) {
            strncpy(args->req_cfg.reqs[cnt].url, token, URL_LEN - 1);
            sscanf(token, "%[^://]://%[^/]%s", args->req_cfg.reqs[cnt].scheme,
                args->req_cfg.reqs[cnt].auth, args->req_cfg.reqs[cnt].path);
        }
        cnt++;
        token = strtok(NULL, separator);
    }
    args->req_cfg.request_cnt = cnt;

    /* parse the server addr */
    if (args->req_cfg.request_cnt > 0) {
        xqc_demo_cli_parse_server_addr(args->req_cfg.reqs[0].url, &args->net_cfg);
    }
}


void
xqc_demo_cli_usage(int argc, char *argv[])
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
        "   -c    Congestion Control Algorithm. r:reno b:bbr c:cubic P:copa\n"
        "   -C    Pacing on.\n"
        "   -t    Connection timeout. Default 3 seconds.\n"
        "   -S    cipher suites\n"
        "   -0    use 0-RTT\n"
        "   -A    alpn selection: h3/hq\n"
        "   -D    save request body directory\n"
        "   -l    Log level. e:error d:debug.\n"
        "   -L    xquic log directory.\n"
        "   -U    Url. \n"
        "   -k    key out path\n"
        "   -K    Client's life circle time\n"
        "   -u    key update packet threshold\n"
        "   -d    do not save responses to files\n"
        "   -M    enable multipath\n"
        "   -o    use interop mode\n"
        "   -i    interface to create a path. For instance, we can use '-i lo -i lo' to create two paths via lo.\n"
        "   -w    waiting N ms to start the first request.\n"
        "   -P    enable MPQUIC to return ACK_MPs on any paths.\n"
        "   -s    multipath scheduler (interop, minrtt, backup), default: interop\n"
        "   -b    set the second path as a backup path\n"
        "   -Z    close one path after X ms\n"
        "   -N    No encryption (default disabled)\n"
        "   -Q    Send requests one by one (default disabled)\n"
        "   -T    Throttle recving rate (Bps)\n"
        "   -R    Reinjection (1,2,4) \n"
        "   -V    Multipath Version (4,5,6)\n"
        "   -B    Set initial path standby after recvd first application data, and set initial path available after X ms\n"
        "   -I    Idle interval between requests (ms)\n"
        "   -n    Throttling the {1,2,...}xn-th requests\n"
        "   -e    NAT rebinding on path 0\n"
        "   -E    NAT rebinding on path 1\n"
        "   -F    MTU size (default: 1200)\n"
        "   -G    Google connection options (e.g. CBBR,TBBR)\n"
        , prog);
}

void
xqc_demo_cli_parse_args(int argc, char *argv[], xqc_demo_cli_client_args_t *args)
{
    int ch = 0;
    while ((ch = getopt(argc, argv, "a:p:c:Ct:S:0m:A:D:l:L:k:K:U:u:dMoi:w:Ps:bZ:NQT:R:V:B:I:n:eEF:G:")) != -1) {
        switch (ch) {
        /* server ip */
        case 'a':
            printf("option addr :%s\n", optarg);
            snprintf(args->net_cfg.server_addr, sizeof(args->net_cfg.server_addr), optarg);
            break;

        /* server port */
        case 'p':
            printf("option port :%s\n", optarg);
            args->net_cfg.server_port = atoi(optarg);
            break;

        /* congestion control */
        case 'c':
            printf("option cong_ctl :%s\n", optarg);
            /* r:reno b:bbr c:cubic p:copa */
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
            case 'P':
                args->net_cfg.cc = CC_TYPE_COPA;
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

        /* idle persist timeout */
        case 't':
            printf("option connection timeout :%s\n", optarg);
            args->net_cfg.conn_timeout = atoi(optarg);
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

        /* multi connections */
        case 'm':
            printf("option multi connection: on\n");
            switch (atoi(optarg)) {
            case 0:
                args->net_cfg.mode = MODE_SCMR;
                break;
            case 1:
                args->net_cfg.mode = MODE_SCSR_SERIAL;
                break;
            case 2:
                args->net_cfg.mode = MODE_SCSR_CONCURRENT;
            default:
                break;
            }
            break;

        /* alpn */
        case 'A':
            printf("option set ALPN[%s]\n", optarg);
            if (strcmp(optarg, "h3") == 0) {
                args->quic_cfg.alpn_type = ALPN_H3;
                strncpy(args->quic_cfg.alpn, "h3", 3);

            } else if (strcmp(optarg, "hq") == 0) {
                args->quic_cfg.alpn_type = ALPN_HQ;
                strncpy(args->quic_cfg.alpn, "hq-interop", 11);
            }

            break;

        /* out file directory */
        case 'D':
            printf("option save body dir: %s\n", optarg);
            strncpy(args->env_cfg.out_file_dir, optarg, sizeof(args->env_cfg.out_file_dir) - 1);
            break;

        /* log level */
        case 'l':
            printf("option log level :%s\n", optarg);
            /* e:error d:debug */
            args->env_cfg.log_level = optarg[0];
            break;

        /* log directory */
        case 'L':
            printf("option log directory :%s\n", optarg);
            strncpy(args->env_cfg.log_path, optarg, sizeof(args->env_cfg.log_path) - 1);
            break;

        /* key out path */
        case 'k':
            printf("key output file: %s\n", optarg);
            args->env_cfg.key_output_flag = 1;
            strncpy(args->env_cfg.key_out_path, optarg, sizeof(args->env_cfg.key_out_path) - 1);
            break;

        /* client life time circle */
        case 'K':
            printf("client life circle time: %s\n", optarg);
            args->env_cfg.life = atoi(optarg);
            break;

        /* request urls */
        case 'U': // request URL, address is parsed from the request
            printf("option url only:%s\n", optarg);
            xqc_demo_cli_parse_urls(optarg, args);
            break;

        /* key update packet threshold */
        case 'u':
            printf("key update packet threshold: %s\n", optarg);
            args->quic_cfg.keyupdate_pkt_threshold = atoi(optarg);
            break;

        case 'd':
            printf("option dummy mode on\n");
            args->req_cfg.dummy_mode = 1;
            break;

        case 'M':
            printf("option multipath on\n");
            args->net_cfg.multipath = 1;
            break;

         case 'o':
            printf("set interop mode\n");
            args->quic_cfg.is_interop_mode = 1;
            break;
        case 'i':
            printf("option adding interface: %s\n", optarg);
            if (args->net_cfg.ifcnt < MAX_PATH_CNT) {
                strncpy(args->net_cfg.iflist[args->net_cfg.ifcnt++], optarg, strlen(optarg));
            } else {
                printf("too many interfaces (two at most)!\n");
                exit(0);
            }
            break;

        case 'w':
            printf("option first req delay: %s\n", optarg);
            args->req_cfg.req_start_delay = atoi(optarg);
            break;
        
        case 'P':
            printf("option ACK_MP on any path on\n");
            args->quic_cfg.mp_ack_on_any_path = 1;
            break;

        case 's':
            printf("option scheduler: %s\n", optarg);
            strncpy(args->quic_cfg.mp_sched, optarg, 32);
            break;

        case 'b':
            printf("option backup path on\n");
            args->quic_cfg.mp_backup = 1;
            break;
        
        case 'Z':
            printf("option close a path after %s ms\n", optarg);
            args->quic_cfg.close_path = atoi(optarg);
            break;

        case 'N':
            printf("option no encryption on\n");
            args->quic_cfg.no_encryption = 1;
            break;

        case 'Q':
            printf("option serial requests on\n");
            args->req_cfg.serial = 1;
            break;

        case 'T':
            printf("option recv rate limit: %s\n", optarg);
            args->quic_cfg.recv_rate = atoi(optarg);
            break;

        case 'R':
            printf("option reinjection: %s\n", optarg);
            args->quic_cfg.reinjection = atoi(optarg);
            break;
        
        case 'V':
            printf("option multipath version: %s\n", optarg);
            args->quic_cfg.mp_version = atoi(optarg);
            break;

        case 'B':
            printf("option multipath set path status: %s ms\n", optarg);
            args->quic_cfg.send_path_standby = 1;
            args->quic_cfg.path_status_timer_threshold = atoi(optarg) * 1000;
            break;

        case 'I':
            printf("option idle gap: %s\n", optarg);
            args->req_cfg.idle_gap = atoi(optarg);
            break;

        case 'n':
            printf("option throttled reqs: %s\n", optarg);
            args->req_cfg.throttled_req = atoi(optarg);
            break;

        case 'e':
            printf("option rebinding path0 after 2s\n");
            args->net_cfg.rebind_p0 = 1;
            break;

        case 'E':
            printf("option rebinding path1 after 3s\n");
            args->net_cfg.rebind_p1 = 1;
            break;     

        case 'F':
            printf("MTU size: %s\n", optarg);
            args->quic_cfg.max_pkt_sz = atoi(optarg);
            break;
        
        case 'G':
            printf("Google connection options: %s\n", optarg);
            strncpy(args->quic_cfg.co_str, optarg, XQC_CO_STR_MAX_LEN);
            break;

        default:
            printf("other option :%c\n", ch);
            xqc_demo_cli_usage(argc, argv);
            exit(0);
        }
    }
}

#define MAX_REQ_BUF_LEN 1500
int
xqc_demo_cli_format_hq_req(char *buf, int len, xqc_demo_cli_request_t* req)
{
    return snprintf(buf, len, "%s", req->path);
    // return snprintf(buf, len, "%s %s\r\n", method_s[req->method], req->path);
}

int
xqc_demo_cli_send_hq_req(xqc_demo_cli_user_conn_t *user_conn,
    xqc_demo_cli_user_stream_t *user_stream, xqc_demo_cli_request_t *req)
{
    /* create request */
    user_stream->hq_request = xqc_hq_request_create(user_conn->ctx->engine, user_conn->hqc_handle,
                                                    &user_conn->cid, user_stream);
    if (user_stream->hq_request == NULL) {
        // printf("user_conn: %p, create stream failed, will try later\n", user_stream);
        return -1;
    }

    /* prepare stream data, which will be sent on callback */
    user_stream->send_buf = calloc(1, MAX_REQ_BUF_LEN);
    user_stream->send_len = xqc_demo_cli_format_hq_req(user_stream->send_buf, MAX_REQ_BUF_LEN, req);
    int ret = xqc_demo_cli_hq_req_send(user_stream->hq_request, user_stream);
    // printf("xqc_demo_cli_hq_req_write_notify, user_stream[%p] send_cnt: %d\n", user_stream, ret);
    return 0;
}


int
xqc_demo_cli_format_h3_req(xqc_http_header_t *headers, size_t sz, xqc_demo_cli_request_t* req)
{
    /* response header buf list */
    xqc_http_header_t req_hdr[] = {
        {
            .name = {.iov_base = ":method", .iov_len = 7},
            .value = {.iov_base = method_s[req->method], .iov_len = strlen(method_s[req->method])},
            .flags = 0,
        },
        {
            .name = {.iov_base = ":scheme", .iov_len = 7},
            .value = {.iov_base = req->scheme, .iov_len = strlen(req->scheme)},
            .flags = 0,
        },
        {
            .name = {.iov_base = ":path", .iov_len = 5},
            .value = {.iov_base = req->path, .iov_len = strlen(req->path)},
            .flags = 0,
        },
        {
            .name = {.iov_base = ":authority", .iov_len = 10},
            .value = {.iov_base = req->auth, .iov_len = strlen(req->auth)},
            .flags = 0,
        }
    };

    size_t req_sz = sizeof(req_hdr) / sizeof(req_hdr[0]);
    if (sz < req_sz) {
        return -1;
    }

    for (size_t i = 0; i < req_sz; i++) {
        headers[i] = req_hdr[i];
    }

    return req_sz;
}

int
xqc_demo_cli_send_h3_req(xqc_demo_cli_user_conn_t *user_conn,
    xqc_demo_cli_user_stream_t *user_stream, xqc_demo_cli_request_t *req)
{
    xqc_stream_settings_t settings = { .recv_rate_bytes_per_sec = 0 };
    int task_idx = user_conn->task->task_idx;
    int req_create_cnt = user_conn->ctx->task_ctx.schedule.schedule_info[task_idx].req_create_cnt;
    if (user_conn->ctx->args->req_cfg.throttled_req != -1) {
        if (req_create_cnt == user_conn->ctx->args->req_cfg.throttled_req) {
            settings.recv_rate_bytes_per_sec = user_conn->ctx->args->quic_cfg.recv_rate;
        }
        
        if (req_create_cnt != 0
            && user_conn->ctx->args->req_cfg.throttled_req != 0 
            && (req_create_cnt % user_conn->ctx->args->req_cfg.throttled_req) == 0)
        {
            settings.recv_rate_bytes_per_sec = user_conn->ctx->args->quic_cfg.recv_rate;
        }
    }

    user_stream->h3_request = xqc_h3_request_create(user_conn->ctx->engine, &user_conn->cid,
        &settings, user_stream);
    if (user_stream->h3_request == NULL) {
        printf("xqc_h3_request_create error\n");
        return -1;
    }

    // char req_buf[MAX_REQ_BUF_LEN] = {0};
    xqc_http_header_t header[H3_HDR_CNT];
    int hdr_cnt = xqc_demo_cli_format_h3_req(header, H3_HDR_CNT, req);
    if (hdr_cnt > 0) {
        user_stream->h3_hdrs.headers = header;
        user_stream->h3_hdrs.count = hdr_cnt;
        xqc_demo_cli_h3_request_send(user_stream);
    }
    return 0;
}

void
xqc_demo_cli_open_file(xqc_demo_cli_user_stream_t *user_stream, const char *save_path,
    const char *req_path)
{
    char file_path[512] = {0};
    snprintf(file_path, sizeof(file_path), "%s%s", save_path, req_path);

    if (user_stream->user_conn->ctx->args->req_cfg.dummy_mode) {
        printf("dummy mode: do not open file[%s]\n", file_path);
        user_stream->recv_body_fp = NULL;
        return;
    }

    user_stream->recv_body_fp = fopen(file_path, "wb");
    if (NULL == user_stream->recv_body_fp) {
        printf("open file[%s] error\n", file_path);
    }
    printf("open file[%s] suc\n", file_path);
}

void
xqc_demo_cli_on_task_req_sent(xqc_demo_cli_ctx_t *ctx, int task_id)
{
    ctx->task_ctx.schedule.schedule_info[task_id].req_create_cnt++;
}

void
xqc_demo_cli_send_requests(xqc_demo_cli_user_conn_t *user_conn, xqc_demo_cli_client_args_t *args,
    xqc_demo_cli_request_t *reqs, int req_cnt)
{
    DEBUG;
    for (int i = 0; i < req_cnt; i++) {
        /* user handle of stream */
        xqc_demo_cli_user_stream_t *user_stream = calloc(1, sizeof(xqc_demo_cli_user_stream_t));
        user_stream->user_conn = user_conn;
        // printf("   .. user_stream: %p\n", user_stream);

        /* open save file */
        xqc_demo_cli_open_file(user_stream, args->env_cfg.out_file_dir, reqs[i].path);
        strncpy(user_stream->file_name, reqs[i].path, RESOURCE_LEN - 1);

        /* send request */
        if (args->quic_cfg.alpn_type == ALPN_HQ) {
            if (xqc_demo_cli_send_hq_req(user_conn, user_stream, reqs + i) < 0) {
                printf("send hq req blocked, will try later, total sent_cnt: %d\n", 
                    user_conn->ctx->task_ctx.schedule.schedule_info[user_conn->task->task_idx].req_create_cnt);
                free(user_stream);
                return;
            }

        } else if (args->quic_cfg.alpn_type == ALPN_H3) {
            if (xqc_demo_cli_send_h3_req(user_conn, user_stream, reqs + i) < 0) {
                printf("send h3 req blocked, will try later, total sent_cnt: %d\n", 
                    user_conn->ctx->task_ctx.schedule.schedule_info[user_conn->task->task_idx].req_create_cnt);
                free(user_stream);
                return;
            }
        }

        xqc_demo_cli_on_task_req_sent(user_conn->ctx, user_conn->task->task_idx);
    }
}

void
xqc_demo_cli_continue_send_reqs(xqc_demo_cli_user_conn_t *user_conn)
{
    xqc_demo_cli_ctx_t *ctx = user_conn->ctx;
    int task_idx = user_conn->task->task_idx;
    int req_create_cnt = ctx->task_ctx.schedule.schedule_info[task_idx].req_create_cnt;
    int req_cnt = user_conn->task->req_cnt - req_create_cnt;
    if (ctx->args->req_cfg.serial) {
        req_cnt = req_cnt > 1 ? 1 : req_cnt;
    }
    if (req_cnt > 0) {
        xqc_demo_cli_request_t *reqs = user_conn->task->reqs + req_create_cnt;
        xqc_demo_cli_send_requests(user_conn, ctx->args, reqs, req_cnt);
    }
}

#if 0
void on_max_streams(xqc_connection_t *conn, void *user_data, uint64_t max_streams, int type)
{
    printf("--- on_max_streams: %Zu, type: %d, continue to send\n", max_streams, type);
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t *)user_data;
    xqc_demo_cli_continue_send_reqs(user_conn);
}
#endif

/******************************************************************************
 *                     start of http/3 callback functions                     *
 ******************************************************************************/

int
xqc_demo_cli_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t *) user_data;
    // printf("xqc_h3_conn_is_ready_to_send_early_data:%d\n", xqc_h3_conn_is_ready_to_send_early_data(h3_conn));
    return 0;
}

int
xqc_demo_cli_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t *)user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(user_conn->ctx->engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" "
           "early_data_flag:%d, conn_err:%d, ack_info:%s, conn_info:%s\n", stats.send_count, stats.lost_count,
           stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err,
           stats.ack_info, stats.conn_info);

    xqc_demo_cli_on_task_finish(user_conn->ctx, user_conn->task);
    free(user_conn);
    return 0;
}

void
xqc_demo_cli_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    DEBUG;
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t *) user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(user_conn->ctx->engine, &user_conn->cid);
    printf("0rtt_flag:%d\n", stats.early_data_flag);

}

void
xqc_demo_cli_h3_conn_ping_acked_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *ping_user_data, void *user_data)
{
    if (ping_user_data) {
        // printf("ping_id:%d\n", *(int *) ping_user_data);
    }
}

#if 0
void
client_h3_conn_max_streams(xqc_h3_conn_t *conn, void *user_data, uint64_t max_streams, int type)
{
    DEBUG;
    xqc_demo_cli_user_conn_t *user_conn = (xqc_demo_cli_user_conn_t *)user_data;
    xqc_demo_cli_continue_send_reqs(user_conn);
}
#endif


void
xqc_demo_cli_init_callback(xqc_engine_callback_t *cb, xqc_transport_callbacks_t *transport_cbs,
    xqc_demo_cli_client_args_t* args)
{
    static xqc_engine_callback_t callback = {
        .log_callbacks = {
            .xqc_log_write_err = xqc_demo_cli_write_log_file,
            .xqc_log_write_stat = xqc_demo_cli_write_log_file,
            .xqc_qlog_event_write = xqc_demo_cli_write_qlog_file,
        },
        .keylog_cb = xqc_demo_cli_keylog_cb,
        .set_event_timer = xqc_demo_cli_set_event_timer,
    };

    static xqc_transport_callbacks_t tcb = {
        .write_socket = xqc_demo_cli_write_socket,
        .write_socket_ex = xqc_demo_cli_write_socket_ex,
        .save_token = xqc_demo_cli_save_token, /* save token */
        .save_session_cb = xqc_demo_cli_save_session_cb,
        .save_tp_cb = xqc_demo_cli_save_tp_cb,
        .conn_update_cid_notify = xqc_demo_cli_conn_update_cid_notify,
        .ready_to_create_path_notify = xqc_demo_cli_conn_create_path,
        .path_removed_notify = xqc_demo_cli_path_removed,
    };

    *cb = callback;
    *transport_cbs = tcb;
}


int
xqc_demo_cli_init_alpn_ctx(xqc_demo_cli_ctx_t *ctx)
{
    int ret = 0;

    xqc_hq_callbacks_t hq_cbs = {
        .hqc_cbs = {
            .conn_create_notify = xqc_demo_cli_hq_conn_create_notify,
            .conn_close_notify = xqc_demo_cli_hq_conn_close_notify,
        },
        .hqr_cbs = {
            .req_close_notify = xqc_demo_cli_hq_req_close_notify,
            .req_read_notify = xqc_demo_cli_hq_req_read_notify,
            .req_write_notify = xqc_demo_cli_hq_req_write_notify,
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
            .h3_conn_create_notify = xqc_demo_cli_h3_conn_create_notify,
            .h3_conn_close_notify = xqc_demo_cli_h3_conn_close_notify,
            .h3_conn_handshake_finished = xqc_demo_cli_h3_conn_handshake_finished,
        },
        .h3r_cbs = {
            .h3_request_create_notify = xqc_demo_cli_h3_request_create_notify,
            .h3_request_close_notify = xqc_demo_cli_h3_request_close_notify,
            .h3_request_read_notify = xqc_demo_cli_h3_request_read_notify,
            .h3_request_write_notify = xqc_demo_cli_h3_request_write_notify,
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
xqc_demo_cli_init_xquic_engine(xqc_demo_cli_ctx_t *ctx, xqc_demo_cli_client_args_t *args)
{
    /* init engine ssl config */
    xqc_engine_ssl_config_t engine_ssl_config;
    xqc_transport_callbacks_t transport_cbs;
    xqc_demo_cli_init_engine_ssl_config(&engine_ssl_config, args);

    /* init engine callbacks */
    xqc_engine_callback_t callback;
    xqc_demo_cli_init_callback(&callback, &transport_cbs, args);

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        return XQC_ERROR;
    }

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

    if (xqc_demo_cli_init_alpn_ctx(ctx) < 0) {
        printf("init alpn ctx error!");
        return -1;
    }

    return XQC_OK;
}


int
xqc_demo_cli_init_xquic_connection(xqc_demo_cli_user_conn_t *user_conn,
    xqc_demo_cli_client_args_t *args)
{
    /* load 0-rtt args before create connection */
    xqc_demo_cli_init_0rtt(args);

    /* init connection settings */
    xqc_conn_settings_t conn_settings;
    xqc_demo_cli_init_conneciton_settings(&conn_settings, args);

    xqc_conn_ssl_config_t conn_ssl_config;
    xqc_demo_cli_init_conn_ssl_config(&conn_ssl_config, args);

    if (args->quic_cfg.alpn_type == ALPN_H3) {
        const xqc_cid_t *cid = xqc_h3_connect(user_conn->ctx->engine, &conn_settings,
            args->quic_cfg.token, args->quic_cfg.token_len, args->net_cfg.host, args->quic_cfg.no_encryption, &conn_ssl_config, 
            (struct sockaddr*)&args->net_cfg.addr, args->net_cfg.addr_len, user_conn);
        if (cid == NULL) {
            return -1;
        }

        memcpy(&user_conn->cid, cid, sizeof(xqc_cid_t));

    } else {
        const xqc_cid_t *cid = xqc_hq_connect(user_conn->ctx->engine, &conn_settings,
            args->quic_cfg.token, args->quic_cfg.token_len, args->net_cfg.host, args->quic_cfg.no_encryption, &conn_ssl_config, 
            (struct sockaddr*)&args->net_cfg.addr, args->net_cfg.addr_len, user_conn);

        if (cid == NULL) {
            return -1;
        }

        memcpy(&user_conn->cid, cid, sizeof(xqc_cid_t));
    }

    if (conn_settings.enable_multipath
        && conn_settings.multipath_version >= XQC_MULTIPATH_06
        && args->quic_cfg.send_path_standby == 1)
    {
        user_conn->send_path_standby = 1;
        user_conn->path_status = 0;
        user_conn->path_status_timer_threshold = args->quic_cfg.path_status_timer_threshold;
        user_conn->path_status_time = 0;
    }

    return 0;
}


uint8_t
xqc_demo_cli_is_0rtt_compliant(xqc_demo_cli_client_args_t *args)
{
    return (args->quic_cfg.use_0rtt
        && args->quic_cfg.st_len > 0 && args->quic_cfg.tp_len > 0);
}

void
xqc_demo_cli_start(xqc_demo_cli_user_conn_t *user_conn, xqc_demo_cli_client_args_t *args,
    xqc_demo_cli_request_t *reqs, int req_cnt)
{
    if (XQC_OK != xqc_demo_cli_init_xquic_connection(user_conn, args)) {
        printf("|xqc_demo_cli_start FAILED|\n");
        return;
    }

#if 0
    if (xqc_demo_cli_is_0rtt_compliant(args)) {
        printf("0rtt compliant, send 0rtt streams\n");
        xqc_demo_cli_send_requests(user_conn, args, reqs, req_cnt);
    }
#endif

    if (args->quic_cfg.close_path) {
        user_conn->ev_close_path = event_new(user_conn->ctx->eb, -1, 0, 
                                            xqc_demo_cli_close_path_timeout, 
                                            user_conn);
        struct timeval tv = {
            .tv_sec = args->quic_cfg.close_path / 1000,
            .tv_usec = (args->quic_cfg.close_path % 1000) * 1000,
        };
        event_add(user_conn->ev_close_path, &tv);
    }

    if (args->net_cfg.rebind_p0) {
        user_conn->ev_rebinding_p0 = event_new(user_conn->ctx->eb, -1, 0, 
                                               xqc_demo_cli_rebind_path0, 
                                               user_conn);
        struct timeval tv = {
            .tv_sec = 2,
            .tv_usec = 0,
        };
        event_add(user_conn->ev_rebinding_p0, &tv);
    }

    if (args->net_cfg.rebind_p1) {
        user_conn->ev_rebinding_p1 = event_new(user_conn->ctx->eb, -1, 0, 
                                               xqc_demo_cli_rebind_path1, 
                                               user_conn);
        struct timeval tv = {
            .tv_sec = 3,
            .tv_usec = 0,
        };
        event_add(user_conn->ev_rebinding_p1, &tv);
    }

    if (args->req_cfg.req_start_delay) {
        user_conn->ev_delay_req = event_new(user_conn->ctx->eb, -1, 0, 
                                            xqc_demo_cli_delayed_req_start, 
                                            user_conn);
        struct timeval tv = {
            .tv_sec = args->req_cfg.req_start_delay / 1000,
            .tv_usec = (args->req_cfg.req_start_delay % 1000) * 1000,
        };
        event_add(user_conn->ev_delay_req, &tv);

    } else {
        /* TODO: fix MAX_STREAMS bug */
        if (args->req_cfg.serial) {
            xqc_demo_cli_send_requests(user_conn, args, reqs, req_cnt > 1 ? 1 : req_cnt);

        } else {
            xqc_demo_cli_send_requests(user_conn, args, reqs, req_cnt);
        }
        
    }
}

void
xqc_demo_cli_init_ctx(xqc_demo_cli_ctx_t *pctx, xqc_demo_cli_client_args_t *args)
{
    strncpy(pctx->log_path, args->env_cfg.log_path, sizeof(pctx->log_path) - 1);
    pctx->args = args;
    xqc_demo_cli_open_log_file(pctx);
    xqc_demo_cli_open_keylog_file(pctx);
}


int
xqc_demo_cli_all_tasks_finished(xqc_demo_cli_ctx_t *ctx)
{
    for (size_t i = 0; i < ctx->task_ctx.task_cnt; i++) {
        if (ctx->task_ctx.schedule.schedule_info[i].status <= TASK_STATUS_RUNNING) {
            return 0;
        }
    }
    return 1;
}


/* get an waiting task while task scheduler is idle */
int
xqc_demo_cli_get_idle_waiting_task(xqc_demo_cli_ctx_t *ctx)
{
    int waiting_idx = -1;
    int idle_flag = 1;
    for (size_t i = 0; i < ctx->task_ctx.task_cnt; i++) {
        /* if any task is running, break loop, and return no task */
        if (ctx->task_ctx.schedule.schedule_info[i].status == TASK_STATUS_RUNNING) {
            idle_flag = 0;
            break;
        }

        if (waiting_idx < 0
            && ctx->task_ctx.schedule.schedule_info[i].status == TASK_STATUS_WAITTING)
        {
            /* mark the first idle task */
            waiting_idx = i;
        }

    }

    return idle_flag ? waiting_idx : -1;
}


static int
xqc_demo_cli_create_socket(xqc_demo_cli_user_path_t *user_path, 
    xqc_demo_cli_net_config_t* cfg, int path_seq)
{

    if (cfg->ifcnt && path_seq >= cfg->ifcnt) {
        printf("too many sockets (ifcnt:%d)\n", cfg->ifcnt);
        return -1;
    }

    int size;
    int fd = 0;
    int ret;
    int flags = 1;
    struct sockaddr *addr = (struct sockaddr*)&cfg->addr;
    fd = socket(addr->sa_family, SOCK_DGRAM, 0);
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

    if (cfg->ifcnt) {
#if !defined(XQC_SYS_WINDOWS)
        struct ifreq ifr;
        memset(&ifr, 0x00, sizeof(ifr));
        strncpy(ifr.ifr_name, cfg->iflist[path_seq], sizeof(ifr.ifr_name) - 1);

#if !defined(__APPLE__)
        printf("fd: %d. bind to nic: %s\n", fd, cfg->iflist[path_seq]);
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifr, sizeof(ifr)) < 0) {
            printf("bind to nic error: %d, try use sudo\n", errno);
            goto err;
        }
#endif
#endif
    }

    user_path->last_sock_op_time = xqc_now();

    return fd;

err:
    close(fd);
    return -1;
}

int 
xqc_demo_cli_init_user_path(xqc_demo_cli_user_conn_t *user_conn, int path_seq, uint64_t path_id)
{
    xqc_demo_cli_ctx_t *ctx = user_conn->ctx;
    xqc_demo_cli_user_path_t *user_path = &user_conn->paths[path_seq];

    /* create the initial path */
    user_path->fd = xqc_demo_cli_create_socket(user_path, &ctx->args->net_cfg, path_seq);
    if (user_path->fd < 0) {
        printf("xqc_create_socket error\n");
        return -1;
    }

    user_path->rebind_fd = -1;
    user_path->ev_rebind_socket = NULL;

    if (ctx->args->net_cfg.rebind_p0 && path_seq == 0) {
        user_path->rebind_fd = xqc_demo_cli_create_socket(user_path, &ctx->args->net_cfg, path_seq);
        if (user_path->rebind_fd < 0) {
            printf("xqc_create_rebind_socket error\n");
            return -1;
        }
    }

    if (ctx->args->net_cfg.rebind_p1 && path_seq == 1) {
        user_path->rebind_fd = xqc_demo_cli_create_socket(user_path, &ctx->args->net_cfg, path_seq);
        if (user_path->rebind_fd < 0) {
            printf("xqc_create_rebind_socket error\n");
            return -1;
        }
    }

    /* socket event */
    user_path->ev_socket = event_new(ctx->eb, user_path->fd, EV_READ | EV_PERSIST,
                                     xqc_demo_cli_socket_event_callback, user_conn);
    event_add(user_path->ev_socket, NULL);

    if (user_path->rebind_fd != -1) {
        user_path->ev_rebind_socket = event_new(ctx->eb, user_path->rebind_fd, EV_READ | EV_PERSIST,
                                                xqc_demo_cli_socket_event_callback, user_conn);
        event_add(user_path->ev_rebind_socket, NULL);
    }

    /* xquic timer */
    user_path->ev_timeout = event_new(ctx->eb, -1, 0, xqc_demo_cli_idle_callback, user_path);
    struct timeval tv;
    tv.tv_sec = ctx->args->net_cfg.conn_timeout;
    tv.tv_usec = 0;
    event_add(user_path->ev_timeout, &tv);

    user_conn->active_path_cnt++;
    user_conn->total_path_cnt++;
    user_path->is_active = 1;
    user_path->user_conn = user_conn;
    user_path->path_id = path_id;

    printf("No.%d path created id = %"PRIu64"\n", user_conn->total_path_cnt - 1, path_id);

    return 0;
}

/* create one connection, send multi reqs in multi streams */
int
xqc_demo_cli_handle_task(xqc_demo_cli_ctx_t *ctx, xqc_demo_cli_task_t *task)
{
    DEBUG;
    /* create socket and connection callback user data */
    xqc_demo_cli_user_conn_t *user_conn = calloc(1, sizeof(xqc_demo_cli_user_conn_t));
    user_conn->ctx = ctx;
    user_conn->task = task;

    /* init the first path */
    if (xqc_demo_cli_init_user_path(user_conn, 0, 0)) {
        return -1;
    }

    /* start client */
    xqc_demo_cli_start(user_conn, ctx->args, task->reqs, task->req_cnt);

    task->user_conn = user_conn;
    return 0;
}


static struct timeval tv_task_schedule = {0, 100};

/* 
 * the task schedule timer callback, will break the main event loop
 * when all tasks are responsed or closed
 * under multi-connction mode, if previous task has finished, will
 * start a new connection and task.
 */
static void
xqc_demo_cli_task_schedule_callback(int fd, short what, void *arg)
{
    xqc_demo_cli_ctx_t *ctx = (xqc_demo_cli_ctx_t*)arg;
    uint8_t all_task_fin_flag = 1;
    uint8_t idle_flag = 1;
    int idle_waiting_task_id = -1;

    for (size_t i = 0; i < ctx->task_ctx.task_cnt; i++) {

        /* check if all tasks are finished */
        if (ctx->task_ctx.schedule.schedule_info[i].status <= TASK_STATUS_RUNNING) {
            all_task_fin_flag = 0;
        }

        /* record the first waiting task */
        if (idle_waiting_task_id == -1
            && ctx->task_ctx.schedule.schedule_info[i].status == TASK_STATUS_WAITTING)
        {
            idle_waiting_task_id = i;
        }
    }

    if (all_task_fin_flag) {
        printf("all tasks are finished, will break loop and exit\n\n");
        event_base_loopbreak(ctx->eb);
        return;
    }

    /* if idle and got a waiting task, run the task */
    if (idle_flag && idle_waiting_task_id >= 0) {
        /* handle task and set status to RUNNING */
        int ret = xqc_demo_cli_handle_task(ctx, ctx->task_ctx.tasks + idle_waiting_task_id);
        if (0 == ret) {
            ctx->task_ctx.schedule.schedule_info[idle_waiting_task_id].status = TASK_STATUS_RUNNING;

        } else {
            ctx->task_ctx.schedule.schedule_info[idle_waiting_task_id].status = TASK_STATUS_FAILED;
        }
    }

    /* start next round */
    event_add(ctx->ev_task, &tv_task_schedule);
}


void
xqc_demo_cli_init_scmr(xqc_demo_cli_task_ctx_t *tctx, xqc_demo_cli_client_args_t *args)
{
    tctx->task_cnt = 1; /* one task, one connection, all requests */

    /* init task list */
    tctx->tasks = calloc(1, sizeof(xqc_demo_cli_task_t) * 1);
    tctx->tasks->req_cnt = args->req_cfg.request_cnt;
    tctx->tasks->reqs = args->req_cfg.reqs;

    /* init schedule */
    tctx->schedule.schedule_info = calloc(1, sizeof(xqc_demo_cli_task_schedule_info_t) * 1);
}


void
xqc_demo_cli_init_scsr(xqc_demo_cli_task_ctx_t *tctx, xqc_demo_cli_client_args_t *args)
{
    tctx->task_cnt = args->req_cfg.request_cnt;

    /* init task list */
    tctx->tasks = calloc(1, sizeof(xqc_demo_cli_task_t) * tctx->task_cnt);
    for (int i = 0; i < tctx->task_cnt; i++) {
        tctx->tasks[i].task_idx = i;
        tctx->tasks[i].req_cnt = 1;
        tctx->tasks[i].reqs = (xqc_demo_cli_request_t*)args->req_cfg.reqs + i;
    }

    /* init schedule */
    tctx->schedule.schedule_info = calloc(1, sizeof(xqc_demo_cli_task_schedule_info_t) * tctx->task_cnt);
}


/* create task info according to args */
void
xqc_demo_cli_init_tasks(xqc_demo_cli_ctx_t *ctx)
{
    ctx->task_ctx.mode = ctx->args->net_cfg.mode;
    switch (ctx->args->net_cfg.mode) {
    case MODE_SCMR:
        xqc_demo_cli_init_scmr(&ctx->task_ctx, ctx->args);
        break;

    case MODE_SCSR_SERIAL:
    case MODE_SCSR_CONCURRENT:
        xqc_demo_cli_init_scsr(&ctx->task_ctx, ctx->args);
        break;

    default:
        break;
    }
}


/* prevent from endless task, this could be used if execution time is limited */
static void
xqc_demo_cli_kill_it_any_way_callback(int fd, short what, void *arg)
{
    xqc_demo_cli_ctx_t *ctx = (xqc_demo_cli_ctx_t*)arg;
    event_base_loopbreak(ctx->eb);
    printf("[* tasks are running more than %d seconds, kill it anyway! *]\n",
        ctx->args->env_cfg.life);
}


void
xqc_demo_cli_start_task_manager(xqc_demo_cli_ctx_t *ctx)
{
    xqc_demo_cli_init_tasks(ctx);

    /* init and arm task timer */
    ctx->ev_task = event_new(ctx->eb, -1, 0, xqc_demo_cli_task_schedule_callback, ctx);

    /* immediate engage task */
    xqc_demo_cli_task_schedule_callback(-1, 0, ctx);

    /* kill it anyway, to protect from endless task */
    if (ctx->args->env_cfg.life > 0) {
        struct timeval tv_kill_it_anyway = {ctx->args->env_cfg.life, 0};
        ctx->ev_kill = event_new(ctx->eb, -1, 0, xqc_demo_cli_kill_it_any_way_callback, ctx);
        event_add(ctx->ev_kill, &tv_kill_it_anyway);
    }
}


void
xqc_demo_cli_free_ctx(xqc_demo_cli_ctx_t *ctx)
{
    xqc_demo_cli_close_keylog_file(ctx);
    xqc_demo_cli_close_log_file(ctx);

    if (ctx->args) {
        free(ctx->args);
        ctx->args = NULL;
    }

    free(ctx);
}



int
main(int argc, char *argv[])
{
    /* init env if necessary */
    xqc_platform_init_env();
    
    /* get input client args */
    xqc_demo_cli_client_args_t *args = calloc(1, sizeof(xqc_demo_cli_client_args_t));
    xqc_demo_cli_init_args(args);
    xqc_demo_cli_parse_args(argc, argv, args);

    /* init client ctx */
    xqc_demo_cli_ctx_t *ctx = calloc(1, sizeof(xqc_demo_cli_ctx_t));
    xqc_demo_cli_init_ctx(ctx, args);

    /* engine event */
    ctx->eb = event_base_new();
    ctx->ev_engine = event_new(ctx->eb, -1, 0, xqc_demo_cli_engine_callback, ctx);
    xqc_demo_cli_init_xquic_engine(ctx, args);

    /* start task scheduler */
    xqc_demo_cli_start_task_manager(ctx);

    event_base_dispatch(ctx->eb);

    xqc_engine_destroy(ctx->engine);
    xqc_demo_cli_free_ctx(ctx);
    return 0;
}
