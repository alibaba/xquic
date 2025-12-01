/**
 * @copyright Copyright (c) 2024, Alibaba Group Holding Limited
 * xquic webtransport 互通性ECHO测试  Demo
 * 通过wt_ctx_init来注入回调函数，目前已经完全实现和浏览器互通
 */

#define _GNU_SOURCE
#define _ITERATOR_DEBUG_LEVEL 0

#include <ctype.h>
#include <errno.h>
#include "../tests/platform.h"
#include <event2/event.h>
#include <fcntl.h>
#include <inttypes.h>
#include <memory.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <xquic/xqc_http3.h>
#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
// #include <io.h>

#include <stdio.h>
#include <xquic/xqc_webtransport.h>
// #include <semaphore>
#include "src/common/utils/var_buf/xqc_var_buf.h"
#include "src/common/xqc_common.h"
#include "src/common/xqc_time.c"   // xqc_now
#include "time.h"
#include <sys/wait.h>
#include <unistd.h>
#define DEBUG ;

#ifndef XQC_SYS_WINDOWS
#else
#    pragma comment(lib, "ws2_32.lib")
#    pragma comment(lib, "event.lib")
#    pragma comment(lib, "Iphlpapi.lib")
#    pragma comment(lib, "Bcrypt.lib")

#endif

#define DEBUG_TEST 1

#if DEBUG_TEST

#endif

// 以下部分都是因DEMO测试需要引入的函数 和webtransport本身无关，后续会调整

#pragma warning(push)
#pragma warning(disable : 2440)
#pragma warning(disable : 2397)
#define UNISTREAM_ECHO 1

#define XQC_PACKET_TMP_BUF_LEN 1500

#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT 4443
#define SESSION_TICKET_KEY_FILE "session_ticket.key"
#define SESSION_TICKET_KEY_BUF_LEN 2048

#define DEFAULT_SERVER_ADDR "127.0.0.1"
#define DEFAULT_SERVER_PORT 8443

#define LOG_PATH "slog.log"
#define KEY_PATH "skeys.log"
#define SOURCE_DIR "."
#define PRIV_KEY_PATH \
    "/Users/sy03/Desktop/webtransport-poc/webtransport-poc/cert/localhost.key"
#define CERT_PEM_PATH \
    "/Users/sy03/Desktop/webtransport-poc/webtransport-poc/cert/localhost.crt"

#define CIPHER_SUIT_LEN 256
#define TLS_GROUPS_LEN 64

#define RSP_HDR_BUF_LEN 32
typedef enum h3_hdr_type
{
    /* rsp */
    H3_HDR_STATUS,
    H3_HDR_CONTENT_TYPE,
    H3_HDR_CONTENT_LENGTH,
    H3_HDR_METHOD,
    H3_HDR_SCHEME,
    H3_HDR_HOST,
    H3_HDR_PATH,

    H3_HDR_CNT
} H3_HDR_TYPE;

enum WTSettingsID
{
    /* h3 settings */
    WT_SETTINGS_ENABLE_WEBTRANSPORT = 0x2b603742,
    WT_SETTINGS_DATAGRAM            = 0x33,
    WT_SETTINGS_EXTENDEDCONNECT     = 0x8,
};

#define USE_WT_VIDEO_DEMO 1

#if USE_WT_VIDEO_DEMO

xqc_bool_t g_isServerRunning = XQC_FALSE;

FILE      *videoFile;

typedef enum cc_type_s
{
    CC_TYPE_BBR,
    CC_TYPE_CUBIC,
    CC_TYPE_RENO,
    CC_TYPE_COPA
} CC_TYPE;

static int
xqc_demo_read_file_data(char *data, size_t data_len, char *filename)
{
    int    ret = 0;
    size_t total_len, read_len;
    FILE  *fp = fopen(filename, "rb");
    if ( fp == NULL ) {
        ret = -1;
        goto end;
    }

    fseek(fp, 0, SEEK_END);
    total_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if ( total_len > data_len ) {
        ret = -1;
        goto end;
    }

    read_len = fread(data, 1, total_len, fp);
    if ( read_len != total_len ) {
        ret = -1;
        goto end;
    }

    ret = read_len;

end:
    if ( fp ) {
        fclose(fp);
    }
    return ret;
}

// 以上部分都是因DEMO测试需要引入的函数 和webtransport本身无关，后续会调整

void
wt_dgram_read_handler(xqc_webtransport_session_t *session, const void *data,
    size_t data_len, void *user_data, uint64_t data_recv_time)
{
    xqc_wt_conn_t *wt_conn = xqc_wt_session_get_conn(session);
    xqc_webtransport_datagram_send(wt_conn, data, data_len);
}

xqc_int_t
wt_unistream_read_handler(xqc_wt_unistream_t *stream, xqc_wt_session_t *session,
    void *data, size_t data_len, void *strm_user_data)
{
    xqc_h3_stream_t    *h3_stream = xqc_wt_session_get_h3_stream(session);
    xqc_wt_unistream_t *unistream = xqc_wt_create_unistream(
        XQC_WT_STREAM_TYPE_SEND, session, NULL, h3_stream);

    // xqc_wt_unistream_send(unistream, data, data_len, 0);
    xqc_wt_unistream_send(unistream, data, data_len, 1);

    xqc_wt_unistream_close(unistream);

    return 1;
}
xqc_int_t
wt_bidistream_read_handler(xqc_wt_bidistream_t *bidistream,
    xqc_wt_session_t *session, void *data, size_t data_len,
    void *strm_user_data)
{
    // xqc_wt_bidistream_send(bidistream, data, data_len, 0); // not finish
    xqc_wt_bidistream_send(bidistream, data, data_len, 1);   // finish stream
    // xqc_h3_stream_send_goaway(session->mStream, 2,0); // test go away

    return 1;
}

xqc_webtransport_dgram_callbacks_t default_dgram_cbs = {
    .dgram_read_notify = wt_dgram_read_handler};

xqc_webtransport_stream_callbacks_t default_stream_cbs = {
    .wt_unistream_read_notify  = wt_unistream_read_handler,
    .wt_bidistream_read_notify = wt_bidistream_read_handler,
};

typedef struct NetConfig_s {
    struct sockaddr mAddr;
    int             mAddrLen;
    char            ip[64];
    short           port;
    int             ipv6;
    CC_TYPE         cc;
    int             pacing;
    int             conn_timeout;
} NetConfig;

int
str_equal_check(const char *str1, const char *str2)
{
    if ( str1 == NULL || str2 == NULL ) {
        return 0;
    }
    return strcmp(str1, str2) == 0;
}

xqc_bool_t is_connected = XQC_FALSE;

typedef struct QuicConfig_s {
    /* cipher config */
    char     cipher_suit[CIPHER_SUIT_LEN];
    char     groups[TLS_GROUPS_LEN];

    int      stk_len;   /* session ticket len */
    char     stk[2048]; /* session ticket buf */
    /* retry */
    int      retry_on;

    /* dummy mode */
    int      dummy_mode;

    /* multipath */
    int      multipath;

    /* multipath version */
    int      multipath_version;
    /* support interop test */
    int      is_interop_mode;

    /* ack on any path */
    int      mp_ack_on_any_path;

    /* scheduler */
    char     mp_sched[32];

    uint32_t reinjection;

    uint64_t keyupdate_pkt_threshold;
    uint64_t least_available_cid_count;

    size_t   max_pkt_sz;
} QuicConfig;

typedef struct EnvConfig_s {
    char *mLogPath;
    int   mLogLevel;
    char *mSourceFileDir;
    char *mPrivKeyPath;
    char *mCertPemPath;
    int   mKeyOutputFlag;
    char *mKeyOutPath;
} EnvConfig;

// DEMO part
typedef struct wt_server_s {
    NetConfig              *wt_NetConfig;
    QuicConfig             *wt_QuicConfig;
    EnvConfig              *wt_EnvConfig;

    struct event_base      *eb;
    xqc_engine_t           *engine;
    struct event           *ev_engine;

    /* ipv4 server */
    int                     fd;
    struct sockaddr_in      local_addr;
    socklen_t               local_addrlen;
    struct event           *ev_socket;

    /* ipv6 server */
    int                     fd6;
    struct sockaddr_in6     local_addr6;
    socklen_t               local_addrlen6;
    struct event           *ev_socket6;

    /* used to remember fd type to send stateless reset */
    int                     current_fd;

    int                     log_fd;
    int                     keylog_fd;
    uint64_t                ReorderingTimeout;

    wt_stream_close_func_pt mCtxCancel;
    int                     mInitErr;

    xqc_str_hash_table_t   *m_request_handle_map;
    xqc_str_hash_table_t   *m_streams_map;

    xqc_id_hash_table_t    *h3stream_to_session_map;

    int                     m_con_id_gen;
    int                     check_connid_cnt;

} WT_Server;

WT_Server *g_Server = NULL;

WT_Server *
server_init()
{
    WT_Server *server        = (WT_Server *)xqc_calloc(1, sizeof(WT_Server));
    server->wt_NetConfig     = (NetConfig *)xqc_calloc(1, sizeof(NetConfig));
    server->wt_QuicConfig    = (QuicConfig *)xqc_calloc(1, sizeof(QuicConfig));
    server->wt_EnvConfig     = (EnvConfig *)xqc_calloc(1, sizeof(EnvConfig));
    server->m_con_id_gen     = 0;
    server->check_connid_cnt = 0;

    return server;
}

void
wt_svr_init_args(WT_Server *server, int argc, char **argv)
{
    /* net cfg */
    strncpy(server->wt_NetConfig->ip, DEFAULT_IP,
        sizeof(server->wt_NetConfig->ip) - 1);
    server->wt_NetConfig->port = DEFAULT_PORT;

    /* quic cfg */
    int ret = xqc_demo_read_file_data(server->wt_QuicConfig->stk,
        SESSION_TICKET_KEY_BUF_LEN, (char *)SESSION_TICKET_KEY_FILE);
    server->wt_QuicConfig->stk_len = ret > 0 ? ret : 0;
    strncpy(server->wt_QuicConfig->cipher_suit, XQC_TLS_CIPHERS,
        CIPHER_SUIT_LEN - 1);
    strncpy(server->wt_QuicConfig->groups, XQC_TLS_GROUPS, TLS_GROUPS_LEN - 1);

    /* env cfg */

    server->wt_EnvConfig->mLogLevel                  = XQC_LOG_DEBUG;
    server->wt_EnvConfig->mLogPath                   = LOG_PATH;
    server->wt_EnvConfig->mSourceFileDir             = SOURCE_DIR;
    server->wt_EnvConfig->mKeyOutPath                = KEY_PATH;
    server->wt_EnvConfig->mPrivKeyPath               = PRIV_KEY_PATH;
    server->wt_EnvConfig->mCertPemPath               = CERT_PEM_PATH;

    server->wt_QuicConfig->keyupdate_pkt_threshold   = UINT64_MAX;
    server->wt_QuicConfig->least_available_cid_count = 1;
    server->wt_QuicConfig->max_pkt_sz                = 1200;

    int ch                                           = 0;
}

void
wt_svr_set_event_timer(xqc_msec_t wake_after, void *eng_user_data)
{
    WT_Server     *server = g_Server;

    struct timeval tv;
    tv.tv_sec  = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(server->ev_engine, NULL);
}

void
wt_svr_write_log_file(xqc_log_level_t lvl, const void *buf, size_t size,
    void *eng_user_data)
{
    WT_Server *server = g_Server;
}

static void
wt_svr_engine_callback(evutil_socket_t fd, short what, void *arg)
{
    WT_Server *server = g_Server;

    xqc_engine_main_logic(server->engine);
}

ssize_t
wt_svr_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    void *conn_user_data)
{
    ssize_t res;

    int     fd = g_Server->current_fd;

    do {
        set_sys_errno(0);
        res = sendto(fd, (const char *)buf, size, 0, peer_addr, peer_addrlen);
        if ( res < 0 ) {
            printf("xqc_demo_svr_write_socket err %zd %s, fd: %d\n", res,
                strerror(get_sys_errno()), fd);
            if ( get_sys_errno() == EAGAIN ) {
                res = XQC_SOCKET_EAGAIN;
            }
        }
    } while ( (res < 0) && (get_sys_errno() == EINTR) );

    return res;
}

ssize_t
wt_svr_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    void *conn_user_data)
{
    return wt_svr_write_socket(buf, size, peer_addr, peer_addrlen,
        conn_user_data);
}

// init basic callbacks
void
wt_svr_init_callbacks(xqc_engine_callback_t *engine_cb,
    xqc_transport_callbacks_t *transport_cb, WT_Server *server)
{
    static xqc_engine_callback_t cbs = {
        .set_event_timer = wt_svr_set_event_timer,
        .log_callbacks   = {.xqc_log_write_err = wt_svr_write_log_file,
              .xqc_log_write_stat              = wt_svr_write_log_file},
    };

    static xqc_transport_callbacks_t tcb = {
        .write_socket    = wt_svr_write_socket,
        .write_socket_ex = wt_svr_write_socket_ex,
    };

    *engine_cb    = cbs;
    *transport_cb = tcb;
}

void
wt_proxy_sig_hndlr(int signo)
{
    if ( signo == SIGTERM ) {
        if ( g_Server ) {
            event_base_loopbreak(g_Server->eb);
        }
    }
}

void
wt_svr_init_ssl_config(xqc_engine_ssl_config_t *cfg, WT_Server *server)
{
    cfg->private_key_file = server->wt_EnvConfig->mPrivKeyPath;
    cfg->cert_file        = server->wt_EnvConfig->mCertPemPath;
    cfg->ciphers          = server->wt_QuicConfig->cipher_suit;
    cfg->groups           = server->wt_QuicConfig->groups;

    if ( server->wt_QuicConfig->stk_len <= 0 ) {
        cfg->session_ticket_key_data = NULL;
        cfg->session_ticket_key_len  = 0;

    } else {
        cfg->session_ticket_key_data = server->wt_QuicConfig->stk;
        cfg->session_ticket_key_len  = server->wt_QuicConfig->stk_len;
    }
}

xqc_conn_settings_t
wt_svr_init_conn_settings(WT_Server *server)
{
    xqc_cong_ctrl_callback_t ccc = {0};
    switch ( server->wt_NetConfig->cc ) {
        case CC_TYPE_BBR: ccc = *xqc_get_bbr_cb(); break;
        case CC_TYPE_CUBIC: ccc = *xqc_get_cubic_cb(); break;
#    ifdef XQC_ENABLE_COPA
        case CC_TYPE_COPA: ccc = xqc_copa_cb; break;
#    endif
#    ifdef XQC_ENABLE_RENO
        case CC_TYPE_RENO: ccc = xqc_reno_cb; break;
#    endif
        default: break;
    }

    xqc_scheduler_callback_t sched = {0};
    if ( strncmp(server->wt_QuicConfig->mp_sched, "minrtt", strlen("minrtt")) ==
         0 ) {
        sched = *xqc_get_minrtt_sheduler_cb();
    }
    if ( strncmp(server->wt_QuicConfig->mp_sched, "backup", strlen("backup")) ==
         0 ) {
        sched = *xqc_get_backup_sheduler_cb();

    } else {
#    ifdef XQC_ENABLE_MP_INTEROP
        // sched = *xqc_get_interop_sheduler_cb();
#    endif
    }

    /* init connection settings */
    xqc_conn_settings_t conn_settings = {
        .pacing_on          = server->wt_NetConfig->pacing,
        .cong_ctrl_callback = ccc,
        .cc_params =
            {
                .customize_on     = 1,
                .init_cwnd        = 32,
                .bbr_enable_lt_bw = 1,
            },
        .init_idle_time_out      = 60000,
        .spurious_loss_detect_on = 1,
        .keyupdate_pkt_threshold =
            server->wt_QuicConfig->keyupdate_pkt_threshold,
        .max_pkt_out_size        = server->wt_QuicConfig->max_pkt_sz,
        .max_datagram_frame_size = 16383,
        .enable_multipath        = (uint64_t)server->wt_QuicConfig->multipath,
        .multipath_version =
            (xqc_multipath_version_t)server->wt_QuicConfig->multipath_version,
        .least_available_cid_count =
            server->wt_QuicConfig->least_available_cid_count,
        .mp_enable_reinjection = (int)server->wt_QuicConfig->reinjection,
        .mp_ack_on_any_path =
            (uint8_t)server->wt_QuicConfig->mp_ack_on_any_path,
        .scheduler_callback         = sched,
        .reinj_ctl_callback         = *xqc_get_deadline_reinj_ctl_cb(),
        .standby_path_probe_timeout = 1000,
        .adaptive_ack_frequency     = 1,
        .is_interop_mode = (xqc_bool_t)server->wt_QuicConfig->is_interop_mode,
    };
    return conn_settings;
    // xqc_server_set_conn_settings(server->engine, &conn_settings);
}

int
wt_svr_init_xquic_engine(WT_Server *server)
{
    xqc_engine_ssl_config_t cfg = {0};
    wt_svr_init_ssl_config(&cfg, server);

    xqc_engine_callback_t     engine_cbs;
    xqc_transport_callbacks_t transport_cbs;
    wt_svr_init_callbacks(&engine_cbs, &transport_cbs, server);

    xqc_conn_settings_t conn_settings = wt_svr_init_conn_settings(server);

    xqc_config_t        config;
    if ( xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) < 0 ) {
        return XQC_ERROR;
    }

    config.cid_len = 12;

    switch ( server->wt_EnvConfig->mLogLevel ) {
        case 'd': config.cfg_log_level = XQC_LOG_DEBUG; break;
        case 'i': config.cfg_log_level = XQC_LOG_INFO; break;
        case 'w': config.cfg_log_level = XQC_LOG_WARN; break;
        case 'e': config.cfg_log_level = XQC_LOG_ERROR; break;
        default: config.cfg_log_level = XQC_LOG_DEBUG; break;
    }

    // config.enable_h3_ext = 1;
    /* create server engine */
    server->engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &cfg,
        &engine_cbs, &transport_cbs, server);
    if ( server->engine == NULL ) {
        printf("xqc_engine_create error\n");
        return -1;
    }

    xqc_server_set_conn_settings(server->engine, &conn_settings);

    xqc_wt_ctx_init(server->engine, &default_dgram_cbs, NULL,
        &default_stream_cbs);

    return 0;
}

void
wt_svr_socket_read_handler(WT_Server *server, int fd)
{
    DEBUG;
    ssize_t             recv_sum = 0;
    struct sockaddr_in6 peer_addr;
    socklen_t           peer_addrlen = sizeof(peer_addr);
    ssize_t             recv_size    = 0;
    unsigned char       packet_buf[XQC_PACKET_TMP_BUF_LEN];

    server->current_fd = fd;

    do {
        recv_size = recvfrom(fd, (char *)packet_buf, sizeof(packet_buf), 0,
            (struct sockaddr *)&peer_addr, &peer_addrlen);
        if ( recv_size < 0 && get_sys_errno() == EAGAIN ) {
            int errcode = get_sys_errno();
            //  printf("err code %d\n", errcode);
            //  printf("haha\n");
            break;
        }

        if ( recv_size < 0 ) {
            printf("!!!!!!!!!recvfrom: recvmsg = %zd err=%s\n", recv_size,
                strerror(get_sys_errno()));
            break;
        }
        recv_sum += recv_size;

        uint64_t  recv_time = xqc_now();
        xqc_int_t ret = xqc_engine_packet_process(server->engine, packet_buf,
            recv_size, (struct sockaddr *)(&server->local_addr),
            server->local_addrlen, (struct sockaddr *)(&peer_addr),
            peer_addrlen, (xqc_usec_t)recv_time, server);
        if ( ret != XQC_OK ) {
            printf("server_read_handler: packet process err, ret: %d\n", ret);
            return;
        }
    } while ( recv_size > 0 );

finish_recv:
    // printf("recvfrom size:%zu\n", recv_sum);
    xqc_engine_finish_recv(server->engine);
}

void
wt_svr_socket_write_handler(WT_Server *server, int fd)
{
    DEBUG
}

static void
wt_svr_socket_event_callback(evutil_socket_t fd, short what, void *arg)
{
    // DEBUG;
    WT_Server *server = (WT_Server *)arg;
    if ( what & EV_WRITE ) {
        wt_svr_socket_write_handler(server, fd);

    } else if ( what & EV_READ ) {
        wt_svr_socket_read_handler(server, fd);

    } else {
        printf("event callback: fd=%d, what=%d\n", fd, what);
        exit(1);
    }
}

static int
wt_svr_init_socket(int family, uint16_t port, struct sockaddr *local_addr,
    socklen_t local_addrlen)
{
    int size;
    int opt_reuseaddr;
    int flags = 1;
    int fd    = socket(family, SOCK_DGRAM, 0);
    if ( fd < 0 ) {
        printf("create socket failed, errno: %d\n", get_sys_errno());
        return -1;
    }

    /* non-block */
#    ifdef XQC_SYS_WINDOWS
    if ( ioctlsocket(fd, FIONBIO, (u_long *)&flags) == SOCKET_ERROR ) {
        goto err;
    }
#    else
    if ( fcntl(fd, F_SETFL, O_NONBLOCK) == -1 ) {
        printf("set socket nonblock failed, errno: %d\n", get_sys_errno());
        goto err;
    }
#    endif

    /* reuse port */
    opt_reuseaddr = 1;
    if ( setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt_reuseaddr,
             sizeof(opt_reuseaddr)) < 0 ) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    /* send/recv buffer size */
    size = 1 * 1024 * 1024;
    if ( setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&size,
             sizeof(int)) < 0 ) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }
    if ( setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&size,
             sizeof(int)) < 0 ) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    /* bind port */
    if ( bind(fd, local_addr, local_addrlen) < 0 ) {
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
wt_svr_create_socket(WT_Server *ctx, NetConfig *cfg)
{
    /* ipv4 socket */
    memset(&ctx->local_addr, 0, sizeof(ctx->local_addr));
    ctx->local_addr.sin_family      = AF_INET;
    ctx->local_addr.sin_port        = htons(cfg->port);
    ctx->local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    ctx->local_addrlen              = sizeof(ctx->local_addr);
    ctx->fd                         = wt_svr_init_socket(AF_INET, cfg->port,
                                (struct sockaddr *)&ctx->local_addr, ctx->local_addrlen);
    printf("create ipv4 socket fd: %d\n", ctx->fd);

    /* ipv6 socket */
    memset(&ctx->local_addr6, 0, sizeof(ctx->local_addr6));
    ctx->local_addr6.sin6_family = AF_INET6;
    ctx->local_addr6.sin6_port   = htons(cfg->port);
    ctx->local_addr6.sin6_addr   = in6addr_any;
    ctx->local_addrlen6          = sizeof(ctx->local_addr6);
    ctx->fd6                     = wt_svr_init_socket(AF_INET6, cfg->port,
                            (struct sockaddr *)&ctx->local_addr6, ctx->local_addrlen6);
    printf("create ipv6 socket fd: %d\n", ctx->fd6);

    if ( !ctx->fd && !ctx->fd6 ) {
        return -1;
    }

    return 0;
}

void
start_wt_server(int argc, char *argv[], WT_Server *server)
{
    if ( g_isServerRunning ) {
        printf("Server is already running\n");
        return;
    }
    g_isServerRunning = XQC_TRUE;

    // xqc_platform_init_env();
    signal(SIGTERM, wt_proxy_sig_hndlr);
    g_Server = server;
    wt_svr_init_args(server, argc, argv);
    g_Server->current_fd  = -1;
    struct event_base *eb = event_base_new();
    g_Server->ev_engine =
        event_new(eb, -1, 0, wt_svr_engine_callback, g_Server);
    if ( g_Server->ev_engine == NULL ) {
        printf("event_new failed\n");
        return;
    }
    g_Server->eb = eb;

    if ( wt_svr_init_xquic_engine(g_Server) < 0 ) {
        printf("xquic engine init failed\n");
        return;
    }

    int ret = wt_svr_create_socket(g_Server, g_Server->wt_NetConfig);
    if ( ret < 0 ) {
        printf("xqc_create_socket error\n");
        return;
    }

    /* socket event */
    g_Server->ev_socket = event_new(server->eb, g_Server->fd,
        EV_READ | EV_PERSIST, wt_svr_socket_event_callback, g_Server);
    event_add(g_Server->ev_socket, NULL);

    /* socket event */
    g_Server->ev_socket6 = event_new(server->eb, g_Server->fd6,
        EV_READ | EV_PERSIST, wt_svr_socket_event_callback, g_Server);
    event_add(g_Server->ev_socket6, NULL);

    event_base_dispatch(eb);

    xqc_engine_destroy(g_Server->engine);

    xqc_free(g_Server);
}

int
main(int argc, char *argv[])
{
    WT_Server *server = server_init();
    start_wt_server(argc, argv, server);
    return 0;
}

#endif