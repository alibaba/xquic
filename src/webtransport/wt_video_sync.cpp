/**
 * @copyright Copyright (c) 2024, Alibaba Group Holding Limited
 * !!!!请勿code review本代码！！！
 * !!!!请勿code review本代码！！！
 * !!!!请勿code review本代码！！！
 * 本代码仅仅为了视频传输demo中的WTServer依赖而存在
 * 后续会删除本文件，目前仅仅是为了测试视频传输DEMO，后续会重构视频传输DEMO中的WTServer
 * 视频传输DEMO server端
 * 基于xqc_webtransport实现
 * 大部分核心内容在wt_video_server.cpp中
 * wt_video_sync_common.cpp wt_video_sync.h wt_video_sync.cpp 只是为了快速配置engine考虑，后续会重构
 */

#define _ITERATOR_DEBUG_LEVEL 0
#define DONOT_NEED_METHOD_S
#include "wt_video_sync.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
// #include <io.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <memory.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <xquic/xqc_http3.h>
#include <xquic/xqc_webtransport.h>
#include <xquic/xquic.h>
#include <src/webtransport/xqc_webtransport_session.h>


enum XQC_WT_ERRORCODE
{
    XQC_WT_CLOSESESSIONERROR = 1000,
    XQC_WT_CREATSTREAMERROR = 1001,
};

const int g_send_body_size = 100;
const bool g_send_dgram = 1;
const bool g_echo = 1;
#define XQC_TEST_DGRAM_BATCH_SZ 32

extern "C"
{
#include <event2/event.h>
// #include "../src/http3/xqc_h3_stream.h"
#include "../src/common/utils/vint/xqc_discrete_int_parser.h"
// #include "../src/http3/xqc_h3_conn.h"
// #include "../src/transport/xqc_engine.h"
#include "../tests/getopt.h"
#include "../tests/platform.h"
    // #include "../src/transport/xqc_conn.h"

    extern size_t xqc_put_varint_len(uint64_t n);
    extern uint8_t *xqc_put_varint(uint8_t *p, uint64_t n);

    extern xqc_stream_id_t xqc_h3_stream_getid(xqc_h3_stream_t *h3s);

    extern xqc_int_t xqc_h3_stream_close(xqc_h3_stream_t *h3s);

    extern void xqc_h3_stream_destroy(xqc_h3_stream_t *h3s);

    extern xqc_int_t xqc_h3_stream_send_buffer(xqc_h3_stream_t *h3s);

    extern xqc_int_t xqc_h3_stream_send_uni_stream_hdr(xqc_h3_stream_t *h3s);

    extern ssize_t xqc_h3_stream_send_data(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_size, uint8_t fin);

    extern xqc_int_t xqc_h3_stream_send_custom_frame_header(xqc_h3_stream_t *h3s, uint64_t *vintValueList,
                                                            size_t valueSize, uint8_t fin);
    extern xqc_int_t xqc_h3_stream_send_custom_data(xqc_h3_stream_t *h3s, unsigned char *data, size_t datasize,
                                                    uint8_t fin);
    extern xqc_int_t xqc_h3_stream_send_finish(xqc_h3_stream_t *h3s);
    extern void *xqc_conn_get_user_data(xqc_connection_t *c);
};

#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100 * 1024 * 1024)

#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT 4443
#define SESSION_TICKET_KEY_FILE "session_ticket.key"
#define SESSION_TICKET_KEY_BUF_LEN 2048
/**
 * ============================================================================
 * the environment config definition section
 * environment config is those arguments about IO inputs and outputs
 * all configuration on environment should be put under this section
 * ============================================================================
 */

#define LOG_PATH "slog.log"
#define KEY_PATH "skeys.log"
#define SOURCE_DIR "."
// #define PRIV_KEY_PATH "D:\\Tools\\ssl_config\\key.pem"
// #define CERT_PEM_PATH "D:\\Tools\\ssl_config\\cert.pem"
// #define PRIV_KEY_PATH "C:\\Users\\Administrator\\AppData\\Local\quinn\\quinn-examples\\data\\key.der"
// #define CERT_PEM_PATH "C:\\Users\\Administrator\\AppData\\Local\quinn\\quinn-examples\\data\\cert.der"
#define PRIV_KEY_PATH "/Users/sy03/Desktop/webtransport-poc/webtransport-poc/cert/localhost.key"
#define CERT_PEM_PATH "/Users/sy03/Desktop/webtransport-poc/webtransport-poc/cert/localhost.crt"

static WTServer *g_Server = nullptr;
static std::map<xqc_h3_stream_t *, xqc_discrete_int_pctx_t> g_h3_stream_pctx_map;


void WTServer::writeKeyLogFile(const xqc_cid_t *scid, const char *line)
{
    if (keylog_fd <= 0)
    {
        printf("write keys error!\n");
        return;
    }

    int write_len = write(keylog_fd, line, strlen(line));
    if (write_len < 0)
    {
        printf("write keys failed, errno: %d\n", get_sys_errno());
        return;
    }
    write_len = write(keylog_fd, line_break, 1);
    if (write_len < 0)
    {
        printf("write keys failed, errno: %d\n", get_sys_errno());
    }
}

void WTServer::onConnectionCreate(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid)
{
    xqc_h3_conn_settings_t settings = {
        .additionalSettingsCount = 2,
    };
    settings.additionalSettings[0].identifier = WT_SETTINGS_ENABLE_WEBTRANSPORT;
    settings.additionalSettings[0].value = 1;
    settings.additionalSettings[1].identifier = WT_SETTINGS_DATAGRAM;
    settings.additionalSettings[1].value = 1;

    xqc_h3_conn_set_settings(h3_conn, &settings);

    WTConnection *wtConnection = new WTConnection();
    wtConnection->mConnTraceId = m_con_id_gen++;
    wtConnection->xqc_conn = h3_conn;
    wtConnection->dgram_blk = (user_dgram_blk_t *)calloc(1, sizeof(user_dgram_blk_t));
    // wtConnection->dgram_not_supported = 0;
    wtConnection->dgram_mss = 100;

    // set remote settings for max_datagram_frame_size

    xqc_conn_public_remote_trans_settings_t remote_trans_settings;
    remote_trans_settings.max_datagram_frame_size = 19901;
    xqc_conn_set_public_remote_trans_settings(xqc_h3_conn_get_xqc_conn(h3_conn), &remote_trans_settings);

    // )

    // xqc_datagram_set_user_data(xqc_h3_conn_get_xqc_conn(h3_conn),wtConnection->dgram_blk);

    // if (g_send_dgram) {
    //     wtConnection->dgram_blk->data = (unsigned char*)calloc(1, g_send_body_size);
    //     wtConnection->dgram_blk->data_len = g_send_body_size;
    //     if (!g_echo) {
    //         wtConnection->dgram_blk->to_send_size = g_send_body_size;
    //     }
    // }
    // wtConnection->dgram_blk = xqc_create_datagram_block();

    xqc_h3_conn_set_user_data(h3_conn, wtConnection);

    /*
        printf("xqc_demo_svr_h3_conn_create_notify, user_conn: %p, h3_conn: %p, ctx: %p\n", user_conn,
            h3_conn, ctx);
    */
    xqc_h3_conn_get_peer_addr(h3_conn, (struct sockaddr *)&wtConnection->peer_addr, sizeof(wtConnection->peer_addr),
                              &wtConnection->peer_addrlen);

    memcpy(&wtConnection->cid, cid, sizeof(*cid));
}

void WTServer::onConnectionClose(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *conn_user_data)
{
    WTConnection *conn = (WTConnection *)conn_user_data;
    delete conn;
}

void WTServer::initArgs(int argc, char **argv)
{
    memset(&mNetCfg, 0, sizeof(NetConfig));
    memset(&mQuicCfg, 0, sizeof(QuicConfig));
    memset(&mEnvCfg, 0, sizeof(EnvConfig));

    /* net cfg */
    strncpy(mNetCfg.ip, DEFAULT_IP, sizeof(mNetCfg.ip) - 1);
    mNetCfg.port = DEFAULT_PORT;

    /* quic cfg */
    int ret = xqc_demo_read_file_data(mQuicCfg.stk, SESSION_TICKET_KEY_BUF_LEN, (char *)SESSION_TICKET_KEY_FILE);
    mQuicCfg.stk_len = ret > 0 ? ret : 0;
    strncpy(mQuicCfg.cipher_suit, XQC_TLS_CIPHERS, CIPHER_SUIT_LEN - 1);
    strncpy(mQuicCfg.groups, XQC_TLS_GROUPS, TLS_GROUPS_LEN - 1);

    /* env cfg */
    mEnvCfg.mLogLevel = XQC_LOG_DEBUG;
    mEnvCfg.mLogPath = LOG_PATH;
    mEnvCfg.mSourceFileDir = SOURCE_DIR;
    mEnvCfg.mKeyOutPath = KEY_PATH;
    mEnvCfg.mPrivKeyPath = PRIV_KEY_PATH;
    mEnvCfg.mCertPemPath = CERT_PEM_PATH;

    mQuicCfg.keyupdate_pkt_threshold = UINT64_MAX;
    mQuicCfg.least_available_cid_count = 1;
    mQuicCfg.max_pkt_sz = 1200;

    int ch = 0;
    while ((ch = getopt(argc, argv, "p:c:CD:l:L:6k:rdMiPs:R:u:a:F:")) != -1)
    {
        switch (ch)
        {
            /* listen port */
        case 'p':
            printf("option port :%s\n", optarg);
            mNetCfg.port = atoi(optarg);
            break;

            /* congestion control */
        case 'c':
            printf("option cong_ctl :%s\n", optarg);
            /* r:reno b:bbr c:cubic P:copa */
            switch (*optarg)
            {
            case 'b':
                mNetCfg.cc = CC_TYPE_BBR;
                break;
            case 'c':
                mNetCfg.cc = CC_TYPE_CUBIC;
                break;
            case 'r':
                mNetCfg.cc = CC_TYPE_RENO;
                break;
            case 'P':
                mNetCfg.cc = CC_TYPE_COPA;
                break;
            default:
                break;
            }
            break;

            /* pacing */
        case 'C':
            printf("option pacing :%s\n", "on");
            mNetCfg.pacing = 1;
            break;

            /* server resource dir */
        case 'D':
            printf("option read dir :%s\n", optarg);
            mEnvCfg.mSourceFileDir = optarg;
            break;

            /* log level */
        case 'l':
            printf("option log level :%s\n", optarg);
            mEnvCfg.mLogLevel = optarg[0];
            break;

            /* log path */
        case 'L': /* log directory */
            printf("option log directory :%s\n", optarg);
            mEnvCfg.mLogPath = optarg;
            break;

            /* ipv6 */
        case '6': // IPv6
            printf("option IPv6 :%s\n", "on");
            mNetCfg.ipv6 = 1;
            break;

            /* key out path */
        case 'k': /* key out path */
            printf("option key output file: %s\n", optarg);
            mEnvCfg.mKeyOutputFlag = 1;
            mEnvCfg.mKeyOutPath = optarg;
            break;

            /* retry */
        case 'r':
            printf("option validate addr with retry packet\n");
            mQuicCfg.retry_on = 1;
            break;

        case 'd':
            printf("option dummpy mode on\n");
            mQuicCfg.dummy_mode = 1;
            break;

        case 'i':
            printf("set interop mode\n");
            mQuicCfg.is_interop_mode = 1;
            break;

        case 'M':
            printf("option multipath enabled\n");
            mQuicCfg.multipath = 1;
            break;

        case 'V':
            printf("option multipath version: %s\n", optarg);
            mQuicCfg.multipath_version = atoi(optarg);
            break;

        case 'P':
            printf("option ACK_MP on any path enabled\n");
            mQuicCfg.mp_ack_on_any_path = 1;
            break;

        case 's':
            printf("option scheduler: %s\n", optarg);

            strncpy(mQuicCfg.mp_sched, optarg, 32);
            break;

        case 'R':
            printf("option reinjection: %s\n", optarg);
            mQuicCfg.reinjection = atoi(optarg);
            break;

        case 'u': /* key update packet threshold */
            printf("key update packet threshold: %s\n", optarg);
            mQuicCfg.keyupdate_pkt_threshold = atoi(optarg);
            break;

        case 'a': /* key update packet threshold */
            printf("least Available cid counts: %s\n", optarg);
            mQuicCfg.least_available_cid_count = atoi(optarg);
            break;

        case 'F':
            printf("MTU size: %s\n", optarg);
            mQuicCfg.max_pkt_sz = atoi(optarg);
            break;

        default:
            printf("other option :%c\n", ch);
            // xqc_demo_svr_usage(argc, argv);
            exit(0);
        }
    }
}

void WTServer::registerRequestHandler(const std::string &requestPath, wt_request_handler_pt handler)
{
    m_request_handle_map[requestPath] = handler;
}

int WTServer::onWebtransportRequest(WTRequest *request)
{
#if 0
    std::string path = request->request_headers[":path"];
    auto iter = m_request_handle_map.find(path);
    if (iter != m_request_handle_map.end())
    {
        xqc_h3_stream_t *qstr = xqc_h3_request_geth3s(request->h3_request);
        //
        auto ses = mSessionManager->addSession(request->connection, xqc_h3_stream_getid(qstr), qstr);
        return iter->second(this, ses, request);
    }
#endif
    return 0;
}

bool WTServer::canHandleWebTransportRequest(const std::string &path)
{
    auto iter = m_request_handle_map.find(path);
    if (iter != m_request_handle_map.end())
    {
        return true;
    }
    return false;
}


/******************************************************************************
 *                   start of engine callback functions                       *
 ******************************************************************************/
void webtransport_svr_set_event_timer(xqc_msec_t wake_after, void *eng_user_data)
{
    // WTServer* server = (WTServer*)eng_user_data;
    WTServer *server = g_Server;

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(server->ev_engine, &tv);
}

int webtransport_svr_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid, void *eng_user_data)
{
    DEBUG;
    return 0;
}

/**
 * start of server keylog functions
 */
void webtransport_svr_write_log_file(xqc_log_level_t lvl, const void *buf, size_t size, void *eng_user_data)
{
    WTServer *server = (WTServer *)eng_user_data;
}

void webtransport_svr_keylog_cb(const xqc_cid_t *scid, const char *line, void *eng_user_data)
{
    WTServer *server = (WTServer *)eng_user_data;
}


/******************************************************************************
 *                     start of socket operation function                     *
 ******************************************************************************/

ssize_t webtransport_svr_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
                                      socklen_t peer_addrlen, void *conn_user_data)
{
    ssize_t res;

    int fd = g_Server->current_fd;

    do
    {
        // set_sys_errno(0);
        res = sendto(fd, (const char *)buf, size, 0, peer_addr, peer_addrlen);
        if (res < 0)
        {
            printf("xqc_demo_svr_write_socket err %zd %s, fd: %d\n", res, strerror(get_sys_errno()), fd);
            if (get_sys_errno() == EAGAIN)
            {
                printf("xqc_demo_svr_write_socket EAGAIN\n");
                res = XQC_SOCKET_EAGAIN;
            }
        }
    } while ((res < 0) && (get_sys_errno() == EINTR));

    return res;
}

ssize_t webtransport_svr_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                                         const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data)
{
    return webtransport_svr_write_socket(buf, size, peer_addr, peer_addrlen, conn_user_data);
}

void webtransport_svr_socket_write_handler(WTServer *server, int fd)
{
    DEBUG
}

void webtransport_svr_socket_read_handler(WTServer *server, int fd)
{
    DEBUG;
    ssize_t recv_sum = 0;
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = sizeof(peer_addr);
    ssize_t recv_size = 0;
    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];

    server->current_fd = fd;

    do
    {
        recv_size =
            recvfrom(fd, (char *)packet_buf, sizeof(packet_buf), 0, (struct sockaddr *)&peer_addr, &peer_addrlen);
        if (recv_size < 0 && get_sys_errno() == EAGAIN)
        {
            int errcode = get_sys_errno();
            //  printf("err code %d\n", errcode);
            //  printf("haha\n");
            break;
        }

        if (recv_size < 0)
        {
            // printf("!!!!!!!!!recvfrom: recvmsg = %zd err=%s\n", recv_size, strerror(get_sys_errno()));
            break;
        }
        recv_sum += recv_size;

        uint64_t recv_time = xqc_now();
        xqc_int_t ret = xqc_engine_packet_process(
            server->engine, packet_buf, recv_size, (struct sockaddr *)(&server->local_addr), server->local_addrlen,
            (struct sockaddr *)(&peer_addr), peer_addrlen, (xqc_usec_t)recv_time, server);
        if (ret != XQC_OK)
        {
            printf("server_read_handler: packet process err, ret: %d\n", ret);
            return;
        }
    } while (recv_size > 0);

finish_recv:
    // printf("recvfrom size:%zu\n", recv_sum);
    xqc_engine_finish_recv(server->engine);
}

static void webtransport_svr_socket_event_callback(evutil_socket_t fd, short what, void *arg)
{
    // DEBUG;
    WTServer *server = (WTServer *)arg;
    if (what & EV_WRITE)
    {
        webtransport_svr_socket_write_handler(server, fd);
    }
    else if (what & EV_READ)
    {
        webtransport_svr_socket_read_handler(server, fd);
    }
    else
    {
        printf("event callback: fd=%d, what=%d\n", fd, what);
        exit(1);
    }
}

/* create socket and bind port */
static int webtransport_svr_init_socket(int family, uint16_t port, struct sockaddr *local_addr, socklen_t local_addrlen)
{
    int size;
    int opt_reuseaddr;
    int flags = 1;
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        printf("create socket failed, errno: %d\n", get_sys_errno());
        return -1;
    }

    /* non-block */
#ifdef XQC_SYS_WINDOWS
    if (ioctlsocket(fd, FIONBIO, (u_long *)&flags) == SOCKET_ERROR)
    {
        goto err;
    }
#else
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
    {
        printf("set socket nonblock failed, errno: %d\n", get_sys_errno());
        goto err;
    }
#endif

    /* reuse port */
    opt_reuseaddr = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt_reuseaddr, sizeof(opt_reuseaddr)) < 0)
    {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    /* send/recv buffer size */
    size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&size, sizeof(int)) < 0)
    {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&size, sizeof(int)) < 0)
    {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    /* bind port */
    if (bind(fd, local_addr, local_addrlen) < 0)
    {
        printf("bind socket failed, family: %d, errno: %d, %s\n", family, get_sys_errno(), strerror(get_sys_errno()));
        goto err;
    }

    return fd;

err:
    close(fd);
    return -1;
}

static int webtransport_svr_create_socket(WTServer *ctx, WTServer::NetConfig *cfg)
{
    /* ipv4 socket */
    memset(&ctx->local_addr, 0, sizeof(ctx->local_addr));
    ctx->local_addr.sin_family = AF_INET;
    ctx->local_addr.sin_port = htons(cfg->port);
    ctx->local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    ctx->local_addrlen = sizeof(ctx->local_addr);
    ctx->fd = webtransport_svr_init_socket(AF_INET, cfg->port, (struct sockaddr *)&ctx->local_addr, ctx->local_addrlen);
    printf("create ipv4 socket fd: %d\n", ctx->fd);

    /* ipv6 socket */
    memset(&ctx->local_addr6, 0, sizeof(ctx->local_addr6));
    ctx->local_addr6.sin6_family = AF_INET6;
    ctx->local_addr6.sin6_port = htons(cfg->port);
    ctx->local_addr6.sin6_addr = in6addr_any;
    ctx->local_addrlen6 = sizeof(ctx->local_addr6);
    ctx->fd6 =
        webtransport_svr_init_socket(AF_INET6, cfg->port, (struct sockaddr *)&ctx->local_addr6, ctx->local_addrlen6);
    printf("create ipv6 socket fd: %d\n", ctx->fd6);

    if (!ctx->fd && !ctx->fd6)
    {
        return -1;
    }

    return 0;
}

static void webtransport_svr_engine_callback(evutil_socket_t fd, short what, void *arg)
{
    WTServer *server = (WTServer *)arg;

    xqc_engine_main_logic(server->engine);
}

static bool g_isServerRunning = false;
static std::thread *g_serverThread = nullptr;

void webtransport_svr_init_callback(xqc_engine_callback_t *cb, xqc_transport_callbacks_t *transport_cbs,
                                    WTServer *server)
{
    static xqc_engine_callback_t callback = {
        .set_event_timer = webtransport_svr_set_event_timer,
        .log_callbacks = {.xqc_log_write_err = webtransport_svr_write_log_file,
                          .xqc_log_write_stat = webtransport_svr_write_log_file},
        .keylog_cb = webtransport_svr_keylog_cb,
    };

    static xqc_transport_callbacks_t tcb = {
        .server_accept = webtransport_svr_accept,
        .write_socket = webtransport_svr_write_socket,
        .write_socket_ex = webtransport_svr_write_socket_ex,
    };

    *cb = callback;
    *transport_cbs = tcb;
}

/* init ssl config */
void webtransport_svr_init_ssl_config(xqc_engine_ssl_config_t *cfg, WTServer *server)
{
    cfg->private_key_file = (char *)server->mEnvCfg.mPrivKeyPath.c_str();
    cfg->cert_file = (char *)server->mEnvCfg.mCertPemPath.c_str();
    cfg->ciphers = server->mQuicCfg.cipher_suit;
    cfg->groups = server->mQuicCfg.groups;

    if (server->mQuicCfg.stk_len <= 0)
    {
        cfg->session_ticket_key_data = NULL;
        cfg->session_ticket_key_len = 0;
    }
    else
    {
        cfg->session_ticket_key_data = server->mQuicCfg.stk;
        cfg->session_ticket_key_len = server->mQuicCfg.stk_len;
    }
}

xqc_conn_settings_t webtransport_svr_init_conn_settings(WTServer *server)
{
    xqc_cong_ctrl_callback_t ccc = {0};
    switch (server->mNetCfg.cc)
    {
    case CC_TYPE_BBR:
        ccc = *xqc_get_bbr_cb();
        break;
    case CC_TYPE_CUBIC:
        ccc = *xqc_get_cubic_cb();
        break;
#ifdef XQC_ENABLE_COPA
    case CC_TYPE_COPA:
        ccc = xqc_copa_cb;
        break;
#endif
#ifdef XQC_ENABLE_RENO
    case CC_TYPE_RENO:
        ccc = xqc_reno_cb;
        break;
#endif
    default:
        break;
    }

    xqc_scheduler_callback_t sched = {0};
    if (strncmp(server->mQuicCfg.mp_sched, "minrtt", strlen("minrtt")) == 0)
    {
        sched = *xqc_get_minrtt_sheduler_cb();
    }
    if (strncmp(server->mQuicCfg.mp_sched, "backup", strlen("backup")) == 0)
    {
        sched = *xqc_get_backup_sheduler_cb();
    }
    else
    {
#ifdef XQC_ENABLE_MP_INTEROP
        sched = *xqc_get_interop_sheduler_cb();
#endif
    }

    /* init connection settings */
    xqc_conn_settings_t conn_settings = {
        .pacing_on = server->mNetCfg.pacing,
        .cong_ctrl_callback = ccc,
        .cc_params =
            {
                .customize_on = 1,
                .init_cwnd = 32,
                .bbr_enable_lt_bw = 1,
            },
        .init_idle_time_out = 60000,
        .spurious_loss_detect_on = 1,
        .keyupdate_pkt_threshold = server->mQuicCfg.keyupdate_pkt_threshold,
        .max_pkt_out_size = server->mQuicCfg.max_pkt_sz,
        .max_datagram_frame_size = 16383,
        .enable_multipath = (uint64_t)server->mQuicCfg.multipath,
        .multipath_version = (xqc_multipath_version_t)server->mQuicCfg.multipath_version,
        .least_available_cid_count = server->mQuicCfg.least_available_cid_count,
        .mp_enable_reinjection = (int)server->mQuicCfg.reinjection,
        .mp_ack_on_any_path = (uint8_t)server->mQuicCfg.mp_ack_on_any_path,
        .scheduler_callback = sched,
        .reinj_ctl_callback = *xqc_get_deadline_reinj_ctl_cb(),
        .standby_path_probe_timeout = 1000,
        .adaptive_ack_frequency = 1,
        .is_interop_mode = (xqc_bool_t)server->mQuicCfg.is_interop_mode,
    };
    return conn_settings;
    // xqc_server_set_conn_settings(server->engine, &conn_settings);
}


/* init xquic server engine */
int webtransport_svr_init_xquic_engine(WTServer *server)
{
    /* init engine ssl config */
    xqc_engine_ssl_config_t cfg = {0};
    webtransport_svr_init_ssl_config(&cfg, server);

    /* init engine callbacks */
    xqc_engine_callback_t callback;
    xqc_transport_callbacks_t transport_cbs;
    webtransport_svr_init_callback(&callback, &transport_cbs, server);

    /* init server connection settings */
    xqc_conn_settings_t conn_settings = webtransport_svr_init_conn_settings(server);

    /* init engine config */
    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0)
    {
        return XQC_ERROR;
    }

    config.cid_len = 12;

    switch (server->mEnvCfg.mLogLevel)
    {
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
    server->engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &cfg, &callback, &transport_cbs, server);
    if (server->engine == NULL)
    {
        printf("xqc_engine_create error\n");
        return -1;
    }

    xqc_server_set_conn_settings(server->engine, &conn_settings);

    // xqc_webtransport_dgram_callbacks_t dgram_cbs = {
    //     .dgram_mss_updated_notify = NULL,
    //     .dgram_write_notify = NULL,
    //     .dgram_read_notify = NULL,
    // };
    // xqc_webtransport_stream_callbacks_t stream_cbs = {
    //     .wt_unistream_create_notify = xqc_unistream_create_notify,
    //     .wt_unistream_read_notify = xqc_unistream_read_data_notify,
    // };
    // xqc_webtransport_session_callbacks_t session_cbs = {
    //     .webtransport_session_handshake_finished_notify = wt_session_handshake_finished_handler,
    // };

    // xqc_wt_ctx_init(server->engine, &dgram_cbs, NULL, &stream_cbs);

    // if (webtransport_svr_init_alpn_ctx(server) < 0) {
    //     printf("init alpn ctx error!");
    //     return -1;
    // }

    return 0;
}

void webtransport_proxy_sig_hndlr(int signo)
{
    if (signo == SIGTERM)
    {
        if (g_Server)
        {
            event_base_loopbreak(g_Server->eb);
        }
    }
}

void startWebtransportServer(int argc, char *argv[], WTServer *server,xqc_webtransport_callbacks_t *wt_cbs)
{
    if (g_isServerRunning)
    {
        return;
    }
    // xqc_global_stream_can_write_callback = webtransport_svr_on_stream_canwrite;

    g_isServerRunning = true;
    /* init env if necessary */
    xqc_platform_init_env();

    signal(SIGTERM, webtransport_proxy_sig_hndlr);
    g_Server = server;
    g_Server->initArgs(argc, argv);
    g_Server->current_fd = -1;

    /* engine event */
    struct event_base *eb = event_base_new();
    g_Server->ev_engine = event_new(eb, -1, 0, webtransport_svr_engine_callback, g_Server);
    g_Server->eb = eb;

    if (webtransport_svr_init_xquic_engine(g_Server) < 0)
    {
        return;
    }

    if(wt_cbs!=NULL){
        xqc_wt_ctx_init(g_Server->engine,&wt_cbs->dgram_cbs,&wt_cbs->session_cbs,&wt_cbs->stream_cbs);
    }

    /* init socket */
    int ret = webtransport_svr_create_socket(g_Server, &g_Server->mNetCfg);
    if (ret < 0)
    {
        printf("xqc_create_socket error\n");
        return;
    }

    /* socket event */
    g_Server->ev_socket =
        event_new(eb, g_Server->fd, EV_READ | EV_PERSIST, webtransport_svr_socket_event_callback, g_Server);
    event_add(g_Server->ev_socket, NULL);

    /* socket event */
    g_Server->ev_socket6 =
        event_new(eb, g_Server->fd6, EV_READ | EV_PERSIST, webtransport_svr_socket_event_callback, g_Server);
    event_add(g_Server->ev_socket6, NULL);

    event_base_dispatch(eb);

    xqc_engine_destroy(g_Server->engine);
    delete g_Server;

}

void stopWebtransportServer()
{
    if (g_isServerRunning)
    {
        g_isServerRunning = false;
        event_base_loopbreak(g_Server->eb);
        g_serverThread->join();
        delete g_serverThread;
        g_serverThread = nullptr;
    }
}