#ifndef XQC_MINI_CLIENT_H
#define XQC_MINI_CLIENT_H

#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <memory.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include <xquic/xquic_typedef.h>

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


#include "../tests/platform.h"
#include "common.h"
#include "mini_client_cb.h"


#define DEFAULT_IP   "127.0.0.1"
#define DEFAULT_PORT 8443
#define DEFAULT_HOST "test.xquic.com"

#define SESSION_TICKET_BUF_MAX_SIZE 8192
#define TRANSPORT_PARAMS_MAX_SIZE 8192
#define TOKEN_MAX_SIZE 8192
#define MAX_PATH_CNT 2
#define XQC_PACKET_BUF_LEN 1500

#define SESSION_TICKET_FILE         "session_ticket"
#define TRANSPORT_PARAMS_FILE       "transport_params"
#define TOKEN_FILE                  "token"

#define LOG_PATH "clog.log"
#define KEY_PATH "ckeys.log"
#define OUT_DIR  "."

/**
 * net config definition
 * net config is those arguments about socket information
 * all configuration on net should be put under this section
 */

typedef struct xqc_mini_cli_net_config_s {
    int                 conn_timeout;
    xqc_usec_t          last_socket_time;

    // /* server addr info */
    // struct sockaddr    *addr;
    // socklen_t           addr_len;
    // char                server_addr[64];
    // short               server_port;
} xqc_mini_cli_net_config_t;

/**
 * quic config definition
 * quic config is those arguments required by quic features, including connection settings, ssl configs, etc.
 * all configuration on quic should be put under this section
 */

typedef struct xqc_mini_cli_quic_config_s {
    /* cipher config */
    char        ciphers[CIPHER_SUIT_LEN];
    char        groups[TLS_GROUPS_LEN];

    /* connection ssl config */
    char        session_ticket[SESSION_TICKET_BUF_MAX_SIZE];
    int         session_ticket_len;
    char        transport_parameter[TRANSPORT_PARAMS_MAX_SIZE];
    int         transport_parameter_len;

    char        token[TOKEN_MAX_SIZE];
    int         token_len;
    
    int         no_encryption;

    /* multipath */
    int         multipath;     // mp option, 0: disable, 1: enable
    char        mp_sched[32];  // mp scheduler, minrtt/backup

    /* congestion control */
    CC_TYPE     cc;             // cc algrithm, bbr/cubic
} xqc_mini_cli_quic_config_t;

/**
 * the environment config definition
 * environment config is those arguments about IO inputs and outputs
 * all configuration on environment should be put under this section
 */

typedef struct xqc_mini_cli_env_config_s {
    /* log config */
    char log_path[PATH_LEN];

    /* tls certificates */
    char private_key_file[PATH_LEN];
    char cert_file[PATH_LEN];

    /* key export */
    char key_out_path[PATH_LEN];

    /* output file */
    char out_file_dir[PATH_LEN];
} xqc_mini_cli_env_config_t;


/**
 * the request config definition
 * request config is those arguments about request information
 * all configuration on request should be put under this section
 */
typedef struct xqc_mini_cli_req_config_s {
    char            path[RESOURCE_LEN];         /* request path */
    char            scheme[8];                  /* request scheme, http/https */
    REQUEST_METHOD  method;
    char            host[256];                  /* request host */
    // char            auth[AUTHORITY_LEN];
    char            url[URL_LEN];               /* original url */
} xqc_mini_cli_req_config_t;


typedef struct xqc_mini_cli_args_s {
    /* network args */
    xqc_mini_cli_net_config_t   net_cfg;

    /* xquic args */
    xqc_mini_cli_quic_config_t  quic_cfg;

    /* environment args */
    xqc_mini_cli_env_config_t   env_cfg;

    /* request args */
    xqc_mini_cli_req_config_t   req_cfg;
} xqc_mini_cli_args_t;


typedef struct xqc_mini_cli_ctx_s {
    struct event_base   *eb;

    xqc_mini_cli_args_t *args;      // server arguments for current context

    xqc_engine_t        *engine;    // xquic engine for current context
    struct event        *ev_engine;

    int                 log_fd;
    int                 keylog_fd;
} xqc_mini_cli_ctx_t;


typedef struct xqc_mini_cli_user_conn_s {
    xqc_cid_t               cid;
    xqc_h3_conn_t          *h3_conn;

    xqc_mini_cli_ctx_t     *ctx;

    /* ipv4 server */
    int                     fd;
    int                     get_local_addr;
    struct sockaddr        *local_addr;
    socklen_t               local_addrlen;
    struct sockaddr        *peer_addr;
    socklen_t               peer_addrlen;

    struct event            *ev_socket;
    struct event            *ev_timeout;

} xqc_mini_cli_user_conn_t;

typedef struct xqc_mini_cli_user_stream_s {
    xqc_mini_cli_user_conn_t   *user_conn;

    /* save file */
    // char                        file_name[RESOURCE_LEN];
    // FILE                        *recv_body_fp;

    /* stat for IO */
    size_t                      send_body_len;
    size_t                      recv_body_len;
    int                         recv_fin;
    xqc_msec_t                  start_time;


    /* h3 request content */
    xqc_h3_request_t           *h3_request;

    xqc_http_headers_t          h3_hdrs;
    uint8_t                     hdr_sent;

    char                       *send_body_buff;
    int                         send_body_size;
    size_t                      send_offset;

} xqc_mini_cli_user_stream_t;



void xqc_mini_cli_init_engine_ssl_config(xqc_engine_ssl_config_t *ssl_cfg, xqc_mini_cli_args_t *args);

void xqc_mini_cli_init_callback(xqc_engine_callback_t *cb, xqc_transport_callbacks_t *tcb, xqc_mini_cli_args_t *args);

int xqc_mini_cli_init_xquic_engine(xqc_mini_cli_ctx_t *ctx, xqc_mini_cli_args_t *args);

void xqc_mini_cli_convert_text_to_sockaddr(int type,
    const char *addr_text, unsigned int port,
    struct sockaddr **saddr, socklen_t *saddr_len);

void xqc_mini_cli_init_args(xqc_mini_cli_args_t *args);

int xqc_mini_cli_init_ctx(xqc_mini_cli_ctx_t *ctx, xqc_mini_cli_args_t *args);

int xqc_mini_cli_init_env(xqc_mini_cli_ctx_t *ctx, xqc_mini_cli_args_t *args);

xqc_scheduler_callback_t xqc_mini_cli_get_sched_cb(xqc_mini_cli_args_t *args);
xqc_cong_ctrl_callback_t xqc_mini_cli_get_cc_cb(xqc_mini_cli_args_t *args);
void xqc_mini_cli_init_conn_settings(xqc_conn_settings_t *settings, xqc_mini_cli_args_t *args);

int xqc_mini_cli_init_alpn_ctx(xqc_mini_cli_ctx_t *ctx);
int xqc_mini_cli_init_engine_ctx(xqc_mini_cli_ctx_t *ctx);

void xqc_mini_cli_free_ctx(xqc_mini_cli_ctx_t *ctx);

void xqc_mini_cli_init_0rtt(xqc_mini_cli_args_t *args);

void xqc_mini_cli_init_conn_ssl_config(xqc_conn_ssl_config_t *conn_ssl_config, xqc_mini_cli_args_t *args);

int xqc_mini_cli_format_h3_req(xqc_http_header_t *headers, xqc_mini_cli_req_config_t* req_cfg);

int xqc_mini_cli_request_send(xqc_h3_request_t *h3_request, xqc_mini_cli_user_stream_t *user_stream);

int xqc_mini_cli_send_h3_req(xqc_mini_cli_user_conn_t *user_conn, xqc_mini_cli_user_stream_t *user_stream);

int xqc_mini_cli_init_socket(xqc_mini_cli_user_conn_t *user_conn);

void xqc_mini_cli_socket_write_handler(xqc_mini_cli_user_conn_t *user_conn, int fd);

void xqc_mini_cli_socket_read_handler(xqc_mini_cli_user_conn_t *user_conn, int fd);

static void xqc_mini_cli_socket_event_callback(int fd, short what, void *arg);
int xqc_mini_cli_init_xquic_connection(xqc_mini_cli_user_conn_t *user_conn);

int xqc_mini_cli_main_process(xqc_mini_cli_user_conn_t *user_conn, xqc_mini_cli_ctx_t *ctx);
xqc_mini_cli_user_conn_t *xqc_mini_cli_user_conn_create(xqc_mini_cli_ctx_t *ctx);

void xqc_mini_cli_free_user_conn(xqc_mini_cli_user_conn_t *user_conn);
void xqc_mini_cli_on_connection_finish(xqc_mini_cli_user_conn_t *user_conn);
#endif